// Package evals is gopherguard's eval harness: the keyless suites that gate
// CI/CD (M4).
//
// Three suites run against the YAML agent config (deploy/agent.yaml):
//
//   - task-success: golden outputs, tolerance-graded — the code-routed
//     coordinator routes golden prompts correctly, the graph assembles
//     keyless, tool grants match the config, and private work never leaves
//     the local model.
//   - trajectory: captured traces stay within the config's budgets (steps,
//     loops, agent hops) and the coordinator's path lands on a configured
//     agent.
//   - injection-resistance: every OWASP ASI pair (internal/owasp) is a
//     permanent regression test — the mapped detection (internal/detect)
//     fires on the vulnerable trace and every rule stays quiet on every
//     hardened trace.
//
// Everything here is keyless and offline: no Ollama, no Gemini, no network.
// The suites exercise the deterministic paths (code routing, scoped-tool
// metadata, the simulated ASI pairs, in-process trace capture) so they can
// run in CI on every PR. `make eval` and .github/workflows/evals.yml wrap
// this package; cmd/ggeval renders the report.
package evals

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// AgentConfig is the parsed deploy/agent.yaml — the GitOps description of the
// agent that the eval pipeline validates and gates on.
type AgentConfig struct {
	APIVersion string      `yaml:"apiVersion"`
	Kind       string      `yaml:"kind"`
	Metadata   Metadata    `yaml:"metadata"`
	Model      ModelConfig `yaml:"model"`
	Agents     []AgentSpec `yaml:"agents"`
	Budgets    Budgets     `yaml:"budgets"`
	Gates      Gates       `yaml:"gates"`
}

// Metadata names the config.
type Metadata struct {
	Name string `yaml:"name"`
}

// ModelConfig describes the model routing policy and its cost inputs.
type ModelConfig struct {
	Mode    string        `yaml:"mode"` // "gemma" (local, keyless) or "gemini"
	Routing RoutingPolicy `yaml:"routing"`
	Cost    CostModel     `yaml:"cost"`
}

// RoutingPolicy mirrors internal/model's router policy knobs.
type RoutingPolicy struct {
	PrivateStaysLocal      bool `yaml:"private_stays_local"`
	HardReasoningEscalates bool `yaml:"hard_reasoning_escalates"`
}

// CostModel holds the planning inputs for the CI cost summary. These are
// estimates for the PR comment, not billing data.
type CostModel struct {
	GemmaUSDPerMTok     float64 `yaml:"gemma_usd_per_mtok"`
	GeminiUSDPerMTok    float64 `yaml:"gemini_usd_per_mtok"`
	EscalationRate      float64 `yaml:"escalation_rate"`
	AvgTokensPerRequest int     `yaml:"avg_tokens_per_request"`
}

// AgentSpec is one agent's least-privilege grant: which tools it holds and
// which privilege scopes those tools are allowed to exercise.
type AgentSpec struct {
	Name   string   `yaml:"name"`
	Tools  []string `yaml:"tools"`
	Scopes []string `yaml:"scopes"`
}

// Budgets are the runtime trajectory budgets the trajectory suite enforces
// against captured traces.
type Budgets struct {
	MaxStepsPerSession int `yaml:"max_steps_per_session"`
	LoopThreshold      int `yaml:"loop_threshold"`
	MaxAgentHops       int `yaml:"max_agent_hops"`
}

// Gates are the pass thresholds for the graded suites.
type Gates struct {
	RoutingPassRate float64 `yaml:"routing_pass_rate"`
	MinPairsHolding int     `yaml:"min_pairs_holding"`
}

// Load reads and strictly parses an agent config. Unknown fields are an
// error, so a typo in the GitOps file fails the gate instead of silently
// deploying a default.
func Load(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load agent config: %w", err)
	}
	return Parse(data)
}

// Parse strictly parses agent-config YAML bytes.
func Parse(data []byte) (*AgentConfig, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	var cfg AgentConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse agent config: %w", err)
	}
	return &cfg, nil
}

// scopeRe is the shape every privilege scope must have. "admin" is not
// grantable via config at all.
var scopeRe = regexp.MustCompile(`^(read|write):[a-z][a-z0-9_-]*$`)

// Validate applies the static policy gate to a parsed config. It rejects
// configs that are structurally fine but violate gopherguard's security
// posture — this runs before any suite, so an unsafe config never gets as far
// as "the evals passed".
func (c *AgentConfig) Validate() error {
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	if c.Kind != "AgentConfig" {
		fail("kind must be AgentConfig, got %q", c.Kind)
	}
	if c.Metadata.Name == "" {
		fail("metadata.name must be set")
	}
	if c.Model.Mode != "gemma" && c.Model.Mode != "gemini" {
		fail("model.mode must be gemma or gemini, got %q", c.Model.Mode)
	}
	if !c.Model.Routing.PrivateStaysLocal {
		fail("model.routing.private_stays_local must be true (privacy invariant)")
	}
	if c.Model.Cost.EscalationRate < 0 || c.Model.Cost.EscalationRate > 1 {
		fail("model.cost.escalation_rate must be in [0,1], got %v", c.Model.Cost.EscalationRate)
	}
	if c.Model.Cost.AvgTokensPerRequest <= 0 {
		fail("model.cost.avg_tokens_per_request must be positive")
	}

	if len(c.Agents) == 0 {
		fail("at least one agent must be configured")
	}
	seen := make(map[string]bool)
	for _, a := range c.Agents {
		if a.Name == "" {
			fail("every agent needs a name")
			continue
		}
		if seen[a.Name] {
			fail("duplicate agent %q", a.Name)
		}
		seen[a.Name] = true

		hasUntrustedRead, hasWrite := false, false
		for _, s := range a.Scopes {
			if !scopeRe.MatchString(s) {
				fail("agent %q: scope %q is not read:<x> or write:<x> (admin is never grantable)", a.Name, s)
			}
			if s == "write:egress" {
				fail("agent %q: write:egress is forbidden — egress is never a standing grant", a.Name)
			}
			if s == "read:web" {
				hasUntrustedRead = true
			}
			if strings.HasPrefix(s, "write:") {
				hasWrite = true
			}
		}
		// Confused-deputy guard: one agent must not both ingest untrusted
		// external content and hold a mutating scope (that is the ASI01
		// injection→action shape as a standing capability).
		if hasUntrustedRead && hasWrite {
			fail("agent %q: read:web plus a write:* scope in one agent is the injection→action shape; split the agents", a.Name)
		}
	}

	if c.Budgets.MaxStepsPerSession <= 0 {
		fail("budgets.max_steps_per_session must be positive")
	}
	if c.Budgets.LoopThreshold <= 0 {
		fail("budgets.loop_threshold must be positive")
	}
	if c.Budgets.MaxAgentHops <= 0 {
		fail("budgets.max_agent_hops must be positive")
	}
	if c.Gates.RoutingPassRate <= 0 || c.Gates.RoutingPassRate > 1 {
		fail("gates.routing_pass_rate must be in (0,1], got %v", c.Gates.RoutingPassRate)
	}
	if c.Gates.MinPairsHolding <= 0 {
		fail("gates.min_pairs_holding must be positive")
	}

	if len(errs) > 0 {
		return fmt.Errorf("agent config invalid:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// agent returns the spec for a named agent, if configured.
func (c *AgentConfig) agent(name string) (AgentSpec, bool) {
	for _, a := range c.Agents {
		if a.Name == name {
			return a, true
		}
	}
	return AgentSpec{}, false
}
