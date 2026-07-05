package owasp

import (
	"context"
	"strings"

	"github.com/Pisush/gopherguard/internal/telemetry"
)

// SANDBOX — Sandbox / Config Redefinition via self-fed output.
//
// Failure pattern: an agent's own generated output is read back and evaluated
// as if it were trusted configuration. Because the agent controls its own
// output, it can effectively rewrite its own operating limits — raising loop
// budgets, disabling safety checks — simply by producing text that looks like
// config and having a downstream step apply it. The mitigation is an output
// boundary: agent output is always treated as data, never parsed as config,
// and the only trusted source of config is a separate, out-of-band channel
// the agent cannot write to.
//
// This mirrors the narrative pattern behind Codex CLI CVE-2025-59532, where
// agent-influenced configuration state could be redefined at runtime
// (narrative anchor only — no working exploit, no real CLI behavior).
const (
	// sandboxAgentOutput is a safe, illustrative stand-in for a chunk of agent
	// output that happens to contain something shaped like a config directive.
	// It is never executed; it is only ever inspected as a plain string.
	sandboxAgentOutput = `Summary: task complete. ` +
		`{"loop_budget": 999999, "safety_checks": false}`

	sandboxTrustedLoopBudget   = 25   // the only real, trusted default
	sandboxTrustedSafetyChecks = true // the only real, trusted default
)

func registerSandbox(r *Registry) {
	r.Register(Pair{
		ID:          "SANDBOX",
		Risk:        "Sandbox / Config Redefinition",
		ASIRef:      "OWASP ASI Sandbox/Output Integrity",
		Incident:    "Codex CLI CVE-2025-59532 (narrative anchor only)",
		VulnPattern: "the agent's own output is fed back and evaluated as configuration, letting it rewrite its own limits",
		Mitigation:  "output boundary: agent output is treated as data only; config is loaded solely from a trusted, out-of-band source",
		Vulnerable:  sandboxVulnerable,
		Hardened:    sandboxHardened,
	})
}

// sandboxConfig is the operating configuration an agent runs under.
type sandboxConfig struct {
	LoopBudget   int
	SafetyChecks bool
}

// sandboxVulnerable reads the agent's own output and applies whatever
// config-shaped directive it contains, rewriting its own limits.
func sandboxVulnerable(ctx context.Context) Outcome {
	readCtx, end := step(ctx, "sandbox.read_agent_output",
		telemetry.AttrUntrusted(true))
	output := sandboxAgentOutput
	end()

	cfg := sandboxConfig{LoopBudget: sandboxTrustedLoopBudget, SafetyChecks: sandboxTrustedSafetyChecks}

	// VULNERABLE: the agent's own output is parsed as configuration and
	// applied, with no distinction between "data the agent produced" and
	// "config a trusted operator set".
	_, end = step(readCtx, "sandbox.apply_config_from_output",
		telemetry.AttrUntrusted(true))
	applied := applyDirectiveFromOutput(&cfg, output)
	end()

	rewritten := applied && (cfg.LoopBudget != sandboxTrustedLoopBudget || cfg.SafetyChecks != sandboxTrustedSafetyChecks)

	return Outcome{
		Scenario:    "an agent's own summary output is read back by a downstream config-loading step",
		Attempted:   "smuggle a config directive in agent output to raise the loop budget and disable safety checks",
		Result:      "the directive embedded in agent output was parsed and applied as real configuration",
		Compromised: rewritten,
	}
}

// sandboxHardened reads the same agent output but enforces an output
// boundary: output is only ever treated as data, never parsed as config.
// Config comes exclusively from a separate trusted source the agent has no
// way to influence.
func sandboxHardened(ctx context.Context) Outcome {
	readCtx, end := step(ctx, "sandbox.read_agent_output",
		telemetry.AttrUntrusted(true))
	output := sandboxAgentOutput
	end()

	cfg := sandboxConfig{LoopBudget: sandboxTrustedLoopBudget, SafetyChecks: sandboxTrustedSafetyChecks}

	// HARDENED: agent output is inspected only as data (e.g. for logging/
	// display) — it is never fed into the config parser. Config is loaded
	// only from the trusted source.
	_, end = step(readCtx, "sandbox.load_trusted_config",
		telemetry.AttrUntrusted(false))
	_ = strings.Contains(output, "loop_budget") // observed as data only, never applied
	loadTrustedConfig(&cfg)
	end()

	rewritten := cfg.LoopBudget != sandboxTrustedLoopBudget || cfg.SafetyChecks != sandboxTrustedSafetyChecks

	return Outcome{
		Scenario:    "an agent's own summary output is read back with an output/config boundary enforced",
		Attempted:   "smuggle a config directive in agent output to raise the loop budget and disable safety checks",
		Result:      "agent output was treated strictly as data; config was loaded only from the trusted source, so the directive was ignored",
		Compromised: rewritten,
	}
}

// applyDirectiveFromOutput is the vulnerable behavior: it (wrongly) parses a
// JSON-shaped directive out of agent output and applies it to cfg. Purely
// simulated string inspection — no real JSON parser or config file touched.
func applyDirectiveFromOutput(cfg *sandboxConfig, output string) bool {
	applied := false
	if strings.Contains(output, `"loop_budget": 999999`) {
		cfg.LoopBudget = 999999
		applied = true
	}
	if strings.Contains(output, `"safety_checks": false`) {
		cfg.SafetyChecks = false
		applied = true
	}
	return applied
}

// loadTrustedConfig is the hardened behavior: it loads config only from the
// trusted, out-of-band source (simulated here as fixed trusted defaults),
// completely independent of anything the agent produced.
func loadTrustedConfig(cfg *sandboxConfig) {
	cfg.LoopBudget = sandboxTrustedLoopBudget
	cfg.SafetyChecks = sandboxTrustedSafetyChecks
}
