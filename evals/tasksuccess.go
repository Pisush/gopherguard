package evals

import (
	"context"
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"github.com/Pisush/gopherguard/internal/agents"
	"github.com/Pisush/gopherguard/internal/model"
	"github.com/Pisush/gopherguard/internal/tools"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/golden_routes.yaml
var goldenRoutesYAML []byte

// goldenRoute is one golden routing case.
type goldenRoute struct {
	Prompt string `yaml:"prompt"`
	Expect string `yaml:"expect"`
}

type goldenRouteFile struct {
	Routes []goldenRoute `yaml:"routes"`
}

// goldenRoutes returns the embedded golden routing set.
func goldenRoutes() ([]goldenRoute, error) {
	var f goldenRouteFile
	if err := yaml.Unmarshal(goldenRoutesYAML, &f); err != nil {
		return nil, fmt.Errorf("golden routes: %w", err)
	}
	if len(f.Routes) == 0 {
		return nil, fmt.Errorf("golden routes: empty set")
	}
	return f.Routes, nil
}

// TaskSuccess is suite 1: golden outputs, tolerance-graded. It checks that
// the deterministic pieces of the agent do what the config says they do —
// routing goldens, keyless graph assembly, tool grants, and the privacy
// routing invariant. All offline; no model call is made.
func TaskSuccess(cfg *AgentConfig, opts Options) SuiteResult {
	opts = opts.withDefaults()
	s := SuiteResult{Name: "task-success"}

	s.Checks = append(s.Checks, routingGoldens(cfg, opts.Classifier))
	s.Checks = append(s.Checks, graphAssembles())
	s.Checks = append(s.Checks, toolGrantsMatch(cfg)...)
	s.Checks = append(s.Checks, privateStaysLocal())
	return s
}

// routingGoldens grades the classifier against the golden set. Tolerance-
// graded: the pass fraction must reach gates.routing_pass_rate, so a single
// borderline golden can be tolerated by policy while a real regression fails.
func routingGoldens(cfg *AgentConfig, classify func(string) string) Check {
	goldens, err := goldenRoutes()
	if err != nil {
		return check("routing goldens", false, "%v", err)
	}
	var failures []string
	for _, g := range goldens {
		if got := classify(g.Prompt); got != g.Expect {
			failures = append(failures, fmt.Sprintf("%q -> %q (want %q)", g.Prompt, got, g.Expect))
		}
	}
	score := float64(len(goldens)-len(failures)) / float64(len(goldens))
	pass := score >= cfg.Gates.RoutingPassRate
	detail := fmt.Sprintf("score %.2f (gate %.2f, %d/%d golden prompts)",
		score, cfg.Gates.RoutingPassRate, len(goldens)-len(failures), len(goldens))
	if len(failures) > 0 {
		detail += "; misroutes: " + strings.Join(failures, "; ")
	}
	return check("routing goldens", pass, "%s", detail)
}

// graphAssembles verifies the full hardened graph builds keyless: least-
// privilege authorization, node wiring, and edges all succeed with the
// local-default model (the router degrades to Gemma when no key is present).
func graphAssembles() Check {
	root, err := agents.BuildGraph(context.Background())
	if err != nil {
		return check("graph assembles keyless", false, "BuildGraph: %v", err)
	}
	return check("graph assembles keyless", true, "root agent %q", root.Name())
}

// knownTools builds the real scoped tools and indexes them by name, so the
// config's grants can be compared against what the code actually enforces.
func knownTools() (map[string]tools.ScopedTool, error) {
	web, err := tools.NewWebSearch()
	if err != nil {
		return nil, err
	}
	db := tools.NewInMemoryDB()
	dbQuery, err := tools.NewDBQuery(db)
	if err != nil {
		return nil, err
	}
	dbWrite, err := tools.NewDBWrite(db)
	if err != nil {
		return nil, err
	}
	out := make(map[string]tools.ScopedTool)
	for _, st := range []tools.ScopedTool{web, dbQuery, dbWrite} {
		out[st.Name()] = st
	}
	return out, nil
}

// toolGrantsMatch checks, per configured agent, that the granted tools exist
// and that the config's scope list exactly matches the scopes the code
// grants those tools — so config and code cannot drift apart in either
// direction (a scope granted in YAML but not in code, or vice versa).
func toolGrantsMatch(cfg *AgentConfig) []Check {
	known, err := knownTools()
	if err != nil {
		return []Check{check("tool grants", false, "building tools: %v", err)}
	}
	var checks []Check
	for _, a := range cfg.Agents {
		name := fmt.Sprintf("tool grants: %s", a.Name)
		scopeSet := make(map[string]bool)
		var missing []string
		for _, tn := range a.Tools {
			st, ok := known[tn]
			if !ok {
				missing = append(missing, tn)
				continue
			}
			scopeSet[st.PrivilegeScope()] = true
		}
		if len(missing) > 0 {
			checks = append(checks, check(name, false, "unknown tools %v", missing))
			continue
		}
		want := setOf(a.Scopes)
		if !sameSet(scopeSet, want) {
			checks = append(checks, check(name, false,
				"config scopes %v != code-granted scopes %v", sorted(want), sorted(scopeSet)))
			continue
		}
		checks = append(checks, check(name, true, "tools %v ⇒ scopes %v", a.Tools, sorted(scopeSet)))
	}
	return checks
}

// privateStaysLocal asserts the router's privacy invariant in whatever
// environment the evals run: a task hinted Private must never route to the
// remote model, regardless of mode or key availability.
func privateStaysLocal() Check {
	r := model.NewRouter(context.Background())
	d := r.Route(model.TaskHint{Private: true, HardReasoning: true})
	if d.Reason == model.ReasonHardReasoning {
		return check("private stays local", false,
			"a Private task routed to the remote model (reason %q)", d.Reason)
	}
	return check("private stays local", true, "route reason %q (mode %s)", d.Reason, r.Mode())
}

func setOf(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
