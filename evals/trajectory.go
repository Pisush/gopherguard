package evals

import (
	"context"
	"fmt"
	"strings"

	"github.com/Pisush/gopherguard/internal/detect"
	"github.com/Pisush/gopherguard/internal/telemetry"
)

// routeToAgent maps the coordinator's route labels to the agent each graph
// edge lands on (internal/agents.BuildGraph). The trajectory suite uses it to
// assert every golden route terminates at an agent the config declares.
var routeToAgent = map[string]string{
	"research": "researcher",
	"data":     "dbagent",
	"write":    "writer",
}

// Trajectory is suite 2: the agent takes a sane path and stays within the
// config's budgets. It checks captured hardened traces against the step /
// loop / hop budgets, that the loop budget cannot drift from the GG-DET-03
// detection, and that every golden prompt's route lands on a configured
// agent in a two-step (coordinator -> agent) path.
func Trajectory(cfg *AgentConfig, opts Options) SuiteResult {
	opts = opts.withDefaults()
	s := SuiteResult{Name: "trajectory"}

	// The deployed loop budget and the detection's threshold must agree, or
	// production would tolerate loops the detection alarms on (or vice versa).
	s.Checks = append(s.Checks, check("loop budget matches GG-DET-03", cfg.Budgets.LoopThreshold == detect.LoopThreshold,
		"config loop_threshold=%d, detect.LoopThreshold=%d", cfg.Budgets.LoopThreshold, detect.LoopThreshold))

	// The loop detection must actually fire past the budget (wired, not
	// decorative): a synthetic runaway one past the threshold must trip it.
	runaway := detect.Capture(func(ctx context.Context) {
		for i := 0; i < detect.LoopThreshold+1; i++ {
			_, span := telemetry.StartSpan(ctx, "tool.web_search")
			span.End()
		}
	})
	f := ruleFinding("GG-DET-03", runaway)
	s.Checks = append(s.Checks, check("loop detection trips past budget", f.Fired,
		"synthetic %d identical spans: fired=%t %s", detect.LoopThreshold+1, f.Fired, f.Evidence))

	// Every hardened (production-path) trace must fit the session budgets.
	for _, p := range opts.Registry.All() {
		p := p
		tr := detect.Capture(func(ctx context.Context) { p.Hardened(ctx) })
		steps := len(tr.Spans)
		hops := countAgentHops(tr)
		name := fmt.Sprintf("budgets: %s hardened", p.ID)
		switch {
		case steps > cfg.Budgets.MaxStepsPerSession:
			s.Checks = append(s.Checks, check(name, false,
				"%d spans > max_steps_per_session %d", steps, cfg.Budgets.MaxStepsPerSession))
		case hops > cfg.Budgets.MaxAgentHops:
			s.Checks = append(s.Checks, check(name, false,
				"%d agent hops > max_agent_hops %d", hops, cfg.Budgets.MaxAgentHops))
		default:
			s.Checks = append(s.Checks, check(name, true, "%d spans, %d hops", steps, hops))
		}
	}

	// Golden-path sanity: for each golden prompt, simulate the coordinator
	// hop (classify -> stamp route -> hand off) and assert the trace is the
	// expected two-step path onto an agent the config actually declares.
	s.Checks = append(s.Checks, goldenPaths(cfg, opts.Classifier)...)
	return s
}

// goldenPaths simulates the coordinator session for each golden prompt and
// checks the path shape: session -> coordinator -> exactly one configured
// agent, one hop, within budget.
func goldenPaths(cfg *AgentConfig, classify func(string) string) []Check {
	goldens, err := goldenRoutes()
	if err != nil {
		return []Check{check("golden paths", false, "%v", err)}
	}
	var checks []Check
	for _, g := range goldens {
		route := classify(g.Prompt)
		agentName, known := routeToAgent[route]
		name := fmt.Sprintf("path: %q", g.Prompt)
		if !known {
			checks = append(checks, check(name, false, "route %q has no graph edge", route))
			continue
		}
		if _, ok := cfg.agent(agentName); !ok {
			checks = append(checks, check(name, false,
				"route %q lands on %q, which the config does not declare", route, agentName))
			continue
		}
		tr := simulateSession(g.Prompt, route, agentName, classify)
		hops := countAgentHops(tr)
		switch {
		case len(tr.Spans) > cfg.Budgets.MaxStepsPerSession:
			checks = append(checks, check(name, false,
				"%d spans > max_steps_per_session %d", len(tr.Spans), cfg.Budgets.MaxStepsPerSession))
		case hops != 1:
			checks = append(checks, check(name, false, "expected exactly 1 agent hop, got %d", hops))
		default:
			checks = append(checks, check(name, true, "coordinator->%s, %d spans", agentName, len(tr.Spans)))
		}
	}
	return checks
}

// simulateSession captures the deterministic slice of a session: the
// coordinator classifies and stamps model.route_reason, then hands off to the
// routed agent with an agent.hop span — the same shape BuildGraph produces,
// minus the model call (keyless).
func simulateSession(prompt, route, agentName string, classify func(string) string) detect.Trace {
	return detect.Capture(func(ctx context.Context) {
		coordCtx, coord := telemetry.StartSpan(ctx, "coordinator",
			telemetry.AttrModelRouteReason("code:"+route))
		_ = classify(prompt) // the decision under trace
		_, hop := telemetry.StartSpan(coordCtx, "agent."+agentName,
			telemetry.AttrAgentHop("coordinator->"+agentName))
		hop.End()
		coord.End()
	})
}

// countAgentHops counts spans carrying an agent.hop attribute.
func countAgentHops(t detect.Trace) int {
	n := 0
	for _, s := range t.Spans {
		if v, ok := s.Str(telemetry.KeyAgentHop); ok && strings.Contains(v, "->") {
			n++
		}
	}
	return n
}

// ruleFinding runs the detection rule with the given ID against a trace.
func ruleFinding(id string, t detect.Trace) detect.Finding {
	for _, r := range detect.Rules() {
		if r.ID == id {
			return r.Detect(t)
		}
	}
	return detect.Finding{Evidence: fmt.Sprintf("rule %s not found", id)}
}
