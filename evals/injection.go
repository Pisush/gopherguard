package evals

import (
	"context"
	"fmt"
	"strings"

	"github.com/Pisush/gopherguard/internal/detect"
	"github.com/Pisush/gopherguard/internal/telemetry"
)

// expectedFirings is the regression matrix: for each OWASP pair whose
// vulnerable trace has a mapped trace-query detection, the rule IDs that MUST
// fire on it. An attack the hardened path blocks is a permanent test — if a
// refactor makes the detection stop firing on the vulnerable trace, the gate
// fails.
var expectedFirings = map[string][]string{
	"ASI01":  {"GG-DET-01", "GG-DET-04"},
	"MEMORY": {"GG-DET-05"},
}

// InjectionResistance is suite 3: injection-resistance regression. Every
// OWASP ASI pair must uphold its invariant (vulnerable compromised, hardened
// blocked), the mapped detections must fire on the vulnerable traces, and —
// the flip side — every detection rule must stay quiet on every hardened
// trace. The two fixture-backed rules (HITL bypass, loop runaway) are pinned
// with synthetic traces.
func InjectionResistance(cfg *AgentConfig, opts Options) SuiteResult {
	opts = opts.withDefaults()
	s := SuiteResult{Name: "injection-resistance"}

	pairs := opts.Registry.All()
	holding := 0
	for _, p := range pairs {
		p := p
		res := struct{ vuln, hard detect.Trace }{
			vuln: detect.Capture(func(ctx context.Context) { p.Vulnerable(ctx) }),
			hard: detect.Capture(func(ctx context.Context) { p.Hardened(ctx) }),
		}

		// Invariant: the vulnerable variant is compromised, the hardened one
		// is not. Run() executes the variants (again) for their outcomes.
		vulnOut := p.Vulnerable(context.Background())
		hardOut := p.Hardened(context.Background())
		holds := vulnOut.Compromised && !hardOut.Compromised
		if holds {
			holding++
		}
		s.Checks = append(s.Checks, check(fmt.Sprintf("pair holds: %s", p.ID), holds,
			"vulnerable compromised=%t, hardened compromised=%t", vulnOut.Compromised, hardOut.Compromised))

		// Mapped detections must fire on the vulnerable trace.
		for _, ruleID := range expectedFirings[p.ID] {
			f := ruleFinding(ruleID, res.vuln)
			s.Checks = append(s.Checks, check(fmt.Sprintf("%s fires on %s vulnerable", ruleID, p.ID), f.Fired,
				"fired=%t %s", f.Fired, f.Evidence))
		}

		// Silence invariant: NO rule may fire on a hardened trace. A firing
		// here means either the hardening regressed or a detection started
		// false-positives on the production path — both block the merge.
		var noisy []string
		for _, rr := range detect.EvaluateAll(res.hard) {
			if rr.Finding.Fired {
				noisy = append(noisy, fmt.Sprintf("%s (%s)", rr.Rule.ID, rr.Finding.Evidence))
			}
		}
		s.Checks = append(s.Checks, check(fmt.Sprintf("all rules quiet on %s hardened", p.ID), len(noisy) == 0,
			"%s", quietDetail(noisy)))
	}

	s.Checks = append(s.Checks, check("pairs holding meets gate", holding >= cfg.Gates.MinPairsHolding,
		"%d/%d pairs hold (gate %d)", holding, len(pairs), cfg.Gates.MinPairsHolding))

	s.Checks = append(s.Checks, fixtureRegressions()...)
	return s
}

func quietDetail(noisy []string) string {
	if len(noisy) == 0 {
		return "quiet"
	}
	return "fired: " + strings.Join(noisy, "; ")
}

// fixtureRegressions pins the two rules that are validated against synthetic
// fixtures rather than an OWASP pair: GG-DET-02 (HITL bypass) and GG-DET-03
// (loop runaway). Each must fire on its attack fixture and stay quiet on the
// benign twin.
func fixtureRegressions() []Check {
	var checks []Check

	bypass := detect.Capture(func(ctx context.Context) {
		_, span := telemetry.StartSpan(ctx, "db_write",
			telemetry.AttrHITLRequired(true),
			telemetry.AttrHITLResult(telemetry.HITLBypassed),
			telemetry.AttrPrivilegeScope("write:db"))
		span.End()
	})
	approved := detect.Capture(func(ctx context.Context) {
		_, span := telemetry.StartSpan(ctx, "db_write",
			telemetry.AttrHITLRequired(true),
			telemetry.AttrHITLResult(telemetry.HITLApproved),
			telemetry.AttrPrivilegeScope("write:db"))
		span.End()
	})
	f := ruleFinding("GG-DET-02", bypass)
	checks = append(checks, check("GG-DET-02 fires on hitl-bypass fixture", f.Fired, "fired=%t %s", f.Fired, f.Evidence))
	f = ruleFinding("GG-DET-02", approved)
	checks = append(checks, check("GG-DET-02 quiet on approved fixture", !f.Fired, "fired=%t %s", f.Fired, f.Evidence))

	normal := detect.Capture(func(ctx context.Context) {
		for i := 0; i < 2; i++ {
			_, span := telemetry.StartSpan(ctx, "tool.web_search")
			span.End()
		}
	})
	f = ruleFinding("GG-DET-03", normal)
	checks = append(checks, check("GG-DET-03 quiet on normal call count", !f.Fired, "fired=%t %s", f.Fired, f.Evidence))
	// The firing side of GG-DET-03 is asserted in the trajectory suite
	// ("loop detection trips past budget").

	return checks
}
