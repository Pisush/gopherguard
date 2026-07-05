package detect

import (
	"fmt"
	"strings"

	"github.com/Pisush/gopherguard/internal/telemetry"
)

// Finding is the result of evaluating a rule against a trace.
type Finding struct {
	Fired    bool
	Evidence string
}

// Rule is one trace-query detection. Detect queries a captured Trace; in
// production the same logic runs as a TraceQL/SQL query over the trace store
// (see detections/ for the query equivalents).
type Rule struct {
	ID      string // e.g. "GG-DET-01"
	ASI     string // the OWASP ASI risk it catches
	Title   string
	Detect  func(Trace) Finding
	Targets string // which M2 pair (or fixture) it is validated against
}

// Rules returns the seed detection rules.
func Rules() []Rule {
	return []Rule{
		{
			ID:      "GG-DET-01",
			ASI:     "ASI01 Goal Hijack",
			Title:   "Injection→exfil chain: untrusted input followed by egress",
			Targets: "ASI01",
			Detect:  detectInjectionExfil,
		},
		{
			ID:      "GG-DET-02",
			ASI:     "Tool misuse / HITL",
			Title:   "HITL bypass: required confirmation not approved but action proceeded",
			Targets: "fixture (hitl-bypass)",
			Detect:  detectHITLBypass,
		},
		{
			ID:      "GG-DET-03",
			ASI:     "Loop / cost runaway",
			Title:   "Loop budget breach: too many identical tool spans in a session",
			Targets: "fixture (loop-runaway)",
			Detect:  detectLoopRunaway,
		},
		{
			ID:      "GG-DET-04",
			ASI:     "ASI03 Privilege abuse",
			Title:   "Privilege widening: privilege scope escalates across a session",
			Targets: "ASI01",
			Detect:  detectPrivilegeWidening,
		},
		{
			ID:      "GG-DET-05",
			ASI:     "Memory poisoning",
			Title:   "Memory taint: untrusted-provenance memory consumed by a mutating decision",
			Targets: "MEMORY",
			Detect:  detectMemoryTaint,
		},
	}
}

// RuleResult pairs a rule with its finding against a trace.
type RuleResult struct {
	Rule    Rule
	Finding Finding
}

// EvaluateAll runs every seed rule against a trace.
func EvaluateAll(t Trace) []RuleResult {
	rules := Rules()
	out := make([]RuleResult, 0, len(rules))
	for _, r := range rules {
		out = append(out, RuleResult{Rule: r, Finding: r.Detect(t)})
	}
	return out
}

// loopThreshold is the identical-tool-span count above which GG-DET-03 fires.
const loopThreshold = 5

// detectInjectionExfil fires when a span that processed untrusted input is
// followed (in the same session) by a span that performs egress — the classic
// indirect-injection→exfiltration chain (ASI01).
func detectInjectionExfil(t Trace) Finding {
	u := t.firstUntrustedIndex()
	if u < 0 {
		return Finding{}
	}
	for j := u; j < len(t.Spans); j++ {
		if v, ok := t.Spans[j].Bool(telemetry.KeyEgress); ok && v {
			evidence := fmt.Sprintf("untrusted input at %q then egress at %q", t.Spans[u].Name, t.Spans[j].Name)
			if scope, ok := t.Spans[j].Str(telemetry.KeyPrivilegeScope); ok {
				evidence += fmt.Sprintf(" under scope %q", scope)
			}
			return Finding{Fired: true, Evidence: evidence}
		}
	}
	return Finding{}
}

// detectHITLBypass fires when a span required human confirmation but the result
// was not "approved" — a gate that should have blocked the action did not.
func detectHITLBypass(t Trace) Finding {
	for _, s := range t.Spans {
		required, ok := s.Bool(telemetry.KeyHITLRequired)
		if !ok || !required {
			continue
		}
		result, _ := s.Str(telemetry.KeyHITLResult)
		if result != telemetry.HITLApproved {
			return Finding{
				Fired:    true,
				Evidence: fmt.Sprintf("span %q required HITL but result was %q", s.Name, result),
			}
		}
	}
	return Finding{}
}

// detectLoopRunaway fires when the same span name repeats more than
// loopThreshold times in a session — a loop-budget breach / cost runaway.
func detectLoopRunaway(t Trace) Finding {
	counts := make(map[string]int)
	for _, s := range t.Spans {
		counts[s.Name]++
		if counts[s.Name] > loopThreshold {
			return Finding{
				Fired:    true,
				Evidence: fmt.Sprintf("span %q repeated %d times (> %d)", s.Name, counts[s.Name], loopThreshold),
			}
		}
	}
	return Finding{}
}

// detectPrivilegeWidening fires when a session's privilege scope escalates: a
// later span runs under a strictly broader scope than an earlier one.
func detectPrivilegeWidening(t Trace) Finding {
	maxRank := -1
	var maxScope string
	for _, s := range t.Spans {
		scope, ok := s.Str(telemetry.KeyPrivilegeScope)
		if !ok {
			continue
		}
		r := scopeRank(scope)
		if maxRank >= 0 && r > maxRank {
			return Finding{
				Fired:    true,
				Evidence: fmt.Sprintf("scope widened from %q to %q", maxScope, scope),
			}
		}
		if r > maxRank {
			maxRank, maxScope = r, scope
		}
	}
	return Finding{}
}

// detectMemoryTaint fires when memory of untrusted provenance is consumed by a
// mutating (write-scoped) decision — the payoff step of memory poisoning.
func detectMemoryTaint(t Trace) Finding {
	tainted := false
	for _, s := range t.Spans {
		if prov, ok := s.Str(telemetry.KeyMemProvenance); ok && isUntrustedProvenance(prov) {
			tainted = true
		}
		if !tainted {
			continue
		}
		if scope, ok := s.Str(telemetry.KeyPrivilegeScope); ok && strings.HasPrefix(scope, "write:") {
			return Finding{
				Fired:    true,
				Evidence: fmt.Sprintf("untrusted-provenance memory consumed by mutating span %q (scope %q)", s.Name, scope),
			}
		}
	}
	return Finding{}
}

// scopeRank orders privilege scopes from least to most powerful so widening can
// be detected. Unknown scopes rank at read level.
func scopeRank(scope string) int {
	switch {
	case strings.HasPrefix(scope, "admin"):
		return 3
	case strings.HasPrefix(scope, "write:egress"), strings.HasPrefix(scope, "write:order"):
		return 2
	case strings.HasPrefix(scope, "write:"):
		return 2
	case strings.HasPrefix(scope, "read:"):
		return 1
	default:
		return 1
	}
}

// isUntrustedProvenance reports whether a mem.provenance label is non-user
// (tool/agent/external) origin, i.e. untrusted.
func isUntrustedProvenance(prov string) bool {
	return prov != "" && !strings.HasPrefix(prov, "user")
}
