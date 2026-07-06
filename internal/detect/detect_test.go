package detect

import (
	"context"
	"testing"

	"github.com/Pisush/gopherguard/internal/owasp"
	"github.com/Pisush/gopherguard/internal/telemetry"
)

// capturePair runs one variant of an M2 pair under a recording provider and
// returns its trace.
func capturePair(t *testing.T, id string, hardened bool) Trace {
	t.Helper()
	p, ok := owasp.DefaultRegistry().Get(id)
	if !ok {
		t.Fatalf("pair %q not found", id)
	}
	variant := p.Vulnerable
	if hardened {
		variant = p.Hardened
	}
	return Capture(func(ctx context.Context) { variant(ctx) })
}

// TestInjectionExfilOnASI01 — GG-DET-01 fires on the ASI01 vulnerable trace
// (untrusted read → egress) and is quiet on the hardened trace.
func TestInjectionExfilOnASI01(t *testing.T) {
	if f := detectInjectionExfil(capturePair(t, "ASI01", false)); !f.Fired {
		t.Error("GG-DET-01 must fire on ASI01 vulnerable trace")
	}
	if f := detectInjectionExfil(capturePair(t, "ASI01", true)); f.Fired {
		t.Errorf("GG-DET-01 must be quiet on ASI01 hardened trace, but fired: %s", f.Evidence)
	}
}

// TestPrivilegeWideningOnASI01 — GG-DET-04 fires when scope escalates
// (read:web → write:egress) in the ASI01 vulnerable trace, quiet on hardened.
func TestPrivilegeWideningOnASI01(t *testing.T) {
	if f := detectPrivilegeWidening(capturePair(t, "ASI01", false)); !f.Fired {
		t.Error("GG-DET-04 must fire on ASI01 vulnerable trace")
	}
	if f := detectPrivilegeWidening(capturePair(t, "ASI01", true)); f.Fired {
		t.Errorf("GG-DET-04 must be quiet on ASI01 hardened trace, but fired: %s", f.Evidence)
	}
}

// TestMemoryTaintOnMemoryPair — GG-DET-05 fires when untrusted-provenance
// memory is consumed by a mutating decision (MEMORY vulnerable), quiet when the
// hardened decision only reads.
func TestMemoryTaintOnMemoryPair(t *testing.T) {
	if f := detectMemoryTaint(capturePair(t, "MEMORY", false)); !f.Fired {
		t.Error("GG-DET-05 must fire on MEMORY vulnerable trace")
	}
	if f := detectMemoryTaint(capturePair(t, "MEMORY", true)); f.Fired {
		t.Errorf("GG-DET-05 must be quiet on MEMORY hardened trace, but fired: %s", f.Evidence)
	}
}

// TestHITLBypass — GG-DET-02 fires on a trace where a HITL-required action was
// not approved but proceeded, quiet when it was approved.
func TestHITLBypass(t *testing.T) {
	vuln := Capture(func(ctx context.Context) {
		_, span := telemetry.StartSpan(ctx, "db_write",
			telemetry.AttrHITLRequired(true),
			telemetry.AttrHITLResult(telemetry.HITLBypassed),
			telemetry.AttrPrivilegeScope("write:db"))
		span.End()
	})
	if f := detectHITLBypass(vuln); !f.Fired {
		t.Error("GG-DET-02 must fire when HITL was required but bypassed")
	}

	ok := Capture(func(ctx context.Context) {
		_, span := telemetry.StartSpan(ctx, "db_write",
			telemetry.AttrHITLRequired(true),
			telemetry.AttrHITLResult(telemetry.HITLApproved),
			telemetry.AttrPrivilegeScope("write:db"))
		span.End()
	})
	if f := detectHITLBypass(ok); f.Fired {
		t.Errorf("GG-DET-02 must be quiet when HITL was approved, but fired: %s", f.Evidence)
	}
}

// TestLoopRunaway — GG-DET-03 fires when identical tool spans exceed the loop
// budget, quiet for a normal number of calls.
func TestLoopRunaway(t *testing.T) {
	vuln := Capture(func(ctx context.Context) {
		for i := 0; i < loopThreshold+2; i++ {
			_, span := telemetry.StartSpan(ctx, "tool.web_search")
			span.End()
		}
	})
	if f := detectLoopRunaway(vuln); !f.Fired {
		t.Error("GG-DET-03 must fire when a tool span repeats past the loop budget")
	}

	ok := Capture(func(ctx context.Context) {
		for i := 0; i < 2; i++ {
			_, span := telemetry.StartSpan(ctx, "tool.web_search")
			span.End()
		}
	})
	if f := detectLoopRunaway(ok); f.Fired {
		t.Errorf("GG-DET-03 must be quiet for a normal call count, but fired: %s", f.Evidence)
	}
}

// TestAllRulesHaveMetadata guards the rule table.
func TestAllRulesHaveMetadata(t *testing.T) {
	rules := Rules()
	if len(rules) != 5 {
		t.Fatalf("expected 5 seed rules, got %d", len(rules))
	}
	for _, r := range rules {
		if r.ID == "" || r.ASI == "" || r.Title == "" || r.Detect == nil || r.Targets == "" {
			t.Errorf("rule %q missing metadata", r.ID)
		}
	}
}
