package owasp

import (
	"context"
	"testing"
)

// TestPairsUpholdInvariant is the core M2 check: for every registered pair, the
// vulnerable variant must be compromised and the hardened variant must not be.
// A pair that fails this is not demonstrating its risk/mitigation.
func TestPairsUpholdInvariant(t *testing.T) {
	r := DefaultRegistry()
	results := RunAll(context.Background(), r)

	if len(results) != 8 {
		t.Fatalf("expected 8 pairs, got %d", len(results))
	}

	for _, res := range results {
		if !res.Vulnerable.Compromised {
			t.Errorf("[%s] vulnerable variant must be compromised, but was not", res.Pair.ID)
		}
		if res.Hardened.Compromised {
			t.Errorf("[%s] hardened variant must NOT be compromised, but was", res.Pair.ID)
		}
		if !res.Holds() {
			t.Errorf("[%s] invariant does not hold", res.Pair.ID)
		}
	}
}

// TestPairsAreDescribed verifies every pair carries the metadata the
// owasp-mapping index and the launchers rely on.
func TestPairsAreDescribed(t *testing.T) {
	for _, p := range DefaultRegistry().All() {
		if p.ID == "" || p.Risk == "" || p.ASIRef == "" || p.Incident == "" ||
			p.VulnPattern == "" || p.Mitigation == "" {
			t.Errorf("pair %q is missing required metadata: %+v", p.ID, p)
		}
	}
}

// TestRegistryRejectsDuplicate ensures the registry guards against duplicate IDs.
func TestRegistryRejectsDuplicate(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate pair ID")
		}
	}()
	r := NewRegistry()
	p := Pair{ID: "X", Vulnerable: func(context.Context) Outcome { return Outcome{} }, Hardened: func(context.Context) Outcome { return Outcome{} }}
	r.Register(p)
	r.Register(p) // must panic
}
