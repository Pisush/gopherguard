// Package owasp holds gopherguard's OWASP Agentic Security Initiative (ASI)
// vulnerable/hardened pairs. Each pair demonstrates a FAILURE PATTERN and its
// mitigation — never a shippable exploit. Scenarios use safe, illustrative
// inputs only: no working payloads, no real target strings, and any "egress" or
// "exfiltration" is simulated (see Sink) and never performed.
//
// Every variant runs inside trust-boundary spans (internal/telemetry) so the M3
// detections can later fire on the vulnerable variant's trace and stay quiet on
// the hardened one. That trace shape is the whole point of the pairs.
package owasp

import (
	"context"
	"fmt"
	"sort"

	"github.com/Pisush/gopherguard/internal/telemetry"

	"go.opentelemetry.io/otel/attribute"
)

// Outcome is the result of running one variant of a pair.
type Outcome struct {
	// Scenario is a one-line description of the safe, illustrative situation.
	Scenario string
	// Attempted is what the attack pattern tries to achieve.
	Attempted string
	// Result is what actually happened in this variant.
	Result string
	// Compromised is true when the attack succeeded (the vulnerable variant)
	// and false when the mitigation blocked it (the hardened variant).
	Compromised bool
}

// Variant runs one side of a pair (vulnerable or hardened) and reports the
// outcome. It emits trust-boundary telemetry as a side effect.
type Variant func(ctx context.Context) Outcome

// Pair is one OWASP ASI risk demonstrated as a vulnerable/hardened couple.
type Pair struct {
	ID          string // e.g. "ASI01"
	Risk        string // e.g. "Goal Hijack / Prompt Injection"
	ASIRef      string // OWASP ASI reference
	Incident    string // narrative-only incident anchor (no payloads)
	VulnPattern string // the failure pattern the vulnerable variant shows
	Mitigation  string // the hardened variant's mitigation
	Vulnerable  Variant
	Hardened    Variant
}

// Registry holds the registered pairs, keyed by ID.
type Registry struct {
	pairs map[string]Pair
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{pairs: make(map[string]Pair)} }

// Register adds a pair. It panics on a duplicate ID or a nil variant, since
// pairs are registered at startup from static definitions.
func (r *Registry) Register(p Pair) {
	if p.ID == "" || p.Vulnerable == nil || p.Hardened == nil {
		panic(fmt.Sprintf("owasp: invalid pair %q (needs ID + both variants)", p.ID))
	}
	if _, dup := r.pairs[p.ID]; dup {
		panic(fmt.Sprintf("owasp: duplicate pair ID %q", p.ID))
	}
	r.pairs[p.ID] = p
}

// Get returns a pair by ID.
func (r *Registry) Get(id string) (Pair, bool) {
	p, ok := r.pairs[id]
	return p, ok
}

// All returns the pairs sorted by ID.
func (r *Registry) All() []Pair {
	out := make([]Pair, 0, len(r.pairs))
	for _, p := range r.pairs {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// DefaultRegistry builds the registry of all implemented pairs. Each pair's
// constructor registers itself here.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	registerASI01(r)
	registerASI03(r)
	registerToolMisuse(r)
	registerSandbox(r)
	registerMemoryPoisoning(r)
	registerInterAgentTrust(r)
	registerConfigVector(r)
	registerSupplyChain(r)
	return r
}

// step starts a child span for one step of a demonstration and stamps the given
// trust attributes on it. Callers defer the returned end func.
func step(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, func()) {
	ctx, span := telemetry.StartSpan(ctx, name, attrs...)
	return ctx, func() { span.End() }
}
