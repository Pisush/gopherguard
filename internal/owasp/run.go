package owasp

import (
	"context"
	"fmt"
	"io"
)

// Result pairs a run of both variants of a Pair for reporting.
type Result struct {
	Pair       Pair
	Vulnerable Outcome
	Hardened   Outcome
}

// Run executes both variants of a pair under their own spans and returns the
// outcomes.
func Run(ctx context.Context, p Pair) Result {
	return Result{
		Pair:       p,
		Vulnerable: p.Vulnerable(ctx),
		Hardened:   p.Hardened(ctx),
	}
}

// RunAll runs every registered pair (both variants) and returns the results.
func RunAll(ctx context.Context, r *Registry) []Result {
	pairs := r.All()
	results := make([]Result, 0, len(pairs))
	for _, p := range pairs {
		results = append(results, Run(ctx, p))
	}
	return results
}

// Holds reports whether the pair upholds the core invariant: the vulnerable
// variant is compromised and the hardened variant is not. A pair that fails
// this is not demonstrating anything.
func (res Result) Holds() bool {
	return res.Vulnerable.Compromised && !res.Hardened.Compromised
}

// ReportVulnerable prints only the vulnerable variant of a pair (used by the
// fenced vulnerable-mode launcher). It never prints real payloads — Outcome
// fields are descriptive text only.
func ReportVulnerable(w io.Writer, p Pair, o Outcome) {
	fmt.Fprintf(w, "[%s] %s\n", p.ID, p.Risk)
	fmt.Fprintf(w, "  ASI ref:   %s\n", p.ASIRef)
	fmt.Fprintf(w, "  incident:  %s\n", p.Incident)
	fmt.Fprintf(w, "  pattern:   %s\n", p.VulnPattern)
	fmt.Fprintf(w, "  scenario:  %s\n", o.Scenario)
	fmt.Fprintf(w, "  attempted: %s\n", o.Attempted)
	fmt.Fprintf(w, "  result:    %s\n", o.Result)
	fmt.Fprintf(w, "  COMPROMISED: %t (mitigation: %s)\n", o.Compromised, p.Mitigation)
}

// ReportContrast prints both variants side by side (used by the hardened
// launcher / docs) to show the mitigation working.
func ReportContrast(w io.Writer, res Result) {
	fmt.Fprintf(w, "[%s] %s\n", res.Pair.ID, res.Pair.Risk)
	fmt.Fprintf(w, "  vulnerable → compromised=%t: %s\n", res.Vulnerable.Compromised, res.Vulnerable.Result)
	fmt.Fprintf(w, "  hardened   → compromised=%t: %s\n", res.Hardened.Compromised, res.Hardened.Result)
	fmt.Fprintf(w, "  invariant holds: %t\n", res.Holds())
}
