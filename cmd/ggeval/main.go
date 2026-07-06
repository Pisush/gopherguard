// Command ggeval runs gopherguard's eval suites against a YAML agent config
// and renders the gate report. It exits non-zero when the gate fails — this
// is the binary `make eval` and .github/workflows/evals.yml gate on.
//
// Usage:
//
//	ggeval [-config deploy/agent.yaml] [-compare path/to/baseline.yaml] [-markdown]
//
// -compare loads a second (baseline, typically main's) agent config and adds
// a cost-delta line to the report, so a PR that changes the routing policy
// shows its estimated cost impact.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Pisush/gopherguard/evals"
)

func main() {
	configPath := flag.String("config", "deploy/agent.yaml", "agent config under eval")
	comparePath := flag.String("compare", "", "baseline agent config for the cost delta (optional)")
	markdown := flag.Bool("markdown", false, "emit GitHub-flavored markdown instead of text")
	flag.Parse()

	// The suites are keyless by design: force the local-only model mode so a
	// developer's GG_MODEL_MODE=gemini + key cannot make an eval run depend
	// on the network.
	os.Setenv("GG_MODEL_MODE", "gemma")

	cfg, err := evals.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ggeval: %v\n", err)
		os.Exit(1)
	}

	rep := evals.Run(cfg, evals.Options{})
	cost := evals.EstimateCostPer1K(cfg)

	var baseline *float64
	if *comparePath != "" {
		if base, err := evals.Load(*comparePath); err == nil {
			b := evals.EstimateCostPer1K(base)
			baseline = &b
		} else {
			fmt.Fprintf(os.Stderr, "ggeval: baseline config skipped: %v\n", err)
		}
	}

	if *markdown {
		rep.WriteMarkdown(os.Stdout, cost, baseline)
	} else {
		rep.WriteText(os.Stdout)
		fmt.Printf("estimated model cost: $%.4f / 1k requests", cost)
		if baseline != nil {
			fmt.Printf(" (baseline $%.4f, delta %+.4f)", *baseline, cost-*baseline)
		}
		fmt.Println()
	}

	if !rep.Pass() {
		os.Exit(1)
	}
}
