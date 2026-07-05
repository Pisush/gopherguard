// Command gopherguard-vuln is the fenced launcher for vulnerable-mode labs.
//
// Vulnerable variants demonstrate failure PATTERNS for teaching and detection —
// never shippable exploits. The fence here is a hard safety boundary and is
// enforced from M0 even though the vulnerable variants themselves land in M2:
//
//   - refuses to start without --i-understand-this-is-insecure
//   - binds to 127.0.0.1 only (never a routable interface)
//   - forces local Gemma (no egress, no API key)
//   - prints a loud banner
//
// This binary is never built into a deployable image and never runs in CI/prod.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/Pisush/gopherguard/internal/detect"
	"github.com/Pisush/gopherguard/internal/owasp"
)

const insecureFlag = "i-understand-this-is-insecure"

const banner = `
╔══════════════════════════════════════════════════════════════════════╗
║  gopherguard VULNERABLE MODE — teaching lab, intentionally insecure   ║
║                                                                      ║
║  • Bound to 127.0.0.1 only. Do NOT expose to any network.            ║
║  • Forced local Gemma: no egress, no API key.                        ║
║  • Demonstrates OWASP Agentic (ASI) failure patterns for detection.  ║
║  • Contains NO working exploits or real target strings.              ║
║  • NEVER deploy this. NEVER run against real systems or data.        ║
╚══════════════════════════════════════════════════════════════════════╝
`

func main() {
	understand := flag.Bool(insecureFlag, false,
		"acknowledge that vulnerable mode is intentionally insecure and localhost-only")
	list := flag.Bool("list", false, "list the OWASP ASI vulnerable/hardened pairs and exit")
	pairID := flag.String("pair", "", "run only the vulnerable variant of this pair ID (e.g. ASI01)")
	detectMode := flag.Bool("detect", false, "run the trace-query detection demo: which rules fire on vulnerable vs hardened traces")
	flag.Parse()

	registry := owasp.DefaultRegistry()

	if *list {
		fmt.Println("gopherguard OWASP ASI pairs:")
		for _, p := range registry.All() {
			fmt.Printf("  %-12s %s\n", p.ID, p.Risk)
		}
		return
	}

	if !*understand {
		fmt.Fprintf(os.Stderr,
			"refusing to start: vulnerable mode is fenced.\n"+
				"re-run with --%s to acknowledge it is intentionally insecure and localhost-only.\n"+
				"(use --list to see the pairs without running anything.)\n",
			insecureFlag)
		os.Exit(1)
	}

	// Force the fence into the environment before running any variant so the
	// process stays localhost-only, keyless, and local-Gemma. The pairs perform
	// only simulated actions, but the fence is defense in depth.
	mustSet("GG_MODEL_MODE", "gemma")
	mustSet("GG_BIND_ADDR", "127.0.0.1")
	mustSet("GG_VULN_MODE", "1")
	os.Unsetenv("GOOGLE_API_KEY")

	fmt.Print(banner)

	ctx := context.Background()
	pairs := registry.All()
	if *pairID != "" {
		p, ok := registry.Get(*pairID)
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown pair %q (use --list)\n", *pairID)
			os.Exit(1)
		}
		pairs = []owasp.Pair{p}
	}

	if *detectMode {
		runDetectionDemo(ctx, pairs)
		return
	}

	fmt.Printf("\nrunning %d vulnerable-variant demonstration(s) (all actions simulated):\n\n", len(pairs))
	for _, p := range pairs {
		owasp.ReportVulnerable(os.Stdout, p, p.Vulnerable(ctx))
		fmt.Println()
	}
	fmt.Println("fence active: 127.0.0.1 only, local Gemma, no egress. See docs/owasp-mapping.md.")
}

// runDetectionDemo captures each pair's vulnerable and hardened traces and
// reports which trace-query detection rules fire on each — the "SIEM for agent
// traces" demo. Rules should fire on the vulnerable trace and stay quiet on the
// hardened one.
func runDetectionDemo(ctx context.Context, pairs []owasp.Pair) {
	fmt.Printf("\ntrace-query detection demo over %d pair(s):\n", len(pairs))
	fmt.Println("(rules should FIRE on the vulnerable trace and be quiet on the hardened one)")

	for _, p := range pairs {
		vulnTrace := detect.Capture(func(ctx context.Context) { p.Vulnerable(ctx) })
		hardTrace := detect.Capture(func(ctx context.Context) { p.Hardened(ctx) })

		fmt.Printf("\n[%s] %s\n", p.ID, p.Risk)
		for _, rr := range detect.EvaluateAll(vulnTrace) {
			hardFired := ruleFired(rr.Rule, hardTrace)
			if rr.Finding.Fired || hardFired {
				fmt.Printf("  %-10s vuln=%-5t hardened=%-5t  %s\n",
					rr.Rule.ID, rr.Finding.Fired, hardFired, rr.Rule.Title)
				if rr.Finding.Fired {
					fmt.Printf("             evidence: %s\n", rr.Finding.Evidence)
				}
			}
		}
	}
	fmt.Println("\nfence active: 127.0.0.1 only, local Gemma, no egress. See detections/.")
}

func ruleFired(r detect.Rule, t detect.Trace) bool {
	return r.Detect(t).Fired
}

func mustSet(key, value string) {
	if err := os.Setenv(key, value); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set %s: %v\n", key, err)
		os.Exit(1)
	}
}
