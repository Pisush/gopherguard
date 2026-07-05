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
	"flag"
	"fmt"
	"os"
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
	flag.Parse()

	if !*understand {
		fmt.Fprintf(os.Stderr,
			"refusing to start: vulnerable mode is fenced.\n"+
				"re-run with --%s to acknowledge it is intentionally insecure and localhost-only.\n",
			insecureFlag)
		os.Exit(1)
	}

	// Force the fence into the environment before any agent/model wiring so
	// downstream code (M2 variants) inherits localhost-only, keyless, local Gemma.
	mustSet("GG_MODEL_MODE", "gemma")
	mustSet("GG_BIND_ADDR", "127.0.0.1")
	mustSet("GG_VULN_MODE", "1")
	os.Unsetenv("GOOGLE_API_KEY") // belt-and-suspenders: no egress even if set

	fmt.Print(banner)
	fmt.Println("vulnerable-mode variants are implemented in M2 (see docs/owasp-mapping.md).")
	fmt.Println("fence active: 127.0.0.1 only, local Gemma, no egress.")
}

func mustSet(key, value string) {
	if err := os.Setenv(key, value); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set %s: %v\n", key, err)
		os.Exit(1)
	}
}
