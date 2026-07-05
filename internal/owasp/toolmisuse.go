package owasp

import (
	"context"
	"strings"

	"github.com/Pisush/gopherguard/internal/telemetry"
)

// Tool Misuse — command-level vs argument-level authorization.
//
// Failure pattern: an allowlist auto-approves a whole tool by name, so once a
// tool is trusted, ANY arguments pass — including ones that reach outside the
// intended boundary. The mitigation inspects the actual arguments, not just the
// command.
//
// Everything is simulated: no file is read, no command runs. The "sensitive"
// path is an obvious placeholder.
const (
	toolMisuseAllowedPrefix = "/workspace/" // arguments must stay under here
	toolMisuseSafeArg       = "/workspace/notes.txt"
	toolMisuseDangerousArg  = "/workspace/../etc/placeholder-secret" // escapes the boundary
)

func registerToolMisuse(r *Registry) {
	r.Register(Pair{
		ID:          "TOOL-MISUSE",
		Risk:        "Tool Misuse (over-broad tool authorization)",
		ASIRef:      "OWASP ASI Tool Misuse",
		Incident:    "Cursor CVE-2026-22708 (narrative anchor only)",
		VulnPattern: "command-level allowlist auto-approves the whole tool, so any argument passes",
		Mitigation:  "argument-level policy: authorize the actual arguments, not just the command name",
		Vulnerable:  toolMisuseVulnerable,
		Hardened:    toolMisuseHardened,
	})
}

// commandAllowlist is the vulnerable, command-level allowlist: it trusts a tool
// by name and ignores arguments entirely.
var commandAllowlist = map[string]bool{"file_read": true}

// toolMisuseVulnerable auto-approves file_read by name and then "reads" a path
// that escapes the intended boundary. Simulated — no real file access.
func toolMisuseVulnerable(ctx context.Context) Outcome {
	arg := toolMisuseDangerousArg
	_, end := step(ctx, "toolmisuse.invoke",
		telemetry.AttrPrivilegeScope("read:fs"),
		telemetry.AttrHITLRequired(false))
	defer end()

	approved := commandAllowlist["file_read"] // command-level: args ignored
	escaped := false
	if approved {
		escaped = pathEscapesBoundary(arg) // happens anyway — no arg check
	}

	return Outcome{
		Scenario:    "agent calls file_read; an allowlist trusts the tool by name",
		Attempted:   "read a path that escapes the intended /workspace boundary",
		Result:      "command-level allowlist approved the tool; the escaping argument was never checked",
		Compromised: approved && escaped,
	}
}

// toolMisuseHardened applies an argument-level policy: the tool may be allowed,
// but the specific path argument is validated against the boundary and denied.
func toolMisuseHardened(ctx context.Context) Outcome {
	arg := toolMisuseDangerousArg
	_, end := step(ctx, "toolmisuse.invoke",
		telemetry.AttrPrivilegeScope("read:fs"),
		telemetry.AttrHITLRequired(false))
	defer end()

	// Argument-level check: the path must stay under the allowed prefix.
	allowed := argAllowed(arg)

	return Outcome{
		Scenario:    "agent calls file_read; an argument-level policy validates the path",
		Attempted:   "read a path that escapes the intended /workspace boundary",
		Result:      "argument policy rejected the escaping path even though the tool itself is allowed",
		Compromised: allowed,
	}
}

// pathEscapesBoundary reports whether a path leaves the allowed prefix (e.g. via
// a traversal segment). Purely lexical and simulated.
func pathEscapesBoundary(path string) bool {
	return strings.Contains(path, "..") || !strings.HasPrefix(path, toolMisuseAllowedPrefix)
}

// argAllowed is the hardened argument policy: the path must be under the allowed
// prefix and contain no traversal.
func argAllowed(path string) bool {
	return strings.HasPrefix(path, toolMisuseAllowedPrefix) && !strings.Contains(path, "..")
}
