package owasp

import (
	"context"
	"strings"

	"github.com/Pisush/gopherguard/internal/telemetry"
)

// ASI03 — Agentic Identity & Privilege Abuse.
//
// Failure pattern: an agent is issued a single, over-scoped credential
// ("admin:*") and reuses it for every tool call regardless of what the task
// actually needs. A task that only ever needs to read ends up holding a
// credential that can also write and delete, so any confused-deputy moment
// (a bad instruction, a bug, an injected step) can escalate straight to a
// destructive action. The mitigation is per-tool, per-task scoped identity:
// issue the minimum scope the task needs ("read:db" for a read task) so an
// attempted write is denied by the identity itself, not by hoped-for good
// behavior downstream.
//
// This mirrors the narrative pattern behind over-privileged "refund bot"
// incidents, where a support agent's single service credential could also
// issue refunds it was never meant to touch (narrative anchor only — no real
// system, credential, or vendor is referenced).
const (
	asi03GodScope   = "admin:*" // vulnerable: one credential for every tool
	asi03ReadScope  = "read:db" // hardened: least-privilege, task-scoped
	asi03ReadQuery  = "SELECT balance FROM placeholder_accounts WHERE id = ?"
	asi03WriteQuery = "DELETE FROM placeholder_accounts WHERE id = ?"
)

func registerASI03(r *Registry) {
	r.Register(Pair{
		ID:          "ASI03",
		Risk:        "Identity / Privilege Abuse",
		ASIRef:      "OWASP ASI03 (Agentic Identity & Privilege)",
		Incident:    "over-privileged refund-bot pattern (narrative anchor only)",
		VulnPattern: "a single over-scoped credential (admin:*) is reused for every tool, so a read task can also write/delete",
		Mitigation:  "per-tool scoped identities (least privilege): the task is issued only the scope it needs",
		Vulnerable:  asi03Vulnerable,
		Hardened:    asi03Hardened,
	})
}

// asi03Vulnerable runs a read-only task holding the god-credential. Because
// the credential is scoped admin:*, an over-privileged write also succeeds —
// the read task never needed write access, but nothing stopped it.
func asi03Vulnerable(ctx context.Context) Outcome {
	readCtx, end := step(ctx, "asi03.read_task",
		telemetry.AttrPrivilegeScope(asi03GodScope))
	readAllowed := scopeAllows(asi03GodScope, asi03ReadQuery)
	end()

	// VULNERABLE: the same god-credential is reused for a write the read task
	// never should have been able to attempt.
	_, end = step(readCtx, "asi03.attempted_write",
		telemetry.AttrPrivilegeScope(asi03GodScope))
	writeAllowed := scopeAllows(asi03GodScope, asi03WriteQuery)
	end()

	return Outcome{
		Scenario:    "a read-only task runs under the agent's single admin:* credential",
		Attempted:   "use the same credential to issue a write/delete the task never needed",
		Result:      "the over-scoped credential authorized both the read and the unrelated write",
		Compromised: readAllowed && writeAllowed,
	}
}

// asi03Hardened issues an identity scoped only to what the read task needs.
// The same attempted write is denied by the identity itself.
func asi03Hardened(ctx context.Context) Outcome {
	readCtx, end := step(ctx, "asi03.read_task",
		telemetry.AttrPrivilegeScope(asi03ReadScope))
	readAllowed := scopeAllows(asi03ReadScope, asi03ReadQuery)
	end()

	// HARDENED: the task-scoped identity is reused for the attempted write and
	// is denied, because "read:db" never grants write/delete.
	_, end = step(readCtx, "asi03.attempted_write",
		telemetry.AttrPrivilegeScope(asi03ReadScope))
	writeAllowed := scopeAllows(asi03ReadScope, asi03WriteQuery)
	end()

	return Outcome{
		Scenario:    "a read-only task runs under an identity scoped only to read:db",
		Attempted:   "use the same identity to issue a write/delete the task never needed",
		Result:      "the scoped identity authorized the read but denied the unrelated write",
		Compromised: readAllowed && writeAllowed,
	}
}

// scopeAllows is a simulated authorization check: it reports whether scope
// permits the operation implied by query. No real database or credential is
// involved — this only inspects the placeholder query text.
func scopeAllows(scope, query string) bool {
	if scope == asi03GodScope {
		return true // admin:* authorizes everything — that's the vulnerability
	}
	// A scoped identity like "read:db" only authorizes read (SELECT) queries.
	verb := strings.Fields(strings.TrimSpace(query))[0]
	switch scope {
	case asi03ReadScope:
		return strings.EqualFold(verb, "SELECT")
	default:
		return false
	}
}
