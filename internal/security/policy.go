// Package security holds gopherguard's policy engine: least-privilege scope
// enforcement (M1) and, later, argument-level allowlists and A2A message
// validation (M2). The design principle is least privilege by construction —
// an agent may only hold tools whose scope it was explicitly granted.
package security

import (
	"fmt"
	"strings"

	"github.com/Pisush/gopherguard/internal/tools"
)

// Policy declares the privilege scopes an agent is allowed to exercise. It is
// the least-privilege boundary: a tool whose scope is not granted cannot be
// registered to the agent.
type Policy struct {
	// Agent is the agent this policy governs (for error messages).
	Agent string
	// AllowedScopes is the set of privilege scopes the agent may use, e.g.
	// {"read:web"} for the researcher. A tool's PrivilegeScope() must be in
	// this set.
	AllowedScopes map[string]bool
}

// NewPolicy builds a policy granting exactly the given scopes.
func NewPolicy(agent string, scopes ...string) Policy {
	allowed := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		allowed[s] = true
	}
	return Policy{Agent: agent, AllowedScopes: allowed}
}

// Authorize verifies every tool's scope is granted by the policy, returning the
// tools on success. It fails closed: any ungranted scope is an error, so an
// over-scoped tool can never reach an agent. This is the least-privilege guard
// referenced in the architecture.
func (p Policy) Authorize(ts ...tools.ScopedTool) ([]tools.ScopedTool, error) {
	for _, t := range ts {
		if !p.AllowedScopes[t.PrivilegeScope()] {
			return nil, fmt.Errorf("policy: agent %q is not granted scope %q required by tool %q (allowed: %s)",
				p.Agent, t.PrivilegeScope(), t.Name(), p.scopeList())
		}
	}
	return ts, nil
}

func (p Policy) scopeList() string {
	ss := make([]string, 0, len(p.AllowedScopes))
	for s := range p.AllowedScopes {
		ss = append(ss, s)
	}
	return strings.Join(ss, ", ")
}

// ArgumentPolicy is the seam for M2's tool-misuse hardening: argument-level
// (not command-level) allowlisting. A command-level allowlist that auto-approves
// a whole tool is the vulnerable pattern (Cursor CVE anchor); the hardened form
// inspects the actual arguments. M1 ships the interface and a permissive
// default; M2 supplies real rules per tool.
type ArgumentPolicy interface {
	// AllowArgs reports whether a specific invocation of tool `name` with the
	// given raw arguments is permitted, and why not if denied.
	AllowArgs(name string, args map[string]any) (allowed bool, reason string)
}

// AllowAll is the permissive default argument policy used in M1.
type AllowAll struct{}

// AllowArgs always allows. Replaced by concrete argument rules in M2.
func (AllowAll) AllowArgs(string, map[string]any) (bool, string) { return true, "" }
