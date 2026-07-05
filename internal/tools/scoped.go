// Package tools defines gopherguard's scoped-tool contract and concrete tools.
//
// Every tool declares its privilege scope, whether it mutates state, and
// whether it touches untrusted input. This metadata is what makes the
// trust-boundary telemetry (internal/telemetry) and the policy engine
// (internal/security) possible — it is enforced at registration time so a tool
// cannot silently escape the model.
package tools

import "google.golang.org/adk/v2/tool"

// ScopedTool is the contract every gopherguard tool implements. It extends the
// ADK tool.Tool with the security metadata the telemetry and policy layers
// depend on.
type ScopedTool interface {
	tool.Tool

	// PrivilegeScope reports the capability the tool exercises, e.g.
	// "read:web", "write:db". Stamped onto spans as trust.privilege_scope.
	PrivilegeScope() string

	// IsMutating reports whether the tool changes external state. Mutating
	// tools are gated behind a human-in-the-loop confirmation.
	IsMutating() bool

	// TouchesUntrusted reports whether the tool returns external / tool-derived
	// content that must be treated as untrusted downstream. Sets
	// trust.untrusted_input on downstream spans.
	TouchesUntrusted() bool
}

// scoped wraps a plain ADK tool with gopherguard's security metadata. Concrete
// tools embed the wrapped tool.Tool (from functiontool.New) and set the flags.
type scoped struct {
	tool.Tool
	scope      string
	mutating   bool
	untrusted  bool
}

func (s scoped) PrivilegeScope() string { return s.scope }
func (s scoped) IsMutating() bool        { return s.mutating }
func (s scoped) TouchesUntrusted() bool  { return s.untrusted }

// Scope wraps an ADK tool with privilege metadata, producing a ScopedTool.
func Scope(t tool.Tool, privilegeScope string, mutating, touchesUntrusted bool) ScopedTool {
	return scoped{Tool: t, scope: privilegeScope, mutating: mutating, untrusted: touchesUntrusted}
}

// Registry enforces that every tool handed to an agent is a ScopedTool. This is
// the registration guard referenced in the architecture: unscoped tools are a
// compile-time impossibility here because Register only accepts ScopedTool.
type Registry struct {
	tools []ScopedTool
}

// NewRegistry creates an empty tool registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds scoped tools to the registry.
func (r *Registry) Register(ts ...ScopedTool) {
	r.tools = append(r.tools, ts...)
}

// Tools returns the registered tools as ADK tool.Tool values for agent wiring.
func (r *Registry) Tools() []tool.Tool {
	out := make([]tool.Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	return out
}

// Scoped returns the registered tools with their scope metadata intact, for the
// policy engine and telemetry to consult.
func (r *Registry) Scoped() []ScopedTool { return r.tools }
