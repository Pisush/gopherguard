// Package tools defines gopherguard's scoped-tool contract and concrete tools.
//
// Every tool declares its privilege scope, whether it mutates state, and
// whether it touches untrusted input. This metadata is what makes the
// trust-boundary telemetry (internal/telemetry) and the policy engine
// (internal/security) possible — it is consulted at agent-build time so a tool
// cannot silently escape the model.
//
// Design note (an ADK 2.0 gotcha): ADK discovers a tool's capabilities by
// type-asserting the concrete tool to internal interfaces (FunctionTool with
// Declaration()/Run(), and RequestProcessor with ProcessRequest()). A wrapper
// that embeds the tool.Tool *interface* forwards only the three tool.Tool
// methods and HIDES the rest, so the agent rejects it at runtime with
// "does not implement RequestProcessor()". We therefore never wrap the tool:
// ScopedTool carries the metadata *alongside* the untouched tool.Tool, and the
// registry hands the raw tool to the agent.
package tools

import "google.golang.org/adk/v2/tool"

// ScopedTool pairs an ADK tool with gopherguard's security metadata without
// wrapping (and thus without hiding) the tool. The raw Tool is passed to the
// agent unchanged; the metadata methods are consulted by the telemetry and
// policy layers.
type ScopedTool struct {
	// Tool is the underlying ADK tool, passed to the agent untouched.
	Tool tool.Tool

	scope     string
	mutating  bool
	untrusted bool
}

// Scope pairs an ADK tool with privilege metadata, producing a ScopedTool.
func Scope(t tool.Tool, privilegeScope string, mutating, touchesUntrusted bool) ScopedTool {
	return ScopedTool{Tool: t, scope: privilegeScope, mutating: mutating, untrusted: touchesUntrusted}
}

// Name returns the underlying tool's name.
func (s ScopedTool) Name() string { return s.Tool.Name() }

// PrivilegeScope reports the capability the tool exercises, e.g. "read:web",
// "write:db". Stamped onto spans as trust.privilege_scope.
func (s ScopedTool) PrivilegeScope() string { return s.scope }

// IsMutating reports whether the tool changes external state. Mutating tools
// are gated behind a human-in-the-loop confirmation.
func (s ScopedTool) IsMutating() bool { return s.mutating }

// TouchesUntrusted reports whether the tool returns external / tool-derived
// content that must be treated as untrusted downstream. Sets
// trust.untrusted_input on downstream spans.
func (s ScopedTool) TouchesUntrusted() bool { return s.untrusted }

// Registry collects scoped tools for an agent. Register only accepts
// ScopedTool, so every tool reaching an agent carries privilege metadata by
// construction — this is the registration guard.
type Registry struct {
	tools []ScopedTool
}

// NewRegistry creates an empty tool registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds scoped tools to the registry.
func (r *Registry) Register(ts ...ScopedTool) {
	r.tools = append(r.tools, ts...)
}

// Tools returns the underlying ADK tools for agent wiring. These are the raw,
// unwrapped tools so ADK's internal type assertions (FunctionTool,
// RequestProcessor) still succeed.
func (r *Registry) Tools() []tool.Tool {
	out := make([]tool.Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t.Tool)
	}
	return out
}

// Scoped returns the registered tools with their scope metadata, for the policy
// engine and telemetry to consult (e.g. by tool name).
func (r *Registry) Scoped() []ScopedTool { return r.tools }
