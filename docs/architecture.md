# Architecture

> Agents fail like distributed systems and get attacked like web apps — so bring SRE and AppSec discipline, in a language built for both.

gopherguard treats a multi-agent system as both a distributed system (which
fails the way distributed systems fail: partial failure, retries, cascading
timeouts) and an application with attack surface (which is attacked the way
web apps are attacked: injection, privilege abuse, trust-boundary violations).
The architecture below is built to make both classes of problem observable
and testable.

## Agent graph

```
                         ┌─────────────┐
                         │    User     │
                         └──────┬──────┘
                                │
                         ┌──────▼──────┐
                         │ Coordinator │   code-routed (Go if/switch),
                         └──┬───┬───┬──┘   NOT LLM-routed
                            │   │   │
              ┌─────────────┘   │   └─────────────┐
              │                 │                 │
      ┌───────▼──────┐  ┌───────▼──────┐  ┌────────▼────────┐
      │  Researcher   │  │   DB Agent   │  │     Writer      │
      │ (Google Search│  │ (MCP →       │  │                 │
      │  / egress)    │  │  Postgres)   │  │                 │
      └───────────────┘  └──────────────┘  └─────────────────┘

      (M5) Python analysis agent, reached via A2A from Coordinator
```

Routing between agents is **code-routed**: the Coordinator dispatches to
Researcher / DB Agent / Writer via explicit Go `if`/`switch` logic, not by
asking an LLM to decide which sub-agent to call. This keeps the control-flow
attack surface auditable and testable like ordinary Go code, rather than
opaque and prompt-dependent.

## Model layer

- **Gemma-local** (default) — served via Ollama on `OLLAMA_HOST`, zero
  egress, no API key required. This is what `make run` uses.
- **Gemini** (opt-in "production mode") — used when `GG_MODEL_MODE=gemini`
  and `GOOGLE_API_KEY` is set.
- A **router** selects between them per request based on cost/availability
  policy and records its decision on every span as `model.route_reason`,
  so "why did this call use Gemini instead of Gemma" is always answerable
  from telemetry alone.

## Trust-boundary telemetry

Every span that crosses a trust boundary (tool call, agent hop, memory
read/write) carries a fixed vocabulary of OTel attributes:

| Attribute | Type | Meaning |
|---|---|---|
| `trust.untrusted_input` | bool | This span processed input originating outside the trust boundary (e.g. tool output, retrieved doc, another agent's message). |
| `trust.privilege_scope` | string | The privilege scope the current operation is executing under (maps to `ScopedTool.PrivilegeScope()`). |
| `trust.hitl_required` | bool | This operation requires human-in-the-loop confirmation before proceeding. |
| `trust.hitl_result` | enum: `approved`\|`denied`\|`bypassed` | Outcome of the HITL gate, if one was required. |
| `trust.egress` | bool | This span performed (or authorized) an outbound network call beyond the local trust boundary. |
| `agent.hop` | string (`src→dest`) | Records an A2A hop between two named agents. |
| `model.route_reason` | string | Why the model router chose the model it did for this call. |
| `mem.provenance` | string | Where a piece of memory came from (e.g. `user`, `tool:web`, `agent:researcher`), used to validate against memory poisoning. |

This vocabulary is what the trace-query attack detections (M3) query against
— detections are written as queries over these attributes, not as ad hoc
log greps.

## Tool contract

All tools implement a `ScopedTool` interface:

```go
type ScopedTool interface {
    PrivilegeScope() string   // named privilege scope this tool executes under
    IsMutating() bool         // true if this tool can change state
    TouchesUntrusted() bool   // true if this tool reads/writes untrusted data
}
```

Any tool where `IsMutating()` is true requires a human-in-the-loop
confirmation gate before execution; the outcome is recorded via
`trust.hitl_required` / `trust.hitl_result` on the invoking span.

## Milestones

- **M0** — Scaffold
- **M1** — Hardened baseline agent
- **M2** — Vulnerable/hardened OWASP Agentic Top 10 pairs (see
  [owasp-mapping.md](owasp-mapping.md))
- **M3** — Trust-boundary telemetry + trace-query detections
- **M4** — Eval-gated CI/CD to Cloud Run
- **M5** — Polyglot A2A (Python analysis agent)
