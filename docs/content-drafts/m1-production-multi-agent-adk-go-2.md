# Building a production multi-agent system in ADK Go 2.0

*Draft — gopherguard milestone M1. Content draft for engineer-to-engineer publication; unverified claims are marked inline with `<!-- VERIFY -->`.*

M0 was scaffolding: pin the toolchain, wire up a keyless local model, get one agent talking. M1 is where gopherguard stops being a demo and starts being a system — a full agent graph with a coordinator, a researcher, a database agent, and a writer, wired together with deterministic routing, first-class telemetry, and human-in-the-loop gates on anything that mutates state.

The thesis hasn't changed since M0, but M1 is where it starts to bite: **agents fail like distributed systems and get attacked like web apps — so bring SRE and AppSec discipline, in a language built for both.** This post is about what that discipline looks like in ADK Go 2.0's graph API.

## Why a graph, not a chat of agents

A lot of multi-agent frameworks model the system as agents talking to agents in a loop, with an LLM deciding at each turn who talks next. That's expedient to prototype and miserable to operate. You can't unit-test "the model decided to call the database agent." You can't put a breakpoint on it. You can't bound its worst-case token spend, and you can't explain to an auditor why a support ticket triggered a write to production data.

ADK Go 2.0 gives you an actual graph: nodes (`workflow.NewFunctionNode`, `workflow.NewAgentNode`, `workflow.NewJoinNode`), edges (`workflow.NewEdgeBuilder()`), and an explicit entry point (`workflow.Start`). A graph is a piece of code with a shape you can read, diff, and review. That shape is the whole point.

## Code-routed edges: routing is not a model's job

The detail that matters most in gopherguard's design: **routing decisions are made by Go code, not by an LLM call.** The coordinator is a `FunctionNode`, not an `AgentNode` — it runs plain Go, inspects the incoming request, and emits a route as data. Edges declared with `StringRoute("x")` fire when `"x"` shows up in the event's `Routes` slice. No token spend, no latency, no probabilistic drift, and — critically — a routing decision you can log, replay, and unit-test like any other branch in your codebase.

```go
func routeRequest(ctx context.Context, in *session.Event) (*session.Event, error) {
    switch {
    case looksLikeDBQuery(in.Text):
        return &session.Event{Routes: []string{"dbagent"}}, nil
    case looksLikeResearchQuery(in.Text):
        return &session.Event{Routes: []string{"researcher"}}, nil
    default:
        return &session.Event{Routes: []string{"writer"}}, nil
    }
}

edges := workflow.NewEdgeBuilder().
    Add(workflow.Start, coordinator).
    AddRoutes(coordinator, map[string]workflow.Node{
        "dbagent":    dbAgentNode,
        "researcher": researcherNode,
        "writer":     writerNode,
    })
```

Compare that to an LLM-routed design, where the same decision costs a model call, adds nondeterministic latency, and leaves you writing prompt-engineering incantations to keep the router from occasionally sending a database write query to the summarizer. Code-routed edges aren't a performance optimization bolted on afterward — they're a correctness and auditability decision made up front. When something in production routes to the wrong agent, you want a stack trace, not a hypothesis about what the model was "thinking."

That's not to say LLMs have no place in the graph — the researcher, dbagent, and writer nodes are themselves backed by models, wrapped as `AgentNode`s via `workflow.NewAgentNode`. The distinction gopherguard draws is: **the model reasons inside a node; Go decides which node runs next.** Fan-out and fan-in (`AddFanOut` / `AddFanIn`) exist for the cases where multiple agents genuinely need to run concurrently and converge — but the decision of whether to fan out is still code.

## The four-agent shape

M1's graph has four agents, each with a narrow job:

- **coordinator** — a `FunctionNode` that classifies the incoming request and routes it. No model call, no tools, no state beyond the routing logic itself.
- **researcher** — an `AgentNode` with read-only web/document tools. Its job is to gather context, not to act on it.
- **dbagent** — an `AgentNode` scoped to the data layer. This is the one agent that can mutate anything, and every mutating tool it holds requires HITL confirmation (more below).
- **writer** — an `AgentNode` that synthesizes a final response from whatever the researcher or dbagent produced. It has no tools at all — its only job is composition.

`workflowagent.New(workflowagent.Config{Name, Description, Edges, SubAgents})` assembles the graph into a single agent the rest of the system can treat as one unit — the internal fan-out is invisible to whatever calls it.

## Least-privilege tool scoping

Each agent gets exactly the tools its role requires, and nothing more. The researcher has no database tools; the dbagent has no arbitrary web-fetch tool; the writer has none at all. This isn't a style preference — it's the same reasoning as IAM scoping in cloud infrastructure, applied to an agent's tool list. If a prompt injection compromises the researcher's reasoning, the blast radius is "it can fetch more documents," not "it can write to the database." Scoping tools per-agent turns a single compromised agent into a contained incident instead of a full-system one.

This is also why the graph shape matters: because routing is deterministic code and not model discretion, the set of tools reachable from any given user input is a static, auditable property of the graph — not something that depends on what an LLM decided to improvise that turn.

## Telemetry and HITL are first-class, not bolted on

Two things are wired into the graph from the start, not added after an incident:

**Telemetry.** Every span carries a fixed trust-boundary attribute vocabulary: `trust.untrusted_input`, `trust.privilege_scope`, `trust.hitl_required`, `trust.hitl_result` (`approved`/`denied`/`bypassed`), `trust.egress`, `agent.hop`, `model.route_reason`, `mem.provenance`. This is native OpenTelemetry — no bespoke logging format — which means it plugs into whatever trace backend you already run. The vocabulary is also the whole reason M1 pays for itself later: M3's trace-query detections are built entirely on top of these attributes existing and being consistent across every agent hop.

**HITL confirmation.** Any tool that mutates state sets `RequireConfirmation: true` in its `functiontool.Config`. ADK 2.0 then pauses execution and issues a human-in-the-loop confirmation before the tool actually runs; the console launcher renders the prompt and feeds the approve/deny decision back in. The dbagent's write tools are the primary consumer of this in M1 — nothing writes to the database without a human in the loop having seen the request first.

Both of these are graph-level properties, declared alongside the tools and edges themselves, not middleware wrapped around an opaque agent loop after the fact. That's deliberate: if telemetry and HITL are add-ons, they get skipped under deadline pressure. If they're part of the tool and node config, skipping them means the code doesn't compile the way you intended.

## What this buys you

None of this is exotic — it's SRE and AppSec fundamentals: bound the blast radius, make the control flow legible, log the trust boundary, gate the dangerous operations on a human. What ADK Go 2.0 buys you is a graph API and a small model interface that make it straightforward to apply those fundamentals in a statically typed, compiled language, instead of retrofitting them onto a Python notebook that grew into a production service. M1 is the proof that the graph shape scales past a single agent without the routing logic turning back into an LLM guessing game.
