# gopherguard: agents fail like distributed systems and get attacked like web apps

*Draft — consolidated project overview, ties together the milestone-specific posts below. Content draft for engineer-to-engineer publication; unverified claims are marked inline with `<!-- VERIFY -->`.*

Most public agent projects are demos: a notebook, a prompt, a screen recording of the model doing something impressive. gopherguard is trying to be the other thing — a production-grade, security-instrumented multi-agent system built on ADK Go 2.0, built around one thesis: **agents fail like distributed systems and get attacked like web apps, so bring SRE and AppSec discipline, in a language built for both.**

That sentence does a lot of work, so it's worth unpacking before touring what got built.

## The thesis, unpacked

"Agents fail like distributed systems" means: the moment your agent is a coordinator dispatching to sub-agents, calling tools, and hitting a model backend, you have a distributed system, whether or not you architected it as one — partial failures, cascading timeouts, compounding retries. Not a new category of problem; the one SREs have instrumented and gated against for two decades.

"Get attacked like web apps" means: an agent that ingests untrusted content (a search result, a retrieved document, another agent's message) and later takes an action is structurally the same shape as a web app that takes user input and executes a query with it. Injection, privilege abuse, trust-boundary violations — AppSec has a mature vocabulary for this. gopherguard's bet is that neither problem needs a new discipline invented from scratch — it needs the two that already exist, applied to agents, in a language genuinely good at both: statically typed, observability-native, built around a toolchain that treats testing and vetting as first-class steps.

Everything below is that thesis, built out milestone by milestone.

## The graph: code-routed, not LLM-routed

The agent graph is a Coordinator dispatching to a Researcher (search/egress), a DB Agent (MCP → Postgres), and a Writer — with a Python analysis agent planned for M5, reached over A2A. The detail that matters more than the org chart: routing between them is **code-routed**. The Coordinator decides which sub-agent handles a request with plain Go `if`/`switch` logic, not by asking an LLM which agent to call.

That's a deliberate rejection of the default in most agent frameworks, where routing is itself a model call. The cost of LLM-routing is that control flow — which agent gets invoked, and by extension which privileges get exercised — becomes opaque, prompt-dependent, and attacker-reachable: anything that can influence model output can potentially influence routing. Code-routing keeps that decision auditable and testable like ordinary software; a golden set of "this prompt should route to the researcher" cases becomes a deterministic unit test, not a probabilistic hope. Model calls get reserved for parts that actually need judgment — summarizing, writing — not internal dispatch.

Sitting under the graph is a model layer with the same "boring by design" philosophy: Gemma running locally via Ollama is the *default*, not a fallback, keeping demos offline-capable and CI keyless. Gemini is opt-in "production mode" behind an API key. A cost-based router picks between them per call and records the decision as `model.route_reason` on every span, so "why did this call use Gemini instead of Gemma" is answerable from telemetry alone.

## The spine: trust-boundary telemetry

Every span that crosses a trust boundary — a tool call, an agent hop, a memory read or write — carries a fixed OpenTelemetry attribute vocabulary:

- `trust.untrusted_input` — did this span process content originating outside the trust boundary
- `trust.privilege_scope` — what scope this operation executes under
- `trust.hitl_required` / `trust.hitl_result` — did this need human confirmation, and what happened
- `trust.egress` — did this span perform or authorize outbound network activity
- `agent.hop` — source→destination for an inter-agent handoff
- `model.route_reason` — why the router chose the model it did
- `mem.provenance` — where a piece of memory came from

Every tool implements a small `ScopedTool` interface (`PrivilegeScope()`, `IsMutating()`, `TouchesUntrusted()`), and any tool where `IsMutating()` is true requires a human-in-the-loop gate before it runs, with the outcome recorded on the invoking span. This vocabulary is deliberately fixed and small — it's the schema everything downstream (detections, evals, canary rollback) queries against, rather than each consumer inventing its own ad hoc logging.

## The pairs: eight OWASP Agentic (ASI) vulnerable/hardened demonstrations

On top of that telemetry, gopherguard implements eight matched pairs mapped to the OWASP Agentic Security Initiative Top 10: goal hijack via indirect prompt injection, identity/privilege abuse, tool misuse, sandbox/config redefinition, memory poisoning, inter-agent trust, config-as-vector, and supply chain risk. Each pair is a vulnerable variant that demonstrates the failure pattern and a hardened variant that blocks the identical attack — same task, same graph, one with the vulnerability present and one with the fix applied.

Safety is architectural, not a disclaimer. Every action in the vulnerable variants is simulated — "egress" appends to an in-process sink and performs no I/O, secrets are obvious placeholders, targets are RFC-reserved `.invalid` names. Vulnerable mode itself is fenced: it refuses to start without `--i-understand-this-is-insecure`, binds to `127.0.0.1` only, forces local Gemma (no external API calls even by accident), and is never built into the Cloud Run deployable. The goal is to teach the failure *pattern*, not to hand anyone a working exploit.

## The detections: a SIEM for agent traces

Because every span carries the same trust-boundary vocabulary, the vulnerable/hardened pairs become the fixtures for something more durable than a demo: five trace-query detection rules that treat agent traces as a queryable security log instead of a transcript you read after the fact.

The canonical example is `GG-DET-01`, the injection→exfil chain, expressed over the trust attributes rather than message content:

```
{ trust.untrusted_input = true } >> { trust.egress = true }
```

Find a span where untrusted input was processed, followed in the same session by a span that performed egress. It doesn't matter what the payload said — a poisoned webpage, a crafted ticket — the query only cares about the sequence of trust-boundary crossings. The other four seed rules apply the same idea elsewhere: `GG-DET-02` (HITL bypass — required but not approved, yet proceeded), `GG-DET-03` (loop/cost runaway — the same span repeating past a threshold), `GG-DET-04` (privilege widening — scope escalating across a session), and `GG-DET-05` (memory taint — untrusted-provenance memory consumed by a later write-scoped action).

The discipline that makes these trustworthy: a detection isn't real until it's proven to fire on the known-bad trace *and* stay quiet on the known-good one, tested both directions against the M2 pairs. The same predicate is expressed three times — Go (the source of truth, unit-tested), TraceQL (for Grafana Tempo), and ClickHouse SQL — so the local test suite and the production trace store are never two implementations that might drift.

## The gate: eval-gated CI/CD

None of this matters if it doesn't actually stop a bad build from shipping, which is what M4 wires up. A keyless eval harness runs three suites in CI on every PR: **task-success** (a golden set of prompts graded as a pass fraction against a threshold, not all-or-nothing), **trajectory** (did the agent get there without doing something insane, checked against span/hop/loop budgets), and **injection-resistance** (every OWASP pair's mapped detection must fire on the vulnerable trace and stay quiet on every hardened one). All three run via `go test`, no API key or model server required, because a gate that can't run on every PR isn't a gate — it's a dashboard that turns red after the regression already merged.

The agent's shape lives as GitOps-managed config (`deploy/agent.yaml`) with strict parsing and a validator that encodes security posture, not just schema — rejecting standing egress grants and any single agent holding both broad read and write scope at once. The CI job also posts a cost-delta comment estimating the dollar impact of a routing-policy change, so a reviewer sees the cost implication of, say, `escalation_rate: 0.10 → 0.35` in the same view as the diff.

Past the merge, the same discipline extends into a canary deploy to Cloud Run: golden prompts get replayed against the canary before real traffic, and — the twist that ties the whole project together — the M3 detections run against canary traffic as automatic rollback triggers. An injection→exfil chain firing on a canary trace is treated exactly like an elevated 5xx rate: a failed health check, not a Slack thread someone notices Monday.

## Why build it this way

None of the individual pieces here are novel. Golden tests, canary deploys, GitOps, structured telemetry — all of that predates agents by years. What's actually been missing in most agent engineering isn't technique, it's plumbing: making every one of those checks a required status on the merge button and a rollback trigger on the running deploy, over a system whose control flow and privilege model are auditable Go code rather than something a prompt negotiates at runtime.

gopherguard is public, runs entirely against local Gemma with zero API key and zero egress by default, and every claim above is exercised by `go test ./...` or reproducible with `make run`, `make detect`, and `make eval`.

## Milestone posts

The milestone-specific write-ups go deeper on each piece:

- **["Scaffolding a security-instrumented ADK Go 2.0 agent (the honest version)"](m0-scaffolding-adk-go-2.md)** — the M0 toolchain and model-layer decisions, and two gotchas a green build didn't catch.
- **["Production multi-agent ADK Go 2.0"](m1-production-multi-agent-adk-go-2.md)** — the M1 hardened baseline: the full code-routed graph, trust-boundary OTel, and least-privilege scoping.
- **["Migrating ADK 1.x to 2.x: a retry/HITL gotcha"](m1-migrating-adk-1x-to-2x-retry-hitl-gotcha.md)** — a specific migration trap in the human-in-the-loop path.
- **["SLOs for non-deterministic systems"](m3-slos-for-non-deterministic-systems.md)** — applying SRE-style service objectives to an agent that doesn't behave deterministically run to run.
- **["SIEM rules for agent traces"](m3-siem-rules-for-agent-traces.md)** — the full detail on the five trust-boundary detection rules and how they're tested against the OWASP pairs.
- **["CI/CD for agents: eval gates, canary prompts, GitOps for YAML agents"](m4-cicd-for-agents-eval-gates.md)** — the eval harness, the agent-as-config validator, and the canary/rollback pipeline.

Next: M5 stretches one trace across two runtimes — a Go coordinator calling a Python analysis agent over A2A, with `agent.hop` keeping the cross-language handoff visible to the same detections.
