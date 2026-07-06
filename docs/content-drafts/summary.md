# gopherguard: a summary

*DRAFT*

**Agents fail like distributed systems and get attacked like web apps — so bring SRE and AppSec discipline, in a language built for both.**

gopherguard is a production-grade, security-instrumented multi-agent system built on ADK Go 2.0. It isn't a toy chatbot demo — it's an argument, made in running code, that the next wave of agent incidents will look less like "the model said something dumb" and more like the incidents SREs and AppSec teams already have playbooks for: partial failures, cascading retries, privilege abuse, injection, and trust-boundary violations. The project's bet is that Go — statically typed, boring in the ways that matter, with a toolchain built for observability and CI — is a better home for that discipline than the notebook-and-prompt-string culture most agent frameworks came from.

## Why this matters for a GDE / security angle

Most public agent projects optimize for "look what the model can do." gopherguard optimizes for "here's how you'd know if it went wrong, and here's the pipeline that stops it from shipping if it did." That's a deliberately unglamorous position, and it's also the one production teams actually need: as agents get real tool access — databases, email, deploys — the question stops being "is the demo cool" and becomes "what's the blast radius when a tool call goes sideways, and how fast do we find out." gopherguard is a concrete answer to that question, built end-to-end rather than argued about in a blog post.

## Five things it demonstrates

1. **A code-routed agent graph.** The Coordinator dispatches to Researcher, DB Agent, and Writer sub-agents via plain Go `if`/`switch` logic — not an LLM deciding who talks to whom. Control flow stays auditable and testable like ordinary code, instead of opaque and prompt-dependent.

2. **Trust-boundary OpenTelemetry.** Every span that crosses a trust boundary — a tool call, an agent hop, a memory read/write — carries a fixed vocabulary: `trust.untrusted_input`, `trust.privilege_scope`, `trust.hitl_required`/`trust.hitl_result`, `trust.egress`, `agent.hop`, `model.route_reason`, `mem.provenance`. Privilege scope and untrusted input become first-class facts you can query, not details buried in a transcript.

3. **Eight OWASP Agentic (ASI) vulnerable/hardened pairs.** Goal hijack via indirect injection, privilege abuse, tool misuse, sandbox/config redefinition, memory poisoning, inter-agent trust, config-as-vector, and supply chain each get a matched pair: a vulnerable variant that demonstrates the failure pattern and a hardened variant that blocks it. Every pair is fenced — `--i-understand-this-is-insecure` required, localhost-only, local-model-only, no working payloads — because the point is teaching the *pattern*, not shipping an exploit.

4. **Trace-query detections — a SIEM for agent traces.** Five seed rules query the trust-boundary attributes directly: `{ untrusted_input=true } >> { egress=true }` catches an injection-to-exfiltration chain as a sequence of stamped facts, not a string match. Each rule is tested to fire on its vulnerable trace and stay quiet on the hardened one, with the same logic expressed as Go, TraceQL, and ClickHouse SQL.

5. **Eval-gated CI/CD.** A keyless eval harness (task-success, trajectory, injection-resistance) runs over a YAML agent config on every PR, gates the merge, and posts a cost-delta comment. Only the hardened build reaches Cloud Run, behind a canary stage where the same detections that catch attacks in a trace store double as automatic rollback triggers.

None of this requires a paid API key to run or verify — the default path is local Gemma via Ollama, zero egress, keyless CI. The point isn't that agents are scary; it's that the tools for making them boring already exist, and mostly nobody has wired them together end to end. gopherguard is that wiring.
