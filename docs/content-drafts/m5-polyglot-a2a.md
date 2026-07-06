# Polyglot A2A: one trace across a Go coordinator and a Python sub-agent

*Draft — gopherguard milestone M5. Content draft for engineer-to-engineer publication; unverified claims are marked inline with `<!-- VERIFY -->`.*

The moment your agent system crosses a process boundary, your observability story is on trial. Inside one Go binary, "the coordinator called the researcher" is a span parent-child relationship you get for free. The A2A protocol makes the same hop cross a network *and* a language runtime — and if the trace breaks at that seam, you've built the exact blind spot attackers love: the place where actions stop being attributable. M5 wires a Go coordinator to a Python ADK sub-agent over A2A and insists on one invariant: **it stays one trace**, with the hop recorded in the same `agent.hop` vocabulary the in-process graph has used since M1.

## Why a Python sub-agent at all

Partly because it's realistic — the analysis/ML side of a security pipeline tends to live in Python, and A2A's whole pitch is that the caller shouldn't care. Partly because it's the honest test of the telemetry design: if the trust-boundary vocabulary from `internal/telemetry/trust.go` only works inside one Go process, it's not a vocabulary, it's a coincidence.

The sub-agent itself (`a2a-python/`) is a deterministic ADK custom agent — no LLM, no API key, no egress. It scores text for prompt-injection indicators (regex heuristics with weights: `ignore-previous-instructions`, `system-prompt-probe`, `encoded-payload`, …) and returns a small report. Deterministic for the same reason the M4 evals are: the cross-language demo must reproduce headless, on any machine, keyless. The point of M5 is the plumbing, not the classifier.

## The seam, in three mechanisms

**1. The hop is an attribute, not a convention.** The Go client (`internal/a2aremote`) wraps every remote call in a span stamped `agent.hop = "coordinator->python-analysis"` — built with the same `telemetry.AttrAgentHop` helper the in-process graph uses, plus `trust.egress = true` (it's a network call by definition) and `trust.untrusted_input = true` (the reply crossed a trust boundary; a remote agent's output deserves exactly as much trust as a web page). The M3 detections query `agent.hop` today; the polyglot hop shows up in the same queries with zero rule changes.

**2. The trace context rides the wire.** The A2A SDK's client transports take a caller-supplied `*http.Client`; gopherguard injects one whose `RoundTripper` writes the W3C `traceparent` header from the request context into every outgoing request. Deliberate detail: it uses the concrete `propagation.TraceContext` propagator rather than the global one, so cross-language continuity can't be broken by whatever the host application did (or didn't do) to global propagator config.

**3. The Python side joins instead of starting over.** The sub-agent's Starlette app is wrapped in OTel's ASGI middleware, which extracts `traceparent` and parents the server span under the Go client span. A server-request hook stamps `agent.hop` on that inbound span too, so the hop is queryable from both halves. The a2a-sdk's own instrumentation then hangs its handler spans underneath — all carrying the Go trace ID.

Run it and the two consoles show the receipt:

```
# Go side                                          # Python side
[otel] span="a2a.analyze"                          [otel] span='POST /'
  trace_id=19a8bae4cfb1bc90ea09c4454181d6fe          trace_id=19a8bae4cfb1bc90ea09c4454181d6fe
  agent.hop=coordinator->python-analysis             agent.hop=coordinator->python-analysis
```

Same trace ID, two runtimes. Point both sides at the M3 trace stack (`make trace-up`, set `OTEL_EXPORTER_OTLP_ENDPOINT`) and Tempo renders it as one waterfall.

## The version skew nobody tells you about

Here's the part that costs an afternoon if you discover it in production: **the two A2A SDKs don't speak the same protocol version by default.** `a2a-go/v2` implements A2A v1.0. Python's `google-adk` currently pins `a2a-sdk` 0.3.x, which serves a v0.3 agent card (`url` + `preferredTransport` instead of `supportedInterfaces`) and v0.3 JSON-RPC. Point a naive v1.0 client at it and card resolution yields zero usable transports.

The Go SDK ships the bridge — `a2acompat/a2av0` — but you have to wire it: gopherguard's client parses the fetched card as v1.0 first, falls back to the v0.3 parser, and registers *both* JSON-RPC transports (native and compat) over the same trace-propagating HTTP client. The factory picks the dialect by the card's declared protocol version, matching on major version. Net effect: the coordinator talks to a v0.3 Python agent today and a v1.0 one the day google-adk bumps its pin, with no code change. (Also a small trap inside the trap: the compat transport is selected by *card-declared* version — a v0.3 server that forgot `protocolVersion` in its card would be treated as v0.3 anyway thanks to the compat default, but don't rely on that. <!-- VERIFY: behavior when protocolVersion is absent -->)

The test suite pins both dialects: one round-trip against the SDK's native v1.0 server, one against a v0.3-format card plus v0.3 JSON-RPC handler — the exact wire shape the Python agent serves. Both tests assert the same two facts: the `a2a.analyze` span carries the hop attribute, and the request that reached the server carried a `traceparent` containing that span's trace ID. That's cross-language continuity as a mechanical assertion, runnable in CI with no Python installed.

## Trust-boundary reading

A2A moves an agent hop from "function call" to "network peer," and the trust posture should move with it. The remote agent's output is untrusted input — same class as web search results in M1. The hop is egress — the same attribute the least-privilege policy fences. And because the hop is attributable end-to-end in one trace, the M3-style question "which external agent's output preceded this HITL bypass?" is a trace query, not an incident-response archaeology session. That's the actual deliverable of M5: the security telemetry doesn't degrade when the system goes polyglot.

## Run it

```sh
make a2a-setup        # once: venv + pinned deps under a2a-python/.venv
make a2a-serve        # terminal 1: Python analysis agent on :8091
make a2a-demo         # terminal 2: Go coordinator → A2A → Python, prints shared trace ID
```

No key, no model server, no cloud — the whole demo is two processes on localhost lying to no one about what it proves: one trace, two runtimes, one hop vocabulary.
