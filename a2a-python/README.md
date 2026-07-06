# gopherguard Python analysis sub-agent (M5)

The Python half of gopherguard's polyglot A2A milestone: a deterministic
[ADK](https://google.github.io/adk-docs/) custom agent that scores text for
prompt-injection indicators, exposed as an
[A2A](https://a2a-protocol.org) server. The Go coordinator calls it via
`internal/a2aremote` (demo: `cmd/gga2a`), and the two runtimes share **one
OpenTelemetry trace**.

No LLM, no API key, no egress: the agent is deterministic on purpose, so the
cross-language demo reproduces headless on any machine.

## Setup

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

(or `make a2a-setup` from the repo root.)

## Run

```sh
.venv/bin/python -m analysis_agent.server
```

(or `make a2a-serve` from the repo root.) This serves, on `127.0.0.1:8091`
(override with `A2A_HOST` / `A2A_PORT`):

- `/.well-known/agent-card.json` — the A2A agent card
- `/` — the A2A JSON-RPC endpoint

Then, from the repo root:

```sh
make a2a-demo    # or: go run ./cmd/gga2a "text to analyze"
```

Both processes print compact `[otel] span=… trace_id=…` lines; the trace IDs
match — one trace spanning Go and Python, with
`agent.hop = coordinator->python-analysis` stamped on both halves. To see the
combined waterfall in Tempo/Grafana instead, start the M3 trace stack
(`make trace-up`) and export both sides to it:

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 .venv/bin/python -m analysis_agent.server
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 go run ./cmd/gga2a "text to analyze"
```

## How the trace joins

- The Go A2A client injects the W3C `traceparent` header on every request.
- `analysis_agent/server.py` wraps the Starlette app (built by ADK's
  `to_a2a`) in OTel's ASGI middleware, which extracts that header, and stamps
  `agent.hop` on the inbound server span.
- `analysis_agent/telemetry.py` exports spans via OTLP when
  `OTEL_EXPORTER_OTLP_ENDPOINT` is set, else as compact console lines.

## Protocol version note

`google-adk` currently pins `a2a-sdk` 0.3.x, so this server speaks A2A
protocol **v0.3** (see the `protocolVersion` in the agent card). The Go
client bridges this via `a2a-go/v2`'s `a2acompat/a2av0` package and will
switch to native v1.0 automatically once the card declares it.
