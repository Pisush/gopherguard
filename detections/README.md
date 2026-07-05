# gopherguard detections — SIEM for agent traces

gopherguard stamps every OpenTelemetry span it emits with a **fixed
trust-boundary attribute vocabulary** (defined in
`internal/telemetry/trust.go`). Because the vocabulary is stable and never
repurposed, a trace store that ingests these spans becomes a general-purpose
SIEM for agent behavior: detections are just queries over well-known
attribute keys, not bespoke application logging.

This directory contains the production-stack equivalents of that idea:

- a local trace-store stack (OTel Collector → Grafana Tempo + ClickHouse →
  Grafana) you can bring up with one command,
- the 5 seed detection rules expressed as **TraceQL** (for Tempo) and
  **ClickHouse SQL** (for a columnar spans table), matching the Go rules in
  `internal/detect/rules.go` attribute-for-attribute,
  - Grafana dashboards for both agent SLOs and fired detections.

The **Go implementations in `internal/detect/rules.go` remain the source of
truth**: they are unit-tested to fire on the M2 vulnerable pairs (the
deliberately-insecure agents under `vulnerable/`) and stay quiet on the
`hardened/` equivalents. The TraceQL/SQL here are meant to reproduce that
same logic against a real trace store in production/staging, where you don't
have a Go process sitting in the request path to evaluate rules synchronously
— you have spans landing in Tempo/ClickHouse after the fact, and you query
them.

## The trust attribute vocabulary

| Attribute | Type | Meaning |
|---|---|---|
| `trust.untrusted_input` | bool | span processed external/tool-derived content |
| `trust.privilege_scope` | string | e.g. `read:web`, `write:db`, `write:egress`, `admin:*` |
| `trust.hitl_required` | bool | action needed human confirmation |
| `trust.hitl_result` | string enum | `approved` \| `denied` \| `bypassed` |
| `trust.egress` | bool | span made an outbound call |
| `agent.hop` | string | A2A source→dest, e.g. `planner->executor` |
| `model.route_reason` | string | why a model was chosen for this span |
| `mem.provenance` | string | origin of a memory read/write, e.g. `user`, `tool:web_search` |

These keys are considered stable API: detections (Go, TraceQL, and SQL) all
key off the literal strings above, so renaming or repurposing one breaks
every consumer at once. Add new attributes instead of overloading existing
ones.

## The 5 seed detection rules

| Rule ID | ASI risk | Attribute pattern queried |
|---|---|---|
| **GG-DET-01** Injection→exfil chain | ASI01 Goal Hijack | within one trace, a span with `trust.untrusted_input=true` precedes (`>>`) a span with `trust.egress=true`, typically under a widened `trust.privilege_scope` |
| **GG-DET-02** HITL bypass | Tool misuse / HITL | a span with `trust.hitl_required=true` whose `trust.hitl_result != "approved"`, where the action proceeded anyway (a mutation was observed) |
| **GG-DET-03** Loop / cost runaway | Loop / cost runaway | more than 5 spans sharing the same `SpanName`/span name within one session/trace (loop-budget breach) |
| **GG-DET-04** Privilege widening | ASI03 Privilege abuse | within a session, `trust.privilege_scope` escalates — a later span runs under a strictly broader scope than an earlier one (rank: `read` < `write` < `admin`) |
| **GG-DET-05** Memory taint | Memory poisoning | a span whose `mem.provenance` is a non-`user` (untrusted) origin is followed by a mutating decision span running under a `write:*` `trust.privilege_scope` |

See `detections/rules/traceql.md` and `detections/rules/clickhouse.sql` for
the runnable query text, and `internal/detect/rules.go` for the reference Go
implementation each query mirrors.

## How spans flow

```
   gopherguard process(es)
   (vulnerable/*, hardened/*, cmd/*)
             |
             |  OTEL_EXPORTER=otlp
             |  OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
             v
   +-----------------------+
   |  OTel Collector       |   detections/otel-collector-config.yaml
   |  (otlp receiver ->    |
   |   batch processor ->  |
   |   otlp + clickhouse   |
   |   exporters, fanned   |
   |   out to both sinks)  |
   +-----------+-----------+
               |
       +-------+--------+
       v                v
 +-----------+    +-------------+
 |  Tempo    |    |  ClickHouse |
 | (TraceQL) |    | (SQL, table |
 |           |    |  otel_traces)|
 +-----+-----+    +------+------+
       \                 /
        \               /
         v             v
        +----------------+
        |    Grafana     |
        |  dashboards:   |
        |  slo.json,     |
        |  detections.json|
        +----------------+
```

- The **OTel Collector** is the single ingestion point; it receives OTLP
  (gRPC 4317 / HTTP 4318) from the app and fans every span out to both
  Tempo (for TraceQL, trace-shaped queries — chains, ordering, structural
  operators) and ClickHouse (for SQL — aggregations, joins, dashboards that
  need `GROUP BY`/`HAVING`).
- **Tempo** is best for the trace-native rules (GG-DET-01, GG-DET-02,
  GG-DET-05 — "does span A precede span B in this trace").
- **ClickHouse** is best for the rules that need aggregation or windowing
  across a session (GG-DET-03's `count > 5`, GG-DET-04's ordered-scope
  comparison), and for building fast SLO dashboards.
- **Grafana** reads from both (plus Prometheus for the SLO metrics panels)
  and renders the two dashboards under `detections/grafana/dashboards/`.

## Bringing the stack up locally

```sh
docker compose -f detections/docker-compose.yaml up
```

This starts:

- the OTel Collector on `4317`/`4318` (OTLP gRPC/HTTP),
- Grafana Tempo on `3200` (query API/UI) and `4317`/`4318` (its own OTLP
  ingest, used internally by the collector's `otlp` exporter),
- ClickHouse on `8123` (HTTP) and `9000` (native),
- Grafana on `3000`, pre-provisioned with the Tempo/ClickHouse/Prometheus
  datasources (`detections/grafana/provisioning/datasources.yaml`) and the
  two dashboards under `detections/grafana/dashboards/`.

Point the app at the collector:

```sh
export OTEL_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

Then run any `vulnerable/*` or `hardened/*` scenario and watch spans land in
Grafana → Explore (Tempo datasource) or query them directly via ClickHouse
(`detections/rules/clickhouse.sql`).

## Notes / caveats

- Image tags in `docker-compose.yaml` are pinned but marked `# VERIFY` —
  confirm current stable tags before using this outside local dev.
- The dashboards use placeholder datasource UIDs (`${DS_PROMETHEUS}`,
  `${DS_TEMPO}`, `${DS_CLICKHOUSE}`) that Grafana's provisioning resolves at
  import time; no real endpoints or credentials are embedded here.
- This layer is intentionally read-only/observability-only: nothing here
  blocks or mutates agent behavior. Enforcement (denying HITL-bypassed
  actions, etc.) is the job of the application-level guards in
  `internal/`, not of the trace store.
