# Detection rules as TraceQL (Grafana Tempo)

These queries are the Tempo-native equivalents of `internal/detect/rules.go`.
Run them in Grafana → Explore with the Tempo datasource, or as panel targets
in `detections/grafana/dashboards/detections.json`.

TraceQL's structural operators used below:

- `A >> B` — span matching `B` is a **descendant** of a span matching `A`
  (i.e. `A` is an ancestor of `B`, anywhere below it in the same trace).
- `A > B` — span matching `B` is a **direct child** of a span matching `A`.
- `{ ... } && { ... }` — both span-matchers must each find a match somewhere
  in the trace (no ordering/ancestry implied).

Tempo's trace model doesn't have a native concept of "session" wider than a
single trace. Where gopherguard's session spans multiple traces (e.g. a
multi-turn agent conversation), configure the collector/SDK to correlate them
under one `trace_id` (recommended), or run these queries per-trace and
aggregate the results downstream (e.g. in the ClickHouse layer — see
`clickhouse.sql` — or via Tempo's metrics-generator / TraceQL metrics).

---

## GG-DET-01 — Injection→exfil chain (ASI01)

A span that processed untrusted input is later followed, in the same trace,
by a span that performed egress. This is the indirect-injection → exfil
chain.

```traceql
// GG-DET-01: untrusted input span precedes an egress span in the same trace
{ span.trust.untrusted_input = true } >> { span.trust.egress = true }
```

Narrower variant that also requires the egress span to be running under a
writable/broadened scope (the "widened privilege" detail called out in the
rule description):

```traceql
// GG-DET-01 (narrow): untrusted input precedes egress under a write/admin scope
{ span.trust.untrusted_input = true } >> { span.trust.egress = true && span.trust.privilege_scope =~ "^(write|admin).*" }
```

No post-processing needed — TraceQL's `>>` operator natively expresses the
ordering/ancestry requirement.

---

## GG-DET-02 — HITL bypass

A span required human-in-the-loop confirmation, but the recorded result
wasn't `approved`, and the action proceeded anyway (i.e. there's a mutating
span downstream in the same trace — TraceQL can't itself confirm the
"mutation occurred" causally, but a `write:*`-scoped descendant span is a
strong proxy).

```traceql
// GG-DET-02: HITL required but not approved
{ span.trust.hitl_required = true && span.trust.hitl_result != "approved" }
```

With the "proceeded anyway" proxy (a write-scoped span appears after it):

```traceql
// GG-DET-02 (with proceed-anyway proxy): non-approved HITL gate followed by a write
{ span.trust.hitl_required = true && span.trust.hitl_result != "approved" } >> { span.trust.privilege_scope =~ "^write:" }
```

Note: TraceQL can find the non-approved gate and, with the second query,
confirm a write happened downstream. It cannot express "the specific action
this gate was guarding is the one that proceeded" (i.e. it can't bind the
gate span to a *specific* mutation beyond ancestry/descendance) — that level
of causal binding is what `internal/detect/rules.go`'s `detectHITLBypass`
does exactly (any non-approved required-HITL span fires immediately, which
is the conservative/correct behavior since the guard should have blocked
before any further action).

---

## GG-DET-03 — Loop / cost runaway

More than 5 spans sharing the same span name within one trace/session.

```traceql
// GG-DET-03 (closest expressible query): find sessions containing this span name at all
{ name = "tool.web_search" }
```

TraceQL has no `GROUP BY`/`HAVING count(*) > 5` equivalent for "count of spans
sharing a name within a trace" as of current Tempo query capabilities
(TraceQL metrics queries can aggregate `count_over_time`/`rate` across
*traces*, not count repeated span names *within* a single trace). **This rule
needs post-processing**:

- Prefer the ClickHouse SQL version (`clickhouse.sql`, GG-DET-03) which does
  a native `GROUP BY TraceId, SpanName HAVING count(*) > 5`, or
- If Tempo TraceQL metrics are enabled, approximate with a metrics query per
  known loop-prone span name and alert on trace-level repetition surfaced by
  the collector/exporter (e.g. stamp a `loop.count` attribute at the SDK
  level and query `{ span.loop.count > 5 }` directly — recommended if you
  want this enforceable purely in TraceQL).

If the SDK is updated to stamp a running per-span-name counter (e.g.
`gg.repeat_count`), the query becomes exact:

```traceql
// GG-DET-03 (if a repeat-count attribute is stamped by the SDK)
{ span.gg.repeat_count > 5 }
```

---

## GG-DET-04 — Privilege widening

Within a session, `trust.privilege_scope` escalates: a later span runs under
a strictly broader scope (rank: `read` < `write` < `admin`) than an earlier
span.

```traceql
// GG-DET-04 (closest expressible query): a read-scoped span precedes a write/admin-scoped span
{ span.trust.privilege_scope =~ "^read:" } >> { span.trust.privilege_scope =~ "^(write|admin).*" }
```

More specific admin-escalation variant:

```traceql
// GG-DET-04 (admin escalation): a write-scoped span precedes an admin-scoped span
{ span.trust.privilege_scope =~ "^write:" } >> { span.trust.privilege_scope =~ "^admin" }
```

Note: TraceQL's `>>` gives true descendant ordering (not just "somewhere
earlier in wall-clock time"), which is actually a stricter and more useful
guarantee than a flat scan for this rule. What TraceQL **cannot** express is
the general "find the max-rank scope seen so far and compare every
subsequent span against that running maximum" logic that
`detectPrivilegeWidening` implements — i.e. arbitrary N-way rank comparison
with a running high-water mark. The two queries above cover the two
practical escalation edges (`read`→`write`/`admin`, `write`→`admin`); for the
fully general form, use the ClickHouse self-join version.

---

## GG-DET-05 — Memory taint

A span with non-`user` (untrusted) `mem.provenance` is followed, in the same
trace, by a mutating decision span running under a `write:*`
`trust.privilege_scope`.

```traceql
// GG-DET-05 (single span): a span that BOTH carries untrusted provenance AND
// runs under a write scope. This is the primary form and matches the MEMORY
// pair, whose memory.decide span stamps both mem.provenance and write:order.
{ span.mem.provenance !~ "^user" && span.mem.provenance != "" && span.trust.privilege_scope =~ "^write:" }
```

```traceql
// GG-DET-05 (cross span): taint on one span, the mutating decision on a later
// descendant span. Use OR-ed with the single-span form above to catch both.
{ span.mem.provenance !~ "^user" && span.mem.provenance != "" } >> { span.trust.privilege_scope =~ "^write:" }
```

The single-span form is primary because the Go rule (rules.go) fires as soon
as one span carries untrusted provenance and, at or after it, a write scope
appears — including the same span. The `>>` (descendant) form alone would MISS
the MEMORY fixture, where both attributes are on one span.
Note the Go rule's `isUntrustedProvenance` treats any provenance not
*prefixed* with `"user"` as untrusted (so `"user:alice"` would still count as
trusted); if provenance values include qualified user identities, prefer:

```traceql
// GG-DET-05 (prefix-aware): matches the Go rule's "not prefixed with user" semantics
{ span.mem.provenance !~ "^user" && span.mem.provenance != "" } >> { span.trust.privilege_scope =~ "^write:" }
```
