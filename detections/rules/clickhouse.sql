-- Detection rules as ClickHouse SQL, mirroring internal/detect/rules.go
-- attribute-for-attribute. Assumes a spans table shaped like:
--
--   CREATE TABLE otel_traces (
--       TraceId        String,
--       SpanId         String,
--       ParentSpanId   String,
--       SpanName       String,
--       Timestamp      DateTime64,
--       SpanAttributes Map(String, String)
--   ) ENGINE = MergeTree ORDER BY (TraceId, Timestamp);
--
-- (This is the shape the otel-collector-contrib clickhouse exporter creates
-- by default; see detections/otel-collector-config.yaml.)
--
-- "Session" here is approximated as TraceId: gopherguard is expected to keep
-- one agent session within one trace (see detections/rules/traceql.md for the
-- same caveat on the Tempo side). Attribute values are read via
-- SpanAttributes['trust.untrusted_input'] etc. and are stored as strings, so
-- boolean attributes are compared against the literal 'true'/'false' text.

-- =====================================================================
-- GG-DET-01: Injection→exfil chain (ASI01)
-- A span with trust.untrusted_input=true is followed, in the same trace, by
-- a span with trust.egress=true (self-join on TraceId, ordered by Timestamp).
-- =====================================================================
SELECT
    u.TraceId                                       AS trace_id,
    u.SpanId                                         AS untrusted_span_id,
    u.SpanName                                       AS untrusted_span_name,
    u.Timestamp                                      AS untrusted_ts,
    e.SpanId                                         AS egress_span_id,
    e.SpanName                                       AS egress_span_name,
    e.Timestamp                                      AS egress_ts,
    e.SpanAttributes['trust.privilege_scope']         AS egress_scope
FROM otel_traces AS u
INNER JOIN otel_traces AS e
    ON u.TraceId = e.TraceId
   AND e.Timestamp >= u.Timestamp
   AND e.SpanId != u.SpanId
WHERE u.SpanAttributes['trust.untrusted_input'] = 'true'
  AND e.SpanAttributes['trust.egress'] = 'true'
ORDER BY trace_id, untrusted_ts;

-- =====================================================================
-- GG-DET-02: HITL bypass
-- A span required HITL confirmation (trust.hitl_required=true) but the
-- recorded result was not "approved" (denied, bypassed, or missing) -- i.e.
-- a gate that should have blocked the action fired without blocking it.
-- =====================================================================
SELECT
    TraceId                                          AS trace_id,
    SpanId                                            AS span_id,
    SpanName                                          AS span_name,
    Timestamp                                         AS ts,
    SpanAttributes['trust.hitl_result']               AS hitl_result
FROM otel_traces
WHERE SpanAttributes['trust.hitl_required'] = 'true'
  AND coalesce(nullIf(SpanAttributes['trust.hitl_result'], ''), 'missing') != 'approved'
ORDER BY trace_id, ts;

-- =====================================================================
-- GG-DET-03: Loop / cost runaway
-- More than 5 spans sharing the same SpanName within one trace/session
-- (loop-budget breach). GROUP BY TraceId, SpanName with HAVING count > 5.
-- =====================================================================
SELECT
    TraceId                                          AS trace_id,
    SpanName                                          AS span_name,
    count(*)                                          AS span_count,
    min(Timestamp)                                    AS first_seen,
    max(Timestamp)                                    AS last_seen
FROM otel_traces
GROUP BY TraceId, SpanName
HAVING span_count > 5
ORDER BY span_count DESC;

-- =====================================================================
-- GG-DET-04: Privilege widening
-- Within a session (TraceId), trust.privilege_scope escalates: a later span
-- runs under a strictly broader scope than an earlier one. Rank scopes
-- read=1, write=2, admin=3 (mirrors scopeRank() in rules.go) and self-join
-- to find any later span whose rank exceeds an earlier span's rank.
-- =====================================================================
WITH ranked AS (
    SELECT
        TraceId,
        SpanId,
        SpanName,
        Timestamp,
        SpanAttributes['trust.privilege_scope']                     AS scope,
        multiIf(
            startsWith(SpanAttributes['trust.privilege_scope'], 'admin'), 3,
            startsWith(SpanAttributes['trust.privilege_scope'], 'write:'), 2,
            startsWith(SpanAttributes['trust.privilege_scope'], 'read:'), 1,
            0
        )                                                            AS scope_rank
    FROM otel_traces
    WHERE SpanAttributes['trust.privilege_scope'] != ''
)
SELECT
    earlier.TraceId                                  AS trace_id,
    earlier.SpanId                                    AS earlier_span_id,
    earlier.SpanName                                  AS earlier_span_name,
    earlier.scope                                     AS earlier_scope,
    earlier.Timestamp                                 AS earlier_ts,
    later.SpanId                                      AS later_span_id,
    later.SpanName                                    AS later_span_name,
    later.scope                                       AS later_scope,
    later.Timestamp                                   AS later_ts
FROM ranked AS earlier
INNER JOIN ranked AS later
    ON earlier.TraceId = later.TraceId
   AND later.Timestamp > earlier.Timestamp
   AND later.scope_rank > earlier.scope_rank
ORDER BY trace_id, earlier_ts;

-- =====================================================================
-- GG-DET-05: Memory taint
-- A span whose mem.provenance is non-user (untrusted) origin is followed, in
-- the same trace, by a mutating decision span running under a write:*
-- privilege scope. Mirrors isUntrustedProvenance(): untrusted means the
-- provenance value is non-empty and does not start with "user".
-- =====================================================================
SELECT
    t.TraceId                                        AS trace_id,
    t.SpanId                                          AS tainted_span_id,
    t.SpanName                                        AS tainted_span_name,
    t.SpanAttributes['mem.provenance']                AS provenance,
    t.Timestamp                                       AS tainted_ts,
    w.SpanId                                          AS mutating_span_id,
    w.SpanName                                        AS mutating_span_name,
    w.SpanAttributes['trust.privilege_scope']         AS mutating_scope,
    w.Timestamp                                       AS mutating_ts
FROM otel_traces AS t
INNER JOIN otel_traces AS w
    ON t.TraceId = w.TraceId
   AND w.Timestamp >= t.Timestamp
   -- NOTE: the taint and the mutating write may be on the SAME span (the Go
   -- rule fires on a single span carrying both mem.provenance and a write:*
   -- scope, as in the MEMORY pair's memory.decide span), so we do NOT exclude
   -- w.SpanId = t.SpanId here.
WHERE t.SpanAttributes['mem.provenance'] != ''
  AND NOT startsWith(t.SpanAttributes['mem.provenance'], 'user')
  AND startsWith(w.SpanAttributes['trust.privilege_scope'], 'write:')
ORDER BY trace_id, tainted_ts;
