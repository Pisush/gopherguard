# SIEM rules for agent traces

*Draft — gopherguard milestone M3. Content draft for engineer-to-engineer publication; unverified claims are marked inline with `<!-- VERIFY -->`.*

Most teams find out an agent did something dangerous by reading the transcript after the fact, if they read it at all. That's not a monitoring strategy, it's an incident report you write to yourself. M3 in gopherguard is about closing that gap: if every trust boundary an agent crosses is stamped with a stable attribute vocabulary, then your traces stop being a debugging aid and become a queryable security log. Attacks become detections you write as queries, not vibes you hope someone notices in a log tail.

## Why trust-boundary attributes, not raw logs

The instinct when you want to detect bad agent behavior is to grep the logs for suspicious strings — a URL that looks like exfiltration, a phrase that looks like a prompt injection. That approach is exactly as durable as string-matching malware signatures: it catches what you already thought of, in the wording you already thought of, and nothing else.

gopherguard's telemetry takes a different cut. Instead of asking "did this text look bad," every span gets stamped with a small, fixed vocabulary of trust attributes that describe what actually happened at each boundary the agent crossed:

- `trust.untrusted_input` (bool) — did this span process input that didn't originate from an authenticated user?
- `trust.privilege_scope` (string) — what scope did this span execute under (`read:*`, `write:*`, `admin`)?
- `trust.hitl_required` / `trust.hitl_result` (bool / `approved`\|`denied`\|`bypassed`) — was human confirmation required, and what happened?
- `trust.egress` (bool) — did this span perform or permit network egress?
- `agent.hop`, `model.route_reason`, `mem.provenance` — which agent handed off to which, why a model was chosen, and where memory a span consumed came from.

None of these attributes describe *content*. They describe *position relative to a trust boundary* — untrusted in, privileged out, approved or not, memory from where. That's the same move SIEMs make with structured security logs: you don't grep firewall logs for "looks like an attack," you query `src_zone=untrusted AND dst_zone=dmz AND action=allow`. Agent traces can carry the same structure, because the boundaries an agent crosses (untrusted input, privilege escalation, egress, human approval, memory provenance) are a fixed, enumerable set — regardless of what the attacker's prompt actually says.

## The canonical example: injection → exfil

The OWASP Agentic Security Initiative's ASI01 (goal hijack via injection) has a shape that's boring once you see it in trace terms: untrusted content enters the agent's context, and downstream, data leaves the boundary. In TraceQL-style pseudocode, over gopherguard's schema, that's:

```
{ trust.untrusted_input = true } >> { trust.egress = true }
```

Read literally: find a span where untrusted input was processed, followed (`>>`, same session) by a span that performed egress. That's the entire detection. It doesn't matter whether the untrusted input was a malicious webpage, a poisoned PDF, or a crafted support ticket — the query doesn't care about content, it cares about the sequence of trust-boundary crossings. This is `GG-DET-01` in gopherguard (`internal/detect/rules.go`, `detectInjectionExfil`): walk the session's spans, find the first one flagged `trust.untrusted_input = true`, then scan forward for any later span with `trust.egress = true`. If both are present, in that order, in the same session, it fires — and the evidence string names both spans plus whatever privilege scope the egress happened under.

The other four seed rules are the same idea applied to other boundaries:

- `GG-DET-02` — HITL bypass: a span required human confirmation (`trust.hitl_required = true`) but `trust.hitl_result` wasn't `approved` and the action proceeded anyway.
- `GG-DET-03` — loop/cost runaway: the same span name repeats more than five times in a session, which is a budget breach whether or not any single call looks harmful.
- `GG-DET-04` — privilege widening: `trust.privilege_scope` escalates across a session (`read` → `write` → `admin`) instead of holding steady or narrowing.
- `GG-DET-05` — memory taint: memory with untrusted `mem.provenance` gets consumed by a later span running under a `write:` scope — the payoff step of memory poisoning.

Each is a handful of lines over the same attribute vocabulary. None of them parse natural language. That's the point: the schema does the work of turning "was this attack" into "did this sequence of stamped facts occur," which is a question you can answer with a query engine instead of a human squinting at a transcript.

## A detection isn't real until it has a counterexample

The discipline that makes these rules trustworthy isn't the query syntax, it's the test contract: **a detection rule isn't real until it fires on a known-bad trace and stays quiet on the known-good one.** A rule that always fires is noise. A rule that never fires is decoration. Either failure mode is indistinguishable from a working rule if you only ever test it against one trace.

This is exactly how gopherguard tests GG-DET-01 through GG-DET-05. M2 produced vulnerable/hardened pairs for each OWASP Agentic scenario — same task, same agent graph, one version with the vulnerability present and one with the fix applied. M3's test suite (`internal/detect/detect_test.go`) captures both variants of a pair in-process using an OTel `SpanRecorder`, runs the rule against each, and asserts:

```go
if f := detectInjectionExfil(capturePair(t, "ASI01", false)); !f.Fired {
    t.Error("GG-DET-01 must fire on ASI01 vulnerable trace")
}
if f := detectInjectionExfil(capturePair(t, "ASI01", true)); f.Fired {
    t.Errorf("GG-DET-01 must be quiet on ASI01 hardened trace, but fired: %s", f.Evidence)
}
```

That's a regression suite for detections, not just for code. If someone later "improves" GG-DET-01 and it starts firing on the hardened trace too, the test catches a false positive before it reaches production and starts paging people for nothing. If a change makes it stop firing on the vulnerable trace, the test catches a false negative before an actual attack sails through silently. Both directions matter, and testing only one is how detection engineering rots — rules that technically exist but nobody trusts, so nobody looks at them.

In production the same rule logic runs as TraceQL over Grafana Tempo (or the SQL equivalent over ClickHouse — see `detections/` for the query forms) and gets visualized in Grafana. The in-process Go tests and the production queries aren't two different implementations that might drift; they're the same trust-boundary predicate, expressed twice for two different execution contexts, validated against the same fixtures.

## Why this generalizes

The reason this is worth building as infrastructure rather than one-off scripts: the moment you have a fixed trust-boundary schema stamped on every span, adding a new detection is a bounded exercise. New attack shows up → identify which boundary crossings it involves → write the query over attributes that already exist → capture or construct a vulnerable/hardened pair → add the fire/quiet assertion. You are never waiting on a new logging statement to ship before you can detect the thing it would have caught, because the vocabulary was general enough to describe it already.

That's also what makes the rule set auditable in a way "the model flagged it as suspicious" never is. Every finding cites the exact spans and attribute values that triggered it. When a rule fires, you can hand someone the evidence string and the trace ID, not a probability. When it's quiet, you have a test that proves it would have caught the same shape of attack on the vulnerable variant. New attack, new rule, permanent test — that's the whole model, and it scales the same way a SIEM's correlation rule library scales: not by getting smarter about language, but by having a schema disciplined enough that "did X happen before Y" is always a well-formed question.
