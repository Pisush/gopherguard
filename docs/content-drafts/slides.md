---
marp: true
theme: default
paginate: true
---

# gopherguard

**Agents fail like distributed systems and get attacked like web apps.**
So bring SRE and AppSec discipline, in a language built for both.

A production-grade, security-instrumented multi-agent system in ADK Go 2.0.

<!-- notes: Open with the thesis line verbatim — it's the README tagline and the spine of the whole talk. Land the two halves (SRE / AppSec) before moving on; everything else is the two halves built out. -->

---

# The thesis, in two halves

- **Fails like a distributed system** — coordinator + sub-agents + tool calls + model backend = partial failures, cascading timeouts, compounding retries
- **Attacked like a web app** — untrusted content in, an action out, is injection/privilege-abuse shaped
- Neither needs a new discipline — SRE and AppSec already exist
- Go: statically typed, observability-native, testing/vetting as first-class toolchain steps

<!-- notes: This is the "why Go" argument in miniature. Emphasize: not inventing new practice, just refusing to skip the practice that already exists because the thing calling itself "agent" feels novel. -->

---

# What ships

- Code-routed Coordinator → Researcher / DB Agent / Writer graph
- Trust-boundary OpenTelemetry on every span
- 8 OWASP Agentic (ASI) vulnerable/hardened pairs — fenced, simulated
- 5 trace-query attack detections — "SIEM for agent traces"
- Eval-gated CI/CD → Cloud Run, canary + auto-rollback

<!-- notes: This is the roadmap slide — five things, matches the five things in the summary doc. Tell the audience you'll walk each one in order. -->

---

# The agent graph

```
                 User
                   │
             ┌─────▼─────┐
             │Coordinator│  code-routed (Go if/switch)
             └──┬───┬───┬┘  NOT LLM-routed
                │   │   │
        ┌───────┘   │   └────────┐
   Researcher   DB Agent      Writer
  (search/egress) (MCP→Postgres)
```

(M5: Python analysis agent, reached via A2A from Coordinator)

<!-- notes: Point at the "NOT LLM-routed" annotation — that's the detail that matters more than the box diagram. Mention M5 briefly as forward-looking, not a current deliverable. -->

---

# Code-routed, not LLM-routed

- Coordinator dispatches via explicit Go `if`/`switch`, not a model call
- Control flow is auditable and testable like ordinary code
- Routing decisions can't be socially engineered by a crafted prompt
- Model calls reserved for tasks that need judgment — not for "which agent handles this"

<!-- notes: Key rhetorical move: this isn't "LLMs are bad at routing," it's "routing is exactly the kind of decision that shouldn't be probabilistic." Golden routing tests run in microseconds because there's no model in the loop. -->

---

# Model layer

- **Gemma-local** (default) — via Ollama, zero egress, no API key
- **Gemini** ("production mode") — opt-in via `GG_MODEL_MODE=gemini` + `GOOGLE_API_KEY`
- Cost-based router picks per request
- Every routing decision recorded as `model.route_reason` span attribute

<!-- notes: Local-first isn't a cost dodge — it's what makes vulnerable-mode labs run with zero egress and what keeps CI keyless. That keylessness pays off again in the eval section. -->

---

# Trust-boundary telemetry

Every span crossing a trust boundary carries a fixed attribute vocabulary:

| Attribute | Meaning |
|---|---|
| `trust.untrusted_input` | processed input from outside the boundary |
| `trust.privilege_scope` | scope this operation runs under |
| `trust.hitl_required` / `hitl_result` | human confirmation needed / outcome |
| `trust.egress` | performed or authorized outbound call |
| `agent.hop` | `src→dest` inter-agent handoff |
| `mem.provenance` | origin of memory read/write |

<!-- notes: This table is the spine everything downstream queries against — detections, evals, canary rollback all key off these literal attribute names. Emphasize "fixed and small," not something that grows per feature. -->

---

# The tool contract

```go
type ScopedTool interface {
    PrivilegeScope() string   // named privilege scope
    IsMutating() bool         // can change state
    TouchesUntrusted() bool   // reads/writes untrusted data
}
```

- Any `IsMutating() == true` tool requires a human-in-the-loop gate
- Outcome recorded as `trust.hitl_required` / `trust.hitl_result` on the span

<!-- notes: Small interface, does a lot of work — this is the hook the trust-boundary telemetry and the detections both hang off. Worth showing verbatim because it's genuinely three methods, not a framework. -->

---

# 8 OWASP Agentic (ASI) pairs

| Pair | Risk |
|---|---|
| ASI01 | Goal hijack / indirect prompt injection |
| ASI03 | Identity / privilege abuse |
| TOOL-MISUSE | Tool misuse (arg-level vs. command-level policy) |
| SANDBOX | Sandbox / config redefinition |
| MEMORY | Memory poisoning |
| A2A-TRUST | Inter-agent trust |
| CONFIG | Config-as-vector |
| SUPPLY-CHAIN | Supply chain |

<!-- notes: Each is a matched pair — vulnerable variant that demonstrates the failure, hardened variant that blocks the identical attack. Same task, same graph, one difference. Don't read every row aloud; point at 2-3 and move on. -->

---

# The safety fence

- Every vulnerable action is **simulated** — no working payloads
  - "egress" appends to an in-process sink; never real I/O
  - secrets are obvious placeholders; targets are `.invalid` domains
- Vulnerable mode refuses to start without `--i-understand-this-is-insecure`
- Binds to `127.0.0.1` only, forces local Gemma, prints a warning banner
- Never built into the Cloud Run deployable

<!-- notes: This slide exists to preempt the obvious question — "wait, you built working exploits?" No. The fence is architectural, checked in code and tests, not a comment saying "please don't misuse this." -->

---

# Running the pairs

```sh
# List the pairs — no fence needed, nothing runs
go run ./cmd/gopherguard-vuln --list

# Run all vulnerable-variant demos (fenced, simulated)
go run ./cmd/gopherguard-vuln --i-understand-this-is-insecure

# Run one pair
go run ./cmd/gopherguard-vuln --i-understand-this-is-insecure --pair ASI01
```

`go test ./internal/owasp/` proves every vulnerable variant is compromised and every hardened variant is not.

<!-- notes: The invariant that matters: vulnerable = Compromised=true, hardened = Compromised=false, enforced by test, not by eyeballing a transcript. -->

---

# From pairs to detections

- Same trust-boundary vocabulary is stamped on every pair's traces
- That turns a trace store into a queryable security log
- Detections are queries over **position relative to a trust boundary**, not content
- You don't grep for "looks like an attack" — you ask "did X precede Y"

<!-- notes: Bridge slide between the OWASP section and the detections section. The reframe: SIEMs don't grep firewall logs for suspicious strings, they query src_zone/dst_zone/action — same move, applied to agent spans. -->

---

# GG-DET-01: injection → exfil

```
{ trust.untrusted_input = true } >> { trust.egress = true }
```

- Find a span where untrusted input was processed
- Followed (`>>`, same session) by a span that performed egress
- Doesn't matter *what* the payload said — only the sequence of crossings
- Reference implementation: `internal/detect/rules.go`, `detectInjectionExfil`

<!-- notes: This is the demo query — the one to slow down on. Read it aloud literally: untrusted in, then egress out, same session, fires. Content-blind by design. -->

---

# The other 4 seed rules

| Rule | Fires when |
|---|---|
| GG-DET-02 | HITL required, not approved, action proceeded anyway |
| GG-DET-03 | Same span repeats >5× in a session (loop/cost runaway) |
| GG-DET-04 | `trust.privilege_scope` escalates across a session |
| GG-DET-05 | Untrusted-provenance memory consumed by a `write:*`-scoped span |

<!-- notes: Don't over-explain each one — the pattern is established by GG-DET-01. Point out GG-DET-05 is the payoff step of memory poisoning specifically. -->

---

# A detection isn't real until it has a counterexample

```go
if f := detectInjectionExfil(capturePair(t, "ASI01", false)); !f.Fired {
    t.Error("GG-DET-01 must fire on ASI01 vulnerable trace")
}
if f := detectInjectionExfil(capturePair(t, "ASI01", true)); f.Fired {
    t.Errorf("GG-DET-01 must be quiet on ASI01 hardened trace: %s", f.Evidence)
}
```

- Fires on the vulnerable trace, stays quiet on the hardened one — tested both directions
- Same predicate, three forms: Go (source of truth), TraceQL (Tempo), ClickHouse SQL

<!-- notes: The regression-suite framing is the point — a rule that's only tested one way is a rule nobody trusts. If someone "improves" a rule and it starts firing on hardened traces, this catches the false positive before it pages anyone. -->

---

# Seeing it run

```sh
make trace-up   # OTel Collector + Tempo + ClickHouse + Grafana, local
make detect     # fenced vuln-mode demo: run pairs, show fired/quiet rules
```

- `make detect` walks the OWASP pairs, shows trust attributes per span, and which `GG-DET-*` rule fired or stayed quiet
- Grafana dashboards visualize the same rules over live trace data

<!-- notes: This is the "let me show you a demo" beat for the deck — pause here if actually live-demoing. Otherwise narrate what the output looks like: vulnerable trace lights up a rule, hardened trace of the same scenario stays quiet. -->

---

# The agent is a YAML file now

- `deploy/agent.yaml` — model routing policy, per-agent tool grants, budgets, gate thresholds
- Strict parsing: unknown fields are a build error, not a silent zero-value
- Validator encodes **posture**, not just syntax:
  - rejects standing `write:egress` grants
  - rejects one agent holding both broad read *and* write scope
  - can't turn off `private_stays_local`

<!-- notes: The validator is where "we don't build agents like that" lives, independent of whether an eval would happen to catch it. Config PRs get the same review + gate as code PRs. -->

---

# Eval-gated CI/CD

- **Task-success** — golden prompts, graded as a pass *fraction* vs. a config threshold
- **Trajectory** — span/hop/loop budgets; loop budget *equals* the GG-DET-03 threshold by construction
- **Injection-resistance** — every pair's mapped detection must fire on vulnerable, stay quiet on hardened
- All three: `go test ./evals/...` — keyless, no model server required

<!-- notes: "A gate you can't run on every PR isn't a gate, it's a dashboard" — keylessness is why this actually runs on every PR instead of nightly. The trajectory/detection threshold equality is a nice detail: raising the loop budget without updating the detection threshold fails the gate. -->

---

# The gate has to have failed on purpose once

- Repo ships deliberate counterexamples:
  - a bad config that passes static validation but fails trajectory
  - a regressed classifier that fails task-success
  - a sabotaged "hardened" variant that fails injection-resistance
- `TestGateCatchesBadConfig` and friends — tests of the *gate*, not the agent
- CI posts a cost-delta comment for routing-policy changes

<!-- notes: "We have evals" vs "our evals have caught something at least once, on purpose" — that's the distinction this slide draws. Worth pausing on: this is the difference between decorative CI and CI you trust. -->

---

# make eval

```sh
make eval   # go test ./evals/... && go run ./cmd/ggeval -config deploy/agent.yaml
```

- Runs on every PR as a required merge status
- Fails loudly on routing regressions, budget blowouts, or a weakened hardened pair
- No API key, no Ollama sidecar — pure Go, deterministic where it can be

<!-- notes: Second half of the demo beat — show or narrate `make eval` failing red on a deliberately broken config, then passing green after a fix, if doing this live. -->

---

# Past the merge: canary + rollback

- Golden prompts replayed against the canary revision at low traffic, before real users
- `GG-DET-*` detections run against canary traffic as **rollback triggers**
- An injection→exfil chain on a canary trace = a failed health check, same tier as 5xx rate
- Only the hardened build is ever a candidate — vulnerable code never reaches Cloud Run

<!-- notes: This is the payoff line for the whole telemetry investment: a security detection becomes as mechanical a rollback signal as an elevated error rate, and it fires at 10% blast radius instead of 100%. -->

---

# Why this matters for GDE / production agents

- Agents with real tool access (databases, email, deploys) need more than "the demo looked cool"
- None of the pieces here are novel — golden tests, canary deploys, GitOps, structured telemetry
- What's missing industry-wide is the **plumbing**: wiring those checks to the merge button and the deploy, not just having them exist somewhere
- gopherguard is public, runs on local Gemma with zero API key — clone it and `make run`

<!-- notes: Closing slide. Land on: this isn't a claim that agents are uniquely scary, it's a claim that the tools to make them boring already exist and mostly aren't wired together. Point to the repo and the Makefile targets as the call to action. -->
