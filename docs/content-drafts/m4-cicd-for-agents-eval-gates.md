# CI/CD for agents: eval gates, canary prompts, GitOps for YAML agents

*Draft — gopherguard milestone M4. Content draft for engineer-to-engineer publication; unverified claims are marked inline with `<!-- VERIFY -->`.*

Nobody merges a payments PR because "the diff looked reasonable." Yet that's roughly the bar most teams apply to agent changes: tweak a prompt, eyeball two transcripts, ship. The industry has spent two years arguing about which evals to run and close to zero time wiring any of them into the one place they change behavior — the merge button. M4 in gopherguard is that wiring: a keyless eval harness, a YAML agent config as the GitOps source of truth, and a GitHub Actions gate that fails the PR when the agent regresses, with a canary stage that extends the same gate past the merge into production traffic.

## An eval that can't run on every PR isn't a gate

The first design constraint sounds banal and eliminates most eval setups: the suite has to run in CI, on every PR, with no API key and no local model server. If your evals need an Ollama sidecar or a metered API, they run nightly at best, and a nightly eval is a dashboard, not a gate — the regression merges in the morning and the graph turns red at midnight.

gopherguard's answer is to aim the evals at the parts of the agent that are deterministic by construction, which — if you've been following the earlier milestones — is deliberately most of it:

- **Routing is Go code**, not a model call. The coordinator classifies requests with a `switch` statement, so "does the coordinator route correctly" is a golden test that runs in microseconds.
- **Attacks are simulated pairs.** The OWASP ASI vulnerable/hardened pairs emit real OpenTelemetry traces without any model in the loop, so injection-resistance is a trace assertion, not a red-team session.
- **Tool privileges are metadata.** Least-privilege grants live on the tools themselves, so config/code drift is a set comparison.

Three suites fall out of this, all runnable via `go test ./evals/...` on a runner with nothing installed but Go:

**Task-success, tolerance-graded.** A golden set of prompts with expected routes. The grade is a pass *fraction* checked against a threshold in the agent config (`routing_pass_rate`), not all-or-nothing — you can tolerate one borderline golden by policy while an actual regression (say, a refactor that makes everything route to the writer) scores 0.33 and fails loudly. Golden evals for agents want tolerance knobs, because "exactly equal output" is the wrong bar even for deterministic components once you start editing the golden set itself.

**Trajectory.** Task success tells you the agent got there; trajectory tells you it didn't get there by doing something insane. The suite captures traces and checks them against budgets from the config: max spans per session, max agent hops, and a loop budget that must *equal* the detection threshold in the trace-query rules (`internal/detect.LoopThreshold`). That equality check matters more than it looks: it means the budget the deploy honors and the threshold the SIEM alarms on are the same number by construction, and a config PR that quietly raises the loop budget to 50 fails the gate because the detection still fires at 5.

**Injection-resistance regression.** Every attack the hardened path blocks becomes a permanent test. For each OWASP pair, the suite asserts the mapped detection fires on the vulnerable trace (GG-DET-01 and GG-DET-04 on ASI01's injection→exfil chain, GG-DET-05 on memory poisoning) *and* that every rule stays quiet on every hardened trace. The second half is the underrated one — it's simultaneously a hardening-regression guard and a false-positive guard for the detections themselves. Delete the egress gate from the hardened ASI01 variant and the "all rules quiet on hardened" check fails; make GG-DET-01 oversensitive and the same check fails from the other direction.

A gate you've never seen fail is a gate you should assume doesn't work, so the repo ships its own counterexamples: a deliberately-bad agent config that passes static validation but fails the trajectory suite, a regressed classifier that fails task-success, and a sabotaged "hardened" variant that fails injection-resistance. Those are tests of the *gate*, not the agent — `TestGateCatchesBadConfig` and friends in `evals/` — and they're the difference between "we have evals" and "our evals have caught something at least once, on purpose."

## The agent is a YAML file now

The second piece is treating the agent's shape as config under GitOps discipline: `deploy/agent.yaml` declares the model routing policy, per-agent tool grants, budgets, and gate thresholds. Two decisions there earn their keep:

**Strict parsing.** Unknown fields are an error (`yaml.Decoder.KnownFields(true)` in Go <!-- VERIFY: exact API name -->). In a config that *is* the deployment, a typo'd `budgets:` block that silently parses to zero-values is a security incident deferred; strict mode turns it into a red PR check instead.

**Validation encodes posture, not just syntax.** The static validator rejects `write:egress` as a standing grant, rejects any single agent holding both `read:web` and a `write:*` scope (that combination is the injection→action shape as a capability, before any prompt is involved), and refuses to let `private_stays_local` be turned off. Some configs are wrong even if every eval would pass — the validator is where "we don't build agents like that" lives.

Because the config is gated like code, an agent change and a code change are the same event: PR, eval gate, review, merge. The CI job also computes a cost estimate from the config's routing policy (escalation rate × remote-model price × average tokens) for both the PR's config and the base branch's, and posts the delta as a sticky PR comment. It's a back-of-envelope number, not billing — but it means the reviewer of a one-line `escalation_rate: 0.10 → 0.35` change sees the dollars-per-thousand-requests implication in the same view as the diff, which is exactly the kind of change that otherwise sails through review looking harmless.

## Canary prompts, canary traffic, and detections as health checks

Past the merge, the same philosophy extends into the deploy (`deploy/deploy.sh` — shipped as a documented plan-mode pipeline for Cloud Run; the cloud specifics are marked unverified in the script). The shape is standard canary: deploy a tagged revision with no traffic, smoke it, shift 10%, watch, then promote or roll back. Two agent-specific twists:

**Canary prompts.** The smoke stage doesn't just hit `/healthz` — it replays the eval harness's golden prompts against the canary URL before the revision sees a single user request. The golden set does double duty: merge gate in CI, canary probe in deploy. If a prompt that must route to the researcher starts routing to the writer only under production config, you find out at 0% traffic.

**Detections as rollback triggers.** The watch window monitors 5xx rate like any canary, plus something canaries usually don't have: the M3 trace-query detections, filtered to the canary revision. Any `GG-DET-*` rule firing on a canary trace triggers automatic rollback. This is the payoff of stamping trust-boundary attributes on every span — "injection→exfil chain observed" becomes as mechanical a rollback signal as "error rate above 1%," and it fires at 10% blast radius instead of 100%. A security detection on production traffic is a failed health check, not a Slack thread.

## The gate is the product

The uncomfortable summary of M4 is that none of the individual pieces are novel — golden tests, trajectory budgets, canary deploys, and GitOps are all decades or years old. What's missing in agent engineering isn't techniques, it's *plumbing*: the discipline of making every one of those checks a required status on the merge and a rollback trigger on the deploy. Agents fail like distributed systems and get attacked like web apps; M4's claim is that they should ship like both, too — behind a gate that has actually failed on purpose at least once, over a config file that can't drift from the code it describes.

Next (M5): stretching one trace across two runtimes — a Go coordinator calling a Python analysis agent over A2A, with `agent.hop` keeping the cross-language handoff visible to the same detections.
