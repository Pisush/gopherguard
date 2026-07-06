# deploy/ — eval-gated CI/CD for a YAML agent

This directory is the GitOps + deploy half of M4. The eval suites themselves
live in [`evals/`](../evals); the CI wiring is
[`.github/workflows/evals.yml`](../.github/workflows/evals.yml).

## agent.yaml — the agent as config

[`agent.yaml`](agent.yaml) describes the deployed agent the way a Kubernetes
manifest describes a workload:

- **model routing policy** — local Gemma vs Gemini, the privacy invariant
  (`private_stays_local` can never be turned off; validation rejects it), and
  the cost inputs the CI summary uses.
- **least-privilege tool grants** — per agent, which tools it holds and which
  scopes those tools may exercise. The eval harness cross-checks this against
  what the code actually grants (`internal/tools` + `internal/security`), so
  YAML and code cannot drift apart in either direction.
- **budgets** — max steps per session, the loop budget (pinned to
  `internal/detect.LoopThreshold` so the deployed budget and the GG-DET-03
  detection cannot disagree), max agent hops.
- **gates** — tolerance thresholds for the graded suites (golden-routing pass
  rate, minimum OWASP pairs holding).

Because the config is part of the gated surface, **changing `agent.yaml` is a
code change**: the PR runs the full eval gate, and the eval-summary comment
shows the estimated cost delta against the base branch's config.

Parsing is strict (`KnownFields`): a typo fails the gate instead of silently
deploying a default.

## The gate

`make eval` runs, keyless and offline:

1. **config** — static policy validation (scope shapes, no `write:egress`,
   no read-untrusted+write agent, privacy invariant).
2. **task-success** — golden outputs, tolerance-graded: coordinator routing
   goldens, keyless graph assembly, tool-grant cross-check, private-stays-local
   routing invariant.
3. **trajectory** — captured traces within step/loop/hop budgets; every golden
   route lands on a configured agent via a sane coordinator→agent path.
4. **injection-resistance** — every OWASP ASI pair is a permanent regression
   test: the mapped detection fires on the vulnerable trace, every rule stays
   quiet on every hardened trace, and the HITL-bypass/loop fixtures pin the
   fixture-backed rules.

CI runs the same command on every PR (`.github/workflows/evals.yml`). To make
it merge-blocking, mark the two jobs as required status checks:
**Settings → Branches → main → require `build / vet / test` and `eval gate`.**

`evals/testdata/agent-bad.yaml` is the proof the gate has teeth: structurally
valid, passes static validation, fails the trajectory suite
(`TestGateCatchesBadConfig`). `TestGateCatchesRegressedClassifier` and
`TestGateCatchesHardeningRegression` do the same for a routing regression and
a deleted mitigation.

## Canary + auto-rollback (concept)

[`deploy.sh`](deploy.sh) is the documented Cloud Run pipeline. Default is
`--plan` (prints every step, executes nothing); `--execute` runs it against a
configured gcloud project. Cloud specifics that have not been verified against
a live project are marked `UNVERIFIED` in the script.

```
make eval ──▶ build (hardened only) ──▶ push ──▶ deploy --no-traffic --tag canary
                                                        │
                                              smoke: /healthz + eval probe
                                                        │
                                              update-traffic canary=10%
                                                        │
                              watch window: 5xx rate + GG-DET rules on canary traces
                                       │                          │
                                   all quiet                 anything fires
                                       │                          │
                             update-traffic canary=100%   AUTO-ROLLBACK to previous
                                                          revision (canary tag kept
                                                          for forensics)
```

The interesting rollback trigger is the third one: the **M3 detections run
against canary traces** (the `detections/` TraceQL/ClickHouse queries filtered
to the canary revision). A `GG-DET-*` rule firing on production traffic is
treated like a failing health check — the canary is rolled back automatically,
because an injection→exfil chain at 10% traffic is still an injection→exfil
chain.

Only `cmd/gopherguard` (hardened) is ever built into the image; the script
refuses to proceed if the vuln launcher is present in the build context.
