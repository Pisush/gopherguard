# Podcast script: "gopherguard" (draft)

*DRAFT — conversational script, gopherguard project overview. HOST A is a curious generalist (agents-curious, not deep in Go or security). HOST B built the project. Unverified external claims marked `<!-- VERIFY -->`.*

---

**HOST A:** Okay, so today we're talking about a project called gopherguard, which — I've been told — is not actually a guard dog mascot, it's a security-instrumented multi-agent system written in Go. Which is already three things I want to unpack. Welcome.

**HOST B:** Thanks for having me. And yeah, "gopherguard" is a pun on the Go gopher, I will not apologize for it.

**HOST A:** I wouldn't ask you to. Okay, let's start with the thesis, because you've got this line you keep repeating — "agents fail like distributed systems and get attacked like web apps." Walk me through that.

**HOST B:** Sure. So the claim has two halves, and they come from two different failure modes people already understand. Half one: agents fail like distributed systems. You've got multiple components talking to each other — a coordinator, some sub-agents, tool calls, maybe a database, maybe a search API — and that's a distributed system now, whether you meant it to be or not. Which means you get partial failures, retries that cascade, timeouts, one slow dependency taking down a whole request. None of that is new. SREs have been dealing with that for twenty years.

**HOST A:** Right, that's just... microservices with extra steps.

**HOST B:** Basically. Half two is the part people talk about less: agents get attacked like web apps. Injection, privilege abuse, trust boundary violations — an agent that reads untrusted content and then takes an action is structurally the same problem as an app that takes user input and runs a SQL query with it. We've had decades of AppSec discipline for that shape of problem. So the thesis is: don't invent a new discipline for agents, bring the two disciplines that already exist — SRE and AppSec — and go build it in a language that's actually good at both.

**HOST A:** Which is the pitch for Go.

**HOST B:** Which is the pitch for Go, yeah.

**HOST A:** So let's talk about that. Why Go, and why specifically ADK Go 2.0? Because I feel like ninety percent of the agent ecosystem right now is Python.

**HOST B:** It is, and there are good reasons for that — the model ecosystem, the notebooks, the research culture. But once you're not researching anymore, once you're trying to ship something that has to be correct under load and auditable when something goes wrong, a lot of that flexibility becomes a liability. Go gives you static typing, a toolchain built around testing and vetting code as a first-class step, and a concurrency model that's actually pleasant for the "coordinator fans out to three sub-agents" shape. ADK — Google's Agent Development Kit — shipped a Go version, 2.0, and it's got a genuinely small model interface. Two methods: `Name()` and `GenerateContent()`, and that second one hands you back `iter.Seq2` for streaming, which is Go 1.23's iterator support. Writing an adapter for a new model backend is not a big lift.

**HOST A:** And you're not always calling out to a paid API, right? I remember reading that the default is local.

**HOST B:** Yeah — Gemma running locally through Ollama is the default model, not a fallback. `make run` starts the whole thing against local Gemma, zero egress, no API key. Gemini is opt-in, "production mode," behind an environment variable and a key. And that's not really a cost-saving move, or not only — it's what keeps the vulnerable-mode labs safe to run with zero egress, and it's what keeps CI keyless, which matters a lot once we get to the eval-gating part.

**HOST A:** Okay, hold that thought, I want to come back to CI. First — the actual architecture. You've got a "code-routed" graph. What does that mean and why is it a whole talking point instead of just... an implementation detail?

**HOST B:** So here's the setup: there's a Coordinator, and it dispatches to a Researcher agent, a DB agent, and a Writer agent. Sounds like a normal multi-agent graph. The question is: how does the Coordinator decide who handles a given request?

**HOST A:** I'm guessing — ask the LLM "which agent should handle this"?

**HOST B:** That's what a lot of frameworks do by default, yeah. LLM-routed: you hand the model a description of your sub-agents and let it pick. gopherguard does the opposite on purpose. The Coordinator routes with plain Go — `if`/`switch` logic, explicit code. Not a model call.

**HOST A:** Why does that matter so much? Isn't the LLM routing thing kind of the point of agents?

**HOST B:** For some things, sure. But think about what you're buying and what you're giving up. If routing is a model call, then your control flow — which agent gets which privileges, which agent can reach the database — is now downstream of a prompt. It's opaque, and worse, it's attacker-influenced, because anything that can influence the model's output can potentially influence routing. If routing is Go code, it's auditable the way any other code is auditable. You can unit test it. You can `go vet` it. A golden set of "this prompt should route to the researcher" cases becomes a deterministic test that runs in microseconds, not a probabilistic thing you're hoping holds up. And it removes an entire class of "the model got socially engineered into routing to the wrong agent" attack, because there's no model in that decision at all.

**HOST A:** So it's not "LLMs are bad at routing," it's "routing is exactly the kind of decision you don't want to be probabilistic."

**HOST B:** Exactly. Save the model calls for the parts that actually need judgment — summarizing search results, writing the response. Not for "which internal function do I call."

**HOST A:** Okay. Now — the telemetry. This is the part I found genuinely interesting when I was reading through it, because it's not "add logging," it's a specific vocabulary.

**HOST B:** Right, this is the spine the whole project hangs off. Every span that crosses what we call a trust boundary — a tool call, a hop from one agent to another, a memory read or write — gets stamped with a fixed set of OpenTelemetry attributes. `trust.untrusted_input`, a bool: did this span process something that came from outside the trust boundary, like tool output or another agent's message. `trust.privilege_scope`, a string: what scope is this operation running under. `trust.hitl_required` and `trust.hitl_result`: did this need a human to confirm it, and what happened when it asked. `trust.egress`: did this span send something outbound. `agent.hop`: source-to-destination for an inter-agent handoff. `model.route_reason`: why the router picked Gemma or Gemini for this call. And `mem.provenance`: where a piece of memory actually came from.

**HOST A:** That's a lot of attributes to remember.

**HOST B:** It's a small, fixed vocabulary though, that's the whole design constraint — it doesn't grow per feature. And the payoff is: once every span has these, your trace store stops being "logs you read after something goes wrong" and starts being a thing you can query. Which — that's basically what a SIEM is. We'll get to that.

**HOST A:** Let's actually go there next, because before detections, I want to talk about the vulnerable pairs, because that's the part that sounds the riskiest to build. You're deliberately writing insecure agents?

**HOST B:** We are, and I want to be really precise about the framing because it's the part I'm most careful about. gopherguard implements eight pairs mapped to the OWASP Agentic Security Initiative Top Ten — the ASI list. Things like goal hijack through indirect prompt injection, identity and privilege abuse, tool misuse, sandbox or config redefinition, memory poisoning, inter-agent trust — where a sub-agent's instructions get trusted blindly — config as an attack vector, and supply chain risk. Each one is a pair: a vulnerable variant that demonstrates the failure pattern, and a hardened variant that blocks the same attack.

**HOST A:** And the "no shippable exploits" thing — that's not just a disclaimer, that's architectural?

**HOST B:** It has to be, or it's just irresponsible. So: every action in the vulnerable variants is simulated. "Egress" appends to an in-process sink, it never actually makes a network call. Fake secrets are obvious placeholders. Any target string is an RFC-reserved `.invalid` domain, so even if someone copy-pasted it somewhere it wouldn't resolve to anything real. And on top of that, there's a launch fence: vulnerable mode refuses to start without an explicit flag — `--i-understand-this-is-insecure` — binds to localhost only, forces local Gemma so there's no external API call even accidentally, and prints a warning banner. It's never built into the deployable Cloud Run image. So the thing that ships to production physically cannot contain the vulnerable code paths.

**HOST A:** So it's a teaching artifact with a lock on it.

**HOST B:** That's a good way to put it, yeah. The point is to demonstrate the *pattern* — what does privilege abuse actually look like in an agent trace — not to hand anyone a working attack.

**HOST A:** Okay, so now the payoff — you've got these vulnerable and hardened pairs, both stamped with the same trust-boundary telemetry. What do you do with that?

**HOST B:** This is the part I called SIEM for agent traces. The instinct when people want to catch bad agent behavior is to grep the logs for something that looks suspicious — a weird URL, a phrase that looks like an injection attempt. That approach has the same shelf life as string-matching malware signatures. It catches what you already thought of, worded the way you already thought of it.

**HOST A:** And misses everything else.

**HOST B:** Right. So instead, the detections are queries over the trust attributes, not over content. Let me give you the canonical one, because it's almost annoyingly simple once you see it. ASI01 — goal hijack via injection — has a shape: untrusted content enters the agent's context, and later, data leaves the boundary. As a query, that's:

```
{ trust.untrusted_input = true } >> { trust.egress = true }
```

**HOST A:** Wait, say that again in English.

**HOST B:** Find a span where untrusted input was processed. Then, later in the same session, find a span where egress happened. If both exist, in that order, fire. It genuinely does not matter what the injection payload said — a poisoned webpage, a crafted support ticket, whatever. The query doesn't read content. It reads the sequence of trust-boundary crossings. That's `GG-DET-01` in the codebase.

**HOST A:** And there are more of these?

**HOST B:** Five seed rules total. `GG-DET-02` is HITL bypass — something needed human approval, didn't get an "approved" result, and the action happened anyway. `GG-DET-03` is a loop or cost runaway — the same span repeating past a threshold, five in our case, which is a budget breach independent of whether any individual call looks harmful. `GG-DET-04` is privilege widening — scope escalating across a session, read to write to admin, instead of holding steady. `GG-DET-05` is memory taint — untrusted-provenance memory getting consumed by a later write-scoped action, which is the actual payoff step of memory poisoning.

**HOST A:** And these get tested how? Because "we wrote a query" and "we know the query works" are different claims.

**HOST B:** That's the discipline part. A detection isn't real until it fires on the known-bad trace and stays quiet on the known-good one. So for every rule, the test suite captures both the vulnerable and hardened variant of the matching pair in-process, runs the rule against each, and asserts the vulnerable one fires and the hardened one doesn't. If someone "improves" a rule and it starts firing on hardened traces too, that's a false positive and the test catches it before it pages anyone. If a change makes it stop firing on the vulnerable trace, that's a false negative slipping through, and the test catches that too.

**HOST A:** Both directions.

**HOST B:** Both directions, always. A rule that only gets tested one way is a rule nobody actually trusts.

**HOST A:** Okay — I want to see this, actually. Can we do the demo thing?

**HOST B:** Yeah, let's do it. So there's a Makefile target — `make detect` — which runs the fenced vulnerable-mode binary with a `--detect` flag. It runs through the OWASP pairs, and for each one it shows you: here's the vulnerable variant's trace, here are the trust attributes on each span, here's which `GG-DET` rule fired and why, and here's the hardened variant's trace running the identical scenario, staying quiet.

**HOST A:** So side by side, same attack shape, one gets caught and one doesn't even trip the alarm.

**HOST B:** Exactly. And separately, if you actually want the production-shaped version, there's `make trace-up`, which stands up a local OTel Collector plus Tempo plus ClickHouse plus Grafana, and the same five rules exist as TraceQL for Tempo and SQL for ClickHouse — attribute for attribute, matching the Go implementation. So it's not "here's a cute test harness" and separately "here's what actually runs in prod" — it's the same predicate, expressed twice, tested against the same fixtures.

**HOST A:** Okay, last piece, and I think this is the one that ties it all together — the CI/CD story. Because a detection is only useful if it's actually gating something.

**HOST B:** Right, this is M4, and I think of it as: nobody merges a payments PR because "the diff looked reasonable," but that's basically the bar most teams apply to an agent change — tweak a prompt, eyeball a couple transcripts, ship. So the goal was: wire evals into the one place that actually changes what ships, which is the merge button.

**HOST A:** And you said keyless earlier — that mattered here too?

**HOST B:** It mattered even more here, honestly. If your eval suite needs an API key or a model server sidecar, it runs nightly at best, and a nightly eval is a dashboard, not a gate — the regression already merged by the time it turns red. So the suites are aimed at the parts of the system that are deterministic by construction. Which, because routing is Go code and the attacks are simulated pairs with no model in the loop, turns out to be most of it. Three suites: task-success — a golden set of prompts with expected routes, graded as a pass fraction against a threshold, not all-or-nothing. Trajectory — did the agent get there without doing something insane, checked against budgets like max spans and max hops. And injection-resistance — for every OWASP pair, assert the mapped detection fires on the vulnerable trace and stays quiet on every hardened trace. All of it runs with `go test`, no API key, no local model server needed.

**HOST A:** `make eval`, I assume.

**HOST B:** `make eval`, yeah — runs the eval suite and a small `ggeval` binary against the agent's YAML config.

**HOST A:** And the config itself is under the same discipline?

**HOST B:** That's the other half — the agent's shape lives in a YAML file, `deploy/agent.yaml`, under GitOps discipline. Strict parsing, so an unknown field is a build failure, not a silent zero-value. And the validator encodes posture, not just syntax — it rejects a standing `write:egress` grant, rejects any single agent holding both broad read and write scopes at once, because that combination is the injection-to-action shape as a capability, before any actual prompt is involved.

**HOST A:** So the config PR gets the same gate as a code PR.

**HOST B:** Same gate, same review, and there's even a cost-delta comment — a back-of-envelope estimate of what a routing-policy change does to your per-thousand-request cost, posted right on the PR. And past the merge, the same philosophy extends into a canary deploy to Cloud Run: golden prompts get replayed against the canary at low traffic before real users see it, and — this is the part I like most — the same `GG-DET` detections run against canary traffic as a rollback trigger. An injection-to-exfil chain showing up on a canary trace is treated exactly like an elevated error rate. It's a failed health check, not a Slack thread somebody notices Monday.

**HOST A:** That's a genuinely different posture than "we'll look at the logs if something seems off."

**HOST B:** That's the whole bet. None of the individual pieces here are novel — golden tests, canary deploys, GitOps, that's all old. What's actually missing in most agent projects isn't technique, it's plumbing — making every one of those checks a required status on the merge, and a rollback trigger on the deploy.

**HOST A:** Alright, I think that's a great place to land it. If people want to actually poke at this?

**HOST B:** It's a public repo — clone it, `make run` gets you the hardened agent against local Gemma with zero setup cost, `make detect` gets you the demo we just talked through, and the docs — architecture and the OWASP mapping — are both there for the details we didn't have time for today.

**HOST A:** Perfect. Thanks for walking through it.

**HOST B:** Thanks for having me.

---

*<!-- VERIFY --> Any adoption/market statistics referenced elsewhere in the content suite (industry eval-gap figures, agent-cancellation predictions) are explicitly out of scope for this script and were not asserted here.*
