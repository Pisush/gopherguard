# M0 build log: scaffolding a security-instrumented ADK Go 2.0 agent (the honest version)

*Draft — gopherguard milestone M0. Numbers marked `<!-- VERIFY -->` are unconfirmed until checked against a primary source at publish time.*

## The thesis, restated in one line

Agents fail like distributed systems and get attacked like web apps — so bring SRE and AppSec discipline, in a language built for both. gopherguard is that argument in code: a production-grade multi-agent system in ADK Go 2.0, shipped as vulnerable/hardened pairs mapped to the OWASP Agentic Top 10, with trust-boundary telemetry and eval-gated CI/CD.

M0 is just the scaffold. But even the scaffold made three decisions worth writing down, because each one is a small bet that the rest of the project rides on.

## Decision 1: the toolchain gap nobody warns you about

ADK Go 2.0 (GA 2026-06-30) requires **Go 1.25+**. The build box had Go 1.22.1. The instinct is to `brew upgrade go` — but that mutates every other project on the machine.

The better move is Go's own toolchain directive. Pin the language version and a concrete toolchain in `go.mod`:

```
go 1.25

toolchain go1.25.11
```

With `GOTOOLCHAIN=auto` (the default), the installed Go 1.22 transparently downloads and runs go1.25.11 **for this module only**. No system upgrade, no disturbing the other 40 repos in `~/Projects`.

One gotcha: a bare `go 1.25` will try to fetch a toolchain literally named `go1.25`, which is not a real release — releases are `go1.25.0`, `go1.25.11`, and so on. Pin the patch version explicitly.

## Decision 2: Gemma-local is the default, not the fallback

Every model call in gopherguard defaults to Gemma running locally via Ollama. Gemini is opt-in "production mode" behind `GOOGLE_API_KEY`. This isn't a cost dodge — it's what keeps demos offline-capable and CI **keyless**, and it's what lets vulnerable-mode labs run with zero egress.

The `model.LLM` interface in ADK 2.0 is refreshingly small:

```go
type LLM interface {
    Name() string
    GenerateContent(ctx context.Context, req *LLMRequest, stream bool) iter.Seq2[*LLMResponse, error]
}
```

Two methods, and it hands you Go 1.23's `iter.Seq2` for streaming. Writing an Ollama adapter is then just: translate `[]*genai.Content` into Ollama's `/api/chat` schema, POST to `127.0.0.1:11434`, yield one `*LLMResponse`. No SDK, no key, no cloud.

The router that sits above the adapters is deliberately **not** an LLM. Routing between Gemma and Gemini is plain Go — a struct of task hints and a `switch`. Every routing decision emits a `model.route_reason` so cost and latency are attributable later. That "routing is code, not a model call" stance is one of the project's core arguments against LLM-routed frameworks.

## Decision 3: the safety fence is real from commit one

Vulnerable variants demonstrate *failure patterns*, never shippable exploits. To make that a boundary rather than a promise, the vulnerable-mode launcher refuses to start without `--i-understand-this-is-insecure`, forces local Gemma, unsets any API key, and prints a loud banner — all in M0, before a single vulnerable variant exists (those land in M2).

Add a pre-commit secret scan while you're at it. It's twenty lines of bash and it's the difference between "we have a secrets policy" and "we enforce a secrets policy."

## What M0 actually ships

- Go module pinned to `google.golang.org/adk/v2` + `google.golang.org/genai` on the go1.25 toolchain.
- Gemma (Ollama) adapter as default, Gemini adapter opt-in, cost-based router.
- A `ScopedTool` contract — every tool declares `PrivilegeScope()`, `IsMutating()`, `TouchesUntrusted()` — enforced by a registration guard. This metadata is the hook the trust-boundary telemetry (M1) and detections (M3) hang off.
- One runnable agent: `make run` starts a coordinator with a single `world_clock` tool on local Gemma, no key.
- Fenced vulnerable-mode launcher, pre-commit secret scan, Apache-2.0, devcontainer.

**Acceptance:** `go build ./...`, `go vet ./...`, and `go test ./...` all green; both binaries build; the vulnerable-mode fence verified to refuse an unacknowledged start.

## Two gotchas the live run caught (that unit tests wouldn't)

Building green is not the same as working. Two things only showed up when an actual agent turn ran against a real local model:

1. **The embedded-interface tool trap.** ADK discovers a tool's capabilities by type-asserting the concrete tool to internal interfaces (`FunctionTool` with `Declaration()`/`Run()`, `RequestProcessor` with `ProcessRequest()`). A "scoped tool" wrapper that embeds the `tool.Tool` *interface* forwards only three methods and hides the rest — so the agent rejects it at runtime with `does not implement RequestProcessor()`, even though everything compiles. The fix is to never wrap: carry security metadata *alongside* the untouched tool and hand ADK the raw tool. (There's a regression test pinning this now.)

2. **Gemma doesn't do native tool-calling — and that's a design input, not a bug.** ADK's tool loop assumes a function-calling-capable model. Ask Ollama to run `gemma2:2b` with a `tools` array and it flatly returns `does not support tools`. So the small local default will *hallucinate* a plausible answer (it confidently told me the time in Tokyo — off by hours, and in one run dated the reply to 2023) rather than call the `world_clock` tool. The mandate is Gemma-local-by-default, so the answer is not "switch models" — it's to build a **prompt-based (ReAct-style) tool bridge** into the Gemma adapter so local models can still drive tools deterministically. That's now an explicit M1 task.

The lesson is old and boring and true: a green `go build` proves your types line up, not that your system works. Drive the real path.

## What's next (M1)

The full code-routed graph — coordinator, researcher, dbagent, writer — with native OTel carrying the trust-boundary attribute vocabulary (`trust.untrusted_input`, `trust.egress`, `trust.hitl_required`, …), HITL gates on mutating tools, and least-privilege scoping. Plus the Gemma tool-bridge from the gotcha above, so local-default agents actually invoke tools. That's where the telemetry spine gets built — the same spine M3 will later query to *catch* attacks.

---

*Publishing note: the "eval gap" and adoption-cancellation statistics planned for later posts (LangChain state-of-agent-engineering, the Gartner 40% cancellation prediction, the Apiiro 322% figure) are all `<!-- VERIFY -->` until confirmed against primary sources.*
