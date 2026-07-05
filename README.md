# gopherguard

> Agents fail like distributed systems and get attacked like web apps — so bring SRE and AppSec discipline, in a language built for both.

## What is this

gopherguard is a production-grade, security-instrumented multi-agent system built on ADK Go 2.0. It ships matched vulnerable/hardened agent pairs mapped to the OWASP Agentic Security Initiative (ASI) Top 10, instrumented end-to-end with trust-boundary OpenTelemetry so that privilege scope, untrusted input, human-in-the-loop outcomes, and inter-agent hops are all first-class span attributes. On top of that telemetry sit trace-query attack detections and an eval-gated CI/CD pipeline that deploys only the hardened build to Cloud Run.

## Status

Milestones, tracked M0 → M5:

- [x] **M0** — Scaffold (module, docs, CI skeleton, dev environment) — *in progress*
- [ ] **M1** — Hardened baseline agent (Coordinator/Researcher/DB/Writer on Gemma-local)
- [ ] **M2** — Vulnerable/hardened OWASP Agentic Top 10 pairs
- [ ] **M3** — Trust-boundary telemetry + trace-query detections
- [ ] **M4** — Eval-gated CI/CD to Cloud Run
- [ ] **M5** — Polyglot A2A (Python analysis agent)

## Quickstart

Prerequisites:

- Go 1.25+
- [Ollama](https://ollama.com), with the local model pulled: `ollama pull gemma2:2b`

Then:

```sh
cp .env.example .env
make run
```

`make run` starts the hardened-mode agent against local Gemma via Ollama — zero egress, no API key required.

To opt into Gemini "production mode" instead, set `GOOGLE_API_KEY` and `GG_MODEL_MODE=gemini` in `.env` before running.

## Repository layout

```
cmd/gopherguard         hardened-mode entrypoint (deployable)
cmd/gopherguard-vuln     fenced vulnerable-mode lab entrypoint (never deployed)
internal/agents          Coordinator/Researcher/DB/Writer agent definitions
internal/model           Gemma-local / Gemini model router
internal/tools           ScopedTool implementations (search, MCP/Postgres, etc.)
internal/telemetry       trust-boundary OpenTelemetry instrumentation
internal/security        HITL, policy, and trace-query detection logic
internal/memory          provenance-tagged session/agent memory
vulnerable/              OWASP ASI vulnerable pattern implementations
hardened/                corresponding hardened mitigations
detections/              trace-query attack detection rules
evals/                   eval suite gating CI/CD
deploy/                  Cloud Run deploy pipeline config
docs/                    architecture, OWASP ASI mapping, and design notes
```

## Safety

- Vulnerable variants exist to **demonstrate failure patterns** for teaching and testing detections — they are never shippable exploits and contain no working payloads or real target strings.
- Vulnerable mode is fenced: it refuses to start without `--i-understand-this-is-insecure`, binds to `127.0.0.1` only, forces Gemma-local (no external API calls), prints a warning banner on startup, and is never built into a Cloud Run deployable.
- Secrets are never committed. Only `.env.example` (placeholders) is tracked; real values are injected at runtime in dev and via Secret Manager in production.

See [docs/owasp-mapping.md](docs/owasp-mapping.md) and [docs/architecture.md](docs/architecture.md) for details.

## Model layer

- **Gemma-local** (default) — runs via Ollama, zero egress, no API key.
- **Gemini** (opt-in "production mode") — requires `GOOGLE_API_KEY` and `GG_MODEL_MODE=gemini`.
- A cost-based router selects between them per request and records the decision as a `model.route_reason` span attribute.

## License

Apache-2.0 — see [LICENSE](LICENSE).

Module: `github.com/Pisush/gopherguard`
