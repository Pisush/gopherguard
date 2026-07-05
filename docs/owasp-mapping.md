# OWASP Agentic Top 10 (ASI) mapping

This is the master index for milestone M2. Each row maps an OWASP Agentic
Security Initiative (ASI) risk to the vulnerable pattern gopherguard
implements (fenced, non-deployable), the corresponding hardened mitigation,
a narrative incident anchor for context, and its current implementation
status.

Each pair is implemented in `internal/owasp/` as a self-contained
demonstration with a vulnerable variant (returns `Compromised=true`) and a
hardened variant that blocks the same attack (`Compromised=false`). Every
variant emits trust-boundary telemetry so the M3 detections fire on the
vulnerable trace and stay quiet on the hardened one.

| Pair ID | Risk | Vulnerable pattern (fenced) | Hardened mitigation | Incident anchor (narrative) | Status |
|---|---|---|---|---|---|
| ASI01 | Goal Hijack / Indirect Prompt Injection | indirect injection via poisoned tool output | content isolation + egress gate after untrusted read | Unit 42 in-the-wild indirect injection | implemented (M2) |
| ASI03 | Identity / Privilege Abuse | one over-scoped credential for all tools | per-tool scoped identities, least privilege | over-privileged refund-bot pattern | implemented (M2) |
| TOOL-MISUSE | Tool Misuse | command-level allowlist auto-approval | argument-level policy, not command-level | Cursor CVE-2026-22708 | implemented (M2) |
| SANDBOX | Sandbox / Config Redefinition | agent output eval'd as config | never eval agent output; output boundary | Codex CLI CVE-2025-59532 | implemented (M2) |
| MEMORY | Memory Poisoning | unvalidated persistent session memory | provenance-tagged, validated memory | MemoryGraft research | implemented (M2) |
| A2A-TRUST | Inter-agent Trust | A2A sub-agent instructions trusted blindly | A2A message validation; agents = untrusted principals | multi-agent lateral movement | implemented (M2) |
| CONFIG | Config-as-Vector | plaintext creds in config dir | runtime env injection, Secret Manager | OpenClaw / Claude Code credential disclosures | implemented (M2) |
| SUPPLY-CHAIN | Supply Chain | unpinned model-gateway dep | pinned deps + checksum/provenance (SLSA-style) verification | LiteLLM PyPI backdoor | implemented (M2) |

## Safety

Incident anchors are **narrative only** — no working payloads or real target
strings are in this repo. All actions are simulated: "egress" appends to an
in-process sink and never performs I/O; "secrets" are obvious placeholders;
"targets" are RFC-reserved `.invalid` names. The vulnerable variants
demonstrate a *failure pattern*, not a usable weapon, and run only behind the
fenced launcher (see below).

## Running the pairs

```sh
# List the pairs (no fence needed — nothing runs):
go run ./cmd/gopherguard-vuln --list

# Run all vulnerable-variant demonstrations (fenced, all actions simulated):
go run ./cmd/gopherguard-vuln --i-understand-this-is-insecure

# Run a single pair's vulnerable variant:
go run ./cmd/gopherguard-vuln --i-understand-this-is-insecure --pair ASI01
```

The paired hardened mitigations, and the invariant that every vulnerable
variant is compromised while every hardened variant is not, are exercised by
`go test ./internal/owasp/`.
