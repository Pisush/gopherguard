# OWASP Agentic Top 10 (ASI) mapping

This is the master index for milestone M2. Each row maps an OWASP Agentic
Security Initiative (ASI) risk to the vulnerable pattern gopherguard
implements (fenced, non-deployable), the corresponding hardened mitigation,
a narrative incident anchor for context, and its current implementation
status.

| ASI ID | Risk | Vulnerable pattern (fenced) | Hardened mitigation | Incident anchor (narrative) | Status |
|---|---|---|---|---|---|
| ASI01 | Goal Hijack / Prompt Injection | indirect injection via poisoned tool output | content isolation + injection-aware routing; egress gate after untrusted read | Unit 42 in-the-wild indirect injection | planned (M2) |
| ASI03 | Identity / Privilege Abuse | one over-scoped credential for all tools | per-tool scoped identities, least privilege | over-privileged refund-bot pattern | planned (M2) |
| (Tool misuse) | Tool Misuse | command-level allowlist auto-approval | argument-level policy, not command-level | Cursor CVE-2026-22708 | planned (M2) |
| (Sandbox) | Sandbox / Config Redefinition | agent output eval'd as config | never eval agent output; output boundary | Codex CLI CVE-2025-59532 | planned (M2) |
| (Memory) | Memory Poisoning | unvalidated persistent session memory | provenance-tagged, validated memory | MemoryGraft research | planned (M2) |
| (A2A) | Inter-agent Trust | A2A sub-agent instructions trusted blindly | A2A message validation; agents = untrusted principals | multi-agent lateral movement | planned (M2) |
| (Config) | Config-as-Vector | plaintext creds in config dir | runtime env injection, Secret Manager | OpenClaw / Claude Code credential disclosures | planned (M2) |
| (Supply chain) | Supply Chain | unpinned model-gateway dep | pinned deps + provenance/SLSA + egress allowlist | LiteLLM PyPI backdoor | planned (M2) |

Incident anchors are narrative only — no working payloads or real target
strings are included in this repo (see repo Safety policy).
