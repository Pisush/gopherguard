package owasp

import (
	"context"
	"strings"

	"github.com/Pisush/gopherguard/internal/telemetry"
)

// CONFIG — Config-as-Vector (plaintext credentials in committed artifacts).
//
// Failure pattern: a real-looking credential is embedded directly in a
// config artifact that gets committed and shipped alongside the agent (a
// ".env" checked into a repo, a config file baked into an image). Anyone or
// anything that can read the artifact — including a compromised agent, a
// leaked build, or a curious support ticket — discloses the credential. The
// mitigation is runtime env injection (or a Secret Manager): the artifact
// holds only a placeholder reference, and the real value is resolved from a
// trusted runtime source at execution time and never persisted anywhere.
//
// This mirrors the narrative pattern behind OpenClaw / Claude Code
// credential-disclosure reports, where secrets embedded in configuration
// state ended up disclosed (narrative anchor only — the credential below is
// an obviously-fake placeholder, never a working key).
const (
	// configFakeCredential is an obviously-fake, non-functional placeholder —
	// never a real key of any kind.
	configFakeCredential = "AKIA-PLACEHOLDER-not-a-real-key"

	// configVulnerableArtifact simulates an on-disk config file that embeds the
	// plaintext credential directly. No real file is read; this is a string.
	configVulnerableArtifact = `{"service":"placeholder-api","api_key":"AKIA-PLACEHOLDER-not-a-real-key"}`

	// configHardenedArtifact simulates the same config file after hardening:
	// only a placeholder reference is committed, never a real value.
	configHardenedArtifact = `{"service":"placeholder-api","api_key":"${GG_API_TOKEN}"}`
)

func registerConfigVector(r *Registry) {
	r.Register(Pair{
		ID:          "CONFIG",
		Risk:        "Config-as-Vector (plaintext credentials)",
		ASIRef:      "OWASP ASI Secrets/Config",
		Incident:    "OpenClaw / Claude Code credential-disclosure pattern (narrative anchor only)",
		VulnPattern: "a plaintext credential lives in a committed config artifact and can be disclosed by reading it",
		Mitigation:  "runtime env injection / Secret Manager: the artifact holds only a placeholder, the value is injected at runtime and never persisted",
		Vulnerable:  configVulnerable,
		Hardened:    configHardened,
	})
}

// configVulnerable reads a simulated on-disk config artifact that embeds the
// plaintext credential directly. The mere presence of the secret in the
// committed artifact is the compromise — reading it discloses it.
func configVulnerable(ctx context.Context) Outcome {
	_, end := step(ctx, "config.read_artifact",
		telemetry.AttrMemProvenance("config:disk"))
	credential := extractAPIKey(configVulnerableArtifact)
	end()

	disclosed := credential == configFakeCredential

	return Outcome{
		Scenario:    "an agent reads its service config from a committed on-disk artifact",
		Attempted:   "recover the API credential from the config artifact",
		Result:      "the plaintext credential was embedded directly in the committed artifact and disclosed on read",
		Compromised: disclosed,
	}
}

// configHardened reads the same shape of config artifact, but it now holds
// only a placeholder reference. The real value is resolved from a simulated
// runtime environment (a local var standing in for a Secret Manager / env
// injection at deploy time) — it is never present in the artifact itself.
func configHardened(ctx context.Context) Outcome {
	_, end := step(ctx, "config.read_artifact",
		telemetry.AttrMemProvenance("config:disk"))
	reference := extractAPIKey(configHardenedArtifact)
	end()

	// The artifact never contained a secret — only a placeholder reference.
	artifactDisclosed := reference == configFakeCredential

	// HARDENED: the real value is resolved from a trusted runtime source at
	// execution time, simulated as a local var — never read from disk, never
	// logged, never persisted back into the artifact.
	_, end = step(ctx, "config.resolve_runtime_secret",
		telemetry.AttrMemProvenance("env:runtime"))
	simulatedRuntimeEnv := map[string]string{"GG_API_TOKEN": configFakeCredential}
	resolved := resolveFromRuntimeEnv(reference, simulatedRuntimeEnv)
	end()

	_ = resolved // used only at call time, never written back to the artifact

	return Outcome{
		Scenario:    "an agent reads its service config from a hardened on-disk artifact",
		Attempted:   "recover the API credential from the config artifact",
		Result:      "the artifact held only a placeholder reference; the real value came from a runtime source and was never in the artifact",
		Compromised: artifactDisclosed,
	}
}

// extractAPIKey pulls the api_key value out of a simulated JSON config
// string. Purely lexical — no real JSON parser, no real file I/O.
func extractAPIKey(artifact string) string {
	const marker = `"api_key":"`
	i := strings.Index(artifact, marker)
	if i < 0 {
		return ""
	}
	rest := artifact[i+len(marker):]
	if j := strings.Index(rest, `"`); j >= 0 {
		return rest[:j]
	}
	return ""
}

// resolveFromRuntimeEnv resolves a "${VAR}" style placeholder reference
// against a simulated runtime environment map, standing in for a real
// Secret Manager or injected env var. It never touches the real process
// environment.
func resolveFromRuntimeEnv(reference string, env map[string]string) string {
	if !strings.HasPrefix(reference, "${") || !strings.HasSuffix(reference, "}") {
		return reference
	}
	name := strings.TrimSuffix(strings.TrimPrefix(reference, "${"), "}")
	return env[name]
}
