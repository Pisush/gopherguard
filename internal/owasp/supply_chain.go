package owasp

import (
	"context"

	"github.com/Pisush/gopherguard/internal/telemetry"
)

// Supply Chain — unpinned dependency resolution.
//
// Failure pattern: a model-gateway dependency is resolved by an unpinned
// "latest" tag with no integrity check, so a swapped or tampered artifact is
// loaded and runs with the process's trust — classically culminating in
// unauthorized egress to an attacker-controlled endpoint. The mitigation is a
// pinned version plus checksum/provenance verification (SLSA-style): a
// tampered artifact's checksum won't match the expected one, so it is
// rejected before it ever runs.
//
// Everything here is simulated and safe: the "registry" and its resolved
// artifact are in-process placeholders, the destination is an RFC-reserved
// .invalid host, and Sink performs no real network I/O.
const (
	// supplyChainPinnedVersion is the version an integrity-conscious build
	// declares it wants.
	supplyChainPinnedVersion = "v1.4.2"

	// supplyChainExpectedChecksum is the checksum recorded for the pinned,
	// known-good artifact (a placeholder digest, not a real hash).
	supplyChainExpectedChecksum = "sha256:placeholder-good-0000000000000000000000000000"

	// supplyChainTamperedChecksum is what actually gets resolved when nothing
	// pins the version and nothing verifies integrity: a swapped artifact.
	supplyChainTamperedChecksum = "sha256:placeholder-tampered-1111111111111111111111"

	// supplyChainFakeRegistry is an obviously-fake destination the tampered
	// artifact tries to phone home to — RFC-reserved .invalid, never real.
	supplyChainFakeRegistry = "registry.exfil.invalid"
)

// resolvedDependency is a simulated dependency resolution result: the version
// that got resolved and the checksum of what was actually fetched.
type resolvedDependency struct {
	version  string
	checksum string
}

func registerSupplyChain(r *Registry) {
	r.Register(Pair{
		ID:          "SUPPLY-CHAIN",
		Risk:        "Supply Chain (unpinned dependency)",
		ASIRef:      "OWASP ASI Supply Chain",
		Incident:    "LiteLLM PyPI backdoor pattern (narrative anchor only)",
		VulnPattern: "a model-gateway dependency resolves to an unpinned \"latest\" with no integrity check, so a tampered artifact loads and runs",
		Mitigation:  "pinned version + checksum/provenance (SLSA-style) verification; a tampered artifact fails the check and is rejected",
		Vulnerable:  supplyChainVulnerable,
		Hardened:    supplyChainHardened,
	})
}

// resolveLatest simulates resolving a dependency by an unpinned "latest" tag:
// whatever the registry currently serves is what you get — here, tampered.
func resolveLatest() resolvedDependency {
	return resolvedDependency{version: "latest", checksum: supplyChainTamperedChecksum}
}

// supplyChainVulnerable resolves the model-gateway dependency by an unpinned
// "latest" tag with no checksum verification. The tampered artifact loads and
// performs a (simulated) egress to a fake registry.
func supplyChainVulnerable(ctx context.Context) Outcome {
	sink := NewSink()

	resolveCtx, end := step(ctx, "supplychain.resolve",
		telemetry.AttrPrivilegeScope("read:deps"))
	dep := resolveLatest() // unpinned: no version pin, no checksum check
	end()

	// VULNERABLE: the artifact loads unconditionally and runs, including its
	// (simulated) exfiltration behavior.
	loadCtx, end := step(resolveCtx, "supplychain.load_and_run",
		telemetry.AttrPrivilegeScope("read:deps"))
	_ = dep.version // resolved to "latest" — never pinned, never checked
	sink.Send(loadCtx, supplyChainFakeRegistry, "tampered-dependency-payload")
	end()

	return Outcome{
		Scenario:    "the model gateway resolves a dependency by an unpinned \"latest\" tag",
		Attempted:   "swap in a tampered artifact that phones home once loaded",
		Result:      "no version pin and no checksum check let the tampered artifact load and (simulated) egress",
		Compromised: sink.Count() > 0,
	}
}

// supplyChainHardened requires a pinned version and a matching checksum. The
// same tampered artifact fails verification and is rejected before it can
// load or perform any egress.
func supplyChainHardened(ctx context.Context) Outcome {
	sink := NewSink()

	resolveCtx, end := step(ctx, "supplychain.resolve",
		telemetry.AttrPrivilegeScope("read:deps"))
	dep := resolveLatest() // same tampered resolution is attempted
	end()

	// HARDENED: verify against a pinned version + expected checksum
	// (SLSA-style provenance check) before ever loading the artifact.
	_, end = step(resolveCtx, "supplychain.verify",
		telemetry.AttrPrivilegeScope("read:deps"))
	verified := dep.version == supplyChainPinnedVersion && dep.checksum == supplyChainExpectedChecksum
	end()

	if !verified {
		return Outcome{
			Scenario:    "the model gateway resolves the same dependency, but requires a pinned version + checksum",
			Attempted:   "swap in a tampered artifact that phones home once loaded",
			Result:      "the resolved artifact was unpinned/mismatched the expected checksum and was rejected before loading",
			Compromised: false,
		}
	}

	// Unreachable in this demo (resolution is always tampered), kept for
	// symmetry with the vulnerable path's shape.
	sink.Send(ctx, supplyChainFakeRegistry, "tampered-dependency-payload")
	return Outcome{
		Scenario:    "the model gateway resolves the same dependency, but requires a pinned version + checksum",
		Attempted:   "swap in a tampered artifact that phones home once loaded",
		Result:      "verification passed unexpectedly",
		Compromised: sink.Count() > 0,
	}
}
