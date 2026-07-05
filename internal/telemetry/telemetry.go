// Package telemetry wires gopherguard's OpenTelemetry setup.
//
// M0 provides the setup/shutdown lifecycle around ADK's native telemetry:
// local (stdout/OTLP) by default, Cloud Trace in production. The fixed
// trust-boundary attribute vocabulary (trust.untrusted_input, trust.egress,
// trust.hitl_required, …) and the span helpers that stamp it are added in M1 —
// this file is the seam they hang off.
package telemetry

import (
	"context"
	"os"

	adktelemetry "google.golang.org/adk/v2/telemetry"
)

// Providers is the running telemetry stack; call Shutdown on exit to flush.
type Providers = adktelemetry.Providers

// Setup initializes telemetry from the environment:
//
//   - OTEL_EXPORTER=cloud with GOOGLE_CLOUD_PROJECT → export to Cloud Trace.
//   - anything else (default) → local providers (stdout/OTLP), keyless.
//
// The returned Providers is installed as the global OTel provider set. Callers
// must defer Shutdown to flush spans.
func Setup(ctx context.Context) (*Providers, error) {
	var opts []adktelemetry.Option

	if os.Getenv("OTEL_EXPORTER") == "cloud" {
		opts = append(opts, adktelemetry.WithOtelToCloud(true))
		if project := os.Getenv("GOOGLE_CLOUD_PROJECT"); project != "" {
			opts = append(opts, adktelemetry.WithGcpResourceProject(project))
		}
	}

	providers, err := adktelemetry.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	providers.SetGlobalOtelProviders()
	return providers, nil
}
