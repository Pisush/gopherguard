// Command gga2a runs the M5 polyglot demo: the Go coordinator calls the
// Python ADK analysis sub-agent (a2a-python/) over the A2A protocol, inside
// one trace.
//
// It starts a coordinator span, hands its context to the A2A client (which
// stamps agent.hop = coordinator->python-analysis and puts the W3C
// traceparent on the wire), prints the remote agent's report, and prints the
// trace ID — compare it with the trace ID in the Python server's span output
// to see the single cross-language trace. With the M3 trace stack running
// (`make trace-up`) and OTEL_EXPORTER_OTLP_ENDPOINT set on the Python side,
// both halves land in Tempo as one trace.
//
// Usage:
//
//	go run ./cmd/gga2a [-url http://127.0.0.1:8091] "text to analyze"
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Pisush/gopherguard/internal/a2aremote"
	"github.com/Pisush/gopherguard/internal/telemetry"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
)

func main() {
	url := flag.String("url", defaultURL(), "base URL of the Python analysis sub-agent's A2A endpoint")
	flag.Parse()

	text := strings.TrimSpace(strings.Join(flag.Args(), " "))
	if text == "" {
		fmt.Fprintln(os.Stderr, `usage: gga2a [-url http://127.0.0.1:8091] "text to analyze"`)
		os.Exit(2)
	}

	if err := run(context.Background(), *url, text); err != nil {
		log.Fatalf("gga2a: %v", err)
	}
}

func defaultURL() string {
	if v := os.Getenv("GG_A2A_URL"); v != "" {
		return v
	}
	return "http://127.0.0.1:8091"
}

func run(ctx context.Context, url, text string) error {
	providers, err := telemetry.Setup(ctx)
	if err != nil {
		return fmt.Errorf("telemetry setup: %w", err)
	}
	defer func() {
		if err := providers.Shutdown(context.Background()); err != nil {
			log.Printf("gga2a: telemetry shutdown: %v", err)
		}
	}()

	// ADK's local telemetry only records spans when an OTLP endpoint is
	// configured (e.g. the M3 trace stack via `make trace-up`). So the demo
	// also works standalone, fall back to compact console spans — the same
	// format the Python sub-agent prints — when no endpoint is set.
	if !otlpConfigured() {
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithSyncer(consoleExporter{}),
			sdktrace.WithResource(resource.NewWithAttributes(semconv.SchemaURL,
				semconv.ServiceName("gopherguard-coordinator"))),
		)
		defer func() {
			if err := tp.Shutdown(context.Background()); err != nil {
				log.Printf("gga2a: console tracer shutdown: %v", err)
			}
		}()
		otel.SetTracerProvider(tp)
	}

	// The coordinator span is the Go half of the cross-language trace; the
	// A2A client starts the hop span (agent.hop stamped) as its child.
	ctx, span := telemetry.StartSpan(ctx, "coordinator")
	defer span.End()

	client, err := a2aremote.NewAnalysisClient(ctx, url)
	if err != nil {
		return err
	}
	report, err := client.Analyze(ctx, text)
	if err != nil {
		return err
	}

	fmt.Println(report)
	fmt.Printf("\ntrace ID: %s  (hop: %s)\n", span.SpanContext().TraceID(), a2aremote.HopToPythonAnalysis)
	fmt.Println("the Python sub-agent's spans carry the same trace ID — one trace, two runtimes")
	return nil
}

// otlpConfigured reports whether the standard OTLP trace-export environment
// variables are set (the condition under which ADK's local telemetry exports).
func otlpConfigured() bool {
	return strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")) != "" ||
		strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")) != ""
}

// consoleExporter prints one compact line per finished span, mirroring the
// Python sub-agent's console formatter so the shared trace ID is easy to eye.
type consoleExporter struct{}

func (consoleExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	for _, s := range spans {
		hop := ""
		for _, kv := range s.Attributes() {
			if kv.Key == telemetry.KeyAgentHop {
				hop = "  agent.hop=" + kv.Value.AsString()
			}
		}
		fmt.Printf("[otel] span=%q trace_id=%s%s\n", s.Name(), s.SpanContext().TraceID(), hop)
	}
	return nil
}

func (consoleExporter) Shutdown(context.Context) error { return nil }
