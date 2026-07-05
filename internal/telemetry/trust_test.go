package telemetry

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// newTestTracerProvider installs a real, in-memory-recording SDK tracer
// provider as the global provider for the duration of the test and returns
// the exporter used to inspect finished spans. It restores the previous
// global provider on cleanup so tests stay isolated and offline.
func newTestTracerProvider(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
	})

	return exporter
}

func TestAttrHelpers(t *testing.T) {
	tests := []struct {
		name string
		kv   attribute.KeyValue
		key  attribute.Key
		val  attribute.Value
	}{
		{"AttrUntrusted true", AttrUntrusted(true), KeyUntrusted, attribute.BoolValue(true)},
		{"AttrUntrusted false", AttrUntrusted(false), KeyUntrusted, attribute.BoolValue(false)},
		{"AttrPrivilegeScope", AttrPrivilegeScope("readonly-fs"), KeyPrivilegeScope, attribute.StringValue("readonly-fs")},
		{"AttrHITLRequired true", AttrHITLRequired(true), KeyHITLRequired, attribute.BoolValue(true)},
		{"AttrHITLResult approved", AttrHITLResult(HITLApproved), KeyHITLResult, attribute.StringValue("approved")},
		{"AttrHITLResult denied", AttrHITLResult(HITLDenied), KeyHITLResult, attribute.StringValue("denied")},
		{"AttrHITLResult bypassed", AttrHITLResult(HITLBypassed), KeyHITLResult, attribute.StringValue("bypassed")},
		{"AttrEgress", AttrEgress(true), KeyEgress, attribute.BoolValue(true)},
		{"AttrAgentHop", AttrAgentHop("planner->executor"), KeyAgentHop, attribute.StringValue("planner->executor")},
		{"AttrModelRouteReason", AttrModelRouteReason("cost-tier-downgrade"), KeyModelRouteReason, attribute.StringValue("cost-tier-downgrade")},
		{"AttrMemProvenance", AttrMemProvenance("user-upload"), KeyMemProvenance, attribute.StringValue("user-upload")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.kv.Key != tt.key {
				t.Errorf("key = %q, want %q", tt.kv.Key, tt.key)
			}
			if tt.kv.Value != tt.val {
				t.Errorf("value = %v, want %v", tt.kv.Value, tt.val)
			}
		})
	}
}

// TestAttrKeyConstants pins the raw key strings, since M3 detections query
// these exact names — a rename here would silently break that consumer.
func TestAttrKeyConstants(t *testing.T) {
	tests := []struct {
		key  attribute.Key
		want string
	}{
		{KeyUntrusted, "trust.untrusted_input"},
		{KeyPrivilegeScope, "trust.privilege_scope"},
		{KeyHITLRequired, "trust.hitl_required"},
		{KeyHITLResult, "trust.hitl_result"},
		{KeyEgress, "trust.egress"},
		{KeyAgentHop, "agent.hop"},
		{KeyModelRouteReason, "model.route_reason"},
		{KeyMemProvenance, "mem.provenance"},
	}

	for _, tt := range tests {
		if string(tt.key) != tt.want {
			t.Errorf("key = %q, want %q", tt.key, tt.want)
		}
	}
}

func TestHITLResultConstants(t *testing.T) {
	if HITLApproved != "approved" {
		t.Errorf("HITLApproved = %q, want %q", HITLApproved, "approved")
	}
	if HITLDenied != "denied" {
		t.Errorf("HITLDenied = %q, want %q", HITLDenied, "denied")
	}
	if HITLBypassed != "bypassed" {
		t.Errorf("HITLBypassed = %q, want %q", HITLBypassed, "bypassed")
	}
}

func TestStartSpan(t *testing.T) {
	exporter := newTestTracerProvider(t)

	ctx, span := StartSpan(context.Background(), "guarded-tool-call",
		AttrUntrusted(true),
		AttrPrivilegeScope("network-egress"),
	)
	if span == nil {
		t.Fatal("StartSpan returned a nil span")
	}
	if !span.IsRecording() {
		t.Fatal("span should be recording before End()")
	}

	// The returned context must carry the new span.
	if got := oteltrace.SpanFromContext(ctx); got != span {
		t.Error("context returned by StartSpan does not carry the started span")
	}
	if !span.SpanContext().IsValid() {
		t.Error("started span has an invalid span context")
	}

	span.End()

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d exported spans, want 1", len(spans))
	}
	got := spans[0]

	if got.Name != "guarded-tool-call" {
		t.Errorf("span name = %q, want %q", got.Name, "guarded-tool-call")
	}
	if got.InstrumentationScope.Name != TracerName {
		t.Errorf("instrumentation scope = %q, want %q", got.InstrumentationScope.Name, TracerName)
	}

	attrs := attribute.NewSet(got.Attributes...)
	if v, ok := attrs.Value(KeyUntrusted); !ok || !v.AsBool() {
		t.Error("exported span missing trust.untrusted_input=true")
	}
	if v, ok := attrs.Value(KeyPrivilegeScope); !ok || v.AsString() != "network-egress" {
		t.Error("exported span missing trust.privilege_scope=network-egress")
	}
}

func TestStampSetsAttributesOnRecordingSpan(t *testing.T) {
	exporter := newTestTracerProvider(t)

	ctx, span := StartSpan(context.Background(), "hitl-gate")
	Stamp(ctx,
		AttrHITLRequired(true),
		AttrHITLResult(HITLDenied),
		AttrEgress(false),
	)
	span.End()

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d exported spans, want 1", len(spans))
	}
	attrs := attribute.NewSet(spans[0].Attributes...)

	if v, ok := attrs.Value(KeyHITLRequired); !ok || !v.AsBool() {
		t.Error("Stamp did not set trust.hitl_required=true")
	}
	if v, ok := attrs.Value(KeyHITLResult); !ok || v.AsString() != HITLDenied {
		t.Error("Stamp did not set trust.hitl_result=denied")
	}
	if v, ok := attrs.Value(KeyEgress); !ok || v.AsBool() {
		t.Error("Stamp did not set trust.egress=false")
	}
}

// TestStampNoSpanIsANoop verifies Stamp doesn't panic and has nothing to
// verify when there's no span in context: it must simply be a no-op.
func TestStampNoSpanIsANoop(t *testing.T) {
	ctx := context.Background()
	if oteltrace.SpanFromContext(ctx).IsRecording() {
		t.Fatal("expected no recording span on a bare background context")
	}
	// Must not panic.
	Stamp(ctx, AttrEgress(true))
}

// TestStampOnEndedSpanIsANoop verifies Stamp does not set attributes once a
// span has stopped recording (after End()), matching the documented
// IsRecording guard.
func TestStampOnEndedSpanIsANoop(t *testing.T) {
	exporter := newTestTracerProvider(t)

	ctx, span := StartSpan(context.Background(), "already-ended")
	span.End()

	// Attempting to stamp after End() must be a no-op: the attribute must
	// not show up in the exported span.
	Stamp(ctx, AttrModelRouteReason("post-end-should-not-apply"))

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d exported spans, want 1", len(spans))
	}
	attrs := attribute.NewSet(spans[0].Attributes...)
	if _, ok := attrs.Value(KeyModelRouteReason); ok {
		t.Error("Stamp set an attribute on a span that had already ended")
	}
}
