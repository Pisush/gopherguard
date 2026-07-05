// Package telemetry: trust-boundary span helpers.
//
// This file is the trust-boundary telemetry spine: a fixed vocabulary of
// OpenTelemetry attributes plus helpers to start spans and stamp them. The
// vocabulary must stay stable, because M3 detections query these exact
// attribute keys — do not rename or repurpose them; add new ones instead.
package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// TracerName is the instrumentation scope name for all gopherguard spans.
const TracerName = "github.com/Pisush/gopherguard"

// The fixed trust-boundary attribute keys. Every Attr* helper below builds
// its attribute.KeyValue from one of these constants; use these keys (not
// string literals) whenever the raw key name is needed, e.g. in queries or
// span-processor filters, so the schema stays stable.
const (
	// KeyUntrusted marks a span as having handled untrusted input.
	KeyUntrusted = attribute.Key("trust.untrusted_input")
	// KeyPrivilegeScope names the privilege scope a span executed under.
	KeyPrivilegeScope = attribute.Key("trust.privilege_scope")
	// KeyHITLRequired marks whether human-in-the-loop approval was required.
	KeyHITLRequired = attribute.Key("trust.hitl_required")
	// KeyHITLResult records the outcome of a human-in-the-loop check.
	KeyHITLResult = attribute.Key("trust.hitl_result")
	// KeyEgress marks whether a span performed (or permitted) network egress.
	KeyEgress = attribute.Key("trust.egress")
	// KeyAgentHop records a "src->dest" transition between agents.
	KeyAgentHop = attribute.Key("agent.hop")
	// KeyModelRouteReason records why a request was routed to a given model.
	KeyModelRouteReason = attribute.Key("model.route_reason")
	// KeyMemProvenance records the origin of memory read into a span.
	KeyMemProvenance = attribute.Key("mem.provenance")
)

// HITL result enum values for AttrHITLResult.
const (
	// HITLApproved indicates a human explicitly approved the action.
	HITLApproved = "approved"
	// HITLDenied indicates a human explicitly denied the action.
	HITLDenied = "denied"
	// HITLBypassed indicates the human-in-the-loop check was bypassed.
	HITLBypassed = "bypassed"
)

// StartSpan starts a span named name on the gopherguard tracer and returns
// the child context and the span. Callers must defer span.End().
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return otel.Tracer(TracerName).Start(ctx, name, trace.WithAttributes(attrs...))
}

// AttrUntrusted reports whether a span handled untrusted input.
// Key: trust.untrusted_input.
func AttrUntrusted(v bool) attribute.KeyValue {
	return KeyUntrusted.Bool(v)
}

// AttrPrivilegeScope names the privilege scope a span executed under.
// Key: trust.privilege_scope.
func AttrPrivilegeScope(scope string) attribute.KeyValue {
	return KeyPrivilegeScope.String(scope)
}

// AttrHITLRequired reports whether human-in-the-loop approval was required.
// Key: trust.hitl_required.
func AttrHITLRequired(v bool) attribute.KeyValue {
	return KeyHITLRequired.Bool(v)
}

// AttrHITLResult records the outcome of a human-in-the-loop check. result
// should be one of HITLApproved, HITLDenied, or HITLBypassed.
// Key: trust.hitl_result.
func AttrHITLResult(result string) attribute.KeyValue {
	return KeyHITLResult.String(result)
}

// AttrEgress reports whether a span performed (or permitted) network egress.
// Key: trust.egress.
func AttrEgress(v bool) attribute.KeyValue {
	return KeyEgress.Bool(v)
}

// AttrAgentHop records a "src->dest" transition between agents.
// Key: agent.hop.
func AttrAgentHop(srcToDest string) attribute.KeyValue {
	return KeyAgentHop.String(srcToDest)
}

// AttrModelRouteReason records why a request was routed to a given model.
// Key: model.route_reason.
func AttrModelRouteReason(reason string) attribute.KeyValue {
	return KeyModelRouteReason.String(reason)
}

// AttrMemProvenance records the origin of memory read into a span.
// Key: mem.provenance.
func AttrMemProvenance(origin string) attribute.KeyValue {
	return KeyMemProvenance.String(origin)
}

// Stamp sets the given attributes on the span currently in ctx, if one is
// present and recording. It is a convenience for adding trust attributes to
// an already-started span without threading the span value around.
func Stamp(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetAttributes(attrs...)
	}
}
