// Package detect is gopherguard's "SIEM for agent traces": trace-query rules
// that catch the OWASP ASI attack patterns by querying the trust-boundary
// telemetry the rest of the system emits.
//
// In production these rules run as queries over a trace store (Tempo/ClickHouse
// — see the detections/ directory for the TraceQL/SQL equivalents and the
// Grafana dashboards). This package provides the same rules as Go predicates
// plus an in-process capture so they can be unit-tested directly against the
// M2 vulnerable/hardened pairs: each rule must fire on the vulnerable trace and
// stay quiet on the hardened one.
package detect

import (
	"context"
	"sort"
	"time"

	"github.com/Pisush/gopherguard/internal/telemetry"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// Span is a captured span reduced to what the detection rules query: its name
// and its attributes, with the span order preserved via the enclosing Trace.
type Span struct {
	Name  string
	start time.Time
	attrs map[attribute.Key]attribute.Value
}

// Bool returns a boolean attribute and whether it was present.
func (s Span) Bool(key attribute.Key) (val, present bool) {
	v, ok := s.attrs[key]
	if !ok {
		return false, false
	}
	return v.AsBool(), true
}

// Str returns a string attribute and whether it was present.
func (s Span) Str(key attribute.Key) (val string, present bool) {
	v, ok := s.attrs[key]
	if !ok {
		return "", false
	}
	return v.AsString(), true
}

// Trace is an ordered sequence of captured spans from one session, oldest
// first. The rules reason about ordering (e.g. "untrusted read BEFORE egress").
type Trace struct {
	Spans []Span
}

// Capture runs fn inside a fresh recording trace provider and returns the spans
// it produced as one ordered Trace. fn receives a context already inside a root
// "session" span, so every span the code under test creates shares one trace.
func Capture(fn func(ctx context.Context)) Trace {
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))

	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(prev)

	ctx, session := telemetry.StartSpan(context.Background(), "session")
	fn(ctx)
	session.End()
	_ = tp.ForceFlush(context.Background())

	ended := recorder.Ended()
	spans := make([]Span, 0, len(ended))
	for _, ro := range ended {
		attrs := make(map[attribute.Key]attribute.Value, len(ro.Attributes()))
		for _, kv := range ro.Attributes() {
			attrs[kv.Key] = kv.Value
		}
		spans = append(spans, Span{Name: ro.Name(), start: ro.StartTime(), attrs: attrs})
	}
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].start.Before(spans[j].start) })
	return Trace{Spans: spans}
}

// firstEgressIndex returns the index of the first span that performed egress, or
// -1. Helper shared by rules.
func (t Trace) firstEgressIndex() int {
	for i, s := range t.Spans {
		if v, ok := s.Bool(telemetry.KeyEgress); ok && v {
			return i
		}
	}
	return -1
}

// firstUntrustedIndex returns the index of the first span that processed
// untrusted input, or -1.
func (t Trace) firstUntrustedIndex() int {
	for i, s := range t.Spans {
		if v, ok := s.Bool(telemetry.KeyUntrusted); ok && v {
			return i
		}
	}
	return -1
}
