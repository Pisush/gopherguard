package owasp

import (
	"context"
	"fmt"

	"github.com/Pisush/gopherguard/internal/telemetry"
)

// Sink records simulated outbound actions. It NEVER performs a real network
// call — a vulnerable variant "exfiltrating" data appends to Sink so the demo
// (and M3 detections) can observe that egress happened, while nothing actually
// leaves the process. This is what keeps the vulnerable variants safe: they
// demonstrate the failure pattern without being usable weapons.
type Sink struct {
	sent []string
}

// NewSink returns an empty simulated egress sink.
func NewSink() *Sink { return &Sink{} }

// Send simulates an outbound send of data to dest. It stamps trust.egress on the
// current span and records the (redacted) attempt, but performs no real I/O.
// dest is always a placeholder — pairs never use real target strings.
func (s *Sink) Send(ctx context.Context, dest, data string) {
	telemetry.Stamp(ctx, telemetry.AttrEgress(true))
	s.sent = append(s.sent, fmt.Sprintf("SIMULATED egress → %s: %s", dest, redact(data)))
}

// Sent returns the simulated sends recorded so far.
func (s *Sink) Sent() []string { return s.sent }

// Count returns how many simulated sends occurred.
func (s *Sink) Count() int { return len(s.sent) }

// redact keeps demos safe: only a short, obviously-fake preview is retained,
// never full data.
func redact(data string) string {
	const max = 24
	if len(data) > max {
		return data[:max] + "…[redacted]"
	}
	return data + "[redacted]"
}
