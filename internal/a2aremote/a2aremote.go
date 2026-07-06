// Package a2aremote is the M5 polyglot bridge: an A2A (Agent-to-Agent
// protocol) client path from the Go coordinator to the Python ADK analysis
// sub-agent under a2a-python/.
//
// Two things make the cross-runtime trace read as ONE trace:
//
//  1. Every A2A call runs inside a span stamped with the trust-boundary
//     vocabulary from internal/telemetry — in particular
//     agent.hop = "coordinator->python-analysis" (HopToPythonAnalysis), the
//     same attribute the in-process graph uses for hops between Go agents.
//  2. The outgoing HTTP request carries a W3C traceparent header derived from
//     that span's context, so the Python server's spans (extracted by its
//     ASGI OTel middleware) share the Go trace ID.
//
// Protocol note: the client speaks A2A v1.0 (a2a-go/v2) and falls back to
// the v0.3 wire format via a2acompat/a2av0, because google-adk for Python
// currently pins a2a-sdk 0.3.x. Which dialect is used is decided by the
// remote agent card, fetched from /.well-known/agent-card.json.
package a2aremote

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Pisush/gopherguard/internal/telemetry"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2aclient/agentcard"
	"github.com/a2aproject/a2a-go/v2/a2acompat/a2av0"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
)

// HopToPythonAnalysis is the agent.hop value stamped on every remote call to
// the Python analysis sub-agent. M3 detections and the M5 demo both key on
// this exact string; keep it in sync with a2a-python/analysis_agent/agent.py.
const HopToPythonAnalysis = "coordinator->python-analysis"

// requestTimeout bounds a single A2A round-trip. Analysis is deterministic
// (no LLM call on the Python side), so a minute is generous.
const requestTimeout = 60 * time.Second

// AnalysisClient calls the remote analysis sub-agent over A2A.
type AnalysisClient struct {
	client *a2aclient.Client
}

// NewAnalysisClient connects to the A2A agent served at baseURL: it fetches
// the agent card from the well-known path (accepting both v1.0 and v0.3 card
// formats) and builds a client over the matching JSON-RPC dialect. All HTTP
// requests it issues carry W3C trace context.
func NewAnalysisClient(ctx context.Context, baseURL string) (*AnalysisClient, error) {
	httpClient := &http.Client{
		Timeout:   requestTimeout,
		Transport: traceparentTransport{base: http.DefaultTransport},
	}

	resolver := &agentcard.Resolver{Client: httpClient, CardParser: parseCard}
	card, err := resolver.Resolve(ctx, baseURL)
	if err != nil {
		return nil, fmt.Errorf("a2aremote: resolve agent card at %s: %w", baseURL, err)
	}

	client, err := a2aclient.NewFromCard(ctx, card,
		// v1.0 JSON-RPC (a2a-go/v2 native), over the trace-propagating client.
		a2aclient.WithJSONRPCTransport(httpClient),
		// v0.3 JSON-RPC compat, for Python a2a-sdk 0.3.x servers (what
		// google-adk pins today), over the same client.
		a2av0.WithJSONRPCTransport(a2av0.JSONRPCTransportConfig{Client: httpClient}),
	)
	if err != nil {
		return nil, fmt.Errorf("a2aremote: create A2A client for %s: %w", baseURL, err)
	}
	return &AnalysisClient{client: client}, nil
}

// Analyze sends text to the remote analysis agent and returns its report.
// The call runs in a span carrying agent.hop = HopToPythonAnalysis; the
// remote's reply is treated as untrusted input (it crossed a trust boundary),
// and the hop is egress by definition.
func (c *AnalysisClient) Analyze(ctx context.Context, text string) (string, error) {
	ctx, span := telemetry.StartSpan(ctx, "a2a.analyze",
		telemetry.AttrAgentHop(HopToPythonAnalysis),
		telemetry.AttrEgress(true),
		telemetry.AttrUntrusted(true),
	)
	defer span.End()

	msg := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart(text))
	result, err := c.client.SendMessage(ctx, &a2a.SendMessageRequest{Message: msg})
	if err != nil {
		span.SetStatus(codes.Error, "a2a send failed")
		span.RecordError(err)
		return "", fmt.Errorf("a2aremote: send message: %w", err)
	}

	reply := replyText(result)
	if reply == "" {
		err := errors.New("a2aremote: remote agent returned no text")
		span.SetStatus(codes.Error, "empty reply")
		span.RecordError(err)
		return "", err
	}
	return reply, nil
}

// parseCard parses an agent card in v1.0 format, falling back to the v0.3
// format when the v1.0 parse yields no usable transport interfaces (a v0.3
// card carries url/preferredTransport instead of supportedInterfaces).
func parseCard(body []byte) (*a2a.AgentCard, error) {
	card, err := agentcard.DefaultCardParser(body)
	if err == nil && len(card.SupportedInterfaces) > 0 {
		return card, nil
	}
	return a2av0.NewAgentCardParser()(body)
}

// replyText extracts the agent's textual reply from an A2A result, which is
// a bare Message for simple agents or a Task (artifacts, then status message,
// then history) for task-based servers like the Python ADK executor.
func replyText(result a2a.SendMessageResult) string {
	switch r := result.(type) {
	case *a2a.Message:
		return messageText(r)
	case *a2a.Task:
		for _, artifact := range r.Artifacts {
			if s := partsText(artifact.Parts); s != "" {
				return s
			}
		}
		if r.Status.Message != nil {
			if s := messageText(r.Status.Message); s != "" {
				return s
			}
		}
		for i := len(r.History) - 1; i >= 0; i-- {
			m := r.History[i]
			if m.Role == a2a.MessageRoleAgent {
				if s := messageText(m); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func messageText(m *a2a.Message) string {
	if m == nil {
		return ""
	}
	return partsText(m.Parts)
}

func partsText(parts a2a.ContentParts) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(p.Text())
	}
	return strings.TrimSpace(b.String())
}

// traceparentTransport injects the W3C traceparent/tracestate headers from
// the request context into every outgoing request. It uses the concrete
// propagation.TraceContext propagator (not the global one) so cross-language
// trace continuity holds regardless of how the global propagator is set up.
type traceparentTransport struct {
	base http.RoundTripper
}

// RoundTrip implements http.RoundTripper. Per the RoundTripper contract the
// incoming request is not mutated; headers are injected into a clone.
func (t traceparentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	propagation.TraceContext{}.Inject(req.Context(), propagation.HeaderCarrier(req.Header))
	return t.base.RoundTrip(req)
}
