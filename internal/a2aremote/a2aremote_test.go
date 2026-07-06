package a2aremote

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Pisush/gopherguard/internal/telemetry"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2acompat/a2av0"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// newTestTracerProvider installs an in-memory-recording SDK tracer provider
// as the global provider for the duration of the test, restoring the previous
// one on cleanup, and returns the exporter used to inspect finished spans.
func newTestTracerProvider(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	return exporter
}

// stubAnalysis is a RequestHandler standing in for the Python analysis
// sub-agent (a2a-python/). Only SendMessage is implemented; every other
// RequestHandler method panics via the embedded nil interface, which is fine:
// the client under test must never call them.
type stubAnalysis struct {
	a2asrv.RequestHandler
	reply a2a.SendMessageResult
}

func (h *stubAnalysis) SendMessage(_ context.Context, req *a2a.SendMessageRequest) (a2a.SendMessageResult, error) {
	if h.reply != nil {
		return h.reply, nil
	}
	echo := ""
	if req.Message != nil {
		echo = partsText(req.Message.Parts)
	}
	return a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("analysis: "+echo)), nil
}

// headerCapture records the traceparent header of every request that reaches
// the stub server, so tests can assert cross-runtime context propagation.
type headerCapture struct {
	mu           sync.Mutex
	traceparents []string
}

func (c *headerCapture) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.traceparents = append(c.traceparents, r.Header.Get("traceparent"))
		c.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (c *headerCapture) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.traceparents...)
}

// startStubServer serves an agent card at the well-known path and the given
// JSON-RPC handler at "/", with traceparent capture on both, mimicking the
// layout of the Python sub-agent's Starlette app. cardJSON receives the
// server base URL, since httptest only assigns it at start.
func startStubServer(t *testing.T, rpc http.Handler, cardJSON func(baseURL string) []byte) (*httptest.Server, *headerCapture) {
	t.Helper()

	capture := &headerCapture{}
	mux := http.NewServeMux()
	server := httptest.NewServer(capture.middleware(mux))
	t.Cleanup(server.Close)

	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(cardJSON(server.URL))
	})
	mux.Handle("/", rpc)
	return server, capture
}

func v1CardJSON(t *testing.T) func(string) []byte {
	t.Helper()
	return func(baseURL string) []byte {
		card := &a2a.AgentCard{
			Name: "python-analysis-stub",
			SupportedInterfaces: []*a2a.AgentInterface{
				a2a.NewAgentInterface(baseURL, a2a.TransportProtocolJSONRPC),
			},
		}
		b, err := json.Marshal(card)
		if err != nil {
			t.Fatalf("marshal v1 card: %v", err)
		}
		return b
	}
}

// v03CardJSON is a card in the v0.3 wire format — the shape the Python
// a2a-sdk 0.3.x (as pinned by google-adk) actually serves.
func v03CardJSON(baseURL string) []byte {
	return fmt.Appendf(nil, `{
		"name": "python-analysis-stub",
		"description": "deterministic analysis stub",
		"protocolVersion": "0.3.0",
		"version": "0.1.0",
		"url": %q,
		"preferredTransport": "JSONRPC",
		"capabilities": {},
		"defaultInputModes": ["text/plain"],
		"defaultOutputModes": ["text/plain"],
		"skills": []
	}`, baseURL)
}

// echoExecutor drives the v1 a2asrv handler for the full-stack variant.
type echoExecutor struct{}

func (echoExecutor) Execute(_ context.Context, execCtx *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		echo := ""
		if execCtx.Message != nil {
			echo = partsText(execCtx.Message.Parts)
		}
		yield(a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("analysis: "+echo)), nil)
	}
}

func (echoExecutor) Cancel(_ context.Context, execCtx *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateCanceled, nil), nil)
	}
}

// assertHopAndPropagation is the shared M5 acceptance assertion: the analyze
// span carries agent.hop = coordinator->python-analysis, and the wire request
// that reached the server carried a traceparent with that span's trace ID —
// i.e. a server on the other side (the Python sub-agent) joins the SAME trace.
func assertHopAndPropagation(t *testing.T, exporter *tracetest.InMemoryExporter, capture *headerCapture) {
	t.Helper()

	var analyze *tracetest.SpanStub
	for _, s := range exporter.GetSpans() {
		if s.Name == "a2a.analyze" {
			s := s
			analyze = &s
			break
		}
	}
	if analyze == nil {
		t.Fatal("no a2a.analyze span was recorded")
	}

	hop := ""
	for _, kv := range analyze.Attributes {
		if kv.Key == telemetry.KeyAgentHop {
			hop = kv.Value.AsString()
		}
	}
	if hop != HopToPythonAnalysis {
		t.Errorf("agent.hop = %q, want %q", hop, HopToPythonAnalysis)
	}

	traceID := analyze.SpanContext.TraceID().String()
	propagated := false
	for _, tp := range capture.all() {
		if strings.Contains(tp, traceID) {
			propagated = true
		}
	}
	if !propagated {
		t.Errorf("no request reached the server with traceparent containing trace ID %s; captured: %v",
			traceID, capture.all())
	}
}

// TestAnalyze_V1 exercises the native v1.0 path end to end against a real
// a2asrv JSON-RPC server (executor → task lifecycle → task result).
func TestAnalyze_V1(t *testing.T) {
	exporter := newTestTracerProvider(t)

	rpc := a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(echoExecutor{}))
	server, capture := startStubServer(t, rpc, v1CardJSON(t))

	ctx := context.Background()
	client, err := NewAnalysisClient(ctx, server.URL)
	if err != nil {
		t.Fatalf("NewAnalysisClient: %v", err)
	}

	got, err := client.Analyze(ctx, "hello from go")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if want := "analysis: hello from go"; got != want {
		t.Errorf("Analyze = %q, want %q", got, want)
	}

	assertHopAndPropagation(t, exporter, capture)
}

// TestAnalyze_V03Compat exercises the v0.3 compat path — the exact dialect
// spoken to the Python sub-agent, whose a2a-sdk (pinned by google-adk) is
// still on protocol 0.3: a v0.3-format agent card plus v0.3 JSON-RPC.
func TestAnalyze_V03Compat(t *testing.T) {
	exporter := newTestTracerProvider(t)

	rpc := a2av0.NewJSONRPCHandler(&stubAnalysis{})
	server, capture := startStubServer(t, rpc, func(baseURL string) []byte {
		return v03CardJSON(baseURL)
	})

	ctx := context.Background()
	client, err := NewAnalysisClient(ctx, server.URL)
	if err != nil {
		t.Fatalf("NewAnalysisClient: %v", err)
	}

	got, err := client.Analyze(ctx, "score this text")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if want := "analysis: score this text"; got != want {
		t.Errorf("Analyze = %q, want %q", got, want)
	}

	assertHopAndPropagation(t, exporter, capture)
}

func TestAnalyze_EmptyReply(t *testing.T) {
	newTestTracerProvider(t)

	rpc := a2av0.NewJSONRPCHandler(&stubAnalysis{
		reply: a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("   ")),
	})
	server, _ := startStubServer(t, rpc, func(baseURL string) []byte {
		return v03CardJSON(baseURL)
	})

	ctx := context.Background()
	client, err := NewAnalysisClient(ctx, server.URL)
	if err != nil {
		t.Fatalf("NewAnalysisClient: %v", err)
	}
	if _, err := client.Analyze(ctx, "anything"); err == nil {
		t.Error("Analyze returned nil error for an empty reply, want error")
	}
}

func TestReplyText(t *testing.T) {
	msg := func(text string) *a2a.Message {
		return a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart(text))
	}

	tests := []struct {
		name   string
		result a2a.SendMessageResult
		want   string
	}{
		{"message", msg("direct reply"), "direct reply"},
		{
			"task artifact wins",
			&a2a.Task{
				Artifacts: []*a2a.Artifact{{Parts: a2a.ContentParts{a2a.NewTextPart("artifact text")}}},
				Status:    a2a.TaskStatus{Message: msg("status text")},
			},
			"artifact text",
		},
		{
			"task falls back to status message",
			&a2a.Task{Status: a2a.TaskStatus{Message: msg("status text")}},
			"status text",
		},
		{
			"task falls back to last agent history message",
			&a2a.Task{History: []*a2a.Message{
				a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("user text")),
				msg("agent text"),
			}},
			"agent text",
		},
		{"empty task", &a2a.Task{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := replyText(tt.result); got != tt.want {
				t.Errorf("replyText = %q, want %q", got, tt.want)
			}
		})
	}
}
