// Package model provides gopherguard's model adapters and cost-based router.
//
// Gemma (local, via Ollama) is the default everywhere: zero egress, no API key,
// so demos stay offline-capable and CI stays keyless. Gemini is opt-in
// "production mode" (see gemini.go). Routing lives in router.go.
package model

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"os"
	"strings"
	"time"

	adkmodel "google.golang.org/adk/v2/model"
	"google.golang.org/genai"
)

// Default local Ollama endpoint and Gemma model. Both overridable via env so
// the same binary works on a laptop and in a keyless CI runner.
const (
	defaultOllamaHost = "http://127.0.0.1:11434"
	defaultGemmaModel = "gemma2:2b"
)

// Gemma is a model.LLM backed by a local Ollama server. It never makes an
// outbound call beyond the configured (localhost by default) Ollama host, and
// requires no API key — this is what keeps vulnerable-mode and CI egress-free.
type Gemma struct {
	host   string
	model  string
	client *http.Client
}

// GemmaOption configures a Gemma adapter.
type GemmaOption func(*Gemma)

// WithHost overrides the Ollama host (default $OLLAMA_HOST or 127.0.0.1:11434).
func WithHost(host string) GemmaOption {
	return func(g *Gemma) { g.host = host }
}

// WithModel overrides the Ollama model tag (default $GG_GEMMA_MODEL or gemma2:2b).
func WithModel(model string) GemmaOption {
	return func(g *Gemma) { g.model = model }
}

// NewGemma builds a local Gemma adapter. It reads OLLAMA_HOST and GG_GEMMA_MODEL
// from the environment, falling back to localhost / gemma2:2b.
func NewGemma(opts ...GemmaOption) *Gemma {
	g := &Gemma{
		host:   envOr("OLLAMA_HOST", defaultOllamaHost),
		model:  envOr("GG_GEMMA_MODEL", defaultGemmaModel),
		client: &http.Client{Timeout: 120 * time.Second},
	}
	for _, opt := range opts {
		opt(g)
	}
	g.host = strings.TrimRight(g.host, "/")
	return g
}

// Name implements model.LLM.
func (g *Gemma) Name() string { return "gemma-local:" + g.model }

// ollamaMessage is one turn in Ollama's /api/chat schema.
type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  map[string]any  `json:"options,omitempty"`
}

type ollamaChatResponse struct {
	Model           string        `json:"model"`
	Message         ollamaMessage `json:"message"`
	Done            bool          `json:"done"`
	PromptEvalCount int32         `json:"prompt_eval_count"`
	EvalCount       int32         `json:"eval_count"`
	Error           string        `json:"error"`
}

// GenerateContent implements model.LLM. For M0 it performs a single
// non-streaming Ollama call and yields one complete response. (Token-level
// streaming and local tool-calling fidelity are hardened in later milestones;
// see docs/architecture.md.) The stream argument is accepted for interface
// compatibility but the local path always resolves to a single final event.
func (g *Gemma) GenerateContent(ctx context.Context, req *adkmodel.LLMRequest, _ bool) iter.Seq2[*adkmodel.LLMResponse, error] {
	return func(yield func(*adkmodel.LLMResponse, error) bool) {
		messages := toOllamaMessages(req)

		// Tool bridge: if the request offers tools, describe them in the
		// prompt and remember which names are callable so we can parse the
		// reply back into a FunctionCall (local Gemma has no native tools).
		//
		// One-shot per turn: only offer tools when no tool has run yet in the
		// current user turn. Once a tool has produced a result this turn,
		// suppress tool-offering so the model must produce a final text answer.
		// This bounds a weak local model to a single tool round-trip per turn
		// instead of looping, without disabling tools for later turns.
		var allowed map[string]bool
		if !toolRanThisTurn(req.Contents) {
			decls := declarations(req.Config)
			if len(decls) > 0 {
				allowed = make(map[string]bool, len(decls))
				for _, d := range decls {
					allowed[d.Name] = true
				}
				messages = append(messages, ollamaMessage{Role: "system", Content: buildToolInstruction(decls)})
			}
		}

		body, err := json.Marshal(ollamaChatRequest{
			Model:    g.model,
			Messages: messages,
			Stream:   false,
			Options:  temperatureOption(req),
		})
		if err != nil {
			yield(nil, fmt.Errorf("gemma: marshal request: %w", err))
			return
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, g.host+"/api/chat", bytes.NewReader(body))
		if err != nil {
			yield(nil, fmt.Errorf("gemma: build request: %w", err))
			return
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := g.client.Do(httpReq)
		if err != nil {
			yield(nil, fmt.Errorf("gemma: call ollama at %s (is `ollama serve` running and `ollama pull %s` done?): %w", g.host, g.model, err))
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			yield(nil, fmt.Errorf("gemma: ollama returned %s (model %q may not be pulled)", resp.Status, g.model))
			return
		}

		var out ollamaChatResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			yield(nil, fmt.Errorf("gemma: decode response: %w", err))
			return
		}
		if out.Error != "" {
			yield(nil, fmt.Errorf("gemma: ollama error: %s", out.Error))
			return
		}

		usage := &genai.GenerateContentResponseUsageMetadata{
			PromptTokenCount:     out.PromptEvalCount,
			CandidatesTokenCount: out.EvalCount,
			TotalTokenCount:      out.PromptEvalCount + out.EvalCount,
		}

		// If tools were offered and the reply is a JSON tool call, hand ADK a
		// FunctionCall part so its normal tool-execution (+ HITL + telemetry)
		// path runs. Otherwise return the reply as plain text.
		if len(allowed) > 0 {
			if fc, ok := parseToolCall(out.Message.Content, allowed); ok {
				yield(&adkmodel.LLMResponse{
					Content: &genai.Content{
						Role:  "model",
						Parts: []*genai.Part{{FunctionCall: fc}},
					},
					ModelVersion:  out.Model,
					TurnComplete:  true,
					UsageMetadata: usage,
				}, nil)
				return
			}
		}

		yield(&adkmodel.LLMResponse{
			Content: &genai.Content{
				Role:  "model",
				Parts: []*genai.Part{{Text: out.Message.Content}},
			},
			ModelVersion:  out.Model,
			TurnComplete:  true,
			UsageMetadata: usage,
		}, nil)
	}
}

// toOllamaMessages flattens an ADK LLMRequest into Ollama's chat schema. The
// system instruction (if any) becomes a leading system message; genai roles
// ("user"/"model") map to Ollama roles ("user"/"assistant"). Only text parts
// are carried in M0.
func toOllamaMessages(req *adkmodel.LLMRequest) []ollamaMessage {
	var messages []ollamaMessage

	if req.Config != nil && req.Config.SystemInstruction != nil {
		if sys := partsText(req.Config.SystemInstruction.Parts); sys != "" {
			messages = append(messages, ollamaMessage{Role: "system", Content: sys})
		}
	}

	for _, c := range req.Contents {
		if c == nil {
			continue
		}
		text := renderContent(c)
		if text == "" {
			continue
		}
		messages = append(messages, ollamaMessage{Role: ollamaRole(c.Role), Content: text})
	}
	return messages
}

// renderContent flattens a content's parts into a single prompt string,
// including tool-bridge parts: an assistant FunctionCall and a tool's
// FunctionResponse are rendered as text so a non-function-calling local model
// keeps multi-turn continuity across a tool round-trip.
func renderContent(c *genai.Content) string {
	var lines []string
	for _, p := range c.Parts {
		switch {
		case p == nil:
			continue
		case p.Text != "":
			lines = append(lines, p.Text)
		case p.FunctionCall != nil:
			lines = append(lines, renderFunctionCall(p.FunctionCall))
		case p.FunctionResponse != nil:
			lines = append(lines, renderFunctionResponse(p.FunctionResponse))
		}
	}
	return strings.Join(lines, "\n")
}

func partsText(parts []*genai.Part) string {
	var b strings.Builder
	for _, p := range parts {
		if p != nil && p.Text != "" {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

func ollamaRole(role string) string {
	switch role {
	case "model", "assistant":
		return "assistant"
	case "system":
		return "system"
	default:
		return "user"
	}
}

func temperatureOption(req *adkmodel.LLMRequest) map[string]any {
	if req.Config == nil || req.Config.Temperature == nil {
		return nil
	}
	return map[string]any{"temperature": float64(*req.Config.Temperature)}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
