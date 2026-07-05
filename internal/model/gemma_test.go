package model

import (
	"testing"

	adkmodel "google.golang.org/adk/v2/model"
	"google.golang.org/genai"
)

func TestOllamaRole(t *testing.T) {
	cases := map[string]string{
		"user":      "user",
		"model":     "assistant",
		"assistant": "assistant",
		"system":    "system",
		"":          "user",
		"tool":      "user",
	}
	for in, want := range cases {
		if got := ollamaRole(in); got != want {
			t.Errorf("ollamaRole(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPartsText(t *testing.T) {
	parts := []*genai.Part{
		{Text: "hello"},
		nil,
		{Text: ""},
		{Text: "world"},
	}
	if got, want := partsText(parts), "hello\nworld"; got != want {
		t.Errorf("partsText = %q, want %q", got, want)
	}
}

// TestToOllamaMessages verifies the ADK→Ollama conversion: the system
// instruction leads, genai roles map correctly, and empty contents are dropped.
func TestToOllamaMessages(t *testing.T) {
	req := &adkmodel.LLMRequest{
		Config: &genai.GenerateContentConfig{
			SystemInstruction: &genai.Content{Parts: []*genai.Part{{Text: "be terse"}}},
		},
		Contents: []*genai.Content{
			{Role: "user", Parts: []*genai.Part{{Text: "hi"}}},
			{Role: "model", Parts: []*genai.Part{{Text: "hello"}}},
			nil,
			{Role: "user", Parts: []*genai.Part{{Text: ""}}}, // dropped: empty
		},
	}

	msgs := toOllamaMessages(req)

	want := []ollamaMessage{
		{Role: "system", Content: "be terse"},
		{Role: "user", Content: "hi"},
		{Role: "assistant", Content: "hello"},
	}
	if len(msgs) != len(want) {
		t.Fatalf("got %d messages, want %d: %+v", len(msgs), len(want), msgs)
	}
	for i := range want {
		if msgs[i] != want[i] {
			t.Errorf("message[%d] = %+v, want %+v", i, msgs[i], want[i])
		}
	}
}

func TestNewGemmaDefaults(t *testing.T) {
	t.Setenv("OLLAMA_HOST", "")
	t.Setenv("GG_GEMMA_MODEL", "")
	g := NewGemma()
	if g.host != defaultOllamaHost {
		t.Errorf("host = %q, want %q", g.host, defaultOllamaHost)
	}
	if g.model != defaultGemmaModel {
		t.Errorf("model = %q, want %q", g.model, defaultGemmaModel)
	}
	if g.Name() != "gemma-local:"+defaultGemmaModel {
		t.Errorf("Name() = %q", g.Name())
	}
}

func TestNewGemmaTrimsTrailingSlash(t *testing.T) {
	g := NewGemma(WithHost("http://127.0.0.1:11434/"))
	if g.host != "http://127.0.0.1:11434" {
		t.Errorf("host = %q, want trailing slash trimmed", g.host)
	}
}
