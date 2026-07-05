package model

import (
	"testing"

	"google.golang.org/genai"
)

func TestExtractJSONObject(t *testing.T) {
	cases := map[string]string{
		`{"tool":"x","args":{}}`:                     `{"tool":"x","args":{}}`,
		"```json\n{\"tool\":\"x\",\"args\":{}}\n```": `{"tool":"x","args":{}}`,
		`sure! {"tool":"x","args":{"k":"v"}} done`:   `{"tool":"x","args":{"k":"v"}}`,
		`no json here`:                  ``,
		`{"a":{"nested":true},"b":1}`:   `{"a":{"nested":true},"b":1}`,
		`{"s":"has } brace in string"}`: `{"s":"has } brace in string"}`,
	}
	for in, want := range cases {
		if got := extractJSONObject(in); got != want {
			t.Errorf("extractJSONObject(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseToolCall(t *testing.T) {
	allowed := map[string]bool{"web_search": true}

	fc, ok := parseToolCall(`{"tool":"web_search","args":{"query":"go news"}}`, allowed)
	if !ok {
		t.Fatal("expected a tool call")
	}
	if fc.Name != "web_search" {
		t.Errorf("Name = %q, want web_search", fc.Name)
	}
	if fc.Args["query"] != "go news" {
		t.Errorf("Args[query] = %v, want 'go news'", fc.Args["query"])
	}

	// Plain-text answer: not a tool call.
	if _, ok := parseToolCall("The latest Go release is great.", allowed); ok {
		t.Error("plain text must not parse as a tool call")
	}

	// A tool name that is not allowed must be rejected (least privilege).
	if _, ok := parseToolCall(`{"tool":"rm_rf","args":{}}`, allowed); ok {
		t.Error("disallowed tool name must not parse as a tool call")
	}

	// Missing args should default to empty, not nil.
	fc, ok = parseToolCall(`{"tool":"web_search"}`, allowed)
	if !ok || fc.Args == nil {
		t.Error("missing args should default to empty map")
	}
}

func TestBuildToolInstructionEmpty(t *testing.T) {
	if got := buildToolInstruction(nil); got != "" {
		t.Errorf("no tools should produce empty instruction, got %q", got)
	}
}

func TestHasFunctionResponse(t *testing.T) {
	none := []*genai.Content{
		{Parts: []*genai.Part{{Text: "hi"}}},
		{Parts: []*genai.Part{{FunctionCall: &genai.FunctionCall{Name: "web_search"}}}},
	}
	if hasFunctionResponse(none) {
		t.Error("no FunctionResponse present, want false")
	}

	withResp := append(none, &genai.Content{
		Parts: []*genai.Part{{FunctionResponse: &genai.FunctionResponse{Name: "web_search"}}},
	})
	if !hasFunctionResponse(withResp) {
		t.Error("FunctionResponse present, want true (one-shot tool gate)")
	}
}
