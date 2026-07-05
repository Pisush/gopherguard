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

	// Gemma commonly fences tool calls as ```tool_code (not ```json).
	fc, ok = parseToolCall("```tool_code\n{\"tool\": \"web_search\", \"args\": {\"query\": \"go\"}}\n```", allowed)
	if !ok || fc.Name != "web_search" {
		t.Errorf("```tool_code fenced call should parse, got ok=%v fc=%v", ok, fc)
	}

	// Plain-text answer: not a tool call.
	if _, ok := parseToolCall("The latest Go release is great.", allowed); ok {
		t.Error("plain text must not parse as a tool call")
	}

	// Prose that merely mentions JSON must not trigger a call.
	if _, ok := parseToolCall(`I could call {"tool":"web_search"} but I won't.`, allowed); ok {
		t.Error("mid-prose JSON must not parse as a tool call")
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

	// Key-variant tolerance: small models emit tool_name/parameters etc.
	fc, ok = parseToolCall(`{"tool_name":"web_search","parameters":{"query":"go"}}`, allowed)
	if !ok || fc.Name != "web_search" || fc.Args["query"] != "go" {
		t.Errorf("tool_name/parameters variant should parse, got ok=%v fc=%+v", ok, fc)
	}
}

func TestBuildToolInstructionEmpty(t *testing.T) {
	if got := buildToolInstruction(nil); got != "" {
		t.Errorf("no tools should produce empty instruction, got %q", got)
	}
}

func TestToolRanThisTurn(t *testing.T) {
	userText := func(s string) *genai.Content {
		return &genai.Content{Role: "user", Parts: []*genai.Part{{Text: s}}}
	}
	modelCall := &genai.Content{Role: "model", Parts: []*genai.Part{{FunctionCall: &genai.FunctionCall{Name: "web_search"}}}}
	toolResult := &genai.Content{Role: "user", Parts: []*genai.Part{{FunctionResponse: &genai.FunctionResponse{Name: "web_search"}}}}

	// First model call of a turn: just the user's text → offer tools.
	if toolRanThisTurn([]*genai.Content{userText("find go news")}) {
		t.Error("fresh user turn: no tool has run, want false")
	}

	// Same turn, after the tool ran → suppress tools (force final answer).
	if !toolRanThisTurn([]*genai.Content{userText("find go news"), modelCall, toolResult}) {
		t.Error("tool result present this turn, want true")
	}

	// Regression (reviewer's blocking issue): a NEW user turn after a prior
	// turn that used a tool must offer tools again — the gate is per turn, not
	// per session.
	newTurn := []*genai.Content{
		userText("find go news"), modelCall, toolResult,
		&genai.Content{Role: "model", Parts: []*genai.Part{{Text: "here is the news"}}},
		userText("now search for rust news"),
	}
	if toolRanThisTurn(newTurn) {
		t.Error("new user turn after a prior tool use: must offer tools again (per-turn gate)")
	}
}
