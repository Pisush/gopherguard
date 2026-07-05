package model

import (
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/genai"
)

// This file implements a prompt-based (ReAct-style) tool bridge for local
// models. ADK's tool loop assumes a function-calling-capable model, but local
// Gemma via Ollama returns "does not support tools" for native function calls
// (a finding from M0). The bridge closes that gap deterministically: it
// describes the available tools in the prompt with a strict JSON call protocol,
// then parses the model's reply back into a genai.FunctionCall so ADK's normal
// tool-execution + HITL + telemetry path runs unchanged.
//
// Reliability is model-dependent: the bridge is correct and lenient (it accepts
// fenced calls and common key variants, and refuses mid-prose JSON), but a very
// small model such as gemma2:2b follows the call protocol only intermittently.
// A larger local model or Gemini production mode drives tools far more reliably;
// the bridge itself does not change.

// toolProtocol is the instruction appended when tools are offered. Keeping the
// contract strict and single-line-JSON makes the reply easy to parse and hard
// to fudge.
const toolProtocol = `You can call tools to help answer.

To call a tool, reply with ONLY a single-line JSON object and nothing else:
{"tool":"<tool_name>","args":{<arguments>}}

If you do not need a tool, reply normally in plain text (no JSON).
After a tool result is provided, use it to give your final plain-text answer.

Available tools:
`

// declarations collects the function declarations offered in the request.
func declarations(req *LLMRequestConfig) []*genai.FunctionDeclaration {
	if req == nil {
		return nil
	}
	var out []*genai.FunctionDeclaration
	for _, t := range req.Tools {
		if t == nil {
			continue
		}
		out = append(out, t.FunctionDeclarations...)
	}
	return out
}

// LLMRequestConfig aliases the genai config so this file can talk about the
// tool-bearing part of a request without importing the ADK model package here.
type LLMRequestConfig = genai.GenerateContentConfig

// buildToolInstruction renders the tool protocol plus a compact description of
// each tool for the prompt.
func buildToolInstruction(decls []*genai.FunctionDeclaration) string {
	if len(decls) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(toolProtocol)
	for _, d := range decls {
		fmt.Fprintf(&b, "- %s: %s\n", d.Name, d.Description)
		if params := schemaHint(d.Parameters); params != "" {
			fmt.Fprintf(&b, "    args: %s\n", params)
		}
	}
	return b.String()
}

// schemaHint renders a tool's parameters as a compact "name(type)" list so the
// model knows what arguments to supply, without dumping full JSON schema.
func schemaHint(s *genai.Schema) string {
	if s == nil || len(s.Properties) == 0 {
		return ""
	}
	parts := make([]string, 0, len(s.Properties))
	for name, prop := range s.Properties {
		typ := "string"
		if prop != nil && prop.Type != "" {
			typ = strings.ToLower(string(prop.Type))
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", name, typ))
	}
	return strings.Join(parts, ", ")
}

// Key aliases the bridge accepts for the tool name and the arguments. Small
// local models are inconsistent about which key they emit (tool vs tool_name vs
// name; args vs arguments vs parameters), so the parser tolerates the common
// variants rather than demanding the exact protocol spelling.
var (
	toolNameKeys = []string{"tool", "tool_name", "name", "function"}
	toolArgsKeys = []string{"args", "arguments", "parameters", "params", "input"}
)

// parseToolCall attempts to extract a tool call from the model's reply. It
// returns a genai.FunctionCall when the reply is a JSON tool call naming one of
// the allowed tools, or ok=false when the reply is a plain-text answer.
func parseToolCall(reply string, allowed map[string]bool) (*genai.FunctionCall, bool) {
	// Require the reply to be predominantly a JSON object (optionally fenced),
	// so a model merely quoting an example mid-prose does not trigger a real
	// tool call. The protocol tells the model to reply with ONLY the JSON.
	if !looksLikeToolCall(reply) {
		return nil, false
	}
	obj := extractJSONObject(reply)
	if obj == "" {
		return nil, false
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(obj), &raw); err != nil {
		return nil, false
	}

	name := firstString(raw, toolNameKeys)
	if name == "" || !allowed[name] {
		return nil, false
	}
	args := firstMap(raw, toolArgsKeys)
	if args == nil {
		args = map[string]any{}
	}
	return &genai.FunctionCall{Name: name, Args: args}, true
}

// firstString returns the first key in keys whose value is a non-empty string.
func firstString(m map[string]any, keys []string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// firstMap returns the first key in keys whose value is a JSON object.
func firstMap(m map[string]any, keys []string) map[string]any {
	for _, k := range keys {
		if v, ok := m[k].(map[string]any); ok {
			return v
		}
	}
	return nil
}

// looksLikeToolCall reports whether the reply is predominantly a JSON object
// (after trimming whitespace and an optional code fence with any language tag,
// e.g. ```json or Gemma's ```tool_code), as opposed to a prose answer that
// happens to contain a JSON example.
func looksLikeToolCall(reply string) bool {
	return strings.HasPrefix(strings.TrimSpace(stripCodeFence(reply)), "{")
}

// stripCodeFence removes a leading Markdown code fence (```lang) and its
// trailing ``` if present, returning the inner content. Handles any language
// tag, including Gemma's ```tool_code.
func stripCodeFence(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	// Drop the opening fence line (```<optional-lang> up to newline).
	if nl := strings.IndexByte(s, '\n'); nl >= 0 {
		s = s[nl+1:]
	} else {
		s = strings.TrimPrefix(s, "```")
	}
	s = strings.TrimSpace(s)
	return strings.TrimSuffix(s, "```")
}

// extractJSONObject returns the first balanced top-level {...} object found in
// s (tolerating models that wrap JSON in prose or code fences), or "".
func extractJSONObject(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")

	start := strings.IndexByte(s, '{')
	if start < 0 {
		return ""
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
			// skip
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

// renderFunctionCall renders an assistant tool-call part back into prompt text
// for multi-turn continuity.
func renderFunctionCall(fc *genai.FunctionCall) string {
	args, _ := json.Marshal(fc.Args)
	return fmt.Sprintf(`{"tool":%q,"args":%s}`, fc.Name, string(args))
}

// renderFunctionResponse renders a tool result into prompt text the model can
// read on the follow-up turn.
func renderFunctionResponse(fr *genai.FunctionResponse) string {
	res, _ := json.Marshal(fr.Response)
	return fmt.Sprintf("Tool result for %s: %s", fr.Name, string(res))
}

// toolRanThisTurn reports whether a tool has already produced a result within
// the CURRENT user turn. It scans history backward: a FunctionResponse seen
// before the most recent user text turn means a tool already ran this turn (so
// the bridge should stop offering tools and force a final answer); reaching the
// user's text turn first means no tool has run yet this turn (offer tools).
//
// Scoping to the current turn matters: ADK builds the request's Contents from
// ALL session events on the agent's branch, so a naive "any FunctionResponse in
// history" check would suppress tools for the whole session after a single use.
func toolRanThisTurn(contents []*genai.Content) bool {
	for i := len(contents) - 1; i >= 0; i-- {
		c := contents[i]
		if c == nil {
			continue
		}
		userText := false
		for _, p := range c.Parts {
			if p == nil {
				continue
			}
			if p.FunctionResponse != nil {
				return true // tool result found before the current user turn
			}
			if p.Text != "" && ollamaRole(c.Role) == "user" {
				userText = true
			}
		}
		if userText {
			return false // reached the current user turn; no tool ran since
		}
	}
	return false
}
