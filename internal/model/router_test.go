package model

import (
	"context"
	"testing"
)

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{
		"":          ModeGemma,
		"gemma":     ModeGemma,
		"GEMMA":     ModeGemma,
		"  gemini ": ModeGemini,
		"gemini":    ModeGemini,
		"nonsense":  ModeGemma,
	}
	for in, want := range cases {
		if got := parseMode(in); got != want {
			t.Errorf("parseMode(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRouterDefaultsLocal verifies that with no API key / gemma mode the router
// always stays local and reports forced_local — the keyless, zero-egress
// default the whole project depends on.
func TestRouterDefaultsLocal(t *testing.T) {
	t.Setenv("GG_MODEL_MODE", "gemma")
	t.Setenv("GOOGLE_API_KEY", "")

	r := NewRouter(context.Background())
	if r.Mode() != ModeGemma {
		t.Fatalf("Mode() = %q, want gemma", r.Mode())
	}

	for _, hint := range []TaskHint{{}, {HardReasoning: true}, {Private: true}} {
		d := r.Route(hint)
		if d.Reason != ReasonForcedLocal {
			t.Errorf("Route(%+v).Reason = %q, want forced_local (no key must never escalate)", hint, d.Reason)
		}
		if d.Model == nil {
			t.Errorf("Route(%+v).Model is nil", hint)
		}
	}
}

// TestRouterGeminiModeWithoutKeyDegrades verifies that requesting gemini mode
// without a key degrades to fully-local rather than failing.
func TestRouterGeminiModeWithoutKeyDegrades(t *testing.T) {
	t.Setenv("GG_MODEL_MODE", "gemini")
	t.Setenv("GOOGLE_API_KEY", "")

	r := NewRouter(context.Background())
	if r.Mode() != ModeGemma {
		t.Fatalf("Mode() = %q, want gemma (should degrade without key)", r.Mode())
	}
	if got := r.Route(TaskHint{HardReasoning: true}).Reason; got != ReasonForcedLocal {
		t.Errorf("Route hard reasoning without key = %q, want forced_local", got)
	}
}
