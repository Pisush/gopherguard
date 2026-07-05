package model

import (
	"context"
	"iter"
	"testing"

	adkmodel "google.golang.org/adk/v2/model"
)

// fakeLLM is a stand-in model.LLM for exercising router branches without a key.
type fakeLLM struct{ name string }

func (f fakeLLM) Name() string { return f.name }
func (f fakeLLM) GenerateContent(context.Context, *adkmodel.LLMRequest, bool) iter.Seq2[*adkmodel.LLMResponse, error] {
	return func(yield func(*adkmodel.LLMResponse, error) bool) {}
}

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

// TestRouterGeminiArmedRouting pins the routing policy when a Gemini backend is
// available: private work must stay on local Gemma, only hard reasoning
// escalates, and cheap default work stays local. The Private-stays-local rule
// is a security property (private input must never leave the machine).
func TestRouterGeminiArmedRouting(t *testing.T) {
	gemma := fakeLLM{name: "gemma"}
	gemini := fakeLLM{name: "gemini"}
	r := &Router{mode: ModeGemini, gemma: gemma, gemini: gemini}

	cases := []struct {
		name       string
		hint       TaskHint
		wantReason RouteReason
		wantModel  string
	}{
		{"private stays local", TaskHint{Private: true}, ReasonPrivateLocal, "gemma"},
		{"private beats hard reasoning", TaskHint{Private: true, HardReasoning: true}, ReasonPrivateLocal, "gemma"},
		{"hard reasoning escalates", TaskHint{HardReasoning: true}, ReasonHardReasoning, "gemini"},
		{"cheap default stays local", TaskHint{}, ReasonForcedLocal, "gemma"},
	}
	for _, tc := range cases {
		d := r.Route(tc.hint)
		if d.Reason != tc.wantReason {
			t.Errorf("%s: Reason = %q, want %q", tc.name, d.Reason, tc.wantReason)
		}
		if d.Model == nil || d.Model.Name() != tc.wantModel {
			t.Errorf("%s: Model = %v, want %q", tc.name, d.Model, tc.wantModel)
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
