package model

import (
	"context"
	"os"
	"strings"

	"google.golang.org/adk/v2/model"
)

// Mode selects which backend the router prefers.
type Mode string

const (
	// ModeGemma forces local Gemma everywhere (default; keyless, zero egress).
	ModeGemma Mode = "gemma"
	// ModeGemini enables opt-in production routing to the Gemini API for hard
	// reasoning while still keeping cheap/private work on local Gemma.
	ModeGemini Mode = "gemini"
)

// RouteReason is the decision label stamped onto the model.route_reason span
// attribute in M1+. Kept as a small closed vocabulary so detections and cost
// dashboards can group by it.
type RouteReason string

const (
	ReasonForcedLocal   RouteReason = "forced_local"        // mode=gemma or no key available
	ReasonPrivateLocal  RouteReason = "private_stays_local" // classify/private → Gemma even in prod
	ReasonHardReasoning RouteReason = "hard_reasoning"      // escalated to Gemini
)

// Decision is the result of a routing call: the chosen model plus the reason,
// which callers stamp onto a span as model.route_reason.
type Decision struct {
	Model  model.LLM
	Reason RouteReason
}

// Router performs cost-based routing: cheap/classify/private work → Gemma;
// hard reasoning → Gemini (only when production mode is enabled and a key
// exists). The default zero value routes everything to local Gemma.
type Router struct {
	mode   Mode
	gemma  model.LLM
	gemini model.LLM // may be nil when no key / gemma mode
}

// TaskHint describes the work being routed so the router can pick a backend
// without an LLM call (the routing itself must be deterministic Go).
type TaskHint struct {
	// HardReasoning marks a step that benefits from the stronger model.
	HardReasoning bool
	// Private marks a step whose input must not leave the machine; such steps
	// stay on local Gemma even in production mode.
	Private bool
}

// NewRouter builds a router. Mode comes from GG_MODEL_MODE (gemma|gemini),
// defaulting to gemma. Gemini is only wired in when mode=gemini AND a key is
// present; otherwise the router silently stays fully local.
func NewRouter(ctx context.Context) *Router {
	r := &Router{
		mode:  parseMode(os.Getenv("GG_MODEL_MODE")),
		gemma: NewGemma(),
	}
	if r.mode == ModeGemini {
		if g, err := NewGemini(ctx); err == nil {
			r.gemini = g
		} else {
			// No key / init failure: degrade to fully-local rather than fail.
			r.mode = ModeGemma
		}
	}
	return r
}

// Route picks a backend for the given task hint and returns the decision plus
// the reason to record as model.route_reason.
func (r *Router) Route(hint TaskHint) Decision {
	if r.mode == ModeGemma || r.gemini == nil {
		return Decision{Model: r.gemma, Reason: ReasonForcedLocal}
	}
	if hint.Private {
		return Decision{Model: r.gemma, Reason: ReasonPrivateLocal}
	}
	if hint.HardReasoning {
		return Decision{Model: r.gemini, Reason: ReasonHardReasoning}
	}
	return Decision{Model: r.gemma, Reason: ReasonForcedLocal}
}

// Default returns the model for the default (cheap/local) path. Used by M0's
// single-agent scaffold before per-step routing exists.
func (r *Router) Default() model.LLM {
	return r.Route(TaskHint{}).Model
}

// Mode reports the effective mode after key resolution.
func (r *Router) Mode() Mode { return r.mode }

func parseMode(s string) Mode {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case ModeGemini:
		return ModeGemini
	default:
		return ModeGemma
	}
}
