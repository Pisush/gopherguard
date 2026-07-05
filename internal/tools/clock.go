package tools

import (
	"fmt"
	"time"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/tool/functiontool"
)

// WorldClockArgs is the input to the world_clock tool.
type WorldClockArgs struct {
	// Timezone is an IANA timezone name, e.g. "Europe/Berlin", "UTC".
	Timezone string `json:"timezone" jsonschema:"IANA timezone name such as Europe/Berlin or UTC"`
}

// WorldClockResult is the output of the world_clock tool.
type WorldClockResult struct {
	Timezone string `json:"timezone"`
	Time     string `json:"time"`
	IsDST    bool   `json:"is_dst"`
}

// NewWorldClock builds the M0 demonstration tool: a read-only, zero-egress,
// non-mutating clock. It proves the full path (functiontool → agent → local
// Gemma) without any network access or credentials.
//
// Scope read:time, non-mutating, does not touch untrusted input.
func NewWorldClock() (ScopedTool, error) {
	t, err := functiontool.New(functiontool.Config{
		Name:        "world_clock",
		Description: "Returns the current time in a given IANA timezone (e.g. Europe/Berlin, UTC).",
	}, func(_ agent.Context, args WorldClockArgs) (WorldClockResult, error) {
		tz := args.Timezone
		if tz == "" {
			tz = "UTC"
		}
		loc, err := time.LoadLocation(tz)
		if err != nil {
			return WorldClockResult{}, fmt.Errorf("unknown timezone %q: %w", tz, err)
		}
		now := time.Now().In(loc)
		return WorldClockResult{
			Timezone: tz,
			Time:     now.Format(time.RFC3339),
			IsDST:    now.IsDST(),
		}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("build world_clock tool: %w", err)
	}
	return Scope(t, "read:time", false, false), nil
}
