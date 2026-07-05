// Package agents assembles gopherguard's agent graph.
//
// M0 wires a single coordinator agent with one scoped tool, running on the
// router's default (local Gemma) model — enough to prove the end-to-end path
// with no API key. The full code-routed graph (coordinator + researcher +
// dbagent + writer) is built in M1.
package agents

import (
	"context"
	"fmt"

	"github.com/Pisush/gopherguard/internal/model"
	"github.com/Pisush/gopherguard/internal/tools"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
)

const coordinatorInstruction = `You are gopherguard's coordinator agent.
You help the user with simple questions and can report the current time in any
timezone using the world_clock tool. Keep answers concise. If asked for the
time, call the world_clock tool with an IANA timezone name.`

// BuildM0 constructs the M0 single-tool coordinator agent. It selects the
// default (local Gemma) model via the router, registers the world_clock tool
// through the scoped-tool registry, and returns the ready agent.
func BuildM0(ctx context.Context) (agent.Agent, error) {
	router := model.NewRouter(ctx)

	registry := tools.NewRegistry()
	clock, err := tools.NewWorldClock()
	if err != nil {
		return nil, fmt.Errorf("build tools: %w", err)
	}
	if err := registry.Register(clock); err != nil {
		return nil, fmt.Errorf("register tools: %w", err)
	}

	a, err := llmagent.New(llmagent.Config{
		Name:        "coordinator",
		Description: "gopherguard coordinator — answers questions and reports the time.",
		Instruction: coordinatorInstruction,
		Model:       router.Default(),
		Tools:       registry.Tools(),
	})
	if err != nil {
		return nil, fmt.Errorf("build coordinator agent: %w", err)
	}
	return a, nil
}
