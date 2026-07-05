// Command gopherguard is the hardened-mode launcher.
//
// It runs on local Gemma by default (no API key, no egress). Set
// GG_MODEL_MODE=gemini plus GOOGLE_API_KEY for opt-in production mode. Use the
// ADK launcher subcommands (e.g. `run`, `web`) via the command line; with no
// args it prints ADK's usage.
package main

import (
	"context"
	"log"
	"os"

	"github.com/Pisush/gopherguard/internal/agents"
	"github.com/Pisush/gopherguard/internal/telemetry"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/cmd/launcher"
	"google.golang.org/adk/v2/cmd/launcher/full"
)

func main() {
	ctx := context.Background()

	providers, err := telemetry.Setup(ctx)
	if err != nil {
		log.Fatalf("gopherguard: telemetry setup: %v", err)
	}
	defer func() {
		if err := providers.Shutdown(context.Background()); err != nil {
			log.Printf("gopherguard: telemetry shutdown: %v", err)
		}
	}()

	root, err := agents.BuildGraph(ctx)
	if err != nil {
		log.Fatalf("gopherguard: build agent graph: %v", err)
	}

	l := full.NewLauncher()
	if err := l.Execute(ctx, &launcher.Config{
		AgentLoader: agent.NewSingleLoader(root),
	}, os.Args[1:]); err != nil {
		log.Fatalf("gopherguard: %v", err)
	}
}
