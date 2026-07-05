package model

import (
	"context"
	"fmt"
	"os"

	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/model/gemini"
	"google.golang.org/genai"
)

const defaultGeminiModel = "gemini-flash-latest"

// NewGemini builds the opt-in "production mode" model. It requires GOOGLE_API_KEY
// and makes outbound calls to the Gemini API, so it is never used in
// vulnerable/fenced mode. The model name is overridable via GG_GEMINI_MODEL.
func NewGemini(ctx context.Context) (model.LLM, error) {
	apiKey := os.Getenv("GOOGLE_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("gemini: GOOGLE_API_KEY is not set (use the default local Gemma, or set the key for production mode)")
	}
	name := envOr("GG_GEMINI_MODEL", defaultGeminiModel)
	return gemini.NewModel(ctx, name, &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI,
	})
}
