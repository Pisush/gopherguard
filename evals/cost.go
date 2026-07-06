package evals

// EstimateCostPer1K returns the estimated model cost in USD per 1,000
// requests under the config's routing policy. It is the back-of-envelope
// number behind the CI cost-delta summary — a planning signal for reviewing
// an agent-config change, not billing.
//
// Model: every request costs avg_tokens_per_request tokens on the local
// model (gemma price, normally $0); in gemini mode, escalation_rate of
// requests instead pay the Gemini per-token price.
func EstimateCostPer1K(cfg *AgentConfig) float64 {
	c := cfg.Model.Cost
	tok := float64(c.AvgTokensPerRequest)
	local := c.GemmaUSDPerMTok / 1e6 * tok
	if cfg.Model.Mode != "gemini" || !cfg.Model.Routing.HardReasoningEscalates {
		return 1000 * local
	}
	remote := c.GeminiUSDPerMTok / 1e6 * tok
	return 1000 * ((1-c.EscalationRate)*local + c.EscalationRate*remote)
}
