package evals

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/Pisush/gopherguard/internal/owasp"
	"github.com/Pisush/gopherguard/internal/telemetry"
)

// keyless pins the environment to the local, keyless model paths so the
// suites behave identically on a laptop with a configured key and in CI.
func keyless(t *testing.T) {
	t.Helper()
	t.Setenv("GG_MODEL_MODE", "gemma")
	t.Setenv("GOOGLE_API_KEY", "")
}

func suite(t *testing.T, r Report, name string) SuiteResult {
	t.Helper()
	for _, s := range r.Suites {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("suite %q not in report", name)
	return SuiteResult{}
}

func logReport(t *testing.T, r Report) {
	t.Helper()
	var b strings.Builder
	r.WriteText(&b)
	t.Log("\n" + b.String())
}

// TestRealConfigPassesGate is the acceptance run: the checked-in GitOps
// config (deploy/agent.yaml) must pass all suites, keyless. This is exactly
// what `make eval` and CI execute.
func TestRealConfigPassesGate(t *testing.T) {
	keyless(t)
	cfg, err := Load("../deploy/agent.yaml")
	if err != nil {
		t.Fatalf("load real config: %v", err)
	}
	rep := Run(cfg, Options{})
	if !rep.Pass() {
		logReport(t, rep)
		t.Fatal("deploy/agent.yaml must pass the eval gate")
	}
}

// TestGateCatchesBadConfig proves the gate: a structurally-valid but wrong
// agent config (drifted loop budget, missing researcher agent) must FAIL the
// trajectory suite even though static validation accepts it.
func TestGateCatchesBadConfig(t *testing.T) {
	keyless(t)
	cfg, err := Load("testdata/agent-bad.yaml")
	if err != nil {
		t.Fatalf("load bad config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("agent-bad.yaml must pass static validation (the point is the evals catch it), got: %v", err)
	}
	rep := Run(cfg, Options{})
	if rep.Pass() {
		logReport(t, rep)
		t.Fatal("the eval gate must fail the deliberately-bad config")
	}
	tr := suite(t, rep, "trajectory")
	if tr.Pass() {
		logReport(t, rep)
		t.Fatal("the trajectory suite must catch the drifted loop budget / missing agent")
	}
}

// TestGateCatchesRegressedClassifier proves the gate catches a routing
// regression: a classifier that lost its routing behavior (everything ->
// writer) must fail the task-success golden suite.
func TestGateCatchesRegressedClassifier(t *testing.T) {
	keyless(t)
	cfg, err := Load("../deploy/agent.yaml")
	if err != nil {
		t.Fatalf("load real config: %v", err)
	}
	regressed := func(string) string { return "write" }
	rep := Run(cfg, Options{Classifier: regressed})
	if rep.Pass() {
		logReport(t, rep)
		t.Fatal("the eval gate must fail a regressed classifier")
	}
	ts := suite(t, rep, "task-success")
	if ts.Pass() {
		t.Fatal("the task-success suite must catch the routing regression")
	}
}

// regressedRegistry returns an OWASP registry containing one pair whose
// "hardened" variant regressed: it egresses after an untrusted read exactly
// like the vulnerable one (mitigation deleted).
func regressedRegistry() *owasp.Registry {
	leak := func(ctx context.Context) owasp.Outcome {
		readCtx, span := telemetry.StartSpan(ctx, "regressed.read_tool_output",
			telemetry.AttrPrivilegeScope("read:web"),
			telemetry.AttrUntrusted(true))
		span.End()
		_, egress := telemetry.StartSpan(readCtx, "regressed.exfil",
			telemetry.AttrPrivilegeScope("write:egress"),
			telemetry.AttrEgress(true))
		egress.End()
		return owasp.Outcome{
			Scenario:    "regression fixture",
			Attempted:   "injection→exfil",
			Result:      "egress performed",
			Compromised: true,
		}
	}
	r := owasp.NewRegistry()
	r.Register(owasp.Pair{
		ID:         "REGRESSED",
		Risk:       "fixture: mitigation deleted",
		Vulnerable: leak,
		Hardened:   leak, // the regression: hardened behaves like vulnerable
	})
	return r
}

// TestGateCatchesHardeningRegression proves the injection-resistance suite is
// a real regression guard: if a hardened variant starts behaving like its
// vulnerable twin (untrusted read followed by egress), the detections fire on
// the "hardened" trace and the gate fails.
func TestGateCatchesHardeningRegression(t *testing.T) {
	keyless(t)
	cfg, err := Load("../deploy/agent.yaml")
	if err != nil {
		t.Fatalf("load real config: %v", err)
	}
	rep := Run(cfg, Options{Registry: regressedRegistry()})
	if rep.Pass() {
		logReport(t, rep)
		t.Fatal("the eval gate must fail when a hardened variant regresses")
	}
	inj := suite(t, rep, "injection-resistance")
	if inj.Pass() {
		t.Fatal("the injection-resistance suite must catch the hardening regression")
	}
	var quietFailed, holdsFailed bool
	for _, c := range inj.Checks {
		if c.Name == "all rules quiet on REGRESSED hardened" && !c.Pass {
			quietFailed = true
		}
		if c.Name == "pair holds: REGRESSED" && !c.Pass {
			holdsFailed = true
		}
	}
	if !quietFailed {
		t.Error("the silence invariant must fail on the regressed hardened trace")
	}
	if !holdsFailed {
		t.Error("the holds invariant must fail on the regressed pair")
	}
}

// TestValidateRejectsUnsafeConfig — the static policy gate refuses configs
// that violate the security posture, before any suite runs.
func TestValidateRejectsUnsafeConfig(t *testing.T) {
	cfg, err := Load("testdata/agent-invalid.yaml")
	if err != nil {
		t.Fatalf("load invalid config (parse should succeed): %v", err)
	}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate must reject the unsafe config")
	}
	for _, want := range []string{"write:egress", "private_stays_local", "injection→action"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Validate error must mention %q, got:\n%v", want, err)
		}
	}

	// Run() surfaces the same failure as a failing "config" suite.
	rep := Run(cfg, Options{})
	if rep.Pass() {
		t.Fatal("Run must fail on an invalid config")
	}
	if len(rep.Suites) != 1 || rep.Suites[0].Name != "config" {
		t.Fatalf("an invalid config must stop at the config suite, got %d suites", len(rep.Suites))
	}
}

// TestParseRejectsUnknownFields — strict GitOps parsing: a typo in
// deploy/agent.yaml is an error, not a silently-ignored field.
func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte("kind: AgentConfig\nbudgetz:\n  max_steps_per_session: 3\n"))
	if err == nil {
		t.Fatal("Parse must reject unknown fields")
	}
}

// TestEstimateCostPer1K pins the cost arithmetic behind the CI cost summary.
func TestEstimateCostPer1K(t *testing.T) {
	cfg := &AgentConfig{}
	cfg.Model.Mode = "gemma"
	cfg.Model.Cost = CostModel{GemmaUSDPerMTok: 0, GeminiUSDPerMTok: 0.30, EscalationRate: 0.10, AvgTokensPerRequest: 2000}
	if got := EstimateCostPer1K(cfg); got != 0 {
		t.Errorf("gemma mode cost = %v, want 0", got)
	}

	cfg.Model.Mode = "gemini"
	cfg.Model.Routing.HardReasoningEscalates = true
	// 10% of 1000 requests * 2000 tok * $0.30/1M tok = $0.06
	if got, want := EstimateCostPer1K(cfg), 0.06; !almost(got, want) {
		t.Errorf("gemini mode cost = %v, want %v", got, want)
	}
}

func almost(a, b float64) bool {
	d := a - b
	return d < 1e-9 && d > -1e-9
}

// TestMain quick sanity: the suites must not depend on the working directory
// beyond testdata (embedded goldens), so `go test ./evals/...` works from
// anywhere.
func TestGoldenRoutesEmbedded(t *testing.T) {
	if _, err := os.Stat("testdata/golden_routes.yaml"); err != nil {
		t.Skip("not running from package dir")
	}
	gs, err := goldenRoutes()
	if err != nil {
		t.Fatalf("goldenRoutes: %v", err)
	}
	if len(gs) < 10 {
		t.Errorf("expected at least 10 golden routes, got %d", len(gs))
	}
}
