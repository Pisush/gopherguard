package evals

import (
	"fmt"

	"github.com/Pisush/gopherguard/internal/agents"
	"github.com/Pisush/gopherguard/internal/owasp"
)

// Check is one named assertion inside a suite.
type Check struct {
	Name   string
	Pass   bool
	Detail string // evidence on failure, score/context on success
}

// SuiteResult is the outcome of one suite.
type SuiteResult struct {
	Name   string
	Checks []Check
}

// Pass reports whether every check in the suite passed.
func (s SuiteResult) Pass() bool {
	for _, c := range s.Checks {
		if !c.Pass {
			return false
		}
	}
	return true
}

// Counts returns (passed, total) checks.
func (s SuiteResult) Counts() (passed, total int) {
	for _, c := range s.Checks {
		if c.Pass {
			passed++
		}
	}
	return passed, len(s.Checks)
}

// Report is the outcome of a full eval run: the config it ran against plus
// every suite's checks. CI turns this into the step summary / PR comment.
type Report struct {
	ConfigName string
	Suites     []SuiteResult
}

// Pass reports whether every suite passed. This is the CI gate.
func (r Report) Pass() bool {
	for _, s := range r.Suites {
		if !s.Pass() {
			return false
		}
	}
	return true
}

// Options carries the harness's injection points. The zero value uses the
// real system (production classifier, default OWASP registry); tests swap in
// deliberately-regressed pieces to prove the gate catches them.
type Options struct {
	// Classifier is the coordinator route decision under eval. Defaults to
	// agents.Classify (the code the deployed graph actually routes with).
	Classifier func(string) string
	// Registry is the OWASP pair registry under eval. Defaults to
	// owasp.DefaultRegistry().
	Registry *owasp.Registry
}

func (o Options) withDefaults() Options {
	if o.Classifier == nil {
		o.Classifier = agents.Classify
	}
	if o.Registry == nil {
		o.Registry = owasp.DefaultRegistry()
	}
	return o
}

// Run validates the config and executes the three eval suites against it.
// A config that fails Validate produces a single failing "config" suite, so
// the gate result is always a Report.
func Run(cfg *AgentConfig, opts Options) Report {
	opts = opts.withDefaults()
	r := Report{ConfigName: cfg.Metadata.Name}

	if err := cfg.Validate(); err != nil {
		r.Suites = append(r.Suites, SuiteResult{
			Name:   "config",
			Checks: []Check{{Name: "static validation", Pass: false, Detail: err.Error()}},
		})
		return r
	}
	r.Suites = append(r.Suites, SuiteResult{
		Name:   "config",
		Checks: []Check{{Name: "static validation", Pass: true, Detail: "policy gate ok"}},
	})

	r.Suites = append(r.Suites,
		TaskSuccess(cfg, opts),
		Trajectory(cfg, opts),
		InjectionResistance(cfg, opts),
	)
	return r
}

// check is a small helper for building pass/fail checks with formatted detail.
func check(name string, pass bool, format string, args ...any) Check {
	return Check{Name: name, Pass: pass, Detail: fmt.Sprintf(format, args...)}
}
