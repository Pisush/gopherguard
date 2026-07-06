package evals

import (
	"fmt"
	"io"
)

// WriteText renders the report for terminal output (`make eval`).
func (r Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "gopherguard eval report — config %q\n", r.ConfigName)
	for _, s := range r.Suites {
		passed, total := s.Counts()
		fmt.Fprintf(w, "\n[%s] %d/%d checks passed\n", s.Name, passed, total)
		for _, c := range s.Checks {
			mark := "ok  "
			if !c.Pass {
				mark = "FAIL"
			}
			fmt.Fprintf(w, "  %s %-40s %s\n", mark, c.Name, c.Detail)
		}
	}
	fmt.Fprintf(w, "\nRESULT: %s\n", passFail(r.Pass()))
}

// WriteMarkdown renders the report as GitHub-flavored markdown for the
// Actions step summary and the PR comment. costDelta is optional baseline
// context (nil to omit).
func (r Report) WriteMarkdown(w io.Writer, cost float64, baseline *float64) {
	fmt.Fprintf(w, "## gopherguard eval gate — %s\n\n", passFail(r.Pass()))
	fmt.Fprintf(w, "Config: `%s`\n\n", r.ConfigName)

	fmt.Fprintf(w, "| Suite | Checks | Result |\n|---|---|---|\n")
	for _, s := range r.Suites {
		passed, total := s.Counts()
		fmt.Fprintf(w, "| %s | %d/%d | %s |\n", s.Name, passed, total, passFail(s.Pass()))
	}

	// Failures get full detail; passing checks stay collapsed to keep the
	// PR comment readable.
	var failures []Check
	for _, s := range r.Suites {
		for _, c := range s.Checks {
			if !c.Pass {
				failures = append(failures, c)
			}
		}
	}
	if len(failures) > 0 {
		fmt.Fprintf(w, "\n### Failing checks\n\n")
		for _, c := range failures {
			fmt.Fprintf(w, "- **%s** — %s\n", c.Name, c.Detail)
		}
	}

	fmt.Fprintf(w, "\n### Cost estimate\n\n")
	fmt.Fprintf(w, "Estimated model cost: **$%.4f / 1k requests** (routing mode + escalation rate from the agent config)\n", cost)
	if baseline != nil {
		delta := cost - *baseline
		sign := "+"
		if delta < 0 {
			sign = "" // the minus comes with the number
		}
		fmt.Fprintf(w, "\nBaseline (main): $%.4f / 1k requests → delta **%s$%.4f**\n", *baseline, sign, delta)
	}
	fmt.Fprintf(w, "\n<sub>Keyless suites: task-success (golden routing, tolerance-graded), trajectory (step/loop/hop budgets), injection-resistance (OWASP pair + detection regression).</sub>\n")
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}
