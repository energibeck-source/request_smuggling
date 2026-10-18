package core

import (
	"log"
	"time"
)

type Module interface {
	Name() string
	Run(ctx ScanContext) ([]Finding, error)
}

type Runner struct {
	Modules    []Module
	ExitOnFind bool
}

func (r *Runner) RunAll(ctx ScanContext, delay time.Duration) []Finding {
	var findings []Finding
	for _, m := range r.Modules {
		modFindings, err := m.Run(ctx)
		if err != nil {
			log.Printf("module %T error: %v", m, err)
			continue
		}

		for _, f := range modFindings {
			findings = append(findings, f)

			if r.ExitOnFind &&
				(f.Severity == SeverityMedium || f.Severity == SeverityHigh) {
				return findings
			}
		}

		if delay > 0 {
			jdelay := JitterDelay(delay)
			time.Sleep(jdelay)
		}
	}

	return findings
}
