package modules

import (
	"log"
	"time"

	"request_smuggling/core"
	"request_smuggling/payloads"
)

type CLTETimingModule struct {
	Requester core.SimpleRequester
	Timeout   time.Duration
}

func (m *CLTETimingModule) Name() string { return "CLTE timing probe" }

func (m *CLTETimingModule) Run(ctx core.ScanContext) ([]core.Finding, error) {
	target := ctx.Target
	var findings []core.Finding

	log.Println("[Time based CLTE module is running]")

	for _, rec := range target.Sitemap {
		if rec.Response.StatusCode == 0 {
			continue
		}
		probe := payloads.BuildTimeCLTE(rec)
		probeResp, probeDur, err := m.Requester.SendRaw(target, probe)

		probeNorm := core.ParseRawResponse(probeResp, probeDur, err)

		if err != nil {
			log.Printf("Err for endpoint %s: \n%v\n", rec.Request.Endpoint, err)
		}

		timeout := core.CheckTimeout(probeNorm, m.Timeout)

		if timeout {
			f := core.Finding{

				Module:   m.Name(),
				Details:  "Time based CLTE payload causes timeout",
				Evidence: "attack duration=" + probeDur.String(),
				Severity: core.SeverityMedium,
			}

			if ctx.Options.ExitOnFind {
				return []core.Finding{f}, nil
			} else {
				findings = append(findings, f)
			}
		}
	}

	return findings, nil
}
