package modules

import (
	"fmt"
	"log"
	"time"

	"request_smuggling/core"
	"request_smuggling/payloads"
)

type CLTEModule struct {
	Requester *core.SimpleRequester
	Timeout   time.Duration
}

func (m *CLTEModule) Name() string { return "CLTE" }

func (m *CLTEModule) Run(ctx core.ScanContext) ([]core.Finding, error) {
	target := ctx.Target
	delay := ctx.Options.RateInterval
	var findings []core.Finding

	log.Println("[CLTE] module is running for", target.Host)

	for i := range target.Sitemap {
		rec := &target.Sitemap[i]
		if rec.Response.StatusCode == 0 {
			continue
		}
		probe := payloads.BuildTimeCLTE(*rec)
		probeNorm := core.ParseRawResponse(m.Requester.SendRaw(target, probe))
		if core.CheckTimeout(probeNorm, m.Timeout) {
			f := core.Finding{

				Module:   m.Name(),
				Details:  "Probe request causes timeout",
				Evidence: "Payload used: " + string(probe),
				Severity: core.SeverityMedium,
			}
			findings = append(findings, f)
			rec.Result.Findings = append(rec.Result.Findings, f)
		}

		time.Sleep(core.JitterDelay(delay))

		for attempt := 0; attempt < ctx.Options.MaxRetries; attempt++ {

			attackReq := payloads.BuildCLTE(*rec)
			_, _, err := m.Requester.SendRaw(target, attackReq)
			if err != nil {
				log.Println("[CLTE] error while sending smuggling payload:", err)
			}

			afterResp, afterDur, err := m.Requester.SendNormal(target, rec.Request.Endpoint)

			if err != nil {
				log.Println("[CLTE] error while sending post-attack normal request:", err)

			}

			after := core.ParseNormal(afterResp, afterDur, err)

			comp := core.CompareRequests(rec.Response, after)
			if comp.Matched {
				f := core.Finding{
					Module:  m.Name(),
					Details: "CLTE: normal request after smuggled one differs from baseline: " + comp.Details,
					Evidence: "baseline_status=" + fmt.Sprint(rec.Response.StatusCode) +
						", after_status=" + fmt.Sprint(after.StatusCode) +
						", after_delay=" + after.Delay.String() +
						", payload used:\n" + string(attackReq),
					Severity: core.SeverityMedium,
				}
				findings = append(findings, f)
				*rec = enrichRecord(*rec, m.Name(), f)
				break
			}

			time.Sleep(core.JitterDelay(delay))

		}
	}
	log.Printf("[CLTE] module complete, findings: %d", len(findings))
	return findings, nil
}
