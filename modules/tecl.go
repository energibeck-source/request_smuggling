package modules

import (
	"fmt"
	"log"
	"time"

	"request_smuggling/core"
	"request_smuggling/payloads"
)

type TECLModule struct {
	Requester *core.SimpleRequester
	Timeout   time.Duration
}

func (m *TECLModule) Name() string { return "TECL" }

func (m *TECLModule) Run(ctx core.ScanContext) ([]core.Finding, error) {
	target := ctx.Target

	log.Println("[TECL] module is running for", target.Host)
	var findings []core.Finding

	for i := range target.Sitemap {
		rec := &target.Sitemap[i]
		if rec.Response.StatusCode == 0 {
			continue
		}
		probe := payloads.BuildTimeTECL(*rec)
		probeNorm := core.ParseRawResponse(m.Requester.SendRaw(target, probe))
		if core.CheckTimeout(probeNorm, m.Timeout) {
			f := core.Finding{

				Module:   m.Name(),
				Details:  "Probe request causes timeout",
				Evidence: "Payload used: " + string(probe),
				Severity: core.SeverityMedium,
			}
			findings = append(findings, f)
			*rec = enrichRecord(*rec, m.Name(), f)

			for i := 1; i < ctx.Options.MaxRetries; i++ {

				attackReq := payloads.BuildTECL(*rec)

				after, err := sendSmuggledAndGetResp(m.Requester, target, attackReq, ctx.Options, m.Name(), rec.Request.Endpoint)
				if err != nil {

					log.Println("[sendSmuggledAndGetResp] error", err)
				}
				log.Println("Comparing with normal request, post-attack status code:", after.StatusCode)

				comp := core.CompareRequests(rec.Response, after)
				if comp.Matched {
					f := core.Finding{

						Module:  m.Name(),
						Details: "TECL: request after smuggled one differs from baseline: " + comp.Details,
						Evidence: "baseline_status=" + fmt.Sprint(rec.Response.StatusCode) +
							", after_status=" + fmt.Sprint(after.StatusCode) +
							", after_delay=" + after.Delay.String() +
							", payload used:\n" + string(attackReq) +
							", endpoint: " + rec.Request.Endpoint,
						Severity: core.SeverityMedium,
					}
					findings = append(findings, f)
					*rec = enrichRecord(*rec, m.Name(), f)
					if ctx.Options.ExitOnFind {
						return findings, nil
					}
				}
			}

		} else {
			log.Printf("[TECL] skipping endpoint %s due to no timeout\n", rec.Request.Endpoint)
		}
	}
	return findings, nil
}
