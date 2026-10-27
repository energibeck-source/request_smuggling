package modules

import (
	"fmt"
	"log"
	"os"
	"time"

	"request_smuggling/core"
	"request_smuggling/payloads"
)

type ZeroCLModule struct {
	Requester *core.SimpleRequester
	Timeout   time.Duration
}

func (m *ZeroCLModule) Name() string { return "ZeroCL" }

func (m *ZeroCLModule) Run(ctx core.ScanContext) ([]core.Finding, error) {
	target := ctx.Target
	var findings []core.Finding

	log.Printf("[ZeroCL] module is running for %s, this one could take some time\n", fmt.Sprintf("%s:%d", target.Host, target.Port))

	for i := range target.Sitemap {
		rec := &target.Sitemap[i]

		if rec.Response.StatusCode == 0 {

			log.Printf("[%s] no baseline for %s, fetching on the fly", m.Name(), rec.Request.Endpoint)
			log.Printf("[debug] request.endpoint: %v", rec.Request.Endpoint)
			resp, dur, err := m.Requester.SendNormal(target, rec.Request.Endpoint)
			rec.Response = core.ParseNormal(resp, dur, err)
			log.Printf("[debug] FULL record: %v\n", rec)
			if rec.Response.StatusCode == 0 {
				log.Printf("[%s] baseline failed for %s: %v", m.Name(), rec.Request.Endpoint, rec.Response.Error)
				continue
			}
		}
		maxAttempts := ctx.Options.MaxRetries
		if maxAttempts < 20 {
			maxAttempts = 20

		}

		causesTimeout := true
		delay := 62 * time.Second

		log.Printf("[0cl probe debug]: %s -> causes timeout: %v, max delay(!attention!): %v", rec.Request.Endpoint, causesTimeout, delay)

		if causesTimeout {

			log.Printf("[%s]: Endpoint %s appears to RESPECT CL due to timeout, trying time-based 0cl technique", m.Name(), rec.Request.Endpoint)
			headers, body := payloads.BuildZeroCLHeadAndBody(*rec, true)

			fmt.Println("=======")
			fmt.Println("Headers: ", string(headers))
			fmt.Println("=======")
			fmt.Println("Body: ", string(body))
			fmt.Println("=======")

			for i := 0; i < maxAttempts; i++ {

				frac := 1.0 - float64(i)*0.005
				if frac < 0.09 {
					break
				}
				pause := time.Duration(float64(delay) * frac)

				log.Printf("[%s] attempt=%d pause=%v(%.0f%% of %v)", m.Name(), i+1, pause, frac*100, delay)

				firstResp, secondResp, firstDur, secondDur, err := m.Requester.SendRawWithDelay(target, headers, body, pause)
				if err != nil {
					log.Printf("[error] timebased %s: error while sending crafted request: %v\n", m.Name(), err)
				}

				first := core.ParseRawResponse(firstResp, firstDur, err)
				first.Body = Truncate(first.Body, 250)
				log.Printf("[time based 0cl debug] fitsr part of crafter response:\n%v\n", first)
				second := core.ParseRawResponse(secondResp, secondDur, err)
				second.Body = Truncate(second.Body, 250)
				log.Printf("[time based 0cl debug] second part of crafter response:\n%v\n", second)

				afterResp, afterDur, err := m.Requester.SendNormal(target, rec.Request.Endpoint)
				if err != nil {
					log.Printf("[error] %s: error while sending following normal request: %v\n", m.Name(), err)
				}
				after := core.ParseNormal(afterResp, afterDur, err)
				log.Printf("[%s debug] normal post-attack response: status_code=%d, content_lenght=%d", m.Name(), after.StatusCode, after.ContentLength)
				comp := core.CompareRequests(rec.Response, after)
				if comp.Matched {
					f := core.Finding{
						Module:  fmt.Sprintf("delay-based %s", m.Name()),
						Details: "normal request after smuggled one differs from baseline: " + comp.Details,
						Evidence: "baseline_status=" + fmt.Sprint(rec.Response.StatusCode) +
							", after_status=" + fmt.Sprint(after.StatusCode) +
							", after_delay=" + after.Delay.String(),
						Severity: core.SeverityMedium,
					}
					findings = append(findings, f)
					*rec = enrichRecord(*rec, m.Name(), f)

					filename := core.ArtifactPath(fmt.Sprintf("0cl_response_%d.txt", i))
					err = os.WriteFile(filename, []byte(after.Body), 0777)
					if err != nil {
						log.Println("Error while creating file, dumping smuggled request in logs")
						log.Println(string(after.Body))
					}

					break
				}

				if ctx.Options.ExitOnFind {
					if len(findings) > 0 {
						return findings, nil
					}
				}
			}

		} else {
			log.Printf("Endpoint %s appears to DISRESPECT CL due to abcense of timeout, trying casual 0cl technique", rec.Request.Endpoint)

			headers, body := payloads.BuildZeroCLHeadAndBody(*rec, false)
			payload := append(headers, body...)

			for i := 0; i < ctx.Options.MaxRetries; i++ {

				_, _, err := m.Requester.SendRaw(target, payload)
				if err != nil {
					log.Printf("[error] %s: error while sending crafted request: %v\n", m.Name(), err)
				}
				afterResp, afterDur, err := m.Requester.SendNormal(target, rec.Request.Endpoint)
				if err != nil {
					log.Printf("[error] %s: error while sending following normal request: %v\n", m.Name(), err)
				}
				after := core.ParseNormal(afterResp, afterDur, err)
				comp := core.CompareRequests(rec.Response, after)
				if comp.Matched {
					f := core.Finding{
						Module:  fmt.Sprintf("casual %s", m.Name()),
						Details: "normal request after smuggled one differs from baseline: " + comp.Details,
						Evidence: "baseline_status=" + fmt.Sprint(rec.Response.StatusCode) +
							", after_status=" + fmt.Sprint(after.StatusCode) +
							", DELAY USED=" + delay.String(),
						Severity: core.SeverityMedium,
					}
					findings = append(findings, f)
					*rec = enrichRecord(*rec, m.Name(), f)

					break
				}

			}

		}
		if ctx.Options.ExitOnFind {
			if len(findings) > 0 {
				return findings, nil
			}
		}
	}
	log.Printf("[%s] module complete, findings: %d", m.Name(), len(findings))
	return findings, nil
}

func (m *ZeroCLModule) sendProbe(ctx core.ScanContext, rec core.Record) (bool, time.Duration) {
	target := ctx.Target
	probe := payloads.BuildZeroCLProbe(rec)

	maxTimeout := 130 * time.Second

	probeNorm := core.ParseRawResponse(m.Requester.SendRawProbe(target, probe, maxTimeout))

	log.Printf("[0cl probe] endpoint: %s; probe = %v", rec.Request.Endpoint, probeNorm)
	return core.CheckTimeout(probeNorm, m.Timeout), probeNorm.Delay
}
