package modules

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"request_smuggling/core"
	"request_smuggling/payloads"
)

type CLZeroModule struct {
	Requester *core.SimpleRequester
	Timeout   time.Duration
}

func (m *CLZeroModule) Name() string { return "CL.0" }

func (m *CLZeroModule) Run(ctx core.ScanContext) ([]core.Finding, error) {
	target := ctx.Target
	var findings []core.Finding

	log.Println("[CL.0] module is running for", target.Host)

	attempts := ctx.Options.MaxRetries
	if attempts < 2 {
		attempts = 2
	}

	for i := range target.Sitemap {
		rec := &target.Sitemap[i]
		if rec.Response.StatusCode == 0 {
			continue
		}

		marker := fmt.Sprintf("cl0probe%d", rand.Int63())
		poison := payloads.BuildCLZero(*rec, marker)
		normal := payloads.BuildNormalGet(*rec)

		for attempt := 0; attempt < attempts; attempt++ {
			resps, err := m.Requester.SendRawPipelined(target, [][]byte{poison, normal}, 0)
			if err != nil {
				log.Printf("[CL.0] pipelined send error for %s: %v", rec.Request.Endpoint, err)
				continue
			}

			statuses := make([]string, 0, len(resps))
			for _, r := range resps {
				if r.Error != nil {
					statuses = append(statuses, "err:"+r.Error.Error())
				} else {
					statuses = append(statuses, fmt.Sprint(r.StatusCode))
				}
			}

			if len(resps) > 2 {
				f := core.Finding{
					Module: m.Name(),
					Details: fmt.Sprintf(
						"CL.0: sent 2 requests, got %d responses on one connection — back-end ignores Content-Length AND a complete request leaked into the queue (WARNING: queue was poisoned, re-check target health)",
						len(resps)),
					Evidence: "endpoint=" + rec.Request.Endpoint +
						", response_statuses=[" + strings.Join(statuses, ",") + "]" +
						", marker=/" + marker +
						", payload used:\n" + string(poison),
					Severity: core.SeverityHigh,
				}
				findings = append(findings, f)
				*rec = enrichRecord(*rec, m.Name(), f)
				if ctx.Options.ExitOnFind {
					return findings, nil
				}
				break
			}

			if len(resps) == 2 {
				last := resps[len(resps)-1]
				comp := core.CompareRequests(rec.Response, last)
				if comp.Matched {
					f := core.Finding{
						Module:  m.Name(),
						Details: "CL.0: trailing request after poison was rewritten (differs from baseline): " + comp.Details,
						Evidence: "endpoint=" + rec.Request.Endpoint +
							", response_statuses=[" + strings.Join(statuses, ",") + "]" +
							", baseline_status=" + fmt.Sprint(rec.Response.StatusCode) +
							", marker=/" + marker,
						Severity: core.SeverityMedium,
					}
					findings = append(findings, f)
					*rec = enrichRecord(*rec, m.Name(), f)
					if ctx.Options.ExitOnFind {
						return findings, nil
					}
					break
				}
			}

		}
	}

	log.Printf("[CL.0] module complete, findings: %d", len(findings))
	return findings, nil
}
