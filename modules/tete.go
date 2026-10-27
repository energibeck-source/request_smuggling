package modules

import (
	"fmt"
	"log"
	"time"

	"request_smuggling/core"
	"request_smuggling/payloads"
)

type TETEModule struct {
	Requester *core.SimpleRequester
	Timeout   time.Duration
}

var obfuscations = []struct {
	name   string
	header string
}{
	{"space", "Transfer-Encoding : chunked"},
	{"quoted", "Transfer-Encoding: \"chunked\""},
	{"tab", "Transfer-Encoding\t:\tchunked"},
	{"case", "TrAnSfEr-EnCoDiNg: chunked"},
	{"with_param", "Transfer-Encoding: chunked; boundary=foo"},
	{"identity", "Transfer-Encoding: chunked, identity"},
	{"multiple", "Transfer-Encoding: chunked, foo"},
	{"multiple2", "Transfer-Encoding: foo, chunked"},
	{"xforward", "X-Forwarded-Transfer-Encoding: chunked"},
	{"foldering", "Transfer-Encoding:\n chunked"},
	{"space_start", " Transfer-Encoding: chunked"},
	{"no-hiding", "Transfer-Encoding: chunked"},
}

func (m *TETEModule) Name() string { return "TETE" }

func (m *TETEModule) Run(ctx core.ScanContext) ([]core.Finding, error) {
	target := ctx.Target
	var findings []core.Finding

	log.Println("[TETE] module is running for", target.Host)
	for i := range target.Sitemap {
		rec := &target.Sitemap[i]
		if rec.Response.StatusCode == 0 {
			continue
		}
		for _, obf := range obfuscations {
			request1, request2 := payloads.BuildTETE(*rec, obf.header)

			log.Printf("[TETE] testing obfuscation: %s (%s)", obf.name, obf.header)
			resp1 := core.ParseRawResponse(m.Requester.SendRaw(target, request1))
			causesTimeout1 := core.CheckTimeout(resp1, m.Timeout)

			resp2 := core.ParseRawResponse(m.Requester.SendRaw(target, request2))
			causesTimeout2 := core.CheckTimeout(resp2, m.Timeout)

			comp := core.CompareRequests(resp1, resp2)

			if causesTimeout1 != causesTimeout2 {
				fmt.Println("[TETE]: anomaly detected - different behavior between two variants")

				f := core.Finding{
					Module: m.Name(),
					Details: fmt.Sprintf("TETE details: anomaly with obfuscation '%s' (timeout_diff=%v)",
						obf.name, causesTimeout1 != causesTimeout2),
					Evidence: fmt.Sprintf(
						"Response1 status=%d, timeout=%v\nResponse2 status=%d, timeout=%v",
						resp1.StatusCode, causesTimeout1, resp2.StatusCode, causesTimeout2,
					),
					Severity: core.SeverityMedium,
				}

				*rec = enrichRecord(*rec, m.Name(), f)

				if comp.Matched {
					log.Printf("Difference in responces using %s type of obfuscation: %s", obf.name, comp.Details)
				}
				if ctx.Options.ExitOnFind {
					return []core.Finding{f}, nil
				}
				findings = append(findings, f)

			}
		}
	}

	log.Println("[TETE] finished")
	return findings, nil
}
