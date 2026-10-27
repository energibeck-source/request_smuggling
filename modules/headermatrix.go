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

type HeaderMatrixModule struct {
	Requester     *core.SimpleRequester
	Timeout       time.Duration
	AttackHeaders []string
}

func (m *HeaderMatrixModule) Name() string { return "HeaderMatrix" }

func reflectionOracle(resp core.NormalResponse, marker string) (bool, string) {
	for k, v := range resp.Headers {
		if strings.Contains(v, marker) {
			return true, "header " + k
		}
	}
	if strings.Contains(resp.Body, marker) {
		return true, "body"
	}
	return false, ""
}

func (m *HeaderMatrixModule) Run(ctx core.ScanContext) ([]core.Finding, error) {
	target := ctx.Target
	var findings []core.Finding

	attackHeaders := m.AttackHeaders
	if len(attackHeaders) == 0 {
		attackHeaders = []string{"Host", "X-Forwarded-Host"}
	}

	log.Println("[HeaderMatrix] module is running for", target.Host)

	for i := range target.Sitemap {
		rec := &target.Sitemap[i]
		if rec.Response.StatusCode == 0 {
			continue
		}

		for _, ah := range attackHeaders {
			for _, mut := range payloads.HeaderMutations {
				marker := fmt.Sprintf("hdr-oracle-%d.probe", rand.Int63())
				probe := payloads.BuildHeaderMatrixProbe(*rec, mut, ah, marker)
				resp := core.ParseRawResponse(m.Requester.SendRaw(target, probe))

				hit, where := reflectionOracle(resp, marker)

				if mut.Name == "canonical" {
					if hit {
						log.Printf("[HeaderMatrix] baseline: %s echoed canonically in %s for %s", ah, where, rec.Request.Endpoint)
					}
					continue
				}

				if hit {
					sev := core.SeverityMedium
					if strings.HasPrefix(where, "header") {
						sev = core.SeverityHigh
					}
					f := core.Finding{
						Module: m.Name(),
						Details: fmt.Sprintf(
							"HeaderMatrix: obfuscated %q header (mutation %q) was honored — marker reflected in %s",
							ah, mut.Name, where),
						Evidence: "endpoint=" + rec.Request.Endpoint +
							", attack_header=" + ah +
							", mutation=" + mut.Name +
							", reflected_in=" + where +
							", payload used:\n" + string(probe),
						Severity: sev,
					}
					findings = append(findings, f)
					*rec = enrichRecord(*rec, m.Name(), f)
					if ctx.Options.ExitOnFind {
						return findings, nil
					}
				}

			}
		}
	}

	log.Printf("[HeaderMatrix] module complete, findings: %d", len(findings))
	return findings, nil
}
