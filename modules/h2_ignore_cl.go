package modules

import (
	"fmt"
	"log"
	"net/url"
	"time"

	"request_smuggling/core"
	"request_smuggling/h2raw"
)

type H2CL_ignoreModule struct {
	Timeout time.Duration
}

func (m *H2CL_ignoreModule) Name() string { return "H2_ignoreCL" }

func (m *H2CL_ignoreModule) Run(ctx core.ScanContext) ([]core.Finding, error) {
	target := ctx.Target
	delay := ctx.Options.RateInterval
	if ctx.H2Baseline == nil || ctx.H2Baseline.Error != nil {
		log.Printf("[H2_ignoreCL] skipping: no valid H2 baseline")
		return nil, fmt.Errorf("[h2cl] no baseline\n")
	}

	scheme := "https"
	if !target.TLS {
		scheme = "http"
	}

	var findings []core.Finding
	for i := range target.Sitemap {
		rec := &target.Sitemap[i]
		if rec.Response.StatusCode == 0 {
			continue
		}
		u, _ := url.Parse(rec.Request.Endpoint)
		core.LogVerbose("[%s] sending probe to imported path from sitemap: %s\n", m.Name(), u.Path)

		req := h2raw.NewRequest("POST", scheme, u.Host, u.Path)

		for k, vs := range target.ExtraHeaders {
			for _, v := range vs {
				req.AddHeader(k, v)
			}
		}
		req.AddHeader("content-length", "5")
		body := []byte("x=1")
		req.Body = &body

		result, probeErr := sendH2Probe(m.Name(), target, req, m.Timeout)

		if probeErr != nil {
			log.Printf("Error while sending probe request, pay attention, error skipped! : %v", probeErr)
			continue
		}

		if result == nil {
			f := core.Finding{
				Module:   m.Name(),
				Details:  fmt.Sprintf("Probe request DIDNT cause timeout on endpoint %s", rec.Request.Endpoint),
				Severity: core.SeverityMedium,
			}
			findings = append(findings, f)
			*rec = enrichRecord(*rec, m.Name(), f)
		}
		if ctx.Options.ExitOnFind {
			break
		} else {
			core.PaceN(delay, 1)
		}
	}

	return findings, nil
}
