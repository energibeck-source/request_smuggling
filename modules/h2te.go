package modules

import (
	"log"
	"net/url"
	"time"

	"request_smuggling/core"
	"request_smuggling/h2raw"
)

type H2TEModule struct {
	Timeout time.Duration
}

func (m *H2TEModule) Name() string { return "H2TE" }

func (m *H2TEModule) Run(ctx core.ScanContext) ([]core.Finding, error) {
	log.Printf("[H2TE] === START ===")

	target := ctx.Target

	var (
		base     core.NormalResponse
		findings []core.Finding
	)

	if ctx.H2Baseline != nil && ctx.H2Baseline.StatusCode > 0 {
		base = *ctx.H2Baseline
		log.Printf("[H2TE] baseline from context: %d", base.StatusCode)
	} else {
		var err error
		base, err = core.H2Baseline(target)
		if err != nil || base.StatusCode == 0 {
			return nil, nil
		}
		log.Printf("[H2TE] made own baseline: %d", base.StatusCode)
	}

	scheme := "https"
	if !target.TLS {
		scheme = "http"
	}

	for i := range target.Sitemap {
		rec := &target.Sitemap[i]
		if rec.Response.StatusCode == 0 {
			continue
		}
		u, _ := url.Parse(rec.Request.Endpoint)
		rec.Result.TriedModules = append(rec.Result.TriedModules, m.Name())
		req := h2raw.NewRequest("POST", scheme, u.Host, u.Path)

		for k, vs := range target.ExtraHeaders {
			for _, v := range vs {
				req.AddHeader(k, v)
			}
		}
		req.AddHeader("transfer-encoding", "chunked")
		result, probeErr := sendH2Probe(m.Name(), target, req, m.Timeout)

		if probeErr != nil {
			log.Printf("Error while sending probe request: %v", probeErr)
			continue
		}

		if result != nil {
			log.Printf("[%s] looks like h2 request containing TE header causes timeout for endpoint %s\n", m.Name(), u.Path)

			*rec = enrichRecord(*rec, m.Name(), *result)
			findings = append(findings, *result)

			if ctx.Options.ExitOnFind {
				return findings, nil
			}
		}
		delay := ctx.Options.RateInterval
		core.PaceN(delay, 1)
	}

	log.Printf("[H2TE] finished, findings: %d\n", len(findings))
	return findings, nil
}
