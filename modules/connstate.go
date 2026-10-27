package modules

import (
	"fmt"
	"log"
	"time"

	"request_smuggling/core"
	"request_smuggling/payloads"
)

type ConnStateModule struct {
	Requester *core.SimpleRequester
	Timeout   time.Duration
	AltHost   string
}

func (m *ConnStateModule) Name() string { return "ConnState" }

func (m *ConnStateModule) Run(ctx core.ScanContext) ([]core.Finding, error) {
	target := ctx.Target
	var findings []core.Finding

	altHost := m.AltHost
	if altHost == "" {
		altHost = "connection-state-probe.invalid"
	}

	log.Println("[ConnState] module is running for", target.Host)

	for i := range target.Sitemap {
		rec := &target.Sitemap[i]
		if rec.Response.StatusCode == 0 {
			continue
		}

		probe := payloads.BuildHostProbe(*rec, altHost)
		prime := payloads.BuildNormalGet(*rec)

		aloneRaw, aloneDur, aloneErr := m.Requester.SendRaw(target, probe)
		alone := core.ParseRawResponse(aloneRaw, aloneDur, aloneErr)
		if alone.StatusCode == 0 {
			log.Printf("[ConnState] no standalone response for %s, skipping", rec.Request.Endpoint)
			continue
		}

		resps, err := m.Requester.SendRawPipelined(target, [][]byte{prime, probe}, 0)
		if err != nil || len(resps) < 2 {
			log.Printf("[ConnState] primed send for %s: err=%v responses=%d", rec.Request.Endpoint, err, len(resps))
			continue
		}
		primed := resps[1]
		if primed.StatusCode == 0 {
			continue
		}

		if alone.StatusCode != primed.StatusCode {
			sev := core.SeverityMedium
			if alone.StatusCode >= 400 && primed.StatusCode != alone.StatusCode {
				sev = core.SeverityHigh
			}
			f := core.Finding{
				Module: m.Name(),
				Details: fmt.Sprintf(
					"ConnState: probe with Host %q behaves differently as 1st vs 2nd request on a connection — front-end validates/routes only the first request",
					altHost),
				Evidence: "endpoint=" + rec.Request.Endpoint +
					", standalone_status=" + fmt.Sprint(alone.StatusCode) +
					", primed_2nd_status=" + fmt.Sprint(primed.StatusCode) +
					", alt_host=" + altHost,
				Severity: sev,
			}
			findings = append(findings, f)
			*rec = enrichRecord(*rec, m.Name(), f)
			if ctx.Options.ExitOnFind {
				return findings, nil
			}
		}

	}

	log.Printf("[ConnState] module complete, findings: %d", len(findings))
	return findings, nil
}
