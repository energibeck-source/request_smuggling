package modules

import (
	"fmt"
	"log"
	"math/rand"
	"net/url"
	"time"

	"request_smuggling/core"
	"request_smuggling/h2raw"
	"request_smuggling/payloads"
)

type H2ZeroModule struct {
	Timeout time.Duration
}

func (m *H2ZeroModule) Name() string { return "H2.0" }

func (m *H2ZeroModule) Run(ctx core.ScanContext) ([]core.Finding, error) {
	target := ctx.Target
	delay := ctx.Options.RateInterval
	var findings []core.Finding

	if !target.TLS {
		log.Printf("[H2.0] skipping: HTTP/2 probe needs TLS target")
		return nil, nil
	}

	scheme := "https"
	log.Println("[H2.0] module is running for", target.Host)

	attempts := ctx.Options.MaxRetries
	if attempts < 2 {
		attempts = 2
	}

	for i := range target.Sitemap {
		rec := &target.Sitemap[i]
		if rec.Response.StatusCode == 0 {
			continue
		}
		u, _ := url.Parse(rec.Request.Endpoint)
		path := u.Path
		if path == "" {
			path = "/"
		}

		for attempt := 0; attempt < attempts; attempt++ {
			finding, done := m.probe(ctx, rec, scheme, u.Host, path)
			if finding != nil {
				findings = append(findings, *finding)
				*rec = enrichRecord(*rec, m.Name(), *finding)
				if ctx.Options.ExitOnFind {
					return findings, nil
				}
				break
			}
			_ = done
			core.PaceN(delay, 2)
		}
	}

	log.Printf("[H2.0] module complete, findings: %d", len(findings))
	return findings, nil
}

func (m *H2ZeroModule) probe(ctx core.ScanContext, rec *core.Record, scheme, authority, path string) (*core.Finding, bool) {
	target := ctx.Target

	client, conn, err := core.NewH2Connection(target)
	if err != nil {
		log.Printf("[H2.0] h2 connect error for %s: %v", rec.Request.Endpoint, err)
		return nil, false
	}
	defer conn.Close()

	marker := fmt.Sprintf("h20probe%d", rand.Int63())
	frag := payloads.BuildSmuggledFragment(marker)

	poison := h2raw.NewRequest("POST", scheme, authority, path)
	poison.AddHeader("content-length", fmt.Sprint(len(frag)))
	body := append([]byte(nil), frag...)
	poison.Body = &body

	normal := h2raw.NewRequest("GET", scheme, authority, path)

	if err := client.WriteRequest(conn, poison, 1); err != nil {
		log.Printf("[H2.0] write stream 1 error: %v", err)
		return nil, false
	}
	if err := client.WriteRequest(conn, normal, 3); err != nil {
		log.Printf("[H2.0] write stream 3 error: %v", err)
		return nil, false
	}

	resps, errs, _ := client.DrainResponses(conn, []uint32{1, 3}, m.Timeout)

	r3, has3 := resps[3]
	err3 := errs[3]
	goaway := errs[0]

	if !has3 || err3 != nil || goaway != nil {
		reason := "stream 3 got no response before deadline"
		if err3 != nil {
			reason = "stream 3 reset: " + err3.Error()
		} else if goaway != nil {
			reason = "connection GOAWAY: " + goaway.Error()
		}
		return &core.Finding{
			Module:   m.Name(),
			Details:  "H2.0: trailing stream consumed/reset after h2 downgrade — back-end ignores content-length: " + reason,
			Evidence: "endpoint=" + rec.Request.Endpoint + ", marker=/" + marker + ", stream1_present=" + fmt.Sprint(resps[1] != nil),
			Severity: core.SeverityHigh,
		}, true
	}

	after := core.H2ToNormal(r3, 0, nil)
	if after.StatusCode != 0 && after.StatusCode != rec.Response.StatusCode {
		return &core.Finding{
			Module:   m.Name(),
			Details:  fmt.Sprintf("H2.0: trailing stream status diverges from baseline (possible rewrite): %d -> %d", rec.Response.StatusCode, after.StatusCode),
			Evidence: "endpoint=" + rec.Request.Endpoint + ", marker=/" + marker + ", stream3_status=" + r3.Status + ", baseline_status=" + fmt.Sprint(rec.Response.StatusCode),
			Severity: core.SeverityMedium,
		}, true
	}

	return nil, false
}
