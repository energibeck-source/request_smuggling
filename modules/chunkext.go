package modules

import (
	"log"
	"time"

	"request_smuggling/core"
	"request_smuggling/payloads"
)

type ChunkExtModule struct {
	Requester *core.SimpleRequester
	Timeout   time.Duration
}

func (m *ChunkExtModule) Name() string { return "ChunkExt" }

func (m *ChunkExtModule) Run(ctx core.ScanContext) ([]core.Finding, error) {
	target := ctx.Target
	var findings []core.Finding

	hardLimit := m.Timeout + 5*time.Second

	log.Println("[ChunkExt] module is running for", target.Host)

	orientations := []struct {
		name    string
		build   func(core.Record) []byte
		details string
	}{
		{"TERM.EXT", payloads.BuildChunkExtTermExt,
			"ChunkExt TERM.EXT: bare-LF chunk extension strands the connection — proxy terminates the size-line at LF, back-end folds it into the extension"},
		{"EXT.TERM", payloads.BuildChunkExtExtTerm,
			"ChunkExt EXT.TERM: bare-LF chunk extension strands the connection — proxy folds the LF into the extension, back-end terminates the size-line at LF"},
	}

	for i := range target.Sitemap {
		rec := &target.Sitemap[i]
		if rec.Response.StatusCode == 0 {
			continue
		}

		for _, o := range orientations {
			probe := o.build(*rec)
			norm := core.ParseRawResponse(m.Requester.SendRawProbe(target, probe, hardLimit))

			if core.CheckTimeout(norm, m.Timeout) {
				f := core.Finding{
					Module:   m.Name(),
					Details:  o.details,
					Evidence: "endpoint=" + rec.Request.Endpoint + ", orientation=" + o.name + ", probe_delay=" + norm.Delay.String() + ", payload used:\n" + string(probe),
					Severity: core.SeverityMedium,
				}
				findings = append(findings, f)
				*rec = enrichRecord(*rec, m.Name(), f)
				if ctx.Options.ExitOnFind {
					return findings, nil
				}
			}

		}
	}

	log.Printf("[ChunkExt] module complete, findings: %d", len(findings))
	return findings, nil
}
