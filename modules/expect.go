package modules

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"request_smuggling/core"
	"request_smuggling/payloads"
)

type ExpectModule struct {
	Requester *core.SimpleRequester
	Timeout   time.Duration
	Pause     time.Duration
}

func (m *ExpectModule) Name() string { return "Expect" }

func classifyPreBody(raw []byte) (has100 bool, early int) {
	s := string(raw)
	for i := 0; ; {
		idx := strings.Index(s[i:], "HTTP/1.1 ")
		if idx < 0 {
			break
		}
		p := i + idx + len("HTTP/1.1 ")
		if p+3 > len(s) {
			break
		}
		code, err := strconv.Atoi(strings.TrimSpace(s[p : p+3]))
		i = p
		if err != nil {
			continue
		}
		if code == 100 {
			has100 = true
		} else if code >= 200 && early == 0 {
			early = code
		}
	}
	return has100, early
}

func (m *ExpectModule) runVariant(target core.Target, rec core.Record, v payloads.ExpectVariant, pause time.Duration) (bool, int) {
	headers, body := payloads.BuildExpectHeadersAndBody(rec, v)
	first, _, _, _, _ := m.Requester.SendRawWithDelay(target, headers, body, pause)
	return classifyPreBody(first)
}

func (m *ExpectModule) Run(ctx core.ScanContext) ([]core.Finding, error) {
	target := ctx.Target
	pause := m.Pause
	if pause <= 0 {
		pause = 2 * time.Second
	}
	var findings []core.Finding

	log.Println("[Expect] module is running for", target.Host)

	for i := range target.Sitemap {
		rec := &target.Sitemap[i]
		if rec.Response.StatusCode == 0 {
			continue
		}

		bHas100, bEarly := m.runVariant(target, *rec, payloads.ExpectNone, pause)
		pHas100, pEarly := m.runVariant(target, *rec, payloads.ExpectPlain, pause)
		oHas100, oEarly := m.runVariant(target, *rec, payloads.ExpectObfuscated, pause)

		evBase := fmt.Sprintf("baseline{100:%v,early:%d} plain{100:%v,early:%d} obf{100:%v,early:%d}",
			bHas100, bEarly, pHas100, pEarly, oHas100, oEarly)

		var f *core.Finding

		switch {
		case (pHas100 && pEarly >= 200) || (oHas100 && oEarly >= 200):
			f = &core.Finding{
				Module:   m.Name(),
				Details:  "Expect: second response-header block before body (100-continue + final) — proxy header-stripping bypass primitive",
				Evidence: "endpoint=" + rec.Request.Endpoint + ", " + evBase,
				Severity: core.SeverityHigh,
			}

		case pEarly >= 200 && bEarly == 0:
			f = &core.Finding{
				Module:   m.Name(),
				Details:  fmt.Sprintf("Expect: server sent a final %d response before the body (early-response gadget; pairs with 0.CL)", pEarly),
				Evidence: "endpoint=" + rec.Request.Endpoint + ", " + evBase,
				Severity: core.SeverityMedium,
			}

		case oHas100 != pHas100 || (oEarly == 0) != (pEarly == 0):
			f = &core.Finding{
				Module:   m.Name(),
				Details:  "Expect: obfuscated Expect header handled differently from plain — front/back parser disagreement",
				Evidence: "endpoint=" + rec.Request.Endpoint + ", " + evBase,
				Severity: core.SeverityMedium,
			}
		}

		if f != nil {
			findings = append(findings, *f)
			*rec = enrichRecord(*rec, m.Name(), *f)
			if ctx.Options.ExitOnFind {
				return findings, nil
			}
		}

	}

	log.Printf("[Expect] module complete, findings: %d", len(findings))
	return findings, nil
}
