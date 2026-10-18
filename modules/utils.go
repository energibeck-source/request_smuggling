package modules

import (
	"request_smuggling/core"
	"request_smuggling/h2raw"

	"fmt"
	"log"
	"net/url"
	"time"
)

func sendH2Probe(moduleName string, target core.Target, req *h2raw.Request, timeout time.Duration) (*core.Finding, error) {

	client, conn, err := core.NewH2Connection(target)
	if err != nil {
		return nil, fmt.Errorf("[debug] func sendH2Probe got err from core.NewH2Connection: %s", err)
	}
	defer conn.Close()

	start := time.Now()
	probeResp, probeErr := client.MakeRequest(conn, req, 1)
	probeDur := time.Since(start)

	probe := core.H2ToNormal(probeResp, probeDur, probeErr)

	if core.CheckTimeout(probe, timeout) {
		f := &core.Finding{
			Module:   moduleName,
			Details:  "Probe request caused timeout",
			Severity: core.SeverityMedium,
		}
		return f, nil
	}
	return nil, nil
}

func sendSmuggledAndGetResp(r *core.SimpleRequester, target core.Target, attackReq []byte, opts core.Options, mName string, url string) (core.NormalResponse, error) {
	var after core.NormalResponse
	_, _, err := r.SendRaw(target, attackReq)

	if err != nil {
		log.Printf("[%s] error sending smuggled request: %v\n", mName, err)
	}

	afterResp, afterDur, err := r.SendNormal(target, url)
	if err != nil {
		log.Println("[TECL] error while sending post-attack normal request:", err)

	}

	after = core.ParseNormal(afterResp, afterDur, err)

	return after, nil
}

func enrichRecord(rec core.Record, mName string, f core.Finding) core.Record {

	if rec.Result.TriedModules == nil {
		rec.Result.TriedModules = []string{}
	}
	if rec.Result.Findings == nil {
		rec.Result.Findings = []core.Finding{}
	}

	alreadyTried := false
	for _, m := range rec.Result.TriedModules {
		if m == mName {
			alreadyTried = true
			break
		}
	}

	if !alreadyTried {
		rec.Result.TriedModules = append(rec.Result.TriedModules, mName)
	}
	u, _ := url.Parse(rec.Request.Endpoint)
	rec.Result.Path = u.Path

	alreadyFound := false
	for _, existing := range rec.Result.Findings {
		if existing.Details == f.Details && existing.Module == f.Module {
			alreadyFound = true
			break
		}
	}
	if !alreadyFound {
		rec.Result.Findings = append(rec.Result.Findings, f)
	}
	return rec
}

func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func TruncateBytes(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + fmt.Sprintf("... [truncated, total %d bytes]", len(b))
}
