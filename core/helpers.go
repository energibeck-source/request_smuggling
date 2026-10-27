package core

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"request_smuggling/h2raw"
)

func H2Baseline(target Target) (NormalResponse, error) {
	client, err := h2raw.NewTLSInsecureClient(target.Path)
	if err != nil {
		return NormalResponse{}, fmt.Errorf("[debug] h2raw.NewTLSInsecireClient says %s", err)
	}

	conn, err := client.NewConnection(target.Endpoint)
	if err != nil {
		return NormalResponse{}, fmt.Errorf("[debug] h2raw.NewConnection says %s", err)
	}
	defer conn.Close()

	scheme := "https"
	if !target.TLS {
		scheme = "http"
	}

	req := h2raw.NewRequest("GET", scheme, target.Host, target.Path)

	start := time.Now()
	resp, err := client.MakeRequest(conn, req, 1)
	dur := time.Since(start)

	return H2ToNormal(resp, dur, err), nil
}

func H2ToNormal(resp *h2raw.Response, dur time.Duration, err error) NormalResponse {
	if err != nil {
		return NormalResponse{Error: err}
	}

	statusCode := 0
	if resp.Status != "" {
		if code, convErr := strconv.Atoi(resp.Status); convErr == nil {
			statusCode = code
		}
	}

	headers := make(map[string]string)
	for k, vs := range resp.Headers {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}

	body := ""
	if resp.Body != nil {
		body = string(*resp.Body)
	}

	return NormalResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Delay:      dur,
		Body:       Prefix(body, 200),
		Error:      nil,
	}
}

func NewH2Connection(target Target) (*h2raw.Client, *h2raw.H2Conn, error) {
	endpoint := fmt.Sprintf("%s:%d", target.Host, target.Port)
	client, err := h2raw.NewTLSInsecureClient(endpoint)
	if err != nil {
		return nil, nil, err
	}

	conn, err := client.NewConnection(endpoint)
	if err != nil {
		return nil, nil, err
	}

	return client, conn, nil
}

func ParseSitemap(sitemap []string) []string {
	var parsed []string
	duplicates := make(map[string]bool)

	for _, rawUrl := range sitemap {
		url, err := url.Parse(rawUrl)

		if err != nil {
			continue
		}

		var result string

		if url.RawQuery != "" {
			result = fmt.Sprintf("%s?%s", url.Path, url.RawQuery)
		} else {
			result = url.Path
		}

		if !duplicates[result] {
			duplicates[result] = true
			parsed = append(parsed, result)
		}
	}

	return parsed

}

func TestMethods(url string) (map[string]int, map[string]int, []string) {
	defaultMethods := []string{"INVALID", "OPTIONS", "GET", "HEAD", "POST", "TRACE"}

	statusResults := make(map[string]int)
	contentLengthResults := make(map[string]int)
	var allowedMethods []string

	c := http.Client{
		Timeout: 5 * time.Second,
	}

	for _, method := range defaultMethods {
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			statusResults[method] = 0
			contentLengthResults[method] = 0
			continue
		}

		req.Body = io.NopCloser(strings.NewReader("x=1"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := c.Do(req)
		if err != nil {
			statusResults[method] = 0
			contentLengthResults[method] = 0
			continue
		}
		defer resp.Body.Close()

		status := resp.StatusCode
		contentLen := int(resp.ContentLength)

		statusResults[method] = status
		contentLengthResults[method] = contentLen

		if status == 200 {
			allowedMethods = append(allowedMethods, method)
		}

		time.Sleep(200 * time.Millisecond)
	}

	return statusResults, contentLengthResults, allowedMethods
}
func IsFileExists(filePath string) bool {
	_, err := os.Lstat(filePath)
	exists := !os.IsNotExist(err)
	if !exists {
		_, err := exec.LookPath("katana")
		if err == nil {
			return true
		}
	}
	return exists
}

func Prefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func ConvertHeaders(h http.Header) map[string]string {
	result := make(map[string]string)
	for k, v := range h {
		if len(v) > 0 {
			result[k] = v[0]
		}
	}
	return result
}

func ImportFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func AskUserForInput(msg string, a ...any) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(msg)
	input, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal("Error while reading input:", err)
	}

	clearInput := strings.TrimSpace(input)
	if clearInput == "" {
		log.Fatal("Not gonna work without your help")
	}
	fmt.Println("Many thanks")
	return clearInput
}

func JitterDelay(delay time.Duration) time.Duration {
	if delay <= 0 {
		return 0
	}
	jitter := time.Duration(rand.Int63n(int64(delay)))
	return delay + jitter
}

func PaceN(delay time.Duration, n int) {
	if delay <= 0 || n <= 0 {
		return
	}
	for i := 0; i < n; i++ {
		time.Sleep(JitterDelay(delay))
	}
}
