package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

type tmpRequest struct {
	Method    string `json:"method"`
	Endpoint  string `json:"endpoint"`
	Raw       string `json:"raw"`
	Tag       string `json:"tag,omitempty"`
	Attribute string `json:"attribute,omitempty"`
	Source    string `json:"source,omitempty"`
}

type tmpResponse struct {
	StatusCode    int               `json:"status_code"`
	Headers       map[string]string `json:"headers"`
	ContentLength int               `json:"content_length"`
	Raw           string            `json:"raw"`
}

func createSitemap(fileName string) ([]Record, error) {

	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var sitemap []Record
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		rec, err := analyzeLine(line)
		if err != nil {
			log.Printf("error durin analyzing line %s\n%v\n", line, err)
			continue
		}
		sitemap = append(sitemap, rec)
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[katana]: found %d endpoints:\n", len(sitemap))
	return sitemap, nil
}

func analyzeLine(line string) (Record, error) {
	if !json.Valid([]byte(line)) {
		return Record{}, fmt.Errorf("Skipping invalid JSON line: %s...\n", line[:min(len(line), 30)])
	}

	var tmp struct {
		Request  tmpRequest  `json:"request"`
		Response tmpResponse `json:"response"`
	}

	if err := json.Unmarshal([]byte(line), &tmp); err != nil {
		return Record{}, fmt.Errorf("JSON error: %v\n", err)
	}

	res, evidence := isCacheable(tmp.Response.Headers)

	var cacheble string
	if res == nil {
		cacheble = "maybe"
	} else if *res {
		cacheble = "yes"
	} else {
		cacheble = "no"
	}
	httpVersion := extractHTTPVersion(tmp.Response.Raw)
	rec := Record{
		Request: Request{
			Method:    tmp.Request.Method,
			Endpoint:  tmp.Request.Endpoint,
			UserAgent: extractUserAgent(tmp.Request.Raw),
			Kind:      determineClass(tmp.Request),
		},
		Response: NormalResponse{
			StatusCode:      tmp.Response.StatusCode,
			Headers:         tmp.Response.Headers,
			ContentLength:   tmp.Response.ContentLength,
			ContentType:     tmp.Response.Headers["Content-Type"],
			LooksCacheble:   cacheble,
			EvidenceOfCache: evidence,
		},
		Result: Result{
			ProtocolVersions: []string{httpVersion},
		},
	}
	return rec, nil
}

func determineClass(req tmpRequest) string {

	u, err := url.Parse(req.Endpoint)
	if err != nil {
		return "url error"
	}

	if req.Tag == "header" && req.Attribute == "location" {
		return "redirect"
	}

	path := strings.ToLower(u.Path)

	apiPaths := []string{
		"/api/", "/v1/", "/v2/", "/v3/", "/v4/",
		"/rest/", "/rpc/", "/jsonrpc", "/oauth/",
		"/openapi", "/graphql", "/swagger", "/docs",
	}

	for _, seg := range apiPaths {
		if strings.Contains(path, seg) {
			return "api"
		}
	}

	if strings.Contains(path, ".") {
		return "static"
	}

	return "normal"
}

func isCacheable(headers map[string]string) (*bool, string) {

	if cacheControl, ok := headers["Cache-Control"]; ok {
		parts := strings.Split(cacheControl, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.EqualFold(part, "no-store") || strings.EqualFold(part, "no-cache") {
				val := false
				return &val, fmt.Sprintf("%s: %s", cacheControl, part)
			}
		}
	}

	var hasCacheIndicator bool
	var ev string
	cacheHeaders := []string{"X-Cache", "ETag", "Vary", "Last-Modified", "Expires", "Cache-Control", "Age"}

	for _, h := range cacheHeaders {
		if _, ok := headers[h]; ok {
			hasCacheIndicator = true
			ev = h
			break
		}
	}

	if !hasCacheIndicator {
		return nil, ev
	}

	if xCache, ok := headers["X-Cache"]; ok {
		if strings.EqualFold(xCache, "HIT") || strings.EqualFold(xCache, "MISS") {
			val := true
			return &val, fmt.Sprintf("%s: HIT/MISS", xCache)
		}
	}

	if cacheControl, ok := headers["Cache-Control"]; ok {
		parts := strings.Split(cacheControl, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.EqualFold(part, "public") {
				val := true
				return &val, fmt.Sprintf("%s: HIT/MISS (public)", cacheControl)
			}
			if strings.HasPrefix(part, "max-age=") {
				val := true
				return &val, fmt.Sprintf("%s: HIT/MISS (max-age)", cacheControl)
			}
		}
	}

	if _, ok := headers["ETag"]; ok {
		val := true
		return &val, "ETag"
	}
	if _, ok := headers["Last-Modified"]; ok {
		val := true
		return &val, "Last-Modified"
	}

	if _, ok := headers["Age"]; ok {
		val := true
		return &val, "Age"
	}

	return nil, "maybe next time"
}

func extractUserAgent(raw string) string {
	lines := strings.Split(raw, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "user-agent:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
}

func extractHTTPVersion(raw string) string {
	if raw == "" {
		return ""
	}
	lines := strings.Split(raw, "\r\n")
	if len(lines) == 0 {
		return ""
	}
	statusLine := lines[0]
	parts := strings.Fields(statusLine)
	if len(parts) < 1 {
		return ""
	}

	return strings.ToLower(parts[0])
}

func runKatana(url string, rl string) (string, error) {

	_, err := exec.LookPath("katana")
	if err != nil {
		return "", fmt.Errorf("katana appears to not being installed")
	}
	log.Println("katana executable was found, running it...")
	sitemapPath := ArtifactPath("sitemap.jsonl")
	cmd := exec.Command(
		"katana",
		"-u", url,
		"-kf", "all",
		"-ignore-query-params",
		"-filter-similar",
		"-tlsi",
		"-js-crawl",
		"-silent",
		"-j",
		"-o", sitemapPath,
		"-ob",
		"-fs", "fqdn",
		"-rl", rl,
	)
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		return "", err
	}
	log.Println("Sitemap saved in " + sitemapPath)
	return sitemapPath, nil
}

func SaveSitemap(sitemap []Record, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sitemap)
}

func fallbackSitemap(rawURL string) []Record {
	return []Record{
		{
			Request: Request{
				Endpoint: rawURL,
				Method:   "GET",
			},
		},
	}
}
