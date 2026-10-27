package core

import (
	"fmt"
	"net/http"
	"time"
)

type Target struct {
	Host         string
	Port         int
	TLS          bool
	Path         string
	ExtraHeaders http.Header
	Endpoint     string
	Sitemap      []Record
}

type Request struct {
	Method    string            `json:"method"`
	Endpoint  string            `json:"endpoint"`
	UserAgent string            `json:"user_agent,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Kind      string
}

type Record struct {
	Request  Request        `json:"request"`
	Response NormalResponse `json:"response"`
	Result   Result         `json:"result,omitempty"`
}

type Result struct {
	Path             string    `json:"path"`
	AllowedMethods   []string  `json:"allowed_methods,omitempty"`
	Findings         []Finding `json:"findings,omitempty"`
	ProtocolVersions []string  `json:"protocol_versions,omitempty"`
	TriedModules     []string  `json:"tried_modules,omitempty"`
	AcceptsBody      *bool     `json:"accepts_body,omitempty"`
}

type NormalResponse struct {
	StatusCode      int               `json:"status_code"`
	Headers         map[string]string `json:"headers"`
	Delay           time.Duration
	ContentLength   int `json:"content_length"`
	Body            string
	Error           error
	LooksCacheble   string
	EvidenceOfCache string
	ContentType     string
}

type Finding struct {
	Module   string
	Details  string
	Evidence string
	Severity Severity
}

type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

type CompareResult struct {
	Matched bool
	Reason  string
	Details string
}

type ScanContext struct {
	Target     Target
	H1Baseline NormalResponse
	H2Baseline *NormalResponse
	Options    Options
}

func (t Target) String() string {
	protocol := "http"
	if t.TLS {
		protocol = "https"
	}
	return fmt.Sprintf("%s://%s:%d", protocol, t.Host, t.Port)
}

type HeaderMap map[string][]string
