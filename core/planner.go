package core

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type Fingerprint struct {
	Protocols  string
	StatusKind int
	Server     string
	ViaProxy   bool

	Redirects   bool
	AcceptsBody bool
	RespChunked bool
	AuthGated   bool
}

func (f Fingerprint) Key() string {
	return fmt.Sprintf("p=%s|s=%d|srv=%s|proxy=%v|redir=%v|body=%v|chunked=%v|auth=%v",
		f.Protocols, f.StatusKind, f.Server, f.ViaProxy,
		f.Redirects, f.AcceptsBody, f.RespChunked, f.AuthGated)
}

func FingerprintOf(rec Record) Fingerprint {
	protos := append([]string(nil), rec.Result.ProtocolVersions...)
	sort.Strings(protos)

	hdr := rec.Response.Headers
	server, via, redir, chunked := "", false, false, false
	if hdr != nil {
		server = strings.ToLower(hdr["Server"])
		if hdr["Via"] != "" || hdr["X-Cache"] != "" || hdr["X-Cache-Hits"] != "" {
			via = true
		}
		if hdr["Location"] != "" {
			redir = true
		}
		if strings.Contains(strings.ToLower(hdr["Transfer-Encoding"]), "chunked") {
			chunked = true
		}
	}

	status := rec.Response.StatusCode
	if status >= 300 && status < 400 {
		redir = true
	}

	return Fingerprint{
		Protocols:   strings.Join(protos, ","),
		StatusKind:  status / 100,
		Server:      server,
		ViaProxy:    via,
		Redirects:   redir,
		AcceptsBody: acceptsBody(rec),
		RespChunked: chunked,
		AuthGated:   status == 401 || status == 403,
	}
}

func speaksH2(rec Record) bool {
	for _, v := range rec.Result.ProtocolVersions {
		if v == "http/2" || v == "h2c" {
			return true
		}
	}
	return false
}

func acceptsBody(rec Record) bool {
	if rec.Result.AcceptsBody != nil {
		return *rec.Result.AcceptsBody
	}
	if len(rec.Result.AllowedMethods) == 0 {
		return true
	}
	for _, m := range rec.Result.AllowedMethods {
		switch strings.ToUpper(m) {
		case "POST", "PUT", "PATCH", "OPTIONS":
			return true
		}
	}
	return false
}

func MeasureBodyAcceptance(r *SimpleRequester, target Target, rec *Record) {
	path, host, ua := recPathHostUA(*rec)
	body := "x=1"
	probe := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"%s",
		path, host, ua, len(body), body,
	)
	resp := ParseRawResponse(r.SendRaw(target, []byte(probe)))
	if resp.Error != nil || resp.StatusCode == 0 {
		return
	}
	accepted := resp.StatusCode != 405 && resp.StatusCode != 501
	rec.Result.AcceptsBody = &accepted
}

func recPathHostUA(rec Record) (string, string, string) {
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

type Requirement struct {
	NeedH2        bool
	NeedBody      bool
	NeedKeepAlive bool
}

func (r Requirement) SatisfiedBy(rec Record) bool {
	if rec.Response.StatusCode == 0 {
		return false
	}
	if r.NeedH2 && !speaksH2(rec) {
		return false
	}
	if r.NeedBody && !acceptsBody(rec) {
		return false
	}
	return true
}

type TestSpec struct {
	Module            string
	Tier              int
	Req               Requirement
	ProbesPerEndpoint int
}

func DefaultTestSpecs() []TestSpec {
	body := Requirement{NeedBody: true}
	h2 := Requirement{NeedH2: true}
	return []TestSpec{
		{"connstate", 0, Requirement{NeedKeepAlive: true}, 2},
		{"clte", 0, body, 3},
		{"tecl", 0, body, 3},
		{"cl0", 0, body, 3},
		{"te0", 0, body, 3},
		{"chunkext", 0, body, 2},
		{"tete", 1, body, 4},
		{"0cl", 1, body, 20},
		{"expect", 1, body, 6},
		{"h2te", 1, h2, 4},
		{"h2cl_ignore", 1, h2, 4},
		{"h20", 1, h2, 4},
		{"headermatrix", 1, Requirement{}, 16},
	}
}

type Cluster struct {
	Key            string
	Fingerprint    Fingerprint
	Representative Record
	Members        []Record
}

func ClusterEndpoints(sitemap []Record) []Cluster {
	index := make(map[string]int)
	var clusters []Cluster
	for _, rec := range sitemap {
		if rec.Response.StatusCode == 0 {
			continue
		}
		fp := FingerprintOf(rec)
		key := fp.Key()
		if i, ok := index[key]; ok {
			clusters[i].Members = append(clusters[i].Members, rec)
			continue
		}
		index[key] = len(clusters)
		clusters = append(clusters, Cluster{
			Key:            key,
			Fingerprint:    fp,
			Representative: rec,
			Members:        []Record{rec},
		})
	}
	return clusters
}

type WorkItem struct {
	Module    string
	Tier      int
	Targets   []Record
	EstProbes int
}

type SkipNote struct {
	Module  string
	Cluster string
	Reason  string
}

type Plan struct {
	Items       []WorkItem
	Skipped     []SkipNote
	Clusters    []Cluster
	SpentProbes int
	Budget      int
}

type Planner struct {
	Specs            []TestSpec
	Budget           int
	SamplePerCluster int
}

func NewPlanner(budget int) Planner {
	return Planner{Specs: DefaultTestSpecs(), Budget: budget, SamplePerCluster: 1}
}

func (p Planner) reps(c Cluster) []Record {
	k := p.SamplePerCluster
	if k <= 0 {
		k = 1
	}
	ordered := make([]Record, 0, len(c.Members))
	var front, back []Record
	for _, m := range c.Members {
		if m.Response.StatusCode >= 300 && m.Response.StatusCode < 400 {
			front = append(front, m)
		} else {
			back = append(back, m)
		}
	}
	ordered = append(ordered, front...)
	ordered = append(ordered, back...)
	if k > len(ordered) {
		k = len(ordered)
	}
	return ordered[:k]
}

func (p Planner) Build(sitemap []Record, maxTier int) Plan {
	clusters := ClusterEndpoints(sitemap)
	plan := Plan{Clusters: clusters, Budget: p.Budget}

	specs := append([]TestSpec(nil), p.Specs...)
	sort.SliceStable(specs, func(i, j int) bool { return specs[i].Tier < specs[j].Tier })

	for _, spec := range specs {
		if spec.Tier > maxTier {
			continue
		}
		var targets []Record
		for _, c := range clusters {
			for _, rep := range p.reps(c) {
				if !spec.Req.SatisfiedBy(rep) {
					plan.Skipped = append(plan.Skipped, SkipNote{spec.Module, c.Key, "precondition not met"})
					continue
				}
				est := spec.ProbesPerEndpoint
				if p.Budget > 0 && plan.SpentProbes+est > p.Budget {
					plan.Skipped = append(plan.Skipped, SkipNote{spec.Module, c.Key, "over budget"})
					break
				}
				targets = append(targets, rep)
				plan.SpentProbes += est
			}
		}
		if len(targets) > 0 {
			plan.Items = append(plan.Items, WorkItem{
				Module:    spec.Module,
				Tier:      spec.Tier,
				Targets:   targets,
				EstProbes: spec.ProbesPerEndpoint * len(targets),
			})
		}
	}
	return plan
}

func (p Planner) Escalate(sitemap []Record, tier int, hitKeys map[string]bool, alreadySpent int) Plan {
	clusters := ClusterEndpoints(sitemap)
	plan := Plan{Clusters: clusters, Budget: p.Budget, SpentProbes: alreadySpent}

	for _, spec := range p.Specs {
		if spec.Tier != tier {
			continue
		}
		var targets []Record
		for _, c := range clusters {
			if !hitKeys[c.Key] {
				continue
			}
			for _, rep := range p.reps(c) {
				if !spec.Req.SatisfiedBy(rep) {
					plan.Skipped = append(plan.Skipped, SkipNote{spec.Module, c.Key, "precondition not met"})
					continue
				}
				est := spec.ProbesPerEndpoint
				if p.Budget > 0 && plan.SpentProbes+est > p.Budget {
					plan.Skipped = append(plan.Skipped, SkipNote{spec.Module, c.Key, "over budget"})
					break
				}
				targets = append(targets, rep)
				plan.SpentProbes += est
			}
		}
		if len(targets) > 0 {
			plan.Items = append(plan.Items, WorkItem{
				Module:    spec.Module,
				Tier:      spec.Tier,
				Targets:   targets,
				EstProbes: spec.ProbesPerEndpoint * len(targets),
			})
		}
	}
	return plan
}

func (pl Plan) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Plan: %d clusters, %d work items, ~%d probes", len(pl.Clusters), len(pl.Items), pl.SpentProbes)
	if pl.Budget > 0 {
		fmt.Fprintf(&b, " (budget %d)", pl.Budget)
	}
	b.WriteString("\n")
	for _, it := range pl.Items {
		fmt.Fprintf(&b, "  tier%d %-14s -> %d endpoint(s), ~%d probes\n", it.Tier, it.Module, len(it.Targets), it.EstProbes)
	}
	if len(pl.Skipped) > 0 {
		fmt.Fprintf(&b, "  skipped %d (module,cluster) pairs\n", len(pl.Skipped))
	}
	return b.String()
}
