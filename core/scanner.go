package core

import (
	"crypto/tls"
	"golang.org/x/net/http2"
	"net"
	"net/http"
	"net/url"
	"time"
)

func InitialRecon(rec Record) ([]string, error) {
	var allowed []string

	if len(rec.Result.ProtocolVersions) > 0 {
		for _, v := range rec.Result.ProtocolVersions {
			allowed = append(allowed, v)
		}
		return uniqueStrings(allowed), nil
	}

	ver, err := getHTTPVersion(rec.Request.Endpoint)
	if err == nil {
		switch ver {
		case 1:
			allowed = append(allowed, "http/1.1")
		case 2:
			allowed = append(allowed, "http/2")
		}
	}

	u, err := url.Parse(rec.Request.Endpoint)
	if err == nil {
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		host := u.Hostname()

		if host != "" && u.Scheme == "https" {
			if checkHTTP2Support(host, port) {
				if !contains(allowed, "http/2") {
					allowed = append(allowed, "http/2")
				}
			}
		}
	}

	if checkH2CSupport(rec.Request.Endpoint) {
		if !contains(allowed, "h2c") {
			allowed = append(allowed, "h2c")
		}
	}

	if checkHTTP09Support(rec.Request.Endpoint) {
		if !contains(allowed, "http/0.9") {
			allowed = append(allowed, "http/0.9")
		}
	}

	return uniqueStrings(allowed), nil
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, v := range input {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

func getHTTPVersion(url string) (int, error) {
	resp, err := http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.ProtoMajor, nil
}

func checkHTTP2Support(host, port string) bool {
	addr := host + ":" + port
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return false
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.NegotiatedProtocol == "h2" {
		return true
	}
	return false
}
func checkH2CSupport(rawUrl string) bool {
	client := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
		},
	}
	resp, err := client.Get(rawUrl)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.ProtoMajor == 2
}

func checkHTTP09Support(rawUrl string) bool {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return false
	}

	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	host := u.Hostname()
	if host == "" {
		return false
	}

	addr := host + ":" + port

	var conn net.Conn
	var errConn error

	if u.Scheme == "https" {
		conn, errConn = net.Dial("tcp", addr)
	} else {
		conn, errConn = net.Dial("tcp", addr)
	}
	if errConn != nil {
		return false
	}
	defer conn.Close()

	path := u.Path
	if path == "" {
		path = "/"
	}

	req := "GET " + path + "\r\n"

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write([]byte(req))
	if err != nil {
		return false
	}

	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		return false
	}
	return true
}

func contains(s []string, v string) bool {
	for i := range s {
		if s[i] == v {
			return true
		}
	}
	return false
}
