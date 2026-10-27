package core

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type SimpleRequester struct {
	Timeout      time.Duration
	TLSConf      *tls.Config
	RateLimiter  <-chan time.Time
	ProxyAddr    string
	TLSProfile   string
	RateInterval time.Duration
}

func (r *SimpleRequester) pace(n int) {
	if r.RateInterval > 0 {
		PaceN(r.RateInterval, n)
	}
}

func (r *SimpleRequester) SendNormal(t Target, url string) (*http.Response, time.Duration, error) {
	defer r.pace(1)

	transport := &http.Transport{}
	if t.TLS {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	client := &http.Client{
		Timeout:   r.Timeout,
		Transport: transport,

		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, 0, err
	}

	for k, vs := range t.ExtraHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	start := time.Now()
	resp, err := client.Do(req)
	return resp, time.Since(start), err
}

func (r *SimpleRequester) dial(t Target) (net.Conn, error) {
	addr := net.JoinHostPort(t.Host, fmt.Sprint(t.Port))

	if !t.TLS {
		return net.DialTimeout("tcp", addr, r.Timeout)
	}

	tlsConf := r.TLSConf
	if tlsConf == nil {
		tlsConf = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	if keyLogPath := os.Getenv("SSLKEYLOGFILE"); keyLogPath != "" {
		f, err := os.OpenFile(keyLogPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err == nil {
			tlsConf.KeyLogWriter = f
		}
	}
	d := &net.Dialer{Timeout: r.Timeout}
	return tls.DialWithDialer(d, "tcp", addr, tlsConf)
}

func (r *SimpleRequester) SendRaw(t Target, payload []byte) ([]byte, time.Duration, error) {
	defer r.pace(1)

	conn, err := r.dial(t)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	if r.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(r.Timeout))
	}
	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return nil, 0, err
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	return buf[:n], time.Since(start), err
}

func (r *SimpleRequester) SendRawProbe(t Target, payload []byte, hardLimit time.Duration) ([]byte, time.Duration, error) {
	defer r.pace(1)
	conn, err := r.dial(t)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(hardLimit))

	start := time.Now()

	if _, err := conn.Write(payload); err != nil {
		return nil, 0, err
	}

	buf := make([]byte, 65535)
	n, readErr := conn.Read(buf)
	dur := time.Since(start)

	return buf[:n], dur, readErr
}

func (r *SimpleRequester) SendRawWithDelay(
	t Target, headers, body []byte, pause time.Duration,
) (
	firstResp, secondResp []byte, firstDur, secondDur time.Duration, err error,
) {
	defer r.pace(1)

	conn, err := r.dial(t)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	defer conn.Close()

	buf := make([]byte, 65535)
	log.Println("===begining of new request===")

	_ = conn.SetWriteDeadline(time.Now().Add(r.Timeout))

	start := time.Now()

	if _, err := conn.Write(headers); err != nil {
		return nil, nil, 0, 0, fmt.Errorf("split request write headers err: %w", err)
	}
	log.Printf("[SendRawWithDelay]: headers are sent, sending body in %v", pause)
	_ = conn.SetReadDeadline(time.Now().Add(pause + 500*time.Millisecond))

	n, readErr := conn.Read(buf)

	firstDur = time.Since(start)
	log.Printf("[SendRawWithDelay]: time since headers were sent %v", firstDur)

	firstResp = append([]byte(nil), buf[:n]...)

	if readErr != nil {
		var ne net.Error
		if !errors.As(readErr, &ne) || !ne.Timeout() {
			return firstResp, nil, firstDur, 0, fmt.Errorf("read first part err: %w", readErr)
		}
	}

	_ = conn.SetWriteDeadline(time.Now().Add(r.Timeout))
	start2 := time.Now()

	if _, err := conn.Write(body); err != nil {
		return firstResp, nil, firstDur, 0, fmt.Errorf("write body err: %w\n", err)
	}
	log.Println("[SendRawWithDelay]: body is sent")

	_ = conn.SetReadDeadline(time.Now().Add(r.Timeout))
	n, readErr = conn.Read(buf)
	secondDur = time.Since(start2)
	secondResp = append([]byte(nil), buf[:n]...)

	return firstResp, secondResp, firstDur, secondDur, readErr
}

func (r *SimpleRequester) SendRawPipelined(t Target, reqs [][]byte, pause time.Duration) ([]NormalResponse, error) {
	if len(reqs) == 0 {
		return nil, fmt.Errorf("SendRawPipelined: no requests given")
	}
	defer r.pace(len(reqs))

	conn, err := r.dial(t)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	for i, req := range reqs {
		if r.Timeout > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(r.Timeout))
		}
		if _, err := conn.Write(req); err != nil {
			return nil, fmt.Errorf("SendRawPipelined: write req %d: %w", i, err)
		}
		if pause > 0 && i < len(reqs)-1 {
			time.Sleep(pause)
		}
	}

	if r.Timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(r.Timeout))
	}

	start := time.Now()
	reader := bufio.NewReader(conn)
	responses := make([]NormalResponse, 0, len(reqs))

	for {
		httpResp, parseErr := http.ReadResponse(reader, nil)
		if parseErr != nil {
			if len(responses) == 0 && !errors.Is(parseErr, io.EOF) {
				responses = append(responses, NormalResponse{Error: parseErr, Delay: time.Since(start)})
			}
			break
		}

		dur := time.Since(start)
		nr := ParseNormal(httpResp, dur, nil)
		responses = append(responses, nr)

		if len(responses) >= 64 {
			break
		}
	}

	return responses, nil
}

func (h HeaderMap) String() string {
	if h == nil {
		return ""
	}

	var sb strings.Builder
	for k, vs := range h {
		sb.WriteString(k)
		sb.WriteString(": ")
		for i, v := range vs {
			if i > 0 {
				sb.WriteString("; ")
			}
			sb.WriteString(v)
		}
		sb.WriteString(" ")
	}
	return strings.TrimSpace(sb.String())
}

func (h *HeaderMap) Set(rawValue string) error {
	parts := strings.SplitN(rawValue, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid header format: %q", rawValue)
	}
	key := http.CanonicalHeaderKey(strings.TrimSpace(parts[0]))
	val := strings.TrimSpace(parts[1])
	if key == "" {
		return fmt.Errorf("empty header name")
	}
	if *h == nil {
		*h = make(HeaderMap)
	}

	(*h)[key] = append((*h)[key], val)
	return nil
}
