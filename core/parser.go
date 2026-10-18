package core

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"time"
)

func ParseNormal(resp *http.Response, duration time.Duration, err error) NormalResponse {

	if err != nil {
		return NormalResponse{Error: err, Delay: duration}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return NormalResponse{
		StatusCode:    resp.StatusCode,
		Headers:       headers,
		Delay:         duration,
		Body:          string(bodyBytes),
		ContentLength: len(bodyBytes),
	}
}

func ParseRawResponse(rawResp []byte, dur time.Duration, err error) NormalResponse {
	resp := NormalResponse{Delay: dur}

	if err != nil {
		resp.Error = err
	}

	reader := bufio.NewReader(bytes.NewReader(rawResp))
	httpResp, parseErr := http.ReadResponse(reader, nil)
	if parseErr != nil {
		resp.Error = parseErr
		return resp
	}
	defer httpResp.Body.Close()

	headers := make(map[string]string)
	for k, v := range httpResp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	resp.StatusCode = httpResp.StatusCode
	bodyBytes, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	resp.Body = string(bodyBytes)
	resp.Headers = headers
	resp.Delay = dur

	resp.ContentLength = int(httpResp.ContentLength)

	if resp.ContentLength == -1 {
		resp.ContentLength = len(bodyBytes)
	}

	return resp
}
