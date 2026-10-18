package core

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

func CompareRequests(base, after NormalResponse) CompareResult {
	if base.StatusCode != after.StatusCode {
		return CompareResult{
			Matched: true,
			Reason:  "status_changed",
			Details: fmt.Sprintf("Status changed: %d -> %d", base.StatusCode, after.StatusCode),
		}
	}

	if base.ContentLength != after.ContentLength {
		return CompareResult{
			Matched: true,
			Reason:  "CL Changed",
			Details: fmt.Sprintf("Content-Length changed: %d -> %d", base.ContentLength, after.ContentLength),
		}
	}
	return CompareResult{Matched: false}
}

func IsConnDeadError(err error) (bool, string) {
	if err == nil {
		return false, ""
	}
	msg := err.Error()
	if strings.Contains(msg, "EOF") {
		return true, "EOF"
	}
	if strings.Contains(msg, "broken pipe") {
		return true, "BROKEN_PIPE"
	}
	if strings.Contains(msg, "GoAway") {
		return true, "GOAWAY"
	}
	if strings.Contains(msg, "PROTOCOL_ERROR") {
		return true, "PROTOCOL_ERROR"
	}
	if strings.Contains(msg, "HPACK") {
		return true, "HPACK_DECODING"
	}
	return false, ""
}

func CheckTimeout(r NormalResponse, timeout time.Duration) bool {

	if r.Error != nil {
		var ne net.Error
		if errors.As(r.Error, &ne) && ne.Timeout() {
			return true
		}
		if strings.Contains(strings.ToLower(r.Error.Error()), "timeout") {
			return true
		}
	}

	if timeout > 0 && r.Delay >= timeout-100*time.Millisecond {
		return true
	}

	if r.StatusCode >= 500 && r.StatusCode < 600 {
		lowerBody := strings.ToLower(r.Body)
		if strings.Contains(lowerBody, "timeout") ||
			strings.Contains(lowerBody, "gateway") ||
			strings.Contains(lowerBody, "timed out") ||
			strings.Contains(lowerBody, "deadline") {
			return true
		}
	}
	return false
}
