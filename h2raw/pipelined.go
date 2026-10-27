package h2raw

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func (c *Client) WriteRequest(h2conn *H2Conn, req *Request, streamId uint32) error {
	if !h2conn.IsIntialized() {
		if err := h2conn.DefaultInit(); err != nil {
			return err
		}
	}

	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	pseudo := []hpack.HeaderField{
		{Name: ":method", Value: req.Method},
		{Name: ":scheme", Value: req.Scheme},
		{Name: ":authority", Value: req.Authority},
		{Name: ":path", Value: req.Path},
	}
	for _, f := range pseudo {
		if err := enc.WriteField(f); err != nil {
			return err
		}
	}
	for k, vs := range req.Headers {
		for _, v := range vs {
			if err := enc.WriteField(hpack.HeaderField{Name: k, Value: v}); err != nil {
				return err
			}
		}
	}

	if err := h2conn.Framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamId,
		BlockFragment: hb.Bytes(),
		EndStream:     !req.HasBody(),
		EndHeaders:    true,
	}); err != nil {
		return err
	}
	if req.HasBody() {
		if err := h2conn.Framer.WriteData(streamId, true, *req.Body); err != nil {
			return err
		}
	}
	return nil
}

type streamAcc struct {
	headers map[string][]string
	body    []byte
	hasBody bool
}

func (c *Client) DrainResponses(h2conn *H2Conn, streamIds []uint32, timeout time.Duration) (map[uint32]*Response, map[uint32]error, error) {
	if nc, ok := h2conn.Conn.(net.Conn); ok && timeout > 0 {
		_ = nc.SetReadDeadline(time.Now().Add(timeout))
	}

	dec := hpack.NewDecoder(4096, nil)
	decode := func(block []byte) map[string][]string {
		out := make(map[string][]string)
		fields, derr := dec.DecodeFull(block)
		if derr != nil {
			return out
		}
		for _, h := range fields {
			out[h.Name] = append(out[h.Name], h.Value)
		}
		return out
	}

	pending := make(map[uint32]bool, len(streamIds))
	for _, id := range streamIds {
		pending[id] = true
	}
	accs := make(map[uint32]*streamAcc)
	responses := make(map[uint32]*Response)
	errs := make(map[uint32]error)

	get := func(id uint32) *streamAcc {
		if accs[id] == nil {
			accs[id] = &streamAcc{headers: make(map[string][]string)}
		}
		return accs[id]
	}
	finalize := func(id uint32) {
		a := get(id)
		status := ""
		if s, ok := a.headers[":status"]; ok && len(s) > 0 {
			status = s[0]
		}
		var b *[]byte
		if a.hasBody {
			bb := a.body
			b = &bb
		}
		responses[id] = &Response{Status: status, Headers: a.headers, Body: b}
		delete(pending, id)
	}

	for len(pending) > 0 {
		frame, err := h2conn.Framer.ReadFrame()
		if err != nil {
			return responses, errs, err
		}
		switch f := frame.(type) {
		case *http2.HeadersFrame:
			id := f.StreamID
			addHeaders(get(id).headers, decode(f.HeaderBlockFragment()))
			if f.StreamEnded() {
				finalize(id)
			}
		case *http2.DataFrame:
			id := f.StreamID
			a := get(id)
			a.body = append(a.body, f.Data()...)
			a.hasBody = true
			if f.StreamEnded() {
				finalize(id)
			}
		case *http2.RSTStreamFrame:
			errs[f.StreamID] = fmt.Errorf("RST_STREAM code=%v", f.ErrCode)
			delete(pending, f.StreamID)
		case *http2.GoAwayFrame:
			errs[0] = fmt.Errorf("GOAWAY code=%v lastStream=%d", f.ErrCode, f.LastStreamID)
			return responses, errs, nil
		default:
		}
	}
	return responses, errs, nil
}
