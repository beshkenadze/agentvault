package client

import (
	"encoding/json"
	"io"

	"github.com/beshkenadze/agentvault/internal/ipc"
)

// scrubChunkSize bounds each "scrub" request. It is a throughput knob only — it does
// NOT bound the masked reply size, because masking inflation is unbounded: the
// placeholder is "{{AV:" + Name + "}}" = 7 + len(Name) bytes per masked byte, and Name
// (the user's logical env-var name) has no fixed length. A chunk that is all 1-byte
// secrets with an N-char name inflates by (7+N)x, so no client chunk size can keep the
// reply under the daemon Decoder's 1 MiB JSON-RPC cap. Instead the daemon splits its
// OWN masked output by byte size (maxScrubReplyBytes) and the client drains the
// remainder via "scrub_drain" while the reply's More flag is set. 256 KiB is a sensible
// chunk for raw-byte throughput.
const scrubChunkSize = 256 * 1024

// Scrub streams in through the daemon's per-connection layer-2 redactor and writes
// the masked result to out. All masking happens daemon-side; the client only ships
// raw bytes and writes back masked bytes (so av stays thin — no redact dependency).
//
// Because the daemon keeps per-connection scrub state (a StreamRedactor whose
// retained tail catches a secret split across chunks), every "scrub"/"scrub_flush"
// for one stream MUST travel over the SAME connection — Scrub dials once and reuses
// the connection for the whole stream, draining the overlap tail with "scrub_flush"
// at EOF.
func (c *Client) Scrub(in io.Reader, out io.Writer) error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	enc := ipc.NewEncoder(conn)
	dec := ipc.NewDecoder(conn)

	var id uint64

	// call sends one request, writes the masked reply, and returns whether the daemon
	// has more masked bytes buffered for this stream.
	call := func(method string, data []byte) (more bool, err error) {
		id++
		params, _ := json.Marshal(ipc.ScrubParams{Data: data})
		if err := enc.Encode(ipc.Request{ID: id, Method: method, Params: params}); err != nil {
			return false, err
		}
		var resp ipc.Response
		if err := dec.Decode(&resp); err != nil {
			return false, err
		}
		if resp.Error != nil {
			return false, resp.Error // non-secret message; carries a stable Code
		}
		var r ipc.ScrubResult
		if err := json.Unmarshal(resp.Result, &r); err != nil {
			return false, err
		}
		if len(r.Masked) > 0 {
			if _, err := out.Write(r.Masked); err != nil {
				return false, err
			}
		}
		return r.More, nil
	}

	// send issues one request, then drains the daemon's leftover masked bytes via
	// "scrub_drain" until More clears. The daemon splits its own (possibly hugely
	// inflated) masked output across replies to stay under the JSON-RPC line cap, so
	// draining here guarantees every masked byte is delivered regardless of inflation.
	send := func(method string, data []byte) error {
		more, err := call(method, data)
		for ; err == nil && more; more, err = call("scrub_drain", nil) {
		}
		return err
	}

	buf := make([]byte, scrubChunkSize)
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			if err := send("scrub", buf[:n]); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	return send("scrub_flush", nil)
}
