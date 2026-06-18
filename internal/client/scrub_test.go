package client

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// resolveSecret populates the in-process daemon's session with SECRET=topsecret
// by driving a resolve, so the scrub stream has a value to mask.
func resolveSecret(t *testing.T, cl *Client) {
	t.Helper()
	vals, err := cl.Resolve("smoke", []byte(runManifestYAML))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if vals["SECRET"] != "topsecret" {
		t.Fatalf("resolve values = %+v", vals)
	}
}

// TestScrubMasksStream proves client.Scrub filters a piped stream, masking a
// session value end to end (daemon-side masking; the client only ships bytes).
func TestScrubMasksStream(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)
	resolveSecret(t, cl)

	in := strings.NewReader("leak: topsecret here\n")
	var out bytes.Buffer
	if err := cl.Scrub(in, &out); err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if strings.Contains(out.String(), "topsecret") {
		t.Fatalf("SECURITY: value survived scrub: %q", out.String())
	}
	if want := "leak: {{AV:SECRET}} here\n"; out.String() != want {
		t.Fatalf("scrub output = %q, want %q", out.String(), want)
	}
}

// chunkReader yields its data in fixed-size pieces so a Scrub read boundary can be
// forced to split the secret across two client reads — exercising the streaming
// overlap across the RPC boundary from the client side.
type chunkReader struct {
	data []byte
	size int
	pos  int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	end := r.pos + r.size
	if end > len(r.data) {
		end = len(r.data)
	}
	n := copy(p, r.data[r.pos:end])
	r.pos += n
	return n, nil
}

// TestScrubSplitAcrossReadChunks forces the secret to straddle two client reads;
// the daemon's per-connection StreamRedactor must still mask it.
func TestScrubSplitAcrossReadChunks(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)
	resolveSecret(t, cl)

	// "top" lands in read 1, "secret" in read 2 — the secret straddles the cut.
	in := &chunkReader{data: []byte("x topsecret y"), size: 5}
	var out bytes.Buffer
	if err := cl.Scrub(in, &out); err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if strings.Contains(out.String(), "topsecret") {
		t.Fatalf("SECURITY: split value survived scrub: %q", out.String())
	}
	if want := "x {{AV:SECRET}} y"; out.String() != want {
		t.Fatalf("scrub output = %q, want %q", out.String(), want)
	}
}
