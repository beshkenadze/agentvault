package client

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/daemon"
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

// newSecretScrubServer starts an in-process daemon with a session holding ONE issued
// value (name -> value) and returns a client bound to it. It wires the scrub stream
// to that session via SetResolver, so scrub masks the issued value. Unlike
// newRunServer it takes an arbitrary name/value, letting a test issue a 1-byte secret
// to force worst-case placeholder inflation.
func newSecretScrubServer(t *testing.T, name, value string) *Client {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := daemon.New(path)
	if err != nil {
		t.Fatal(err)
	}
	sess := daemon.NewSession(15 * time.Minute)
	sess.Unlock(15 * time.Minute)
	sess.Issue(name, value)
	srv.SetResolver(daemon.NewResolver(nil, daemon.NewStubPresence(), sess))
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return New(path)
}

// TestScrubReplyInflationUnderLineLimit is the reply-inflation cap regression. The
// placeholder is "{{AV:" + Name + "}}" = 7 + len(Name) bytes, where Name is the user's
// LOGICAL env-var name (unbounded). So a 1-byte secret with a realistic name inflates
// by 7 + len(Name) PER masked byte — NOT a fixed 8x. With a 32-char name the placeholder
// is 39 bytes (~39x), so a 1 MiB all-secret input masks to ~39 MiB; base64-framed in
// JSON-RPC that is far past the 1 MiB Decoder line cap.
//
// A client-side chunk cap that assumes fixed 8x inflation cannot bound this: the
// inflation is name-dependent and unbounded. The fix is daemon-side reply splitting —
// the daemon splits its OWN masked output by byte size so each response line stays under
// the cap regardless of how much the input inflated. This test asserts the whole stream
// completes with NO "token too long" and the output is fully masked (no raw secret).
func TestScrubReplyInflationUnderLineLimit(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	// A realistic 32-char logical name -> placeholder "{{AV:<32 chars>}}" = 39 bytes,
	// ~39x inflation for a 1-byte secret. The placeholder does NOT contain the secret
	// byte, so any raw secret byte in the output is a genuine leak.
	const name = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 32 chars
	const secret = "S"
	placeholder := "{{AV:" + name + "}}"
	cl := newSecretScrubServer(t, name, secret)

	const n = 1 << 20 // 1 MiB of the 1-byte secret repeated -> ~39 MiB masked
	in := bytes.NewReader(bytes.Repeat([]byte(secret), n))
	var out bytes.Buffer
	if err := cl.Scrub(in, &out); err != nil {
		// A "token too long" / bufio.ErrTooLong here is the exact failure daemon-side
		// reply splitting prevents; surface it clearly.
		t.Fatalf("Scrub of large 1-byte-secret input failed (reply-split regression?): %v", err)
	}

	// SECURITY: not a single raw secret byte may survive (the whole input was the secret).
	if bytes.Contains(out.Bytes(), []byte(secret)) {
		t.Fatalf("SECURITY: raw 1-byte secret survived scrub")
	}
	// Fully masked: exactly n placeholders, nothing else.
	if want := strings.Repeat(placeholder, n); out.String() != want {
		t.Fatalf("masked output length = %d, want %d (n placeholders)", out.Len(), len(want))
	}
}
