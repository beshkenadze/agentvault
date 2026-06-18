package daemon

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// newScrubServer starts a Server with a session that has one issued value, wired
// so the scrub methods use that SAME session (via SetResolver capturing it).
func newScrubServer(t *testing.T, name, value string) (string, *Session) {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	sess := NewSession(15 * time.Minute)
	sess.Issue(name, value)
	// Wire a resolver over the same session so the Server captures it for scrub.
	srv.SetResolver(NewResolver(nil, NewStubPresence(), sess))
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return path, sess
}

// scrubChunk sends one "scrub" or "scrub_flush" request on conn and returns the
// masked bytes from the reply.
func scrubChunk(t *testing.T, enc *ipc.Encoder, dec *ipc.Decoder, id uint64, method string, data []byte) []byte {
	t.Helper()
	params, _ := json.Marshal(ipc.ScrubParams{Data: data})
	if err := enc.Encode(ipc.Request{ID: id, Method: method, Params: params}); err != nil {
		t.Fatal(err)
	}
	var resp ipc.Response
	if err := dec.Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		t.Fatalf("%s error: %+v", method, resp.Error)
	}
	var r ipc.ScrubResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatal(err)
	}
	return r.Masked
}

// TestScrubRPCSplitAcrossChunks is the load-bearing test: an issued value is SPLIT
// across two scrub chunks over the wire, then flushed. The concatenated masked
// output must mask the value with no raw bytes surviving — proving the Phase 1
// streaming overlap guarantee holds across the RPC boundary.
func TestScrubRPCSplitAcrossChunks(t *testing.T) {
	const secret = "ghp_SPLITSECRET"
	path, _ := newScrubServer(t, "TOKEN", secret)

	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	enc := ipc.NewEncoder(c)
	dec := ipc.NewDecoder(c)

	// Split the secret across two chunks: "x ghp_SPLIT" + "SECRET y".
	cut := 2 + len("ghp_SPLIT") // after "x ghp_SPLIT"
	full := "x " + secret + " y"
	var out bytes.Buffer
	out.Write(scrubChunk(t, enc, dec, 1, "scrub", []byte(full[:cut])))
	out.Write(scrubChunk(t, enc, dec, 2, "scrub", []byte(full[cut:])))
	out.Write(scrubChunk(t, enc, dec, 3, "scrub_flush", nil))

	got := out.String()
	if bytes.Contains(out.Bytes(), []byte(secret)) {
		t.Fatalf("raw secret survived scrub: %q", got)
	}
	if want := "x {{AV:TOKEN}} y"; got != want {
		t.Fatalf("scrub output = %q, want %q", got, want)
	}
}

// TestScrubRPCPerConnectionIsolated proves per-connection scrub state does not leak
// across connections: a second connection that only flushes (never wrote a partial)
// gets empty output, unaffected by the first connection's retained tail.
func TestScrubRPCPerConnectionIsolated(t *testing.T) {
	const secret = "ghp_ISOLATED"
	path, _ := newScrubServer(t, "TOKEN", secret)

	// Conn 1: write a partial that would be retained as a tail, then abandon it.
	c1, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	enc1, dec1 := ipc.NewEncoder(c1), ipc.NewDecoder(c1)
	_ = scrubChunk(t, enc1, dec1, 1, "scrub", []byte("ghp_ISOL")) // partial -> retained
	c1.Close()

	// Conn 2: fresh state. A flush before any scrub must yield nothing, and a full
	// secret in one chunk must mask cleanly with no leftover from conn 1.
	c2, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	enc2, dec2 := ipc.NewEncoder(c2), ipc.NewDecoder(c2)
	if m := scrubChunk(t, enc2, dec2, 1, "scrub_flush", nil); len(m) != 0 {
		t.Fatalf("fresh-connection flush returned %q, want empty", m)
	}
	var out bytes.Buffer
	out.Write(scrubChunk(t, enc2, dec2, 2, "scrub", []byte("v="+secret)))
	out.Write(scrubChunk(t, enc2, dec2, 3, "scrub_flush", nil))
	if got := out.String(); got != "v={{AV:TOKEN}}" {
		t.Fatalf("conn 2 output = %q, want v={{AV:TOKEN}}", got)
	}
}
