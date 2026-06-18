package daemon

import (
	"bytes"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/detect/gitleaks"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// newGitleaksScrubServer starts a Server whose session is wired with the real
// gitleaks detector (layer-2 net) AND optionally one exact-match issued value.
// It exercises the SAME wiring cmd/avd uses: NewSession -> WithDetector(gitleaks).
// When unlocked is false the session is left LOCKED, so scrub must mask nothing
// (no exact-match, no gitleaks).
func newGitleaksScrubServer(t *testing.T, name, value string, unlocked bool) string {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	det, err := gitleaks.New()
	if err != nil {
		t.Fatalf("gitleaks.New(): %v", err)
	}
	sess := NewSession(15 * time.Minute)
	sess.WithDetector(det)
	if unlocked {
		sess.Unlock(15 * time.Minute)
		if name != "" {
			sess.Issue(name, value)
		}
	}
	srv.SetResolver(NewResolver(nil, NewStubPresence(), sess))
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return path
}

// scrubAll pipes data through one scrub chunk + scrub_flush and returns the
// concatenated masked output.
func scrubAll(t *testing.T, path string, data []byte) []byte {
	t.Helper()
	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	enc, dec := ipc.NewEncoder(c), ipc.NewDecoder(c)
	var out bytes.Buffer
	out.Write(scrubChunk(t, enc, dec, 1, "scrub", data))
	out.Write(scrubChunk(t, enc, dec, 2, "scrub_flush", nil))
	return out.Bytes()
}

// TestScrubGitleaksDerivedToken is the load-bearing test for the layer-2 net: a
// DERIVED GitHub PAT the daemon NEVER issued is piped through scrub and must be
// masked by the gitleaks detector. The raw token must not survive and a REDACTED
// placeholder must appear.
func TestScrubGitleaksDerivedToken(t *testing.T) {
	// Unlocked session with an UNRELATED exact value; the token below is NOT issued.
	path := newGitleaksScrubServer(t, "TOKEN", "ghp_SOMETHING_ELSE", true)

	const derived = "ghp_0123456789abcdefABCDEF0123456789abcd"
	got := scrubAll(t, path, []byte("export GH_TOKEN="+derived))

	if bytes.Contains(got, []byte(derived)) {
		t.Fatalf("raw derived token survived scrub: %q", got)
	}
	if !bytes.Contains(got, []byte("{{AV:REDACTED:")) {
		t.Fatalf("scrub output = %q, want a {{AV:REDACTED:...}} placeholder", got)
	}
}

// TestScrubGitleaksExactStillMasked is the regression: with the detector wired,
// an EXACT issued session value is still masked via the StreamRedactor tier.
func TestScrubGitleaksExactStillMasked(t *testing.T) {
	const secret = "ghp_EXACTISSUEDVALUE"
	path := newGitleaksScrubServer(t, "TOKEN", secret, true)

	got := scrubAll(t, path, []byte("v="+secret))
	if bytes.Contains(got, []byte(secret)) {
		t.Fatalf("raw exact value survived scrub: %q", got)
	}
	if string(got) != "v={{AV:TOKEN}}" {
		t.Fatalf("scrub output = %q, want v={{AV:TOKEN}}", got)
	}
}

// TestScrubGitleaksBenignString proves recall-over-precision does not catastrophically
// destroy normal text: a plain commit hash passes through without crashing. The basic
// case must remain intact (the literal text need not be byte-identical, but a benign
// short word must survive).
func TestScrubGitleaksBenignString(t *testing.T) {
	path := newGitleaksScrubServer(t, "TOKEN", "ghp_UNRELATED", true)

	const benign = "fixed in commit deadbeef cafe"
	got := scrubAll(t, path, []byte(benign))
	if !bytes.Contains(got, []byte("commit")) {
		t.Fatalf("benign text over-destroyed: %q", got)
	}
}

// TestScrubGitleaksLockedMasksNothing proves a LOCKED session masks nothing: neither
// the exact-match tier (no issued values) nor the gitleaks tier runs while locked.
func TestScrubGitleaksLockedMasksNothing(t *testing.T) {
	path := newGitleaksScrubServer(t, "", "", false) // left LOCKED

	const derived = "ghp_0123456789abcdefABCDEF0123456789abcd"
	in := "export GH_TOKEN=" + derived
	got := scrubAll(t, path, []byte(in))
	if string(got) != in {
		t.Fatalf("locked session masked something: got %q, want %q", got, in)
	}
}
