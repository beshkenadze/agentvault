package daemon

import (
	"testing"
	"time"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/ipc"
)

// newUnlockServer mirrors newLockServer but lets a test inject the session (so it can be
// WithUnwrapper) and the presence (so it can be a recording countingPresence). It wires
// the SAME presence on SetPresence (serves "unlock") and the resolver (dangerous-tier
// resolve), so the unwrap-vs-prompt branch is exercised over the real socket dispatch.
func newUnlockServer(t *testing.T, sess *Session, presence Presence) string {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: map[string]string{"GH": "ghp_xyz"}})
	srv.SetPresence(presence)
	srv.SetResolver(NewResolver(reg, presence, sess))
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return path
}

// TestUnlockUnwrapsWithoutPrompt: with an unwrapper wired, "unlock" UNWRAPS the vault key
// (the unwrap IS the presence proof) and must NOT call presence.Prompt — one Touch ID,
// not two. After unlock the session holds a usable identity.
func TestUnlockUnwrapsWithoutPrompt(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	sess := NewSession(15 * time.Minute).WithUnwrapper(stubUnwrapper(id))
	presence := &countingPresence{} // records whether Prompt was called
	path := newUnlockServer(t, sess, presence)

	if st := statusOf(t, rpc(t, path, "unlock")); st.Locked {
		t.Fatalf("after unlock, status must be unlocked: %+v", st)
	}
	if presence.n != 0 {
		t.Fatalf("unwrap path must NOT call presence.Prompt, got %d calls", presence.n)
	}
	if _, err := sess.Identity(); err != nil {
		t.Fatalf("Identity after unwrap-unlock must succeed, got %v", err)
	}
}

// TestUnlockNoUnwrapperPrompts: with NO unwrapper, "unlock" keeps the existing path —
// it calls presence.Prompt. With the prompt denying (ErrLocked stub default), the session
// stays locked and Identity stays ErrLocked.
func TestUnlockNoUnwrapperPrompts(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "") // stub presence denies with ErrLocked
	sess := NewSession(15 * time.Minute)
	presence := NewStubPresence()
	path := newUnlockServer(t, sess, presence)

	resp := rpc(t, path, "unlock")
	if resp.Error == nil || resp.Error.Code != ipc.CodeLocked {
		t.Fatalf("want CodeLocked from denied prompt, got error=%+v result=%s", resp.Error, resp.Result)
	}
	if _, err := sess.Identity(); err != ErrLocked {
		t.Fatalf("Identity must stay ErrLocked without unwrapper, got %v", err)
	}
}

// TestUnlockNoUnwrapperPromptCalled: with NO unwrapper and an allowing recording presence,
// "unlock" MUST invoke presence.Prompt exactly once (the existing presence path).
func TestUnlockNoUnwrapperPromptCalled(t *testing.T) {
	sess := NewSession(15 * time.Minute)
	presence := &countingPresence{} // allows + records
	path := newUnlockServer(t, sess, presence)

	if st := statusOf(t, rpc(t, path, "unlock")); st.Locked {
		t.Fatalf("after allowing prompt, status must be unlocked: %+v", st)
	}
	if presence.n != 1 {
		t.Fatalf("no-unwrapper path must call presence.Prompt once, got %d", presence.n)
	}
}

// TestUnlockUnwrapDeniedStaysLocked: an unwrapper returning ErrDenied (the user denied
// Touch ID) maps to CodeDenied and leaves the session LOCKED — unwrap is the presence
// proof, so a denied unwrap is a denied unlock.
func TestUnlockUnwrapDeniedStaysLocked(t *testing.T) {
	sess := NewSession(15 * time.Minute).WithUnwrapper(func() ([]byte, error) {
		return nil, ErrDenied
	})
	presence := &countingPresence{}
	path := newUnlockServer(t, sess, presence)

	resp := rpc(t, path, "unlock")
	if resp.Error == nil || resp.Error.Code != ipc.CodeDenied {
		t.Fatalf("want CodeDenied from denied unwrap, got error=%+v result=%s", resp.Error, resp.Result)
	}
	if presence.n != 0 {
		t.Fatalf("denied-unwrap path must NOT fall back to presence.Prompt, got %d", presence.n)
	}
	if st := statusOf(t, rpc(t, path, "status")); !st.Locked {
		t.Fatalf("denied unwrap must leave session locked: %+v", st)
	}
}
