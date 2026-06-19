package daemon

import (
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/ipc"
)

// countingUnwrapper yields the identity's bytes and records how many times it ran, so a
// test can assert the on-demand unlock fired exactly once (NoPrompt:false) or never
// (NoPrompt:true). It mirrors stubUnwrapper but counts the calls.
func countingUnwrapper(id *age.X25519Identity, n *int32) func() ([]byte, error) {
	return func() ([]byte, error) {
		atomic.AddInt32(n, 1)
		return []byte(id.String() + "\n"), nil
	}
}

// autoUnlockServer wires a Server over a real socket whose "file" backend is the seeded
// age vault and whose session is locked but WithUnwrapper(unwrap) — so resolve/add must
// go through ensureUnlocked before touching the resolver/writer. It mirrors addrmServer
// but injects the session (so the test controls its lock state + unwrapper).
func autoUnlockServer(t *testing.T, vaultPath string, id age.Identity, sess *Session) string {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := backend.NewRegistry()
	reg.Register("file", agefile.New(agefile.Static{ID: id}, vaultPath))
	reg.Register("mock", mockBE{data: map[string]string{"GH": "ghp_xyz"}})
	srv.SetResolver(NewResolver(reg, NewStubPresence(), sess))
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return path
}

// resolveFileManifest is a manifest whose normal-tier secret resolves off the "file"
// backend (the seeded age vault), so a successful resolve proves the session was opened.
const resolveFileManifest = `profiles:
  smoke:
    TOKEN:
      ref: av://file/TOKEN
      tier: normal
`

// TestResolveAutoUnlocksWhenAllowed: a LOCKED session with an unwrapper, resolved with
// NoPrompt:false, auto-unlocks (the unwrapper runs once) and returns the value.
func TestResolveAutoUnlocksWhenAllowed(t *testing.T) {
	vault, id := newAgeVault(t, map[string]string{"TOKEN": "ghp_secret"})
	var n int32
	sess := NewSession(15 * time.Minute).WithUnwrapper(countingUnwrapper(id, &n))
	path := autoUnlockServer(t, vault, id, sess)

	resp := rpcParams(t, path, "resolve", ipc.ResolveParams{
		Profile: "smoke", Manifest: []byte(resolveFileManifest), NoPrompt: false,
	})
	if resp.Error != nil {
		t.Fatalf("resolve with NoPrompt:false should auto-unlock and succeed, got %+v", resp.Error)
	}
	if got := atomic.LoadInt32(&n); got != 1 {
		t.Fatalf("unwrapper must run exactly once on auto-unlock, ran %d times", got)
	}
}

// TestResolveNoPromptStaysLocked: a LOCKED session resolved with NoPrompt:true must NOT
// auto-unlock — it returns CodeLocked and the unwrapper is never called (the agent gets
// the exit-69 pause instead of blocking on Touch ID).
func TestResolveNoPromptStaysLocked(t *testing.T) {
	vault, id := newAgeVault(t, map[string]string{"TOKEN": "ghp_secret"})
	var n int32
	sess := NewSession(15 * time.Minute).WithUnwrapper(countingUnwrapper(id, &n))
	path := autoUnlockServer(t, vault, id, sess)

	resp := rpcParams(t, path, "resolve", ipc.ResolveParams{
		Profile: "smoke", Manifest: []byte(resolveFileManifest), NoPrompt: true,
	})
	if resp.Error == nil || resp.Error.Code != ipc.CodeLocked {
		t.Fatalf("resolve with NoPrompt:true on a locked session must return CodeLocked, got error=%+v result=%s", resp.Error, resp.Result)
	}
	if got := atomic.LoadInt32(&n); got != 0 {
		t.Fatalf("NoPrompt:true must NOT call the unwrapper, ran %d times", got)
	}
}

// TestAddAutoUnlocksWhenAllowed: add with NoPrompt:false on a locked session auto-unlocks
// (unwrapper runs once) and the write succeeds.
func TestAddAutoUnlocksWhenAllowed(t *testing.T) {
	vault, id := newAgeVault(t, map[string]string{"A": "1"})
	var n int32
	sess := NewSession(15 * time.Minute).WithUnwrapper(countingUnwrapper(id, &n))
	path := autoUnlockServer(t, vault, id, sess)

	resp := rpcParams(t, path, "add", ipc.AddParams{
		Backend: "file", Locator: "NEW", Value: []byte("v"), NoPrompt: false,
	})
	if resp.Error != nil {
		t.Fatalf("add with NoPrompt:false should auto-unlock and succeed, got %+v", resp.Error)
	}
	if got := atomic.LoadInt32(&n); got != 1 {
		t.Fatalf("unwrapper must run exactly once on auto-unlock, ran %d times", got)
	}
}

// TestAddNoPromptStaysLocked: add with NoPrompt:true on a locked session returns
// CodeLocked WITHOUT calling the unwrapper (no biometric block for an agent).
func TestAddNoPromptStaysLocked(t *testing.T) {
	vault, id := newAgeVault(t, map[string]string{"A": "1"})
	var n int32
	sess := NewSession(15 * time.Minute).WithUnwrapper(countingUnwrapper(id, &n))
	path := autoUnlockServer(t, vault, id, sess)

	resp := rpcParams(t, path, "add", ipc.AddParams{
		Backend: "file", Locator: "NEW", Value: []byte("v"), NoPrompt: true,
	})
	if resp.Error == nil || resp.Error.Code != ipc.CodeLocked {
		t.Fatalf("add with NoPrompt:true on a locked session must return CodeLocked, got error=%+v result=%s", resp.Error, resp.Result)
	}
	if got := atomic.LoadInt32(&n); got != 0 {
		t.Fatalf("NoPrompt:true must NOT call the unwrapper, ran %d times", got)
	}
}
