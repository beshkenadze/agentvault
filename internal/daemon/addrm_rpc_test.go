package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// newAgeVault creates a seeded age vault file on disk and returns its path plus the
// identity, so the test can both Resolve through the daemon and verify on disk.
func newAgeVault(t *testing.T, seed map[string]string) (string, *age.X25519Identity) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := agefile.EncryptVault(f, id.Recipient(), seed); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path, id
}

// addrmServer wires a Server with a registry holding the real agefile backend under
// "file" (writable) and a read-only mock under "mock", with a bufLogger audit sink, so
// the add/rm RPC can be exercised end-to-end (write then resolve back) over the socket.
func addrmServer(t *testing.T, vaultPath string, id age.Identity) (string, *bufLogger) {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := backend.NewRegistry()
	reg.Register("file", agefile.New(id, vaultPath))
	reg.Register("mock", mockBE{data: map[string]string{"GH": "ghp_xyz"}}) // read-only
	log := &bufLogger{}
	sess := NewSession(15 * time.Minute)
	srv.SetResolver(NewResolver(reg, NewStubPresence(), sess))
	srv.SetAudit(log)
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return path, log
}

// rpcParams dials, sends one request for method WITH params, and returns the response.
// (The param-less rpc helper lives in lock_rpc_test.go.)
func rpcParams(t *testing.T, path, method string, params any) ipc.Response {
	t.Helper()
	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pb, _ := json.Marshal(params)
	if err := ipc.NewEncoder(c).Encode(ipc.Request{ID: 1, Method: method, Params: pb}); err != nil {
		t.Fatal(err)
	}
	var resp ipc.Response
	if err := ipc.NewDecoder(c).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// fileResolve issues a resolve through the registry's "file" backend by going around
// the daemon's resolve RPC (which needs a manifest); it resolves directly off the same
// vault path/identity to confirm the value round-tripped through the encrypted file.
func fileResolve(t *testing.T, vaultPath string, id age.Identity, name string) (string, error) {
	t.Helper()
	sec, err := agefile.New(id, vaultPath).Resolve(name)
	return sec.Value, err
}

// TestAddRPCRoundTrips: an "add" RPC writes the value into the encrypted vault, and a
// subsequent Resolve off the SAME file returns it — the secret round-trips through the
// age-encrypted file the daemon owns.
func TestAddRPCRoundTrips(t *testing.T) {
	const secret = "ghp_SUPERSECRET_value"
	vault, id := newAgeVault(t, map[string]string{"EXISTING": "old"})
	path, _ := addrmServer(t, vault, id)

	resp := rpcParams(t, path, "add", ipc.AddParams{Backend: "file", Locator: "NEW_TOKEN", Value: []byte(secret)})
	if resp.Error != nil {
		t.Fatalf("add error: %+v", resp.Error)
	}
	got, err := fileResolve(t, vault, id, "NEW_TOKEN")
	if err != nil {
		t.Fatalf("resolve after add: %v", err)
	}
	if got != secret {
		t.Fatalf("round-trip value = %q, want %q", got, secret)
	}
}

// TestRmRPCRemoves: an "rm" RPC deletes the entry so a subsequent Resolve is NotFound.
func TestRmRPCRemoves(t *testing.T) {
	vault, id := newAgeVault(t, map[string]string{"DOOMED": "v", "KEEP": "k"})
	path, _ := addrmServer(t, vault, id)

	resp := rpcParams(t, path, "rm", ipc.RmParams{Backend: "file", Locator: "DOOMED"})
	if resp.Error != nil {
		t.Fatalf("rm error: %+v", resp.Error)
	}
	if _, err := fileResolve(t, vault, id, "DOOMED"); err != backend.ErrNotFound {
		t.Fatalf("resolve removed = %v, want ErrNotFound", err)
	}
	if v, err := fileResolve(t, vault, id, "KEEP"); err != nil || v != "k" {
		t.Fatalf("KEEP after rm = %q, %v; want k, nil", v, err)
	}
}

// TestRmRPCMissingIsBadRequest: removing an absent name maps the backend's ErrNotFound
// to CodeBadRequest (a client fault) — not a silent ok.
func TestRmRPCMissingIsBadRequest(t *testing.T) {
	vault, id := newAgeVault(t, map[string]string{"A": "1"})
	path, _ := addrmServer(t, vault, id)

	resp := rpcParams(t, path, "rm", ipc.RmParams{Backend: "file", Locator: "NOPE"})
	if resp.Error == nil {
		t.Fatal("expected error removing absent name")
	}
	if resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("code = %d, want CodeBadRequest", resp.Error.Code)
	}
}

// TestAddRPCReadOnlyBackendRejected: an "add" against a read-only backend (mock, which
// does not implement backend.Writer) is rejected with CodeBadRequest and writes nothing.
func TestAddRPCReadOnlyBackendRejected(t *testing.T) {
	vault, id := newAgeVault(t, map[string]string{"A": "1"})
	path, _ := addrmServer(t, vault, id)

	resp := rpcParams(t, path, "add", ipc.AddParams{Backend: "mock", Locator: "X", Value: []byte("v")})
	if resp.Error == nil {
		t.Fatal("expected error adding to a read-only backend")
	}
	if resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("code = %d, want CodeBadRequest", resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "read-only") {
		t.Fatalf("message = %q, want it to mention read-only", resp.Error.Message)
	}
}

// TestAddRPCUnknownBackendRejected: an "add" against an unregistered backend id is a
// client fault (CodeBadRequest), not an internal error.
func TestAddRPCUnknownBackendRejected(t *testing.T) {
	vault, id := newAgeVault(t, map[string]string{"A": "1"})
	path, _ := addrmServer(t, vault, id)

	resp := rpcParams(t, path, "add", ipc.AddParams{Backend: "ghost", Locator: "X", Value: []byte("v")})
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("resp.Error = %+v, want CodeBadRequest", resp.Error)
	}
}

// TestAddRmAuditHasNoValue: the add/rm audit entries record kind+name+backend but NEVER
// the value — scanning the entire audit output must not contain the secret.
func TestAddRmAuditHasNoValue(t *testing.T) {
	const secret = "sk_live_TOPSECRET_neverlog"
	vault, id := newAgeVault(t, map[string]string{"A": "1"})
	path, log := addrmServer(t, vault, id)

	if resp := rpcParams(t, path, "add", ipc.AddParams{Backend: "file", Locator: "K", Value: []byte(secret)}); resp.Error != nil {
		t.Fatalf("add: %+v", resp.Error)
	}
	if resp := rpcParams(t, path, "rm", ipc.RmParams{Backend: "file", Locator: "K"}); resp.Error != nil {
		t.Fatalf("rm: %+v", resp.Error)
	}

	raw := log.raw(t)
	if strings.Contains(raw, secret) {
		t.Fatalf("audit output leaked the secret value:\n%s", raw)
	}
	// And the kinds must be present (add then rm), with the name recorded.
	want := map[string]bool{"add": false, "rm": false}
	for _, e := range log.all() {
		if _, ok := want[e.Kind]; ok {
			want[e.Kind] = true
			if e.Name != "K" {
				t.Fatalf("%s event Name = %q, want K", e.Kind, e.Name)
			}
		}
	}
	for k, seen := range want {
		if !seen {
			t.Fatalf("missing audit kind %q", k)
		}
	}
}

// TestAddRPCErrorHasNoValue: even when the write fails, the error returned to the client
// must not contain the secret value (the agefile backend never wraps the value).
func TestAddRPCErrorHasNoValue(t *testing.T) {
	const secret = "ghp_should_never_appear_in_error"
	// Point the file backend at a vault whose identity does NOT match, so load() fails
	// on decrypt — the value is in flight but must not surface in the error.
	vault, _ := newAgeVault(t, map[string]string{"A": "1"})
	wrongID, _ := age.GenerateX25519Identity()
	path, _ := addrmServer(t, vault, wrongID)

	resp := rpcParams(t, path, "add", ipc.AddParams{Backend: "file", Locator: "K", Value: []byte(secret)})
	if resp.Error == nil {
		t.Fatal("expected an error (wrong identity cannot decrypt to modify)")
	}
	if strings.Contains(resp.Error.Message, secret) {
		t.Fatalf("error leaked the secret value: %q", resp.Error.Message)
	}
}
