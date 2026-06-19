package client

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/daemon"
	"github.com/beshkenadze/agentvault/internal/ipc"
)

// addrmDaemon wires an in-process daemon whose registry holds the real agefile backend
// under "file" (writable), seeded with `seed`. It returns the client and the vault path
// + identity so the test can verify the secret round-tripped through the encrypted file.
func addrmDaemon(t *testing.T, seed map[string]string) (*Client, string, *age.X25519Identity) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	vdir := t.TempDir()
	vault := filepath.Join(vdir, "vault.age")
	f, err := os.OpenFile(vault, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := agefile.EncryptVault(f, id.Recipient(), seed); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	path := shortSocketPath(t)
	srv, err := daemon.New(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := backend.NewRegistry()
	reg.Register("file", agefile.New(agefile.Static{ID: id}, vault))
	srv.SetResolver(daemon.NewResolver(reg, daemon.NewStubPresence(), daemon.NewSession(15*time.Minute)))
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return New(path), vault, id
}

// TestClientAddRoundTrips: client.Add sends the value over the socket; resolving the
// vault file confirms the secret was written through the daemon.
func TestClientAddRoundTrips(t *testing.T) {
	const secret = "ghp_client_secret"
	cl, vault, id := addrmDaemon(t, map[string]string{"A": "1"})

	if err := cl.Add("file", "TOKEN", []byte(secret)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	sec, err := agefile.New(agefile.Static{ID: id}, vault).Resolve("TOKEN")
	if err != nil {
		t.Fatalf("resolve after Add: %v", err)
	}
	if sec.Value != secret {
		t.Fatalf("value = %q, want %q", sec.Value, secret)
	}
}

// TestClientRemove: client.Remove deletes the entry; resolving is NotFound.
func TestClientRemove(t *testing.T) {
	cl, vault, id := addrmDaemon(t, map[string]string{"GONE": "v", "STAY": "s"})

	if err := cl.Remove("file", "GONE"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := agefile.New(agefile.Static{ID: id}, vault).Resolve("GONE"); err != backend.ErrNotFound {
		t.Fatalf("resolve removed = %v, want ErrNotFound", err)
	}
}

// TestClientRemoveMissingReturnsRPCError: removing an absent name surfaces the daemon's
// *ipc.RPCError (CodeBadRequest) so cmd/av can map it to a clear exit.
func TestClientRemoveMissingReturnsRPCError(t *testing.T) {
	cl, _, _ := addrmDaemon(t, map[string]string{"A": "1"})

	err := cl.Remove("file", "NOPE")
	if err == nil {
		t.Fatal("expected error removing absent name")
	}
	rpc, ok := err.(*ipc.RPCError)
	if !ok {
		t.Fatalf("err type = %T, want *ipc.RPCError", err)
	}
	if rpc.Code != ipc.CodeBadRequest {
		t.Fatalf("code = %d, want CodeBadRequest", rpc.Code)
	}
}
