package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/ipc"
)

// noFileServer wires a Server with a registry that has NO "file" backend (only the
// read-only "mock"), so add/rm against "file" hits the unregistered path — the
// zero-config "store not provisioned yet" state before `av setup` has run.
func noFileServer(t *testing.T) string {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: map[string]string{"GH": "ghp_xyz"}}) // read-only, not "file"
	sess := NewSession(15 * time.Minute)
	srv.SetResolver(NewResolver(reg, NewStubPresence(), sess))
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return path
}

// TestAddFileUnregisteredHintsSetup: an "add" against "file" when no file backend is
// registered (no local vault yet) returns CodeBadRequest with a message that guides
// the user to run `av setup` — so the thin av exits 2 with an actionable hint.
func TestAddFileUnregisteredHintsSetup(t *testing.T) {
	path := noFileServer(t)
	resp := rpcParams(t, path, "add", ipc.AddParams{Backend: "file", Locator: "K", Value: []byte("v")})
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("resp.Error = %+v, want CodeBadRequest", resp.Error)
	}
	if !strings.Contains(resp.Error.Message, "run 'av setup' first") {
		t.Fatalf("message = %q, want it to mention run 'av setup' first", resp.Error.Message)
	}
}

// TestRmFileUnregisteredHintsSetup: the same hint applies to "rm" against an
// unregistered file backend.
func TestRmFileUnregisteredHintsSetup(t *testing.T) {
	path := noFileServer(t)
	resp := rpcParams(t, path, "rm", ipc.RmParams{Backend: "file", Locator: "K"})
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("resp.Error = %+v, want CodeBadRequest", resp.Error)
	}
	if !strings.Contains(resp.Error.Message, "run 'av setup' first") {
		t.Fatalf("message = %q, want it to mention run 'av setup' first", resp.Error.Message)
	}
}

// TestAddUnknownBackendKeepsGenericMessage: a non-"file" unregistered backend keeps the
// generic read-only/not-registered message — only "file" gets the setup hint.
func TestAddUnknownBackendKeepsGenericMessage(t *testing.T) {
	path := noFileServer(t)
	resp := rpcParams(t, path, "add", ipc.AddParams{Backend: "nope", Locator: "K", Value: []byte("v")})
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("resp.Error = %+v, want CodeBadRequest", resp.Error)
	}
	if strings.Contains(resp.Error.Message, "av setup") {
		t.Fatalf("message = %q, must not hint setup for a non-file backend", resp.Error.Message)
	}
	if !strings.Contains(resp.Error.Message, "read-only or not registered") {
		t.Fatalf("message = %q, want the generic read-only/not-registered message", resp.Error.Message)
	}
}
