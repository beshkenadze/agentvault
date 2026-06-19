package client

import (
	"testing"

	"github.com/beshkenadze/agentvault/internal/daemon"
	"github.com/beshkenadze/agentvault/internal/ipc"
)

// setupDaemon wires an in-process daemon with an injected stub provisioner and returns a
// client plus a pointer to the captured params, so the test can drive client.Setup over
// the socket without linking age/enclave into the client (the provisioner is the seam).
func setupDaemon(t *testing.T, provision func(ipc.SetupParams) (ipc.SetupResult, error)) *Client {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := daemon.New(path)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetProvisioner(provision)
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return New(path)
}

// TestClientSetupRoundTrips: client.Setup sends the params and returns the daemon's
// SetupResult — paths + Created — round-tripped through the socket.
func TestClientSetupRoundTrips(t *testing.T) {
	var got ipc.SetupParams
	canned := ipc.SetupResult{
		VaultPath:    "/store/vault.age",
		IdentityPath: "/store/identity.txt",
		Created:      true,
	}
	cl := setupDaemon(t, func(p ipc.SetupParams) (ipc.SetupResult, error) {
		got = p
		return canned, nil
	})

	res, err := cl.Setup(ipc.SetupParams{Plaintext: true})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !got.Plaintext || got.Rotate {
		t.Fatalf("provisioner got params %+v, want Plaintext only", got)
	}
	if res != canned {
		t.Fatalf("result = %+v, want %+v", res, canned)
	}
}

// TestClientSetupReturnsRPCError: a provisioner failure surfaces as *ipc.RPCError
// (CodeInternal) so cmd/av can map it to an exit code.
func TestClientSetupReturnsRPCError(t *testing.T) {
	cl := setupDaemon(t, nil) // nil provisioner -> daemon replies CodeInternal

	_, err := cl.Setup(ipc.SetupParams{})
	if err == nil {
		t.Fatal("expected an error with no provisioner wired")
	}
	rpc, ok := err.(*ipc.RPCError)
	if !ok {
		t.Fatalf("err type = %T, want *ipc.RPCError", err)
	}
	if rpc.Code != ipc.CodeInternal {
		t.Fatalf("code = %d, want CodeInternal", rpc.Code)
	}
}
