package daemon

import (
	"encoding/json"
	"testing"

	"github.com/beshkenadze/agentvault/internal/ipc"
)

// setupServer wires a Server with an injected stub provisioner and returns the socket
// path plus a pointer to the captured params, so the test can assert the "setup" case
// round-trips params -> result without linking age/enclave into the daemon package.
func setupServer(t *testing.T, provision func(ipc.SetupParams) (ipc.SetupResult, error)) string {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if provision != nil {
		srv.SetProvisioner(provision)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return path
}

// TestSetupRPCRoundTrips: the "setup" case forwards SetupParams to the injected
// provisioner and returns its SetupResult verbatim (paths + Created) to the client.
func TestSetupRPCRoundTrips(t *testing.T) {
	var got ipc.SetupParams
	canned := ipc.SetupResult{
		VaultPath:    "/store/vault.age",
		IdentityPath: "/store/identity.enc",
		Created:      true,
	}
	path := setupServer(t, func(p ipc.SetupParams) (ipc.SetupResult, error) {
		got = p
		return canned, nil
	})

	resp := rpcParams(t, path, "setup", ipc.SetupParams{Rotate: true, Plaintext: true})
	if resp.Error != nil {
		t.Fatalf("setup error: %+v", resp.Error)
	}
	if !got.Rotate || !got.Plaintext {
		t.Fatalf("provisioner got params %+v, want Rotate+Plaintext set", got)
	}
	var res ipc.SetupResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if res != canned {
		t.Fatalf("result = %+v, want %+v", res, canned)
	}
}

// TestSetupRPCNilProvisionerIsInternal: with no provisioner wired, "setup" fails with
// CodeInternal ("setup not configured") rather than panicking.
func TestSetupRPCNilProvisionerIsInternal(t *testing.T) {
	path := setupServer(t, nil)

	resp := rpcParams(t, path, "setup", ipc.SetupParams{})
	if resp.Error == nil {
		t.Fatal("expected an error with no provisioner wired")
	}
	if resp.Error.Code != ipc.CodeInternal {
		t.Fatalf("code = %d, want CodeInternal", resp.Error.Code)
	}
}
