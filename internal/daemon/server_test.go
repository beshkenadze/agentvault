package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// shortSocketPath returns a socket path under /tmp to stay well under the macOS
// 104-byte sun_path limit (t.TempDir() paths are too long for unix sockets).
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "avd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "avd.sock")
}

func TestServePing(t *testing.T) {
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	defer srv.Close()

	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := ipc.NewEncoder(c).Encode(ipc.Request{ID: 1, Method: "ping"}); err != nil {
		t.Fatal(err)
	}
	var resp ipc.Response
	if err := ipc.NewDecoder(c).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	var pong string
	json.Unmarshal(resp.Result, &pong)
	if pong != "pong" {
		t.Fatalf("result = %q, want pong", pong)
	}
}

func TestUnknownMethod(t *testing.T) {
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	defer srv.Close()

	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ipc.NewEncoder(c).Encode(ipc.Request{ID: 2, Method: "nope"})
	var resp ipc.Response
	ipc.NewDecoder(c).Decode(&resp)
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("want CodeBadRequest, got %+v", resp.Error)
	}
}

// TestHandleRejectsUnverifiedPeer exercises the actual security gate in handle():
// when the peer-credential check fails, the connection must be rejected with
// CodeUnauthorized and closed BEFORE any request is dispatched. A foreign UID
// can't be forged locally, so we inject a forced-reject checkPeer via the seam.
func TestHandleRejectsUnverifiedPeer(t *testing.T) {
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	// Override the seam BEFORE Serve(): every peer is now rejected, simulating a
	// foreign UID that the local kernel would never let us forge for real.
	srv.checkPeer = func(net.Conn) error { return fmt.Errorf("forced reject") }
	go srv.Serve()
	defer srv.Close()

	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Send a ping — it must NEVER be dispatched (no "pong" must ever come back).
	if err := ipc.NewEncoder(c).Encode(ipc.Request{ID: 1, Method: "ping"}); err != nil {
		t.Fatal(err)
	}

	dec := ipc.NewDecoder(c)
	var resp ipc.Response
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("expected an unauthorized response, got decode error: %v", err)
	}
	// The single response must be the unauthorized rejection, not a pong result.
	if resp.Error == nil || resp.Error.Code != ipc.CodeUnauthorized {
		t.Fatalf("want CodeUnauthorized, got error=%+v result=%s", resp.Error, resp.Result)
	}
	if resp.Result != nil {
		t.Fatalf("rejected peer must not receive a dispatched result, got %s", resp.Result)
	}

	// The connection must then be CLOSED: a subsequent Decode must hit EOF, proving
	// the ping was never dispatched and no "pong" ever follows the rejection.
	var after ipc.Response
	if err := dec.Decode(&after); !errors.Is(err, io.EOF) {
		t.Fatalf("conn must be closed after reject (want io.EOF), got err=%v resp=%+v", err, after)
	}
}

// TestSecondInstanceRefuses asserts the single-instance liveness guard: a second
// daemon.New on the same path must refuse (return an error) rather than clobber
// the live daemon's socket. The first server must keep answering ping.
func TestSecondInstanceRefuses(t *testing.T) {
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	defer srv.Close()

	// Second instance must refuse: a live peer answers on the socket.
	if srv2, err := New(path); err == nil {
		srv2.Close()
		t.Fatal("second New must refuse while a live daemon is listening")
	}

	// The original daemon must still be answering on the same socket.
	c, err := transport.Dial(path)
	if err != nil {
		t.Fatalf("first daemon should still be reachable: %v", err)
	}
	defer c.Close()
	if err := ipc.NewEncoder(c).Encode(ipc.Request{ID: 3, Method: "ping"}); err != nil {
		t.Fatal(err)
	}
	var resp ipc.Response
	if err := ipc.NewDecoder(c).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		t.Fatalf("first daemon ping failed: %v", resp.Error)
	}
	var pong string
	json.Unmarshal(resp.Result, &pong)
	if pong != "pong" {
		t.Fatalf("first daemon result = %q, want pong", pong)
	}
}
