package daemon

import (
	"encoding/json"
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
