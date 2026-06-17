package client

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/beshkenadze/agentvault/internal/daemon"
)

// shortSocketPath returns a socket path under /tmp to stay well under the macOS
// 104-byte sun_path limit (t.TempDir() paths are too long for unix sockets).
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "avc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "avd.sock")
}

// TestPingAgainstRunningServer is the happy path: an in-process daemon is already
// listening, so the client dials it directly (no autostart) and gets "pong".
func TestPingAgainstRunningServer(t *testing.T) {
	path := shortSocketPath(t)
	srv, err := daemon.New(path)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	defer srv.Close()

	cl := New(path)
	got, err := cl.Ping()
	if err != nil {
		t.Fatal(err)
	}
	if got != "pong" {
		t.Fatalf("ping = %q, want pong", got)
	}
}
