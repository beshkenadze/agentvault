package client

import (
	"errors"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/daemon"
)

// healDaemon wires an in-process daemon reporting the given build version (via SetVersion)
// and records whether the "shutdown" RPC fired (the injected teardown callback). It returns
// the socket path and the fired channel so a heal test can assert Shutdown was/wasn't called
// WITHOUT the real os.Exit teardown (the callback only records — that is the injection seam).
// The session is unlocked so a Status() after a (non-)heal succeeds rather than locking.
func healDaemon(t *testing.T, avdVersion string) (path string, fired chan struct{}) {
	t.Helper()
	path = shortSocketPath(t)
	srv, err := daemon.New(path)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetVersion(avdVersion)
	sess := daemon.NewSession(15 * time.Minute)
	sess.Unlock(15 * time.Minute) // Status() reports unlocked rather than locked
	srv.SetResolver(daemon.NewResolver(nil, daemon.NewStubPresence(), sess))
	fired = make(chan struct{}, 1)
	srv.SetShutdown(func() {
		select {
		case fired <- struct{}{}:
		default:
		}
		// NOTE: a recording callback only — it does NOT exit, so the daemon keeps serving
		// the OLD version. The interactive heal then times out (no upgraded binary in test).
	})
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return path, fired
}

// TestHealNoPromptSurfacesErrDaemonOutdated: an agent (NoPrompt) facing a stale daemon must
// NOT auto-restart it — ensureFresh (via Status) returns *ErrDaemonOutdated and the daemon
// is left running (no shutdown fired).
func TestHealNoPromptSurfacesErrDaemonOutdated(t *testing.T) {
	path, fired := healDaemon(t, "v0.1.0")
	cl := New(path).WithNoPrompt(true).WithVersion("v0.2.0")

	_, _, err := cl.Status()
	var outdated *ErrDaemonOutdated
	if !errors.As(err, &outdated) {
		t.Fatalf("NoPrompt skew must return *ErrDaemonOutdated, got %v", err)
	}
	if outdated.Av != "v0.2.0" || outdated.Avd != "v0.1.0" {
		t.Fatalf("ErrDaemonOutdated = %+v, want Av=v0.2.0 Avd=v0.1.0", outdated)
	}
	select {
	case <-fired:
		t.Fatal("agent path must NOT shut the daemon down")
	default:
	}
}

// TestHealInteractiveShutsDownAndDoesNotHang: a human (no NoPrompt) facing a stale daemon
// restarts it — ensureFresh fires Shutdown. The test does not respawn an upgraded daemon, so
// the poll times out within healWait and returns nil (the LOUD warning) WITHOUT hanging, and
// the heal is attempted exactly once.
func TestHealInteractiveShutsDownAndDoesNotHang(t *testing.T) {
	path, fired := healDaemon(t, "v0.1.0")
	cl := New(path).WithVersion("v0.2.0").withHealWait(300 * time.Millisecond)

	done := make(chan error, 1)
	go func() { _, _, err := cl.Status(); done <- err }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("interactive heal must return nil after timing out, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ensureFresh hung — must return within healWait, never block")
	}
	select {
	case <-fired:
		// Shutdown was invoked (the heal action) — as required.
	default:
		t.Fatal("interactive skew must fire Shutdown")
	}

	// Heal is attempted at most once: a second work call must NOT fire Shutdown again.
	if _, _, err := cl.Status(); err != nil {
		t.Fatalf("second Status after heal: %v", err)
	}
	select {
	case <-fired:
		t.Fatal("heal must run at most once (Shutdown fired a second time)")
	default:
	}
}

// TestHealMatchedVersionsNoOp: equal versions are no skew — no shutdown, no error.
func TestHealMatchedVersionsNoOp(t *testing.T) {
	path, fired := healDaemon(t, "v0.2.0")
	cl := New(path).WithVersion("v0.2.0").withHealWait(300 * time.Millisecond)

	if _, _, err := cl.Status(); err != nil {
		t.Fatalf("matched versions Status: %v", err)
	}
	select {
	case <-fired:
		t.Fatal("matched versions must not shut the daemon down")
	default:
	}
}

// TestHealDevDaemonNoOp: a "dev" daemon (mixed dev/brew setup) must never be auto-restarted —
// healing a dev daemon would loop. No shutdown, no error.
func TestHealDevDaemonNoOp(t *testing.T) {
	path, fired := healDaemon(t, "dev")
	cl := New(path).WithVersion("v0.2.0").withHealWait(300 * time.Millisecond)

	if _, _, err := cl.Status(); err != nil {
		t.Fatalf("dev daemon Status: %v", err)
	}
	select {
	case <-fired:
		t.Fatal("a dev daemon must not be auto-restarted")
	default:
	}
}

// TestHealDevClientNoOp: an unstamped/dev av must never restart a release daemon (it would
// loop in a mixed setup). ensureFresh short-circuits before even calling Version — no skew.
func TestHealDevClientNoOp(t *testing.T) {
	path, fired := healDaemon(t, "v0.2.0")
	cl := New(path).WithVersion("dev").withHealWait(300 * time.Millisecond)

	if _, _, err := cl.Status(); err != nil {
		t.Fatalf("dev client Status: %v", err)
	}
	select {
	case <-fired:
		t.Fatal("a dev av must not restart a release daemon")
	default:
	}
}
