package daemon

import (
	"testing"
	"time"
)

// TestStartAutoLockReturnsStop verifies the auto-lock seam constructs and that
// the returned stop func is callable without panic or hang.
//
// It deliberately does NOT trigger a screen-lock or sleep notification: those
// originate from the OS (loginwindow / pmset) and cannot be synthesized in CI
// (no GUI session, no run loop we control, no way to lock the screen). On
// darwin+cgo this still registers and removes the real OS observers, so the test
// doubles as a compile/linkage smoke check that start+stop are balanced and
// stop() does not block. On non-darwin/non-cgo it exercises the no-op seam.
func TestStartAutoLockReturnsStop(t *testing.T) {
	stop := StartAutoLock(NewSession(time.Minute))
	if stop == nil {
		t.Fatal("StartAutoLock returned a nil stop func")
	}
	// stop() must be non-blocking and safe; if it hung the test would time out.
	stop()
}
