//go:build darwin && cgo

package daemon

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework AppKit

// av_autolock_start / av_autolock_stop are implemented in autolock_darwin.m
// (compiled by cgo on darwin). start registers OS observers for screen-lock and
// system-sleep and spins a dedicated thread running a CFRunLoop so the
// distributed/workspace notifications are actually delivered; each observer
// calls back into Go via the exported goAutoLockFire. stop removes the observers
// and stops that run loop.
void av_autolock_start(void);
void av_autolock_stop(void);
*/
import "C"

import "sync"

// autoLockMu guards autoLockFn. The OS observer thread (via goAutoLockFire) and
// StartAutoLock/stop all touch autoLockFn, so every access is serialized here.
//
// We bridge to C through this package-level function rather than passing the
// *Session pointer into C: cgo pointer rules forbid storing a Go pointer in C
// and calling back with it. Instead StartAutoLock stashes s.Lock here, C calls
// the argument-free goAutoLockFire, and we dispatch to the stored func.
var (
	autoLockMu sync.Mutex
	autoLockFn func()
)

// StartAutoLock registers macOS observers that lock the session when the screen
// locks or the machine sleeps, and returns a stop func that removes them.
//
// Notification delivery REQUIRES an active run loop. avd's Go main does not run
// a CFRunLoop, so av_autolock_start spins a dedicated thread that runs one after
// registering the observers (see autolock_darwin.m). This is the most likely
// reason the feature compiles but does not fire if the run loop is missing —
// the manual hardware-verification step must confirm a real screen-lock locks
// the session.
//
// stop() is non-blocking and safe to call once: it removes the observers, stops
// the run loop, and clears the stored callback. Calling stop more than once is a
// harmless no-op on the Go side (the C side guards against a double stop).
func StartAutoLock(s *Session) (stop func()) {
	autoLockMu.Lock()
	autoLockFn = s.Lock
	autoLockMu.Unlock()

	C.av_autolock_start()

	var once sync.Once
	return func() {
		once.Do(func() {
			C.av_autolock_stop()
			autoLockMu.Lock()
			autoLockFn = nil
			autoLockMu.Unlock()
		})
	}
}

// goAutoLockFire is invoked from C (the observer blocks) when the screen locks
// or the machine sleeps. It runs the stored lock callback under the mutex; if no
// callback is registered (e.g. after stop) it is a no-op.
//
//export goAutoLockFire
func goAutoLockFire() {
	autoLockMu.Lock()
	fn := autoLockFn
	autoLockMu.Unlock()
	if fn != nil {
		fn()
	}
}
