//go:build !darwin

package client

import "errors"

// autostart is the non-darwin fallback. v1 is macOS-only; the detached avd
// launch relies on darwin process semantics, so here it FAILS LOUDLY rather
// than pretending to start the daemon. The symbol exists on every build so
// client.dial compiles regardless of build tags.
func autostart(socketPath string) error {
	_ = socketPath
	return errors.New("daemon autostart unsupported on this platform")
}
