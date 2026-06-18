//go:build !darwin || !cgo

package daemon

import "errors"

// newTouchIDPresence is the fallback for builds without darwin+cgo (e.g.
// CGO_ENABLED=0, or non-macOS). The Touch ID backend requires LocalAuthentication
// via cgo on darwin; here it is unavailable. The constructor exists on every
// build so callers (cmd/avd) compile regardless of build tags.
func newTouchIDPresence() (Presence, error) {
	return nil, errors.New("touch id unavailable: requires a darwin cgo build")
}

// NewTouchIDPresence is the exported constructor cmd/avd wires in production. On
// builds without darwin+cgo it returns the same unavailable error, so cmd/avd
// fails loudly rather than silently running without a real presence check.
func NewTouchIDPresence() (Presence, error) { return newTouchIDPresence() }
