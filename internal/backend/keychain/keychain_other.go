//go:build !darwin

// Package keychain on non-darwin platforms provides a stub Backend so cmd/avd compiles
// and cross-compiles everywhere. The macOS keychain (and the `security` CLI) exist only
// on darwin; the real implementation lives in keychain_darwin.go. Here Resolve always
// fails with a clear, value-free "requires macOS" error, and List is empty.
package keychain

import (
	"errors"

	"github.com/beshkenadze/agentvault/internal/backend"
)

// errUnsupported is the value-free error returned by every Resolve on non-darwin.
var errUnsupported = errors.New("keychain backend requires macOS")

// Backend is the non-darwin stub. It carries no state; every Resolve errors.
type Backend struct{}

// New returns the non-darwin stub backend.
func New() *Backend {
	return &Backend{}
}

// NewWithRunner exists for API parity with the darwin build (so test/wiring code can be
// written platform-agnostically). The runner is ignored: there is no `security` here.
func NewWithRunner(_ func(args ...string) ([]byte, error)) *Backend {
	return &Backend{}
}

// Resolve always fails on non-darwin: there is no macOS keychain to query. The error
// carries no secret material.
func (b *Backend) Resolve(locator string) (backend.Secret, error) {
	return backend.Secret{}, errUnsupported
}

// List returns an empty metadata set (metadata-only, not load-bearing).
func (b *Backend) List(prefix string) ([]backend.Meta, error) {
	return nil, nil
}

// compile-time check that Backend satisfies the interface on non-darwin too.
var _ backend.Backend = (*Backend)(nil)
