package backend

import (
	"errors"
	"fmt"
)

// ErrNotFound is returned by a backend when a locator has no value.
var ErrNotFound = errors.New("secret not found")

// Registry dispatches av:// references to registered backends by backend id.
//
// Registration is expected to happen once at startup, before the registry begins
// serving Resolve/List calls. A Registry is NOT safe for concurrent Register with
// Resolve/List (or for concurrent Register calls); the daemon (Phase 4) must finish
// wiring all backends before it starts handling requests.
type Registry struct {
	backends map[string]Backend
}

func NewRegistry() *Registry {
	return &Registry{backends: map[string]Backend{}}
}

// Register adds a backend under an id (e.g. "file", "1p", "keychain"). It OVERWRITES
// any existing backend under that id (it is a map assignment, not append-only): the
// live `setup` provisioner relies on this to re-wire "file" against a freshly
// provisioned store without a daemon restart. The concurrency note above still holds —
// re-registration must happen before/outside concurrent Resolve/List.
func (r *Registry) Register(id string, b Backend) {
	r.backends[id] = b
}

// Resolve parses ref, dispatches to the backend, and returns the secret value.
func (r *Registry) Resolve(ref string) (Secret, error) {
	p, err := ParseRef(ref)
	if err != nil {
		return Secret{}, err
	}
	b, ok := r.backends[p.Backend]
	if !ok {
		return Secret{}, fmt.Errorf("no backend registered for %q", p.Backend)
	}
	return b.Resolve(p.Locator)
}

// List returns metadata (no values) from one backend.
func (r *Registry) List(backendID, prefix string) ([]Meta, error) {
	b, ok := r.backends[backendID]
	if !ok {
		return nil, fmt.Errorf("no backend registered for %q", backendID)
	}
	return b.List(prefix)
}

// Writer returns the registered backend under backendID as a Writer, with ok=true
// only if it both exists AND supports writes (implements Writer). A read-only backend
// (1p, keychain) is registered but returns ok=false, so the caller (the "add"/"rm"
// dispatch) can reject the write rather than half-mutate an external store.
func (r *Registry) Writer(backendID string) (Writer, bool) {
	b, ok := r.backends[backendID]
	if !ok {
		return nil, false
	}
	w, ok := b.(Writer)
	return w, ok
}
