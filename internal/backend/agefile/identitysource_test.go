package agefile

import (
	"errors"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/beshkenadze/agentvault/internal/backend"
)

// errSource is an IdentitySource whose Identity() always fails. It models a locked
// session: the key is unavailable and the failure must propagate to the caller rather
// than being swallowed (e.g. mis-reported as a missing secret).
type errSource struct{ err error }

func (s errSource) Identity() (age.Identity, error) { return nil, s.err }

// errLocked is a sentinel the test asserts on via errors.Is, standing in for the real
// daemon.ErrLocked the session source will return once the identity moves into it.
var errLocked = errors.New("source locked")

// TestSourceErrorPropagates: every operation that needs the identity (Resolve via load,
// Add and Remove via load + recipient) must SURFACE the source's error. If a locked
// source were silently treated as "empty vault" or "not found", a real secret could be
// dropped — so the original error must travel back unchanged (errors.Is).
func TestSourceErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	b := New(errSource{err: errLocked}, path)

	if _, err := b.Resolve("ANY"); !errors.Is(err, errLocked) {
		t.Fatalf("Resolve err = %v, want errors.Is(errLocked)", err)
	}
	if err := b.Add("K", "v"); !errors.Is(err, errLocked) {
		t.Fatalf("Add err = %v, want errors.Is(errLocked)", err)
	}
	if err := b.Remove("K"); !errors.Is(err, errLocked) {
		t.Fatalf("Remove err = %v, want errors.Is(errLocked)", err)
	}
}

// TestStaticRoundTrips: Static(id) wraps a fixed identity, so a backend built on it
// behaves exactly like the old held-identity backend — an Add then Resolve round-trips
// the value through the age-encrypted file.
func TestStaticRoundTrips(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{})

	b := New(Static{ID: id}, path)
	if err := b.Add("GITHUB_TOKEN", "ghp_value"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := b.Resolve("GITHUB_TOKEN")
	if err != nil {
		t.Fatalf("Resolve after Add: %v", err)
	}
	if got.Value != "ghp_value" {
		t.Fatalf("value = %q, want ghp_value", got.Value)
	}
	// A missing key must still be ErrNotFound, not the (nil) source error path.
	if _, err := b.Resolve("MISSING"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("missing key err = %v, want ErrNotFound", err)
	}
}
