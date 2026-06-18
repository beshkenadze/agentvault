package agefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/beshkenadze/agentvault/internal/backend"
)

// TestAddResolvesBack: Add writes a new entry that Resolve reads back, and the
// re-encrypted vault still decrypts with the SAME identity (recipient derived from
// the identity, so the file the daemon decrypts on every Resolve is unchanged in
// recipient).
func TestAddResolvesBack(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{"EXISTING": "old"})

	b := New(id, path)
	if err := b.Add("GITHUB_TOKEN", "ghp_new"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := b.Resolve("GITHUB_TOKEN")
	if err != nil {
		t.Fatalf("Resolve after Add: %v", err)
	}
	if got.Value != "ghp_new" {
		t.Fatalf("value = %q, want ghp_new", got.Value)
	}
	// The pre-existing entry must survive an Add (Add modifies the map, not replaces it).
	if g, err := b.Resolve("EXISTING"); err != nil || g.Value != "old" {
		t.Fatalf("EXISTING after Add = %q, %v; want old, nil", g.Value, err)
	}
}

// TestAddOverwrites: Add to an existing name updates its value.
func TestAddOverwrites(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{"K": "v1"})

	b := New(id, path)
	if err := b.Add("K", "v2"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := b.Resolve("K")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "v2" {
		t.Fatalf("value = %q, want v2", got.Value)
	}
}

// TestRemove: Remove deletes an entry so a subsequent Resolve returns ErrNotFound,
// and a Remove of an absent name returns ErrNotFound (so the caller learns nothing
// was removed rather than a silent no-op).
func TestRemove(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{"A": "1", "B": "2"})

	b := New(id, path)
	if err := b.Remove("A"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := b.Resolve("A"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("Resolve removed A: err = %v, want ErrNotFound", err)
	}
	// The sibling entry must remain.
	if g, err := b.Resolve("B"); err != nil || g.Value != "2" {
		t.Fatalf("B after Remove(A) = %q, %v; want 2, nil", g.Value, err)
	}
	// Removing an absent name reports ErrNotFound.
	if err := b.Remove("MISSING"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("Remove(MISSING) = %v, want ErrNotFound", err)
	}
}

// TestAddIsAtomicNoTempLeftover: a successful Add leaves no ".tmp" sidecar in the
// vault dir (write-then-rename cleans up; rename consumes the temp).
func TestAddIsAtomicNoTempLeftover(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{"A": "1"})

	b := New(id, path)
	if err := b.Add("B", "2"); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

// TestAddFailureLeavesOriginalIntact: if the write cannot complete (the temp path
// is not creatable — its parent dir is read-only), Add returns an error and the
// LIVE vault is byte-for-byte unchanged (write-then-rename never touches the
// original until the atomic rename). This is the corruption-safety invariant.
func TestAddFailureLeavesOriginalIntact(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{"A": "1"})

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Make the dir read-only so creating "<path>.tmp" fails. The original file
	// already exists and is readable for load(); only the NEW temp create fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	b := New(id, path)
	if err := b.Add("B", "2"); err == nil {
		t.Fatal("expected Add to fail when temp cannot be created")
	}

	// Restore write perms so we can read the original back for comparison.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("live vault was modified by a failed Add (corruption-safety violated)")
	}
}

// TestVaultMode0600: the re-written vault keeps owner-only permissions.
func TestVaultMode0600(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{"A": "1"})

	b := New(id, path)
	if err := b.Add("B", "2"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("vault mode = %o, want 600", fi.Mode().Perm())
	}
}

// TestAddNonX25519IdentityErrors: Add must derive the recipient from the identity.
// A non-X25519 identity cannot yield an X25519 recipient, so Add must error
// CLEARLY rather than silently writing an unreadable vault.
func TestAddNonX25519IdentityErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	// Seed a valid vault with a real identity so load() succeeds; then point a
	// backend with a NON-X25519 identity at it to isolate the recipient-derivation
	// failure (not a decrypt failure).
	realID, _ := age.GenerateX25519Identity()
	writeEncrypted(t, path, realID, map[string]string{"A": "1"})

	b := New(notX25519{realID}, path)
	err := b.Add("B", "2")
	if err == nil {
		t.Fatal("expected Add to error for a non-X25519 identity")
	}
	if errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("recipient-derivation failure misreported as ErrNotFound: %v", err)
	}
}

// notX25519 wraps a real identity so load()/decrypt still works (Unwrap delegates),
// but the concrete type is NOT *age.X25519Identity, so the recipient type-assert in
// Add/Remove must fail.
type notX25519 struct{ inner age.Identity }

func (n notX25519) Unwrap(stanzas []*age.Stanza) ([]byte, error) { return n.inner.Unwrap(stanzas) }
