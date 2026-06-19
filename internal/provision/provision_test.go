package provision

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// stubWrap is an injected Wrap that prefixes its input, so the provision tests need no
// real Secure Enclave: it stands in for enclave.Wrap (which avd injects in production).
// It must be reversible enough for the test to assert the wrapped blob is NOT plaintext.
func stubWrap(in []byte) ([]byte, error) { return append([]byte("WRAP:"), in...), nil }

// fileMode returns the file's permission bits (the 0o600 we require for both the
// identity and the vault), failing the test if the file is missing.
func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// TestProvisionWrapped: with an injected Wrap, Provision writes identity.enc + vault.age
// (both 0600) under the temp dir, returns Created:true, and the wrapped identity file is
// NOT the plaintext identity (it went through Wrap). We can't decrypt the wrapped case
// without an unwrap, so we assert files exist + modes + that wrap was applied.
func TestProvisionWrapped(t *testing.T) {
	dir := t.TempDir()
	r, err := Provision(Options{Dir: dir, Wrap: stubWrap})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !r.Created {
		t.Fatal("Created = false, want true on first provision")
	}
	encPath := filepath.Join(dir, "identity.enc")
	vaultPath := filepath.Join(dir, "vault.age")
	if r.IdentityPath != encPath {
		t.Fatalf("IdentityPath = %q, want %q", r.IdentityPath, encPath)
	}
	if r.VaultPath != vaultPath {
		t.Fatalf("VaultPath = %q, want %q", r.VaultPath, vaultPath)
	}
	if m := fileMode(t, encPath); m != 0o600 {
		t.Fatalf("identity.enc mode = %o, want 600", m)
	}
	if m := fileMode(t, vaultPath); m != 0o600 {
		t.Fatalf("vault.age mode = %o, want 600", m)
	}
	// The identity must have gone through Wrap: the on-disk blob starts with our marker.
	blob, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(blob, []byte("WRAP:")) {
		t.Fatalf("identity.enc was not wrapped (prefix missing)")
	}
	// A plaintext identity.txt must NOT exist in the wrapped path.
	if _, err := os.Stat(filepath.Join(dir, "identity.txt")); !os.IsNotExist(err) {
		t.Fatalf("identity.txt should not exist in wrapped mode, stat err = %v", err)
	}
}

// TestProvisionIdempotent: a second Provision with an existing store (and !Rotate)
// returns Created:false and leaves BOTH files byte-for-byte unchanged.
func TestProvisionIdempotent(t *testing.T) {
	dir := t.TempDir()
	if _, err := Provision(Options{Dir: dir, Wrap: stubWrap}); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	encPath := filepath.Join(dir, "identity.enc")
	vaultPath := filepath.Join(dir, "vault.age")
	encBefore, _ := os.ReadFile(encPath)
	vaultBefore, _ := os.ReadFile(vaultPath)

	r, err := Provision(Options{Dir: dir, Wrap: stubWrap})
	if err != nil {
		t.Fatalf("second Provision: %v", err)
	}
	if r.Created {
		t.Fatal("Created = true on idempotent re-run, want false")
	}
	encAfter, _ := os.ReadFile(encPath)
	vaultAfter, _ := os.ReadFile(vaultPath)
	if !bytes.Equal(encBefore, encAfter) {
		t.Fatal("identity.enc changed on idempotent re-run")
	}
	if !bytes.Equal(vaultBefore, vaultAfter) {
		t.Fatal("vault.age changed on idempotent re-run")
	}
}

// TestProvisionRotate: Rotate:true regenerates the identity even when a store exists,
// so the identity bytes change (and a fresh empty vault is written).
func TestProvisionRotate(t *testing.T) {
	dir := t.TempDir()
	if _, err := Provision(Options{Dir: dir, Wrap: stubWrap}); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	encPath := filepath.Join(dir, "identity.enc")
	encBefore, _ := os.ReadFile(encPath)

	r, err := Provision(Options{Dir: dir, Rotate: true, Wrap: stubWrap})
	if err != nil {
		t.Fatalf("rotate Provision: %v", err)
	}
	if !r.Created {
		t.Fatal("Created = false on rotate, want true")
	}
	encAfter, _ := os.ReadFile(encPath)
	if bytes.Equal(encBefore, encAfter) {
		t.Fatal("identity.enc unchanged after Rotate, want a fresh identity")
	}
}

// TestProvisionPlaintext: Plaintext:true writes identity.txt (no Wrap applied, no
// identity.enc) and the vault decrypts to an empty JSON map with the on-disk identity.
func TestProvisionPlaintext(t *testing.T) {
	dir := t.TempDir()
	// Wrap is non-nil but must NOT be called in plaintext mode (proves no wrap path).
	wrapCalled := false
	r, err := Provision(Options{Dir: dir, Plaintext: true, Wrap: func(b []byte) ([]byte, error) {
		wrapCalled = true
		return b, nil
	}})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if wrapCalled {
		t.Fatal("Wrap was called in plaintext mode, want it skipped")
	}
	txtPath := filepath.Join(dir, "identity.txt")
	if r.IdentityPath != txtPath {
		t.Fatalf("IdentityPath = %q, want %q", r.IdentityPath, txtPath)
	}
	if m := fileMode(t, txtPath); m != 0o600 {
		t.Fatalf("identity.txt mode = %o, want 600", m)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.enc")); !os.IsNotExist(err) {
		t.Fatalf("identity.enc should not exist in plaintext mode, stat err = %v", err)
	}

	// The produced vault must decrypt to an empty map with the generated identity.
	idBytes, err := os.ReadFile(txtPath)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := age.ParseIdentities(strings.NewReader(string(idBytes)))
	if err != nil {
		t.Fatalf("parse identity.txt: %v", err)
	}
	vf, err := os.Open(r.VaultPath)
	if err != nil {
		t.Fatal(err)
	}
	defer vf.Close()
	dr, err := age.Decrypt(vf, ids...)
	if err != nil {
		t.Fatalf("decrypt vault: %v", err)
	}
	plain, err := io.ReadAll(dr)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(plain)); got != "{}" {
		t.Fatalf("vault plaintext = %q, want %q", got, "{}")
	}
}

// TestProvisionWrappedRequiresWrap: the wrapped (default) path errors clearly when no
// Wrap is injected, rather than writing an unusable identity — and leaves no files.
func TestProvisionWrappedRequiresWrap(t *testing.T) {
	dir := t.TempDir()
	if _, err := Provision(Options{Dir: dir}); err == nil {
		t.Fatal("expected an error when Wrap is nil and !Plaintext")
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.age")); !os.IsNotExist(err) {
		t.Fatalf("vault.age should not be written when Wrap is missing, stat err = %v", err)
	}
}
