// Package provision creates the local age store for `av setup`: a fresh X25519 identity
// (Secure-Enclave-wrapped by default) plus an empty age vault. It is linked only by avd,
// never by the thin av — so the Wrap step is INJECTED (avd passes enclave.Wrap; tests
// pass a stub), keeping this package free of the cgo enclave import. SECURITY: the
// identity bytes and vault contents are never logged nor returned in an error — only the
// on-disk paths are. Writes are atomic (temp + fsync + rename) so a crash never leaves a
// partial identity or vault.
package provision

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/config"
)

// Options configures a provisioning run. A zero Options provisions the default config
// dir with an Enclave-wrapped identity (and so requires Wrap to be set).
type Options struct {
	// Dir is the store directory; empty means config.DefaultConfigDir().
	Dir string
	// Rotate forces a fresh identity + empty vault even if a store already exists.
	Rotate bool
	// Plaintext writes the identity unwrapped to identity.txt instead of the
	// Enclave-wrapped identity.enc (the escape hatch for hosts without an Enclave).
	Plaintext bool
	// Wrap seals the identity bytes (enclave.Wrap in production, a stub in tests). It is
	// REQUIRED unless Plaintext is set; injected so this package needs no enclave import.
	Wrap func([]byte) ([]byte, error)
}

// Result reports the on-disk paths and whether files were created this call. SECURITY:
// it carries paths + a bool only — never the identity bytes or vault contents.
type Result struct {
	VaultPath    string
	IdentityPath string
	Created      bool
}

// Provision creates (or, when idempotent, reports) the local age store. Behavior:
//   - Resolve the dir (Options.Dir or the config default) and ensure it exists (0700).
//   - IDEMPOTENT: if both the vault and the identity already exist and !Rotate, return
//     their paths with Created:false and touch nothing.
//   - Otherwise generate a fresh X25519 identity, write the identity (wrapped to
//     identity.enc by default, or plaintext to identity.txt), and write an EMPTY age
//     vault encrypted to that identity's recipient. Both writes are atomic (0600).
func Provision(o Options) (Result, error) {
	dir := o.Dir
	if dir == "" {
		dir = config.DefaultConfigDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Result{}, fmt.Errorf("create store dir: %w", err)
	}

	vaultPath := filepath.Join(dir, "vault.age")
	idPath := filepath.Join(dir, "identity.enc")
	if o.Plaintext {
		idPath = filepath.Join(dir, "identity.txt")
	}

	// Idempotency: a fully provisioned store (both files present) is left untouched
	// unless the caller asks to Rotate. We re-provision when EITHER file is missing, so a
	// half-written store (only one file) is completed rather than reported as done.
	if !o.Rotate && fileExists(vaultPath) && fileExists(idPath) {
		return Result{VaultPath: vaultPath, IdentityPath: idPath, Created: false}, nil
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		return Result{}, fmt.Errorf("generate identity: %w", err)
	}
	// age.ParseIdentities (the reader on unlock/decrypt) expects newline-terminated lines.
	idBytes := []byte(id.String() + "\n")

	// Write the identity FIRST. If we wrote the vault first and then failed on the
	// identity, the store would have a vault no reader could ever open.
	if o.Plaintext {
		if err := writeAtomic(idPath, idBytes); err != nil {
			// SECURITY: the path-only error never includes idBytes.
			return Result{}, fmt.Errorf("write identity: %w", err)
		}
	} else {
		if o.Wrap == nil {
			return Result{}, fmt.Errorf("wrap required for Enclave identity (use Plaintext for an unwrapped store)")
		}
		blob, err := o.Wrap(idBytes)
		if err != nil {
			return Result{}, fmt.Errorf("wrap identity: %w", err)
		}
		if err := writeAtomic(idPath, blob); err != nil {
			return Result{}, fmt.Errorf("write identity: %w", err)
		}
	}

	// Write an EMPTY vault encrypted to the new identity's recipient. We reuse
	// agefile.EncryptVault (SSOT for the vault's on-disk format) and stage it to a temp
	// file, then fsync+rename so the live vault is never partially written.
	if err := writeVaultAtomic(vaultPath, id.Recipient()); err != nil {
		return Result{}, err
	}

	return Result{VaultPath: vaultPath, IdentityPath: idPath, Created: true}, nil
}

// fileExists reports whether path is an existing (regular or any) file. A stat error
// other than not-exist is treated as "exists" so we never silently clobber on a transient
// error — Rotate is the explicit way to overwrite.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// writeAtomic writes data to path via a UNIQUE temp file in the SAME dir (so the rename
// is atomic on one filesystem), fsyncing before the rename and removing the temp on any
// error so a partial file never lingers. The temp name is os.CreateTemp(<base>.tmp-*),
// NOT a fixed "<path>.tmp", so two concurrent `av setup` runs can't truncate each other's
// staging file. Mode is 0600 — the identity is secret material (CreateTemp opens 0600).
func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := os.Chmod(tmp, 0o600); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// writeVaultAtomic encrypts an empty name->value map to a UNIQUE temp file via
// agefile.EncryptVault, fsyncs, then renames it over the vault path (atomic). The temp
// name is os.CreateTemp(<base>.tmp-*), NOT a fixed "<path>.tmp", so two concurrent
// `av setup` runs can't truncate each other's staging vault. On any error before the
// rename it removes the temp so no partial vault is left behind.
// SECURITY: errors carry the path only — never the (empty here) vault contents.
func writeVaultAtomic(vaultPath string, recipient age.Recipient) error {
	f, err := os.CreateTemp(filepath.Dir(vaultPath), filepath.Base(vaultPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp vault: %w", err)
	}
	tmp := f.Name()
	if err := os.Chmod(tmp, 0o600); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("chmod temp vault: %w", err)
	}
	if err := agefile.EncryptVault(f, recipient, map[string]string{}); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("encrypt vault: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("fsync temp vault: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close temp vault: %w", err)
	}
	if err := os.Rename(tmp, vaultPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename temp vault: %w", err)
	}
	syncDir(filepath.Dir(vaultPath))
	return nil
}

// syncDir best-effort fsyncs a directory so a rename within it is durable across a crash.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
