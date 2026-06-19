// Package agefile implements an age-encrypted-file Backend. The plaintext is a JSON
// object mapping logical names to secret values. The age identity is injected (Phase 6
// wraps it in the Secure Enclave). Isolated package: keeps filippo.io/age out of av.
package agefile

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"filippo.io/age"
	"github.com/beshkenadze/agentvault/internal/backend"
)

// IdentitySource yields the age identity the file backend decrypts/encrypts with, or an
// error (e.g. daemon.ErrLocked when the session is locked). The backend fetches it PER
// operation rather than holding it, so the key can live in the daemon session — unwrapped
// from the Secure Enclave on unlock and zeroized on lock — instead of sitting in the
// backend for the daemon's whole lifetime. A nil identity with a non-nil error must
// SURFACE that error (Resolve/Add/Remove), never be swallowed as "empty vault".
type IdentitySource interface {
	Identity() (age.Identity, error)
}

// Static wraps a fixed identity as an IdentitySource. It preserves the old held-identity
// behavior for the plaintext / env path and for tests; Identity never errors.
type Static struct{ ID age.Identity }

// Identity returns the wrapped fixed identity (never an error).
func (s Static) Identity() (age.Identity, error) { return s.ID, nil }

// Backend decrypts an age file on each call and resolves a name -> value lookup.
type Backend struct {
	src  IdentitySource
	path string
	// wmu serializes Add/Remove. Each is a load→modify→write-then-rename sequence;
	// without it, two concurrent writers each load a snapshot and rename their whole
	// map over the file, dropping the other's entry (lost update). The daemon is the
	// single writer (single-instance flock), so an in-process mutex is sufficient.
	wmu sync.Mutex
}

// New returns a backend that decrypts path with the identity src yields per operation.
func New(src IdentitySource, path string) *Backend {
	return &Backend{src: src, path: path}
}

// EncryptVault age-encrypts a name -> value map to w for recipient. It is the inverse
// of load: the plaintext is the JSON object the Backend decrypts. Phase 6's `av add`
// uses it to write the vault; tests use it instead of duplicating the encrypt logic.
func EncryptVault(w io.Writer, recipient age.Recipient, data map[string]string) error {
	plain, err := json.Marshal(data)
	if err != nil {
		return err
	}
	aw, err := age.Encrypt(w, recipient)
	if err != nil {
		return err
	}
	if _, err := aw.Write(plain); err != nil {
		return err
	}
	return aw.Close()
}

func (b *Backend) load() (map[string]string, error) {
	// Fetch the identity per operation; if the source is locked/errored, SURFACE the
	// error so the caller can distinguish "can't decrypt right now" from "no such secret"
	// (fail-closed, not fail-open). It is read before opening the file so a locked source
	// fails fast without touching the vault on disk.
	id, err := b.src.Identity()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(b.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, id)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", b.path, err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var data map[string]string
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, fmt.Errorf("parse vault plaintext: %w", err)
	}
	return data, nil
}

// Add sets name->value in the vault and atomically rewrites the encrypted file.
// SECURITY: value is the only secret in flight here; it is never logged and never
// reaches an error. The vault is re-encrypted to the SAME recipient (derived from
// the injected identity), so the file the daemon decrypts on every Resolve keeps the
// same single reader. The write is atomic (temp + fsync + rename), so a crash mid-
// write never leaves a partial/corrupt live vault.
func (b *Backend) Add(name, value string) error {
	b.wmu.Lock()
	defer b.wmu.Unlock()
	data, err := b.load()
	if err != nil {
		return err
	}
	data[name] = value
	return b.writeVault(data)
}

// Remove deletes name from the vault and atomically rewrites it. It returns
// backend.ErrNotFound if the name is absent, so the caller learns nothing was
// removed rather than seeing a silent no-op.
func (b *Backend) Remove(name string) error {
	b.wmu.Lock()
	defer b.wmu.Unlock()
	data, err := b.load()
	if err != nil {
		return err
	}
	if _, ok := data[name]; !ok {
		return backend.ErrNotFound
	}
	delete(data, name)
	return b.writeVault(data)
}

// writeVault atomically re-encrypts data to the vault path: it derives the recipient
// from the injected identity, encrypts to a temp file in the SAME dir, fsyncs, then
// os.Renames over the live vault (atomic on one filesystem). On ANY error before the
// rename it removes the temp and returns — the live vault is never partially written.
// SECURITY: the plaintext map (carrying secret values) only lives in the temp file's
// ciphertext; no value is ever logged or wrapped in an error.
func (b *Backend) writeVault(data map[string]string) error {
	recipient, err := b.recipient()
	if err != nil {
		return err
	}
	dir := filepath.Dir(b.path)
	tmp := b.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create temp vault: %w", err)
	}
	// From here on, any failure must remove the temp so a corrupt sidecar never lingers.
	if err := EncryptVault(f, recipient, data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
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
	if err := os.Rename(tmp, b.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename temp vault: %w", err)
	}
	// Best-effort fsync of the directory so the rename itself is durable across a crash.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// recipient derives the age recipient the vault must be (re-)encrypted to from the
// source's identity. It fetches the identity per operation and SURFACES a source error
// (e.g. locked session) before type-asserting. The file backend's identity is an
// *age.X25519Identity (both the plaintext-file and the Secure-Enclave-unwrapped paths
// parse via age.ParseIdentities, which yields X25519). A non-X25519 identity cannot yield
// an X25519 recipient, so we error CLEARLY rather than silently writing a vault no reader
// can open.
func (b *Backend) recipient() (age.Recipient, error) {
	id, err := b.src.Identity()
	if err != nil {
		return nil, err
	}
	x, ok := id.(*age.X25519Identity)
	if !ok {
		return nil, fmt.Errorf("agefile: cannot derive recipient: identity is %T, not *age.X25519Identity", id)
	}
	return x.Recipient(), nil
}

func (b *Backend) Resolve(locator string) (backend.Secret, error) {
	data, err := b.load()
	if err != nil {
		return backend.Secret{}, err
	}
	v, ok := data[locator]
	if !ok {
		return backend.Secret{}, backend.ErrNotFound
	}
	return backend.Secret{Value: v}, nil
}

func (b *Backend) List(prefix string) ([]backend.Meta, error) {
	data, err := b.load()
	if err != nil {
		return nil, err
	}
	var out []backend.Meta
	for k := range data {
		if prefix == "" || (len(k) >= len(prefix) && k[:len(prefix)] == prefix) {
			out = append(out, backend.Meta{Locator: k})
		}
	}
	return out, nil
}

// compile-time checks that Backend satisfies the read AND write interfaces. agefile is
// the ONLY backend that implements backend.Writer (it owns the vault end-to-end), so
// `av add`/`av rm` reach it via registry.Writer while read-only backends are rejected.
var (
	_ backend.Backend = (*Backend)(nil)
	_ backend.Writer  = (*Backend)(nil)
)
