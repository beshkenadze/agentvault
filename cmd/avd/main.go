// Command avd is the AgentVault broker daemon.
package main

import (
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/audit"
	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/backend/keychain"
	"github.com/beshkenadze/agentvault/internal/backend/onepassword"
	"github.com/beshkenadze/agentvault/internal/daemon"
	"github.com/beshkenadze/agentvault/internal/detect/gitleaks"
	"github.com/beshkenadze/agentvault/internal/enclave"
	"github.com/beshkenadze/agentvault/internal/transport"
)

func main() {
	path, err := transport.DefaultSocketPath()
	if err != nil {
		log.Fatalf("avd: socket path: %v", err)
	}
	srv, err := daemon.New(path)
	if err != nil {
		log.Fatalf("avd: listen: %v", err)
	}

	// Wire the resolver so `resolve` can broker secrets and `scrub` can mask them
	// against the same session. cmd/avd only assembles plumbing — it never reads a
	// secret value itself; the agefile backend decrypts inside avd on demand.
	reg := backend.NewRegistry()
	registerBackends(reg)
	// daemon.DefaultTTL is the single source of truth for the session window: the
	// same const the unlock RPC uses (server.go), so the session TTL and the unlock
	// duration can never drift. Issued values clear after this window; auto-lock on
	// screen-lock/sleep (StartAutoLock below, landed in Phase 5) re-locks earlier.
	sess := daemon.NewSession(daemon.DefaultTTL)

	// Layer-2 net: wire the gitleaks detector into the session so scrub catches
	// DERIVED secrets the daemon never issued and dangerous-tier values that are never
	// cached (exact-match issued values are the split-safe layer-1 streaming tier).
	// gitleaks stays in avd's path ONLY — the thin av never links it. A build failure
	// here is fatal: avd must not run with a broken layer-2 net (the construction error
	// carries no secret material).
	det, err := gitleaks.New()
	if err != nil {
		log.Fatalf("avd: gitleaks detector: %v", err)
	}
	sess.WithDetector(det)

	// One presence instance is shared by BOTH the unlock RPC (SetPresence) and the
	// dangerous-tier resolver (NewResolver), so unlock and dangerous-tier resolve go
	// through the same auth seam. Production uses real Touch ID; AV_TEST_AUTH=allow
	// selects the env-gated stub so e2e/CI stay automatable without a biometric prompt.
	presence := selectPresence()

	// Append-only audit log (default-on for the real daemon): one metadata-only entry
	// per dangerous touch — issuance, unlock, lock, rate-limit alert, denied access. It
	// lives alongside the socket (user dir, 0600). SECURITY: only names/tiers/profiles/
	// reasons are written — NEVER a value (audit.Event has no value field). On open
	// failure we fall back to the NopLogger rather than refuse to start: audit is
	// defense-in-depth, not a hard dependency of brokering.
	auditLog := openAuditLog(path)
	srv.SetResolver(daemon.NewResolver(reg, presence, sess, daemon.WithAudit(auditLog)))
	srv.SetPresence(presence)
	srv.SetAudit(auditLog)

	// Auto-lock observers (screen-lock/sleep on darwin; no-op elsewhere) re-lock the
	// SAME session. stop() removes them on shutdown.
	stopAutoLock := daemon.StartAutoLock(sess)

	go srv.Serve()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	stopAutoLock()
	srv.Close()
	if c, ok := auditLog.(io.Closer); ok {
		c.Close() // flush/close the audit fd (NopLogger is not a Closer)
	}
	os.Remove(path)
}

// selectPresence returns the presence the daemon authorizes with: the env-gated
// stub when AV_TEST_AUTH=allow (e2e/CI, no biometric prompt), otherwise the real
// Touch ID backend. A missing Touch ID backend (e.g. a non-darwin/non-cgo build)
// is fatal — avd must never run without a real presence check in production.
//
// SECURITY: nothing here logs a secret value; only the selection and any
// construction error (which carries no key material) are logged.
func selectPresence() daemon.Presence {
	if os.Getenv("AV_TEST_AUTH") == "allow" {
		log.Printf("avd: using stub presence (AV_TEST_AUTH=allow)")
		return daemon.NewStubPresence()
	}
	p, err := daemon.NewTouchIDPresence()
	if err != nil {
		log.Fatalf("avd: presence: %v", err)
	}
	return p
}

// openAuditLog opens the append-only audit log next to the socket (audit.jsonl in the
// same user dir, which daemon.New already created 0700). On any open error it logs the
// reason (no key material) and returns a NopLogger so the daemon still runs — audit is
// defense-in-depth, never a blocker for brokering.
func openAuditLog(socketPath string) audit.Logger {
	auditPath := filepath.Join(filepath.Dir(socketPath), "audit.jsonl")
	l, err := audit.NewFileLogger(auditPath)
	if err != nil {
		log.Printf("avd: audit log disabled: %v", err)
		return audit.NopLogger{}
	}
	log.Printf("avd: audit log enabled")
	return l
}

// registerBackends registers the secret backends. The age-file backend ("file") is
// wired only when AV_AGE_VAULT is set AND an age identity can be obtained; if not it
// is skipped (the daemon still runs, and a resolve of av://file/... returns a "no
// backend registered" error). The 1Password backend ("1p") is registered
// UNCONDITIONALLY: it is lazy — it never touches the `op` binary at registration time,
// only on Resolve — so wiring it costs nothing until a av://1p/... ref is resolved
// (which then requires `op` installed + signed in; see internal/backend/onepassword).
// It logs which ids were registered to the daemon's own stderr — NEVER a secret value.
//
// IDENTITY PRECEDENCE (the seam Phase 6 fills with the Secure Enclave):
//  1. AV_AGE_IDENTITY_ENCLAVE (HARDENED, preferred): a path to a wrapped-identity
//     BLOB produced by enclave.Wrap. The age key is unwrapped on demand via
//     enclave.Unwrap, which triggers a LIVE Touch ID (user-presence ACL) — so even
//     a daemon compromise can't decrypt the vault without the user present. This
//     REPLACES the plaintext-on-disk identity. (Requires a darwin+cgo build on
//     Secure Enclave hardware; on any other build enclave.Unwrap returns the
//     "unavailable" error and the file backend is skipped — it does NOT silently
//     fall back to plaintext, because the operator explicitly asked for the
//     hardened path.)
//  2. AV_AGE_IDENTITY (FALLBACK, Phase 5/4 default): a path to a plaintext age
//     identity file. Used only when AV_AGE_IDENTITY_ENCLAVE is unset. This keeps
//     the daemon runnable on non-Enclave setups (and in CI/e2e).
//
// SECURITY: the age identity is loaded here only to construct the backend; the
// plaintext vault is decrypted lazily inside the backend on each Resolve. The
// unwrapped identity bytes never appear in a log or error; identity-loading errors
// carry only a path/reason or an OSStatus, never key material.
func registerBackends(reg *backend.Registry) {
	registered := []string{}

	vaultPath := os.Getenv("AV_AGE_VAULT")
	enclavePath := os.Getenv("AV_AGE_IDENTITY_ENCLAVE")
	idPath := os.Getenv("AV_AGE_IDENTITY")
	switch {
	case vaultPath == "" || (enclavePath == "" && idPath == ""):
		log.Printf("avd: no file backend (set AV_AGE_VAULT and AV_AGE_IDENTITY_ENCLAVE [hardened] or AV_AGE_IDENTITY [plaintext] to enable)")
	default:
		id, err := loadFileBackendIdentity(enclavePath, idPath)
		if err != nil {
			// The error carries only a path/reason or an OSStatus, never key material.
			log.Printf("avd: file backend disabled: %v", err)
		} else {
			// Wrap the (plaintext or Enclave-unwrapped) identity in a Static source for
			// now — the backend fetches it per operation via the IdentitySource seam.
			// Task 6 replaces the Enclave path's Static with the daemon session, so the
			// key lives in the session (zeroized on lock) rather than held here.
			reg.Register("file", agefile.New(agefile.Static{ID: id}, vaultPath))
			registered = append(registered, "file")
		}
	}

	// Lazy: registering does not invoke `op`. Resolve of av://1p/... shells out to the
	// real `op read` and needs `op` installed + signed in (verified manually, not in CI).
	reg.Register("1p", onepassword.New())
	registered = append(registered, "1p")

	// Lazy: registering does not invoke `security`. Resolve of av://keychain/... shells
	// out to the real `security find-generic-password` and needs macOS + a populated
	// keychain (verified manually, not in CI). On non-darwin builds keychain.New() is the
	// stub whose Resolve errors "requires macOS", so registration is safe everywhere.
	reg.Register("keychain", keychain.New())
	registered = append(registered, "keychain")

	log.Printf("avd: registered backends: %s", strings.Join(registered, " "))
}

// loadFileBackendIdentity resolves the age identity for the file backend following
// the precedence documented on registerBackends: the Secure-Enclave-wrapped blob
// (hardened) wins when AV_AGE_IDENTITY_ENCLAVE is set; otherwise the plaintext
// AV_AGE_IDENTITY file (fallback). Exactly one source is consulted — the hardened
// path never silently degrades to plaintext.
func loadFileBackendIdentity(enclavePath, idPath string) (age.Identity, error) {
	if enclavePath != "" {
		log.Printf("avd: file backend identity: Secure Enclave (hardened; Touch ID on first resolve)")
		return loadEnclaveIdentity(enclavePath)
	}
	log.Printf("avd: file backend identity: plaintext file (fallback; set AV_AGE_IDENTITY_ENCLAVE to harden)")
	return loadAgeIdentity(idPath)
}

// loadEnclaveIdentity reads a wrapped-identity blob from disk, unwraps it with the
// Secure Enclave (enclave.Unwrap triggers Touch ID via the key's user-presence ACL),
// and parses the recovered bytes as an age identity. On a non-Enclave build, or if
// the Enclave is unreachable / the user denies, enclave.Unwrap returns a value-free
// error and the file backend is skipped.
//
// SECURITY: the unwrapped bytes are only handed to age.ParseIdentities; they are
// never logged. Errors carry a path or an OSStatus, never key material.
func loadEnclaveIdentity(path string) (age.Identity, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	plaintext, err := enclave.Unwrap(blob)
	if err != nil {
		return nil, err
	}
	ids, err := age.ParseIdentities(strings.NewReader(string(plaintext)))
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errNoIdentity
	}
	return ids[0], nil
}

// loadAgeIdentity reads an age identity file and returns its first identity.
// age.ParseIdentities(io.Reader) ([]age.Identity, error) parses the standard age
// identity file format (one "AGE-SECRET-KEY-..." per line, '#'-comments allowed).
func loadAgeIdentity(path string) (age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errNoIdentity
	}
	return ids[0], nil
}

// errNoIdentity is returned when the identity file parses but contains no identity.
var errNoIdentity = ageError("no age identity found in AV_AGE_IDENTITY file")

// ageError is a tiny no-secret error type for identity-loading failures.
type ageError string

func (e ageError) Error() string { return string(e) }
