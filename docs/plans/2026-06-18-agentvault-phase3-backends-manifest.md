# AgentVault Phase 3 — Backends + Manifest Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or subagent-driven-development) to implement this plan task-by-task.

**Goal:** Resolve a logical secret name to a value through pluggable, compiled-in backends — built and proven as isolated libraries, before wiring them into the daemon's resolve RPC (Phase 4). End state: given an `agentvault.yaml` and a backend (mock or age-file), the code can turn a profile entry's `av://…` reference into a secret value, with metadata-only listing that never returns values.

**Architecture:** Three small packages. `internal/backend` defines the `Backend` interface, the `av://` reference parser, the `Secret`/`Meta` value types, and a `Registry` that dispatches a ref to the right backend. `internal/backend/agefile` is the first real backend (an `age`-encrypted file), kept in its own package so its `filippo.io/age` dependency never reaches the thin `av` binary. `internal/manifest` parses `agentvault.yaml` (profiles → entries → ref+tier). All testable in isolation with a mock backend; no daemon/RPC wiring yet (that is Phase 4).

**Tech Stack:** Go 1.26.3, stdlib + `gopkg.in/yaml.v3` (manifest, pure-Go, light) + `filippo.io/age` (age-file backend only; pulls `golang.org/x/crypto`/`x/sys` — light, not a gitleaks-scale tree). Module `github.com/beshkenadze/agentvault`. macOS-targeted but these packages are platform-neutral.

**Scope:** Phase 3 only. Phases 1 (redaction core) and 2 (IPC skeleton) are complete on `main`. Deferred to **Phase 4**: wiring resolve over IPC, the session/TTL, `av run` env-injection + redaction layers, and the `AV_TEST_AUTH=allow` auth stub (auth only becomes a gate once resolve is wired). Deferred to **Phase 6**: loading the age identity from a Secure-Enclave-wrapped key, and the `av add/rm` management CLI.

**Design reference:** `docs/plans/2026-06-17-agentvault-design.md` — *Backends and manifest*.

**Carry-forward from Phase 1 & 2 reviews (apply throughout):**
- **Dependency isolation is CI-enforced.** The thin `av` binary must not link the heavy gitleaks tree (existing `cmd/av/deps_test.go` guard). Backends live in `avd`'s path: `cmd/av` must NOT import `internal/backend/agefile` (or any backend impl). Task 5 extends the guard so `av` links neither `gitleaks` nor `filippo.io/age`.
- **Commit on `main`** (no feature branches/worktrees) — past subagents created branches that had to be hand-merged. Each task: TDD red→green→commit.
- **Use SHORT temp paths** in tests that touch the filesystem near sockets (not relevant here, but keep `os.MkdirTemp("/tmp", …)` habit for any path work).
- **1Password may lock mid-run.** If `git commit` fails with a signing/buffer error, use `git -c commit.gpgsign=false commit …` (never `--no-verify`) and report the unsigned SHA for later re-signing. (Known unsigned so far: `45af884`.)
- **Fail loud, never silently truncate/drop a secret.** `List` must never return values; `Resolve` of a missing key must error, not return empty.

---

## Task 1: Backend interface, ref parser, value types, Registry (`internal/backend`)

**Files:**
- Create: `internal/backend/backend.go`
- Create: `internal/backend/ref.go`
- Create: `internal/backend/registry.go`
- Test: `internal/backend/ref_test.go`
- Test: `internal/backend/registry_test.go`

**Step 1: Write the failing ref-parser test**

`internal/backend/ref_test.go`:
```go
package backend

import "testing"

func TestParseRef(t *testing.T) {
	cases := []struct {
		in       string
		wantBE   string
		wantLoc  string
	}{
		{"av://1p/Eng/GitHub CI/token", "1p", "Eng/GitHub CI/token"},
		{"av://file/GITHUB_TOKEN", "file", "GITHUB_TOKEN"},
		{"av://keychain/av/STRIPE", "keychain", "av/STRIPE"},
	}
	for _, c := range cases {
		ref, err := ParseRef(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if ref.Backend != c.wantBE || ref.Locator != c.wantLoc {
			t.Errorf("%s -> %+v, want backend=%q locator=%q", c.in, ref, c.wantBE, c.wantLoc)
		}
	}
}

func TestParseRefRejectsBad(t *testing.T) {
	for _, bad := range []string{"", "1p/x", "http://x/y", "av://", "av://onlybackend"} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}
```

**Step 2: Run it, verify it fails**

Run: `go test ./internal/backend/ -run TestParseRef -v`
Expected: FAIL — `ParseRef`/`Ref` undefined.

**Step 3: Implement value types + ref parser**

`internal/backend/backend.go`:
```go
// Package backend defines AgentVault's secret-backend interface, the av:// reference
// scheme, and a registry that dispatches references to compiled-in backends. Backend
// IMPLEMENTATIONS live in sub-packages so their dependencies stay out of the thin av.
package backend

// Secret is a resolved secret value. Phase 6 will back Value with memguard-protected
// memory; for now it is a plain string held only transiently.
type Secret struct {
	Value string
}

// Meta is metadata about a secret entry — never the value. Used by List.
type Meta struct {
	Locator string
}

// Backend fetches one secret value by its backend-specific locator (the part of an
// av:// reference after the backend id), and lists metadata only.
type Backend interface {
	Resolve(locator string) (Secret, error)
	List(prefix string) ([]Meta, error)
}
```

`internal/backend/ref.go`:
```go
package backend

import (
	"fmt"
	"strings"
)

// Ref is a parsed av:// reference: a backend id and a backend-specific locator.
type Ref struct {
	Backend string
	Locator string
}

const scheme = "av://"

// ParseRef parses "av://<backend>/<locator...>". The locator may contain slashes
// and spaces; only the first path segment is the backend id.
func ParseRef(s string) (Ref, error) {
	if !strings.HasPrefix(s, scheme) {
		return Ref{}, fmt.Errorf("not an av:// reference: %q", s)
	}
	rest := strings.TrimPrefix(s, scheme)
	be, loc, ok := strings.Cut(rest, "/")
	if !ok || be == "" || loc == "" {
		return Ref{}, fmt.Errorf("malformed reference (want av://backend/locator): %q", s)
	}
	return Ref{Backend: be, Locator: loc}, nil
}
```

**Step 4: Run the ref tests, verify pass**

Run: `go test ./internal/backend/ -run TestParseRef -v` → PASS.

**Step 5: Write the failing Registry test (with a mock backend)**

`internal/backend/registry_test.go`:
```go
package backend

import (
	"testing"
)

// mockBackend is an in-memory backend for tests.
type mockBackend struct{ data map[string]string }

func (m *mockBackend) Resolve(loc string) (Secret, error) {
	v, ok := m.data[loc]
	if !ok {
		return Secret{}, ErrNotFound
	}
	return Secret{Value: v}, nil
}
func (m *mockBackend) List(prefix string) ([]Meta, error) {
	var out []Meta
	for k := range m.data {
		if len(prefix) == 0 || (len(k) >= len(prefix) && k[:len(prefix)] == prefix) {
			out = append(out, Meta{Locator: k})
		}
	}
	return out, nil
}

func TestRegistryResolve(t *testing.T) {
	r := NewRegistry()
	r.Register("mock", &mockBackend{data: map[string]string{"TOKEN": "s3cr3t"}})

	got, err := r.Resolve("av://mock/TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "s3cr3t" {
		t.Fatalf("value = %q, want s3cr3t", got.Value)
	}
}

func TestRegistryUnknownBackend(t *testing.T) {
	r := NewRegistry()
	if _, err := r.Resolve("av://nope/X"); err == nil {
		t.Fatal("expected error for unregistered backend")
	}
}

func TestRegistryListNoValues(t *testing.T) {
	r := NewRegistry()
	r.Register("mock", &mockBackend{data: map[string]string{"A": "1", "B": "2"}})
	metas, err := r.List("mock", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("got %d metas, want 2", len(metas))
	}
	// Meta has no value field — compile-time guarantee values aren't leaked by List.
}
```

**Step 6: Run, verify fails**

Run: `go test ./internal/backend/ -run TestRegistry -v` → FAIL (NewRegistry/ErrNotFound undefined).

**Step 7: Implement Registry**

`internal/backend/registry.go`:
```go
package backend

import (
	"errors"
	"fmt"
)

// ErrNotFound is returned by a backend when a locator has no value.
var ErrNotFound = errors.New("secret not found")

// Registry dispatches av:// references to registered backends by backend id.
type Registry struct {
	backends map[string]Backend
}

func NewRegistry() *Registry {
	return &Registry{backends: map[string]Backend{}}
}

// Register adds a backend under an id (e.g. "file", "1p", "keychain").
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
```

**Step 8: Run all backend tests, vet**

Run: `go test ./internal/backend/ -v` → PASS. `go vet ./...`.

**Step 9: Commit**

```bash
git add internal/backend/
git commit -m "feat(backend): Backend interface, av:// ref parser, registry, mock"
```

---

## Task 2: Manifest parser (`internal/manifest`)

Parses `agentvault.yaml`: profiles → entries (logical name → ref + tier). Validates tiers.

**Files:**
- Create: `internal/manifest/manifest.go`
- Test: `internal/manifest/manifest_test.go`
- Test data: `internal/manifest/testdata/agentvault.yaml`
- Modify: `go.mod`/`go.sum` (add `gopkg.in/yaml.v3`)

**Step 1: Add the dependency**

Run: `go get gopkg.in/yaml.v3@latest` (pure-Go, light — confirm it pulls nothing heavy).

**Step 2: Create test data**

`internal/manifest/testdata/agentvault.yaml`:
```yaml
profiles:
  smoke:
    GITHUB_TOKEN:
      ref: av://file/GITHUB_TOKEN
      tier: normal
    STRIPE_SECRET:
      ref: av://file/STRIPE_SECRET
      tier: dangerous
```

**Step 3: Write the failing test**

`internal/manifest/manifest_test.go`:
```go
package manifest

import (
	"path/filepath"
	"testing"
)

func TestLoadProfile(t *testing.T) {
	m, err := Load(filepath.Join("testdata", "agentvault.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p, ok := m.Profile("smoke")
	if !ok {
		t.Fatal("smoke profile missing")
	}
	gh, ok := p["GITHUB_TOKEN"]
	if !ok {
		t.Fatal("GITHUB_TOKEN missing")
	}
	if gh.Ref != "av://file/GITHUB_TOKEN" || gh.Tier != TierNormal {
		t.Fatalf("bad entry: %+v", gh)
	}
	if p["STRIPE_SECRET"].Tier != TierDangerous {
		t.Fatalf("STRIPE tier = %v, want dangerous", p["STRIPE_SECRET"].Tier)
	}
}

func TestRejectsUnknownTier(t *testing.T) {
	const bad = "profiles:\n  p:\n    X:\n      ref: av://file/X\n      tier: bogus\n"
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("expected error for unknown tier")
	}
}

func TestRejectsMissingRef(t *testing.T) {
	const bad = "profiles:\n  p:\n    X:\n      tier: normal\n"
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("expected error for missing ref")
	}
}
```

**Step 4: Run, verify fails**

Run: `go test ./internal/manifest/ -v` → FAIL (undefined).

**Step 5: Implement**

`internal/manifest/manifest.go`:
```go
// Package manifest parses agentvault.yaml: profiles mapping logical names to a
// backend reference and an access tier. It holds no secret values.
package manifest

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Tier is the access tier of an entry.
type Tier string

const (
	TierNormal    Tier = "normal"
	TierDangerous Tier = "dangerous"
)

// Entry maps a logical env name to a backend reference and a tier.
type Entry struct {
	Ref  string `yaml:"ref"`
	Tier Tier   `yaml:"tier"`
}

// Profile is the set of entries activated together (logical name -> entry).
type Profile map[string]Entry

// Manifest is the parsed agentvault.yaml.
type Manifest struct {
	Profiles map[string]Profile `yaml:"profiles"`
}

func Load(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func Parse(b []byte) (*Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	for pname, p := range m.Profiles {
		for name, e := range p {
			if e.Ref == "" {
				return fmt.Errorf("profile %q entry %q: missing ref", pname, name)
			}
			if e.Tier != TierNormal && e.Tier != TierDangerous {
				return fmt.Errorf("profile %q entry %q: invalid tier %q (want normal|dangerous)", pname, name, e.Tier)
			}
		}
	}
	return nil
}

func (m *Manifest) Profile(name string) (Profile, bool) {
	p, ok := m.Profiles[name]
	return p, ok
}
```

**Step 6: Run, verify pass; vet**

Run: `go test ./internal/manifest/ -v` → PASS. `go vet ./...`.

**Step 7: Commit**

```bash
git add internal/manifest/ go.mod go.sum
git commit -m "feat(manifest): parse agentvault.yaml profiles with tier validation"
```

---

## Task 3: age-file backend (`internal/backend/agefile`)

An `age`-encrypted file whose plaintext is a JSON object of `name -> value`. The age identity (private key) is injected (Phase 6 wraps it in the Secure Enclave). Kept in its own package so `filippo.io/age` never reaches `av`.

**Files:**
- Create: `internal/backend/agefile/agefile.go`
- Test: `internal/backend/agefile/agefile_test.go`
- Modify: `go.mod`/`go.sum` (add `filippo.io/age`)

JSON (not dotenv) is used for the plaintext so secret values containing newlines/`=`/quotes round-trip safely.

**Step 1: Add the dependency**

Run: `go get filippo.io/age@latest` (pulls `golang.org/x/crypto`, `x/sys` — light; confirm no gitleaks-scale tree).

**Step 2: Write the failing test**

`internal/backend/agefile/agefile_test.go`:
```go
package agefile

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/beshkenadze/agentvault/internal/backend"
)

// writeEncrypted age-encrypts a name->value map to path for the given recipient.
func writeEncrypted(t *testing.T, path string, id *age.X25519Identity, data map[string]string) {
	t.Helper()
	plain, _ := json.Marshal(data)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := age.Encrypt(f, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestResolveAndList(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{
		"GITHUB_TOKEN": "ghp_value",
		"STRIPE_SECRET": "sk_live_value",
	})

	b := New(id, path)

	got, err := b.Resolve("GITHUB_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "ghp_value" {
		t.Fatalf("value = %q", got.Value)
	}

	if _, err := b.Resolve("MISSING"); err != backend.ErrNotFound {
		t.Fatalf("missing key err = %v, want ErrNotFound", err)
	}

	metas, err := b.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("got %d metas, want 2", len(metas))
	}
	// List must not expose values (Meta has no Value field — compile-time guard).
	_ = bytes.TrimSpace
}

func TestWrongIdentityFails(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{"X": "y"})

	b := New(other, path) // wrong identity
	if _, err := b.Resolve("X"); err == nil {
		t.Fatal("expected decryption failure with wrong identity")
	}
}
```

**Step 3: Run, verify fails**

Run: `go test ./internal/backend/agefile/ -v` → FAIL (New undefined).

**Step 4: Implement**

`internal/backend/agefile/agefile.go`:
```go
// Package agefile implements an age-encrypted-file Backend. The plaintext is a JSON
// object mapping logical names to secret values. The age identity is injected (Phase 6
// wraps it in the Secure Enclave). Isolated package: keeps filippo.io/age out of av.
package agefile

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"github.com/beshkenadze/agentvault/internal/backend"
)

// Backend decrypts an age file on each call and resolves a name -> value lookup.
type Backend struct {
	id   age.Identity
	path string
}

// New returns a backend that decrypts path with id.
func New(id age.Identity, path string) *Backend {
	return &Backend{id: id, path: path}
}

func (b *Backend) load() (map[string]string, error) {
	f, err := os.Open(b.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, b.id)
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

// compile-time check that Backend satisfies the interface.
var _ backend.Backend = (*Backend)(nil)
```

**Step 5: Run, verify pass; vet; build**

Run: `go test ./internal/backend/agefile/ -v` → PASS. `go vet ./...`. `go build ./...`.

**Step 6: Commit**

```bash
git add internal/backend/agefile/ go.mod go.sum
git commit -m "feat(backend): age-encrypted file backend (injected identity)"
```

---

## Task 4: Registry + agefile integration through a ref

End-to-end: register the agefile backend under "file" and resolve `av://file/NAME`.

**Files:**
- Test: `internal/backend/agefile/integration_test.go`

**Step 1: Write the test**

`internal/backend/agefile/integration_test.go`:
```go
package agefile_test

import (
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/backend/agefile"
)

func TestResolveThroughRegistry(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	// reuse a tiny inline encrypt (or call an exported test helper)
	writeVault(t, path, id, map[string]string{"GITHUB_TOKEN": "ghp_xyz"})

	reg := backend.NewRegistry()
	reg.Register("file", agefile.New(id, path))

	got, err := reg.Resolve("av://file/GITHUB_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "ghp_xyz" {
		t.Fatalf("value = %q", got.Value)
	}
}
```
(Provide `writeVault` — either copy the small encrypt helper from Step 2 of Task 3 into this `_test.go`, or export a `WriteVault` test helper. Keep DRY: if you find yourself copying it a third time, add an exported `agefile.EncryptVault(w io.Writer, recipient age.Recipient, data map[string]string) error` in the package and use it from both tests and, later, the `av add` CLI.)

**Step 2: Run, verify pass**

Run: `go test ./internal/backend/... -v` → PASS.

**Step 3: Commit**

```bash
git add internal/backend/agefile/integration_test.go
git commit -m "test(backend): resolve av://file/NAME end-to-end through the registry"
```

---

## Task 5: Extend the thin-binary dependency guard

Now that a heavy-ish backend dep (`filippo.io/age`) exists, make "backends are avd-only, av stays thin" CI-enforced.

**Files:**
- Modify: `cmd/av/deps_test.go`

**Step 1: Extend the guard**

Add `filippo.io/age` to the banned-substring list in `TestAvDoesNotLinkGitleaks` (or add a sibling assertion), so `cmd/av` linking any backend implementation fails the test. Keep the existing "package resolved" vacuity guard. Example addition to the banned list:
```go
for _, bad := range []string{"gitleaks", "wazero", "spf13/viper", "spf13/afero", "filippo.io/age"} {
```
Optionally rename the test to `TestAvStaysThin` to reflect the broader intent; keep it in `package main` under `cmd/av`.

**Step 2: Verify it still passes (av imports no backend yet)**

Run: `go test ./cmd/av/ -v` → PASS (av currently imports nothing from internal/backend).

**Step 3: Prove it has teeth (temporary)**

Temporarily add `import _ "github.com/beshkenadze/agentvault/internal/backend/agefile"` to a throwaway file in `cmd/av`, run the guard, confirm it FAILS, then remove the throwaway. Report.

**Step 4: Commit**

```bash
git add cmd/av/deps_test.go
git commit -m "test(cmd): guard av against linking backend deps (filippo.io/age)"
```

---

## Phase 3 — definition of done

- `internal/backend`: ref parser, registry, interface, mock — all tested; `List` returns metadata only (no value field).
- `internal/manifest`: loads `agentvault.yaml`, validates tier ∈ {normal,dangerous}, rejects missing ref.
- `internal/backend/agefile`: round-trips a JSON vault through age; wrong identity fails; missing key → `ErrNotFound`; resolves via the registry through an `av://file/NAME` ref.
- `go test ./...` and `go vet ./...` green; `make build` builds both binaries.
- The thin-binary guard rejects `av` linking `filippo.io/age` (and still rejects gitleaks).

## Roadmap (next)

**Phase 4 — Session + `av run` (wire resolve + redaction).** RPC methods: `resolve(profile)` → values (avd owns a `backend.Registry`); session store + TTL + auto-lock; **decide who reads `agentvault.yaml`** (likely `av` reads its cwd manifest and sends the profile's refs+tiers to `avd`, keeping a single read; confirm during design). `av run` injects env, forks the child, wraps stdout/stderr in `redact.StreamRedactor` (layer 1); `av scrub` streams through the `redact.Redactor` + gitleaks detector (layer 2). Add the `AV_TEST_AUTH=allow` stub (test builds only) so e2e can run without Touch ID. End-to-end: agent runs a command with secrets it never sees as plaintext.

**Phase 5 — Touch ID + dangerous tier.** LocalAuthentication via cgo; per-user GUI-session LaunchAgent; per-secret labeled prompts; dangerous-tier never-cache/fresh-presence; distinguishable exit codes.

**Phase 6 — Real backends + hardening + adapter.** 1Password (`op`) backend; macOS Keychain backend; load the age identity from a Secure-Enclave-wrapped key; memguard/mlock/no-dump (and switch `backend.Secret.Value` to a protected buffer); rate limiting; append-only audit log; `av add/rm` (writes the age vault via `EncryptVault`); `av init --agent claude-code`; `av read` non-TTY refusal; connection deadlines; non-darwin build stubs.

## Notes for the executing engineer

- **Keep `internal/backend` (the interface package) dependency-free** so it can be imported anywhere (incl. potentially `av` for types). Heavy deps (`filippo.io/age`) live only in the impl sub-package `internal/backend/agefile`, which `av` must never import (Task 5 guard).
- **`Secret.Value` is a plain string for now** — Phase 6 swaps it for memguard-protected memory and adds zeroization. Do not scatter copies of the value; resolve-use-discard.
- **`List` must never carry values.** `Meta` deliberately has no value field — a compile-time guarantee. Keep it that way.
- **Decrypt-per-call** in `agefile` is intentional (KISS; the broker holds no plaintext at rest). Phase 4/6 may add a short-lived session cache for normal-tier; dangerous-tier must never be cached.
- TDD throughout: red → green → commit, one behavior per task. Commit on `main`.
