# AgentVault Phase 4 — Session + `av run` + Redaction Wiring Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or subagent-driven-development) to implement this plan task-by-task.

**Goal:** Prove the whole point of AgentVault end-to-end: `av run --profile smoke -- <cmd>` resolves a profile's secrets through `avd`, injects them into the child process's environment, masks the child's output at the source (layer 1), and `av scrub` redacts arbitrary tool output through the daemon's session redactor + gitleaks (layer 2). The agent sees `{{AV:NAME}}`, never a value.

**Architecture:** `avd` gains a **session** (the set of values issued since unlock, used to build the redactor), an **Authorizer** seam (Phase 4 ships only a test stub; real Touch ID is Phase 5), a **Resolver** (manifest → registry → authorizer → session), and two RPC methods: `resolve` and the streaming `scrub`. `av run` (the designated plaintext handler) reads `agentvault.yaml`, calls `resolve`, injects env, forks the child, and wraps its stdio in `redact.StreamRedactor` (layer 1). `av scrub` streams stdin through the daemon's per-connection redactor (layer 2: exact-match over all session-issued values + gitleaks).

**Tech Stack:** Go 1.26.3. Reuses Phase 1 `internal/redact` (+ `internal/detect/gitleaks`), Phase 2 `internal/ipc`/`transport`/`daemon`/`client`, Phase 3 `internal/backend`(+`agefile`)/`internal/manifest`. No new external deps expected.

**Scope:** Phase 4 only. Phases 1-3 are complete on `main`. **Deferred to Phase 5:** real Touch ID `Authorizer`, per-user GUI LaunchAgent, dangerous-tier per-secret fresh-presence, auto-lock on screen-lock/sleep. **Deferred to Phase 6:** memguard `Secret.Value`, 1Password/Keychain backends, Enclave-wrapped identity, rate limiting, audit log, `av add/rm`, `av init`, `av read` TTY-refusal, connection deadlines.

**Design reference:** `docs/plans/2026-06-17-agentvault-design.md` — *Architecture*, *Native authorization*, *CLI surface*, *Redaction pipeline*, *Error handling*.

---

## Design decisions for this phase (read before starting)

1. **`av` stays thin: it does NOT parse the manifest or link backends.** `av run` finds `agentvault.yaml` in the cwd, reads its **raw bytes**, and sends `{profile, manifestBytes}` to `avd`. `avd` parses (it already links `internal/manifest`), resolves via its `backend.Registry`, and returns the resolved `name→value` map. So `av` links neither `yaml.v3` nor any backend. The `TestAvStaysThin` guard (extended in Phase 3) keeps this honest — do NOT import `internal/manifest` or `internal/backend/agefile` from `cmd/av`/`internal/client`.

2. **`av run` forks the child (confirmed in design brainstorm), not `avd`.** `av run` therefore receives the plaintext values (it must, to inject env), masks the child's stdout/stderr locally with a `redact.StreamRedactor` built from those values (layer 1), and zeroizes on exit. `avd` remains the broker/session holder.

3. **Auth is a SEAM in Phase 4, satisfied only by a test stub.** `avd`'s `Resolver` calls an `Authorizer` before issuing each value. Phase 4 ships exactly one implementation: a stub that authorizes iff `AV_TEST_AUTH=allow` is set in the daemon's environment. **An `avd` started without it refuses `resolve` with `CodeLocked`** ("auth not configured; ask a human / Phase 5"). This means Phase 4's daemon is intentionally NOT usable for real secrets yet — but the entire pipeline is provable via the stub, and Phase 5 swaps in the real Touch ID authorizer with no other change. No insecure allow-by-default ships.

3b. **`resolve` carries plaintext over the socket** (peer-cred-checked, `0600`, same-UID only — established in Phase 2). This is the established trust boundary; `av run` is the sole plaintext-handling client.

4. **Session = issued-values set, used to build the redactor.** Every value `avd` issues via `resolve` is recorded in the session. The `scrub` service redacts using a `redact.Redactor` (exact-match over ALL session-issued values + gitleaks detector). The session has a TTL (default 15 min); on expiry it clears the issued values and the redactor resets. (Auto-lock on screen-lock is Phase 5.) The session is shared across connections → it MUST be concurrency-safe (mutex).

5. **`scrub` is streamed per-connection to respect the 1 MiB JSON-RPC line cap.** A large tool output cannot be sent as one message. `av scrub` loops: read a chunk (≤ 256 KiB), send a `scrub` request, write the masked chunk it gets back; at EOF send `scrub_flush` to drain the overlap buffer. `avd` keeps a per-connection `*redact.StreamRedactor` (created lazily from the session redactor on the first `scrub` request) so a secret split across chunks is still masked — exactly the Phase 1 streaming guarantee, now over the wire.

6. **Exit codes the agent can branch on:** `av run` propagates the child's exit code on success; maps `CodeLocked`→a distinct code (e.g. 69 "vault locked, ask a human"), `CodeDenied`→another (e.g. 77 "dangerous-tier denied"). Document them so the agent adapter (Phase 6) can react.

---

## Task 1: Session store (`internal/daemon/session.go`)

Holds the values issued since unlock, builds a redactor from them, expires on TTL. Concurrency-safe.

**Files:**
- Create: `internal/daemon/session.go`
- Test: `internal/daemon/session_test.go`

**Step 1: Write the failing test**

`internal/daemon/session_test.go`:
```go
package daemon

import (
	"testing"
	"time"
)

func TestSessionIssueAndRedactor(t *testing.T) {
	s := NewSession(15 * time.Minute)
	s.Issue("GITHUB_TOKEN", "ghp_secret")
	s.Issue("STRIPE", "sk_live_x")

	r := s.Redactor() // *redact.Redactor over all issued values
	got := r.Redact("token=ghp_secret and sk_live_x")
	if got == "token=ghp_secret and sk_live_x" {
		t.Fatalf("issued values not masked: %q", got)
	}
}

func TestSessionExpiryClears(t *testing.T) {
	s := NewSession(0) // already-expired TTL
	s.Issue("X", "v")
	if !s.Expired() {
		t.Fatal("zero TTL should be expired immediately")
	}
	// After expiry, the redactor must not mask the old value.
	if r := s.Redactor(); r.Redact("v") != "v" {
		t.Fatal("expired session must not mask old values")
	}
}
```
(Note: `NewSession` should take the TTL and a "now" via an injectable clock or accept a deadline so tests don't sleep. Since the repo forbids wall-clock flakiness, prefer an injectable `now func() time.Time` field defaulting to `time.Now`, OR compute the deadline at unlock. For `TestSessionExpiryClears`, a 0 TTL must read as already expired.)

**Step 2: Run, verify fails**

Run: `go test ./internal/daemon/ -run TestSession -v` → FAIL (undefined).

**Step 3: Implement**

`internal/daemon/session.go`:
```go
package daemon

import (
	"sync"
	"time"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/redact"
)

// Session holds the secret values issued since unlock. It builds the redactor used by
// the scrub service and expires after a TTL. Safe for concurrent use.
type Session struct {
	ttl time.Duration
	now func() time.Time

	mu       sync.Mutex
	deadline time.Time
	issued   map[string]string // logical name -> value (for redaction + {{AV:NAME}})
	det      redact.Detector   // optional gitleaks detector for layer 2
}

func NewSession(ttl time.Duration) *Session {
	s := &Session{ttl: ttl, now: time.Now, issued: map[string]string{}}
	s.deadline = s.now().Add(ttl)
	return s
}

// WithDetector sets the gitleaks detector used by the scrub redactor.
func (s *Session) WithDetector(d redact.Detector) *Session { s.det = d; return s }

func (s *Session) Issue(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expiredLocked() {
		s.issued = map[string]string{}
	}
	s.issued[name] = value
	s.deadline = s.now().Add(s.ttl)
}

func (s *Session) Expired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiredLocked()
}

func (s *Session) expiredLocked() bool { return !s.now().Before(s.deadline) }

// Redactor returns a redactor over the currently-valid issued values (empty if expired).
func (s *Session) Redactor() *redact.Redactor {
	s.mu.Lock()
	defer s.mu.Unlock()
	var secrets []redact.Secret
	if !s.expiredLocked() {
		for name, val := range s.issued {
			secrets = append(secrets, redact.Secret{Name: name, Value: val})
		}
	}
	return redact.NewRedactor(secrets, redact.Options{Detector: s.det})
}

// Lock clears all issued values (used by av lock / TTL expiry / Phase 5 auto-lock).
func (s *Session) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.issued {
		delete(s.issued, k)
	}
}

var _ = backend.ErrNotFound // keep import tidy if backend types referenced later
```
(Drop the trailing `var _` if `backend` ends up unused; it's a hint that the resolver couples these. Keep `Session` itself backend-free if possible — it only needs name/value strings.)

**Step 4: Run, verify pass; vet**

Run: `go test ./internal/daemon/ -run TestSession -v` → PASS. `go vet ./...`.

**Step 5: Commit**

```bash
git add internal/daemon/session.go internal/daemon/session_test.go
git commit -m "feat(daemon): session store with issued-values redactor and TTL"
```

---

## Task 2: Authorizer seam + test stub (`internal/daemon/auth.go`)

**Files:**
- Create: `internal/daemon/auth.go`
- Test: `internal/daemon/auth_test.go`

**Step 1: Write the failing test**

`internal/daemon/auth_test.go`:
```go
package daemon

import (
	"testing"

	"github.com/beshkenadze/agentvault/internal/manifest"
)

func TestStubAuthorizerRequiresEnv(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "")
	a := NewStubAuthorizer()
	if err := a.Authorize(manifest.TierNormal, "X"); err == nil {
		t.Fatal("without AV_TEST_AUTH=allow, authorize must fail")
	}
}

func TestStubAuthorizerAllows(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	a := NewStubAuthorizer()
	if err := a.Authorize(manifest.TierNormal, "X"); err != nil {
		t.Fatalf("with AV_TEST_AUTH=allow, authorize must pass: %v", err)
	}
	if err := a.Authorize(manifest.TierDangerous, "Y"); err != nil {
		t.Fatalf("stub authorizes dangerous too (real prompt is Phase 5): %v", err)
	}
}
```

**Step 2: Run, verify fails**

Run: `go test ./internal/daemon/ -run TestStubAuthorizer -v` → FAIL.

**Step 3: Implement**

`internal/daemon/auth.go`:
```go
package daemon

import (
	"errors"
	"os"

	"github.com/beshkenadze/agentvault/internal/manifest"
)

// ErrLocked means the daemon cannot authorize a secret issuance (no auth configured,
// or session locked). Maps to ipc.CodeLocked.
var ErrLocked = errors.New("vault locked: authorization not available")

// Authorizer decides whether a secret of a given tier may be issued now. Phase 5
// provides the Touch ID implementation; Phase 4 ships only the test stub.
type Authorizer interface {
	Authorize(tier manifest.Tier, name string) error
}

// stubAuthorizer authorizes iff AV_TEST_AUTH=allow is set in the daemon's environment.
// It exists so the Phase 4 pipeline is end-to-end testable before Touch ID lands.
type stubAuthorizer struct{}

func NewStubAuthorizer() Authorizer { return stubAuthorizer{} }

func (stubAuthorizer) Authorize(_ manifest.Tier, _ string) error {
	if os.Getenv("AV_TEST_AUTH") == "allow" {
		return nil
	}
	return ErrLocked
}
```

**Step 4: Run, verify pass**

Run: `go test ./internal/daemon/ -run TestStubAuthorizer -v` → PASS.

**Step 5: Commit**

```bash
git add internal/daemon/auth.go internal/daemon/auth_test.go
git commit -m "feat(daemon): Authorizer seam + AV_TEST_AUTH stub (real Touch ID is Phase 5)"
```

---

## Task 3: Resolver — manifest → registry → authorizer → session (`internal/daemon/resolver.go`)

**Files:**
- Create: `internal/daemon/resolver.go`
- Test: `internal/daemon/resolver_test.go`

**Step 1: Write the failing test (with a mock backend)**

`internal/daemon/resolver_test.go`:
```go
package daemon

import (
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/backend"
)

type mockBE struct{ data map[string]string }

func (m mockBE) Resolve(loc string) (backend.Secret, error) {
	v, ok := m.data[loc]
	if !ok {
		return backend.Secret{}, backend.ErrNotFound
	}
	return backend.Secret{Value: v}, nil
}
func (m mockBE) List(string) ([]backend.Meta, error) { return nil, nil }

const manifestYAML = `profiles:
  smoke:
    GITHUB_TOKEN:
      ref: av://mock/GH
      tier: normal
`

func TestResolveProfile(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: map[string]string{"GH": "ghp_xyz"}})
	sess := NewSession(15 * time.Minute)
	rv := NewResolver(reg, NewStubAuthorizer(), sess)

	vals, err := rv.Resolve("smoke", []byte(manifestYAML))
	if err != nil {
		t.Fatal(err)
	}
	if vals["GITHUB_TOKEN"] != "ghp_xyz" {
		t.Fatalf("values = %+v", vals)
	}
	// the issued value must now be in the session redactor
	if sess.Redactor().Redact("ghp_xyz") == "ghp_xyz" {
		t.Fatal("resolved value not recorded in session")
	}
}

func TestResolveDeniedWhenLocked(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "") // not allowed
	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: map[string]string{"GH": "x"}})
	rv := NewResolver(reg, NewStubAuthorizer(), NewSession(time.Minute))
	if _, err := rv.Resolve("smoke", []byte(manifestYAML)); err == nil {
		t.Fatal("locked authorizer must fail resolve")
	}
}
```

**Step 2: Run, verify fails**

Run: `go test ./internal/daemon/ -run TestResolve -v` → FAIL.

**Step 3: Implement**

`internal/daemon/resolver.go`:
```go
package daemon

import (
	"fmt"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/manifest"
)

// Resolver turns a (profile, manifest bytes) request into resolved name->value pairs,
// authorizing each by tier and recording issued values in the session.
type Resolver struct {
	reg  *backend.Registry
	auth Authorizer
	sess *Session
}

func NewResolver(reg *backend.Registry, auth Authorizer, sess *Session) *Resolver {
	return &Resolver{reg: reg, auth: auth, sess: sess}
}

// Resolve parses the manifest, selects the profile, authorizes + resolves each entry,
// records issued values in the session, and returns name->value. On any authorize
// failure it returns ErrLocked (so the daemon maps it to CodeLocked) and issues nothing.
func (r *Resolver) Resolve(profile string, manifestBytes []byte) (map[string]string, error) {
	m, err := manifest.Parse(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	p, ok := m.Profile(profile)
	if !ok {
		return nil, fmt.Errorf("profile %q not found", profile)
	}
	out := make(map[string]string, len(p))
	for name, e := range p {
		if err := r.auth.Authorize(e.Tier, name); err != nil {
			return nil, err // ErrLocked / denied — issue nothing
		}
		sec, err := r.reg.Resolve(e.Ref)
		if err != nil {
			return nil, fmt.Errorf("resolve %s (%s): %w", name, e.Ref, err)
		}
		out[name] = sec.Value
		r.sess.Issue(name, sec.Value)
	}
	return out, nil
}
```
(Design note: dangerous-tier here is authorized by the stub like normal. Phase 5's authorizer will treat dangerous specially — fresh per-secret prompt, never cached — without changing this resolver's shape.)

**Step 4: Run, verify pass; vet**

Run: `go test ./internal/daemon/ -run TestResolve -v` → PASS. `go vet ./...`.

**Step 5: Commit**

```bash
git add internal/daemon/resolver.go internal/daemon/resolver_test.go
git commit -m "feat(daemon): resolver wires manifest+registry+authorizer+session"
```

---

## Task 4: `resolve` RPC method + client call

Wire the resolver into the daemon dispatch and add `internal/ipc` param/result types and a `client` method. Also construct the daemon's `Registry`/`Session`/`Resolver` in `Server`.

**Files:**
- Modify: `internal/ipc/proto.go` (add ResolveParams/ResolveResult)
- Modify: `internal/daemon/server.go` (Server holds *Resolver; dispatch "resolve")
- Modify: `internal/client/client.go` (Resolve method)
- Test: `internal/daemon/resolve_rpc_test.go`

**Step 1: Add IPC types**

In `internal/ipc/proto.go`:
```go
// ResolveParams is the client request for `resolve`.
type ResolveParams struct {
	Profile  string `json:"profile"`
	Manifest []byte `json:"manifest"` // raw agentvault.yaml bytes
}

// ResolveResult is the daemon reply: logical name -> secret value.
type ResolveResult struct {
	Values map[string]string `json:"values"`
}
```

**Step 2: Wire the daemon (TDD)**

Write `internal/daemon/resolve_rpc_test.go`: start a `Server` configured with a mock-backed `Resolver` (add a `New`-style constructor or an exported field/option to inject the resolver for tests), dial, send a `resolve` request with the manifest + `AV_TEST_AUTH=allow`, assert the response `Values["GITHUB_TOKEN"]`. Also assert a locked daemon returns `Error.Code == ipc.CodeLocked`.

In `internal/daemon/server.go`:
- Add a `resolver *Resolver` field. Provide a constructor/option so production wires `NewResolver(realRegistry, NewStubAuthorizer(), session)` and tests wire a mock-backed one. (Keep `New(path)` working; add `NewWithResolver(path, *Resolver)` or a functional option.)
- In `dispatch`, add:
```go
case "resolve":
    var p ipc.ResolveParams
    if err := json.Unmarshal(req.Params, &p); err != nil {
        return errResp(req.ID, ipc.CodeBadRequest, err.Error())
    }
    vals, err := s.resolver.Resolve(p.Profile, p.Manifest)
    if err != nil {
        code := ipc.CodeInternal
        if errors.Is(err, ErrLocked) { code = ipc.CodeLocked }
        return errResp(req.ID, code, err.Error())
    }
    res, _ := json.Marshal(ipc.ResolveResult{Values: vals})
    return ipc.Response{ID: req.ID, Result: res}
```
(Add a small `errResp` helper; ensure secret values never appear in error strings.)

**Step 3: Client method**

In `internal/client/client.go`:
```go
func (c *Client) Resolve(profile string, manifestBytes []byte) (map[string]string, error) {
	p, _ := json.Marshal(ipc.ResolveParams{Profile: profile, Manifest: manifestBytes})
	resp, err := c.call(ipc.Request{ID: 1, Method: "resolve", Params: p})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error // caller inspects Code (Locked/Denied)
	}
	var r ipc.ResolveResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	return r.Values, nil
}
```

**Step 4: Run, verify pass; vet; the av-thin guard still green** (client now references ipc types only — no manifest/backend).

Run: `go test ./... -v` (relevant packages) → PASS. `go test ./cmd/av/` guard → PASS.

**Step 5: Commit**

```bash
git add internal/ipc/ internal/daemon/ internal/client/
git commit -m "feat: resolve RPC (avd resolver) + client.Resolve; CodeLocked on lock"
```

---

## Task 5: `av run` — resolve, inject env, fork child, layer-1 source masking

The primary path. Fiddly stdio — verify behavior against the OS.

**Files:**
- Create: `internal/client/run.go` (the run orchestration; keeps `cmd/av` thin)
- Create: `cmd/av/` wiring for the `run` subcommand (extend main.go)
- Test: `internal/client/run_test.go`

**Behavior (`av run [--profile P] -- cmd args...`):**
1. Find `agentvault.yaml` in the cwd (Phase 4: cwd only; error clearly if missing). Read raw bytes.
2. `client.Resolve(profile, bytes)` → `map[name]value`. On `resp.Error.Code == CodeLocked` → exit 69 with "vault locked: ask a human to unlock"; `CodeDenied` → exit 77. (Map via ipc codes.)
3. Build a `redact.Matcher`/`StreamRedactor` from the resolved values.
4. `exec.Command(cmd, args...)`; set `cmd.Env = append(os.Environ(), "NAME=value"...)` for each resolved pair; set `cmd.Stdin = os.Stdin`.
5. Pipe the child's stdout and stderr through **two** `redact.StreamRedactor`s writing to `os.Stdout`/`os.Stderr` (layer 1, source masking) — use `cmd.StdoutPipe()`/`StderrPipe()` + `io.Copy` into the redactors, or set `cmd.Stdout = redactor` directly (a `StreamRedactor` is an `io.Writer`; remember to `Close()` it after `cmd.Wait()` to flush the tail).
6. `cmd.Run()`/`Wait()`; propagate the child's exit code (`exec.ExitError.ExitCode()`).
7. Zeroize the value strings/matcher after the child exits (best-effort; Phase 6 memguard hardens this).

**Step 1: Write the test**

`internal/client/run_test.go` — `TestRunMasksChildOutput`:
- Start an in-process `daemon.Server` wired with a mock resolver returning `{"SECRET":"topsecret"}` (reuse the Task 4 test harness), with `AV_TEST_AUTH=allow`.
- Run `av run` logic against a child command that echoes the secret, e.g. `sh -c 'echo "value is $SECRET"'`, capturing the redacted stdout.
- Assert the captured output contains `{{AV:SECRET}}` and does NOT contain `topsecret`.
- Assert the child actually received the env var (the echo proves it).
- Assert exit code 0 propagates; and a child exiting 3 makes `av run` return 3.

(Structure `run.go` so the test can inject the socket path / a `*client.Client` and capture stdout/stderr via `io.Writer` params rather than the real `os.Stdout` — e.g. `Run(cl *Client, opts RunOptions, stdout, stderr io.Writer) (exitCode int, err error)`.)

**Step 2-4: Red → implement → green.** Mark the stdio plumbing as the area to verify on real macOS (pipe close ordering: close the redactors AFTER `Wait` so the tail flushes; ensure no deadlock by reading pipes concurrently if using `StdoutPipe`).

**Step 5: Commit**

```bash
git add internal/client/run.go cmd/av/main.go internal/client/run_test.go
git commit -m "feat(av): av run resolves, injects env, forks child, masks output (layer 1)"
```

---

## Task 6: `av scrub` — streaming layer-2 redaction

**Files:**
- Modify: `internal/ipc/proto.go` (ScrubParams/ScrubResult; methods "scrub"/"scrub_flush")
- Modify: `internal/daemon/server.go` (per-connection StreamRedactor; handle scrub/scrub_flush)
- Create: `internal/client/scrub.go` (stdin→avd→stdout streaming filter)
- Test: `internal/daemon/scrub_rpc_test.go`, `internal/client/scrub_test.go`

**Design (per decision 5):**
- IPC: `ScrubParams{ Data []byte }`, `ScrubResult{ Masked []byte }`. Methods `scrub` (mask a chunk) and `scrub_flush` (flush overlap tail at EOF).
- Daemon `handle`: keep a per-connection `var sr *redact.StreamRedactor` plus a `bytes.Buffer` sink. On first `scrub`, create `sr` from `s.session.Redactor()`'s matcher writing into the buffer (NOTE: the streaming redactor needs the session's exact-match matcher; the gitleaks tier can run on the flushed output or be folded in — for Phase 4, layer-2 streaming uses the exact-match `StreamRedactor`; running gitleaks per-chunk over a stream is a Phase 4 stretch — if it complicates, mask exact-match in the stream and run gitleaks on the whole flushed result, or note gitleaks-on-scrub as a follow-up). Each `scrub`: write chunk to `sr`, return what landed in the buffer (then reset the buffer). `scrub_flush`: `sr.Close()`, return remaining buffer.
- Client `Scrub(in io.Reader, out io.Writer)`: loop reading ≤256 KiB, send `scrub`, write masked; at EOF send `scrub_flush`, write masked; close.

**Tests:**
- `scrub_rpc_test.go`: issue a value into the session, then drive `scrub` chunks where the value is **split across two chunks**, assert the value is masked in the concatenated masked output (proves the over-the-wire streaming overlap works — the Phase 1 guarantee end-to-end).
- `scrub_test.go`: client filter masks a session value in a piped stream.

**Step 1-4: Red → implement → green.** Pay attention: the split-across-chunks case is the load-bearing test (reuse Phase 1's exhaustive-split mindset for at least the 2-chunk boundary).

**Step 5: Commit**

```bash
git add internal/ipc/ internal/daemon/ internal/client/scrub.go internal/daemon/scrub_rpc_test.go internal/client/scrub_test.go
git commit -m "feat: av scrub streaming layer-2 redaction via per-connection redactor"
```

---

## Task 7: Error handling + end-to-end integration

**Files:**
- Modify: `cmd/av/main.go` (map CodeLocked→exit 69, CodeDenied→exit 77, with clear stderr; no secret in any message)
- Create: `internal/client/e2e_test.go`
- Modify: `internal/daemon/server.go` constructor used by `cmd/avd` to wire a real registry (mock or agefile) + `NewStubAuthorizer()` + session

**Step 1: End-to-end test** (`internal/client/e2e_test.go`, non-short):
- Build a real age vault with `agefile.EncryptVault` containing `{"GITHUB_TOKEN":"ghp_REAL"}`.
- Start an in-process `daemon.Server` whose resolver uses a `backend.Registry` with the agefile backend under "file", `AV_TEST_AUTH=allow`, a fresh session.
- Write an `agentvault.yaml` with profile `smoke` → `GITHUB_TOKEN: {ref: av://file/GITHUB_TOKEN, tier: normal}`.
- Run `av run --profile smoke -- sh -c 'echo got=$GITHUB_TOKEN'` and assert: output is `got={{AV:GITHUB_TOKEN}}`, the string `ghp_REAL` appears NOWHERE in av's stdout/stderr.
- Pipe a string containing `ghp_REAL` through `av scrub` and assert it is masked.
- With `AV_TEST_AUTH` unset, assert `av run` exits 69 and prints a "locked" message (no secret).

**Step 2: Error-code mapping** in `cmd/av/main.go`; document the exit codes in a comment.

**Step 3: Verify**

`go test ./...` (full) + `go vet ./...` green; `make build`; `go test ./cmd/av/` thin-guard green; **manually** (or in the e2e) confirm a real `av run` cold path masks a real secret end-to-end. No leftover daemon.

**Step 4: Commit**

```bash
git add cmd/av/main.go internal/client/e2e_test.go internal/daemon/
git commit -m "feat(av): exit-code mapping + end-to-end run/scrub redaction test"
```

---

## Phase 4 — definition of done

- `av run --profile P -- cmd` resolves via `avd`, injects env, runs the child, and masks its output at the source — a real secret never appears in `av`'s stdout/stderr; the agent sees `{{AV:NAME}}`.
- `av scrub` redacts arbitrary piped output via the daemon's session redactor, including a value split across chunks (streaming overlap holds over the wire).
- Auth is a seam: `avd` without `AV_TEST_AUTH=allow` refuses `resolve` with `CodeLocked`; `av run` maps it to a distinct exit code with a human-readable, secret-free message.
- Session records issued values and expires on TTL; concurrency-safe.
- `go test ./...`/`go vet ./...` green; `make build` builds both; `TestAvStaysThin` still passes (av links neither yaml/manifest nor backends).

## Roadmap (next)

**Phase 5 — Touch ID + dangerous tier.** Replace the stub `Authorizer` with `LocalAuthentication` (cgo); per-user GUI-session LaunchAgent; per-secret labeled prompts; dangerous-tier never-cached/fresh-presence (the resolver's `Authorize(dangerous,...)` triggers a fresh prompt and the session must NOT cache dangerous values); auto-lock on screen-lock/sleep (clears the session); `av lock`/`unlock`/`status`.

**Phase 6 — Real backends + hardening + adapter.** 1Password (`op`) + macOS Keychain backends; Enclave-wrapped age identity; memguard `Secret.Value` + zeroize; rate limiting on issuance; append-only audit log (one entry per issuance/dangerous touch); `av add/rm` (writes the age vault via `EncryptVault`, atomic write-then-rename — closes the EncryptVault writer-leak note); `av init --agent claude-code` (hook + skill generation); `av read` non-TTY refusal; gitleaks-on-scrub if deferred; connection read/write deadlines; non-darwin build stubs.

## Notes for the executing engineer

- **`av` MUST stay thin.** Do not import `internal/manifest` or `internal/backend/*` from `cmd/av`/`internal/client`. `av run` sends raw manifest bytes; `avd` parses. Run `go test ./cmd/av/` after any client change.
- **`av run` is the only plaintext-handling client.** Resolve-use-inject-mask-zeroize; do not write values to logs or temp files.
- **Flush the layer-1 `StreamRedactor` AFTER `cmd.Wait()`** so the overlap tail is masked; closing before the child finishes truncates output.
- **The split-across-chunks scrub test is load-bearing** — it proves the Phase 1 streaming guarantee survives the RPC boundary. Don't skip it.
- **Never let a secret reach an error string, log line, or the audit (audit is Phase 6).** Error messages carry names/refs, never values.
- TDD throughout: red → green → commit, one behavior per task. Commit on `main`.
- Known unsigned commits awaiting 1Password unlock: `45af884`, `23a4496`, `97a1074`, `593a114` — re-sign before any push.
```
