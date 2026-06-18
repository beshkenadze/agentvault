# AgentVault Phase 5 — Touch ID + Dangerous Tier + Lock/Unlock Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or subagent-driven-development) to implement this plan task-by-task.

**Goal:** Replace the Phase-4 auth stub with real native presence (Touch ID), enforce the design's tier policy — normal-tier served from an unlocked session, **dangerous-tier never cached and requiring fresh presence per secret** — and add `av lock` / `unlock` / `status` plus auto-lock on screen-lock/sleep.

**Architecture:** A `Presence` seam (`Prompt(reason) error`) replaces the Phase-4 `Authorizer`. The **logic** that uses presence — session unlock state, the resolver's per-tier branching (normal needs unlocked session; dangerous prompts fresh and is never written to the session), and the lock/unlock/status RPCs — is fully TDD-tested with a programmable stub presence. The **platform bindings** — Touch ID via `LocalAuthentication` (cgo), the per-user LaunchAgent, and auto-lock observers — sit behind the seam, are compile-verified, and require **manual hardware verification by the user** (a biometric prompt cannot be exercised in automated tests).

**Tech Stack:** Go 1.26.3 + cgo (Objective-C `LocalAuthentication`/`Foundation`) for the darwin presence + auto-lock. Reuses all of Phases 1-4.

**TESTABILITY BOUNDARY (read first):**
- Tasks 1-4 and 8 (logic, RPCs, wiring, e2e-with-stub) are **fully TDD-tested** by subagents.
- Tasks 5-7 (cgo Touch ID, LaunchAgent plist, auto-lock observers) are **built + `go build`/`go vet` compile-verified** by subagents but **NOT functionally tested** — they carry explicit **MANUAL VERIFICATION** steps the user performs on real hardware. Do not claim them "working" from a green build; a green cgo build only proves it compiles.

**Scope:** Phase 5 only. Phases 1-4 complete on `main`. **Deferred to Phase 6:** 1Password/Keychain backends, Enclave-wrapped age identity, memguard `Secret.Value`, rate limiting, audit log, `av add/rm/init/read`, Claude Code adapter, gitleaks-on-scrub, connection deadlines, non-darwin stubs.

**Design reference:** `docs/plans/2026-06-17-agentvault-design.md` — *Native authorization*, *Security model*. Carry-forward site: `internal/daemon/resolver.go:36-39`.

---

## Design decisions for this phase

1. **`Presence` replaces `Authorizer`.** `type Presence interface { Prompt(reason string) error }`. One call = one native presence check. The resolver/session — not the presence object — enforce the *policy* (which tier needs what). This keeps the cgo surface minimal (just "prompt and return ok/err") and the policy fully testable.
2. **Unlock is an explicit step; normal-tier resolve does NOT prompt.** `av unlock` → one `Prompt` → opens the session for a TTL. Normal-tier `resolve` only checks `session.Locked()` (never prompts mid-agent-run); if locked → `CodeLocked` → the agent asks a human to `av unlock`. This matches the design ("normal served from open session without re-prompting") and avoids a Touch ID prompt firing in the middle of an autonomous agent run.
3. **Dangerous-tier ALWAYS prompts fresh, per secret, and is NEVER cached** (closes the carry-forward). At `resolve`, each dangerous entry calls `presence.Prompt("Allow '<profile>' to use <NAME>?")` independently; on success the value is returned to `av run` for the single command but is **not** written to the session (`sess.Issue` is skipped). On denial → `ErrDenied` → `CodeDenied` → exit 77. Consequence: layer-2 `scrub` won't exact-match dangerous values (they're masked at layer-1 during the run; gitleaks is the only layer-2 net for them) — an accepted tradeoff of "never cached"; note it.
4. **Production uses real Touch ID; tests use the stub.** `cmd/avd` wires `touchIDPresence` by default. When `AV_TEST_AUTH=allow` is set, it wires `stubPresence` instead (so existing e2e and CI stay automatable). The stub is the same seam, env-gated exactly like Phase 4.
5. **`avd` must run as a per-user GUI-session LaunchAgent** for `LocalAuthentication` to present UI (design invariant). Phase 5 ships the plist + a manual install step; `av init` (Phase 6) will generate it.
6. **Auto-lock** observes screen-lock (`com.apple.screenIsLocked`) and sleep; on either, `session.Lock()`. Platform glue, manually verified.

---

## Task 1: `Presence` seam (replace `Authorizer`) + stub

**Files:** modify `internal/daemon/auth.go` (→ presence), `internal/daemon/auth_test.go`; touch `internal/daemon/resolver.go` (signature only).

- Rename/replace `Authorizer` with `Presence interface { Prompt(reason string) error }`. Keep `ErrLocked`; add `var ErrDenied = errors.New("access denied")`.
- `stubPresence` (was stubAuthorizer): `Prompt` returns nil iff `os.Getenv("AV_TEST_AUTH")=="allow"` else `ErrLocked`. `NewStubPresence() Presence`.
- Update `NewResolver` to take a `Presence` (rename the field `auth`→`presence`); for THIS task just change the type and have `Resolve` call `presence.Prompt(...)` where it used to call `Authorize` (full per-tier logic lands in Task 3 — minimal change to keep it compiling/green here, or fold Task 3 in if cleaner).
- Update `auth_test.go` → `presence_test.go`: TestStubPresenceRequiresEnv, TestStubPresenceExactMatchOnly (keep the exact-match hardening from Phase 4).
- TDD; `go test ./internal/daemon/` green; `go vet`. Commit: `refactor(daemon): Presence seam replaces Authorizer; add ErrDenied`.

## Task 2: Session unlock/lock state

**Files:** modify `internal/daemon/session.go`, `session_test.go`.

- Add explicit unlocked state: `Unlock(ttl time.Duration)` sets deadline = now+ttl and marks unlocked; `Locked() bool` (true if never unlocked or past deadline); `Status() (locked bool, remaining time.Duration)`; `Lock()` already exists (clears issued + mark locked). Reconcile with the existing TTL: a fresh `NewSession` is **locked** until `Unlock`. (This is a behavior change: Phase 4 had no explicit unlock — issued values just expired. Now normal-tier resolve requires `Locked()==false`.)
- Concurrency-safe (mutex). Injected clock retained.
- Tests: unlock makes Locked()==false until TTL; Lock() re-locks and clears; Status reports remaining; expiry re-locks; no-resurface (carry the Phase-4 test).
- TDD; green; vet. Commit: `feat(daemon): session unlock/lock state + Status`.

## Task 3: Resolver per-tier policy (dangerous never-cached) — THE security task

**Files:** modify `internal/daemon/resolver.go`, `resolver_test.go`.

- Rework `Resolve` per decision #2/#3:
  - normal: `if r.sess.Locked() { return nil, ErrLocked }`; resolve; `out[name]=val`; `r.sess.Issue(name, val)` (cached).
  - dangerous: `if err := r.presence.Prompt(fmt.Sprintf("Allow %q to use %s", profile, name)); err != nil { return nil, ErrDenied }`; resolve; `out[name]=val`; **do NOT** call `sess.Issue` (never cached).
  - Keep `ErrBadRequest` for unknown profile / malformed manifest.
- Tests (with stub presence + injectable session):
  - normal-tier with LOCKED session → ErrLocked, nothing resolved.
  - normal-tier with UNLOCKED session → value returned AND present in session redactor (cached).
  - **dangerous-tier (presence allows) → value returned but NOT in the session redactor** (the never-cached assertion — load-bearing).
  - dangerous-tier (presence denies) → ErrDenied, value not returned, not cached.
  - mixed profile: normal cached, dangerous not.
- Update the resolver doc comment (remove the "Phase 5 REQUIREMENT" note — now implemented) and dispatch mapping for ErrDenied→CodeDenied (Task 4 touches dispatch; ensure it's wired).
- TDD; green; vet. Commit: `feat(daemon): per-tier resolve — normal needs unlocked session, dangerous never cached`.

## Task 4: lock/unlock/status RPCs + client + cmd

**Files:** `internal/ipc/proto.go` (StatusResult{Locked bool, RemainingSeconds int}); `internal/daemon/server.go` (dispatch unlock/lock/status; Server needs a `presence Presence` + the session — wire alongside the resolver); `internal/client/client.go` (Unlock/Lock/Status); `cmd/av/main.go` (unlock/lock/status subcommands); tests.

- dispatch:
  - "unlock" → `s.presence.Prompt("Unlock AgentVault")`; on ok `s.session.Unlock(ttl)`; on err → CodeLocked/CodeDenied. (This is the call that fires Touch ID in production.)
  - "lock" → `s.session.Lock()` → ok.
  - "status" → `s.session.Status()` → StatusResult (no values, ever).
  - Map `errors.Is(err, ErrDenied)` → `ipc.CodeDenied` in resolve + unlock paths.
- Wire `s.presence` into the Server (SetResolver already captures the session; add `SetPresence` or capture presence from the resolver — minimal clean wiring; the unlock RPC and the resolver must share the SAME presence + session).
- client: `Unlock() error`, `Lock() error`, `Status() (locked bool, remaining int, err error)`.
- cmd/av: `av unlock` (prints "unlocked for Nm" or the locked/denied message + exit code), `av lock`, `av status` (prints locked/unlocked + remaining). Reuse the exit-code mapping.
- Tests (stub presence, AV_TEST_AUTH=allow): unlock→status shows unlocked; lock→status shows locked; unlock-denied (no env)→CodeLocked; full `go test` green; `TestAvStaysThin` green.
- Commit: `feat: lock/unlock/status RPCs + client + av subcommands`.

## Task 5: Touch ID presence via cgo (BUILD + COMPILE-VERIFY; MANUAL hardware verification)

**Files:** `internal/daemon/presence_darwin.go` (`//go:build darwin && cgo`), `internal/daemon/presence_other.go` (`//go:build !darwin || !cgo` — returns an error so the package builds everywhere).

- `touchIDPresence` implements `Presence.Prompt(reason)` via `LocalAuthentication`:
  - cgo bridges to Objective-C: create an `LAContext`, `canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics` (fall back to `...WithBiometricsOrWatch`/device-passcode policy if biometrics unavailable — your call, document), then `evaluatePolicy:localizedReason:reply:` and BLOCK (a dispatch semaphore) until the reply, mapping success→nil, cancel/failure→ErrDenied.
  - Link flags: `// #cgo LDFLAGS: -framework LocalAuthentication -framework Foundation`.
- `presence_other.go`: `func newTouchIDPresence() (Presence, error) { return nil, errors.New("touch id unavailable on this build") }` so non-cgo/non-darwin still compiles.
- **Subagent does:** write it; `CGO_ENABLED=1 go build ./...` and `go vet` must pass on this macOS (report the exact build output); ensure the non-cgo path also builds (`CGO_ENABLED=0 go build ./...`).
- **Subagent does NOT claim it works.** Add a tiny manual harness `cmd/av-touchid-smoke` (or a `// +build ignore` script) OR document the manual step (below).
- **MANUAL VERIFICATION (user, on hardware):** after Task 8 wiring, run `av unlock` and confirm a real Touch ID prompt appears with the reason text and that touching the sensor unlocks (and Esc/cancel yields exit 69/77). Record the result.
- Commit: `feat(daemon): Touch ID presence via LocalAuthentication (cgo) [manual-verify]`.

## Task 6: LaunchAgent plist + GUI-session requirement (BUILD artifact; MANUAL verify)

**Files:** `init/com.beshkenadze.agentvault.avd.plist` (or `packaging/`), a short `docs/launchagent.md`.

- A per-user LaunchAgent plist that runs the built `avd` in the user's Aqua/GUI session (so Touch ID can present). Keep it minimal: `Label`, `ProgramArguments` (path to `avd`), `RunAtLoad`/`KeepAlive` as appropriate, and the env passthrough needed (`AV_AGE_IDENTITY`/`AV_AGE_VAULT` for now — note Phase 6 Enclave will remove the identity env).
- **MANUAL VERIFICATION (user):** `cp` the plist to `~/Library/LaunchAgents/`, `launchctl bootstrap gui/$(id -u) <plist>`, then `av unlock` and confirm Touch ID prompts (proving the GUI-session requirement). A system `LaunchDaemon` must NOT be used (it can't present UI) — the doc states this.
- No code; compile nothing. Commit: `docs(packaging): per-user LaunchAgent plist for avd (GUI session) [manual-verify]`.

## Task 7: Auto-lock on screen-lock/sleep (BUILD + COMPILE-VERIFY; MANUAL verify)

**Files:** `internal/daemon/autolock_darwin.go` (`//go:build darwin && cgo`), `autolock_other.go` (no-op).

- Register observers: `com.apple.screenIsLocked` (and optionally `screensaver`/sleep via `NSWorkspaceWillSleepNotification`) on `NSDistributedNotificationCenter`/`NSWorkspace.notificationCenter`; each callback invokes a Go-side `func()` that calls `session.Lock()`. Provide `StartAutoLock(s *Session) (stop func())`.
- `autolock_other.go`: `StartAutoLock` returns a no-op stop.
- **Subagent does:** write + `CGO_ENABLED=1 go build`/`vet` pass; non-cgo builds too.
- **MANUAL VERIFICATION (user):** `av unlock`, lock the screen (Ctrl-Cmd-Q), unlock the screen, `av status` → must report **locked** (auto-lock fired). Record result.
- Wire `StartAutoLock(session)` in `cmd/avd` (darwin). Commit: `feat(daemon): auto-lock session on screen-lock/sleep (cgo) [manual-verify]`.

## Task 8: Production wiring + e2e (stub) + manual smoke script

**Files:** `cmd/avd/main.go` (choose touchID vs stub presence by `AV_TEST_AUTH`; StartAutoLock; SetPresence); update `internal/client/e2e_test.go` (now `av unlock` before `av run` for normal-tier; add a dangerous-tier-never-cached e2e via stub); `scripts/manual-touchid-smoke.sh` (user-run).

- cmd/avd: `presence := daemon.NewStubPresence()` if `AV_TEST_AUTH==allow` else `p, err := daemon.NewTouchIDPresence()` (fatal/clear log if cgo build lacks it); `srv.SetPresence(presence)`; wire resolver with the same presence; `StartAutoLock(session)` on darwin.
- e2e (stub, automatable): the Phase-4 e2e must now `av unlock` (stub allows) before `av run` of the normal-tier profile; assert masking + no-leak as before. ADD: a profile with a dangerous-tier entry → after run, assert (via a follow-up `av scrub` of the dangerous value, or a direct session check helper) that the dangerous value is NOT in the session (never cached), while a normal value IS. Locked path: without `av unlock`, normal `av run` → CodeLocked → exit 69.
- `scripts/manual-touchid-smoke.sh`: documents/automates the human steps for Tasks 5-7 (build avd, install LaunchAgent, `av unlock` → expect prompt, cancel → expect denial, screen-lock → `av status` locked). The USER runs this; it is the real verification of the cgo work.
- `go test ./... -race` + `-short` + vet + `make build` (with cgo) green; no leftover daemon. Commit: `feat: wire Touch ID presence + auto-lock in avd; e2e for unlock + dangerous-never-cached`.

---

## Phase 5 — definition of done

**Automated (subagent-verified):**
- `Presence` seam in place; resolver enforces: normal-tier needs an unlocked session (else CodeLocked), dangerous-tier prompts fresh per secret and is **never written to the session** (load-bearing test) — denial → CodeDenied/exit 77.
- `av unlock`/`lock`/`status` work over RPC (stub presence); status never reveals values; session unlock/lock/auto-expiry correct and concurrency-safe.
- e2e (stub): `av unlock` then `av run` masks a real secret end-to-end; dangerous value confirmed not cached; locked `av run` → exit 69.
- `go test ./... -race`/`vet`/`make build` (cgo) green; `TestAvStaysThin` green; cgo builds AND non-cgo builds compile; no leftover daemon.

**Manual (USER-verified on hardware — NOT claimed done by a green build):**
- `av unlock` presents a real Touch ID prompt; touch unlocks, cancel → exit 69/77.
- avd as a per-user LaunchAgent can present the prompt (GUI session).
- Screen-lock auto-locks the session (`av status` → locked afterward).

## Roadmap (next): Phase 6 — real backends + hardening + adapter
1Password (`op`) + Keychain backends; Enclave-wrapped age identity (removes identity env); memguard `Secret.Value` + zeroize; rate limiting; append-only audit log; `av add/rm/init/read`; Claude Code adapter (hook + skill); gitleaks-on-scrub; connection deadlines; non-darwin stubs; the scrub reply-inflation cap fix.

## Notes for the executing engineer
- **Do not over-claim cgo.** A green `go build` with cgo means it COMPILES, not that Touch ID works. Tasks 5-7 ship with MANUAL VERIFICATION steps; the user runs `scripts/manual-touchid-smoke.sh`.
- **The dangerous-never-cached test is the security heart of this phase** — assert the dangerous value is absent from `session.Redactor()`/`Matcher()` after a resolve. Don't weaken it.
- **Keep the stub path working** so CI/e2e stay automatable (`AV_TEST_AUTH=allow` selects stub presence).
- **`av` stays thin** — unlock/lock/status use only ipc types. Run `TestAvStaysThin` after client changes.
- Commit on `main`, TDD red→green for Tasks 1-4 & 8 logic. 1Password may lock — use the signing fallback and report unsigned SHAs.
