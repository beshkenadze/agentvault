# AgentVault Phase 6 — Real Backends + Hardening + Adapter Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or subagent-driven-development) to implement this plan task-by-task.

**Goal:** Complete v1: the real secret backends (1Password, macOS Keychain), the remaining security hardening (rate limiting, audit log, memguard, gitleaks-on-scrub, `av read` TTY-guard, connection deadlines, Enclave-wrapped identity), and the agent adapter (`av init`, `av add/rm`). After this phase, AgentVault matches the approved design's v1 scope.

**Architecture:** Builds on Phases 1-5 (redaction core, IPC, backends interface, session+run, Touch ID + dangerous tier). Most additions slot behind existing seams: new `backend.Backend` implementations, an `audit` package the daemon writes to, a rate limiter in the resolver/session path, gitleaks wired into the existing layer-2 scrub, and new `av` subcommands.

**Tech Stack:** Go 1.26.3 (+cgo for Secure Enclave); `github.com/awnumar/memguard` (or equivalent) for locked memory; the existing gitleaks/age deps; the `op` CLI (1Password) and macOS Keychain (`security` CLI or go-keychain) as external integrations.

**THIS PHASE IS LARGE — execute in 3 groups (each is a green, shippable checkpoint):**
- **Group A — Security completeness (all TESTABLE):** Tasks A1-A8. Highest value, fully TDD-able. Do this first.
- **Group B — Real backends (MOCK-testable + MANUAL for the real integration):** Tasks B1-B3. `op`/Keychain/Enclave need real env/hardware; test the logic via injected runners, verify the real path manually.
- **Group C — Adapter & vault management (TESTABLE content + MANUAL integration):** Tasks C1-C2.

**Testability legend:** `[TDD]` fully automated; `[MOCK+MANUAL]` logic tested via injected mock, real integration user-verified; `[COMPILE+MANUAL]` cgo/hardware — compile-verified by subagents, hardware-verified by the user (same boundary as Phase 5 Touch ID).

**Scope:** Phase 6 completes v1. **Out of v1 (design Non-goals):** malicious-agent defense, Windows/Linux full support (Phase 6 adds non-darwin BUILD stubs only so the tree cross-compiles, not full platform auth), external plugin backends, the ML classifier, Vault/AWS backends.

**Design reference:** `docs/plans/2026-06-17-agentvault-design.md` — *Backends*, *Redaction pipeline* (ML/gitleaks), *Security model*, *CLI surface*, *Error handling*. Carry-in Minors from prior phase reviews are folded into the tasks below.

---

# Group A — Security completeness (TESTABLE)

## Task A1: `av read NAME` with non-TTY refusal [TDD]
The deliberate guard from the design: an agent reading a value through a pipe must get nothing.
- `internal/client` + `cmd/av`: `av read NAME` resolves a single logical name (via a `resolve`-style RPC or a dedicated `read` RPC) and prints the value — **but only if stdout is a TTY**. If stdout is NOT a TTY (a pipe/file), refuse with a distinct exit code + message ("av read refuses non-TTY output; an agent must use av run").
- Use `golang.org/x/term`'s `term.IsTerminal(int(os.Stdout.Fd()))` (or `os.Stdout.Stat()` + `ModeCharDevice`).
- Tests: stdout-is-pipe → refuses (exit code, nothing printed); the TTY path is hard to unit-test (no TTY in CI) — test the guard function directly with a fake fd / inject the isTTY check so the refusal branch is fully covered. (This refusal is the security property; the print-on-TTY branch is the easy direction.)
- Security regression test (design's Testing section): `av read` through a pipe never prints a value.

## Task A2: Rate limiting on issuance [TDD]
Design: "mass enumeration forces a relock and raises an alert."
- A rate limiter in the resolve path (daemon): count issuances within a window; beyond a threshold (e.g. N secrets / M seconds) → `session.Lock()` + emit an alert (to the audit log, Task A3) + return a distinct error.
- Injectable clock (reuse the session's clock pattern) so tests don't sleep.
- Tests: under threshold → fine; a burst over threshold → relocks the session + the next resolve returns CodeLocked + an alert recorded.

## Task A3: Append-only audit log [TDD]
Design: "append-only audit log of every issuance (one entry per dangerous touch)."
- `internal/audit`: an append-only writer (JSONL to a file under the user dir, mode 0600). One entry per: issuance (name, tier, profile, timestamp — **NEVER the value**), dangerous-tier touch, unlock, lock, rate-limit alert, denied access.
- Wire into the resolver/session/unlock paths.
- Tests: each event produces exactly one entry; entries contain names/tiers/timestamps but **no secret value** (assert the value never appears in the log); the log is append-only (existing entries preserved); file mode 0600.
- SECURITY: grep the audit output for the value in tests — it must never appear.

## Task A4: gitleaks-on-scrub (layer-2 derived-secret net) [TDD]
Deferred from Phase 4. Wire the gitleaks `Detector` into the streaming scrub so derived secrets (and dangerous values, which aren't session-cached) get a heuristic net.
- The per-connection scrub `StreamRedactor` currently uses only the session's exact-match Matcher. Add the gitleaks tier: after exact-match masking of a flushed region, run the session `Redactor`'s gitleaks `Detector` over it (whole-string per flush, since gitleaks is not streaming). Handle the chunk boundary: gitleaks runs on the exact-match-masked output of each flush; a derived secret split across chunks may be missed at the seam — acceptable (note it), or buffer per-line.
- Reuse `internal/detect/gitleaks` (already isolated; only avd links it — keep av thin).
- Tests: a derived token (e.g. a `ghp_...` the daemon never issued) piped through `av scrub` is masked as `{{AV:REDACTED:<rule>}}`; a normal commit hash is NOT over-masked into a problem (recall-over-precision is fine, but assert the basic case).

## Task A5: memguard-protected secret values + zeroize [TDD where possible]
Design: "mlock so secrets never hit swap, zeroize on TTL expiry."
- Add `github.com/awnumar/memguard` (or implement a minimal mlock+zeroize buffer). Protect the at-rest secret storage in the daemon session (the issued values) and zeroize on `Lock()`/expiry. `av run`'s transient values zeroized on exit (already best-effort; upgrade).
- KNOWN TENSION (document): the redactor's Matcher needs cleartext strings to mask, so derived encoding forms exist transiently in normal Go memory; memguard protects the canonical stored value, not every derived form. Scope honestly: protect `backend.Secret`/session storage + zeroize; note the matcher-forms limitation.
- `backend.Secret.Value` may change from `string` to a protected type — this ripples through resolver/session/run; do it carefully behind a small accessor so the redactor can still get a string when masking.
- Tests: a value is zeroized after `Lock()`/expiry (where observable); mlock may need RLIMIT_MEMLOCK — gate the mlock assertion or skip if unprivileged, but always test zeroize.

## Task A6: Connection deadlines + scrub reply-inflation cap [TDD]
Two hardening carry-ins.
- Daemon `handle`: set read/write deadlines on the conn (e.g. idle timeout) so a peer that connects and stalls doesn't park a goroutine forever. Reset the deadline per request.
- scrub: the masked reply can exceed the 1 MiB JSON-RPC line cap for pathologically short secrets (Phase 4 minor). Size the client's scrub chunk against the cap accounting for max placeholder inflation, OR have the daemon split oversized masked replies. Tests: a stalled conn times out; a chunk of a 1-byte secret doesn't blow the decoder cap.

## Task A7: Non-darwin build stubs [TDD]
The tree currently doesn't cross-compile (`transport.CheckPeer`, presence, autolock are darwin-only with no non-darwin counterpart for CheckPeer).
- Add `//go:build !darwin` stubs: `transport.CheckPeer` (Linux: SO_PEERCRED via x/sys/unix `Getsockopt...Ucred`, OR a clear "unsupported" stub for non-macOS to keep v1 macOS-only but cross-compilable). Given v1 is macOS-only, a stub returning an error is acceptable — the goal is `GOOS=linux go build ./...` succeeds.
- Tests/CI: `GOOS=linux CGO_ENABLED=0 go build ./...` succeeds; `GOOS=darwin` unchanged.

## Task A8: Carry-in Minors [TDD]
- TTL SSOT: collapse `daemon.unlockTTL` and `cmd/avd.sessionTTL` (both 15m) to one source.
- Touch ID prompt timeout: replace `DISPATCH_TIME_FOREVER` with a bounded wait (e.g. 60s) in `touchid_darwin.m` so a never-answered prompt eventually returns ErrDenied (fail-closed). [COMPILE-verify; the timeout firing is manual but the bound is reviewable.]
- Update the stale `cmd/avd` `sessionTTL` comment ("auto-lock-on-screen-lock is Phase 5").

**Group A done:** all `go test ./... -race`/vet/build(cgo+nocgo)/cross-compile green; av thin; audit/rate-limit/read-guard tested; no value in audit.

---

# Group B — Real backends (MOCK-testable + MANUAL)

## Task B1: 1Password backend via `op` CLI [MOCK+MANUAL]
- `internal/backend/onepassword`: implements `backend.Backend` by shelling out to `op read "op://Vault/Item/field"` (map the `av://1p/Vault/Item/field` locator → `op://...`). Inject the exec runner (`type runner func(args ...string) ([]byte, error)`) so tests use a mock; production uses real `op`.
- Isolated package (like agefile) so its weight/deps don't reach `av`.
- Tests [TDD via mock runner]: locator→op-ref mapping; success parses the value; `op` error → backend error (no value in error); not-found → ErrNotFound.
- **MANUAL:** with `op` installed + signed in, register the backend and resolve a real `av://1p/...` ref end-to-end. Document in a smoke note.
- Register in `cmd/avd` under "1p" when configured (env/flag for the op path).

## Task B2: macOS Keychain backend [MOCK+MANUAL / macOS-only]
- `internal/backend/keychain` (`//go:build darwin`): implement `backend.Backend` over the macOS keychain (`security find-generic-password` via injected runner, or go-keychain via cgo). Map `av://keychain/<service>/<account>` → keychain item.
- Tests [TDD via mock runner on darwin]: mapping + parse + not-found. A real-keychain integration test may write/read a temp item under a test service name with cleanup (macOS dev machine only; guard with testing.Short()).
- Register under "keychain" in cmd/avd.

## Task B3: Secure-Enclave-wrapped age identity [COMPILE+MANUAL]
Design: the file backend's age key wrapped in the Secure Enclave with a user-presence ACL — so even daemon compromise can't decrypt without live Touch ID.
- cgo: generate/load a SecKey in the Secure Enclave (`kSecAttrTokenIDSecureEnclave`, access control `kSecAccessControlUserPresence`); use it to wrap/unwrap the age identity (or derive a key that decrypts the age file). Replace the `AV_AGE_IDENTITY` env path with the Enclave-wrapped key.
- COMPILE-verify (cgo builds; non-cgo fallback to the env-path identity for testability); MANUAL hardware verification (Enclave + Touch ID on real hardware).
- This is the deepest hardware integration — scope carefully; if it proves too large, ship the file backend with the env-path identity (Phase 5 state) and mark Enclave-wrapping as a documented follow-up. Be honest about what's compile-only.

**Group B done:** backends mock-tested green; av still thin (no op/keychain/Enclave deps in cmd/av); manual smoke notes for the real integrations.

---

# Group C — Adapter & vault management (TESTABLE content + MANUAL integration)

## Task C1: `av add` / `av rm` (manage the age vault) [TDD]
- `av add NAME` (reads the value from a TTY prompt or stdin — NEVER echoes it; refuses to read a value from a non-TTY arg to avoid it landing in shell history/argv) and `av rm NAME`: load the age vault, modify the name→value map, re-encrypt via `agefile.EncryptVault` with **atomic write-then-rename** (write temp, fsync, rename) so a crash can't corrupt the vault. Close the EncryptVault writer-leak path noted in P3.4.
- Tests [TDD]: add→the value resolves; rm→ErrNotFound; atomic write (a temp file + rename; partial write doesn't clobber the live vault); `ls` (metadata only) shows names without values.
- SECURITY: the value is never in argv/history/logs; add reads from TTY/stdin only.

## Task C2: `av init --agent claude-code` (the agent adapter) [TDD content + MANUAL integration]
The payoff: generate the per-agent hook + skill so a real agent uses AgentVault.
- `av init --agent claude-code|generic`: generate (a) the Claude Code hook script that pipes tool output through `av scrub` (layer 2) for every context-ingress channel (Bash output, file reads, MCP output — per the design's adapter contract), and (b) a skill/doc file telling the agent to use `av run`/`av scrub` and to treat `{{AV:NAME}}` as opaque.
- Generated, not hand-written; the core stays agent-agnostic (template per agent).
- Tests [TDD]: the generated hook + skill files have the expected shape/content; the scrub-coverage contract is documented (enumerate the channels). 
- **MANUAL integration:** install the generated hook in a real Claude Code project and confirm a command run via `av run` shows `{{AV:NAME}}` and a value piped through a hooked tool is masked. (This is the real-world proof of the whole project.)

> **Implemented.** Generator lives in `internal/adapter` (pure stdlib: `embed` +
> `os` — no backend/age/gitleaks, so `av` stays thin; `TestAvStaysThin` still
> green). The registry (`internal/adapter/adapter.go`) is the SSOT for which agents
> are supported; adding an agent = a registry entry + template files under
> `internal/adapter/templates/<agent>/`, no new logic.
>
> **Generated for `claude-code`** (into cwd, or `--dir D`):
> - `.claude/hooks/av-scrub.sh` (0755) — `#!/bin/sh` … `exec av scrub` (layer-2).
> - `.claude/agentvault.hooks.json` — a **PostToolUse** wiring snippet, explicitly
>   labeled a TEMPLATE TO MERGE (not an authoritative schema — the Claude Code hook
>   shape varies by version) that carries the scrub-coverage contract.
> - `.claude/skills/agentvault/SKILL.md` — tells the agent: use `av run --profile P
>   -- <cmd>`; pipe tool output through `av scrub`; treat `{{AV:NAME}}` as opaque
>   (never recover the value); `av read` is for a human TTY only. Includes the
>   coverage contract (channels that MUST be hooked: Bash/shell, file reads, MCP
>   tool output, web fetch/search, any future ingress channel).
>
> **Generated for `generic`:** `agentvault/av-scrub.sh` (0755) +
> `agentvault/AGENTVAULT.md` (same contract, no Claude-Code-specific paths).
>
> **No-clobber:** `av init` refuses to overwrite an existing file (conflicts detected
> up front, nothing written) unless `--force` is passed, so a user's customized hook
> is never destroyed. Unknown agent / write conflict → exit 2, secret-free message.
>
> **MANUAL real-world proof (cannot be run by a subagent — needs a live Claude Code
> session):** in a real Claude Code project, run `av init --agent claude-code`, merge
> `.claude/agentvault.hooks.json` into your Claude Code settings (adjust the matcher
> to your version), then (1) confirm a command run via `av run --profile P -- …`
> shows `{{AV:NAME}}` in place of the value, and (2) read a file / run a tool whose
> output contains a known secret and confirm the PostToolUse scrub hook masks it
> before it reaches the model's context.

**Group C done:** add/rm/init tested; generated adapter content verified; manual integration note for the real Claude Code hook.

---

## Phase 6 — definition of done

**Automated:** `av read` refuses non-TTY (security regression test); rate limiting relocks + alerts; append-only audit log with no values; gitleaks-on-scrub masks derived secrets; memguard zeroizes on lock/expiry; connection deadlines + scrub cap; cross-compiles (GOOS=linux build green); 1Password/Keychain backends mock-tested; `av add/rm` atomic + TTY-only; `av init` generates the adapter; `go test ./... -race`/vet/build(cgo+nocgo)/cross green; av thin (no op/keychain/enclave/gitleaks in cmd/av).

**Manual (USER, on hardware/real env):** real `op` resolve; real Keychain resolve; Secure-Enclave identity + Touch ID unwrap; the Claude Code adapter masking a real secret in a real agent session; (carry-over from Phase 5) Touch ID prompt + auto-lock smoke.

## Notes for the executing engineer
- **Execute in groups A → B → C**; each group is a green checkpoint. Group A is the highest-value, fully-testable security completeness — do it first.
- **Never log/audit a secret value** — audit entries carry names/tiers/timestamps only; assert this in tests.
- **Keep `av` thin** — op/keychain/enclave/gitleaks live only in avd's path; run `TestAvStaysThin` after every change.
- **Real integrations (op/Keychain/Enclave/Claude-Code hook) are MANUAL** — subagents mock + compile-verify; the user verifies the real path. Don't claim them working from a green build.
- Commit on `main`, TDD red→green for all `[TDD]` work. 1Password may lock — use the signing fallback and report unsigned SHAs; batch re-sign before any push. (Outstanding from Phase 5: 7 unsigned commits `1e5ca4a..481e116`.)
```
