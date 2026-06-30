# `avd` as a Login Item — design

> Make the broker start at login with zero manual steps, via Apple's modern
> `SMAppService` for the signed cask and a `~/Library/LaunchAgents` fallback for
> build-from-source — replacing the broken `brew services start agentvault` story
> (casks cannot declare a service).

**Status:** design approved 2026-06-30. Implementation plan to follow
(`writing-plans`).

## Problem

There is no real Login Item today. `avd` is started *lazily* by
`internal/client/autostart_darwin.go` the first time `av` dials the socket
(detached, `Setsid`). It survives the `av` process, but **nothing brings it back
at next login.** The documented "start it" command — `brew services start
agentvault` (`getting-started.md §2`, cask `caveats`) — is a no-op: Homebrew
**casks cannot declare a `service` block**, only formulae can. So the resident-at-
login promise is currently false.

## Decisions

Two forks settled during brainstorming:

1. **Scope — hybrid.** `SMAppService` only works for the signed `.app` (it seals
   the plist inside the bundle and is macOS 13+). Build-from-source ships a bare
   `avd` Mach-O with no bundle, so it gets a traditional `~/Library/LaunchAgents`
   plist instead. One interface, two backends, auto-selected at runtime.

2. **Trigger — the setup/enable action, never every start.** Since macOS 13 a
   login item is a **user-owned setting**: macOS notifies the user on first
   registration ("AgentVault added items that can run in the background") and
   surfaces a toggle in **System Settings → General → Login Items → Allow in the
   Background**. An app that re-registers on every launch *fights* a user who
   turned it off — the exact anti-pattern that toggle exists to stop. So:
   - `av setup` (deliberate user action) auto-registers, best-effort.
   - `av service on` / `off` give explicit control.
   - **A plain `avd` start does nothing about registration.** launchd /
     SMAppService already starts it at login; avd never re-asserts the toggle.
   - A bare `go run ./cmd/avd` (no vault, no setup) never creates a login item —
     no dev surprise.

## Architecture

### Registration runs inside `avd`, not `av`

`SMAppService.agent(plistName:)` resolves the plist relative to the **calling
process's main bundle**. `avd` runs from `AgentVault.app/Contents/MacOS/avd`, so
its main bundle is the app. `av` lives at `bin/av` — a different location, no
bundle. Therefore **only `avd` can register.** `av service on` is a thin RPC to
the daemon; avd performs the register. This fits the trigger: `av setup`
cold-starts avd (autostart fix below), then asks it to register.

### One interface, two backends

New package `internal/loginitem`:

```go
type State int
const (
    StateDisabled        State = iota // not registered / user turned it off
    StateEnabled                      // registered, starts at login
    StateRequiresApproval             // SMAppService only: user must approve in Settings
)

type Manager interface {
    Enable() error            // register / install + bootstrap (idempotent)
    Disable() error           // unregister / bootout + remove
    Status() (State, error)
}
```

- `smappservice_darwin.go` (+ `.m` cgo shim, modeled on
  `internal/enclave/enclave_darwin.m`) — used when `os.Executable()` is inside
  `…/Contents/MacOS/avd` **and** macOS ≥ 13. Wraps
  `+[SMAppService agentServiceWithPlistName:]`, `-registerAndReturnError:`,
  `-unregisterAndReturnError:`, `.status`.
- `launchagent_darwin.go` (pure Go) — renders an **embedded plist template**
  (absolute path from `os.Executable()`, log paths) to
  `~/Library/LaunchAgents/app.bshk.agentvault.avd.plist`, then
  `launchctl bootstrap gui/$uid …`. Disable = `launchctl bootout …` + remove
  file. Used for the bare-binary tier (macOS 11+).
- `manager_other.go` — non-darwin stub (v1 is macOS-only).

A detector (`bundle path? + macOS version`) selects the backend. The av-side
command and the RPC are identical for both; `av service status` reports *which*
backend and its state.

### Two plist shapes (this splits the original "rewrite the plist" item)

- **Bundled SMAppService plist** — `packaging/app.bshk.agentvault.avd.plist`
  rewritten with `BundleProgram = Contents/MacOS/avd` (relative), `RunAtLoad`,
  `KeepAlive`, `ProcessType Interactive`, **no `__PLACEHOLDERS__`**. Lives at
  `AgentVault.app/Contents/Library/LaunchAgents/` and is sealed by the signature.
- **Fallback traditional plist** — an **embedded Go template** in
  `internal/loginitem` (absolute `ProgramArguments` path), written at
  `av service on` time. Not a packaging file (avd knows its own path at runtime).

## Command surface

| Command | Behavior |
|---|---|
| `av service status` | RPC → avd reports backend + `State`; prints whether it starts at login |
| `av service on` | RPC → avd `Enable()` (explicit, idempotent) |
| `av service off` | RPC → avd `Disable()` (escape hatch; mirrors the Settings toggle) |

`av setup`, after provisioning the vault:

```
created vault …
(best-effort) Enable():
  • SMAppService tier → macOS notifies "added background item"
  • prints: "avd will start at login. Manage in System Settings → General →
    Login Items, or `av service off`."
```

Registration is **best-effort**: if `Enable()` fails (e.g. SMAppService
`requiresApproval`), `av setup` still succeeds — it warns and points to Login
Items. Provisioning and autostart are independent; one failing must not abort the
other.

**Three-state status** (SMAppService adds `requiresApproval`):

- `enabled` — registered, starts at login.
- `requires-approval` — registered but the user must flip it on in Settings (print
  the path; optionally `SMAppService.openSystemSettingsLoginItems()`).
- `disabled` — not registered / turned off. `av service on` to re-enable.

The LaunchAgent backend only reports `enabled` / `disabled`.

## File map

| # | File | Change |
|---|---|---|
| 1 | `internal/client/autostart_darwin.go` | add candidate `<dir>/AgentVault.app/Contents/MacOS/avd` to the avd lookup (cask layout) |
| 2 | `packaging/app.bshk.agentvault.avd.plist` | rewrite as the bundled `SMAppService` plist (`BundleProgram`, no placeholders) |
| 3 | `scripts/release-signed.sh` | copy bundled plist into `AgentVault.app/Contents/Library/LaunchAgents/` **before** signing |
| 4 | `internal/loginitem/{manager,smappservice_darwin,launchagent_darwin,manager_other}.go` + `.m` | interface, detector, cgo SMAppService shim, pure-Go LaunchAgent backend, stub, embedded fallback template |
| 5 | `cmd/av/main.go`, `internal/ipc`, `internal/daemon/server.go` | `av service on/off/status`, new RPC, avd handler; `av setup` best-effort `Enable()`; **avd start does not register** |
| 6 | `packaging/avd.app.Info.plist.template`, `agentvault-cask.json` | `LSMinimumSystemVersion 11.0 → 13.0`; cask `depends_on macos: :ventura` |
| 7 | `agentvault-cask.json` caveats, `getting-started.md`, `launchagent.md`, `README.md` | remove `brew services start agentvault`; document the `av setup` → Login Items story |

## Test boundary

cgo / `SMAppService` cannot run in CI (no signed bundle, no GUI session) — the same
boundary as the Touch ID path.

- **Unit:** detector (bundle-path + version gate via injected inputs); LaunchAgent
  plist rendering (template → golden); `launchctl` command construction via an
  **injected runner** (the Keychain-backend pattern); `av service` arg parsing;
  RPC round-trip with a fake `Manager`.
- **Manual** (documented in `launchagent.md`): real `SMAppService` register → the
  macOS "added background item" notification → item appears in Login Items →
  survives logout/login.

## Non-goals

- No Windows/Linux autostart (v1 is macOS-only).
- avd does not self-heal the *registration* on start (only the existing
  version-skew daemon restart remains). Registration drift is fixed with
  `av service on`.
