# AgentVault — Zero-config writable store + session-coupled Enclave identity

**Status:** Approved (design phase)
**Date:** 2026-06-19
**Author:** Aleksandr

## Problem

After `brew install agentvault && brew services start agentvault` there is **no
writable backend**: Keychain and 1Password are read-only in AgentVault, and the
age-file backend only activates when the daemon is hand-fed `AV_AGE_VAULT` + an age
identity via env. So `av add` / `av rm` are dead on arrival — to store a secret with
AgentVault's own command a user must first hand-generate an age identity, create a
vault, and reconfigure the daemon. That is an onboarding cliff, not KISS.

Goal: `brew install → brew services start → av setup → av add NPM_TOKEN → av run`
works with zero hand-configuration, and the vault key is hardware-protected by
default (Secure Enclave).

## Decisions (validated)

1. **Explicit `av setup` (one-time), not lazy auto-provision.** Crypto material is
   created by a deliberate user action, never silently by a write command.
2. **Enclave-wrapped identity, unwrapped at `av unlock`, held in the mlock'd session
   for the TTL, zeroized on lock.** One Touch ID per unlock covers both the session
   and the vault key; the daemon does NOT unwrap at startup (no login prompt); a
   daemon compromise after lock cannot decrypt the vault.
3. **Unlock unification:** when a wrapped identity is configured, `av unlock` *is*
   the `enclave.Unwrap` — a successful unwrap proves presence. One Touch ID, not two.
   When there is no wrapped identity (Keychain/1Password only), unlock falls back to
   the existing `presence.Authorize`.
4. **`av setup` is an RPC to `avd`, not local crypto in `av`.** `av` must stay thin
   (`TestAvStaysThin` forbids it linking `filippo.io/age` / `internal/enclave`).
   `avd` (which already links both) does keygen + Enclave-wrap + vault creation and
   registers the file backend live; `av setup` only sends the request and prints
   the resulting paths (never a key).
5. **Default paths, auto-discovered by the daemon (no env):**
   `~/.config/agentvault/identity.enc` (Enclave-wrapped blob, 0600) and
   `~/.config/agentvault/vault.age`. Honors `$XDG_CONFIG_HOME` if set. Existing
   `AV_AGE_*` env still wins (explicit override / CI).

## Architecture changes

### `IdentitySource` seam (identity leaves the backend, moves to the session)

Today `agefile.Backend` holds a fixed `age.Identity` injected at construction, and
`cmd/avd` unwraps it eagerly at startup. New shape:

```go
// IdentitySource yields the age identity for the file backend, or ErrLocked.
type IdentitySource interface { Identity() (age.Identity, error) }
```

- `agefile.New(src IdentitySource, vaultPath)` — `Resolve`/`Add`/`Remove`/`recipient`
  call `src.Identity()` per operation instead of holding a key.
- A trivial `StaticIdentity` source (wraps a fixed identity) preserves the old
  behavior for tests and the plaintext / env path.

### Session holds the unwrapped identity

- `Session` gains an optional **unwrapper** `func() (age.Identity, error)` (a closure
  over `enclave.Unwrap(blob)`), set by `avd` when a wrapped identity is configured.
- `Unlock`: if an unwrapper is set, call it (this is the Touch ID) and store the
  result as a mlock'd `lockedIdentity` (mirrors `lockedValue`); otherwise
  `presence.Authorize` as today.
- `Session` implements `IdentitySource`: `Identity()` returns the held identity, or
  `ErrLocked` when locked/expired.
- `Lock` / TTL expiry / auto-lock → zeroize the identity alongside issued values.

### Daemon wiring & discovery

- `registerBackends`: if `AV_AGE_VAULT`/`AV_AGE_IDENTITY*` unset, probe the default
  paths; if `vault.age` + `identity.enc` both exist, configure the session unwrapper
  and register the file backend with the session as its `IdentitySource`. If they do
  not exist, no file backend yet (Keychain/1Password still work).
- New **`setup` RPC**: `avd` generates an X25519 identity → `enclave.Wrap` →
  writes `identity.enc` (0600) + an empty `vault.age` (atomic) at the default (or
  requested) path → configures the unwrapper + registers the file backend live, so a
  following `av add` works with no daemon restart. Idempotent: refuses to clobber an
  existing store unless `--rotate`; `--plaintext` provisions an unwrapped identity
  (0600) for machines without a Secure Enclave (explicit opt-out, logged).

### CLI

- New `av setup [--rotate] [--plaintext]` → `setup` RPC → prints created paths
  (no key material) or "already provisioned".
- `av add` / `av rm` with no writable backend → `av: no local vault — run 'av setup'
  first` (exit 2), instead of a cryptic "no backend".
- `av init` is unchanged (it stays about agent adapters — SSOT).

## Security properties (unchanged or strengthened)

- Key at rest is Enclave-wrapped; the unwrapped key exists only in the unlocked
  session window, mlock'd and zeroized on lock — strictly better than the previous
  "unwrap once at startup, hold for daemon lifetime".
- No login-time Touch ID (the daemon never unwraps until `av unlock`).
- `av` stays thin (setup is an RPC; no age/enclave in `av`).
- `av setup` performs no unwrap → no Touch ID; only `av unlock` (unwrap) prompts.

## Testing

- `av setup`: provisions files (modes 0600), idempotent, `--rotate`, `--plaintext`.
- Auto-discovery: daemon wires the file backend from default paths when present.
- Session: unlock-with-unwrapper holds the identity; lock/TTL zeroizes it;
  `Identity()` returns `ErrLocked` when locked. Uses a **stub unwrapper** in tests
  (same pattern as `AV_TEST_AUTH=allow`) so no real Enclave is needed in CI.
- Unlock unification: with an unwrapper, unlock calls it once and does NOT also call
  `presence.Authorize`; without one, it calls `presence.Authorize`.
- Regression: **no login Touch ID** — `avd` starts (and registers the backend)
  without unwrapping.
- `av add` with no store → the helpful error + exit 2.
- e2e: `setup` → `add` → `unlock` → `run` masks the value (stub unwrapper).

## Docs / packaging

- Root `README.md`: the real flow `brew install → brew services start → av setup →
  av add → av run`, backends table, security model, manual-verification pointer.
- Homebrew formula: no change required (env is no longer needed); caveats mention
  `av setup`.

## Non-goals

- Linux/Windows (still macOS-only v1).
- Changing Keychain/1Password to writable (they remain read-only; managed by their
  own tools).
- Multi-vault / vault selection (single default vault in v1).
