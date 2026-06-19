# AgentVault — Tiered identity protection + auto-unlock + av version + signed distribution

**Status:** Approved (design phase)
**Date:** 2026-06-19
**Author:** Aleksandr

## Problem

The v0.2.0 "Enclave-by-default" local vault fails on the Homebrew build: a
`go build` binary is ad-hoc signed with no entitlements, so creating a Secure
Enclave SecKey returns `errSecMissingEntitlement` (OSStatus -34018). Secure Enclave
requires a binary code-signed with an Apple Team ID entitlement — impossible for
build-from-source. So `av setup` is dead on the brew install.

Separately, two UX problems surfaced while debugging this:
- There was **no way to see versions** — a stale 0.1.0 `avd` kept serving after an
  upgrade and only behavioral probing revealed it. `av --version` (and the daemon's
  version) would have caught it instantly.
- `av add` requiring an explicit `av unlock` first is needless friction for a human.

Goal: the local vault works **out of the box on every install**, uses the strongest
key protection the binary can actually provide, prompts Touch ID **on demand**, and
exposes versions/diagnostics. The strongest tier (Enclave) becomes available through
a signed distribution channel.

## Decisions (validated)

### 1. Tiers of at-rest key protection — best-available
`Enclave > keychain > plaintext`.
- **Enclave** (`identity.enc`): age key ECIES-wrapped by a per-user, non-exportable
  Secure Enclave key. Requires a **signed binary** (entitlement) — Cask channel only.
- **keychain** (login-keychain generic-password via the `security` CLI): OS-encrypted
  at rest, **no entitlement needed**. The default for the build-from-source Formula.
- **plaintext** (`identity.txt`, 0600): explicit opt-out only.

### 2. Tier selection (`av setup`)
Auto: try Enclave → on `-34018`/unsigned, fall back to **keychain** with a LOUD
warning. Detection is try-and-catch (you cannot reliably predict Enclave availability
without attempting it). Flags: `--plaintext` (explicit, weakest), `--require-enclave`
(error instead of downgrading — for signed deployments that must use Enclave),
`--keychain` (force). Plaintext is NEVER chosen automatically.

### 3. Session — all tiers session-coupled
A single "unwrapper" closure encapsulates the Touch ID, installed per tier:
- Enclave: `enclave.Unwrap` (one touch = presence AND key).
- keychain/plaintext: `presence.Prompt` (LocalAuthentication Touch ID — needs NO
  entitlement) → then read the identity bytes from the keychain item / file.
The unwrapped identity lives in the mlock'd session for the TTL and is zeroized on
lock/expiry (the existing Task 3 machinery). With NO local vault (only 1Password/
Keychain *secret* backends), unlock is just `presence.Prompt`.

### 4. Auto-unlock on demand
`av add` / `av rm` / `av read` / `av run` that need the key, on a locked session,
trigger the unlock flow inline (Touch ID), open the session for the TTL, and proceed.
`av unlock` remains as an optional "warm the session" command. **Agent opt-out:** the
`av init` adapter sets `AV_NO_PROMPT=1`; the `av` CLI then sends `NoPrompt` in the RPC,
and the daemon returns `ErrLocked` → exit 69 ("ask a human to unlock") instead of
blocking on a biometric prompt — so an agent pauses cleanly rather than stalling up to
the 60s Touch ID timeout. (This preserves the original agent-pause design intent while
fixing the human UX.)

### 5. `av version`
A new `version` RPC. `av version` prints: `av` version, `avd` version (with a LOUD
**mismatch warning** — catches the stale-daemon case), the active key-tier
(enclave/keychain/plaintext), whether the running binary is signed-for-Enclave, and the
socket path. Versions are injected at build via ldflags from the git tag
(`-X main.version=<tag>`) in the Formula and Cask.

### 6. Distribution — two channels, one codebase
- **Formula** (build-from-source, ad-hoc) → keychain tier. `brew install ...`.
- **Cask** (pre-built, signed with Developer ID + entitlements, notarized + stapled)
  → Enclave tier. `brew install --cask ...`. A Cask installs the binary AS-IS (no
  relocation/re-sign), so the signature + entitlements survive — unlike a Formula
  (ad-hoc build) or a bottle (Homebrew ad-hoc re-signs on relocation, stripping
  entitlements). The tier is chosen at RUNTIME by what the binary can do, so the same
  source serves both channels.

Entitlements (`entitlements.plist`):
```
com.apple.application-identifier = <TeamID>.com.beshkenadze.agentvault
keychain-access-groups          = [ <TeamID>.com.beshkenadze.agentvault ]
```
Signing pipeline: `codesign --options runtime --entitlements entitlements.plist -s
"Developer ID Application: …"` → `notarytool submit` → `stapler staple`. (No
provisioning profile needed for Developer-ID macOS CLI tools — cf. Secretive.)

## Implementation phases

- **Phase 1 — v0.2.1 (now):** keychain tier (identity stored/read via `security`);
  tier-selection in `av setup` (Enclave-try → keychain → `--plaintext`; `--require-
  enclave`, `--keychain`); per-tier session unwrapper; auto-unlock on demand +
  `AV_NO_PROMPT` opt-out (RPC `NoPrompt` flag, set by the adapter); `av version`
  (version RPC + ldflags + tier/signed/mismatch); honest README/caveats. The Enclave
  code path stays (works automatically once a signed binary runs it).
- **Phase 2 — v0.3.0 (when the cert/CI is ready):** codesign + notarize pipeline,
  the `entitlements.plist`, and the Homebrew **Cask** carrying the signed binary.

## Security properties

- Strongest tier the binary can provide is used automatically; downgrade is loud and
  plaintext is never silent.
- Every tier gates the key behind Touch ID at unlock and holds it only in an mlock'd
  session, zeroized on lock — even the plaintext-on-disk key is only loaded into the
  daemon after a presence check and only during the unlocked window.
- Enclave (signed channel): the key never leaves hardware; a daemon compromise after
  lock cannot decrypt.
- `av` stays thin (no age/enclave); `av setup`/`av version` are pure RPCs.

## Non-goals
- Linux/Windows (still macOS-only).
- Mac App Store distribution / sandboxed app.
- Touch-ID-gated keychain ACLs on unsigned binaries (the unlock presence gate already
  covers this; per-item biometric ACLs risk the same entitlement wall).
