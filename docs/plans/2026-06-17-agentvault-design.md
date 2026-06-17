# AgentVault — Design (refined)

**Status:** Approved (design phase)
**Date:** 2026-06-17
**Language:** Go
**Author:** Aleksandr
**Supersedes:** initial design dated 2026-06-11 (see *Changelog from initial design*)

## Problem

AI coding agents need credentials (API keys, tokens, passwords) to run harnesses
and smoke tests, but must never receive those values as plaintext in their
context. The values are required by the subprocesses the agent launches, not by
the agent itself.

Today this works via 1Password plus RTK, an stdout/stderr proxy that filters
secret values before they reach the LLM. AgentVault replaces that ad-hoc setup
with a single, agent-agnostic CLI that fronts pluggable secret backends, gates
access behind native OS authentication, and guarantees that values cannot be read
back into the agent's context by accident.

## Threat model

**In scope:** accidental exposure by a cooperative agent. The agent is not
adversarial; it will not deliberately exfiltrate secrets or attack the host. The
job is to make it *impossible to read a secret value by accident* — through env
inspection, command output, log files, or a careless `cat`.

**Out of scope for v1:** an actively malicious agent, prompt-injection-driven
exfiltration, or an attacker with root / debugger access under the user's own UID.
No userspace design stops those; see Non-goals. The security model still reduces
the blast radius of a daemon compromise, but defeating an active local attacker is
a non-goal.

This scope drives a key simplification: because the agent will not `ptrace` or
read `/proc` of its own helper processes, plaintext may transit the short-lived
`av run` process. Hardening against a *malicious* agent reading that memory would
be effort spent on an out-of-scope threat.

## Architecture

Daemon-plus-thin-CLI. Three parts:

- **`avd`** — a resident broker. Talks to backends, holds the unlocked session,
  drives native authentication, runs the redaction service, keeps the audit log,
  and enforces rate limits. It is a *broker, not a store*: it owns no master key
  and never caches the full vault. Only values issued during the current session
  live in memory (needed for exact-match redaction). `avd` is the one binary that
  receives full hardening.
- **`av`** — a thin CLI the agent invokes. It carries no backend or storage logic
  and forwards requests to `avd` over a local socket. One subcommand, `av run`, is
  the sole exception: it handles plaintext transiently to inject the environment
  and to mask its child's output at the source. It zeroizes that plaintext on
  exit. Peer credentials are verified on every connection.
- **Agent adapters** — generated, not hand-written. `av init --agent <name>`
  produces the hook script and skill file for a given agent. The core stays
  agent-agnostic; per-agent specifics live entirely in generated adapters.

### Division of labour

| Concern | Lives in |
|---|---|
| Backend access (`op`, keychain, age-file) | `avd` |
| Session (issued values), TTL, auto-lock | `avd` |
| Native auth / Touch ID prompts | `avd` |
| Redaction service for layer 2 (`av scrub`) | `avd` |
| Audit log, rate limiting | `avd` |
| Memory hardening (mlock, zeroize, no-dump) | `avd` |
| Resolve a profile → values | `avd` (served to `av run`) |
| Inject env, fork/exec child, source-mask child stdio | `av run` |
| Relay other CLI verbs to `avd` | `av` |

### IPC

- Transport: unix domain socket in `$XDG_RUNTIME_DIR` (mode `0600`). No network
  listener, ever.
- Protocol: newline-delimited JSON-RPC. Minimal surface, trivial parser.
- Authentication: peer-credential check that the client UID equals the daemon UID
  — `getpeereid` on macOS.
- Lifecycle: `av` autostarts `avd` on first use. `avd` runs as a **per-user
  `launchd` LaunchAgent in the Aqua/GUI session** — required so `LocalAuthentication`
  can present a Touch ID prompt. A system `LaunchDaemon` cannot show that UI and is
  therefore disallowed.

### Process and redaction flow

```
agent --(Bash tool)--> av run --profile P -- cmd
   av  --socket-->  avd: resolve(P)
        avd: normal-tier  -> serve from open session (within TTL)
             dangerous    -> fresh Touch ID per secret, never cached
   avd  -->  av: { NAME: value, ... }
   av:  inject env -> fork/exec cmd
   av:  child stdout/stderr -> mask (exact-match) -> own stdout -> zeroize   [LAYER 1]
agent output hook: any tool output -> av scrub -> avd (exact-match + gitleaks) [LAYER 2]
```

`av run`'s output passes through **both** layers — that is the point of the
design, not redundancy to remove.

## Backends and manifest

In v1, backends are compiled-in Go implementations behind one interface — not an
external plugin system (YAGNI until third-party code must load).

```go
type Backend interface {
    Resolve(ref string) (Secret, error)   // fetch one secret value
    List(prefix string) ([]Meta, error)   // enumerate metadata only, no values
}
```

References use a 1Password-style scheme: `av://1p/Vault/Item/field`.

Each project carries an `agentvault.yaml` that maps logical names to references,
assigns a tier, and declares how each maps into the subprocess environment. The
agent deals only in logical names; it never sees a reference resolve to a value.

```yaml
# agentvault.yaml
profiles:
  smoke:
    GITHUB_TOKEN:
      ref: av://1p/Eng/GitHub CI/token
      tier: normal
    STRIPE_SECRET:
      ref: av://1p/Eng/Stripe/secret_key
      tier: dangerous
```

`tier` is `normal` or `dangerous`. Dangerous-tier secrets are never cached and
require fresh user presence on every access (see below).

v1 backends (all on macOS):

- **1Password** — via the `op` CLI initially; migrate to the official 1Password Go
  SDK later.
- **OS keychain** — macOS Keychain via `go-keychain`.
- **File** — an `age`-encrypted file (`filippo.io/age`) whose key is wrapped in the
  Secure Enclave (see Security model).

Later: HashiCorp Vault, AWS Secrets Manager.

## Native authorization (macOS, v1)

Unlock is hybrid: one biometric prompt opens a session with a TTL; dangerous-tier
secrets additionally require fresh presence on each access.

| OS | Mechanism | Key storage |
|----|-----------|-------------|
| macOS | LocalAuthentication (Touch ID) via cgo | Secure Enclave |

Windows Hello and Linux polkit/`fprintd` are deferred (see Non-goals).

Session behaviour:

- Unlock → session valid for a TTL (default **15 minutes**).
- Auto-lock on screen lock or system sleep.
- `normal`-tier reads are served from the open session without re-prompting.
- `dangerous`-tier reads always trigger a **fresh Touch ID prompt per secret** and
  are never cached, so a compromised daemon cannot issue them to itself. When one
  `av run` needs several dangerous secrets, the user touches the sensor once per
  secret. Each prompt **names the specific secret and the command** it authorizes
  (`Allow 'pytest' to use STRIPE_SECRET? [Touch ID]`) so the user can tell the
  prompts apart and the audit log records one touch per issuance.
- When no human is present (the agent invoked `av run` headless), a dangerous read
  blocks until timeout, then returns a distinguishable exit code so the agent
  pauses and asks a human.

## CLI surface

- **`av run [--profile X] -- <cmd>`** — the primary path. Resolves the profile's
  secrets via `avd`, injects them into the subprocess environment, forks the
  command, and masks the child's stdout/stderr at the source (layer 1) before any
  byte reaches the agent. Zeroizes plaintext on exit.
- **`av scrub`** — stdin → stdout filter. Agent hooks pipe command and tool output
  through it for redaction (layer 2); it forwards to `avd`.
- **`av init --agent claude-code|generic`** — generate the hook + skill files for
  an agent.
- **`av lock` / `unlock` / `status` / `audit`** — session and audit-log control.
- **`av ls` / `add` / `rm`** — manage entries (metadata only; `ls` never prints
  values).
- **`av read NAME`** — print a single value. **Refuses if stdout is not a TTY**, so
  an agent reading through a pipe cannot capture plaintext even by calling it
  directly. This is the deliberate guard against the "agent runs `av read` itself"
  failure mode.

## Redaction pipeline (defense-in-depth)

Redaction is enforced at **two independent layers**. Failure of either one alone
does not leak a secret.

**Layer 1 — source masking in `av run`.** `av run` owns its child's stdout/stderr
and masks them locally with exact-match against the values it just received. This
does not depend on the agent wiring any hook, and it natively closes the "agent
runs `av run -- env`" path: that output is masked before it leaves `av run`.

**Layer 2 — hook masking via `av scrub`.** The agent's output hook pipes every
context-ingress channel (Bash output, file reads, MCP tool output, …) through
`av scrub`, which asks `avd` to redact. The adapter contract is therefore *not*
"hook stdout" but "enumerate every channel that carries external text into the
agent's context and intercept each." A channel left unhooked is a hole.

`avd`'s redaction runs three tiers, in order:

1. **Exact match on session values** — always on. Every value issued this session,
   plus its common encodings (base64, hex, URL-encoded, JSON-escaped), is matched
   and masked. Zero false negatives **for values issued in the current session**,
   at microsecond cost, with no ML.
2. **gitleaks engine** — on by default. Catches *derived* secrets the daemon never
   issued (e.g. an OAuth JWT the subprocess fetched using a `CLIENT_SECRET`) and
   values from prior sessions that exact-match no longer knows. Runs as a library
   inside `avd` — hundreds of rules (prefixes like `sk-`, `ghp_`, JWT shapes,
   entropy) with no separate process.
3. **ML classifier** — optional, off by default, **alert-only**. A future plugin
   that flags "this looks like a leaked token of type X" for the audit log. Never a
   gate on masking: the cost of errors is asymmetric (a false positive masks a
   commit hash — minor; a false negative leaks a secret — bad), so masking
   optimises for recall, and a precision-oriented classifier must not *suppress*
   masking.

Masked spans become `{{AV:NAME}}` for named (session) values, so the agent can
still refer to a secret by name without seeing its value. gitleaks findings with
no associated name become `{{AV:REDACTED:<rule>}}`.

**Streaming requirement.** Both layers redact a byte *stream*, so a value split
across two `read()` chunks would evade exact-match. Each layer must keep an
overlap buffer at least as long as the longest known value (and the longest
encoding expansion of it) across chunk boundaries.

## Security model

The goal is to shrink the worst case from "dump the entire vault" to "the current
session's secrets, minus the dangerous tier."

- **Broker, not store.** `avd` holds no master key and caches no full vault.
  Secrets are fetched on demand; only session-issued values sit in memory.
  Compromising the daemon leaks this session, not the whole store.
- **Plaintext locus.** Plaintext exists only in `avd`, in the leaf child's
  environment (which needs it), and transiently in `av run` (which must hold it to
  inject env and source-mask). Under the cooperative threat model the agent does
  not attack `av run`'s memory, so this transit is acceptable; the heavy hardening
  is concentrated in the single long-lived `avd` binary rather than duplicated into
  the CLI.
- **Backend keys out of the daemon's reach.** The file backend's key is wrapped in
  the Secure Enclave with a user-presence ACL, so even a process in full control of
  `avd` cannot decrypt the vault without a live Touch ID. Dangerous-tier secrets
  are never cached and demand fresh presence per access.
- **Memory hygiene.** memguard-style handling in `avd`: `mlock` so secrets never
  hit swap, zeroize on TTL expiry. `av run` zeroizes its transient copy on exit.
- **Reduced attack surface.** Core dumps and `ptrace` disabled on `avd` (hardened
  runtime on macOS). IPC is local-only, `0600`, peer-credential checked. Minimal
  protocol, minimal parser.
- **Behavioural safeguards.** Auto-lock on screen lock / sleep; short session TTL;
  rate limiting on issuance — mass enumeration forces a relock and raises an alert;
  append-only audit log of every issuance (one entry per dangerous touch).

This is also the argument for the daemon over a stateless CLI: a stateless CLI must
persist a session token somewhere readable by any of the user's processes, which
protects it *worse*.

## Error handling

- Daemon unreachable → `av` starts it and retries.
- Vault locked → distinct exit code and a message the agent understands ("ask a
  human to unlock"), so the agent pauses rather than fails blindly.
- Dangerous-tier access denied / timed out → explicit, distinguishable message.
- Secret values never appear in error text or logs.

## Testing

- **Unit** — mock backends behind the `Backend` interface.
- **End-to-end** — real daemon + file backend + an auth stub (`AV_TEST_AUTH=allow`,
  compiled only into test builds).
- **Golden tests** for `scrub` and for layer-1 masking, including every encoding
  transform and chunk-boundary splits.
- **Security regression tests** — socket permissions, peer-credential enforcement,
  the `av read` refusal when stdout is not a TTY, and the dangerous-tier
  no-cache / fresh-presence path.
- CI on macOS (single platform for v1).

## v1 scope

**In:** macOS only; all three backends (1Password via `op`, macOS Keychain,
age-file); the `avd` daemon with unix socket + peer-cred; session TTL + auto-lock;
dangerous-tier with per-secret Touch ID; defense-in-depth redaction (layer 1
source + layer 2 hook with exact-match and gitleaks-as-library); memguard;
Secure Enclave key wrap; rate limiting; append-only audit log; `av run` / `scrub`
/ `read` / `lock` / `unlock` / `status` / `audit` / `ls` / `add` / `rm` / `init`;
one Claude Code adapter.

**Out (deferred):** Windows and Linux (and their auth stacks); the ML classifier;
Vault and AWS Secrets Manager backends; an external/dynamic plugin system; the
1Password Go SDK migration.

## Implementation risks (verify before building)

- **gitleaks as a library.** Its public API targets scanning git repositories, not
  streaming string redaction. We may need to depend on its `detect` package and
  rule set directly, or vendor the rules. Confirm feasibility before committing the
  daemon to embed it.
  - **RESOLVED 2026-06-17 (Task 6 spike) — GO.** gitleaks **v8.30.1** exposes a
    pure in-memory detection API needing no git and no filesystem:
    `detect.NewDetectorDefaultConfig() (*Detector, error)` builds a detector with
    the embedded default rule set in one call (no `ViperConfig.Translate` dance),
    and `(*Detector).DetectString(s string) []report.Finding` scans a bare string.
    Each `report.Finding` carries 1-based `StartColumn`/`EndColumn` (plus the raw
    `Match` and captured `Secret`); for a single-line input `in[StartColumn-1:EndColumn]`
    reconstructs the secret exactly, so the offsets are directly usable to mask
    spans as `{{AV:REDACTED:<RuleID>}}`. Verified by `internal/redact/gitleaks_spike_test.go`
    (github-pat and aws-access-token both detected with correct offsets). For
    streaming, `(*Detector).DetectReader(io.Reader, bufSize)` and
    `StreamDetectReader` also exist. **Layer 2 embeds gitleaks as a library.**
    **Cost:** the dependency tree goes from **1** module (zero external deps) to
    **202** (`go list -m all`), pulling in a WASM regex runtime
    (`wasilibs/go-re2` + `tetratelabs/wazero`), the full `spf13/viper`+`cobra`+`pflag`
    CLI stack, many archive/compression codecs (`mholt/archives`, lz4, xz, brotli,
    sevenzip, rardecode), and charm TUI libs (`lipgloss`, `termenv`). Large but
    acceptable: it is linked only into `avd` (the one hardened daemon binary), not
    into the thin `av` CLI. Revisit if build size or supply-chain surface becomes a
    concern (the vendor-the-regexes fallback remains available).
- **Streaming buffer boundary.** Exact-match over a chunked stream needs an overlap
  buffer (see Redaction pipeline). Get this right in both layers or values split
  across reads will leak.
- **Exact-match is session-scoped.** Its "zero false negatives" holds only for
  values issued in the live session. Anything from a prior session or derived by a
  subprocess rests on gitleaks (heuristic). State this plainly to users.
- **Daemon must run as a GUI-session LaunchAgent** (not a LaunchDaemon) or Touch ID
  cannot be presented.

## Changelog from initial design

Decisions taken during brainstorming on 2026-06-17, with rationale:

1. **v1 narrowed to a full daemon on macOS only.** The original implied tri-platform
   v1; a single platform keeps the (already large) surface tractable while still
   proving every core mechanism.
2. **Redaction is two-layer defense-in-depth, not a single hook.** The original
   enforced redaction only in the agent's output hook — a single point of failure
   dependent on correct adapter wiring and on the hook's ability to *rewrite*
   output. Source masking in `av run` is added as an independent first layer.
3. **`av run` forks the child, not `avd`.** An earlier idea had `avd` spawn the
   child to keep plaintext out of the agent's process tree. That defends only
   against a *malicious* agent (out of scope) while inverting the process
   hierarchy (stdio/pty/signal proxying, orphan handling). Reverted: `av run`
   forks normally and masks at the source.
4. **`avd` must be a per-user GUI-session LaunchAgent.** Required for Touch ID;
   recorded as an invariant.
5. **Dangerous-tier uses per-secret Touch ID** with each prompt naming the secret
   and command, for precise per-issuance audit.
6. **Design principle softened.** "av carries no secret logic" → "av carries no
   backend/storage logic; the only plaintext it touches is the current command's
   profile values, held transiently and zeroized on exit."

## Non-goals (v1)

- Defending against an actively malicious agent or an attacker with root/debugger
  access under the user's UID.
- Windows and Linux support and their auth stacks.
- An external/dynamic plugin system for backends (compiled-in interface only).
- The ML classifier as a masking gate.
- Vault / AWS Secrets Manager backends.

## Open questions / future work

- Migrate the 1Password backend from the `op` CLI to the official Go SDK.
- Extend to Linux and Windows: polkit/`fprintd` + TPM2/keyring, Windows Hello +
  NCrypt/TPM, named pipe with restrictive SDDL and `GetNamedPipeClientProcessId`.
- age-file backend key-rotation flow.
- Build the alert-only ML classifier plugin once exact-match + gitleaks are proven.
- Add Vault and AWS Secrets Manager backends when needed.
