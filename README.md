# AgentVault

An agent-agnostic secret broker for macOS. AI coding agents run real commands with
real credentials, but never see those credentials in plaintext: the value is injected
into a child process and masked at the source, so anything the agent reads back —
stdout, logs, errors — shows `{{AV:NAME}}` instead of the secret. macOS-only (v1).

## How it works

A resident daemon, `avd`, brokers secrets and redacts output; a thin `av` CLI talks to
it over a local socket. `av run` resolves a profile's secrets, launches your command
with them in its environment, and masks the values in the child's output at the source —
the agent driving `av run` only ever sees `{{AV:NAME}}`. Brokering is gated by a
Touch-ID-unlocked session; the vault's age key is wrapped by the Secure Enclave and
unwrapped only into that session, never held at rest.

## Install

```sh
brew install beshkenadze/tap/agentvault
# newer Homebrew gates third-party taps:
brew tap beshkenadze/tap && brew trust beshkenadze/tap
```

Requires macOS and the Xcode Command Line Tools (the Touch ID / Secure Enclave paths
are built with cgo).

## Quick start

```sh
brew services start agentvault          # run avd as a per-user LaunchAgent
av setup                                # provision the local Enclave-wrapped age vault
av unlock                               # Touch ID — unwraps the key into the session (15m)
av add GITHUB_TOKEN                     # hidden prompt; the value never touches argv
```

`av add` reads the value from a hidden prompt (or piped stdin) — never from the command
line — so the secret stays out of your shell history and the process table.

Describe a profile in `agentvault.yaml` in your project:

```yaml
profiles:
  smoke:
    GITHUB_TOKEN:
      ref: av://file/GITHUB_TOKEN
      tier: normal
```

Then run a command that needs it:

```sh
av run --profile smoke -- sh -c 'echo $GITHUB_TOKEN'
# -> {{AV:GITHUB_TOKEN}}
```

The command really receives the token in its environment; the value is masked in the
output at the source, so the agent reading this line sees only `{{AV:GITHUB_TOKEN}}`.

## Backends

A reference is `av://<backend>/<locator>`.

| Backend    | Ref                              | Access     | Populate with                                  |
|------------|----------------------------------|------------|------------------------------------------------|
| age file   | `av://file/NAME`                 | read/write | `av setup` then `av add NAME` (`av rm` to drop) |
| Keychain   | `av://keychain/<service>/<account>` | read-only | `security add-generic-password -s <service> -a <account> -w` |
| 1Password  | `av://1p/<Vault>/<Item>/<field>` | read-only  | manage the item in 1Password (`op`); resolves via `op read` |

The age file backend is the only writable one — `av setup` provisions it and `av add` /
`av rm` manage it. Keychain and 1Password are read-only: AgentVault resolves them but
you populate and rotate them with their own tools.

## Manifest (`agentvault.yaml`)

A manifest maps logical environment names to a backend reference and an access tier,
grouped into profiles. It holds no secret values.

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

- **normal** — served from the unlocked session for its TTL (one Touch ID covers the
  window).
- **dangerous** — a fresh Touch ID per access; the value is never cached in the session.

## CLI

```
av ping                                 reach the daemon (prints pong)
av run [--profile P] -- cmd args...     run cmd with secrets injected, output masked
av read [--profile P] NAME              print one secret — to a TTY only (refuses a pipe)
av add [--backend file] NAME            store a value (hidden prompt or stdin; never argv)
av rm  [--backend file] NAME            delete a value from the writable vault
av setup [--rotate] [--plaintext]       provision the local age vault
av init --agent claude-code|generic [--dir D] [--force]   generate adapter files
av unlock                               Touch ID — open the session
av lock                                 re-lock and clear issued values
av status                               print lock state and remaining time
av scrub                                filter stdin -> stdout through the redactor
```

`av read` refuses when stdout is not a terminal (exit **80**) so a piped secret cannot
leak — agents must use `av run`. Daemon errors map to stable, secret-free exit codes:
**69** (vault locked), **77** (access denied, dangerous tier), **2** (bad request,
e.g. unknown profile). `--profile` defaults to `smoke`.

`av setup` defaults to a Secure-Enclave-wrapped identity; `--plaintext` writes the
identity unwrapped (an escape hatch for hosts without a Secure Enclave), `--rotate`
provisions a fresh identity and vault.

## Security model

- **Broker, not store.** The agent never holds the secret: `av run` injects it into a
  child and `av read` prints only to a real terminal (refusing a pipe).
- **Source masking.** `av run` masks resolved values in the child's output at the
  source — the value is replaced before the agent can read it back.
- **Defense-in-depth redaction.** `av scrub` runs a second pass: exact-match of the
  session's issued values plus a gitleaks detector for *derived* secrets the daemon
  never issued.
- **Enclave-wrapped key, session-scoped.** The vault's age identity is wrapped by the
  Secure Enclave and unwrapped only on `av unlock` (the Touch ID *is* the presence
  proof) into an `mlock`'d session, zeroized on `lock`, TTL expiry, or auto-lock
  (screen-lock / sleep). The daemon does not unwrap at startup, so there is no
  login-time prompt and a daemon compromise after lock cannot decrypt the vault.
- **Local trust boundary.** `av` ↔ `avd` is a `0600` unix-domain socket with a
  peer-credential check (same-UID only).
- **Honest scope.** This is a *cooperative-agent* threat model: it stops an agent (and
  its logs) from capturing plaintext it has no business seeing. It is macOS-only (v1)
  and does **not** defend against an actively malicious same-user local attacker —
  malicious-agent defense is an explicit non-goal for v1.

## Agent integration

`av init --agent claude-code|generic` generates the adapter files (a hook that pipes
agent output through `av scrub`, plus a skill/doc) into your project so the agent's
output is redacted automatically.

## Verification & development

The Touch ID, Secure Enclave, and real-backend paths cannot be exercised by automated
tests — verify them manually:

- `scripts/smoke-e2e.sh` — isolated end-to-end of the age-file backend (stub presence,
  ephemeral daemon and vault; no Touch ID).
- `scripts/smoke-backends.sh` — real Keychain (and optional 1Password) resolution.
- `scripts/manual-touchid-smoke.sh` — the human-in-the-loop Touch ID / auto-lock check.
- `docs/launchagent.md` — running `avd` as a per-user LaunchAgent (when not using
  `brew services`).

Build and test from source with `make build` and `make test`.

> The `AV_TEST_AUTH` and `AV_TEST_ENCLAVE` environment variables select stub presence /
> stub enclave for CI and the smoke scripts. They are **test-only** and bypass the
> hardware protections — never set them in real use.

## Status / non-goals

macOS-only in v1. Linux/Windows support and additional backends (HashiCorp Vault, AWS
Secrets Manager) are future work. Keychain and 1Password stay read-only — manage those
secrets with their own tools.
