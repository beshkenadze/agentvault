---
name: agentvault
description: Use secrets safely via AgentVault. Run commands that need credentials with `av run` so the values never enter your context; treat {{AV:NAME}} as an opaque reference.
---

# AgentVault — using secrets you never see

AgentVault keeps real secret values out of your context. You work with **logical
names** only; the daemon (`avd`) holds the values and injects them into subprocesses
on your behalf. Follow these rules.

## Quick reference (exact syntax — don't guess)

- **Find the PROFILE and logical NAMEs in `agentvault.yaml`** (read it). Never invent a
  profile/name; `av run` has no safe default profile — always pass `--profile`.
- **Run a command that needs secrets:**
  `av run --profile <PROFILE> -- <command> [args...]`
- **A tool that reads a CONFIG FILE** (`.npmrc`, `.env`, etc.): do NOT write the value to
  disk. Put an environment *reference* in the file and run the tool under `av run`, so the
  value is resolved at runtime and never persisted. Example:
  `printf '//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n' > .npmrc`
  then `av run --profile <PROFILE> -- npm whoami`.
- `av read [--profile <PROFILE>] <NAME>` — **human-only** (refuses a pipe/file). Don't use
  it to fetch a value; use `av run`. If a human needs the value, they run it themselves.
- `av status` (lock state) · `av version` (av/avd) · `av unlock` is a human action.

## 1. Run commands with `av run` — never read the secret yourself

To run a command that needs credentials, wrap it:

```
av run --profile <PROFILE> -- <command> [args...]
```

`av run` resolves the profile's secrets, injects them into the command's
environment, runs it, and **masks the command's own stdout/stderr at the source**
before any byte reaches you (layer 1). You get the command's output with secrets
already replaced by `{{AV:NAME}}`.

Do NOT try to print or capture a secret value (e.g. `env`, `cat .env`, `echo
$TOKEN`). Even if you do, `av run` masks it. Resolve credentials only through
`av run`.

## 2. Treat `{{AV:NAME}}` as opaque — never try to recover the value

When you see `{{AV:NAME}}` (or `{{AV:REDACTED:<rule>}}`) in any output, that is a
**redacted secret**. It is a reference, not a value:

- You MAY refer to the secret by its name (`{{AV:GITHUB_TOKEN}}`) in your reasoning.
- You MUST NOT attempt to un-redact, reconstruct, decode, brute-force, or otherwise
  recover the underlying value. The value is intentionally withheld from you.
- Do not ask the user to paste the value so you can see it.

## 3. Pipe tool output through `av scrub` (layer 2)

The generated hook (`.claude/hooks/av-scrub.sh`) pipes context-ingress text through
`av scrub`, which asks the daemon to redact session values and gitleaks-detected
secrets. This is the independent second layer that catches secrets `av run` did not
issue (e.g. a token a subprocess derived, or a value pasted into a file you read).

## 4. `av read` is for a human at a TTY only

`av read NAME` prints a single value, but **refuses unless stdout is a real
terminal**. It will not print to a pipe or a file. Do not call `av read` to capture
a value — it is the deliberate guard against an agent reading a secret directly. If
you need a credential for a command, use `av run`.

## 5. A locked vault is a pause, not a failure (`AV_NO_PROMPT`)

The generated hook exports `AV_NO_PROMPT=1`, so when the vault is locked your `av
run` / `av read` / `av add` exits **69** (`EX_UNAVAILABLE`) instead of blocking on a
Touch ID prompt. Treat exit 69 as "ask a human to run `av unlock`", then retry —
never try to bypass it.

---

## Scrub-coverage contract (for whoever wires the hooks)

Layer 2's promise holds only if **every channel that carries external text into the
agent's context is intercepted** by the scrub hook. The contract is not "hook
stdout" — it is "enumerate every ingress channel and intercept each." A channel left
unhooked is a hole.

Channels that MUST be hooked:

- **Bash** / shell tool output (stdout and stderr)
- **file read** tool output (file contents shown to the model)
- **MCP** tool output (results from every MCP server's tools)
- web fetch / web search results
- any future tool whose result is shown to the model

See `.claude/agentvault.hooks.json` for the PostToolUse wiring template (merge it
into your Claude Code settings and adjust to your version). Layer 1 (`av run`
source-masking) and layer 2 (this scrub hook) are independent: failure of either one
alone does not leak a secret.
