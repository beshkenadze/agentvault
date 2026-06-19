# AgentVault — generic agent integration

AgentVault keeps real secret values out of your agent's context. The agent works
with **logical names** only; the daemon (`avd`) holds the values and injects them
into subprocesses. This is the agent-agnostic integration; wire the two generated
pieces into whatever hook system your agent provides.

## The two pieces

1. **`av-scrub.sh`** — a hook script that pipes stdin through `av scrub` (layer-2
   redaction). Run it on every context-ingress channel.
2. **This doc** — the contract the agent must follow.

## Rules for the agent

- **Run commands with `av run`.** Use `av run --profile <PROFILE> -- <command>` to
  run anything that needs credentials. `av run` injects the secrets into the
  command's environment and masks the command's own output at the source (layer 1)
  before it reaches the agent. Never print/capture a secret value directly.
- **Treat `{{AV:NAME}}` as opaque.** When you see `{{AV:NAME}}` (or
  `{{AV:REDACTED:<rule>}}`) it is a redacted secret — a reference, not a value. You
  may refer to it by name; you MUST NOT try to recover, decode, or reconstruct the
  value, nor ask the user to paste it.
- **Pipe tool output through `av scrub`.** The scrub hook is the independent second
  layer that catches secrets `av run` did not issue (derived tokens, values in files
  the agent reads).
- **`av read` is for a human at a TTY only.** `av read NAME` refuses unless stdout is
  a real terminal, so an agent cannot capture a value through a pipe. Use `av run`
  for credentials.
- **A locked vault is a pause, not a failure (`AV_NO_PROMPT`).** The generated hook
  exports `AV_NO_PROMPT=1`, so a locked vault makes `av run`/`av read`/`av add` exit
  **69** (`EX_UNAVAILABLE`) instead of blocking on a Touch ID. Treat exit 69 as "ask a
  human to run `av unlock`", then retry — do not try to bypass it.

## Scrub-coverage contract

Layer 2's promise holds only if **every channel that carries external text into the
agent's context is intercepted** by the scrub hook. The contract is not "hook
stdout" — it is "enumerate every ingress channel and intercept each." A channel left
unhooked is a hole.

Channels that MUST be hooked (map these to your agent's tool/hook names):

- shell / command output (stdout and stderr)
- file read output (file contents shown to the model)
- tool / plugin output (anything that returns external text to the model)
- web fetch / web search results
- any future channel whose result is shown to the model

Layer 1 (`av run` source-masking) and layer 2 (this scrub hook) are independent:
failure of either one alone does not leak a secret.
