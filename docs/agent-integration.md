# Agent integration

This guide wires AgentVault into an AI coding agent so the agent can use credentials it
never sees, and so any secret that slips into the agent's context is redacted
automatically. It covers Claude Code (first-class) and any other agent (generic).

## The two layers

AgentVault protects the agent's context with **two independent layers**. Either one
failing alone does not leak a secret.

1. **Layer 1 — source masking (`av run`).** When the agent runs a command with
   `av run --profile P -- …`, the daemon injects the secrets into the child and masks
   their values in the child's stdout/stderr *at the source*, before any byte reaches the
   agent. The agent sees `{{AV:NAME}}`.
2. **Layer 2 — scrub net (`av scrub`).** A hook pipes every other channel of external
   text (file reads, web fetches, MCP tool output, …) through `av scrub`, which asks the
   daemon to redact session values (exact match plus common encodings) and
   gitleaks-detected secrets the daemon never issued.

Layer 1 covers what the agent runs through AgentVault; layer 2 catches everything else.

## Generate the adapter

```sh
av init --agent claude-code      # in your project root
# wrote .claude/hooks/av-scrub.sh
# wrote .claude/skills/agentvault/SKILL.md
# wrote .claude/agentvault.hooks.json
```

Flags:

- `--agent claude-code|generic` (required)
- `--dir D` — target directory (default: current directory)
- `--force` — overwrite existing files (default: refuse, so a customized hook is never
  clobbered)

For a non-Claude agent:

```sh
av init --agent generic
# wrote av-scrub.sh
# wrote AGENTVAULT.md
```

## Claude Code

`av init --agent claude-code` writes three files:

| File | Role |
|------|------|
| `.claude/hooks/av-scrub.sh` | the layer-2 hook (executable; pipes stdin through `av scrub`) |
| `.claude/skills/agentvault/SKILL.md` | the skill that teaches the agent the rules and exact `av` syntax |
| `.claude/agentvault.hooks.json` | a **merge template** for the `PostToolUse` wiring |

### Wire the hook (PostToolUse)

The generated `.claude/agentvault.hooks.json` is a template to **merge** into your Claude
Code settings — the exact hook schema varies by version, so it is not applied
automatically. The `hooks` block it ships:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash|Read|Glob|Grep|WebFetch|WebSearch|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/av-scrub.sh"
          }
        ]
      }
    ]
  }
}
```

Merge it into `.claude/settings.json` and adjust the matcher / event names to your
installed version (check `claude --version` and your version's hooks docs).

### The hook script

```sh
#!/bin/sh
# ... (generated header omitted)
export AV_NO_PROMPT=1
exec av scrub
```

Two functional lines:

- `export AV_NO_PROMPT=1` marks this as the **agent path**: a locked vault returns
  **exit 69** ("pause for a human to unlock") instead of blocking the agent on an
  on-demand Touch ID prompt it cannot satisfy. The export means every `av` call the agent
  makes (`av run`/`av read`/`av add`) inherits the opt-out.
- `exec av scrub` pipes the hook's stdin through the daemon's layer-2 redactor and writes
  the masked result to stdout.

## Generic agents

`av init --agent generic` writes a portable `av-scrub.sh` (same two functional lines as
above) and `AGENTVAULT.md` (the contract the agent must follow). Wire `av-scrub.sh` into
whatever hook/filter mechanism your agent provides, on **every** ingress channel (see the
scrub-coverage contract below).

## The scrub-coverage contract

Layer 2's promise holds **only if every channel that carries external text into the
agent's context is intercepted**. The contract is not "hook stdout" — it is "enumerate
every ingress channel and intercept each." A channel left unhooked is a hole.

Channels that MUST be hooked (map these to your agent's tool/hook names):

- shell / command output (stdout **and** stderr)
- file-read output (file contents shown to the model)
- tool / plugin output (anything returning external text to the model — every MCP server)
- web fetch / web search results
- any future channel whose result is shown to the model

The default Claude Code matcher `Bash|Read|Glob|Grep|WebFetch|WebSearch|mcp__.*` covers
these for a typical setup. If you add a tool that surfaces external text, add it to the
matcher.

## What the agent must know

The generated skill/doc teaches the agent these rules. In short:

1. **Run commands with `av run --profile <PROFILE> -- <command>`.** Find the profile and
   logical names in `agentvault.yaml`; never invent them. There is no safe default
   profile — always pass `--profile`.
2. **For a tool that reads a config file** (`.npmrc`, `.env`, …): put an environment
   *reference* in the file (`${NPM_TOKEN}`) and run the tool under `av run`, so the value
   is resolved at runtime and never written to disk.
3. **Treat `{{AV:NAME}}` as opaque.** It is a reference, not a value. The agent may refer
   to it by name but must never try to recover, decode, or reconstruct the value, nor ask
   the user to paste it.
4. **`av read` is for a human at a TTY only.** It refuses to print to a pipe or file
   (exit 80), so an agent cannot capture a value through it. Agents use `av run`.
5. **A locked vault is a pause, not a failure.** With `AV_NO_PROMPT=1`, a locked vault
   makes `av` exit **69**. The agent should treat exit 69 as "ask a human to run
   `av unlock`", then retry — never try to bypass it.

## Verify the integration

After wiring, confirm both layers:

```sh
# Layer 1: the value is masked at the source
av run --profile smoke -- sh -c 'echo $GITHUB_TOKEN'
# -> {{AV:GITHUB_TOKEN}}

# Layer 2: a secret echoed through an unhooked-looking channel is still scrubbed
echo "token is $(av read GITHUB_TOKEN 2>/dev/null)" | av scrub   # at a TTY only
```

> `av read` only prints to a real terminal, so the second check is a human spot-check —
> an agent would get exit 80 from `av read` and nothing to leak.

See also: [security model](security-model.md) for the guarantees behind these layers, and
[troubleshooting](troubleshooting.md) if a hook isn't firing or the agent hits exit 69.
