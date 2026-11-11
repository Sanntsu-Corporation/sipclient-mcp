# Adding sipclient-mcp to Codex, Claude Code, and Claude Desktop

This document walks you, the developer, through installing the
`sipclient-mcp` MCP server and its companion skill so your coding agent
(Codex, Claude Code, or the Claude Desktop app) can use them.

## Background and purpose

`sipclient-mcp` is a development daemon, reachable over the internal
network, that exposes a real SIP UAC/UAS stack over MCP (Model Context
Protocol): create user agents,
dial/answer/hangup calls, transfer answered calls (blind or attended),
send/receive DTMF, play/record media, capture per-call pcaps, and read
voice-quality metrics — all as tool calls (`ua_create`, `call_dial`,
`call_transfer`, `dtmf_send`, `media_*`, `capture_*`, `quality_get`, ...) an
AI coding agent can drive directly. It exists so an agent working on this
repository (or any SIP-adjacent codebase) can exercise real call flows
end-to-end during development, instead of a human placing test calls by hand.

Two separate pieces make this usable:

- **The MCP server** is what provides the tools themselves — it is the thing
  you *connect* your agent to.
- **The `sipclient-mcp` skill** (currently BETA) is a companion document that
  teaches the agent *how* to use those tools correctly: the session/UA/call
  concepts, the typical call/transfer flow, and known gotchas. The server
  gives the agent capability; the skill gives it working knowledge. Skipping
  the skill still lets the tools work, but the agent is more likely to
  misuse them (e.g. confusing a session with a UA).

The daemon supports **multiple independent bearer tokens** — one can be
minted per machine or agent and revoked on its own without affecting anyone
else's. By default it listens on loopback only; an operator can start it on another
address with `--listen` (see the README Security model before doing so). The examples
below use port 8100 and assume it is reachable at
**`<DAEMON_HOST>:8100`** (the address of the machine running it; ask its operator), or over VPN. You will need
your own token from whoever operates the daemon; do not reuse someone
else's, and never use the separate *admin* token for ordinary tool access
(it exists only for the admin-scoped
`config_get`/`config_set`/`admin_token_rotate` tools).

## Prerequisites

- A bearer token, given to you by the daemon operator.
- Network reachability to the daemon at `<DAEMON_HOST>:8100` — directly
  or over VPN. (If you happen to be on the daemon's own host,
  `127.0.0.1:8100` also works.)

## Adding the MCP server

### Codex CLI

Codex reads a bearer token from an environment variable rather than storing
it in `config.toml`, so set that first:

```bash
export SIPCLIENT_MCP_TOKEN="<your-token>"
codex mcp add sipclient-mcp \
  --url http://<DAEMON_HOST>:8100/mcp \
  --bearer-token-env-var SIPCLIENT_MCP_TOKEN
```

Verify:

```bash
codex mcp list
codex mcp get sipclient-mcp
```

### Claude Code

```bash
claude mcp add --transport http sipclient-mcp \
  http://<DAEMON_HOST>:8100/mcp \
  --header "Authorization: Bearer <your-token>" \
  -s user
```

`-s user` registers it once for every project on this machine (matching how
it's already registered on the daemon's own host). Use `-s project` instead
if you only want it available inside one specific repo checkout.

Verify:

```bash
claude mcp list
```

`sipclient-mcp` should show as `Connected`.

Note: unlike Codex, this command takes the token directly on the command
line rather than by environment-variable indirection — avoid leaving it in
shared shell history if that matters on your machine.

### Claude Desktop app

Don't use Settings → Connectors ("custom connectors") for this. That path
always proxies through Anthropic's cloud infrastructure, on every Claude
surface including Desktop — so a server added that way must be reachable
from the public internet, which this daemon deliberately is not (private
network/VPN only).

Instead, use Desktop's **local (stdio) MCP config**, bridged to the daemon
with [`mcp-remote`](https://github.com/punkpeye/mcp-remote): a small process
Desktop spawns *on your own machine*, which then makes the HTTP request to
`<DAEMON_HOST>:8100` itself — the same way `curl` running locally would, so
nothing needs to be exposed to the internet. Requires Node.js (for `npx`) on
your desktop machine.

Edit `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "sipclient-mcp": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://<DAEMON_HOST>:8100/mcp",
        "--header",
        "Authorization:${AUTH_TOKEN}"
      ],
      "env": {
        "AUTH_TOKEN": "Bearer <your-token>"
      }
    }
  }
}
```

Fully quit and reopen Claude Desktop for the change to load.

## Adding the skill

The skill file itself lives in this repo at
`.claude/skills/sipclient-mcp/SKILL.md`.

### Codex CLI

Codex loads skills from `$CODEX_HOME/skills/<name>/SKILL.md` (default
`~/.codex/skills`):

```bash
# from the repository root
mkdir -p ~/.codex/skills/sipclient-mcp
cp .claude/skills/sipclient-mcp/SKILL.md \
   ~/.codex/skills/sipclient-mcp/SKILL.md
```

If you're on a different machine, pull the same file from this repo's `main`
branch instead of copying a local path.

### Claude Code

This repo already tracks the skill at `.claude/skills/sipclient-mcp/SKILL.md`
(project-scoped), so it loads automatically whenever Claude Code is working
inside a checkout of this repository — nothing further to do.

To make it available in *every* project on this machine, not just this repo,
copy it to the user-level skills directory instead:

```bash
# from the repository root
mkdir -p ~/.claude/skills/sipclient-mcp
cp .claude/skills/sipclient-mcp/SKILL.md \
   ~/.claude/skills/sipclient-mcp/SKILL.md
```

### Claude Desktop app

Desktop has no separate skills mechanism to install this into — it works
from the tool descriptions the MCP server itself returns. That's enough for
basic use; for the session/UA/call concepts and known gotchas the skill
covers, read `.claude/skills/sipclient-mcp/SKILL.md` in this repo directly.

## Optional: credential proxy (sipclient-proxy)

If you do not want SIP passwords to appear in tool calls, run `sipclient-proxy`
on your machine: it keeps your SIP accounts in a local file, and the agent
creates UAs by account name (`ua_create {"account":"name"}`) without ever seeing
a password. See [docs/sipclient-proxy.md](sipclient-proxy.md) for install and
configuration.

## Verifying it works

Ask your agent to run a read-only tool call, e.g. "list my sipclient-mcp
calls" — it should call `call_list` and get back something like
`{"ok":true,"calls":[]}`. A 401 means the token is wrong or missing; a
connection error means the daemon isn't reachable from where you are —
report either to the operator rather than guessing at a fix.
