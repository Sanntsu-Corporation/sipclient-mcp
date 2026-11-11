# Giving an agent SIP account credentials

Creating a user agent with `ua_create` normally means passing the account's
`auth_pass` in the tool call. AI models and agent harnesses can be cautious
about that: the password then sits in the model's context, in the transcript
and in any log of the session. Some will refuse the call, ask you to
approve it every time, or block it outright.

This guide gives you two ways to get a working user agent. Use the first
whenever you can.

| | Option 1: `sipclient-proxy` (recommended) | Option 2: allow the call in Claude Code |
|---|---|---|
| Does the model see the password? | No. It sends `ua_create {"account":"name"}` only | Yes, it is in the tool call and the transcript |
| Needs the model's cooperation to handle a secret? | No | Yes |
| Works with any MCP client | Yes | Claude Code only |
| Extra component | One small local binary | None |

## Option 1: use `sipclient-proxy`

The proxy keeps your SIP accounts, with their passwords, in a file on your own
machine. The model refers to an account by name, and the proxy fills in the
credential fields locally before forwarding the call to the daemon. This is the
purpose it was built for.

1. Download `sipclient-proxy` from the release page and verify it against
   `SHA256SUMS`, as described in [sipclient-proxy.md](sipclient-proxy.md#install).
2. Register it with your client. The token is read from a file so it never
   appears in the process list or shell history:

   ```bash
   sipclient-proxy configure --upstream https://HOST:8100/mcp --token-file ./daemon-token
   ```

   `configure` registers `sipclient-proxy` with Claude Code and Codex. For
   Claude Desktop it prints a snippet for you to paste.
3. Add your accounts to the credentials file it created (mode 0600; default
   path `~/.config/sipclient-proxy/sipclient-proxy.json` on macOS; the Windows path
   is in [sipclient-proxy.md](sipclient-proxy.md#config-file)):

   ```json
   {
     "accounts": {
       "sbc-lab": { "mode": "register", "sipserver": "10.1.2.3", "port": 5060,
                    "transport": "udp", "username": "1001", "password": "<password>" }
     }
   }
   ```

   Edit the file yourself, in an editor. Do not ask the agent to write the
   password into it.
4. Restart your client, then ask the agent to create a user agent from the
   account `sbc-lab`. It calls `account_list` to see the names, then
   `ua_create {"account":"sbc-lab"}`. Tell it to always pass `account` and
   never `auth_pass`: the proxy's `ua_create` still accepts raw credentials when
   `account` is left out.

Use the proxy's tools, not the daemon's, for this: the daemon's own `ua_create`
still takes a raw password. If both servers are registered, tell the agent to
use `sipclient-proxy`. The full reference (config keys, trust boundary, the
limits of the redaction) is in [sipclient-proxy.md](sipclient-proxy.md).

## Option 2: allow the call in Claude Code

Use this only if you cannot run the proxy, for example when you are testing
against a throwaway lab account. Claude Code has two separate controls, and a
password in a tool call may need both.

**Ordinary permission rule** (stops the per-call prompt). In
`~/.claude/settings.json`, or a project's `.claude/settings.json`, allow the
tool. Use the server name you registered it under; `sipclient-mcp` is the
default:

```json
{
  "permissions": {
    "allow": ["mcp__sipclient-mcp__ua_create"]
  }
}
```

An allow rule for an MCP tool takes no parentheses or argument pattern; a rule
with parentheses matches nothing. `mcp__sipclient-mcp` allows every tool of the
server, which is broader than you need.

**Auto-mode classifier** (applies when you run Claude Code in auto mode). The
classifier decides on its own whether an action is safe, and it may block a
call that sends a live credential to an endpoint. If it does, you can describe
an exception in plain language under `autoMode.allow`. Put it in your **user** settings
(`~/.claude/settings.json`), because Claude Code reads `autoMode` from user,
managed and `--settings` scope and ignores it in a project's
`.claude/settings.json`:

```json
{
  "autoMode": {
    "allow": [
      "$defaults",
      "Calling the sipclient-mcp ua_create tool with a SIP account password (auth_pass) is allowed: it is a lab account on our own PBX"
    ]
  }
}
```

`"$defaults"` keeps the built-in entries; leaving it out replaces them. Entries
are sentences the classifier reads, not patterns, so word the exception
narrowly, name the tool and say why it is safe. Run `claude auto-mode config`
to see what is in effect, or use the **Auto mode** tab in `/permissions`.

### What Option 2 does not do

- **It does not change what the model is willing to do.** These rules control
  what Claude Code allows or prompts for, not the model's own judgement.
  Claude Code's documentation says nothing about changing a model's refusals. If
  the agent declines to put a password into a tool call, do not argue it round:
  use Option 1.
- **The password is exposed.** It is in the model's context, in the transcript
  and in any session logs, and it travels to the daemon in the tool call. Use a
  dedicated, low-privilege account that you can rotate, never a production
  trunk or a personal credential.
- **Do not widen the rule.** Allowing the whole server, or describing the
  exception broadly in `autoMode.allow`, lets an injected instruction in a web
  page or document place calls on your SIP account. The README
  [Security model](../README.md#security-model) explains the toll-fraud risk.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Agent says it cannot handle the password | Expected. Use Option 1 |
| `ua_create` is refused locally with a conflict message | You sent `account` together with a credential field. Send `account` alone |
| Error about an unknown account | The name is not in the credentials file. The error lists the valid names, and `account_list` also shows any invalid entries |
| Still prompted after adding the allow rule | The server name in the rule does not match the registered name, or a deny or ask rule takes precedence |
| `autoMode` entries have no effect | They are in a project settings file. Move them to `~/.claude/settings.json` |
