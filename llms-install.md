# Installing sipclient-mcp (guide for AI agents)

`llms-install.md` is the file name some MCP marketplaces use for install
instructions an AI agent reads and executes on a user's behalf.

You are an AI coding agent (Claude Code, Codex, Cline, or similar). Follow this
file to install, for the user on this machine:

- `sipclient-mcpd`, the daemon: an HTTP MCP server at `http://127.0.0.1:<port>/mcp`
  that drives a real SIP user agent.
- optionally `sipclient-proxy`, a local stdio MCP proxy that keeps SIP passwords
  out of the model's context (recommended).
- optionally the companion skill that teaches an agent how to use the tools.

Read this whole file before you run anything. Steps marked **STOP AND ASK**
need the user's answer first.

## Ground rules

1. **STOP AND ASK** before any install location other than the default given
   below, before registering with the user's MCP client, and before starting a
   long-running process.
2. Never ask for, accept or echo a SIP password in chat. Never put one in a
   command line or tool call. The user edits the accounts file themselves; see
   [docs/credentials-and-agents.md](docs/credentials-and-agents.md).
3. Never print or paste the bearer or admin token into chat. Read the token from
   its file inside the shell command that needs it.
4. Download only from the project's releases page,
   https://github.com/Sanntsu-Corporation/sipclient-mcp/releases. Verify
   `SHA256SUMS` before you run any binary.
5. Do not use `sudo` unless the user approves it.
6. Keep the daemon on loopback (`127.0.0.1`). Bind another address only if the
   user explicitly asks, after they have read the README
   [Security model](README.md#security-model): the token travels in clear text
   and the daemon can place arbitrary outbound calls.
7. `go install ...@version` is not supported (the module uses a `replace`
   directive). Use a release archive or build from a clone.
8. Never stop or modify a process or file you did not create in this run. Never
   stop a process by name (`pkill`, `killall`).

## Step 0: detect the platform and check prerequisites

macOS or Linux:

```bash
uname -sm
```

Windows PowerShell:

```powershell
$env:PROCESSOR_ARCHITECTURE
```

Pick the archives. `<VERSION>` is a release tag such as `v0.1.0`.

| Platform | Daemon archive | Proxy archive |
|---|---|---|
| macOS, Apple silicon (`Darwin arm64`) | `sipclient-mcpd_<VERSION>_darwin_arm64.zip` | `sipclient-proxy_<VERSION>_darwin_arm64.zip` |
| Linux x86-64 (`Linux x86_64`) | `sipclient-mcpd_<VERSION>_linux_amd64.zip` | none: build from source |
| Linux arm64 (`Linux aarch64`) | `sipclient-mcpd_<VERSION>_linux_arm64.zip` | none: build from source |
| Windows x86-64 (`AMD64`) | `sipclient-mcpd_<VERSION>_windows_amd64.zip` | `sipclient-proxy_<VERSION>_windows_amd64.zip` |

Any other platform (for example macOS on Intel): use Path B.

Prerequisites: `curl` or `gh`, and `unzip` (Windows: `Expand-Archive` is built in).
For Path B also `git`, `make` and Go 1.25 or newer (`go version`). If something is
missing, tell the user what and stop.

Find the latest version (either command):

```bash
gh release view --repo https://github.com/Sanntsu-Corporation/sipclient-mcp --json tagName -q .tagName
curl -fsSIL -o /dev/null -w '%{url_effective}\n' https://github.com/Sanntsu-Corporation/sipclient-mcp/releases/latest
```

The second prints a URL ending in `/tag/<VERSION>`. If `gh release view` prints
`gh auth login` or `release not found`, or any download returns 404, the
repository or release may still be private: **STOP and tell the user**. Do not
authenticate, log in, copy tokens or look for another download source. If the
user hands you a local zip and `SHA256SUMS`, start at the checksum step.

## Step 1: get the binaries

Default install directory: `~/.local/bin` (Windows: `%USERPROFILE%\bin`).
**STOP AND ASK** if the user wants a different one, or if that directory is not
on `PATH` (then use the full path in later commands, or ask).

### Path A: release archive (preferred)

macOS or Linux (set `OS_ARCH` to `darwin_arm64`, `linux_amd64` or `linux_arm64`):

```bash
VERSION=<VERSION>; OS_ARCH=<os_arch>
BASE=https://github.com/Sanntsu-Corporation/sipclient-mcp/releases/download/$VERSION
WORK=$(mktemp -d) && cd "$WORK"
curl -fsSLO "$BASE/sipclient-mcpd_${VERSION}_${OS_ARCH}.zip"
curl -fsSLO "$BASE/SHA256SUMS"
# verify only the archive you downloaded; use `sha256sum -c -` on Linux
grep -F "  sipclient-mcpd_${VERSION}_${OS_ARCH}.zip" SHA256SUMS | shasum -a 256 -c -
```

Expected: `sipclient-mcpd_<VERSION>_<os_arch>.zip: OK`. On `FAILED` or no output,
delete the download and stop (see Troubleshooting).

```bash
unzip -q "sipclient-mcpd_${VERSION}_${OS_ARCH}.zip"
mkdir -p ~/.local/bin
cp "sipclient-mcpd_${VERSION}_${OS_ARCH}/sipclient-mcpd" ~/.local/bin/
chmod +x ~/.local/bin/sipclient-mcpd
```

macOS only, if the archive came through a browser or the binary is refused:
`xattr -d com.apple.quarantine ~/.local/bin/sipclient-mcpd`. Release binaries are
not notarized and carry only the Go linker's ad-hoc signature.

Windows PowerShell:

```powershell
$V = "<VERSION>"; $A = "sipclient-mcpd_${V}_windows_amd64.zip"
$Base = "https://github.com/Sanntsu-Corporation/sipclient-mcp/releases/download/$V"
$Work = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "sipclient-mcp-$V") -Force; Set-Location $Work
Invoke-WebRequest "$Base/$A" -OutFile $A; Invoke-WebRequest "$Base/SHA256SUMS" -OutFile SHA256SUMS
$want = ((Select-String -Path SHA256SUMS -Pattern ([regex]::Escape($A))).Line -split '\s+')[0]
if ((Get-FileHash $A -Algorithm SHA256).Hash -ieq $want) { "OK" } else { "MISMATCH" }
```

Expected: `OK`. On `MISMATCH` stop. Then:

```powershell
Expand-Archive $A -DestinationPath .
New-Item -ItemType Directory -Force "$env:USERPROFILE\bin" | Out-Null
Copy-Item "sipclient-mcpd_${V}_windows_amd64\sipclient-mcpd.exe" "$env:USERPROFILE\bin\"
```

The Windows commands in this file follow the code and docs but have not been run
on a real Windows host. If one fails, report it instead of improvising.

For the optional proxy (Step 5), repeat the same download, verify and copy with
`sipclient-proxy_<VERSION>_<os_arch>.zip` and the binary `sipclient-proxy`
(`.exe` on Windows). Reuse the same `SHA256SUMS`.

### Path B: build from source

```bash
git clone https://github.com/Sanntsu-Corporation/sipclient-mcp.git && cd sipclient-mcp
make build                                            # writes bin/sipclient-mcpd
go build -o bin/sipclient-proxy ./cmd/sipclient-proxy   # optional proxy
mkdir -p ~/.local/bin && cp bin/sipclient-mcpd bin/sipclient-proxy ~/.local/bin/
```

### Confirm the binary runs

```bash
~/.local/bin/sipclient-mcpd --version
```

Expected: one line `sipclient-mcpd <VERSION> (commit <hash>, built <timestamp>)`.
A source build without tags prints a `git describe` string or `dev`.

## Step 2: start the daemon

**STOP AND ASK**: tell the user you will start `sipclient-mcpd` on
`127.0.0.1:8100` as a background process, and which port if 8100 is taken
(`lsof -i :$PORT` on macOS/Linux; `Get-NetTCPConnection -LocalPort $PORT` on
Windows; any output means it is in use). Use the chosen port as `PORT` below
(Windows: `$Port`).

State and tokens live in `~/.local/state/sipclient-mcp/` (or
`$XDG_STATE_HOME/sipclient-mcp/`; Windows: `%USERPROFILE%\.local\state\sipclient-mcp\`):
`state.yaml`, `bearer.token` (ordinary tool access) and `admin.token` (only for
`config_get`, `config_set`, `admin_token_rotate`; never use it for ordinary access).
On the first run the daemon creates them and prints both tokens once on
**stdout**. Send stdout away so the tokens never reach your context; logs go to
stderr:

```bash
PORT=8100
mkdir -p -m 700 ~/.local/state/sipclient-mcp
nohup ~/.local/bin/sipclient-mcpd --listen 127.0.0.1:$PORT \
  >/dev/null 2>~/.local/state/sipclient-mcp/daemon.log & echo $! > ~/.local/state/sipclient-mcp/daemon.pid
```

`daemon.pid` lets you stop exactly the process you started (see Uninstall).

For a quick try the user can instead run it in a foreground terminal, which
shows the tokens in that terminal only. On Windows, have the user run
`& "$env:USERPROFILE\bin\sipclient-mcpd.exe" --listen 127.0.0.1:$Port` in their own
PowerShell window, then read `bearer.token` as below. Do not create systemd or launchd units unless the user asks.

Set the token file path for the next steps (never `cat` the file to your output):

```bash
TOKFILE=~/.local/state/sipclient-mcp/bearer.token
```

Health check, which needs no token. Expected: `ok`.

```bash
curl -s http://127.0.0.1:$PORT/healthz
```

Auth check. Expected: `HTTP/1.1 401 Unauthorized` (body `unauthorized`):

```bash
curl -s -i -X POST http://127.0.0.1:$PORT/mcp -d '{}' | head -1
```

Authenticated check. Expected: `HTTP/1.1 200 OK`, and a body containing
`"serverInfo":{"name":"sipclient-mcp"`:

```bash
curl -s -i -X POST http://127.0.0.1:$PORT/mcp \
  -H "Authorization: Bearer $(cat "$TOKFILE")" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"install-check","version":"0"}}}'
```

If the daemon exits at once, read the last lines of `daemon.log`. It does not
contain the tokens (see Troubleshooting for "address already in use").

## Step 3: register with the user's MCP client

**STOP AND ASK** which client(s) to register with, and whether user scope
(every project) is acceptable. Registration stores the token in the client's own
configuration, which is expected. Register only the clients the user names.

Claude Code (user scope; the token is read from the file inside the command):

```bash
claude mcp add --transport http sipclient-mcp http://127.0.0.1:$PORT/mcp \
  --header "Authorization: Bearer $(cat "$TOKFILE")" -s user
claude mcp list
```

Expected: `sipclient-mcp` listed as `Connected`.

Codex CLI (the token is read from an environment variable, not stored in
`config.toml`):

```bash
export SIPCLIENT_MCP_TOKEN="$(cat "$TOKFILE")"
codex mcp add sipclient-mcp --url http://127.0.0.1:$PORT/mcp --bearer-token-env-var SIPCLIENT_MCP_TOKEN
codex mcp list && codex mcp get sipclient-mcp
```

Codex needs `SIPCLIENT_MCP_TOKEN` in the environment it starts from. Tell the
user; do not edit their shell profile without asking.

Claude Desktop and other JSON-configured clients: do not write the token
yourself. Show the user this snippet for `claude_desktop_config.json`
(macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`;
Windows: `%APPDATA%\Claude\claude_desktop_config.json`), tell them to put their
token in `AUTH_TOKEN` (from `sipclient-mcpd --print-tokens`, first line) and to
restart Desktop. It needs Node.js (`npx`). Do not use Settings > Connectors:
that path goes through Anthropic's cloud and cannot reach a loopback daemon.

```json
{
  "mcpServers": {
    "sipclient-mcp": {
      "command": "npx",
      "args": ["mcp-remote", "http://127.0.0.1:<port>/mcp", "--header", "Authorization:${AUTH_TOKEN}"],
      "env": { "AUTH_TOKEN": "Bearer <your-token>" }
    }
  }
}
```

Cline and other clients: use that client's "streamable HTTP MCP server" setting
with URL `http://127.0.0.1:<port>/mcp` and header `Authorization: Bearer <token>`,
and have the user enter the token.

## Step 4: install the companion skill (optional)

**STOP AND ASK.** The skill is `.claude/skills/sipclient-mcp/SKILL.md`. From a
clone (Path B), copy it; otherwise download that one file from the repository at
`<VERSION>`, read it, then copy it.

Run from the repository root of the clone (or use the absolute path to the file):

```bash
mkdir -p ~/.claude/skills/sipclient-mcp     # Codex: ~/.codex/skills/sipclient-mcp
cp .claude/skills/sipclient-mcp/SKILL.md ~/.claude/skills/sipclient-mcp/SKILL.md
```

Claude Desktop has no skills mechanism; skip it. Inside a checkout of this
repository Claude Code already loads the skill.

## Step 5: credential proxy (optional, recommended)

Skip this if the user only wants throwaway accounts. Otherwise **STOP AND ASK**,
then run. If `sipclient-proxy` is not on `PATH`, use its full path (for example
`~/.local/bin/sipclient-proxy configure ...`); that is the normal case with the
default install.

```bash
sipclient-proxy configure --upstream http://127.0.0.1:$PORT/mcp --token-file "$TOKFILE"
```

This writes the credentials file (mode 0600; never modifies an existing one),
registers `sipclient-proxy` at user scope with Claude Code and Codex when their
CLIs are on `PATH`, and prints a Claude Desktop snippet. Expected lines:
`claude: registered sipclient-proxy (user scope)` and `codex: registered
sipclient-proxy` (or `skipped <cli>: '<cli>' not found on PATH`); the `codex:`
line appears only when Codex is installed. It keeps a backup of each client
config it touches (`*.sipclient-proxy.bak-*`) and prints its path. Tell the user
the path, and that the backup holds a full copy of that client's config,
including the registered token, so they can delete it once happy. After
`configure --remove` only the newest backup remains.

Credentials file: `~/.config/sipclient-proxy/sipclient-proxy.json`
(Windows: `%APPDATA%\sipclient-proxy\sipclient-proxy.json`). **Tell the user to
add their SIP accounts to it themselves, in an editor.** The format is in
[docs/sipclient-proxy.md](docs/sipclient-proxy.md#config-file). Do not write,
read back or ask for passwords. With the proxy registered, the agent should call
`account_list` and `ua_create {"account":"name"}` on `sipclient-proxy`, not the
daemon's own `ua_create`. Ask whether the user wants the direct `sipclient-mcp`
registration removed so raw `auth_pass` cannot be used.

## Step 6: verify

Restart the client or open a new session (most clients load MCP tools at
start), then check and report each item:

1. The client lists `sipclient-mcp` (and `sipclient-proxy` if installed) as
   connected: `claude mcp list` or `codex mcp list`.
2. The tool list includes `ua_create`, `call_dial`, `call_hangup`,
   `call_transfer`, `dtmf_send`, `media_play`, `capture_start` and `quality_get`
   (Claude Code names them `mcp__sipclient-mcp__<tool>`).
3. Smoke test, no SIP account or external service needed: call `call_list`.
   Expected: `{"ok":true,"calls":[]}`.

If you cannot see the new tools in your current session, say so; do not claim
success for items you could not run. Optional check straight against the daemon
(responses are SSE-framed, so keep only the `data:` line; the token is read from
the file and never printed):

```bash
mcp() { curl -s -D "${HDR:-/dev/null}" -X POST http://127.0.0.1:$PORT/mcp \
  -H "Authorization: Bearer $(cat "$TOKFILE")" -H "Mcp-Session-Id: $SID" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d "$1" | grep '^data:'; }
HDR=$(mktemp); SID= mcp '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"install-check","version":"0"}}}' >/dev/null
SID=$(tr -d '\r' <"$HDR" | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}'); rm -f "$HDR"; unset HDR
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"call_list","arguments":{}}}'
```

Expected: the `tools/list` line names `ua_create`, `call_dial`, `call_hangup`,
`call_transfer`, `dtmf_send`, `media_play`, `capture_start` and `quality_get`;
the `call_list` line contains `{\"ok\":true,\"calls\":[]}` (JSON-escaped inside
the result text).

## Final report to the user

```text
Installed: sipclient-mcpd <VERSION> at <path>; sipclient-proxy <VERSION> at <path or "not installed">
Daemon: 127.0.0.1:<port>, state in <state dir>, log <path>, started with <command>
Registered with: <clients and scope>
Skill: <installed at path / skipped>
Checks: healthz <ok>, unauthenticated /mcp <401>, initialize <200>, tools <n found>, call_list <result>
Uninstall: stop only the daemon you started, never by name. macOS/Linux:
    kill "$(cat ~/.local/state/sipclient-mcp/daemon.pid)"
  (or confirm the listener with `lsof -ti tcp:$PORT -sTCP:LISTEN` and that it is sipclient-mcpd first).
  Windows: Stop-Process -Id <pid> for the sipclient-mcpd process listening on the port
  (Get-NetTCPConnection -LocalPort $Port -State Listen, then check its name);
  delete the binaries; claude mcp remove sipclient-mcp -s user; codex mcp remove sipclient-mcp
  ("No MCP server named ... found" just means it was never added; harmless);
  sipclient-proxy configure --remove (keeps the credentials file);
  delete the installed skill directory (~/.claude/skills/sipclient-mcp, and
  ~/.codex/skills/sipclient-mcp if you put it there);
  delete the *.sipclient-proxy.bak-* backups configure printed (they hold the client config, token included);
  ask before deleting the credentials file ~/.config/sipclient-proxy/sipclient-proxy.json
  (Windows: %APPDATA%\sipclient-proxy\sipclient-proxy.json);
  the state directory holds the tokens: delete it only if the user agrees.
You still need to: add SIP accounts to the credentials file yourself (never in chat);
  set destinations.allow and limits.* before real testing (README Security model).
No firewall change is needed: the daemon listens on loopback only.
```

## Troubleshooting

| Symptom | Cause and action |
|---|---|
| `address already in use` in `daemon.log` | The port is taken. Pick another with `--listen 127.0.0.1:<port>` and use it in every URL; ask before stopping whatever holds it |
| 401 on an authenticated request | Wrong or stale token. Re-read `bearer.token` (not `admin.token`, which is for admin tools only). Do not paste the token into chat |
| Client shows `sipclient-mcp` failed or not connected | Daemon not running (`curl http://127.0.0.1:$PORT/healthz`), wrong port in the registration, or the token changed after `admin_token_rotate`: re-register |
| Checksum `FAILED` or `MISMATCH` | Delete the archive and `SHA256SUMS`, download again once. If it still fails, stop and tell the user; do not run the binary |
| Nothing printed, or a "no properly formatted" checksum error | The asset name does not match a line in `SHA256SUMS`; recheck `<VERSION>` and `<os_arch>` |
| macOS: "cannot be opened" or killed on launch | Quarantine flag: `xattr -d com.apple.quarantine <binary>`. Binaries are not notarized; if it is still refused, report it |
| 404 on download | The repository or release may be private, or the version is wrong. Check `<VERSION>` on the releases page, then stop and tell the user |
| `go install` fails | Unsupported by design; use Path A or B |
| Agent refuses to pass a SIP password | Expected. Use the proxy: [docs/credentials-and-agents.md](docs/credentials-and-agents.md) |
