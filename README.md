# sipclient-mcp

`sipclient-mcp` is an MCP (Model Context Protocol) server that drives a real
SIP user agent. An MCP client (an AI coding agent, for example) can create
user agents, dial, answer, reject and hang up calls, transfer answered calls
(blind or attended, via SIP REFER), send and receive DTMF, play and record
media, capture per-call pcaps and ladders, and read voice-quality metrics. It
exists so an agent can exercise real call flows during development.

The daemon is `cmd/sipclient-mcpd`. The optional credential proxy is
`cmd/sipclient-proxy`.

## Install

Two paths are supported:

- **Release binaries.** Download the archive for your platform from the
  project's GitHub Releases page, verify it against `SHA256SUMS`, unzip it and
  run `sipclient-mcpd` (the proxy ships as `sipclient-proxy`). See
  [Release builds](#release-builds) for the platforms and signing status.
- **Clone and build.** Needs Go 1.25 or newer.

  ```bash
  git clone https://github.com/Sanntsu-Corporation/sipclient-mcp.git
  cd sipclient-mcp
  make build        # writes bin/sipclient-mcpd
  make test         # go test -race ./... (plus the importguard package, uncached)
  ```

`go install github.com/sanntsu-corporation/sipclient-mcp/...@version` is not
supported: the module depends on a vendored fork of sipgo through a `replace`
directive (`third_party/sipgo`), and `go install pkg@version` refuses a module
whose `go.mod` contains `replace` directives.

## Run

```bash
bin/sipclient-mcpd --listen 127.0.0.1:8100
```

Flags (from `cmd/sipclient-mcpd/flags.go`):

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `127.0.0.1:8080` | HTTP listen address (the MCP endpoint is served at `/mcp`) |
| `--state` | `$XDG_STATE_HOME/sipclient-mcp/state.yaml`, else `~/.local/state/sipclient-mcp/state.yaml` | The daemon's own state file |
| `--policy` | none | Policy YAML used as a one-shot seed on the first run only; optional |
| `--print-tokens` | off | Print the bearer and admin tokens from `--state`, then exit |
| `--version` | off | Print the version and exit |

On the first run (no state file) the daemon creates its own state file and
mints a bearer token and an admin token. It prints them once, in a banner, and
stores them as `bearer.token` and `admin.token` beside the state file. Recover
them later with `bin/sipclient-mcpd --print-tokens`. Settings are changed at
runtime over MCP with `config_get`, `config_set` and `admin_token_rotate`
(these need the admin token), not by editing a policy file.

## Connect an MCP client

Clients connect over HTTP to `http://<host>:<port>/mcp` with
`Authorization: Bearer <token>`. Registration commands for Codex, Claude Code
and Claude Desktop, and how to install the companion skill, are in:

- [docs/setup-mcp-and-skill.en.md](docs/setup-mcp-and-skill.en.md)
- [docs/setup-mcp-and-skill.zh-TW.md](docs/setup-mcp-and-skill.zh-TW.md)
- [docs/setup-mcp-and-skill.ja.md](docs/setup-mcp-and-skill.ja.md)

The companion skill is [.claude/skills/sipclient-mcp/SKILL.md](.claude/skills/sipclient-mcp/SKILL.md).

## Credential proxy

`sipclient-proxy` is a local stdio MCP server that sits between the client and
the daemon. SIP accounts and passwords stay in a file on your machine and the
model refers to an account by name only. See
[docs/sipclient-proxy.md](docs/sipclient-proxy.md).

## Release builds

Both targets cross-compile with CGO off, zip each binary, and write
`SHA256SUMS` under `dist/` (git-ignored). Pass `VERSION=...` to name the
archives; in a git worktree add `GOFLAGS=-buildvcs=false`.

```bash
make dist         # sipclient-mcpd: linux/amd64, linux/arm64, darwin/arm64, windows/amd64 -> dist/mcpd
make proxy-dist   # sipclient-proxy: darwin/arm64, windows/amd64 -> dist/proxy
```

Archives built by CI are not signed with a developer identity and not notarized
(macOS binaries carry only the Go linker's ad-hoc signature). `make dist` and
`make proxy-dist` do no signing; the optional manual steps (Windows
`osslsigncode`, macOS notes) are described in
[docs/sipclient-proxy.md](docs/sipclient-proxy.md). Verify downloads against
`SHA256SUMS`. On macOS a browser-downloaded binary may need
`xattr -d com.apple.quarantine <binary>`.

## Security model

`sipclient-mcp` is a development tool for a trusted machine or network. Read
this before exposing it anywhere.

- **Localhost or a trusted network only.** The daemon listens on
  `127.0.0.1` by default. Do not expose the port to untrusted networks, and do
  not connect untrusted agents or MCP clients to it.
- **The bearer token travels in clear text over plain HTTP** unless you put a
  TLS-terminating reverse proxy in front of the daemon. Anyone who can read the
  traffic can use the token. The admin token (needed for `config_set` and
  `admin_token_rotate`) is a separate secret and is held to the same standard.
- **It can place arbitrary outbound calls.** Whoever holds the bearer token can
  make the daemon dial any destination the destination allow/deny lists permit,
  which means toll fraud and premium-rate charges are a real risk. Set
  `destinations.allow`/`destinations.deny` and the `limits.*` caps (concurrent
  calls, call duration) to match what you intend to test.
- **It handles SIP credentials.** `ua_create` takes the account and password in
  the tool call, so an agent that supplies them exposes them to the model, its
  transcript and logs. The [credential proxy](#credential-proxy) keeps the
  password out of the model's context; use it for anything but throwaway
  accounts.
- **`tls.insecure_skip_verify: true` turns off certificate verification** for
  outbound SIP over TLS. Anyone on the path can then impersonate the far end
  and read or alter signalling, and SDES keys carried in the SDP. Prefer
  `tls.ca_bundle` for private CAs; use the override only in a lab. Verification
  is on by default.
- **Release archives are not signed with a developer identity and not notarized**
  (macOS binaries carry only the Go linker's ad-hoc signature; see
  [Release builds](#release-builds)).

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Known limitations

- **Minor:** the limit of 1024 retained SIP server transactions is a
  process-wide aggregate bound, not per-peer isolation: one peer can use up the
  retention capacity for every user agent in the process. The limit counts
  retained transactions, which are kept after their handler returns; requests
  still executing handlers are not bounded by it. While it is reached, request retransmissions
  are processed again and a 200 OK to an in-dialog re-INVITE is not
  retransmitted, so a call whose first such 200 OK is lost over UDP ends after
  about 32 seconds.
- **Connection slots can be held by one host.** Each TCP/TLS listener accepts at
  most 50 inbound connections and may close a connection that has been silent
  for 92 seconds or more to make room. A single remote host that keeps opening
  and touching connections can occupy all 50 slots and displace legitimate
  peers that are quiet for that long. There is no per-source limit yet.
- **The macOS and Windows launcher is not fully verified on real hosts.**
  `sipclient-proxy configure` registers the proxy with Claude Code and Codex.
  The registration through an `npm`-installed `.cmd` shim on Windows, and the
  quoting of the printed manual command in `cmd.exe` and PowerShell, have not
  been exercised on real machines, and Finder double-click launch of the macOS
  binary has not been tested. The `.exe` registration path and the macOS
  ad-hoc-signed binary were checked on real hosts.

Changes between releases, including removed configuration keys, are in
[CHANGELOG.md](CHANGELOG.md). The architecture is described in
[docs/design.md](docs/design.md). To contribute, see
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT, see [LICENSE](LICENSE). The vendored `third_party/sipgo` keeps its own license file.
