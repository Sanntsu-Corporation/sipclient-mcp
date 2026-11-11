# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project is
pre-1.0: minor versions may change behavior and configuration.

## [0.1.0]

First public release.

### Added

- **`sipclient-mcpd`**, a daemon that serves MCP over streamable HTTP at `/mcp`
  and drives a real SIP user agent, with bearer-token authentication and a
  separate admin token for configuration changes.
- **User agents** (`ua_create`, `ua_status`, `ua_destroy`): register against a
  registrar or run in direct IP-to-IP mode, over UDP, TCP or TLS, with RTP or
  SDES-SRTP media, re-registration, digest authentication, and CRLF or OPTIONS
  NAT keepalive.
- **Calls** (`call_dial`, `call_answer`, `call_reject`, `call_hangup`,
  `call_list`, `call_status`): outbound and inbound, 3xx redirect following
  (`limits.max_redirects`), RFC 4028 session timers, and a declarative
  `media_plan` that runs play, record, DTMF and wait steps without further round
  trips.
- **Call transfer** (`call_transfer`): blind and attended transfer with SIP REFER,
  reporting the outcome from the transferee's NOTIFY messages.
- **Events** (`call_wait`, `call_events`): an ordered, bounded per-call event log
  and a blocking wait for the next matching event.
- **DTMF** (`dtmf_send`, `dtmf_received`): RFC 4733 telephone-event, in-band
  tones and SIP INFO, in both directions.
- **Media** (`media_play`, `media_record_start`, `media_record_stop`): G.711
  mu-law and A-law, prompts by registered name only, recordings as WAV artifacts.
- **Diagnostics** (`call_ladder`, `capture_start`, `capture_stop`,
  `quality_get`): SIP ladder diagrams as text, Mermaid or JSON; per-call pcap
  capture; passive RTP statistics with an E-model MOS estimate. Secrets in
  signalling (digest credentials and SDES keys) are redacted from ladders and
  captures.
- **Runtime configuration** (`config_get`, `config_set`, `admin_token_rotate`)
  over MCP with the admin token. On first run the daemon creates its own state
  file and mints its tokens; `--print-tokens` recovers them.
- **Policy**: destination allow/deny lists, limits (concurrent calls, call
  duration, sessions, user agents, waiters), a prompt allow-list, TLS trust
  settings, capture and artifact retention caps.
- **`sipclient-proxy`**, an optional local stdio MCP server that keeps SIP
  account passwords in a local file so the model never sees them. See
  [docs/sipclient-proxy.md](docs/sipclient-proxy.md).
- A companion agent skill and setup guides in English, Traditional Chinese and
  Japanese.
- Cross-compiled release archives with SHA-256 sums (`make dist`,
  `make proxy-dist`). They are not signed with a developer identity and not notarized (macOS
  binaries carry only the Go linker's ad-hoc signature).

### Security

- Outbound TLS verifies the peer certificate by default, using the system roots
  or `tls.ca_bundle`. Skipping verification requires the explicit
  `tls.insecure_skip_verify: true`, which logs a warning.
- Capped the SIP server transactions kept for retransmission handling at 1024
  per process (above the cap a transaction is released when its handler returns,
  as before), so a flood of distinct requests can no longer pin unbounded memory.
- Each TCP/TLS listener limits inbound connections to 50 and closes idle
  connections; the HTTP listener times out slow pre-authentication connections.
- SDP from a peer is validated (IPv4 literal `c=` addresses only; multicast,
  broadcast and out-of-range ports refused), and RTP from an unexpected source
  is dropped.

### Notes for upgrading from earlier builds

These apply only if you ran an earlier build with a policy file of your own.

- **Removed configuration keys.** The policy keys `webhooks:` and `quality:`
  (`webhooks.allow`, `webhooks.deny`, `webhooks.allow_http`,
  `webhooks.allow_private_addresses`, `webhooks.connect_timeout_ms`,
  `quality.pesq_python`, `quality.pesq_script`) were never wired to any
  behavior and have been removed, and so has the `profiles:` registry (accounts
  are now given inline to `ua_create`). The policy file is read strictly, so a
  file that still contains one of these keys is rejected at startup, even if
  the block is empty. If the error message mentions `webhooks` or `quality`,
  delete the whole `webhooks:` or `quality:` block from your policy file; the
  daemon then starts normally and behavior is unchanged.
- **Stricter validation.** `ua_create` rejects values outside sane limits
  (`expires_s` above 86400, `session_expires_s` above 7200, an unknown
  `keepalive` mode), and a `media_plan` step carrying a field its operation does
  not use is rejected with `invalid_argument` instead of being ignored.
- **Media-plan steps are bounded** by `limits.max_step_duration_s` (default 180).

[0.1.0]: https://github.com/Sanntsu-Corporation/sipclient-mcp/releases/tag/v0.1.0
