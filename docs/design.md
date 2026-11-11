# Architecture overview

This document describes how `sipclient-mcp` is put together: the components, the
tool surface, the policy model, transport and media handling, the session model
and how it is tested. It is an orientation for contributors, not a protocol
reference; the code and its tests are authoritative.

## Purpose and shape

`sipclient-mcp` lets an AI agent (or any MCP client) exercise real SIP call flows
during development: register, place and receive calls, send DTMF, play and record
audio, transfer calls, capture signalling and read call quality. Every one of
those is a tool call against a long-lived daemon that owns the sockets, timers and
audio, so the client never touches SIP or RTP directly.

Design goals, in priority order:

1. **Behave like a real endpoint.** The far end should see a standards-following
   user agent, because the point is to test that far end. The SIP stack is real
   (a vendored fork of [sipgo](https://github.com/emiago/sipgo)), not a simulator.
2. **Be safe to hand to an autonomous agent.** The main risk is not an attacker but
   a capable agent doing exactly what it was asked, at machine speed, to a real
   telephone network. Limits and destination filters live server-side, out of the
   agent's reach.
3. **Return immediately, report through events.** Tool calls do not block on the
   network, except one explicit wait tool.
4. **Be deterministic enough to test.** Time, clocks and the network can all be
   replaced in tests.

There are two executables:

| Binary | Role |
|---|---|
| `cmd/sipclient-mcpd` | The daemon. Serves MCP over streamable HTTP at `/mcp`, plus `/healthz`, `/readyz`, `/metrics`, artifact downloads and an admin plane. |
| `cmd/sipclient-proxy` | An optional local stdio MCP server that injects SIP credentials from a local file and forwards everything else to the daemon. See [sipclient-proxy.md](sipclient-proxy.md). |

## Components and layering

```
  MCP client (agent)                               operator / scripts
        |  MCP over HTTP, bearer token                    |  GET /artifacts, /metrics
        v                                                 v
  +-------------------------------------------------------------------+
  | internal/transport/mcp   tools, bearer auth, admin plane, artifacts|
  +----------------------------+--------------------------------------+
                               | handles and plain structs only
              +----------------+-----------------+
              v                                  v
  +-------------------------+      +----------------------------------+
  | internal/policy         |<-----| internal/session                 |
  |  limits, allow/deny,    |      |  session / UA / call registries  |
  |  TLS trust, tokens      |      |  handles, event logs, waiters    |
  |  decides only: no I/O   |      |  media-plan executor (plan/)     |
  +-------------------------+      +--------+-----------+-------------+
                                            |           |
                 +--------------------------+           +------------------+
                 v                          v                              v
   +-----------------------+   +-----------------------+   +--------------------+
   | internal/sipua        |   | internal/media        |   | internal/trace     |
   |  register, dialogs,   |   |  RTP/SRTP, jitter     |   |  SIP/RTP taps,     |
   |  transfer, timers,    |   |  buffer, play/record, |   |  ladder renderer,  |
   |  udp / tcp / tls      |   |  DTMF, SDP, quality   |   |  pcap writer       |
   +-----------+-----------+   +-----------+-----------+   +---------+----------+
               |                           |                         |
               v                           v                         v
   +-----------------------------------------------------------------------+
   | internal/artifact   recordings, pcaps, ladders: store, URIs, janitor  |
   +-----------------------------------------------------------------------+
               |
               v
   +-----------------------------------------------------------------------+
   | internal/sipengine and third_party/sipgo   vendored, owned, modifiable |
   +-----------------------------------------------------------------------+
```

### The layering rule

The MCP layer never touches SIP, RTP or codec types. It speaks only to
`internal/session`. `internal/session` is the only package that drives
`internal/sipua`, `internal/media` and `internal/trace`, and those three are peers
that never call each other: they report upward through `session` as typed events
and callbacks.

Two things follow from this:

- The tool surface is a stable contract an agent has learned to use, while the SIP
  and media engine changes often. Pinning the boundary at `session` keeps engine
  changes from leaking into tool signatures.
- Every layer can be tested against fakes of the layer below it.

`session` depends on four small interfaces that it declares itself and that the
concrete packages satisfy: `UserAgent` (`sipua`), `MediaSession` (`media`), `Tap`
(`trace`) and `ArtifactStore` (`artifact`). Hand-written fakes for each live under
`internal/testutil/fakes`, so the session manager can be built and driven from
fakes alone.

The boundary is enforced by tests, not convention: `internal/importguard` runs
`go list -deps` and fails the build if, for example, `internal/transport/mcp`
transitively imports `sipua`, `media`, `trace` or `sipgo`, or if the daemon
reaches anything under `internal/testutil`.

### Package map

| Package | Responsibility |
|---|---|
| `cmd/sipclient-mcpd` | Flags, first-run bootstrap (state file and tokens), wiring, serve, graceful shutdown. |
| `internal/transport/mcp` | Tool and resource registration, bearer-token middleware, health/metrics endpoints, artifact HTTP, admin endpoints, MCP session identity. |
| `internal/policy` | Policy model, strict YAML load, destination matching, secrets, token handling, the persisted state file and its store. |
| `internal/session` | Registries, handles, event ordering, waiters, caps and admission, retention janitor, shutdown, transfer orchestration. |
| `internal/session/plan` | The media-plan step grammar and executor. |
| `internal/sipua` | A user agent: registration and refresh, outbound and inbound dialogs, re-INVITE/UPDATE, REFER, session timers, keepalive, digest auth, redirects, transport listeners. |
| `internal/media` | SDP offer/answer, RTP and SRTP (SDES), fixed jitter buffer, packet-loss concealment, TX pacing, DTMF, recording and playback. |
| `internal/media/codec` | G.711 mu-law and A-law, DTMF generation and detection, WAV reading and writing. |
| `internal/media/quality` | Passive RTP statistics and the E-model MOS estimate. |
| `internal/trace` | Ladder rendering (text, Mermaid, JSON) and the pcap writer. |
| `internal/artifact` | Per-call artifact directories, resource URIs, TTL and byte high-watermark janitor. |
| `internal/apierr` | The error taxonomy shared by every tool. |
| `internal/proxy` | The credential proxy's relay, injection and redaction logic. |
| `internal/sipengine` | A vendored SIP test engine snapshot (see its `VENDOR.md`). |
| `third_party/sipgo` | A fork of sipgo wired in with a `replace` directive (see its `VENDOR.md`). |
| `internal/testutil` | Test-only scaffolding: loopback harness, scripted SIP peer, in-process proxy, fault injector, fake clock and DNS, test CA. |

## MCP tool surface

All tools take and return JSON, and every result carries `ok`. Failures use a
small closed set of error codes (for example `invalid_argument`, `not_found`,
`gone`, `denied`, `precondition_failed`, `resource_limit`, `not_supported`,
`tls_failure`). A SIP failure of the call itself (a 486, a 404) is a *result* the
agent can inspect, not a tool error.

| Area | Tools |
|---|---|
| User agents | `ua_create`, `ua_status`, `ua_destroy` |
| Calls | `call_dial`, `call_answer`, `call_reject`, `call_hangup`, `call_transfer`, `call_status`, `call_list` |
| Events | `call_wait`, `call_events` |
| DTMF | `dtmf_send`, `dtmf_received` |
| Media | `media_play`, `media_record_start`, `media_record_stop` |
| Diagnostics | `call_ladder`, `capture_start`, `capture_stop`, `quality_get` |
| Session | `session_keepalive` |
| Admin (admin token) | `config_get`, `config_set`, `admin_token_rotate` |

Notable design choices:

- **Handles, not objects.** `ua_create` and `call_dial` return opaque handles
  (`ua_...`, `call_...`). Everything else names a handle.
- **Account fields are inline.** `ua_create` takes the AOR, registrar and
  credentials in the call itself; there is no server-side account registry. The
  credential proxy exists so a model need not see those fields.
- **`call_dial` returns at once** in state `dialing`. Progress arrives as events.
- **`call_wait` is the only blocking tool.** It waits for a named event (`ringing`,
  `answered`, `media_start`, `dtmf`, `transfer`, `completed`, `terminated`, `any`) and
  evaluates its predicate against the existing log first, so an event that happened
  before the call is not missed. A timeout is a normal result, not an error.
- **Events** are an ordered, bounded per-call log (`call_events` drains it from a
  sequence number). Types include `incoming_call`, `ringing`, `answered`,
  `media_start`, `media_stop`, `dtmf`, `record_start`, `record_stop`, `plan_step`,
  `session_refresh`, `bye`, `policy_timeout`, `transfer` and `error`.
- **Call states.** Outbound: `dialing`, `ringing`, `answered`, `terminated` or
  `failed`. Inbound calls are created in `ringing` and end by `call_answer`,
  `call_reject` or the ring timeout. `call_status` reports a closed set of
  `termination_reason` values.
- **Long calls need no tool.** A call stays up until hangup or the duration cap;
  session-timer refresh and NAT keepalive run automatically.
- **Media plans.** `call_dial` and `call_answer` accept an optional ordered list of
  steps (`play`, `record`, `dtmf`, `wait`, `wait_dtmf`, `hangup`) that the server
  runs without further round trips. Plans are validated before the INVITE goes out.
  A step that fails at run time aborts the plan but leaves the call up, so the
  agent keeps control.
- **Transfer.** `call_transfer` sends a REFER in the call's dialog, either blind
  (to a URI) or attended (replacing a second answered call, via `Replaces`). It
  blocks only for the REFER's own final response; the transferee's NOTIFY messages
  arrive as `transfer` events. A transfer never sends BYE itself.
- **Artifacts** (recordings, pcaps, ladders) are returned as
  `mcp://sipclient/artifacts/{call}/{name}` URIs and are also served over
  `GET /artifacts/{call}/{name}` with the bearer token.

## Policy and configuration

The server-side policy is a YAML document decoded strictly (unknown keys reject the
whole file). It holds everything an agent must not be able to change:

- `auth`: paths to the bearer and admin token files.
- `destinations`: ordered allow and deny regular expressions, matched against the
  normalised destination at dial time; the matched rule is named in a denial.
- `limits`: concurrent calls (per session and in total, checked in that order),
  maximum call duration, UAs and sessions, `call_wait` bounds, redirect count,
  media-plan step length, registry retention, shutdown grace period.
- `media`: local address, RTP port range, jitter-buffer depth.
- `tls`: CA bundle, client certificate and key, and `insecure_skip_verify`.
- `capture`, `artifact`: byte caps, artifact directory, retention.
- `prompts`: the named audio files `media_play` may use. A tool takes a prompt
  *name*, never a path.

Behavior worth knowing:

- **Caps are independent and first-come-first-served.** A dial that finds the
  server-wide cap full is denied immediately, never queued, and the denial names
  which key fired, so the agent can tell "I am using too much" from "the server is
  full".
- **Duration cap.** An agent-supplied `max_duration_s` can only lower the policy
  cap. A breach ends the call with `policy_timeout`.
- **Reload.** New operations always use the current policy. A call already in
  progress continues under the policy it started with, except that a lowered
  duration cap applies to live calls immediately. An invalid new file is rejected
  as a whole and the old policy stays.
- **State file and bootstrap.** On first run the daemon writes its own state file
  (a complete policy plus token paths), mints a bearer and an admin token, and
  prints them once. `--policy` seeds that state on the first run only. Afterwards
  the state file is the source of truth, changed at runtime through `config_set`
  (a curated set of keys, admin token required) rather than by editing YAML.
- **Admin plane.** Configuration changes and UA reclamation use a separate admin
  token that is never the MCP bearer token. Reclaiming a stranded UA transfers
  no call content and gives no agent a new capability.

## Transport

`internal/sipua` supports UDP, TCP and TLS for signalling.

- **Listeners.** Each UA owns its listeners; a UDP UA also listens on TCP at the
  same port so large requests and TCP-only peers work. TCP and TLS listeners cap
  inbound connections at 50 and close idle connections.
- **Outbound connections are separate from inbound ones.** A request is sent on a
  connection opened to its own destination; a connection accepted from a peer is
  pooled only under the peer's own address. This stops a peer from steering our
  later requests back into ourselves.
- **Size.** A request too large for UDP is sent over TCP. Responses to stream
  requests leave on the arrival connection.
- **Resolution.** A host without a port resolves SRV first, then A/AAAA.
- **NAT.** `received` and `rport` are honored (RFC 3581), a REGISTER after the first
  advertises the learned address, and keepalive is CRLF ping/pong or OPTIONS.
- **TLS.** Outbound TLS verifies the peer certificate against the system roots or
  `tls.ca_bundle`; `insecure_skip_verify` is an explicit lab override that logs a
  warning and the peer's certificate fingerprint. A client certificate can be
  supplied for mutual TLS. Trust material is policy-only: no tool can set it.
- **Authentication.** Digest authentication for REGISTER and INVITE keeps a real
  nonce count per nonce, handles 401 and 407, and caches the registrar's
  challenge so a refresh is one REGISTER on the wire. Credentials are withheld
  from hosts outside the account's allowed set unless the UA opts in with
  `auth_any_host`.
- **Redirects.** 3xx responses are followed up to `limits.max_redirects`, and every
  target passes the destination policy; a `sips:` target is never downgraded.
- **Session timers** follow RFC 4028 in both roles, refreshing with UPDATE when the
  peer allows it and re-INVITE otherwise, with a watchdog that ends a call whose
  refreshes stop.
- **Hardening.** Retransmission handling keeps at most 1024 server transactions per
  process; the stream parser bounds an unterminated header line; a hostile
  `Content-Length` fails the message before anything is allocated; slow
  pre-authentication HTTP connections time out.

## Media

- **Codecs.** G.711 mu-law (PCMU) and A-law (PCMA), plus RFC 4733 telephone-event.
  Audio is 8 kHz, mono, 16-bit.
- **SDP.** Offer/answer follows RFC 3264. A peer's `c=` must be an IPv4 literal
  (no DNS on the media path), multicast and broadcast are refused, and a refused
  offer draws 488. A re-INVITE or UPDATE offer changes the live call (codec, hold
  and resume, media address). RTP from a source other than the signalled address is
  dropped.
- **SRTP** uses SDES keys in the SDP, so it requires TLS signalling unless the UA
  sets `allow_cleartext_sdes`. A per-call `srtp` can only tighten the UA's policy.
  Key material is scrubbed from ladders and pcaps.
- **Receive path.** A fixed-delay jitter buffer (default 60 ms, configurable from 20
  to 200 ms) indexed by RTP sequence number reorders packets, drops duplicates and
  counts late arrivals separately from lost ones. It is deliberately fixed, not
  adaptive, so the playout path is not a second uncontrolled variable in
  quality measurements. A missing frame is concealed by replaying the previous
  frame, attenuated, fading to silence after four consecutive losses.
- **Transmit path.** Frames are scheduled against absolute time derived from a
  cumulative frame count, not an accumulating ticker, so a 30-minute call does not
  drift. A host that falls well behind resynchronises instead of bursting.
- **Local media address.** On a multi-homed host the media address comes from, in
  order: an explicit IP in `local_addr`, `media.local_ip`, the route to the
  remote, then a unicast fallback. A wildcard address is never used as the
  media address.
- **DTMF** is sent as RFC 4733 events, in-band tones or SIP INFO, and detected from
  either RTP events or audio with a Goertzel detector. Requesting RFC 4733 when
  `telephone-event` was not negotiated is an error, not a silent downgrade.
- **Quality.** `quality_get` reports packets sent, received and lost, reorder and
  duplicate counts, burst gaps, jitter, and an R-factor and MOS estimate from the
  ITU-T G.107 E-model. The MOS is an estimate derived from impairments, not a
  listening-quality measurement.

## Session model

An MCP connection maps to a **logical session**. Handles are scoped to the session
that created them: using another session's handle returns `not_found`, so an agent
cannot learn that the handle exists. A session is resumed by presenting both the
server-issued session id and the bearer token it was issued to; neither alone is
enough.

- A session with live UAs has a fixed lifetime (five minutes by default) renewed by
  `ua_create` and `session_keepalive`. An empty session lingers only for the resume
  window.
- Inbound INVITEs are routed to the UA, not to the connection that created it, so a
  UA keeps answering at the SIP level even if its client has gone away. An
  orphaned UA is reclaimed through the admin plane or expires with its session.
- Finished calls and UAs stay queryable for a retention period and are then
  evicted oldest-first; asking for an evicted handle returns `gone`. Artifact
  retention is separate, so a recording can outlive the registry entry that made it.
- Everything is bounded: concurrent waiters, event log length, retained handles,
  ladders, sessions, artifact bytes. A runaway client exhausts a configured limit
  and gets a named denial, not an out-of-memory daemon.

### Concurrency

- Registries use read-write locks; each UA and call has its own mutex. Locks are
  taken in the order registry, then UA, then call, and none is held across a
  network write or an artifact write.
- A call's event log is appended and its waiters are signalled inside one critical
  section, so a waiter cannot miss an event between its check and its wait.
  Waiters are cancellable, always woken on a terminal state or eviction, and always
  removed from both the call and the session's waiter count.
- State transitions and the checks that guard them happen atomically under the call
  mutex, so two racing tool calls produce exactly one success and one
  `precondition_failed`.
- Shutdown stops accepting new work, ends live dialogs with BYE where it can and
  drains within the configured grace period.

## Security design

Most of the model is in the README's *Security model* section. Architecturally:

- Bearer auth guards every HTTP route except `GET /healthz`, which returns a fixed
  `ok` and discloses nothing.
- Policy is read at startup, on reload and through admin-only `config_set`. No
  non-admin tool can read or change it, which is what makes the other controls
  meaningful.
- Credentials are wrapped in a secret type on entry, never logged, and redacted from
  ladders, pcaps and errors. The proxy adds a second layer: the model sees an
  account name, never a password.
- Prompts are registered names, artifact names are validated against traversal,
  absolute paths and dotfiles, and header injection through user-supplied header
  values is rejected.

## Testing approach

- **Loopback harness.** The centerpiece is an in-process harness
  (`internal/testutil/loopback`) that runs the real daemon and talks to it through a
  real MCP client, against scripted SIP peers on loopback sockets. Tests cover
  registration, dialling, inbound calls, DTMF, transfer, TLS, SRTP and the
  concurrency invariants.
- **Scripted peers and fault injection.** `internal/testutil/peer` is a controllable
  far end; `netfault` injects loss, reordering, duplication and delay on UDP;
  `sipproxy` is a small in-process proxy with a media relay; a fake clock and fake
  DNS make timer and resolution behavior deterministic.
- **Fakes at every seam.** Each of the four `session` interfaces has a hand-written
  fake, so `session` and `transport/mcp` are tested without the real engine.
- **Race detection.** `make test` runs with `-race`, and the concurrency tests
  repeat contested operations many times from goroutines released together.
- **Protocol pins and vectors.** Tests that pin specific RFC behaviors, ITU codec
  and DTMF vectors under `testdata`, and pcap and ladder golden output.
- **Import boundaries** are asserted by `internal/importguard`, as described above.
- **Interop gate (opt-in).** `e2e/` holds an Asterisk-based rig and a loop-call gate
  that drive the daemon against a real PBX over UDP, TCP and TLS with RTP and SRTP.
  It needs a host you control and is skipped unless enabled; see
  [CONTRIBUTING.md](../CONTRIBUTING.md) and `e2e/asterisk/README.md`.

## Known gaps in the design

- The pcap is a reconstruction: signalling is written as the bytes observed at the
  socket (byte-exact over UDP, TCP and TLS), not a kernel-level capture.
- Voice quality is passive and model-based. There is no listening-quality (PESQ)
  measurement and no RTCP-XR.
- Only G.711 is supported.
- IPv6 literals in a destination URI are not supported for outbound dialling.
- Session state is in memory; a daemon restart ends live calls. The state file
  preserves configuration, not calls.
- See the README's *Known limitations* for current, specific issues.
