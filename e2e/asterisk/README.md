# e2e/asterisk

Test infrastructure for the sipclient-mcp spec's §14.5 interop
gate. This is **not** the SIP client under test — it's the far-end
Asterisk PBX that `sipclient-mcp` places test calls against, so that
both ends do not share our implementation's misunderstandings of SIP.

**This is a lab-only deployment with deliberately weak, published test
credentials (see below). Do not expose it outside the lab network, and
do not reuse these credentials or certs for anything else.**

## Environment variables

The rig scripts and the `e2e/loop` gate take the rig's addresses from the
environment. Which variables are mandatory depends on the entry point; the shell
scripts stop with a message naming a missing mandatory variable, `e2e/loop` does
not (see below).

| Variable | Meaning |
|---|---|
| `RIG_HOST` | Address of the Asterisk test host (what the transports bind and the SUT dials). Rendered into the `@RIG_HOST@` token in `conf/pjsip.conf` by `deploy.sh`. |
| `RIG_SSH` | `user@host` ssh target for deploying and for rig-side cross-checks. |
| `WS_IP` | The SUT's (workstation's) address on the rig network. |

Mandatory per entry point:

| Entry point | Must be set |
|---|---|
| `deploy.sh` | `RIG_HOST`, and `RIG_SSH` (or the ssh target as the first argument) |
| `gen-certs.sh` | `RIG_HOST` (or `CERT_HOST`) |
| `smoke-test.sh` | `RIG_HOST` (or the host as the first argument) |
| `assert-tcp-tls-capture.sh` | `WS_IP` and `RIG_HOST` |
| `assert-nat-rport.sh` | `WS_IP` |
| `e2e/loop` live gate | `RIG_HOST` only (`SIPCLIENT_E2E_ASTERISK`, or `-asterisk`); `-sanity` needs none |

`e2e/loop` checks only the rig address. `WS_IP` and `RIG_SSH` are optional there:
an unset `WS_IP` leaves the local address at the `127.0.0.1` placeholder (not
reachable from a real rig, but not rejected), and an unset
`RIG_SSH` disables the ssh cross-checks and fails the ext-602 DTMF scenario.

`e2e/loop` (Go) reads `SIPCLIENT_E2E_ASTERISK`, `SIPCLIENT_E2E_LOCAL` and
`SIPCLIENT_E2E_SSH`, which `e2e/loop/run.sh` sets from `RIG_HOST`, `WS_IP` and
`RIG_SSH`. The proxy live test reads `SIPPROXY_LIVE_RIG_HOST`.

**How to use:** this document covers what the platform is. For day-to-day
operation — status/logs/restart, CLI debugging recipes, running the smoke
test, pointing `sipclient-mcp` at this rig, and troubleshooting — see
[`USAGE.md`](USAGE.md).

## What it is

- Own `Dockerfile`, `FROM ubuntu:24.04`, installing the distro Asterisk 20
  package (`universe` component) — no third-party/community Asterisk
  image.
- `network_mode: host` — SIP and RTP bind directly on the test host
  (`RIG_HOST`; ports 5070/5071, since other programs may hold 5060 and
  `e2e-asterisk-xfer` uses 5080/5081). This is deliberate: Docker's NAT
  would rewrite RTP source addresses and mask the symmetric-RTP latching
  behaviour (spec R10) the E2E tests exist to exercise.
- PJSIP only (`chan_sip` is explicitly `noload`ed in `modules.conf` — it's
  deprecated upstream).
- Full spec surface: SIP over UDP/TCP/TLS; RTP and SRTP (SDES,
  `AES_CM_128_HMAC_SHA1_80`); G.711 µ-law/A-law; DTMF via RFC
  2833, inband, and SIP INFO.

## Deploying

```sh
cd e2e/asterisk
./gen-certs.sh      # once, or whenever certs expire -- writes conf/keys/ (gitignored)
./deploy.sh          # renders @RIG_HOST@, rsyncs this dir to $RIG_SSH and runs
                      # `docker compose up -d --build` there
```

`deploy.sh` takes the ssh target as an optional first argument
(`./deploy.sh user@host`) in place of `RIG_SSH`. The host is provisioned
entirely from what's rsynced — there is no host-only config. Everything needed to rebuild
from a clean checkout lives in this directory.

`sipclient-mcp` (or any test client that needs to trust the TLS
transport) needs the generated CA cert as its trust anchor:
`e2e/asterisk/conf/keys/ca.crt`.

## Endpoints

All passwords below are the same fixed, obviously-non-production string:
`e2e-test-only-not-a-secret`. This is test-only infrastructure on a lab
network; per-endpoint unique credentials would add nothing here.

| Endpoint            | Mode                  | Media   | DTMF     | Notes |
|----------------------|------------------------|---------|----------|-------|
| `e2e-uac-register`   | register (dynamic AOR) | RTP     | rfc4733  | REGISTERs first, then dials in as its own registered contact. |
| `e2e-uac-direct`     | direct (no registration)| RTP     | rfc4733  | Dials straight in; identified by SIP username, digest-challenged per request. |
| `e2e-uac-srtp`       | direct                 | **SRTP required** (SDES, `AES_CM_128_HMAC_SHA1_80`, not optimistic) | rfc4733 | A plain-RTP offer is rejected. Provisioned but currently unexercised by `e2e/loop` (the W4 carry-forward gap, spec §8 OPPORTUNISTIC not required this phase). |
| `e2e-uac-inband`     | direct                 | RTP     | inband   | Tones carried in audio, no RFC 2833 events. Provisioned but unexercised by `e2e/loop`: the owner has ruled rfc2833 the operating mode for P3 and inband a carried-forward, non-blocking limitation. Ext `602` is mode-agnostic, so wiring a scenario up to this endpoint is now only a matter of deciding to. |
| `e2e-uac-info`       | direct                 | RTP     | info     | Tones carried via SIP INFO. Provisioned but unexercised by `e2e/loop`: DTMF-over-INFO *reception* is out of scope in production by design (`internal/sipua/dtmf.go`'s `onInfo`), so `e2e/loop` proves the INFO send path against its own local receiver instead. A rig-side INFO scenario against ext `602` is the obvious follow-up. |

All endpoints allow codecs `ulaw,alaw` (G.711 µ-law, G.711 A-law).

Direct-mode endpoints have no fixed source IP to match against (the SUT's
IP isn't known ahead of time), so they're identified by SIP username
(`identify_by=username`) rather than by IP — see the note in
`conf/pjsip.conf`.

## Extensions (context `[e2e]`)

| Extension | Behaviour |
|-----------|-----------|
| `600`     | Echo test: `Answer()` then `Echo()` — loops the caller's own RTP back. This is what exercises the SUT's encode/decode round-trip. |
| `601`     | Plays a known, stable prompt (`demo-congrats` from core-sounds-en) for signalling/media inspection. |
| `602`     | DTMF collect-and-echo: `Read(DIGITS,silence/1,8,,,10)` then `SayDigits`. Working and exercised by `e2e/loop`'s "DTMF rfc2833 vs Asterisk ext 602" scenario. **The `silence/1` prompt argument is load-bearing**: with an empty filename argument `Read()` never waits for a digit at all. Read [`USAGE.md`](USAGE.md)'s Troubleshooting entry before editing this line. |
| `603XX`   | Ringing-then-answer with a controllable delay: dial `603` + 2-digit seconds, e.g. `60305` sends 180 Ringing, waits 5s, answers, then echoes. |
| `486`     | Rejects with 486 Busy Here (never answers). |
| `604`     | Rejects with 404 Not Found (never answers) — `Hangup(1)` maps `AST_CAUSE_UNALLOCATED` to a final 404. |
| `605`     | Long-hold: answers and holds the call open (silent) for up to an hour — for RFC 4028 session-timer refresh and long-call duration tests. No MOH sound package is installed; this exercises the signalling path, not audio content. |

## Ports

| Port      | Protocol | Purpose |
|-----------|----------|---------|
| 5070/udp  | SIP      | UDP transport |
| 5070/tcp  | SIP      | TCP transport |
| 5071/tcp  | SIP/TLS  | TLS transport |
| 10000-10200/udp | RTP/SRTP | Media (kept narrow deliberately) |

Non-standard ports: 5060/5061 may already be bound by other programs on the
host, and `e2e-asterisk-xfer` binds 5080/5081.

## Files

```
e2e/asterisk/
  Dockerfile           ubuntu:24.04 + distro Asterisk 20, runs `asterisk -f -vvv` in the foreground
  Dockerfile.sipp        sipp image for the `sipp` service, built from Dockerfile.sipp
  docker-compose.yml    services `asterisk` and `sipp`, host networking, builds from Dockerfile / Dockerfile.sipp
  conf/
    asterisk.conf        runuser/rungroup only; directory paths use compiled-in FHS defaults
    modules.conf          autoload=yes, noload chan_sip.so
    logger.conf           console + file logging
    pjsip.conf             transports, endpoints/auths/AORs
    extensions.conf        [e2e] dialplan context
    rtp.conf                RTP port range 10000-10200, ICE/STUN off
    keys/                    generated by gen-certs.sh, gitignored
  scenarios/            reusable sipp XML scenarios, one per verified surface (see USAGE.md)
  gen-certs.sh          generates conf/keys/{ca,server}.{crt,key}
  deploy.sh              rsync + `docker compose up -d --build` on the test host
  smoke-test.sh          runs the full scenarios/ matrix, prints a PASS/FAIL/SKIP summary
  USAGE.md               operating runbook: daily ops, CLI recipes, smoke test, troubleshooting
```
