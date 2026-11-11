# e2e/asterisk — USAGE

Operating instructions for the rig described in `README.md` (what it is,
the endpoint/extension/port tables — read
that first if you haven't). This document is the day-to-day runbook:
how to run it, poke at it, debug a failing E2E run, and point
`sipclient-mcp` at it.

All commands below assume `RIG_HOST` and `RIG_SSH` are set (see
[`README.md`](README.md)) and the default remote directory
(`~/e2e-asterisk`, per `deploy.sh`'s `REMOTE_DIR`). `docker compose`
commands run from that directory on the test host.

## Daily operation

```sh
# status
ssh <RIG_SSH> 'cd ~/e2e-asterisk && docker compose ps'

# tail logs (Asterisk runs in the foreground in the container, -vvv, so
# this is the live console output)
ssh <RIG_SSH> 'cd ~/e2e-asterisk && docker compose logs -f'

# restart without rebuilding (config unchanged)
ssh <RIG_SSH> 'cd ~/e2e-asterisk && docker compose restart'

# rebuild + restart after a config change (conf/*.conf, Dockerfile, etc.)
# -- same as running deploy.sh, which rsyncs first
./deploy.sh

# tear down
ssh <RIG_SSH> 'cd ~/e2e-asterisk && docker compose down'
```

An interactive Asterisk console, if you want one instead of one-shot
`-rx` commands:

```sh
ssh <RIG_SSH> 'docker exec -it e2e-asterisk asterisk -rvvv'
```
(`Ctrl-C` or `exit` at the CLI leaves the container running — it detaches
the console, it does not stop Asterisk.)

## Useful Asterisk CLI recipes

Run any of these as `docker exec e2e-asterisk asterisk -rx "<command>"`
from the test host, or from inside the console above.

| Command | What it shows |
|---|---|
| `pjsip show endpoints` | Endpoint state, in-use channel count, per-endpoint auth/AOR. Start here. |
| `pjsip show contacts` | Registered contacts (should be empty except during/just after a register-mode test — see Troubleshooting). |
| `pjsip show aors` | AORs and their bound contacts. |
| `pjsip show transports` | The three transports and their bind addresses — confirms UDP/TCP/TLS all loaded. |
| `pjsip show channelstats` | Per-channel RTP stats (packets/bytes/loss) for active calls. |
| `core show channels verbose` | Active channels, their extension/priority/application and duration — the first place to look for a call that's stuck instead of completing. |
| `pjsip set logger on` | Live SIP message trace on the console (`pjsip set logger off` to stop). The single most useful command for "why did my INVITE not get the response I expected." |
| `rtp set debug on` | Per-packet RTP trace (`rtp set debug off` to stop). Confirms media is actually flowing and on which ports. |
| `dialplan show e2e` | Dumps the `[e2e]` context exactly as loaded — cross-check against `conf/extensions.conf` if an extension misbehaves. |
| `core show codecs` | Full codec table Asterisk knows about (informational only — doesn't reflect this config's `allow=` list). |

## Running the smoke test

```sh
ssh <RIG_SSH> '~/e2e-asterisk/smoke-test.sh'
```

It runs every scenario in `scenarios/` once over UDP, `register.xml`
again over TCP, and prints one line per scenario:

```
  register             ... PASS  ( Successful call | 0 | 1 )
  echo-pcmu             ... PASS  ( Successful call | 0 | 1 )
  ...
  register-tls          ... SKIP  (the installed sipp 3.7.2 build cannot ...)

=== 9 passed, 0 failed, 1 skipped ===
```

`PASS` means sipp's own mandatory `<recv>` matches all succeeded and the
process exited 0 — read as "this surface behaved exactly as specified,"
not just "no crash." `FAIL` dumps the last 20 lines of that scenario's
sipp log (under `/tmp/e2e-asterisk-smoke/` on the test host) so you don't
have to go hunting; look at the `Unexpected-Msg` counters in that log
first, they name which step diverged. `SKIP` is reserved for the one
case sipp genuinely can't drive (TLS, see Known limitations below) — it's
never used to quietly drop a scenario that's merely inconvenient.

Exit code is non-zero if anything `FAIL`ed. sipp runs inside the `sipp`
Compose service (see `docker-compose.yml`), granted only the `NET_RAW`
*capability* the codec scenarios' raw-socket media step needs — no host
sudo is required or provisioned. (That's a statement about the capability
set specifically, not about isolation generally — see "Host privilege
model" below.)

Run an individual scenario the same way, if you're iterating on one.
Unlike `smoke-test.sh` above, this is a raw `docker compose` invocation, so
it needs to run from the project directory itself (where
`docker-compose.yml` lives) rather than resolving its own path:

```sh
ssh <RIG_SSH> 'cd ~/e2e-asterisk && docker compose run --rm -T sipp -sf /scenarios/register.xml <RIG_HOST>:5070 -m 1'
```

## Pointing sipclient-mcp at this rig

| Transport | Target URI |
|---|---|
| UDP | `sip:<RIG_HOST>:5070` |
| TCP | `sip:<RIG_HOST>:5070;transport=tcp` |
| TLS | `sips:<RIG_HOST>:5071` |

Endpoint/credential choice depends on which mode you're testing (see
README's endpoint table for the full picture):

- **Register mode** → `e2e-uac-register` / `e2e-test-only-not-a-secret`.
  REGISTER first, then dial in as the contact you just registered.
- **Direct mode** (no registration) → `e2e-uac-direct` /
  `e2e-test-only-not-a-secret`. Dial straight in; every request gets
  digest-challenged (see Troubleshooting's AOR-name note for why this
  isn't handled by registration instead).
- **SRTP** → `e2e-uac-srtp` / `e2e-test-only-not-a-secret`, direct mode,
  same as above but the offer must include a valid SDES `a=crypto` line
  or Asterisk returns 488 (see `scenarios/srtp-sdes.xml` for the exact
  key-length trap and a known-good offer to copy).
- **Inband/SIP-INFO DTMF** → `e2e-uac-inband` / `e2e-uac-info`, same
  password, direct mode.

TLS trust anchor: `e2e/asterisk/conf/keys/ca.crt` (generated by
`gen-certs.sh`, gitignored — regenerate locally if it's missing, then
`./deploy.sh` to push it).

## Task 33 (P3) acceptance scenarios: DTMF, session-timer, keepalive

`e2e/loop` (the standing loop-call gate, not sipp) drives these; run the
whole gate with `./e2e/loop/run.sh` from the repository root (`-sanity` for
a non-live plumbing check only). Full detail, including exact assertions,
is `e2e/loop/README.md`'s Task 33 section — this is the pointer from the
rig's own docs the design spec's Step 6 asks for.

- **DTMF, two scenarios, two directions.** `DTMF rfc2833 vs Asterisk ext 602`
  dials extension `602` as `e2e-uac-direct` and asserts on Asterisk's own
  `User entered '<digits>'` console line — this is the §14.5 third-party
  proof that an independent implementation understands the RFC 4733 events
  we send, and it needs `ssh` (the digits live in a channel variable that
  dies with the channel, so there is no post-call CLI query for them). The
  three older `DTMF rfc2833/inband/info` scenarios dial a second real UA
  `e2e/loop` hosts locally (`e2e/loop/dtmf_receiver.go`) and prove the
  opposite direction, our own RX decode path. Neither replaces the other.
  `e2e-uac-inband`/`e2e-uac-info` are provisioned but not dialled by any
  scenario — see the endpoint table in `README.md`.
- **Session-timer, two roles:** `session-timer: we refresh` dials
  extension `605` (long-hold) with `session_expires_s`/`min_se_s` both 90,
  proving the daemon's own RFC 4028 refresh against this rig for real.
  `session-timer: peer refreshes` and `session-timer: in-dialog timeout`
  (§11.3.1 case 2) drive their *faulty* leg against local stubs instead
  (RULING 2 — see `e2e/loop/README.md`), since there is no way to make
  Asterisk itself go silent mid-dialog or claim the peer-refresher role on
  demand without a bespoke `pjsip.conf`/`extensions.conf` change that would
  exist only to serve one scenario. (The rig freeze that originally forced
  this was lifted 2026-07-28; the retargeting stands on its own merits, not
  on the freeze.)
  **`session-timer: in-dialog timeout` still needs this rig**, though: its
  control leg dials extension `605` to prove a healthy call survives the
  same interval. Taking the rig down will fail it at `dial 605 (control)`.
- **Keepalive** is driven entirely against a local stub too (out-of-dialog
  OPTIONS traffic has no rig-observable signal Asterisk exposes a counter
  for); this rig is not involved.

## Troubleshooting

Real, already-diagnosed failures from building this rig — check here
before re-debugging any of these from scratch.

- **REGISTER returns 404, every time, silently.** The AOR section name
  must exactly equal the registering username. Asterisk's registrar
  matches the AOR by literal section name
  (`res_pjsip_registrar.c`'s `find_aor_name()`) — an AOR named
  `aor-<user>` (or anything else that isn't the bare username) 404s
  forever with no other symptom. This is why `conf/pjsip.conf`'s
  `[e2e-uac-register]` AOR section is named exactly that, matching the
  `[type=endpoint]` section of the same name (PJSIP keys sections by
  `(name, type)`, so the two coexist).

- **`Read()` returns instantly with zero digits when its `filename`
  argument is empty.** Extension `602` was written as
  `Read(DIGITS,,8,,,10)` and, live-tested, returned in ~50µs with
  `READSTATUS=OK` and an empty `DIGITS` on every call, regardless of what
  DTMF arrived — `Answer` → `Read` → `SayDigits` → `Hangup` all inside the
  same millisecond. It is not a DTMF, codec, media or client problem: an
  independent `sipp` client reproduced it exactly, and the fix is one
  argument. `apps/app_read.c` sets `arglist.filename = NULL` when the field
  is empty; `main/app.c`'s `ast_app_getdata_terminator()` then drives its
  read loop with `ast_strsep(&filename, '&', ...)`; and `ast_strsep()`
  (`main/utils.c`) returns `NULL` immediately for an empty string — unlike
  POSIX `strsep()`, which yields one empty token. The loop body never runs,
  `ast_readstring()` is never called, and the function returns
  `AST_GETDATA_COMPLETE` (0) with an untouched buffer, which `app_read.c`
  maps to `READSTATUS=OK`. Verified against the Asterisk 20.6.0 source, and
  empirically bisected on the rig: `Read(DIGITS,&,8,,,10)` — a filename
  argument that is non-empty but plays nothing — waits the full timeout,
  while `Playback(silence/1)` followed by `Read(DIGITS,,8,,,10)` still
  returns instantly. It is the *argument* that matters, not the audio.
  `602` now passes `silence/1`. Note the diagnostic tell: a genuine
  digit timeout sets `READSTATUS=TIMEOUT`, this failure sets `OK`.
  (An earlier hypothesis — that the empty `attempts` field parsed to 0 —
  was refuted against `app_read.c`, which parses `attempts` only when
  non-empty and clamps `<= 0` to 1. It is not the cause.)

- **TLS transport fails to load: `priv_key_file missing or not
  readable`.** Key file permissions. The container's `asterisk` user has
  a different uid than the host user that ran `gen-certs.sh`/rsynced the
  files, so owner-only permissions on the key files make them unreadable
  inside the container even though they're right there in
  `conf/keys/`. `gen-certs.sh` already `chmod 644`s everything it
  generates for exactly this reason — if you hit this, check you didn't
  hand-copy a key some other way.

- **TLS handshake rejected by a modern client: `tlsv1 alert protocol
  version`.** `method` in `[transport-tls]` must be pinned to
  `tlsv1_2`. Left as the PJSIP default ("unspecified"), the transport
  negotiates down to a TLS version too old for a default-policy OpenSSL 3
  client to accept.

- **A blank `stunaddr =` line in `rtp.conf` produces a startup ERROR.**
  `res_rtp_asterisk` attempts to DNS-resolve an empty string and logs an
  ERROR on every start. STUN isn't used here (no NAT — see README's
  host-networking rationale), so just omit the line entirely rather than
  leaving it blank.

- **~135 startup warnings about ODBC, PostgreSQL, LDAP, ARI, XMPP,
  STIR/SHAKEN, IAX2, and other optional subsystems declining to load.**
  Expected and benign — a direct consequence of `modules.conf`'s
  `autoload=yes` with only `chan_sip.so` explicitly `noload`ed. None of
  these subsystems are needed for the SIP/RTP surface this rig tests.
  Don't chase them.

- **sipp exits 1 immediately, before even resolving the remote host,
  with `Variable $x is referenced 1 times!`.** Not a platform issue —
  this build of sipp treats an `<ereg assign_to="x">` capture that's
  never referenced again anywhere else in the scenario as a fatal
  scenario-load error. Every `ereg`-based assertion in `scenarios/`
  works around this with a trailing `<log message="...[$x]..."/>` in the
  same `<action>` block; if you add a new capturing assertion, do the
  same.

- **`play_pcap_audio` fails with `Can't create raw IPv4 socket...
  Operation not permitted`.** Needs `CAP_NET_RAW` — the `sipp` Compose
  service is granted only that *capability* via `cap_add: [NET_RAW]`,
  which is why `smoke-test.sh` and any by-hand scenario runs go through
  `docker compose run --rm -T sipp ...` rather than a bare `sipp` binary. If
  you see this error, you're running `sipp` outside that container. (The
  capability grant is narrow, but the container's overall host privilege
  isn't — see "Host privilege model" below.)

## Host privilege model

"Granted only the `NET_RAW` capability" (used twice above) is a true
statement about the `sipp` container's capability set specifically. It is
not a statement about isolation generally, and reading it that way
overstates what this wave actually closed. Two things worth being
explicit about:

- **The ssh user is in the host's `docker` group.** Group membership
  in `docker` is root-equivalent independent of `sudo` — anyone who can
  run `docker run -v /:/host ...` can read and write anything root can.
- **The `sipp` container can read and write the host filesystem via
  `/proc/1/root/`.** It runs as uid 0 with no `user:` directive, and
  `pid: host` (see `docker-compose.yml`) makes `/proc/1/root/` a working
  symlink to the host's real root. Reaching through it is gated by
  ordinary Unix owner-permission bits, not by capabilities — so
  `cap_drop: [ALL]` / `cap_add: [NET_RAW]` doesn't touch this path at
  all. What `cap_drop` *does* close is `CAP_KILL` against the host's
  process tree (operative only because of `pid: host`, see
  `docker-compose.yml`'s comment) and `CAP_SYS_ADMIN`-gated tricks like
  `setns()`-based container-hopping.

**Net effect:** the ceiling of what the ssh user, or the `sipp` container,
could touch on the host is host-root-equivalent via the `docker` group and,
for the `sipp` container specifically, via `/proc/1/root/`.

## Known limitations

- **Transports bind to the literal `RIG_HOST` address**, not `0.0.0.0`
  (`conf/pjsip.conf`'s three `bind =` lines hold an `@RIG_HOST@` token that
  `deploy.sh` renders at deploy time). Deploying to a different address means
  re-running `deploy.sh` with a different `RIG_HOST`.
- **No audio device on the host.** This limits `baresip`-style tooling to
  signalling-only use unless a virtual soundcard (e.g. `snd-aloop`) is
  loaded on the host first — out of scope for this rig as committed.
- **The installed sipp build (3.7.2-TLS) cannot complete a TLS handshake
  in single-socket mode** (`-t l1`). Confirmed by hand: `sipp -t l1
  <host>:5061 -tls_ca conf/keys/ca.crt` fails during TLS context init
  before ever attempting the handshake. (That exact command is a
  pre-containerization historical reference — sipp now runs only inside
  the `sipp` Compose service, which doesn't bind-mount `conf/keys/`, so
  this literal invocation isn't reproducible as written; the underlying
  TLS-handshake limitation it demonstrates still holds.) `smoke-test.sh`
  skips TLS explicitly with this reason rather than silently omitting it
  — TLS itself is proven working (see `pjsip show transports` and the
  Troubleshooting entries above), just not drivable by this sipp build.
