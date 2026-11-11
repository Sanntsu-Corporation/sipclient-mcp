# e2e/loop — standing loop-call interop gate

The Wave-1 exit-criterion gate (spec §14.5). It drives a **locally spawned
`sipclient-mcpd`** over **MCP-over-HTTP** through six loop-call scenarios against
the Asterisk rig, exercising the SUT's **inbound** path (inbound INVITE,
ringing, `call_answer`/`call_reject`, inbound BYE/CANCEL) that the outbound-only
interop run never touched.

```
caller (direct UA e2e-uac-direct) ──INVITE 720/721──▶ Asterisk <RIG_HOST>
                                                          │ Dial(PJSIP/e2e-uac-register)
                                        ◀──inbound INVITE─┘
callee (register UA e2e-uac-register) — the only AOR the rig knows
```

Both UAs are created inside **one** MCP session on one daemon; Asterisk bridges
the two legs, so a single daemon plays both caller and callee.

## Transport (ratified 2026-07-21: stdio → HTTP)

Rule-6a decision #7 originally said "MCP stdio". The daemon has **no stdio
transport** — it serves MCP over **HTTP only** (`cmd/sipclient-mcpd` builds an
`http.Server` on `--listen`, default `127.0.0.1:8080`). The owner ratified the
switch to HTTP. The harness therefore:

1. `go build`s `./cmd/sipclient-mcpd` and spawns it with
   `--listen 127.0.0.1:<free-port> --policy e2e/loop/policy.yaml --state
   <private temp dir>/state.yaml` (its working directory is the repo root, so
   the policy's repo-root-relative file paths resolve). The policy is only a
   one-shot seed for that fresh state file; the daemon then runs from its own
   state;
2. connects a go-sdk **`StreamableClientTransport`** (v1.6.1) to
   `http://127.0.0.1:<port>/mcp`, injecting `Authorization: Bearer <token>` on
   every request, where the token is the one the daemon minted for itself and
   wrote to `<state dir>/bearer.token` (not the committed
   `e2e/loop/bearer_token.txt`, which must exist but is not what the daemon
   authenticates against);
3. drives the `ua_*` / `call_*` tools and asserts the observable outcome of each
   scenario.

No production or daemon code is involved — the harness is purely additive under
`e2e/loop/`.

## Prerequisites

- **Set `RIG_HOST`, `RIG_SSH` and `WS_IP`** as described at the top of
  [`../asterisk/README.md`](../asterisk/README.md); `run.sh` maps them onto the
  `SIPCLIENT_E2E_*` variables the harness reads. Without them the harness
  refuses to run the gate.
- **The rig is up** at `<RIG_HOST>` (ports 5070/5071) with the `[e2e]`
  dialplan loaded (720/721). Run `e2e/asterisk/smoke-test.sh` before trusting
  any result:
  ```sh
  ssh <RIG_SSH> 'docker exec e2e-asterisk asterisk -rx "dialplan show e2e"'   # shows 720, 721
  cd e2e/asterisk && ./smoke-test.sh                                                        # exits 0
  ```
- **This host is `<WS_IP>`** on the rig network — both UAs bind
  `local_addr <WS_IP>` (`-local <ip>` or `SIPCLIENT_E2E_LOCAL`).
- **Credentials** (committed, test-only): SIP digest password
  `e2e-test-only-not-a-secret` in `auth_pass.txt`; MCP bearer token in
  `bearer_token.txt`. Neither is a real secret (see the rig README) and both
  guard only a loopback-bound daemon that emits SIP to the test rig alone.
- Go toolchain, and `ssh` access to the rig. Most `ssh` use is best-effort
  cross-checking, but the `DTMF rfc2833 vs Asterisk ext 602` scenario FAILS
  without it — it asserts on Asterisk's own log of the digits it decoded.

## Run

From the **repository root**:

```sh
go run ./e2e/loop          # the full gate
# or
./e2e/loop/run.sh
```

Expected output ends with one `PASS` line per scenario (19 as of Task 33 + M8/D5) and:

```
=== 19/19 passed ===
```

Exit code is `0` iff every scenario passes, non-zero otherwise. Each scenario prints one
`PASS`/`FAIL` line with a one-line reason.

Useful flags: `-local <ip>` (bind address), `-asterisk <ip>` (rig),
`-ssh <RIG_SSH>` (`""` disables the Asterisk cross-checks, and fails the
ext-602 DTMF scenario — see Prerequisites),
`-v` (stream the daemon's stderr), `-sanity` (see below).

### Non-live sanity (`-sanity`)

```sh
go run ./e2e/loop -sanity
```

Spawns the daemon, connects over MCP/HTTP, calls `tools/list` (asserting the
expected call/UA tools are advertised and that the removed `profile_list`
has NOT come back), then does an inline-account `ua_create`/`ua_destroy`
round-trip (asserting no credential is echoed back in the response), and
shuts down — **emitting no SIP to the rig**. Proves the transport, bearer
auth, and inline-account plumbing in isolation. This is the only mode safe
to run without a healthy rig.

## The original six scenarios

(Since extended by P2 W4/W5's codec-negotiation/488/echo-quality/play-record
scenarios and Task 33's eight below; this table is the original Wave-1 set.)

| # | Name | Drive | Assertion |
|---|------|-------|-----------|
| #3 | caller-id | dial 720, inspect callee's inbound leg, answer | callee `from_uri` user part == `e2e-uac-direct`; both legs answer |
| #7 | remote-reject | dial 720, callee `call_reject` 486 | caller leg `last_response.code` == 486 |
| #6 | remote-offline | `ua_destroy` callee (drops AOR contact), dial 720, re-register callee | caller leg `last_response.code` == 404 |
| #1 | remote-disconnect (D1) | dial 720, answer, **caller** hangs up → Asterisk BYEs callee | callee `termination_reason` == `remote_bye`, state `terminated` (no 481) |
| #2 | local-disconnect (D1) | dial 720, answer, **callee** hangs up (UAS BYE) | caller `termination_reason` == `remote_bye` (callee's UAS BYE accepted, not 481) |
| #5 | remote-no-answer (D3) | dial 721 (8 s ring), do **not** answer; Asterisk cancels at ring expiry | callee `termination_reason` == `cancelled`, **not** `inbound_ring_timeout` |
| #5b | caller-CANCEL (CF-043) | dial 721, once the callee rings `call_hangup` the **caller** at ~1 s | caller `terminated`/`local_hangup`; callee `cancelled` within 3 s of the hangup (well before Asterisk's 8 s ring budget); caller ladder has one CANCEL and a 487 |
| CF-037 | sibling survives a dial timeout | dial 600 (answered), then dial `sip:x@192.0.2.1` (TEST-NET-1 black hole) and a second one hung up at once; wait out the 32 s dial timeout | the 600 call is still `answered` and `call_hangup` on it succeeds |

The answered scenarios also implicitly exercise **D2** (Asterisk's mid-dialog
re-INVITE, guarded) and **D5** (digest-authed dial with ringing).

Scenario #5 note: the *caller-initiated* CANCEL variant is driven by #5b.
The D3 assertion in #5 (callee sees `cancelled`, not `inbound_ring_timeout`)
is exercised via **Asterisk's** ring-expiry CANCEL.

## Task 33 (P3): DTMF, session-timer and keepalive acceptance

Design spec §8's Asterisk e2e coverage for R2/R9/§11.3.1 case 2/keepalive
(R2's ±20ms loopback timing suite lives in `internal/sipua` instead — see
`p3_acceptance_test.go`/`p3_r8_test.go`). Per RULING 2 (Task 33's
owner-ratified retargeting), the session-timer peer-refresher half, the
in-dialog-timeout scenario and keepalive are driven against LOCAL stubs
(`sessiontimer_peer_stub.go`, `sessiontimer_silent_stub.go`,
`keepalive_stub.go`) rather than the shared rig: there is no way to make
Asterisk go silent mid-dialog or claim the peer-refresher role on demand
without a bespoke config change existing only to serve one scenario. That
still holds now the rig freeze is lifted — it is a design judgement, not a
consequence of the freeze.

**DTMF is covered in both directions, by two different kinds of scenario.**

- `DTMF rfc2833 vs Asterisk ext 602` dials the rig and proves our **TX**
  encoding is understood by an independent implementation — the bug class
  §14.5's interop gate exists to catch, since a local loopback has our
  implementation on both ends and cannot see a shared misunderstanding of
  the protocol.
- The three `DTMF rfc2833/inband/info` scenarios dial a SECOND real
  `sipua.UA` this binary hosts (`dtmf_receiver.go`) and prove our **RX**
  decode path (RFC 4733 decode, Goertzel inband detection) digit by digit.

Historical note, kept because it cost real time to find: ext 602 was
originally `Read(DIGITS,,8,,,10)` and returned in ~50µs with zero digits on
every call regardless of what arrived (`Answer` → `Read` → `SayDigits` →
`Hangup` all inside the same millisecond). That is an Asterisk behaviour,
not a rig misconfiguration — `Read()` with an *empty* filename argument
never waits for a digit at all. The mechanism, and the empirical bisect
that pins it to the argument rather than to DTMF, media or our client, is
in `e2e/asterisk/USAGE.md`'s Troubleshooting section. The rig freeze that
made the retarget mandatory was lifted 2026-07-28; ext 602 is fixed
(`Read(DIGITS,silence/1,8,,,10)`) and dialled again. `e2e-uac-inband`/
`e2e-uac-info` remain defined in `policy.yaml` but are still unreferenced —
inband is a ruled, carried-forward limitation and INFO *reception* is out of
scope in production, so neither is blocked on the rig any more.

| Name | Drive | Assertion |
|------|-------|-----------|
| DTMF rfc2833 | `e2e-uac-direct` dials a local second real UA (`dtmf_receiver.go`), `dtmf_send(mode=rfc2833)` — **no rig traffic** | `digits_sent`==8, the receiver UA's own production RX decode reports back the same 8 digits, plain BYE (no `Reason`) in the ladder |
| DTMF rfc2833 vs Asterisk ext 602 | `e2e-uac-direct` dials ext `602` on the rig, `dtmf_send(mode=rfc2833)` with 8 digits derived from the wall clock — **real rig traffic** | `digits_sent`==8, and Asterisk's own `User entered '<digits>'` console line (read over `ssh`, `docker logs`) names exactly those digits. Fresh digits per run mean a line from an earlier run can never satisfy a later one. **Requires `-ssh`**: the digits live in a channel variable that dies with the channel, and `PJSIP_HEADER(add,…)` is not applied to the `BYE` `Hangup()` generates, so there is no post-call CLI query and no in-band SIP carrier for them |
| DTMF inband | same local receiver, `dtmf_send(mode=inband)` — **no rig traffic** | same: 8 digits decoded by the receiver's real inband (Goertzel) detector |
| DTMF SIP INFO | same local receiver, `dtmf_send(mode=info)` — **no rig traffic** | 8 SIP INFO requests confirmed in the ladder (DTMF-over-INFO RECEPTION is out of scope in production by design — `dtmf.go`'s `onInfo` doc comment — so there is no receiver-side digit to check for this mode) |
| session-timer: we refresh | `e2e-uac-sessiontimer` (90/90) dials ext 605 (long-hold) — reaches the rig | `session_timer.refresher`==`uac`, `next_refresh_ms` observed decreasing, still `answered` past the original 90s interval |
| session-timer: peer refreshes | a local stub UAC dials the daemon's UA (fixed `local_addr`) proposing `Session-Expires: 90;refresher=uac`; stub sends one mid-dialog UPDATE before 90s — **no rig traffic** | `session_timer.refresher`==`uac` (the peer, who dialled, IS the UAC — `Refresher` names the SIP role, not "us" vs "peer"), still `answered` ~95s in (the watchdog rearmed) |
| session-timer: in-dialog timeout (§11.3.1 case 2) | dial a local stub that answers `Session-Expires: 90;refresher=uac` then goes silent on our refresh; a second, ordinary call on the SAME UA (ext 605, reaches the rig) runs alongside | faulty leg: `terminated`/`transport_failure`, an `error` event with `detail.cause`==`in_dialog_timeout`, **no BYE** in its ladder, `calls_by_termination_reason{reason="transport_failure"}` up by exactly 1; control leg: still `answered` |
| keepalive observable | `e2e-uac-keepalive` registers against a local stub (`keepalive_interval_s: 5`) — **no rig traffic** | the stub counts >= 2 inbound OPTIONS within 12s |

## Phase 4 W1 (M8/D5): registration refresh, sustained

Placed **last** in the scenario list (`gate.go`). Subject: the **standing**
`r.registerUA` — not a new UA, since the rig's `e2e-uac-register` AOR is
`max_contacts=1, remove_existing=yes` and a second register-mode UA would
evict the standing one's contact and break every later scenario. By the time
this scenario runs, the standing UA has been registered ~5.5 min and
refreshed several times already, so this proves *sustained* refresh, not just
the first one. Drive: none — it is a pure observation window, polling
`ua_status` every 5s until two fresh refreshes are observed or a 130s
deadline expires (Asterisk grants 60s for `e2e-uac-register`;
`registerRefreshFraction=0.85 +/- registerRefreshJitter=0.05`,
`internal/sipua/register.go`, fires the actual refresh at 48-54s per cycle).

| Name | Drive | Assertion |
|------|-------|-----------|
| registration refresh, sustained | none — observes the standing register UA's own refresh timer over a 130s window | (1) registrar-side: `pjsip show contacts` (polled live over ssh, every 5s alongside the local poll) shows Asterisk's own AOR still holding a contact at EVERY sample, no gaps, across a window spanning >=2 of the registrar's granted 59s expiry cycles — proves the refresh landed registrar-side, not just self-reported; the original design (grepping `docker logs` for "Added contact" lines) didn't survive live-rig verification: that NOTICE line fires once per UA lifetime, not per refresh, on this rig (see `scenarios_p4.go`); (2) wire-level (bracketed by `pjsip set logger on`/`off`, filtered to this run's own Contact URI): exactly 1 distinct Call-ID and strictly increasing CSeq across the REGISTERs in the window (RFC 3261 §10.2, walking M3's 401-challenge retry path live) — confirmed empirically that the logger's SIP-message dump reaches `docker logs` on this rig, so this assertion is a full gate verdict, not a diagnostic; (3) local: `registered`/`register_code` stay `true`/`200`, `expires_s` stays `59` throughout (Asterisk's own AUTHORITATIVE Contact `expires` parameter on this rig — one second under policy.yaml's requested `60`, confirmed live and RFC 3261 §10.2.4-correct; see `scenarios_p4.go`), and `next_refresh_ms` shows a sawtooth (a jump-up after each refresh, not a monotone decay to 0) |

**What this scenario cannot prove**: Asterisk never reuses a nonce (Phase 4
Inputs §1), so RFC 7616 `nc=1,2,3,4` monotonicity is not observable here —
that is already proven at unit level against `internal/testutil/peer` in M3.
This scenario proves the rewrite didn't break registration-refresh against a
real registrar: regression-safety, not the nonce-count feature.

## Cross-checks

After each scenario's teardown the harness (best-effort, over `ssh`) runs
`core show channels` and **warns** if the rig still holds active channels — a
wedged channel the MCP-side assertions cannot see. After `ua_destroy` the callee
leaves no contact (`pjsip show contacts` empty). These are diagnostics, not gate
verdicts; disable them with `-ssh ""`.

## Standing gate

Every later P2 wave's closeout **re-runs this gate**: it is the regression
harness for the inbound path, not a one-off. Keep it green.
