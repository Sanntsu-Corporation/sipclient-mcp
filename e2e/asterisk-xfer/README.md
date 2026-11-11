# e2e/asterisk-xfer — Call Transfer Interop Rig

## 1. Purpose

This is the real-Asterisk interop gate for the call-transfer feature (design spec §7.2). It
checks how a real B2BUA reacts to our REFER/NOTIFY implementation — the
loopback suite in `internal/sipua` proves our own protocol behavior, this rig
proves interop with a real peer.

It is **separate** from `e2e/asterisk` (the §14.5 SIPp gate), so that gate's
state is never disturbed. This rig runs on the same kind of test host, using
ports **5080 (UDP/TCP) and 5081 (TLS)** — never 5060/5061, which other programs
on that host may already hold — and reuses the Asterisk image already built
there.

Set `RIG_HOST`, `RIG_SSH` and `WS_IP` as described at the top of
[`../asterisk/README.md`](../asterisk/README.md); this README writes them as
`<RIG_HOST>`, `<RIG_SSH>` and `<WS_IP>`.

## 2. Preflight

Confirm the SSH/Docker access model on the test host first. Run:

```bash
ssh -o BatchMode=yes -o ConnectTimeout=5 <RIG_SSH> 'id; docker version --format "{{.Server.Version}}"; docker images --format "{{.Repository}}:{{.Tag}} {{.ID}}"'
```

- If the SSH login fails, or `docker` needs sudo: **STOP**. Report to the
  user which user and group model to use (compare `e2e/asterisk/USAGE.md`
  "Host privilege model"). Hand any privileged command to the operator.
- From the image list, identify the pre-built Asterisk image. If it is
  ambiguous, **STOP** and ask. Then check that it runs Asterisk in the
  foreground against `/etc/asterisk`:
  `ssh <RIG_SSH> 'docker image inspect <image> --format "{{json .Config.Cmd}} {{json .Config.Entrypoint}}"; docker run --rm --entrypoint asterisk <image> -V'`
  Expected: a command equivalent to `asterisk -f` (the `e2e/asterisk` image uses
  `["asterisk","-f","-vvv"]`) and a version line `Asterisk 1x.y`. chan_pjsip
  must be present:
  `docker run --rm --entrypoint sh <image> -c 'ls /usr/lib/*/asterisk/modules/chan_pjsip.so /usr/lib/asterisk/modules/chan_pjsip.so 2>/dev/null'`.
  If there is no PJSIP, **STOP**.
- Ports free on the test host:
  `ssh <RIG_SSH> 'ss -lntup | grep -E ":(5080|5081)\b" || echo FREE; ss -lnup | awk "{print \$5}" | grep -E ":(10[3-4][0-9]{2}|10500)$" || echo RTP-FREE'`
  Expected: `FREE` and `RTP-FREE`. If something is bound, **STOP** and report
  the conflicting port.
- The workstation's address on the rig network, used as every UA's
  `local_addr` below: `ip -4 -o addr show | awk '{print $4}'` → record it as
  `WS_IP`.
- Reachability: `nc -zvu -w2 <RIG_HOST> 5080`. UDP says little, so the
  real check is the REGISTER/dial in the Deploy/Scenario steps below.

**Expected on a healthy host:**

| Item | Value |
|---|---|
| `<image>` | an Asterisk image whose command is `asterisk -f -vvv` |
| chan_pjsip | present (`/usr/lib/x86_64-linux-gnu/asterisk/modules/chan_pjsip.so`) |
| Ports 5080/5081 | `FREE` |
| RTP range 10300-10500 | `RTP-FREE` |
| Access model | no `sudo` needed — the ssh user is in the `docker` group |

## 3. Deploy

```bash
KEYS_DIR=e2e/asterisk-xfer/conf/keys CERT_HOST=<RIG_HOST> e2e/asterisk/gen-certs.sh
XFER_ASTERISK_IMAGE=e2e-asterisk-asterisk:latest e2e/asterisk-xfer/deploy.sh <RIG_SSH>
ssh <RIG_SSH> 'docker exec e2e-asterisk-xfer asterisk -rx "pjsip show transports"'
```

The health check must list the udp/tcp transports on `:5080` and tls on
`:5081`.

## 4. Procedure

- [ ] **Step 4: Deploy and health-check.** Run the Deploy section above.
  `pjsip show transports` must show `<RIG_HOST>:5080` (udp, tcp) and
  `<RIG_HOST>:5081` (tls). `pjsip show endpoints` must list `xfer-a`.
  `dialplan show xfer-parties` must list `party-b` and `party-c`.

- [ ] **Step 5: Put the new binary behind the local daemon.**
  ```bash
  make build && systemctl --user restart sipclient-mcpd && systemctl --user is-active sipclient-mcpd
  ```
  Expected: `active`. If the `sipclient-mcp` MCP tools in this session do
  not list `call_transfer`, reconnect the server (`/mcp` → reconnect). The
  client caches `tools/list`.

  Start raw capture before each scenario. Rule 21 applies: the capture is
  the evidence and logs are not. Non-sudo `tcpdump` works on this
  workstation.
  ```bash
  mkdir -p e2e/asterisk-xfer/captures
  tcpdump -i any -s 0 -w e2e/asterisk-xfer/captures/<scenario>-$(date +%Y%m%dT%H%M%S).pcap 'host <RIG_HOST> and (port 5080 or portrange 10300-10500)'
  ```
  Run it in the background. Stop it after the scenario ends.

- [ ] **Step 6: Scenario 1 — blind transfer.** Use the `sipclient-mcp` MCP
  tools. `WS_IP` comes from the preflight. All three scenarios run on
  **one** UA in **one** MCP session. Do not `ua_destroy` until all three
  scenarios are finished (the end of Scenario 3): it also deletes the
  calling MCP session, and later tool calls then fail `not_found` until the
  MCP server is reconnected.
  1. `ua_create {"mode":"direct","transport":"udp","local_addr":"<WS_IP>:0","aor":"sip:xfer-a@<RIG_HOST>:5080","auth_user":"xfer-a","auth_pass":"e2e-test-only-not-a-secret"}` → UA-A.
  2. `call_dial {"ua":"<UA-A>","to_uri":"sip:710@<RIG_HOST>:5080"}` → call A1. Then `call_wait {"call":"<A1>","until":"answered","timeout_ms":10000}`.
  3. On the rig, record the bridge: `ssh <RIG_SSH> 'docker exec e2e-asterisk-xfer asterisk -rx "core show channels verbose"'`. Expect one PJSIP/xfer-a channel bridged with `Local/party-b@xfer-parties-...;1`, and `...;2` running `Echo`.
  4. `call_transfer {"call":"<A1>","mode":"blind","target":"sip:700@<RIG_HOST>:5080"}`. **Expect** `accepted:true` and `status_code:202`.
  5. Loop on `call_wait {"call":"<A1>","until":"transfer","timeout_ms":35000}` plus `call_events` until an event has `detail.final == true`. **Expect** `success:true, status_code:200`, possibly preceded by `final:false` events (100 or 180). Then `call_wait {"call":"<A1>","until":"terminated","timeout_ms":10000}` must report `remote_bye`, because Asterisk BYEs the transferer.
     This `success:true` confirms interop with a real peer, but it does **not** itself exercise the tight NOTIFY-vs-BYE race D16/D18 guard against: Asterisk's own deferred-BYE behavior means the recorded gap between the final NOTIFY and the BYE (item 7) is typically well past any real scheduling race window, not inside it. That race — a NOTIFY and a BYE landing close enough together that goroutine scheduling alone could reorder their effect — is proven deterministically only by the unit tests `TestAFinalNotifyThatArrivedFirstWinsEvenWhenTheByesHandlerRunsFirst` and `TestAPeerByeThatArrivedFirstWinsEvenWhenTheNotifysHandlerRunsFirst`, run in-process. This scenario checks what those tests cannot: that Asterisk really sends the NOTIFY before the BYE at all, and that both requests reach our one read loop. So a final event of `success:false` with reason `"the dialog ended before a final NOTIFY"`, while the pcap (item 7) shows a `SIP/2.0 200 OK` sipfrag NOTIFY **before** the BYE from the same source address and port, is a **blocking finding on its first occurrence**. It is a deterministic defect, not bad luck, and must not be re-run until it passes. Also check the daemon log for D18's `waited out the arrival-order bound` Warn: any occurrence is a blocking finding (an orphaned ticket on a healthy path). Still run the scenario three times (fresh `call_dial` each time; one Interop log row per run). The repetitions now record the variety of NOTIFY-to-BYE gaps, not a scheduling lottery.
  6. On the rig, `core show channels verbose` must now show the `Local/party-b...;1` channel in extension `700` (`Echo`) and no PJSIP/xfer-a channel. This is Asterisk-internal state, so the CLI is the only place it can be seen.
  7. Check the pcap with `tshark -r <pcap> -Y sip -T fields -e frame.time_relative -e ip.src -e udp.srcport -e sip.Method -e sip.Status-Code -e sip.CSeq -e sip.Event -e sip.Refer-To`. On A1's Call-ID the capture must show, in order:
     - REFER from `WS_IP`, with Refer-To `<sip:700@<RIG_HOST>:5080>`;
     - 202;
     - one or more NOTIFYs from Asterisk, each answered 200 by us, with `Event: refer;id=<the REFER's CSeq>` or `Event: refer`;
     - a final NOTIFY whose sipfrag is `SIP/2.0 200 OK`;
     - a BYE **from `<RIG_HOST>`**, after that NOTIFY, and **no BYE from `WS_IP`**. Record the gap between the final NOTIFY and the BYE (`frame.time_relative`) in the Interop log Notes. A gap of a few milliseconds is the condition D16 and D18 exist for. Also record that the NOTIFY and the BYE share one source `ip:port` (`-e udp.srcport`). D18's order guarantee is per transport connection, and a single UDP source to our listener satisfies it.

     Where the log and the capture disagree, the capture wins.

- [ ] **Step 7: Scenario 2 — attended transfer.** Same UA-A and MCP session. Start a fresh capture.
  1. `call_dial` `sip:710@<RIG_HOST>:5080` → A1 (bridged to party-b). `call_dial` `sip:711@<RIG_HOST>:5080` → A2 (bridged to party-c). Both must reach `answered`.
  2. `call_transfer {"call":"<A1>","mode":"attended","consult_call":"<A2>"}`. **Expect** `accepted:true`, status 202.
  3. The final `transfer` event on A1 must be `success:true`. Both A1 and A2 must terminate with `remote_bye`, which shows Asterisk's `Replaces` handling ended both of A's legs. A2 gets **no** `transfer` event.
  4. On the rig, `bridge show all` and `core show channels verbose` must show `Local/party-b...;1` and `Local/party-c...;1` bridged **to each other**, and no PJSIP/xfer-a channel left.
  5. Check the pcap:
     - The REFER on A1's Call-ID carries `Refer-To: <sip:...@<RIG_HOST>:5080?Replaces=<A2 Call-ID percent-encoded>%3Bto-tag%3D<Asterisk's tag on A2>%3Bfrom-tag%3D<our tag on A2>>`.
     - Cross-check both tags against A2's INVITE (our From-tag) and its 200 (Asterisk's To-tag) in the same capture.
     - The NOTIFY sequence matches Scenario 1.
     - There is a BYE **from `<RIG_HOST>`** on both A1 and A2, and none from `WS_IP`.

  Do **not** `ua_destroy` yet. Scenario 3 runs on the same UA.

- [ ] **Step 7b: Scenario 3 — retry after a rejected transfer (D13 against a real peer).**
  This checks D13's retry rule on a real notifier. It also settles the
  plan's open question: does Asterisk (PJSIP) put `id` on the `Event: refer`
  header of its NOTIFYs, for a first REFER and for a later one on the same
  dialog? Same UA-A and MCP session. Start a fresh capture.
  1. `call_dial` `sip:710@<RIG_HOST>:5080` → A3 (bridged to party-b). It must reach `answered`.
  2. First attempt, to an extension that does not exist in `[xfer]`: `call_transfer {"call":"<A3>","mode":"blind","target":"sip:799@<RIG_HOST>:5080"}`. **Expect** a failed transfer, in one of two shapes. Record which one happened, because the plan does not assume either:
     - (a) `accepted:false` with a 4xx `status_code` (res_pjsip_refer rejecting the REFER synchronously). No subscription was created.
     - (b) `accepted:true`, then a final `transfer` event with `success:false` (Asterisk accepted and reported the failure by NOTIFY).

     Either way, loop `call_wait {"call":"<A3>","until":"transfer","timeout_ms":35000}` until this attempt's final `transfer` event (`final:true`) has arrived. A synchronous rejection emits one too. The call must still be `answered` (`call_status`). A failed transfer does not end the call.
  3. Retry on the same call: `call_transfer {"call":"<A3>","mode":"blind","target":"sip:700@<RIG_HOST>:5080"}`. **Expect** `accepted:true`, then a final `transfer` event with **`success:true, status_code:200`**, then `remote_bye`.
  4. Check the pcap. List every NOTIFY with its headers: `tshark -r <pcap> -Y 'sip.Call-ID contains "<A3 Call-ID>" && sip.Method == "NOTIFY"' -O sip | grep -E 'CSeq:|Event:|Subscription-State:|SIP/2.0 [0-9]{3}'`. Also list the REFERs' CSeqs: `tshark -r <pcap> -Y 'sip.Method == "REFER"' -T fields -e sip.CSeq`. Record in the Interop log Notes:
     - whether the NOTIFYs' `Event` header carries `id=`, separately for the first attempt (if it drew any NOTIFY) and for the retry, and whether each `id` equals its own REFER's CSeq;
     - in shape (b), whether the first attempt's final NOTIFY carried `Subscription-State: terminated`.
  5. Verdict. A retry that ends `success:true` is a PASS, whatever the `id` answer. If the retry instead ends `"no final NOTIFY before the transfer outcome deadline"` while the pcap shows a `200 OK` sipfrag NOTIFY for it, read the daemon log's `refer NOTIFY on a live dialog matched no in-flight transfer` Warn line and its `why`:
     - `why` names an earlier subscription that may still be live, the retry's NOTIFYs carry no `id`, and the first attempt was shape (b) **without** `terminated`: D13 behaved as designed on a non-compliant final NOTIFY (RFC 3515 §2.4.7). Report it to the owner as an interop limitation, not a code defect.
     - Any other `why` (From-tag, id mismatch), or a shape-(a) first attempt: **blocking finding**.
  6. Clean up: `ua_destroy {"ua":"<UA-A>"}`. This also ends the MCP session.

If any scenario fails, capture Asterisk's own view (`pjsip set logger on`,
re-run, `docker logs e2e-asterisk-xfer --since 5m`) as supporting context
only. Then stop and report it as a blocking finding.
Do not change the rig to force a pass.

## 5. Interop log

| Date | Commit | Asterisk version | Scenario | Verdict | Evidence (pcap path) | Notes |
|---|---|---|---|---|---|---|
| 2026-09-27 | 1c0fdb3 | 20.6.0~dfsg+~cs6.13.40431414-2build5 | 1 (blind, rep 1) | PASS | `captures/scenario1-run1-20260927T093839.pcap` | REFER→202 at t=15.6147s; two NOTIFYs (CSeq 27475/27476, `Event: refer`, no `id=`) at t=15.6186/15.6187 (~4ms after 202), both answered 200; `success:true,status_code:200`. BYE from the rig at t=75.6204 — exactly 60.002s after the NOTIFYs, same src ip:port throughout. |
| 2026-09-27 | 1c0fdb3 | 20.6.0~dfsg+~cs6.13.40431414-2build5 | 1 (blind, rep 2) | PASS | same pcap | REFER at t=135.5978; NOTIFYs at t=135.6009/135.6010 (~3.1ms after 202); BYE at t=195.6018 — 60.001s gap. |
| 2026-09-27 | 1c0fdb3 | 20.6.0~dfsg+~cs6.13.40431414-2build5 | 1 (blind, rep 3) | PASS | same pcap | REFER at t=214.5173; NOTIFYs at t=214.5205/214.5206 (~3.1ms after 202); BYE at t=274.5211 — 60.001s gap. |
| 2026-09-27 | 1c0fdb3 | 20.6.0~dfsg+~cs6.13.40431414-2build5 | 2 (attended) | PASS | same pcap | A1→710, A2→711, both answered; `call_transfer(mode=attended,consult_call=A2)` → `accepted:true,202`; A1's final transfer event `success:true,status_code:200`. `bridge show all` confirmed `party-b`/`party-c` bridged to each other, no `xfer-a` channel left. Both A1 and A2 terminated `remote_bye` after Asterisk's ~46-60s deferred BYE; A2 emitted no `transfer` event (confirmed via `call_events`). |
| 2026-09-27 | 1c0fdb3 | 20.6.0~dfsg+~cs6.13.40431414-2build5 | 3 (retry after rejection) | PASS | same pcap | A3→710. First attempt to nonexistent `799`: `accepted:true,202` (shape b). Wire timing (pcap, REFER CSeq 5 at t=424.2927): 202 at t=424.2935 (+0.78ms), a provisional NOTIFY (CSeq 19330, sipfrag 100) at t=424.2938 (+1.08ms), the final NOTIFY (CSeq 19331, sipfrag 404, `Subscription-State: terminated`) at t=424.2941 (+1.38ms) — `success:false,status_code:404,reason:"Not Found"`; call stayed `answered`. (`call_events`' own `at_ms` field, which is elapsed-since-dial and includes this operator's own tool-call latency between steps, is not a protocol timing measure — the pcap figures above are the real REFER→outcome gap, per Rule 21: capture wins over any other clock.) Retry to `700` on the same call (REFER CSeq 6 at t=456.0477): 202 at +2.8ms, both NOTIFYs at +5.4ms, `success:true,status_code:200`, then `remote_bye` after the usual ~60s defer. **D13 retry rule confirmed against a real peer.** Neither attempt's NOTIFY carried an `id=` parameter on `Event: refer` (checked both the rejected first attempt and the successful retry) — Asterisk 20.6/pjproject 2.14.1 never sends `id`, answering the plan's own open question. The retry worked because the first attempt's final NOTIFY correctly carried `Subscription-State: terminated`, so D13's `referSubMaybeLive` flag was never set. |

## 6. Known interop findings (2026-09-27 investigation)

- **Extension 700's dialplan shape controls NOTIFY timing, not our code.** `res_pjsip_refer`'s progress framehook (Asterisk 20.6.0 / pjproject 2.14.1, `res_pjsip_refer.c`) only fires a NOTIFY when the transferee target writes an ANSWER control frame, a voice frame, or joins a bridge. A target that is already `Up` (like the `Local/party-b` channel here) and runs a bare `Answer()`+`Echo()` produces none of those — Asterisk then sends **no NOTIFY at all** until the implicit refer subscription's own `PJSIP_XFER_EXPIRES` (600s) hard-expires, confirmed with a two-sided packet capture. Fixed by adding `Playback(beep)` before `Echo()` in extension 700, confirmed via 3 repetitions above (~40ms to success every time). Any dialplan target used for future interop testing needs to produce a voice/answer frame or join a bridge promptly, or it will hit this same 600s stall — this is a property of the *test rig's dialplan*, not of `sipclient-mcp`.
- **Asterisk defers the transferor-leg BYE by a flat 60 seconds after every successful transfer**, independent of NOTIFY timing (`ast_sip_session_defer_termination`, `res_pjsip_session.c`) — confirmed exactly (60.001-60.002s) across all 3 Scenario 1 repetitions. Since this feature's spec (§4.5) deliberately never sends BYE itself, every Asterisk-mediated transfer will hold the transferor's call for ~60s unless the agent proactively calls `call_hangup` (which D17 already supports as meaningful post-success). Anyone running or extending this rig should budget `call_wait(until="terminated", ...)` timeouts well past 60s, not the ~10s a first guess might use.
- **Asterisk (this version) never puts an `id` parameter on a refer-event NOTIFY's `Event` header**, for either a dialog's first REFER or a later one — confirmed in Scenario 3's pcap for both the rejected first attempt and the successful retry. D13's sticky `referSubMaybeLive` flag (not a first-REFER-only rule) is what makes retries still correlate correctly against a real notifier that behaves this way.
- **Genuine failure cases are fast**, bounded only by the dialplan's own explicit timing, not by any hidden Asterisk delay: a nonexistent target reports failure in ~1.4ms on the wire (see Scenario 3's row above). During the investigation, temporary (non-committed) dialplan targets that rang unanswered or returned busy also reported failure exactly at their own `Wait()` duration (20s and 5s respectively) — no hidden Asterisk-side delay in either case. Those extensions aren't part of this checked-in rig; add them again under a new extension number if a future task wants to exercise those paths as part of the checked-in Scenario 3.
- A stray `session_reaper`-driven UA teardown (5-minute session TTL, `internal/session/registry.go`) was initially mistaken for a code bug during investigation — `call_dial`/`call_transfer` do not renew a session's TTL, only `ua_create`/`session_keepalive` do. Anyone driving this rig interactively for more than a few minutes between tool calls should call `session_keepalive` periodically.
