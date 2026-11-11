---
name: sipclient-mcp
description: "(BETA) Exercise the sipclient-mcp SIP client MCP server for dev testing — driving its ua_create/call_dial/call_transfer/dtmf_send/media_* tools. Use when asked to test, drive, or debug SIP calls, call transfer, DTMF, media record/playback or pcap capture through the sipclient-mcp server. The daemon itself is managed outside this skill — if it's not connected, report that rather than trying to start it."
---

# sipclient-mcp (BETA)

**This skill is BETA.** It wraps a development build of the `sipclient-mcp`
SIP client daemon (this repository), reachable over HTTP. It has not been used across many sessions yet — verify
tool output against `call_status`/`call_events` rather than assuming
success, and report anything that looks wrong rather than silently working
around it.

## What this is

`sipclient-mcp` is an MCP server that drives a real SIP UAC/UAS stack: create
user agents, dial/answer/hangup calls, transfer answered calls (blind or
attended), send/receive DTMF, play/record media, capture per-call pcaps, and
read voice-quality metrics. This skill is agent-agnostic: it applies to
whichever MCP client you're using (Claude Code, Codex, or another) once the
server is registered under the name **`sipclient-mcp`** (HTTP transport,
`http://127.0.0.1:8100/mcp`, or whatever address the daemon was started with via `--listen` — see `docs/setup-mcp-and-skill.en.md` in
this repo for exact registration commands per client), or under
`sipclient-proxy` (a local stdio proxy in front of the same daemon; see
'Using a named account' below). Check your client's
connected-servers list — e.g. `claude mcp list` for Claude Code, `codex mcp
list` for Codex — to confirm it shows connected before using its tools. The
daemon itself is managed by you, not by this skill, so
if it's not connected, treat that as a blocker to report, not something to
start, stop, or restart yourself.

## Concepts: session, UA, and call

Three different things get called "session"-adjacent in this document and
are easy to conflate:

- **Session** — one MCP protocol session, identified by `Mcp-Session-Id`,
  created by a single `initialize` call and bound to whichever token
  (bearer or admin) that `initialize` call used. **Your registered MCP
  connection opens exactly one session for its whole lifetime** — every
  tool call you make on it goes through that same session, no matter how
  many calls you make (the exact tool name your client shows you varies —
  Claude Code prefixes them as `mcp__sipclient-mcp__<tool>`; other clients
  may not). `ua_create` never
  creates a session; it only acts on whichever session/token the request
  already carries. A session holding at least one live UA expires after
  `limits.session_ttl` (policy-configurable, default 5 minutes) unless
  `session_keepalive` resets it, and `ua_destroy` tears down and deletes
  only its own UA handle — the session and any sibling UAs are untouched.
- **UA (user agent)** — a SIP client identity, created by `ua_create`. A
  session can hold up to `max_uas_per_session` (default 8,
  policy-configurable) independent UAs, each with its own
  account/registrar/transport. `ua_create`'s response `ua_handle` is what
  every later UA-scoped tool call (`ua_status`, `ua_destroy`) and the `ua`
  field on `call_dial` use to address a specific one; call-scoped tools
  (`call_answer`, `dtmf_send`, `media_play`, etc.) need no UA parameter at
  all because `call_handle` already identifies the right one.
- **Call** — one SIP dialog on a UA, created by `call_dial` (outbound) or
  answered/rejected inbound via `call_answer`/`call_reject`. One UA can
  hold several concurrent calls (`max_concurrent_calls_per_session`,
  currently 50).

So the chain is: **one MCP connection → one session → up to
`max_uas_per_session` UAs → each UA's several calls.** Your registered
connection only ever gives you the one session; calling
`ua_create` again on it is how you get a second (or third, up to the cap)
UA for a two-party test, all sharing that same session. Using the
admin-scoped tools (which need a session bound to the admin token, not
the bearer one) still means opening an *additional* raw MCP session over
`curl`, not swapping the `Authorization` header mid-session.

## Tool catalog

| Tool | Purpose |
|---|---|
| `ua_create` | Create a UA with **inline account fields** (`account` (only when the sipclient-proxy is the connected server), `aor`, `auth_user`, `auth_pass`, `registrar`, `transport`, `expires_s`, `dtmf_mode`, `session_expires_s`, `min_se_s`, `keepalive_interval_s`, `session_refresh_method`, `keepalive`, `srtp`, `auth_any_host`, `allow_cleartext_sdes`) — there is no `profile` name lookup any more (`profile_list` was removed, not deferred). `mode: "direct"` needs no registrar — use this for local loopback testing. `mode: "register"` needs `aor` and `registrar`. A session can hold up to `max_uas_per_session` UAs (default 8, policy-configurable); credentials are accepted inline in the request/response, deliberately, for this local dev daemon. Response includes `session_cookie`/`expires_at` — see the session TTL note below. **SRTP (CF-134):** `srtp` is `disabled` (default), `optional` or `required`; any other value is `invalid_argument`. SDES sends the SRTP key in the SDP body, so `optional`/`required` on `transport: "udp"` or `"tcp"` (the default is `udp`) is refused with `invalid_argument` ("needs transport \"tls\" ... set allow_cleartext_sdes"); use `transport: "tls"`, or set `allow_cleartext_sdes: true` (bool, default false; that UA only; logs a WARN) to test SRTP over plaintext signalling on purpose. Telephone events (DTMF) are integrity-protected only with `srtp: "required"` over TLS. **Digest destination guard (CF-046):** the daemon answers an INVITE's 401/407 digest challenge only when the `call_dial` target host is the UA's registrar host (register mode) or its `aor` host (ports ignored), and only when the challenge comes from an address that host resolved to, **pinned per UA** at the first challenge (an IP-literal host is pinned to itself; a DNS change is not followed until `ua_destroy` + `ua_create`; an SRV-only host fails closed); otherwise the challenge is NOT answered, the password is never used, and the call fails with the real 401/407 and `last_response` = `credentials withheld: <host> is not this account's registrar or AOR host (ua_create auth_any_host allows it)`; the pin adds `credentials withheld: the challenge came from <IP>, not a pinned address of <host> (...)`, `credentials withheld: the INVITE was sent to <IP>, not a pinned address of <host> (...)` and `credentials withheld: <host> could not be resolved to pin the challenge source (...)`. Fix: dial through the registrar host, or create the UA with `auth_any_host: true` (bool, default false; disables the WHOLE guard, name check and pin, for that UA only: a security trade-off). A `direct` UA with credentials and no matching `aor` needs it. With sipclient-proxy, prefer `account`; see 'Using a named account'. A `sips:` registrar on a `udp`/`tcp` UA is refused with `invalid_argument` (use `transport: "tls"`). |
| `session_keepalive` | Reset the session's TTL (`limits.session_ttl`, policy-configurable, default 5 minutes); call this before roughly half the TTL elapses or the session (and its live UAs) is torn down and deleted. An EMPTY session (every UA already destroyed) is not deleted immediately — it survives for `limits.session_resume_window` instead. Returns the same `session_cookie`/`expires_at` shape as `ua_create`. |
| `ua_status` / `ua_destroy` | Inspect / tear down a UA. `ua_destroy` tears down **only its own UA handle** — the session and any sibling UAs it still holds are untouched; a subsequent tool call on the destroyed handle 404s, but the session itself and other UAs on it keep working. |
| `call_dial` / `call_answer` / `call_reject` / `call_hangup` | Call control. `call_hangup` on a ringing outbound call sends a CANCEL; on a ringing **inbound** call it declines with 603. A `call_hangup` that lands while `call_answer` is writing its 200 is no longer refused: it is recorded and returns once the answer settles (up to 2 s, then it still returns success); the answered call is then ended with one BYE, or declined 603 if the 200 could not be written. `call_answer` in that race returns success without `codec`, and blocks while the BYE transaction runs. `call_answer` on an INVITE without SDP succeeds without `codec`; the codec and media appear in `call_status` once the caller's ACK carries the answer, and a missing or unusable answer ends the call (`terminated`, `termination_reason` `media_negotiation_failed`). |
| `call_transfer` | Transfer an **answered** call via SIP REFER. `call` is the transferee's dialog. `mode: "blind"` needs `target` (a `sip:`/`sips:` URI). `mode: "attended"` needs `consult_call` (a second, answered call **on the same UA**) — the transferee is replaced into that call's dialog (RFC 3891 `Replaces`). Returns immediately with the REFER's own response, not the transfer's outcome — the outcome arrives later as a `"transfer"` event (see below). Never hangs up either call itself; `call_hangup` on the transferred call is refused with `precondition_failed` while the REFER is pending. |
| `call_status` / `call_list` / `call_events` / `call_wait` | Call inspection; `call_wait` is the only blocking tool. `call_wait` takes an optional `since` (fixed 2026-09-27): pass the `seq` from a prior `call_wait`/`call_events` response to wait for the NEXT new matching event, rather than re-matching the first one ever logged. `since` defaults to 0 (today's behavior: match from the start of the log) when omitted. |
| `call_ladder` | Render a call's SIP ladder (text/mermaid/json). |
| `dtmf_send` / `dtmf_received` | Send/drain DTMF (rfc2833/inband/info). |
| `media_play` / `media_record_start` / `media_record_stop` | Play a policy-registered prompt / record received audio to WAV. |
| `capture_start` / `capture_stop` | Arm/finalize a per-call pcap. |
| `quality_get` | Tier-1 passive voice-quality metrics + MOS estimate. |
| `config_get` / `config_set` / `admin_token_rotate` | Admin-scoped (require the **admin** token, not the bearer one — ask the daemon operator for it; they retrieve it via `sipclient-mcpd --print-tokens --state ~/.local/state/sipclient-mcp/state.yaml` on the daemon's own host, never hardcoded). Read/write the daemon's dynamic config (destinations, limits, artifact settings, etc.) without editing a file or restarting. Not needed for ordinary call/UA testing; needs its own admin-token-initialized session, not the registered bearer one — see the session-binding gotcha under Reporting problems below. |

## Using a named account (sipclient-proxy)

If your MCP client shows a server named `sipclient-proxy` (tools appear as
`mcp__sipclient-proxy__<tool>` in Claude Code) it fronts the same daemon and
keeps SIP credentials on the user's machine. In that case:

1. Call `account_list` first. It returns the configured account names with
   mode, server, port, transport and username, and lists unusable entries under
   `invalid`. It never returns passwords.
2. Create the UA with `ua_create {"account": "<name>"}`. Optional non-credential
   fields (`local_addr`, `srtp`, `codec_pref`, `keepalive`, `expires_s`,
   `dtmf_mode`, `session_expires_s`, `min_se_s`, `keepalive_interval_s`,
   `session_refresh_method`) may be added alongside `account`.
3. Never ask the user for a SIP password and never put `auth_pass` in a call
   when a named account exists. Do not combine `account` with `mode`,
   `transport`, `registrar`, `aor`, `auth_user`, `auth_pass` or `auth_any_host`
   (not even empty): the call is refused locally and nothing is sent.
   `auth_any_host` is account-owned like the rest: it is set only from the
   account's entry in `sipclient-proxy.json`. A `register` account answers a
   digest challenge only from its `sipserver` host; a `direct` account has no
   registrar/AOR to match, so it answers a challenge only when its entry sets
   `"auth_any_host": true`, otherwise a challenged `call_dial` fails 401/407
   with the "credentials withheld" reason. This guarantee (the model cannot make
   the daemon send an account's digest to a host outside the account's
   registrar/AOR host) covers named-account calls only: a caller talking to the
   daemon directly supplies its own `aor` and `auth_any_host`, which the daemon
   honours as given.
4. An unknown account name returns an error listing the valid names.
5. If the daemon session expires or the daemon restarts, the proxy opens a new
   session by itself and retries the call once; UAs of the old session are gone
   and must be recreated (a failure after such a re-open says so). If a call
   answers "upstream session lost", the daemon is unreachable or the token was
   rejected: the next call tries again; after a token rotation the user edits
   `token` in the config file and restarts the MCP client.

If there is no `account_list` tool you are connected to the daemon directly:
use the inline fields as described above. Everything else (call_dial,
session_keepalive, ...) is identical either way.

Full parameter tables: `internal/session/input.go` in the repo.

**Session TTL, in short:** a session holding at least one live UA is torn
down and deleted after `limits.session_ttl` (policy-configurable, default 5
minutes) unless `session_keepalive` is called first. An EMPTY session
(every UA already destroyed) is not deleted on that clock — it survives
instead for `limits.session_resume_window`. There is no more "leave it
running and come back later" on the live-UA clock — if a session with a
live UA goes quiet past its TTL, its UAs are gone and their handles 404;
create fresh ones.

## Typical call flow

**Placing an outbound call:**
1. `call_dial` — returns a `call_handle` immediately in state `dialing`.
2. Block on `call_wait` with `until: "answered"` (or `"ringing"` for the
   provisional response first), or poll `call_status`. `call_wait`'s
   `until` only accepts `"any"`, `"ringing"`, `"answered"`, `"media_start"`,
   `"dtmf"`, and `"completed"`/`"terminated"` (each maps to one SIP event) —
   **there is no `"failed"` value**. A rejected dial (4xx–6xx) lands the
   call in state `failed` via an internal error event none of those named
   values catch, so to reliably notice a failed dial either poll
   `call_status`, or use `until: "any"` and check the returned call state
   yourself.
3. Drive the call once `answered` — `dtmf_send`, `media_play`,
   `media_record_start`/`media_record_stop`, `capture_start`/`capture_stop`.
4. `call_hangup` to end it; `ua_destroy` when done with the UA (this only
   tears down that UA — the session and any sibling UAs survive).

**Receiving an inbound call** (on a UA registered against a registrar, or
dialed by another local UA on a separate session — see Concepts above):
1. An inbound call is created already in state `ringing` — there's no
   handle to `call_wait` on before you know it exists, so poll
   `call_status`/`call_list` to notice it.
2. `call_answer` it, or `call_reject` with a chosen status code to decline.
3. Same as the outbound flow from there — drive the call, then `call_hangup`.

`call_ladder` renders either side's SIP ladder (text/mermaid/json) at any
point — useful for seeing what actually went out on the wire when a call
doesn't behave as expected.

**Transferring an answered call:**
1. `call_transfer` — for blind, pass `target`; for attended, first `call_dial`
   a second call on the *same UA* to the consultation party, wait for it to
   reach `answered`, then pass its handle as `consult_call`. The call returned
   by `call_transfer` itself is just the REFER's own (usually 202) response.
2. `call_wait` with `until: "transfer"` **and check `detail.final == true`
   before trusting the result** — the event only resolves once `final` is
   true (fixed 2026-09-27; the predicate used to also match a provisional
   NOTIFY). `detail` carries `mode`, `status_code`, `success`, `reason`,
   `final`. Default wait is up to 120s (300s ceiling) — real Asterisk can take
   this long on a slow-to-answer or unreachable transfer target, it isn't
   necessarily stuck.
3. **Known gap, now with a fix:** if the call has more than one transfer attempt
   (e.g. a retry after an inconclusive first attempt), `call_wait(until="transfer")`
   with `since` omitted (or 0) returns the **first** transfer's outcome, not the
   latest one. Fixed 2026-09-27 (CF-015): pass `since` = the `seq` from the first
   attempt's `call_wait`/`call_events` response to wait for the retry's outcome
   specifically, instead of falling back to a separate `call_events` poll.
4. **Known race:** if the transferee hangs up (BYE) before the transfer's
   final NOTIFY arrives, your `call_wait(until="transfer")` wakes with the
   terminal event instead — check `call_events` in that case rather than
   assuming the wait timed out. (`call_transfer`'s own tool description now
   states this caveat directly, added 2026-09-27 — CF-016.)
5. Neither call is hung up automatically — `call_hangup` each side yourself
   once you're done with it.

## Reporting problems

This skill and the daemon it drives are BETA — log anything that doesn't
match this document to this machine's `sipclient-mcp` issues log (a plain
Markdown table, global to this machine, not this repo). For Claude Code
that's `~/.claude/sipclient-mcp-issues.md`; if your agent keeps notes
somewhere else, use that instead, and still flag the discrepancy to the
daemon operator either way. Append one row per distinct problem — a daemon
crash, a tool error that doesn't match what's documented here, a
wrong/missing field in a tool's response, a readiness/auth failure,
anything you had to work around. Do this in the same turn you hit the
problem, not as an afterthought, and quote the tool's actual `code`/
`message` rather than paraphrasing it. Read that file's own header for the
exact column rules before appending — don't invent a different format.

## Known discrepancies (as of 2026-09-24)

Two small mismatches confirmed live, logged in
`~/.claude/sipclient-mcp-issues.md` (Claude Code's copy of this machine's
issues log) — not blockers, but don't be surprised by them:

- The `max_uas_per_session` cap denial's actual `"code"` is
  `"denied"`, not `"resource_limit"` as several repo comments and the
  2026-09-23 closeout doc claim. If you're branching on the response
  code to detect this specific cap, branch on `"rule":"max_uas_per_session"`
  instead of `"code":"resource_limit"`.
- `config_set`'s response JSON has a duplicate `"ok"` key:
  `{"ok":true,"key":"...","ok":true}`. Harmless (most decoders take the
  last value) but don't be alarmed if you see it.
