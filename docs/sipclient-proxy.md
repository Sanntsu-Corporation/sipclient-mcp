# sipclient-proxy

## What it is

`sipclient-mcp` is driven by an AI agent, and creating a SIP user agent
normally means putting the account's `auth_pass` into a tool call, so the model
(and the transcript) sees the password. `sipclient-proxy` is a small local MCP
server (stdio) that sits between your MCP client and the sipclient-mcp daemon.
You keep your SIP accounts, with their passwords, in a file on your own machine;
the model refers to an account only by its name.

The guarantee: the model calls `ua_create {"account":"name"}`, the proxy fills
in the credential fields locally and forwards the call, and the password is
never shown to the model, in results, errors, logs or progress messages (see
"Behaviour notes" for the exact, stated limits of the redaction). Every other
tool is forwarded to the daemon unchanged. There is no network listener and no
change to the daemon.

## Install

1. Download `sipclient-proxy_<VERSION>_darwin_arm64.zip` (macOS, Apple silicon)
   or `sipclient-proxy_<VERSION>_windows_amd64.zip` (Windows, x86-64), together
   with `SHA256SUMS`.
2. Verify: `sha256sum -c SHA256SUMS` (Linux, Windows with a coreutils shell) or
   `shasum -a 256 -c SHA256SUMS` (macOS).
3. Unzip and place the `sipclient-proxy` binary (`sipclient-proxy.exe` on
   Windows) somewhere stable, for example `~/bin`.

macOS: if the zip was downloaded with a browser, remove the quarantine flag with
`xattr -d com.apple.quarantine <binary>`. The Go linker embeds an ad-hoc code
signature in the binary; whether your macOS accepts it (Gatekeeper, `codesign
-v`) is unverified.

Windows: signing the executable with the organisation CA (`osslsigncode`)
happens outside this repository.

## Configure

```
sipclient-proxy configure --upstream https://host:8100/mcp --token-file <file>
```

`--allow-insecure-http` writes `"allow_insecure_http": true` when it creates the
file for a non-loopback `http://` upstream (see the `upstream` rule below); for
an `https://` or loopback upstream it is ignored and says so.

Prefer `--token-file` or `--token-stdin` over `--token`: the latter is visible in
the process list and in shell history. The token is never prompted for.

What `configure` changes:

- It writes the credentials file (mode 0600) at the default path below. An
  existing credentials file is never modified.
- It registers `sipclient-proxy` at user scope in Claude Code and in
  `~/.codex/config.toml`, each through that client's own CLI.
- It prints a Claude Desktop snippet for you to paste; it does not edit
  Desktop's config.
- `--remove` undoes the client registrations and leaves the credentials file.

Backups: before it changes a client's config, `configure` copies it to
`*.sipclient-proxy.bak-<timestamp>` (mode 0600, created exclusively so a symlink
at that name is never followed; the copy holds every other token that config
contains). The snapshot is taken only when two reads agree and, for
`~/.claude.json`, the content parses as JSON: a half-written file is refused
with an error that names the previous backup, and nothing is changed. A new copy
is written only when the file differs from the existing one, and this tool's
older copies are deleted only after the client command has succeeded, so at most
one exists per client config once a run finishes, and a failed run leaves the
previous one in place. Claude Code rewrites `~/.claude.json` continuously, so in
practice each successful run replaces the previous copy. The path is printed on
every run together with "delete it when it is no longer needed": delete it once
you have checked the result.

If a step fails, `configure` prints the exact command to run by hand. Windows
`.cmd` shims are handled (through `%SystemRoot%\System32\cmd.exe`, never through
`PATH`) but this is UNVERIFIED on a real Windows machine.

## Config file

Default path: `~/.config/sipclient-proxy/sipclient-proxy.json` (macOS),
`%APPDATA%\sipclient-proxy\sipclient-proxy.json` (Windows); override with
`--config`.

```json
{
  "upstream": "https://host:8100/mcp",
  "token": "<daemon bearer token>",
  "accounts": {
    "sbc-lab":   { "mode": "register", "sipserver": "10.1.2.3", "port": 5060,
                   "transport": "udp", "username": "1001", "password": "<password>" },
    "carrier-x": { "mode": "direct", "transport": "tls",
                   "username": "acme", "password": "<password>",
                   "auth_any_host": true }
  }
}
```

- `mode`: `register` or `direct` (required). `username` and `password` are
  required. `sipserver` is required for `register`, optional for `direct`.
- `auth_any_host` is an optional boolean, default `false`. The daemon answers a
  digest challenge only from the account's registrar or AOR host; a `register` account
  is answered from its `sipserver` without it, but a `direct` account has no
  registrar or AOR to match, so a `direct` account with credentials needs
  `"auth_any_host": true` to authenticate at all (see the trust boundary below).
  A wrong type makes that one entry invalid.
- `port` is optional: 5060 for udp and tcp, 5061 for tls. `transport` is
  optional: `udp` (default), `tcp` or `tls`.
- `sipserver` is a host name or IP only (IPv6 with or without brackets; put the
  port in `port`; no zone ids, no non-ASCII names). Accounts always dial
  `host:port`: SRV/NAPTR is not used.
- Unknown keys are rejected. At the top level the proxy will not start; inside
  one account, that account is reported and unusable while the others keep
  working. A bad account is listed under `invalid` by `account_list`.
- The accounts are re-read on every lookup. An editor that truncates the file
  while the proxy reads it can make that one call fail with a load error the
  model can see; the next call works. `configure` and the proxy's own writes are
  atomic.
- `upstream` must be `https://` unless the host is `localhost`, `127.x.x.x` or
  `::1` (a trailing-dot host such as `localhost.` is not treated as loopback and
  needs `https://`). It must not contain credentials and is never redirected: a
  redirect from the daemon is an error, so configure the final URL.
  Exception: with `"allow_insecure_http": true` a non-loopback `http://`
  upstream is accepted. The daemon token and every tool call, including the SIP
  passwords the proxy injects, then cross the network in cleartext, and the
  proxy warns at every start (on stderr, which some MCP clients hide). For an
  opted-in upstream prefer an IP literal or a hosts-file entry over a host name,
  so a spoofed name answer cannot redirect the token.
- Use passwords of at least 8 characters (see the redaction limits below).

Trust boundary: the file and the directory that holds it must be writable only
by you. The proxy follows symlinks and does not check ownership, and anyone who
can replace the file can point `upstream` at a server they run and receive the
daemon token. The proxy warns about a group- or world-accessible file on POSIX;
it cannot check a Windows ACL.

## Using it from an agent

- `account_list` returns the configured account names with mode, server, port,
  transport and username, and lists unusable entries under `invalid`. It never
  returns passwords (a password equal to a listed value, such as the username,
  is shown as `[redacted]`). An upstream tool named `account_list` is ignored: the name
  belongs to the proxy.
- `ua_create {"account":"name"}` creates the UA from the named account. Optional
  non-credential fields may be added alongside it.
- Conflict rule: any of `mode`, `transport`, `registrar`, `aor`, `auth_user`,
  `auth_pass` or `auth_any_host`, even empty or null, combined with `account` is refused locally and
  nothing is sent upstream.
- An unknown account name returns an error listing the valid names.
- No password is ever shown to the model.

## What is forwarded

The proxy forwards `tools/list` (and `tools/list_changed`, re-mirroring the tools
and re-applying the `ua_create` rewrite), `tools/call` with its `_meta`, progress
notifications, log messages and `logging/setLevel`, request cancellation and the
initialize `instructions`. Everything passes through a typed SDK hop.

- Round-trips: name, title, description, annotations, icons, `_meta`, and
  schemas including unknown keywords.
- Does not round-trip: fields the SDK's types do not model, structured numbers
  beyond 2^53, and server-initiated requests (the daemon offers no prompts,
  resources, sampling or elicitation, and the proxy bridges none of them).
- Progress and log notifications travel separately from a call's final result,
  so their order relative to it is unspecified; a late one is harmless. A call
  already running when the tool list changes finishes normally.
- The proxy keeps one long-lived event stream to the daemon to hear about
  tool-list changes. It re-establishes the stream silently when an intermediary
  ends it (the daemon itself sends no events today; a stream that a server ends
  immediately without a `retry:` field is re-polled every 1-2 seconds for as
  long as the proxy runs). It treats the session as lost only when a call fails,
  the daemon says the session is gone, or a reconnect of the stream is answered
  with an HTTP error status such as a 502 from an intermediary.
- While the daemon is unreachable the proxy itself retries the stream connection
  in the background, one attempt about every 15-30 seconds, until the daemon is
  back or the proxy exits: it neither gives up nor crashes. (The MCP SDK's own
  reconnect backoff overflows after 57 consecutive failed attempts and would
  panic after about 40 minutes of outage, so the proxy handles those retries
  itself.) The cost is one open connection.

## When things go wrong

### When the daemon goes away

The proxy connects to the daemon at start and keeps that session while it
works. The start itself is limited to 30 seconds: an upstream that accepts the
connection and never answers makes the proxy exit with an error naming the URL.

If the session expires (idle sessions do: call `session_keepalive` to keep one
alive) or the daemon restarts, the daemon answers that the session no longer
exists. The proxy then opens a new session, with the same URL and token, and
sends the call once more (since 2026-10-08, CF-206; until then it never
reconnected). Concurrent calls share one new session. A daemon session owns the
UAs created in it, so the UAs (and their calls) of the old session are gone and
must be recreated; a call that fails on the new session says so in its error,
and the re-open is logged as a warning on stderr. A call is sent again only when
the daemon cannot have run it: the daemon answered that call's own request with
HTTP 404 (session not found), or the request was never sent because the session
had already failed or been closed. It is never sent a third time. A call the
daemon had already accepted when the session failed (for example a `call_wait`
in progress when another call found the session gone) is NOT sent again, since
it may have run: it returns the "upstream session lost" error, and the next call
opens the new session.

If no new session can be opened (the daemon is down, the network dropped, or
the daemon's token was rotated or is rejected), every forwarded tool call
answers at once with an error that starts "upstream session lost". The next
call tries again, at most once a second (an attempt the caller gave up on
counts). Against a daemon that accepts connections but never answers, each
attempt is cut off by the 30-second start limit, and no new attempt starts
until the abandoned one has been closed (its closing request is limited like
the one at shutdown). A log-level change (`logging/setLevel`), and passing your
level on to a new session, waits at most the 30-second start limit, plus the
3-second closing limit for the cancellation the MCP SDK then sends; a change
still waiting at that limit fails with an error. `account_list` and the proxy's own
refusals (an unknown account, `account` combined with a credential field) still
answer locally. After a token rotation edit `token` in the config file and
restart your MCP client (or the sipclient-proxy server entry). No password or
token appears in that message.

`upstream` and `token` are read once at start; a re-opened session uses the same
ones. If you rotate the daemon's bearer token (`admin_token_rotate`), edit `token`
in the file and restart the client. Only `accounts` are re-read, on every lookup, so account edits apply
at once.

If the tool list changes upstream while you work, the proxy re-mirrors it and your
client is notified (`tools/list_changed`).

## Behaviour notes

- Session keepalive is unchanged: the proxy does not keep the daemon session
  alive by itself.
- Credentials are stored in plaintext at rest, in the config file. The Windows
  ACL is not checked.
- Redaction is defence in depth with a precise, stated guarantee. A secret (the
  bearer token or a password) of 8 or more characters is removed
  unconditionally, wherever it occurs, from every result, error, log and progress
  message, from the tool definitions the daemon lists and from its initialize
  instructions, in every textual spelling: raw, JSON-escaped, URL-encoded (upper-,
  lower- or mixed-case hex), base64 (standard and URL alphabets, with and without
  padding) and the base64 of `username:password`. A result in which such a secret
  is split across adjacent text blocks or across structured string values is
  withheld entirely (structured values are read in sorted-key order, so a split
  across two values of one JSON object in the other order is not detected).
- Content blocks other than text (image, audio, resource link, embedded
  resource) are not rewritten: if one carries a secret in any field, its `_meta`
  or annotations, or its binary data, the whole result is withheld, and so is a
  result with a content block of any other type. A text block's annotations are
  checked the same way.
- A secret of fewer than 8 characters is removed when it stands alone (between
  spaces, quotes, brackets or commas, or as a whole JSON string value) but is NOT
  redacted when it is glued to other text, for example `pw=1001&x` or `1001.`,
  because redacting it there would corrupt legitimate output (SIP URIs, handles,
  timestamps, numbers), and a 1-2 character password can blank an unrelated
  standalone word. The proxy does not refuse or warn about short passwords, so
  use passwords of at least 8 characters if the guarantee matters to you.
- Base64 inside a longer blob, and irreversible transforms such as a SIP digest
  response, are not recognised (see the trust boundary below for what a digest
  still reveals). The daemon does not echo passwords today; this is a safety net.
  Replacing a password with `[redacted]` is not an oracle-proof scheme: a model
  that can make the daemon echo text back (for example a `call_dial` `to_uri` such
  as `sip:<guess>@host`) sees `[redacted]` exactly when the guess is a password in
  the file, used or not. Not naming the requested account in the unknown-account
  error closes that one echo, not the class; long random passwords are what keep
  a guess out of reach.
- Further accepted limits of the redaction (none reachable by today's daemon
  output):
  - JSON numbers in `structuredContent`, `_meta` and log data are never
    scrubbed, so a long all-digit password that appeared as a number would pass.
  - A panic value is not scrubbed, and an error the proxy rewrites drops its
    chain, so a secret carried only in a panic value or an inner error would not
    be caught (returned error text itself is scrubbed).
  - The process-wide scrub set only grows: every password the file has held, with
    its encoded forms, stays scrubbed for the proxy's lifetime (a restart resets
    it), which is the safe direction but keeps a retired password's spellings
    blanked.
- Trust boundary: the proxy keeps passwords out of the model's view. The model
  still chooses `call_dial`'s `to_uri`, so the daemon guards where a digest
  response can go: it answers a 401/407 on an INVITE only when the target host is
  the account's registrar host (`sipserver`, `register` accounts) or AOR host,
  unless the account's entry sets `auth_any_host`. Otherwise the challenge is not
  answered, no digest is computed, and the call fails with the peer's 401/407 and
  the reason `credentials withheld: <host> is not this account's registrar or AOR
  host (ua_create auth_any_host allows it)`. Ways out: dial through the registrar
  host, or set `"auth_any_host": true` in that account's entry (all hosts, that
  account only).
  - This guarantee (the model cannot make the daemon send an account's digest to
    a host outside its registrar or AOR host) holds for calls made through a
    named account, where the proxy owns `aor`, `registrar` and `auth_any_host`: a
    model-supplied `auth_any_host` next to `account` is refused locally. A caller
    talking to the daemon directly supplies its own `aor` and `auth_any_host` and
    already holds the password, so the daemon honours both as given.
  - Ports are ignored: every port on the registrar or AOR host is inside the
    boundary. Accepted: the threat is a third-party host receiving a
    password-derived digest, and another port on the account's own host is the
    same operator's machine.
  - The name match is followed by an address pin (CF-054). On the first
    challenge that needs it, the daemon resolves the anchor host (A/AAAA; an IP
    literal is pinned to itself, no DNS) and pins every address it got for that
    UA's lifetime. It then answers only a challenge whose real source address is
    one of the pinned ones (ports ignored) AND only when the INVITE itself went
    to a pinned address (a UDP challenge's source can be forged, and the digest
    goes to the INVITE's destination: `credentials withheld: the INVITE was sent
    to <IP>, not a pinned address of <host> (...)`). A challenge from another address (a
    multi-homed or anycast server, a NAT rewriting the reply source) is withheld
    with `credentials withheld: the challenge came from <source IP>, not a pinned
    address of <host> (ua_create auth_any_host allows it)`; an anchor that cannot
    be resolved is withheld with `credentials withheld: <host> could not be
    resolved to pin the challenge source (...)` and the failure is not cached.
    Consequences: DNS is trusted at the moment of the first challenge, a later DNS
    change is not followed until the UA is recreated (`ua_destroy` + `ua_create`
    re-pins), and an anchor with only SRV records (no A/AAAA) now fails closed.
    `auth_any_host: true` is the workaround for a refused challenge and disables
    the WHOLE destination guard (name check and pin) for that UA: a stated
    security trade-off.
  - Not closed: the guard covers only the next hop. If the registrar is a
    forwarding proxy that relays a downstream 401 (rather than terminating the
    call itself, as Asterisk and VOS do), the relayed challenge still arrives from
    the registrar's own, pinned address, so a dial to `sip:<extension>@<registrar>`
    can have that downstream challenge answered.
    Answering only a 407 from the anchor was considered and rejected: Asterisk,
    the main interop target, challenges an INVITE with 401, so that option would
    refuse every challenge it sends (`e2e/asterisk/scenarios/echo-pcma.xml`
    expects `<recv response="401" auth="true"/>` for an INVITE; the rig's
    endpoints are digest-challenged per request, `e2e/asterisk/README.md`).
  - A `direct` account carries no registrar or AOR, so it has no anchor; the
    proxy does not infer one. A `direct` account with credentials answers no
    challenge until its entry sets `"auth_any_host": true` (with it, every host
    receives a digest response, so keep `destinations.allow` in place).
  - Unchanged adjacent paths: a `Route` header from the model is refused by
    `call_dial`, a 3xx is never followed by the daemon, a REFER's dialling is done
    by the peer, and the REGISTER digest exchange only ever talks to the
    registrar and is not affected.
  - A digest response still lets whoever issued a challenge guess a weak password
    offline. When real accounts are configured, have the daemon operator set the
    daemon's `destinations.allow` policy (admin-scoped `config_set`) to the
    destinations those accounts are meant to reach; it remains a second layer.
  - Rollback and migration. Rolling the proxy back to a build without this field
    makes an entry that carries `auth_any_host` invalid (`json: unknown field
    "auth_any_host"`, listed under `invalid`) while the file still loads and the
    other entries keep working; remove the key to use that entry with an older
    proxy. A new proxy in front of an older daemon forwards `auth_any_host` only
    for an account whose entry enables it, so only such accounts are affected: the
    older daemon's `ua_create` schema is expected to reject the field. Upgrade the
    daemon first or together. After upgrading the daemon, an existing `direct`
    entry with credentials, and an inline direct-daemon UA whose `aor` host
    differs from the hosts it dials, must add `"auth_any_host": true` (inline: a
    matching `aor`) or its calls fail 401/407 with the reason above.
- The set of secrets to scrub lives for the lifetime of the process: the token
  plus every password the config file has held since start, used or not (valid
  and invalid entries, including a numeric password of an invalid entry), plus
  each valid account's base64 `username:password` pair. The file is re-read on
  every forwarded call, so an account added while the proxy runs is covered at
  once. The set only grows, so it is bounded by the number of distinct passwords
  the file has held, and it is never written anywhere. An unknown-account error
  does not echo the requested name.
- The bearer token is only ever sent to the configured origin; a redirect is never
  followed.
- ChatGPT desktop via the Codex config is to be verified on real machines;
  ChatGPT web is unsupported.
- The live test picks a free loopback port for its throwaway daemon. Its rig
  registrations are destroyed by the test but, if the run is interrupted, simply
  expire on the rig.

## Build

```
make proxy-dist
```

writes `dist/proxy/sipclient-proxy_<VERSION>_darwin_arm64.zip`,
`..._windows_amd64.zip` and `dist/proxy/SHA256SUMS`. It needs `python3` (stdlib
`zipfile`) and `sha256sum`. In a git worktree run it as
`GOFLAGS=-buildvcs=false make proxy-dist`. Signing (Windows `osslsigncode`, macOS
notarisation) is done outside the repository; `darwin/amd64` is built on request
only.

The live gate needs the Asterisk rig in `e2e/asterisk/` and starts its own
throwaway daemon:

```
SIPPROXY_LIVE=1 go test -tags live -run TestLiveRig -count=1 -v ./cmd/sipclient-proxy/
```
