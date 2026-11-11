# Vendored sipgo fork

A `replace`-target fork, not a version bump. From here the copy is **owned and
modifiable** and diverges from upstream by twenty-eight production changes: the P2
Wave 2 Task 1 nil-guard (one line), the P2 Wave 2c Task 1 `B2` opt-in
outbound ephemeral local port option (design §6.1, closeout §8; W2c plan
Task 1), the P2 Wave 2c Task 5 capture dial-wrap hook (W2c plan Task 5), the
P2 Wave 3 Task 7 `ServerTransaction.OnCancel` interface method (W3 plan
Task 7), the P3 comma-combined Contact header params fix (one line), the
Phase 4 M1 B7 IPv6-literal `uriStateHost` fix (the sixth), the Phase 4
M1 B1 `parseMsgHeader` receiver-shadow fix (one line, the seventh), and the
Phase 4 W3 P4-W1-N05 stream-parser header-accumulation cap (the eighth), and the CF-050
`actInviteResend` nil-guard (the ninth), and the CF-058 accepted-stream-connection
pooling fix (the tenth), and the N1 stream Via-key destination check (the
eleventh), and the N2 `WriteMsgTo` request dial deadline (the twelfth), and the CF-066
`transportTLS.CreateConnection` handshake-failure close (the thirteenth), and the CF-064
`ConnectionPool.CloseAndDelete` compare-and-delete (the fourteenth), and the CF-069
identity-checked `Delete`/`DeleteMultiple` and repaired `AddIfNotExists` (the
fifteenth), and the CF-064 part 2 dialed-connection key rule with tracking and
promotion (the sixteenth), and the CF-073 `crypto/rand` identifier generators (the
seventeenth), and the CF-069 (a)(d) WSS dial close and per-write stream
write deadline (the eighteenth), and the CF-106 oversize-UDP-request switch to
TCP (the nineteenth), and the CF-096 `OnCancel` veto of `actCancel`'s automatic
487 (the twentieth),
and the CF-168 UDP response size limit (the twenty-first),
and the CF-077 `received`/`rport` Via stamp and sorted RFC 2543 server-transaction key (the twenty-second), and the CF-081 SRV-first resolution (the twenty-third),
and the CF-079 response-on-the-arrival-connection association (the twenty-fourth), and the CF-111 non-INVITE Proceeding retransmission (the twenty-fifth), and the CF-089 non-2xx ACK Request-URI (the twenty-sixth), and the CF-172 `sips:` default transport (the twenty-seventh), and the CF-194 server-transaction lifetime (the twenty-eighth).

## Source

| | |
|---|---|
| Upstream module | `github.com/emiago/sipgo` |
| Upstream version | `v0.24.1` (**unchanged** — this is the same version already pinned in `go.mod`'s `require` block prior to this fork; a `v1.4.3` bump is deliberately **not** taken, design §6.1) |
| Module hash (`h1:`) | `h1:RKy6NqVnvjgpLywo1sa4v+lwfEz5O5/0yk4Z8eek4XM=` |
| `go.mod` hash | `h1:UB0Ao5xk1b1TQisO29jmUDz0mXNINpHBR4YXsLbLXEs=` |
| Obtained via | `go mod download github.com/emiago/sipgo@v0.24.1`, copied from `$(go env GOMODCACHE)/github.com/emiago/sipgo@v0.24.1` (reproducible; no hard-coded developer path) |
| Copy date | `2026-07-21` |
| Upstream `go.mod` floor | `go 1.20` (sipgo's own floor — kept as-is; **not** conflated with `sipclient-mcp`'s `go 1.25.0`, and not raised) |

A reviewer can re-derive the exact source tree by running the same
`go mod download` and comparing the two hashes above against `go.sum`'s
historical entry for `v0.24.1` (removed from this repo's `go.sum` by
`go mod tidy` once the `replace` directive made resolution local — the hashes
are recorded here instead, as the fork's own provenance record).

## Why a fork, not a dependency

`sip/transaction_client_tx_fsm.go`'s `actResend` (client-transaction
retransmit FSM, non-2xx path) calls `tx.timer_a.Reset(tx.timer_a_time)`
unconditionally. When the client transaction terminates mid-retransmit,
`timer_a` is cleared to `nil` elsewhere in the FSM, and a subsequent
`actResend` firing against the already-nil timer panics — a **production**
panic, not a test flake (P2 Wave 1 closeout §8). `actInviteProceeding`
(`sip/transaction_client_tx_fsm.go:242` in upstream, unchanged here) already
guards the equivalent `timer_a` dereference with a nil check; `actResend` did
not. Upstream sipgo has no released fix at the pinned version, so the guard
is applied locally.

## The one production divergence

`sip/transaction_client_tx_fsm.go`, in `actResend`:

```diff
-	tx.timer_a.Reset(tx.timer_a_time)
+	if tx.timer_a != nil {
+		tx.timer_a.Reset(tx.timer_a_time)
+	}
```

Mirrors the existing nil-guard shape already present at `actInviteProceeding`
(`:242`). This was the **only** line that differed from upstream `v0.24.1`
anywhere in this tree until the P2 W2c B2 option below.

## P2 W2c B2: opt-in outbound ephemeral local port

**Purpose:** let a UA that is already listening on `BoundIP:5060` dial an
*outbound* TCP/TLS request without `EADDRINUSE` from trying to rebind its own
listening port as the dial's local port. Upstream always builds the dial's
local address as the Via-derived `IP:Port` (the listening port); when a UA
dials out from the same host/port it is bound to, that collides.

**Design: instance-scoped opt-in, default off (upstream behavior).** The
initial plan considered making this unconditional, on the premise that
`internal/sipua` was the fork's only `sipgo.NewUA` consumer. Cycle B
verification found other first-party consumers —
`internal/sipengine/calltester` (`runner.go:228,242`) and `siptest.NewClient`
(`client.go:19`) — plus sipgo's own test suite construct `TransportLayer`s
directly. An unconditional change would alter dial behavior for all of them,
which the change's own UDP-only regression coverage could not prove safe. So
`B2` is a new `sipgo.WithDialEphemeralLocalPort() UserAgentOption`: **default
off preserves upstream `BoundIP:Port` dialing for every consumer that does
not opt in**; `internal/sipua` opts in (P2 W2c Task 2). This mirrors the
wave's other two instance-scoped options, `WithUserAgenTLSConfig` and
`WithDialConnWrap`.

**The changes:**

- `ua.go`: new `dialEphemeralLocalPort bool` field on `UserAgent`; new
  `WithDialEphemeralLocalPort() UserAgentOption` (mirrors
  `WithUserAgenTLSConfig`'s shape) setting it; threaded as a new 4th
  parameter into the `sip.NewTransportLayer(...)` call in `NewUA`.
- `sip/transport_layer.go`: `NewTransportLayer` gains a
  `dialEphemeralLocalPort bool` parameter, set on both the `tcp` and `tls`
  transport instances it constructs (the `tls` instance's field is the one
  promoted from its embedded `*transportTCP` — see below).
- `sip/transport_tcp.go`: new pure helper `dialLocalAddr(laddr Addr)
  *net.TCPAddr` (keeps the Via IP, forces port 0); new
  `dialEphemeralLocalPort bool` field on `transportTCP`; new
  `(*transportTCP).dialLocalFor(laddr Addr) *net.TCPAddr` method gating the
  choice (default: upstream `IP:Port`; opted-in: `dialLocalAddr`'s `IP:0`).
  `CreateConnection` now builds its `tladdr` via `t.dialLocalFor(laddr)`
  instead of inline upstream construction.
- `sip/transport_tls.go`: `transportTLS.CreateConnection` has its own
  `tladdr` construction (duplicated from `transportTCP`'s, no shared helper
  upstream) — patched independently to call `t.dialLocalFor(laddr)` (the
  promoted method/field from its embedded `*transportTCP`), so TLS dials are
  gated the same way as TCP.
- `sip/transport_test.go`: mechanical call-site fix — the 4 existing
  `NewTransportLayer(net.DefaultResolver, NewParser(), nil)` calls now pass
  the new 4th parameter as `false` (upstream behavior, unaffected by B2).
- `sip/transport_b2_localport_test.go` (new): `TestB2LocalPortIsEphemeral`
  (unit test of `dialLocalAddr`) and `TestB2DialLocalPortGatedByOption`
  (proves both the default=upstream-port and opted-in=`IP:0` paths).

## P2 W2c capture dial-wrap hook

**Purpose:** let a caller observe/tap the plaintext of an *outbound* TCP/TLS
dial, so the daemon's SIP capture (§14.5 pcap rendering, W2c Task 5) can
record both directions of a call, not just inbound. Upstream's dial path
hands the raw dialed conn (post-handshake `*tls.Conn` for TLS) straight to
`initConnection` with no seam for an observer to attach.

**Design: instance-scoped hook, default nil (upstream behavior), mirrors
`B2`'s shape.** Same rationale as `B2` above: `internal/sipengine/calltester`,
`siptest.NewClient`, and sipgo's own test suite construct `TransportLayer`s
directly and must not have their dial path altered. `WithDialConnWrap(wrap
func(net.Conn) net.Conn) UserAgentOption` is new and additive; a consumer
that does not set it keeps the exact upstream dial behavior (nil-check
before invoking). Instance-scoped is **load-bearing, not incidental**: the
daemon runs multiple UAs concurrently, each with its own `TransportLayer`; a
package-level global wrap would let one UA's outbound capture leak into (or
be clobbered by) another's. `dialConnWrap` is a field on `transportTCP`, and
`transportTLS` reaches it via its embedded `*transportTCP` (the same
embedding `dialEphemeralLocalPort`/`dialLocalFor` already use) — each
`newTLSTransport` call constructs its own embedded `transportTCP`, so the TLS
and TCP transports of a given `TransportLayer` (and, in turn, of different
`TransportLayer`s / UAs) never share a `dialConnWrap` instance.

**The changes:**

- `ua.go`: new `dialConnWrap func(net.Conn) net.Conn` field on `UserAgent`;
  new `WithDialConnWrap(func(net.Conn) net.Conn) UserAgentOption` (mirrors
  `WithUserAgenTLSConfig`'s shape) setting it; threaded as a new 5th
  parameter into the `sip.NewTransportLayer(...)` call in `NewUA` (D4: the
  final fork-constructor signature is now `NewTransportLayer(dnsResolver,
  parser, tlsConfig, dialEphemeralLocalPort bool, dialConnWrap func(net.Conn)
  net.Conn)`).
- `sip/transport_layer.go`: `NewTransportLayer` gains a `dialConnWrap
  func(net.Conn) net.Conn` parameter, set on both the `tcp` and `tls`
  transport instances it constructs — same two-instance pattern
  `dialEphemeralLocalPort` already uses, so `dialConnWrap` reaches **both**
  constructors (unlike `tlsConfig`, which only reaches `newTLSTransport`).
- `sip/transport_tcp.go`: new `dialConnWrap func(net.Conn) net.Conn` field on
  `transportTCP`. `createConnection` calls it on the freshly-dialed `conn`
  (only if non-nil) and passes the wrap's return value — not the raw dialed
  conn — into `initConnection`, so the wrapped value is what
  `TCPConnection.Conn` ends up holding.
- `sip/transport_tls.go`: `transportTLS.CreateConnection` calls the
  (inherited, via its embedded `*transportTCP`) `dialConnWrap` on the
  **post-handshake** `tlsConn` — after `HandshakeContext` succeeds, before
  `initConnection` — so a tap observes decrypted plaintext, not
  pre-handshake TCP bytes.
- `sip/transport_test.go`: mechanical call-site fix — the 4 existing
  `NewTransportLayer(net.DefaultResolver, NewParser(), nil, false)` calls now
  pass the new 5th parameter as `nil` (upstream/no-op behavior, unaffected by
  this hook).
- `sip/transport_dialwrap_test.go` (new): `TestDialConnWrapInvokedOnDialedConnBeforeInitConnection`
  (TCP: wrap's return value is what's stored before `initConnection`),
  `TestDialConnWrapInvokedOnPostHandshakeTLSConn` (TLS: wrap observes the
  post-handshake `*tls.Conn`), and `TestDialConnWrapTwoInstancesDoNotInterfere`
  (two independent `transportTCP` instances with distinct wraps and distinct
  call counters never observe each other's wrap — the multi-UA-safety
  property).

## P2 W3: `ServerTransaction.OnCancel` interface method

**Purpose:** let `internal/sipua`'s `onInvite` register a per-transaction CANCEL
hook (P2 W3 plan Task 7 — the CANCEL-during-admission bookkeeping fix) through
the `sip.ServerTransaction` interface it already holds, instead of a
concrete-type assertion `tx.(*sip.ServerTx)` reaching past that interface.

**Design: additive interface method, non-breaking.**
`(*ServerTx).OnCancel(f func(r *Request))` already exists
(`sip/transaction_server_tx.go:182`); this change only promotes it onto the
`ServerTransaction` interface. `*ServerTx` is the interface's sole implementer
in this tree — `siptest.ServerTxRecorder` embeds `*sip.ServerTx` and inherits
the method for free — so adding it breaks no implementer. This mirrors the
additive shape of the `WithDialEphemeralLocalPort`/`WithDialConnWrap`
divergences above: a consumer that never calls it is unaffected.

**The changes:**

- `sip/transaction.go`: the `ServerTransaction` interface gains
  `OnCancel(f func(r *Request))`, below `Acks()`. `*ServerTx` already
  satisfies it, `ServerTxRecorder` inherits it.
- `sip/transaction_server_tx.go` (Rule 13 Cycle 3 fix, commit `6593687`):
  `(*ServerTx).OnCancel`'s write of `tx.onCancel` now locks `tx.fsmMu`
  (was `tx.mu`) — matching `actCancel`'s (`sip/transaction_server_tx_fsm.go`,
  inside `spinFsm`) existing read of the same field under `tx.fsmMu`, per the
  sibling `fsmCancel`/`fsmResp` convention that these fields "must be
  protected with fsm Lock".

Amended by CF-096 (below): the hook's signature is now
`OnCancel(f func(r *Request) bool)`, and a hook returning false vetoes the 487.

## P3: comma-combined Contact headers carried the wrong params

**The defect.** RFC 3261 §7.3.1 lets a sender fold several same-name header
rows into one comma-separated line, and Kamailio/OpenSIPS-class registrars
build their REGISTER `200 OK` that way. `sip/parse_address.go`'s
`parseContactHeader` handles that line by parsing one section, returning
`errComaDetected(idx)`, and letting `parseHeaderLine`
(`sip/parse_header.go:96-115`) re-enter on `fieldText[idx+1:]` — so the split
itself is correct and each `*ContactHeader` gets the **right address**. But on
the comma branch it breaks out of its scan with `endInd` still at
`len(headerText)`, so the `ParseAddressValue(headerText[:endInd], ...)` call
below reads the header params from the **whole line** rather than from this
section. `HeaderParams.Add` is a map write, so the last section's params win
and **every split header ends up carrying the last section's params**.
The sibling function `parseRouteAddress` (same file, same scan shape) does not
have the bug — it slices `headerText[:idx]` on the comma path.

Measured through `sip.NewParser()` before the fix:

```
Contact: <sip:alice@192.0.2.7:5060>;expires=60, <sip:alice@10.0.0.9:5060>;expires=3600
  parsed[0] host=192.0.2.7:5060 params=expires=3600   <-- wrong; 60 was granted
  parsed[1] host=10.0.0.9:5060  params=expires=3600
```

It is not only `expires`, and not only a wrong value — a param present on one
section leaks onto all of them, and a section's own param can be corrupted
with the rest of the line:

```
Contact: "A,B" <sip:alice@192.0.2.7:5060>;expires=60, <sip:b@10.0.0.9>;q=0.5
  parsed[0] params=expires="60, <sip:b@10.0.0.9>"&q=0.5
```

**Why it cannot be worked around downstream.** Once parsed, a comma-combined
list and the same bindings on separate rows are **indistinguishable** — the
consumer receives N `*ContactHeader`s either way, with no record of how they
arrived on the wire. There is nothing left to detect, so no downstream guard
is possible; the fix has to be in the parser. Re-parsing the raw line in
`internal/sipua` would mean reimplementing address parsing outside the
canonical parser, which is worse.

The concrete blast radius that forced it: `internal/sipua/register.go`'s
`responseExpires`/`contactExpires` read the registrar's grant from the Contact
`expires` parameter, and since P3 that value **arms the registration refresh
timer**. A registrar granting us 60s and another device 3600s on one combined
line made the UA schedule its refresh at `0.85 x 3600 = 3060s` against a
binding that lapses at 60s — unreachable for ~50 minutes of every cycle, with
`refreshRegister` re-deriving the same wrong value forever, no warning (the
contact *did* match) and `ua_status` reporting `registered: true,
expires_s: 3600`. `parseContactHeader` also parses dialog-forming INVITE/200 OK
contacts (the remote target), REFER, and every other Contact in the product,
so the same leak reached those too.

**The change** — `sip/parse_address.go`, in `parseContactHeader`:

```diff
 			switch {
 			case char == ',':
+				// Only this comma-delimited section is ours; the caller
+				// re-enters with the remainder. Without narrowing endInd the
+				// address below is parsed from this section but the header
+				// params are read from the WHOLE line, so every split header
+				// ends up carrying the last section's params.
+				endInd = idx
 				err = errComaDetected(idx)
 			case idx == end:
 				endInd = idx + 1
```

`errComaDetected(idx)` still carries the **unmodified** comma index, which is
what `parseHeaderLine` slices the remainder from (`fieldText[commaErr+1:]`) —
only the section handed to `ParseAddressValue` narrows. Single-contact headers
(the overwhelmingly common path) never enter the comma branch at all: they end
via `case idx == end`, which is untouched, so their behavior is byte-identical
to upstream. Quoted commas are unaffected — the `inQuotes`/`inBrackets` scan
that decides what counts as a separating comma is not modified.

**Not fixed here:** the identical `endInd`-style narrowing is already correct in
`parseRouteAddress`, and no other header parser in this tree shares the defect.
A section with whitespace *before* the separating comma (`;expires=60 , <...>`,
legal SWS) now yields the param value `"60 "` rather than the wrong section's
value; `contactExpires` already applies `strings.TrimSpace` before `Atoi`, so
that is handled at the consumer, and trimming inside the parser was left out as
out-of-scope for this fix.

> **F-M9 (Phase 4 W2): the note above is narrower than the behaviour.** The
> trailing space is a property of **every** header parameter that sits on a
> non-final comma section, not of `expires` specifically. `contactExpires`'s
> `TrimSpace` is the only consumer that compensates, so any future reader of a
> multi-value header's parameters — `;transport=`, `;received=`, `;branch=` on a
> Via list, `;q=` on a Contact list — will see the same trailing space and must
> trim it too.
>
> Not fixed in the vendored parser (G4 freezes the code; only this file is
> editable). The bounded, durable action is this warning at the place a future
> consumer looks.

**Behavioural change a future upgrader will not expect — an EMPTY comma section
now hard-fails the whole message parse.** Narrowing `endInd` means a comma at
index 0 of a section produces `endInd = 0`, so `ParseAddressValue("")` returns
`"Empty Address"` — which is *not* an `errComaDetected`, so `parseHeaderLine`
aborts the entire message rather than continuing the split. Measured to flip
three inputs from "parses with garbage" to a `ParseSIP` error:
`Contact: ,<sip:a@1>;expires=60`, `Contact: <sip:a@1>,,<sip:a@2>`, and
`Contact: <sip:a@1>;expires=60,,<sip:a@2>;expires=30`.

This is deliberate and is **not** considered a regression: the shape is illegal
per RFC 3261, and upstream `v0.24.1` already hard-fails a *trailing* comma
identically both before and after this change — so the fix merely makes leading
and interior empty sections consistent with the trailing case. It is recorded
here because the practical effect is real: a middlebox emitting a doubled comma
in a Contact list previously let the UA register (with a garbage expiry) and now
causes the 200 OK to be discarded at parse time, timing the transaction out.

## Phase 4 M1 B7: IPv6-literal host killed the entire message parse

**The defect.** `uriStateHost` (`sip/parse_uri.go`) had no `[`/`]` awareness.
RFC 3261 19.1.1 (via RFC 2732) requires an IPv6 reference host to be written
bracketed, e.g. `sip:[::1]:5060`, so its own internal colons are not mistaken
for the host/port separator. `uriStateHost` scanned for the first bare `:`
without skipping over a bracketed span, so it split at the literal's OWN
first colon: `Host = "["`, and handed `uriStatePort` the remainder
`":1]:5060"`, which fails `strconv.Atoi`. Since `ParseUri` runs inside the
start-line/header parser with no external seam — `VENDOR.md`'s P3 section
above already rejected the equivalent "re-parse outside the parser" idea for
the structurally identical comma-Contact defect — one malformed
Contact/Request-URI/To/From carrying an IPv6 host killed the parse of the
**entire message**, not just that one URI.

**The change** — `sip/parse_uri.go`, in `uriStateHost`: the scan now tracks
an `inBracket` flag (set on `[`, cleared on `]`) and skips the `:`/`;`/`?`
boundary checks while it is true. One loop, all four `uriStateHost` exits
(the `:` port boundary, the `;` uri-params boundary, the `?` headers
boundary, and end-of-string) are covered identically — a partial fix that
only handled the `:` exit would still break on
`sip:[::1];transport=tcp`/`sip:[::1]?h=v`.

**Brackets are RETAINED in `Uri.Host`** (`"[::1]"`, not `"::1"`) — this is
load-bearing, not cosmetic: `StringWrite` (`uri.go:83`) writes `Host`
verbatim, so a stripped-bracket `Host` would make `String()` round-trip to
the invalid `sip:::1:5060`; `HostPort()` (`uri.go:148-150`) is
`Host + ":" + port`, consumed by `SetDestination` → `ParseAddr`
(`transport.go:88`, `net.SplitHostPort`), which *requires* the brackets and
strips them itself before `net.ParseIP`. Retaining brackets is the only
choice under which both the string round-trip and the dial path stay correct
with zero further downstream edits.

**Not extended to Via.** `sip/transport_layer.go:352` does
`net.ParseIP(viaHop.Host)` and would break on a bracketed Via host; Via
parsing is a separate code path from URI parsing and is left as a noted
limitation, not fixed here (surgical scope).

**Consumer-side consequence: outbound IPv6 targets still fail, just later
and by a different mechanism.** `internal/sipua/register.go`'s
`validSIPURI` (used by both `Dial` and `Register` to fail fast on a bad
target, D134/C7 and D123) called this same `sip.ParseUri` and relied on it
*failing* for an IPv6 host as its only signal. Once `ParseUri` legitimately
succeeds, that guard would silently let an IPv6 target through — and
`internal/sipua`'s UAs bind an IPv4 UDP/TCP socket, so dialing/registering
against an IPv6 peer still cannot work; it would now fail only after
`BuildInvite`/`BuildRegister`, at the OS socket layer
(`write udp ...: address ...: non-IPv4 address`), reintroducing exactly the
slow/untyped failure D134 and D123 were built to prevent. `validSIPURI`
(`internal/sipua/register.go`) was therefore given its own explicit
IPv6-literal check (recognizing the retained `"["` this fix writes into
`Uri.Host`) so it keeps rejecting an IPv6 outbound target — same result as
before, now for the accurate reason (unsupported target, not an unparseable
one). This is a consumer-side, non-fork change; recorded here because it is
the direct, load-bearing consequence of this divergence.

**Gate run.** Full `go build ./...`, `go test -race ./...` (every package
`ok`, including `internal/sipua`), `go vet ./...` (clean, other than the two
pre-existing `context.WithTimeout` findings in `dialog_integration_test.go`,
confirmed present on the pre-change tree too), `go test -count=1
./internal/importguard/...` and `go test ./internal/apierr/...` (both
green), and `git diff -- internal/sipengine/` empty. The `go run ./e2e/loop`
gate was not run: like the P3 divergence above, `uriStateHost` has no
IPv6-Contact scenario in the loop's existing script that would exercise this
change; blast radius is established instead by the full unit suite plus two
mutation proofs (reverting the `uriStateHost` hunk reddens all 6
`TestParseUriIPv6Literal` subcases and the full-message test with the
located `strconv.Atoi: parsing ":1]..."` error; removing the
`validSIPURI` IPv6 check reddens the two locked-decision regression tests
below) and the two pre-existing, wave-locked regression tests this change
directly interacts with — both confirmed green, including under `-race`:
`TestDialRejectsIPv6ToURI` (`internal/sipua/call_outbound_test.go`, D134/C7)
and `TestRegisterInvalidRegistrarIsInvalidArgumentNotPanic`
(`internal/sipua/register_test.go`, D123).

## Phase 4 M1 B1: `parseMsgHeader` ignored its own receiver

**The defect.** `sip/parse_header.go`'s `mapHeadersParser.parseMsgHeader`
receiver is named `headersParser` (singular). Its header-parser lookup read
`headersParsers[lowerFieldName]` — the **package-level global** `var
headersParsers` (`sip/parse_header.go:40`) — instead of the receiver. The
receiver was otherwise never referenced in the method body. Because this is
the *only* call site of `parseMsgHeader` (`Parser.ParseSIP` and
`ParserStream.ParseSIPStream` both call it as `p.headersParsers.parseMsgHeader(...)`),
any custom map passed via `WithHeadersParsers`/`sipgo.WithUserAgentParser`
was silently inert for line-by-line header dispatch — proven empirically: a
`*sip.Parser` built with a `content-length` entry that unconditionally
errors still accepted `Content-Length: 0` unchanged. This made per-parser
header-parser overrides dead code across the whole fork (not something B1
introduced — the bug predates this wave), and was the blocking precondition
discovered while implementing B1's Content-Length hardening
(`internal/sipua/parserhardening.go`): the wiring the plan specified could
not take effect until this was fixed.

**The change** — `sip/parse_header.go`, in `parseMsgHeader`:

```diff
-	headerParser, ok := headersParsers[lowerFieldName]
+	headerParser, ok := headersParser[lowerFieldName]
```

Minimal, one line: the receiver variable already existed under the correct
name, it was simply never read. For the common case (no `WithHeadersParsers`
override), `NewParser()` initializes `p.headersParsers` to the same global
map (`parser.go:63`), so this line reads an identical map either way and
behavior for every existing caller is unchanged. The only behavioral
difference is for a caller that DOES pass a custom map — which, before this
fix, no first-party code in this tree did (B1 is the first consumer of
`WithUserAgentParser`/`WithHeadersParsers`).

**Gate run.** Full `go build ./...`, `go test -race ./...` (every package
`ok`, including `internal/sipua`), `go vet ./...` (clean, other than two
pre-existing `context.WithTimeout` findings in `dialog_integration_test.go`,
confirmed present on the pre-change tree too — not introduced by this
change), `go test -count=1 ./internal/importguard/...` and
`go test ./internal/apierr/...` (both green), and
`git diff -- internal/sipengine/` empty. The `go run ./e2e/loop` gate was
not run: like the P3 divergence above, `parseMsgHeader` has no
custom-header-parser scenario in the loop's existing script that would
exercise this change; blast radius is established instead by the full unit
suite plus `internal/sipua/parserhardening_test.go`'s direct exercise of the
now-functional wiring (including two mutation proofs: removing the wiring
reddens the rejection test, and moving `maxBodyLen` reddens the boundary
test — proving the bound is read, not duplicated).

## Phase 4 W3 P4-W1-N05: the stream parser's header accumulator had no bound

**The defect.** `sip/parser_stream.go`'s `ParserStream.reader` (`:34`) is a
`*bytes.Buffer` that `ParseSIPStream` appends to on every call
(`reader.Write(data)`, `:56`) with no size check anywhere in the function.
When a header line has no CRLF yet, `nextLine` drains what it read and returns
`ErrParseLineNoCRLF`; the function's own tail then RESTORES the whole unparsed
remainder (`reader.Reset(); reader.Write(unparsed)`, `:166-169`) and returns
`ErrParseSipPartial` to wait for more. So a peer that completes a TCP or TLS
handshake and then drip-feeds bytes containing no CRLF at all grows that
connection's buffer without limit — measured live before this fix: 32MB fed in,
32MB retained. Reachable unauthenticated on `transport: tcp`, and on
`transport: tls` too, since the server config sets no `ClientAuth`.

**Why it could not be fixed outside the fork.** `p.reader` is a private field
mutated inside `ParseSIPStream`'s own state machine, and the only production
caller is `sip/transport_tcp.go:222` — also inside this tree. Unlike the Phase 4
M1 B1 Content-Length hardening, which had a legitimate extension point
(`sip.WithHeadersParsers`, consumed by `internal/sipua/parserhardening.go`),
there is no hook for the header-*line* accumulator: nothing in non-frozen code
can observe or bound it. `internal/sipua/observestream.go`'s existing 64KB
`maxHeaderBuf` bounds the passive observation tap's OWN side-buffer
(`streamFramer`), which has zero influence on the buffer the real stack parses
from.

**The check is on the partial-parse path, not immediately after
`reader.Write(data)`.** An earlier draft of this fix placed the check right
after `reader.Write(data)`, testing `p.state != stateContent && reader.Len() >
maxStreamHeaderBuf` before any parsing of that call happened. That draft was
caught by this repository's own pre-existing `internal/sipua`
`TestHardenedParserBoundary/exactly_maxBodyLen_is_accepted`: a single
`ParseSIPStream` call carrying a complete header block plus a legitimate 1MiB
body (a normal single-TCP-segment delivery) starts that call with `p.state`
still at its zero value (`stateStartLine`) and `reader.Len()` already holding
the whole 1MiB+ buffer, which is indistinguishable, at that check point, from a
genuine unbounded no-CRLF header — both present as "state not yet
`stateContent`, buffer already large." The fix below moves the check to where
`p.state` and the pending-bytes snapshot (`unparsed`) reflect what *this call's
own parse attempt* actually consumed, not what stood before it ran.

**The change** — `sip/parser_stream.go`, three hunks in one file:

```diff
 import (
 	"bytes"
+	"errors"
 	"fmt"
 	"io"
 	"strconv"
 	"sync"
 )
```

```diff
-var ()
+var ErrParseHeaderTooLarge = errors.New("SIP stream header accumulation exceeded the limit")
+
+const maxStreamHeaderBuf = 64 * 1024
```

```diff
 	for {
 		msg, err := parseSingle(reader)
 		switch err {
 		case ErrParseLineNoCRLF, ErrParseReadBodyIncomplete:
+			if p.state != stateContent && len(unparsed) > maxStreamHeaderBuf {
+				p.reset()
+				return nil, ErrParseHeaderTooLarge
+			}
 			reader.Reset()
 			reader.Write(unparsed)
 			return nil, ErrParseSipPartial
 		}
```

(The shipped hunk carries a substantial explanatory comment; the diff above is
stripped to its load-bearing lines.)

**Three decisions inside that small diff, each deliberate.**

*The bound is 64KB because that is the number this repository already chose.*
`internal/sipua/observestream.go`'s `maxHeaderBuf` is `64 * 1024` for the
identical hazard on the observation path. It is restated as a literal rather
than imported because `third_party/sipgo` is a **separate Go module** (its own
`go.mod`, required by the `replace` target rule) and `internal/...` is
unimportable from it in any direction. Both sites carry a comment naming the
other so the two cannot silently drift. The value also sits just above
`transportBufferSize` (65535, `sip/transport.go:38`), the largest single read
any transport hands to `ParseSIPStream`, so no one legitimate read trips it.

*The check reads `unparsed`, not `reader.Len()`, and runs on the partial-parse
path.* `parseSingle` only ever returns `ErrParseLineNoCRLF` /
`ErrParseReadBodyIncomplete` — the two errors this switch arm handles — so
every path that completes a message successfully (including a full header
block plus a large legitimate body delivered in one write) never reaches this
check at all. By the time this arm runs, `unparsed` is the exact snapshot
`nextLine`/`reader.Read` left behind for *this* call, not a pre-parse guess.

*`stateContent` is exempt, matching the intent of the hazard being bounded,
though the current body-read implementation makes the exemption unreachable in
practice.* Below `stateContent` the buffer is un-drained — a peer that never
finishes a header line grows `unparsed` without limit. In `stateContent`,
`reader.Read(body[p.readContentLength:])` (`:145`) drains the buffer on every
call, and by construction of `bytes.Buffer.Read` it can only return fewer
bytes than requested by draining everything currently buffered — so whenever
this switch arm is reached with `p.state == stateContent` (i.e.
`ErrParseReadBodyIncomplete`), `unparsed` is always empty. **Mutation testing
confirms this**: removing the whole `if` block reddens
`TestParseSIPStreamCapsHeaderAccumulation` and
`TestParseSIPStreamRecoversAfterTheHeaderCap`, but narrowing the guard to drop
only `p.state != stateContent &&` reddens **no test** — the clause is
currently dead code at this location, kept as documentation of intent and a
guard against a future change to the body-read path that stops fully draining
the buffer on an incomplete read. This is a known, deliberately-accepted gap
in mutation coverage for this one clause, not a correctness gap: the cap
itself (mutation 1) and the body-exemption *outcome* (`TestParseSIPStreamCapDoesNotApplyToTheBody`,
which passes because that scenario's completing call never reaches this
switch arm at all) are both proven.

*A distinct sentinel, and the buffer is not pooled.* `ErrParseHeaderTooLarge` is
not a reuse of `ErrParseSipPartial`, because "partial" means "send me more of
this message" and after this error there is no message left to be partial about.
`transportTCP.parseStream` (`sip/transport_tcp.go:222-236`) special-cases only
`ErrParseSipPartial` and otherwise ranges over an empty `msgs` slice, so this
error is handled exactly as every other non-partial parse error already is: the
connection stays open, nothing is logged, and the next chunk starts a fresh
message. **That silence is inherited, not introduced** — it is the pre-existing
shape of `parseStream`'s error handling for every parse error, and widening it
would mean a second frozen-file edit this divergence does not take. The
oversized buffer is deliberately NOT handed back to `streamBufReader`: pooling
an array a hostile peer talked us into allocating would keep it alive for the
process's lifetime. `p.reset()` nils `p.reader`, so it becomes garbage at once.

**Gate run.** `gofmt -l` silent on both files; `go test github.com/emiago/sipgo/sip -count=1` (the whole
fork package, `ok`); `go build ./...` clean; `go vet ./...` clean; `go test -count=1
./internal/sipua/...` (including `TestHardenedParserBoundary`, which the earlier pre-parse-check draft of
this fix broke and which now passes), `./internal/trace/...`, `./internal/testutil/loopback/...`,
`./internal/apierr/...` and `./internal/importguard/...` all `ok` (Rule 6a decision 2: this is the full
`VENDOR.md` "Re-gate obligation" bar, not a subset of it); and `git diff -- internal/sipengine/` empty.
The `go run ./e2e/loop` gate was not run: like the P3 and B7 divergences above, the loop has no drip-feed
non-terminated-header scenario that would exercise this change, and its own
transports never produce the input. Blast radius is established instead by the
full unit suite plus **two mutation proofs**: removing the `if` block reddens
`TestParseSIPStreamCapsHeaderAccumulation` and
`TestParseSIPStreamRecoversAfterTheHeaderCap`; narrowing the guard to drop only
`p.state != stateContent &&` reddens no test (see the third decision above —
recorded honestly rather than claimed as a red it does not produce).

## CF-050: `actInviteResend` reset a Timer A that terminate had cleared

`sip/transaction_client_tx_fsm.go`, `actInviteResend`: the `tx.timer_a.Reset(...)`
had no nil check, while `delete()` (`sip/transaction_client_tx.go`) closes `done`
and nils `timer_a` under `tx.mu` but not under `tx.fsmMu`. A Timer A callback
already inside the FSM could therefore take `tx.mu` after `delete()` released it
and call `Reset` on a nil `*time.Timer`, panicking on a timer goroutine and
taking the whole daemon down. A dial timeout (or hangup/CANCEL) landing on a
Timer A instant (500, 1500, 3500 ms ...) reproduces it. `actResend` already had
the identical guard. The diff (the bare `Reset` line removed; the `if`, the
indented `Reset` and the closing brace added):

```diff
-	tx.timer_a.Reset(tx.timer_a_time)
+	if tx.timer_a != nil {
+		tx.timer_a.Reset(tx.timer_a_time)
+	}
```

Behaviour with a live transaction is unchanged (the guard fires only after
termination, when there is nothing left to retransmit). The doubling of
`timer_a_time` stays unconditional, as in `actResend`.

Not fixed, reported: `actInviteFinal`/`actFinal` can start a `timer_d` after
`delete()` (a leaked timer whose later `actDelete` is a no-op through
`closeOnce`; no panic). The server side already starts `timer_g` when nil.

Reproducer: `internal/sipua` `TestDialTimeoutOnATimerAInstantDoesNotPanic`
(five concurrent dials, timeout 1500 ms): 15 of 20 separate unfixed runs
panicked, 0 of 20 fixed (and `-race -count=20` fixed: ok).

Upstream status: not filed (owner-side).

**Gate run.** `go test github.com/emiago/sipgo/...` (`ok`), the three guard
tests at `-count=200`, `go build ./...`, `go vet ./...`, `golangci-lint run`,
and `go test -count=1 ./internal/apierr/... ./internal/importguard/...`. The
`go run ./e2e/loop` gate was not run for this divergence. Mutation proofs:
removing the new guard reddens `TestActInviteResendAfterTerminateDoesNotPanic`;
removing `actResend`'s existing guard reddens
`TestActResendAfterTerminateDoesNotPanic` while the copy-based
`TestActResendNilTimerADoesNotPanic` stays green.

## CF-058: accepted stream connections were pooled under the listen address

`sip/transport_tcp.go`, `initConnection` pooled EVERY connection under both
`conn.LocalAddr().String()` and the remote address. For an ACCEPTED connection
the local address is the listener's, which is exactly the UA's Via sent-by
(sipclient-mcp hands its listen address to the client as `LocalAddr`, and its
own outbound connections use an ephemeral local port through
`WithDialEphemeralLocalPort`). `TransportLayer.ClientRequestConnection`
(`sip/transport_layer.go`) looks up `GetConnection(<Via host:port>)` BEFORE it
considers the destination, and `TCPConnection.WriteMsg` ignores
`Destination()`, so the most recently accepted inbound connection carried every
outbound request: INVITE (and its digest retry), 2xx ACK, CANCEL, BYE, INFO,
re-INVITE/UPDATE, REFER, OPTIONS keepalives, REGISTER (and its digest retry).
RFC 3261 §18.1.1 allows reusing a connection only towards the request's own
destination, so this was misdelivery, not connection reuse. Responses never
depended on the listen-address entry: the server transaction takes its
connection by the request's source (the remote key), as §18.2.2 requires.

The fix: `initConnection` gains `accepted bool` (true only from `Serve`'s accept
loop). An accepted connection is pooled only under its remote address and its
reader gets an empty `laddr`; `readConnection`'s `Delete(laddr)` is guarded, so
it deletes only a key its own connection added. Outbound connections
(`createConnection`, `transportTLS.CreateConnection`, both passing `false`) keep
both keys. The pool, `GetConnection`, `ClientRequestConnection` and `WriteMsg`
are unchanged. With an accepted connection open, an outbound request now takes
the path it already took when none was open: the Via lookup misses and
`CreateConnection` dials the destination.

```diff
-		t.initConnection(conn, conn.RemoteAddr().String(), handler)
+		t.initConnection(conn, conn.RemoteAddr().String(), true, handler)
...
-	c := t.initConnection(outConn, addr, handler)
+	c := t.initConnection(outConn, addr, false, handler)
...
-func (t *transportTCP) initConnection(conn net.Conn, raddr string, handler MessageHandler) Connection {
+func (t *transportTCP) initConnection(conn net.Conn, raddr string, accepted bool, handler MessageHandler) Connection {
...
-	t.pool.Add(laddr, c)
+	if accepted {
+		laddr = "" // not pooled under the listen address; readConnection deletes no local key
+	} else {
+		t.pool.Add(laddr, c)
+	}
 	t.pool.Add(raddr, c)
...
-	defer t.pool.Delete(laddr)
+	if laddr != "" {
+		defer t.pool.Delete(laddr)
+	}
 	defer t.pool.CloseAndDelete(conn, raddr)
```

plus `sip/transport_tls.go`'s one call (`initConnection(outConn, addr, false,
handler)`) and an explanatory comment above `initConnection`.

TLS is covered by the same hunk: `transportTLS` embeds `*transportTCP` and
defines no `Serve` and no `initConnection`, so `ServeTLS` runs the promoted
`transportTCP.Serve` and pools through this `initConnection`. WS/WSS are NOT
changed: `sip/transport_ws.go` has its own `initConnection` with the same two
`Add`s, but sipclient-mcp never serves WS (`internal/sipua` admits only `udp`,
`tcp` and `tls` and calls only `ServeTCP`/`ServeTLS`), so it is not reachable
here. UDP is unaffected (no accept path).

Behaviour change for operators: a TCP/TLS peer that cannot ACCEPT an inbound
connection (behind NAT or a firewall, without RFC 5626 outbound) no longer
receives our in-dialog requests (BYE as callee, refreshes, INFO, REFER). It
used to receive them only by accident, through the most recently accepted
connection, which with two inbound callers delivered one caller's BYE to the
other. On TLS each such request now performs a client handshake that verifies
the peer's certificate unless `TLSInsecureSkipVerify` is set.

Probes on `31f696c` (before the fix): a raw TCP (owner) and a raw TLS (planner)
connection held open to UA `a`'s listener, then `a.Dial` to a different UA: the
`INVITE sip:p@127.0.0.1:<port>;transport=tcp` (`;transport=tls`) line arrived on
the raw connection and the real peer never saw it.

Not changed, recorded: `ConnectionPool.CloseAndDelete` deletes its key
unconditionally, so a connection exiting after a NEWER connection was added
under the same key removes the newer mapping. That race is pre-existing; on the
accept path only the remote key remains, and the new guarded `Delete(laddr)`
runs only for outbound connections, whose `laddr` is their own ephemeral
address. Fixed afterwards by the CF-064 entry below.

Upstream status: not filed (owner-side); upstream sipgo still pools every
accepted connection under BOTH the listen address and the remote address, so a
re-vendor must re-apply this hunk.

**Gate run.** `go test -race -count=50` of the four new `sip` tests (`ok`),
`go test -count=1 github.com/emiago/sipgo/...` (`ok`), the five new
`internal/sipua` tests at `-race -count=10` (`ok`), `go test -race -count=3 -run
'TestTCP|TestTLS|TestCRLFKeepaliveFallsBackToOPTIONSOnAStreamTransport'
./internal/sipua/`, `go test -race -count=1 ./internal/sipua/
./internal/testutil/loopback/`, `go build ./...`, `go vet ./...`,
`golangci-lint run --max-same-issues=0 ./...` and `go test -count=1
./internal/apierr/... ./internal/importguard/...`. The live `go run ./e2e/loop
-transport tcp` / `-transport tls` gate against the lab Asterisk rig was not run
by the implementer (owed to the wave's parent session). Mutation proofs:
reverting the fix reddens both `TestAccepted*IsNotPooledUnderTheListenAddress`,
`TestClosingAnAcceptedConnectionLeavesTheListenAddressEntryAlone`, both
subtests of `internal/sipua`'s `TestOutboundInviteIgnoresAnAcceptedInboundConnection`
(the raw connection reads the INVITE line),
`TestRegisterAndItsDigestRetryIgnoreAnAcceptedInboundConnection` (`Register`
times out) and `TestCalleeByeOnAnInboundTCPCallGoesToTheCallersContact` (the
BYE rides the accepted INVITE connection); keeping the single key but restoring
the unconditional `Delete(laddr)` reddens
`TestClosingAnAcceptedConnectionLeavesTheListenAddressEntryAlone` 20 of 20 at
`-count=20`; pooling the accepted connection under neither key reddens
`TestInboundCallResponsesStillUseTheAcceptedConnection` (the server
transaction logs `connection "<remote>" does not exist` and the INVITE is never
admitted).

## N1: a stream Via-key hit was used whatever its destination

`sip/transport_layer.go`, `ClientRequestConnection`: when the Via sent-by is a
full `IP:port` it returns `GetConnection(<Via host:port>)` BEFORE it considers
the destination, and `TCPConnection.WriteMsg` ignores `Destination()`. CF-058
took accepted connections out of that key, but an OUTBOUND stream connection is
still pooled under its remote address (and its own ephemeral local address).
So when the UA dials its OWN listen address, that connection lands under the
Via key and carries every later outbound request back to the UA itself until
`UA.Close`: REGISTER refreshes and their digest retries, outbound INVITEs and
their retries, BYEs to other peers. Reachable remotely: an inbound TCP/TLS
caller whose Contact is `sip:x@<UA_IP>:<UA_PORT>;transport=tcp` makes the UA's
first in-dialog request after the answer (BYE, session refresh, INFO) dial
itself; a callee's 2xx Contact does the same through the ACK; a `0.0.0.0` bind
too. Impact: registration loss and denial of outbound calls (no credential
reaches a third party). Same bug class as CF-058, pre-existing.

The fix: a stream (`*TCPConnection`) Via-key hit is used only when its remote
address is the request's resolved destination; otherwise
`ClientRequestConnection` falls through to `CreateConnection`, the path it
already took whenever the Via key missed. `GetConnection`, the pool,
`initConnection` and `WriteMsg` are unchanged.

```diff
 	if laddr.IP != nil && laddr.Port > 0 {
 		c, _ = transport.GetConnection(laddr.String())
+		// SIPCLIENT-MCP DIVERGENCE (N1): an outbound stream connection is
+		// pooled under its remote address too, so one the UA opened to its
+		// own listen address sits under the Via key. Use a stream hit only
+		// when it leads to this request's destination; otherwise dial it.
+		if tc, ok := c.(*TCPConnection); ok && tc.RemoteAddr().String() != raddr.String() {
+			c = nil
+		}
 		if c != nil {
 			return c, nil
 		}
```

Why this mechanism and not "skip the Via lookup for stream transports": a
consumer that does not opt into `WithDialEphemeralLocalPort` dials from the Via
`IP:Port` itself, so its only outbound connection is pooled under the Via key as
its LOCAL address, and the Via lookup is how it reuses that connection; a second
dial from the same `IP:Port` would fail with `EADDRINUSE`. Comparing the remote
address keeps that reuse whenever the destination matches and drops only the
misdelivery. The first-party consumers without the option
(`internal/sipengine/calltester`, `siptest.NewClient`) build only `udp` requests
(`siptest.BuildRegister/BuildInvite(cfg, "udp")`), so neither path reaches
them; `internal/sipua` opts in, so its Via key is never a stream connection's
local address. `raddr.String()` and `net.TCPAddr.String()` are both
`net.JoinHostPort(ip.String(), port)` (`raddr.IP` is always set by this point:
it is resolved above), so a destination match compares equal; a zoned IPv6
remote would compare unequal and simply dial (no misdelivery).

TLS is covered by the same hunk: `transportTLS` builds its connections with the
promoted `transportTCP.initConnection`, so they are `*TCPConnection` too. UDP is
not changed: its listener (`*UDPConnection`, pooled under its local address) is
still returned by the Via lookup for any destination, which is how UDP sends
connectionless. WS/WSS connections are `*WSConnection` and keep upstream
behaviour (not served by sipclient-mcp).

Probe: on `2d9037e` (before the fix) a `TransportLayer` with
`WithDialEphemeralLocalPort` serving a TCP (and a TLS) listener dialled its own
listen address, then asked for a connection to a different peer with the same
Via: it got the self connection (`request to 127.0.0.1:46231 got a connection
to 127.0.0.1:44715 (the Via-key self connection)`), so the request would have
been written back to the UA.

Upstream status: not filed (owner-side); upstream sipgo's Via lookup has no
destination check, so a re-vendor must re-apply this hunk.

**Gate run** (on the tree carrying both N1 and N2, which landed in the same
pass). `go test -race -count=20` of the three new N1/N2 `sip` tests together with
the CF-058, dial-wrap and B2 tests (`ok`); `go test -count=1
github.com/emiago/sipgo/...` (`ok`); `go test -race -count=3 -run
'TestTCP|TestTLS|TestCRLFKeepaliveFallsBackToOPTIONSOnAStreamTransport|TestRegister|TestOutboundInvite|TestInbound|TestCallee|TestStream'
./internal/sipua/` (`ok`) and `-race -count=1 -run
'TestDial|TestHangup|TestClose|TestSession|TestRefresh|TestUAClose'` (`ok`);
`go build ./...`, `go vet ./...`, `golangci-lint run --max-same-issues=0 ./...`
(0 issues, exit 0); `go test -count=1 ./internal/apierr/...
./internal/importguard/...` (`ok`); `go.mod`/`go.sum` unchanged. The live
`go run ./e2e/loop` gate was not run by the implementer. Recorded, not caused
here: upstream's `TestTransportLayerClientConnectionReuse` and
`TestTransportLayerClientConnectionNoReuse` report a data race under `-race`
(testify's `require.NotEqual` deep-compares `*UDPConnection` structs while
their reader goroutines run) on the unchanged `2d9037e` tree too; they pass
without `-race`.
Mutation proofs: removing the new `if` reddens both subtests of
`TestStreamViaKeyHitIsUsedOnlyTowardsItsOwnDestination` (the peer request gets
the self connection); dropping every stream Via hit (`if _, ok :=
c.(*TCPConnection); ok`) reddens both subtests at the legitimate-reuse check
(`did not reuse the Via-key connection that leads there`); widening the guard to
non-stream hits (`!ok || ...`) reddens `TestUDPViaKeyStillFindsTheListener`
(`listen udp 127.0.0.1:<port>: bind: address already in use`).

## N2: a request written outside a transaction dialled without a deadline

`sip/transport_layer.go`, `WriteMsgTo` (which `WriteMsg` calls): the request
branch passed `context.Background()` to `ClientRequestConnection`, so neither
the TCP dial nor `transportTLS.CreateConnection`'s `HandshakeContext` had a
deadline. This is the path of every request written outside a transaction
(`Client.WriteRequest`), above all the 2xx ACK (`internal/sipua/call.go`
`runDial`, `internal/sipua/sessiontimer.go` re-INVITE refresh). A callee whose
2xx Contact host accepts TCP but stalls the TLS handshake pinned `runDial` in
`phaseAnswering` indefinitely: one goroutine and one fd per call. Pre-existing;
CF-058 widened it slightly (an accepted connection no longer stands in for the
dial).

The fix: the request branch derives `context.WithTimeout(context.Background(),
Timer_B)`. Timer B (64*T1, 32 s at the default T1) is the existing bound for an
INVITE transaction and is also how long a UAS retransmits its 2xx waiting for
the ACK (RFC 3261 §13.3.1.4), so an ACK not on the wire by then is useless. No
new option or config surface; a consumer that changes T1 through
`sip.SetTimers` moves this bound with it.

```diff
 	case *Request:
-		var ctx = context.Background()
+		// SIPCLIENT-MCP DIVERGENCE (N2): bound the dial and TLS handshake. This
+		// path carries the 2xx ACK, which has no transaction to time it out;
+		// after Timer_B (64*T1) the UAS has stopped retransmitting the 2xx.
+		ctx, cancel := context.WithTimeout(context.Background(), Timer_B)
+		defer cancel()
 		//Every new request must be handled in seperate connection
 		conn, err = l.ClientRequestConnection(ctx, m)
```

TLS is the case the test drives: `HandshakeContext` aborts on the deadline and
closes the underlying TCP connection (crypto/tls interrupts a context-bound
handshake by closing the conn), so the fd is released too. TCP dials are bounded
by the same `DialContext` context. The context only bounds connection
establishment: `net.Dialer.DialContext` and `HandshakeContext` do not tie an
established connection to it, so `cancel()` on return does not affect a pooled
connection. UDP's `ListenPacket` is unaffected in practice (it does not block).
WS/WSS dials become bounded as well, which falls out of the same context
(`transportWSS` already applies a context deadline to its upgrade). Transaction
requests do not use this path (`ClientTx` takes the caller's context) and are
unchanged.

Probe: on `2d9037e` (before the fix) `TransportLayer.WriteMsg` of a
`;transport=tls` request to a listener that accepts TCP and never answers the
ClientHello did not return within 5 s with `Timer_B` set to 200 ms.

Not changed, recorded: `transportTLS.CreateConnection` does not close the dialed
TCP connection when `HandshakeContext` fails for a reason other than the context
(for example a certificate error), so such an fd lives until the peer closes it.
Pre-existing, outside this item's scope. Fixed afterwards by the CF-066 entry
below.

Upstream status: not filed (owner-side); upstream sipgo still writes
non-transaction requests with `context.Background()`, so a re-vendor must
re-apply this hunk.

**Gate run.** The combined N1 + N2 gate recorded in the N1 entry above.
Mutation proof: restoring `var ctx = context.Background()` reddens
`TestWriteMsgRequestDialIsBoundedByTimerB` (`WriteMsg to a destination that
stalls the TLS handshake did not return within 5s (Timer_B is 200ms)`).

## CF-066: a failed TLS handshake leaked the dialed TCP connection

`sip/transport_tls.go`, `transportTLS.CreateConnection`: when
`HandshakeContext` failed for a reason other than the context (for example an
untrusted certificate), the dialed TCP connection was never closed, so each
attempt held one fd until the peer closed it. Reachable by an MCP caller
repeatedly pointing a TLS UA at a registrar with a bad certificate.
Pre-existing in upstream. A context end was already closed by crypto/tls (see
the N2 entry).

The fix closes the dialed connection on every handshake failure; nothing is
pooled or wrapped on that path (both come after the handshake).

```diff
 	if err := tlsConn.HandshakeContext(ctx); err != nil {
+		// SIPCLIENT-MCP DIVERGENCE (CF-066): release the dialed TCP connection
+		// on every handshake failure (a context end is already closed by
+		// crypto/tls; the second close is harmless).
+		_ = conn.Close()
 		return nil, fmt.Errorf("TLS handshake error: %w", err)
 	}
```

Probe (go1.25.0): a client with no trusted root against a self-signed server
fails the handshake; before the fix the server's read on the raw connection ended
in `i/o timeout` (never closed), after it in EOF or a connection reset.

Not changed, recorded (CF-064/CF-066 round, not reachable from this repo):
`transportWSS.CreateConnection` (`sip/transport_wss.go`) dials TCP and returns
without closing it when `url.ParseRequestURI` or `Upgrade` fails. This repo's
`networkFor` admits only `udp`, `tcp` and `tls`, and no first-party code dials
WS/WSS.

Upstream status: not filed (owner-side); a re-vendor must re-apply this hunk.

**Gate run.** `go test -race -count=20` of the two new tests, the fork's suite,
`go build`/`go vet`/`golangci-lint`, `internal/apierr` and `internal/importguard`.
Mutation proof: deleting the `conn.Close()` reddens
`TestTLSHandshakeFailureClosesTheDialedConnection` (`i/o timeout`).

## CF-064 part (1): `CloseAndDelete` deleted a key that was no longer its own

`sip/transport_connection_pool.go`, `ConnectionPool.CloseAndDelete`: after
closing the connection it ran `delete(p.m, addr)` unconditionally. Each live
caller passes the connection it owns when that connection's reader exits
(`transportTCP.readConnection`, key `raddr`; `transportUDP.readListenerConnection`,
key `laddr`; `transportWS.readConnection`, key `raddr`), and `Add` overwrites, so
an exit after a NEWER connection was added under the same key removed the newer
mapping. Reachable on the outbound stream path: every outbound connection to one
destination is pooled under the same remote key. Pre-existing in upstream.

The fix deletes the key only while it still maps to the connection being closed
(identity of the dynamic pointer). The close itself stays unconditional.

```diff
-	delete(p.m, addr)
+	if cur, ok := p.m[addr]; ok && cur == c {
+		delete(p.m, addr)
+	}
```

Not changed, recorded (CF-064 part 2 and the sibling sites stay carried):
`Delete` and `DeleteMultiple` also delete unconditionally (live callers:
`transport_tcp.go` `readConnection`'s local-key delete, `transport_udp.go`
`readUDPConnection` and the `DeleteMultiple` of the learned remote addresses,
`transport_ws.go`). `AddIfNotExists` tests `!exists` where it means `exists` and
has no caller. The listen-port peer collision (CF-064 part 2) is not addressed.
(Both are fixed in the next two entries: CF-069 (b)(c) and CF-064 part (2).)

Upstream status: not filed (owner-side); a re-vendor must re-apply this hunk.

**Gate run.** `go test -race -count=20` of the three new tests, the fork's
suite, the sipua stream-transport tests, `go build`/`go vet`/`golangci-lint`.
Mutation proof: restoring the unconditional `delete` reddens
`TestCloseAndDeleteLeavesANewerConnectionUnderTheSameKey` and
`TestAnExitingOutboundConnectionKeepsANewerOnesRemoteKey`; closing only when the
key is the connection's own reddens the first at its "was not closed" check.

## CF-069 (b)(c): `Delete`/`DeleteMultiple` deleted another connection's key, `AddIfNotExists` never stored

`sip/transport_connection_pool.go`. (b) `Delete(addr)` and `DeleteMultiple(addrs)`
ran `delete(p.m, a)` whatever the key now mapped to. Their four live callers all
run when the reader of the connection that added the key exits
(`transportTCP.readConnection` and `transportWS.readConnection` for the
connection's own local key; `transportUDP.readUDPConnection` for a created
connection's remote key; `transportUDP.readListenerConnection` for the remote
addresses a listener learned), so an exit after a newer connection took the key
removed the newer mapping: the sibling of the CF-064 part (1) flaw.
(c) `AddIfNotExists` tested `!exists` where it meant `exists`: it never stored a
new key and overwrote a held one. It had no caller.

The fix: `Delete(c, addr)` and `DeleteMultiple(c, addrs)` take the exiting
connection first (as `CloseAndDelete(c, addr)` does) and delete a key only while
it maps to `c`; neither closes anything. `AddIfNotExists(a, c) bool` stores only
under a free key and reports whether it stored, through an unexported helper
that assumes the lock is held (`AddOrTrack`, the next entry, reuses it). The four
callers pass their own connection.

```diff
-func (p *ConnectionPool) Delete(addr string) {
+func (p *ConnectionPool) Delete(c Connection, addr string) {
 	p.Lock()
 	defer p.Unlock()
-	delete(p.m, addr)
+	if cur, ok := p.m[addr]; ok && cur == c {
+		delete(p.m, addr)
+	}
 }
```

`DeleteMultiple` has the same guard per key; the `AddIfNotExists` diff is the
rewrite described above. Not changed, recorded: the other CF-069 items stay
carried, (a) `transportWSS.CreateConnection` leaks its dialed TCP connection when
the upgrade fails (WS/WSS is unreachable from this repo) and (d) stream writes
have no write deadline (CF-067).

Upstream status: not filed (owner-side); a re-vendor must re-apply these hunks
and the first argument at the four callers.

**Gate run.** `go test -race -count=20` of the six new tests, the fork's suite
(without `-race`: two upstream `TestTransportLayerClientConnection*` tests race at
`main`), `go vet`, gofmt of the touched files, `golangci-lint`, the apierr and
importguard tests. Mutation proof (each reverted byte-identical): the
unconditional `delete` in `Delete` reddens
`TestDeleteLeavesAKeyHeldByAnotherConnection` and
`TestAnExitingOutboundConnectionLeavesItsLocalKeyToANewerHolder`; in
`DeleteMultiple` it reddens `TestDeleteMultipleRemovesOnlyTheConnectionsOwnKeys`
and `TestAnExitingUDPListenerLeavesALearnedAddressToANewerHolder`; the old
`!exists` test reddens both `AddIfNotExists` tests; skipping the store while
returning true reddens `TestAddIfNotExistsStoresUnderAFreeKey`.

## CF-064 part (2): a dialed connection overwrote the key of a listen-port peer's accepted connection

`sip/transport_connection_pool.go`, `sip/transport_tcp.go`. A peer that opens TCP
to us from its own listen port is pooled (accept path) as `peer:<listen port>`.
Our in-dialog request to its Contact then dials a new connection, and the
outbound `initConnection` ran `Add(raddr, c)`, overwriting that key. Responses
then left on the dialed connection; once it closed, the key was removed and a
request arriving on the accepted connection failed `Server tx get connection
failed`; and `Clear` no longer reached the accepted connection (fd and reader
stayed until the peer closed).

The fix: the pool gains `unkeyed map[Connection]string` and
`AddOrTrack(a, c) bool`. The outbound branch of `transportTCP.initConnection`
(TCP and TLS) calls `AddOrTrack(raddr, c)`: a free key is stored exactly as
`Add` would; a held key is left alone and `c` is tracked with the key it wanted.
`Clear` also closes tracked connections. `CloseAndDelete` forgets the exiting
connection from `unkeyed` and, only when it owned the key, promotes one tracked
connection that wanted exactly that key and is not yet closed (this keeps the
CF-064 part (1) outcome for two dialed connections: a tracked one receives the
key when the older one exits; with several waiters the winner is map order). The
accept path, UDP and WS keep `Add`.

```diff
-	t.pool.Add(raddr, c)
+		t.pool.AddOrTrack(raddr, c)
```

(in the outbound branch only; the accept branch keeps `t.pool.Add(raddr, c)`.)

Not changed, recorded: our own in-dialog requests still dial a new connection
each time (CF-063); with two live connections to one remote address the pool has
one key, so a response to a request that arrived on the non-holder leaves on the
holder (a new carry-forward row). `TestAnExitingOutboundConnectionKeepsANewerOnesRemoteKey`
(CF-064 part 1) changed one precondition: the second dial no longer overwrites,
so the remote key holds the first connection until it exits and the final
assertion is unchanged.

Consequences, recorded: two dialed connections to one destination now leave the
key with the OLDEST live one, not the newest; a dead holder whose reader has not
yet exited keeps the key until it does; and "not yet closed" in the promotion
guard means a nonzero reference count, so a connection the peer closed but whose
reader has not noticed can still be promoted (its exit then promotes the next).

Residual, recorded: the accept path still overwrites (`Add`), so a dialed holder
that a peer's later accepted connection displaces is no longer tracked; it stays
reachable by `Clear` through its local key, but the key is not handed back when
the accepted connection exits.

Upstream status: not filed (owner-side); a re-vendor must re-apply these hunks,
keep `NewConnectionPool` initialising `unkeyed`, and keep the outbound branch of
`transportTCP.initConnection` as `Add(laddr)` plus `AddOrTrack(raddr)`.

**Gate run.** `go test -race -count=20` of the new and the related existing
tests, the fork's suite, `go test -race` of `internal/sipua` (the stream subset
and the whole package), `go vet`, gofmt of the touched files, `golangci-lint`.
Mutation proof (each reverted byte-identical): the outbound branch back to `Add`
reddens both listen-port tests and the CF-064 part (1) reader-exit test; dropping
`unkeyed[c] = a` reddens the Clear, promotion and reader-exit tests; deleting
`Clear`'s tracked loop reddens
`TestAConnectionRefusedAKeyIsTrackedAndClosedByClear`; deleting
`delete(unkeyed, c)` reddens
`TestCloseAndDeleteOfATrackedConnectionForgetsItAndKeepsTheHolder`; deleting the
promotion loop reddens the promotion tests; moving it outside the ownership guard
reddens `TestAnExitingTrackedConnectionDoesNotDisplaceTheLiveHolder`; making
`AddOrTrack` always track reddens `TestAddOrTrackOnAFreeKeyIsAnAdd`; promoting
regardless of key reddens `TestPromotionOnlyHandsAKeyToAConnectionThatWantedIt`;
dropping the `Ref(0) > 0` guard reddens
`TestPromotionSkipsATrackedConnectionAlreadyClosed`.

## CF-073: tags, branches and Call-IDs came from math/rand

`sip/utils.go`: `RandString` (Call-ID, nonce) and `RandStringBytesMask` (every
`GenerateTagN` and `GenerateBranchN`) drew from math/rand, seeded from the clock
in `init`. RFC 3261 19.3 (rfc3261.txt:8876-8878) requires a tag to be globally
unique and cryptographically random with at least 32 bits of randomness; the
outputs were a function of the global math/rand state (two builds after
`rand.Seed(7)` were identical). Pre-existing in upstream.

The fix adds `randInt63` (8 bytes from `crypto/rand`, shifted right one bit)
and uses it for both `rand.Int63()` calls; `RandString` keeps its body with
`crypto/rand`'s `Read`; the `init` seed is deleted. `NonceWrite` (dead code, no
caller) changed only as far as it must to compile (`randInt63()%len`).
Alphabet and lengths are unchanged (tag 8, Call-ID 10 plus `@host`, branch
`z9hG4bK.` plus 10). Marker `SIPCLIENT-MCP DIVERGENCE (CF-073)` in each changed
doc comment.

Not changed, recorded: the second, now harmless `rand.Seed` in
`sip/transport_layer.go` (`init`, seeds the global math/rand only), and
`RandString`'s modulo bias (a byte modulo the 62-character alphabet; the
first characters are slightly more likely; still far above 32 bits of entropy
for tags). Cost: about 1 microsecond per identifier.

Tests (`sip/utils_crypto_test.go`, new): `TestGeneratorsIgnoreTheMathRandSeed`,
`TestGeneratorsKeepTheirFormat`. The repo's NEW-A-2 pin
(`internal/sipengine/siptest/rfc3261_pin_hdr_test.go`) is flipped to
`TestRFC3261_NEWA2_BuiltIdentifiersAreIndependentOfTheMathRandSeed`; that is the
wave's only `internal/sipengine` diff (recorded exception to the re-gate's
"`git diff -- internal/sipengine/` empty", decision D-073).

Mutation proof: restoring `math/rand.Int63` reddens
`TestGeneratorsIgnoreTheMathRandSeed` (tag and branch lines); restoring the
math/rand `Read` in `RandString` reddens its RandString line.

Upstream status: not filed (owner-side); a re-vendor must re-apply this hunk.

## CF-069 (a)(d): a failed WSS dial leaked its connection, stream writes were unbounded

(a) `sip/transport_wss.go`, `transportWSS.CreateConnection`: the dialed TCP
connection was not closed when `Upgrade` (or `url.ParseRequestURI`) failed, so
each failed WSS dial held one fd. Reachable: a peer's `Contact: ...;transport=wss`
makes in-dialog requests dial WSS (this supersedes the "not reachable" remark
in the CF-066 entry above). The fix mirrors CF-066: close on both error paths.
The `ParseRequestURI` failure is practically unreachable (the address was
resolved before), so its close has no red-able test, as for P4-W1-N05.

(d) `sip/transport_tcp.go`, `TCPConnection.Write`: a write to a peer that never
reads blocked forever. The fix sets a write deadline of `Timer_B` (64*T1, the N2
dial-deadline precedent; it follows `sip.SetTimers`, no config key) on every
write, never once per connection (a pong written after an old deadline would
fail on a healthy connection). `TCPConnection` gains `writeMu`, held for the
deadline and the write: without it a second writer's `SetWriteDeadline` moves the
deadline of a first write already blocked (`tls.Conn` behaves the same way), so a
stuck peer with traffic more often than every 32 s would never time out. On
`os.ErrDeadlineExceeded` the connection is closed (a partial write corrupted the
framing; crypto/tls treats that state as corrupt), and closed while `writeMu` is
still held: a writer queued behind the timed-out one must never append its bytes
to the partial message (it fails on the closed connection instead). Its reader
then exits and the pool's identity-checked `CloseAndDelete` cleans up.
Trade-off: a peer that leaves more than about 1 MB unread for 32 s loses its
connection; the pong write on the reader goroutine is bounded too. Not covered:
WS/WSS writes (`WSConnection.Write`, `sip/transport_ws.go`) still have no write
deadline; this hygiene item covers TCP and TLS only.

Test fake: `fakes/tcp_conn.go` gains a no-op `SetWriteDeadline` (its embedded
`net.Conn` is nil, so the per-write deadline above panicked the fork's root
package tests; found in Rule 13 round 1). The fork's root-package tests need the
gitignored `testdata/certs`; `go test .` passes with them present.

Tests (new files): `sip/transport_wss_upgrade_fail_test.go`
(`TestWSSUpgradeFailureClosesTheDialedConnection`) and
`sip/transport_tcp_write_deadline_test.go`
(`TestStreamWriteToAPeerThatNeverReadsIsBoundedByTimerB`,
`TestStreamWriteDeadlineIsRefreshedPerWrite`,
`TestTwoBlockedWritersAreBothBoundedByTimerB`,
`TestAQueuedWriterNeverWritesAfterATimedOutPartialWrite`: a controlled stream
reports a partial write and a deadline error while a second writer is queued on
`writeMu`; the second writer must fail and nothing may be accepted onto the
stream before the close).

Mutation proof: deleting the Upgrade-path `Close` reddens the WSS test
(`i/o timeout`); deleting the deadline reddens the bound test and the
two-writer test; setting the deadline once per connection reddens the refresh
test; dropping `writeMu` reddens the two-writer test (the first writer returns
after about 1.5 x `Timer_B`); dropping the `Close` on a deadline error reddens
the EOF check and the queued-writer test; closing after `writeMu.Unlock()` (the
first cut's order) reddens the queued-writer test (`writer 2 succeeded on a
stream left partial by a timed-out write`).

Upstream status: not filed (owner-side); a re-vendor must re-apply these hunks.

## CF-106: an oversize request over UDP was refused, not sent over TCP

`sip/transport_layer.go`, `TransportLayer.ClientRequestConnection`: RFC 3261
18.1.1 says a request larger than 1300 bytes with the path MTU unknown MUST be
sent over a congestion-controlled transport such as TCP, and the top Via MUST
then be changed. The path MTU is never known here, so the rule is "larger than
1300 bytes" (`UDPMTUSize-200`, the size `UDPConnection.WriteMsg` refuses
above). At the top of the function, when the request's network is `udp` and its
serialised length exceeds that, the top Via transport and `req.SetTransport`
become `TCP`, the branch is kept, and the function continues with network `tcp`.
The transaction layer calls it before creating the client transaction, so the
transaction is reliable (no Timer A). The 18.1.1 `TODO` in `WriteMsgTo` is
replaced by a pointer to the switch. Marker `SIPCLIENT-MCP DIVERGENCE (CF-106)`.

The switch is default-on for every sipgo consumer, `internal/sipengine`
included: it implements an RFC MUST (unlike a transaction-lifetime change,
which would alter every consumer's behaviour for no MUST). A consumer that never
sends over 1300 bytes on UDP sees no change.

Residuals, not fixed: a header added after `ClientRequestConnection` measured
the request could still meet the UDP refusal just above the boundary; the 18.1.1
SHOULD fallback to UDP on a TCP reset is not implemented; an error-path response
to our sent-by needs a TCP listener on a UDP UA (CF-076, resolved by cf5-f Task 4); responses over 1300
bytes on UDP were still refused (resolved by CF-168, below).

Test (new file): `sip/transport_layer_size_switch_test.go`
(`TestClientRequestConnectionSwitchesAnOversizeUDPRequestToTCP`: 1301 bytes goes
to a `*TCPConnection` with a `TCP` top Via, `req.Transport()` `TCP` and the
branch unchanged; exactly 1300 bytes stays UDP; a TCP request is untouched).

Mutation proof: deleting the switch reddens the 1301-byte case (a
`*UDPConnection` is returned); `>=` instead of `>` reddens the 1300-byte case.

Upstream status: not filed (owner-side); a re-vendor must re-apply this hunk.

## CF-096: a CANCEL on a live INVITE transaction always drew sipgo's 487

`internal/sipua` now holds an inbound initial INVITE's handler until its server
transaction ends (RFC 3261 17.2.1: retransmissions meet the live transaction,
the ACK of a non-2xx confirms it), so a CANCEL that arrives after the TU has
claimed its final (Answer's 200, Reject's 486) but before writing it matches the
live transaction. Upstream `actCancel` calls the `OnCancel` hook and then
unconditionally builds and sends a 487, which would end the INVITE transaction
under a final the TU had already chosen (probe: a phantom ringing call).

The change: `OnCancel(f func(r *Request) bool)` on the `ServerTransaction`
interface and on `*ServerTx` (its `onCancel` field likewise), and in
`sip/transaction_server_tx_fsm.go` `actCancel` returns `FsmInputNone` without
building the 487 when the hook returns false; the transaction stays in its
state and the TU writes its own final. A nil hook (every other sipgo consumer,
`internal/sipengine` included) and a hook returning true keep upstream's 487.
The hook runs under `fsmMu`, so it must not call `Respond`. `server.go` is not
changed (skipping `Terminate` for INVITE there would change every consumer's
transaction lifetime). Marker `SIPCLIENT-MCP DIVERGENCE (CF-096)` in the
`actCancel` comment.

Test (new file): `sip/transaction_server_tx_cancel_veto_test.go`
(`TestActCancelVetoSuppressesThe487`: a vetoing hook gives no 487, the
transaction stays in Proceeding and a later 200 moves it to Accepted; an allowing
hook gives the 487, Completed and `ErrTransactionCanceled`).

Mutation proof: ignoring the hook's result in `actCancel` reddens the veto
subtest, and in `internal/sipua` reddens
`TestCancelDuringAnswerWriteLetsThe200Win` and
`TestCancelDuringRejectWriteLetsTheRejectWin` (`transaction canceled`).

Upstream status: not filed (owner-side); a re-vendor must re-apply these hunks.

## CF-168: a UDP response over 1300 bytes was refused

`sip/transport_udp.go`, `UDPConnection.WriteMsg`: the 1300-byte refusal
(`UDPMTUSize-200`) applied to every message. RFC 3261 18.1.1 binds that rule to
requests (CF-106 switches those to TCP); a response goes to the request's
source over the same transport and cannot switch, so refusing it simply lost it.
A `*Response` is now capped at `udpMaxDatagramPayload` (65535 - 20 - 8 = 65507,
the maximum datagram less the IPv4 and UDP headers); a request keeps the 1300
refusal as the CF-106 safety net. The error value is unchanged. Marker
`SIPCLIENT-MCP DIVERGENCE (CF-168)`. The CF-106 comment in
`transport_layer.go` `ClientRequestConnection` now says "for a request".

Residual: a response over the path MTU is IP-fragmented; a middlebox that drops
fragments loses it (today it was never sent at all).

Mutation proof: reverting the response branch reddens the first two tests;
`>=` reddens the 65507 case; applying 65507 to requests reddens the request pin.

Upstream status: not filed (owner-side); a re-vendor must re-apply this hunk.

## CF-077: the top Via of a received request got no `received`/`rport`

`sip/transport_layer.go`, `handleMessage` calls the new `stampReceived` for a
`*Request` before the handler loop (the one point every transport's reader
passes): RFC 3261 18.2.1 says the top Via MUST get `received` when its sent-by
is a domain or an IP other than the packet source; RFC 3581 4 says an empty
`rport` MUST be filled with the source port (and `received` added). Every
response built from the request copies the Via. A zoned or unparsable source,
a request without a Via and a response are left alone. The 18.2.1 comment in
`WriteMsgTo` now points at `stampReceived`. Marker
`SIPCLIENT-MCP DIVERGENCE (CF-077)`.

Accepted deviation (owner, Lane F): the response destination stays the packet
source, not the `received` address with the sent-by port (RFC 3261 18.2.2);
sending to a peer-chosen sent-by port is a reflection vector. With `rport` this
is RFC 3581.

`sip/transaction.go`, `makeServerTxKey` (RFC 2543 branch only): the top Via is
written with its parameters in sorted order and without `received` and `rport`.
`HeaderParams` is a map, so the old `Via.StringWrite` varied between a request
and its retransmission as soon as the stamp made two parameters common. RFC 3261
20.42 Via equality is order-free. The RFC 3261 branch (branch, sent-by, method)
is unchanged.

Mutation proof: deleting the stamp call reddens the table test and the sipua
NEWA7 test; unsorting the key reddens the stable-key test; dropping `fillRport`
from the condition reddens the empty-rport case.

Upstream status: not filed (owner-side); a re-vendor must re-apply these hunks.

## CF-081: DNS resolution tried A/AAAA before SRV

`sip/transport_layer.go`: `NewTransportLayer` sets `DNSPreferSRV = true`
(RFC 3263 4.2: a host name without a port is resolved by SRV first, A/AAAA as
fallback). `ClientRequestConnection` passes `uriPortGiven(req)` to `resolveAddr`;
with a port in the target (RFC 3263 4.2) only A/AAAA is used, with
`DNSPreferSRV=false` the upstream order (A/AAAA, SRV on failure) is kept.
`resolveAddrSRV` queries `_sips._tcp` for TLS (was `_sip._tls`) and resolves
the SRV target through `resolveAddrIP` (IPv4 preferred) instead of the first
resolver result. An SRV miss logs at Debug. Marker
`SIPCLIENT-MCP DIVERGENCE (CF-081)`. The default flips for every fork consumer.

Accepted deviation (owner, Lane F): NAPTR (RFC 3263 4.1) is not implemented;
Go's standard library has no NAPTR lookup and a resolver library is a new
dependency.

Residuals, not fixed: no RFC 2782 failover to later SRV records; an SRV target
of `.` falls back to A. (A 16-byte `/etc/hosts` IPv4 result, which `resolveAddrIP`
once resolved to `ips[0]`, was fixed later: see divergence 78, "Release prep:
`resolveAddrIP` missed an IPv4 address held in 16 bytes".)

Mutation proof: default back to false reddens the NEWA11, default and fallback
tests; ignoring `portGiven` reddens the explicit-port test; `"sip"` for TLS
reddens the TLS test.

Upstream status: not filed (owner-side); a re-vendor must re-apply these hunks.

## CF-079: the response to a stream request left on the pool's connection, not the arrival one

RFC 3261 18.2.2: a response to a request over a reliable transport MUST use the
existing connection to the source of the request, "if that connection is still
open". The server transaction took its connection from
`tpl.GetConnection(req.Transport(), req.Source())`, a pool lookup by source
address; when two live connections share the peer address (a peer that dials
from the port it listens on, plus our own dial-back) the pool returns the other
one.

`sip/message.go`: `MessageData` gains `rxConn Connection`, the stream
connection a request was read from (nil for UDP, local messages, responses).
`sip/transport_tcp.go`: `readConnection` passes its `*TCPConnection` to
`parseStream`, which sets `rxConn` on each parsed `*Request` before the handler.
`sip/transaction_layer.go`: `handleRequest` uses `req.rxConn` (with `Ref(1)`, as
the pooled path does) when set, else the pool lookup as before; the 200 to a
CANCEL is written on the CANCEL's own `rxConn` when set. `server.go`:
`defaultUnhandledHandler` answers the 405 with `tx.Respond` (was
`srv.WriteResponse`, a pool lookup). Marker `SIPCLIENT-MCP DIVERGENCE (CF-079)`.

The field is set before `handler(msg)` and read in the goroutine the handler
starts, so the go statement orders it; nothing writes it afterwards.

Accepted behaviour: a connection that closes between parse and dispatch leaves
the transaction on a closed connection (its writes fail, as for any closed
pooled connection); no fallback connection is opened (the 18.2.2 SHOULD).
Residuals: WS/WSS keep the pool lookup; `parseFull` (unused upstream) is not
changed.

Mutation proof: ignoring `rxConn` in `handleRequest` reddens the first test and
the sipua NEWA9 test; dropping the `parseStream` assignment reddens the parse
test; dropping the CANCEL branch reddens the CANCEL test; reverting the
`server.go` hunk reddens the sipua unhandled-method test.

## CF-111: a provisional response stopped a non-INVITE request's retransmission

RFC 3261 17.1.2.2: "If Timer E fires while in the "Proceeding" state, the
request MUST be passed to the transport layer for retransmission, and Timer E
MUST be reset with a value of T2 seconds." Upstream routes a non-INVITE 1xx to
`actPassup`, which stops Timer A (the non-INVITE Timer E), so the
`client_input_timer_a` case of `stateProceeding` was unreachable and a lost
final response was never recovered.

The change, in `sip/transaction_client_tx_fsm.go`: `stateCalling` and
`stateProceeding` route `client_input_1xx` to a new `actPassupProceeding`
(pass up, leave Timer E running), and `stateProceeding`'s `client_input_timer_a`
goes to a new `actResendProceeding` (reset Timer E to T2, resend, with the
CF-050 nil guard). `actPassup`, `actResend` and every INVITE state are
unchanged (`actPassup` still serves `inviteStateProcceeding`, where Timer A was
already stopped). Marker `SIPCLIENT-MCP DIVERGENCE (CF-111)` on both actions.

Tests (new file): `sip/transaction_client_tx_proceeding_test.go`
(`TestNonInviteProceedingRetransmitsAtT2`,
`TestNonInviteFinalInProceedingStopsRetransmission`,
`TestNonInviteReliableProceedingNeverRetransmits`,
`TestInviteProceedingStillStopsTimerA`,
`TestActResendProceedingAfterTerminateDoesNotPanic`).

Mutation proof: routing the 1xx back to `actPassup` reddens the first two;
keeping the doubling in `actResendProceeding` reddens
`TestNonInviteProceedingRetransmitsAtT2` (gaps of 20 ms).

Gate run: `go test github.com/emiago/sipgo/sip` (the fork's full package tree
fails on absent testdata certs before and after), the diff against pristine
v0.24.1 below, and the `internal/sipua` suite.

Upstream status: not filed (owner-side); a re-vendor must re-apply these hunks.

## CF-089: the ACK for a non-2xx final took its Request-URI from the response's Contact

`sip/request.go`, `newAckRequestNon2xx`: RFC 3261 17.1.1.3 says the ACK built by
the client transaction MUST carry the Request-URI of the request it
acknowledges. `NewAckRequest` replaces the Request-URI with the response's
Contact (right for a 2xx ACK, wrong for a 3xx/485 ACK). After calling it,
`newAckRequestNon2xx` sets the ACK's Recipient to a clone of the INVITE's
Recipient. `NewAckRequest` itself is unchanged. Marker
`SIPCLIENT-MCP DIVERGENCE (CF-089)`. Default-on for every consumer
(`internal/sipengine` included): it implements a MUST.

Residual, not fixed: with no Route on the INVITE, `NewAckRequest` still adds
Route headers from the response's Record-Route, which 17.1.1.3 does not ask of
a non-2xx ACK.

Test (new file): `sip/request_ack_non2xx_test.go`
(`TestNewAckRequestNon2xxKeepsTheOriginalRequestURI`,
`TestNewAckRequestNon2xxWithoutContact`,
`TestNewAckRequestNon2xxDoesNotAliasTheInviteURI`).

Mutation proof: removing the override reddens the first test; assigning
without `Clone` reddens the aliasing test.

Upstream status: not filed (owner-side); a re-vendor must re-apply this hunk.

## CF-172: a sips: request with no transport signal defaulted to UDP

`sip/request.go`, `Request.Transport()`: RFC 3261 19.1 / 26.4.2 make a SIPS
target mean TLS. The encrypted-URI upgrade mapped only TCP to TLS and WS to WSS,
so a `sips:` request with no pinned transport, no Via and no `transport` URI
parameter (every request rebuilt without a Via: the 422 retry, redirected legs,
in-dialog requests) reported UDP. When the transport came from the default and
the target (Recipient, or the top Route) is encrypted, the result is now TLS.
A Via, a pinned transport or an explicit parameter still wins, as upstream.
Marker `SIPCLIENT-MCP DIVERGENCE (CF-172)`.

Test (new file): `sip/request_transport_sips_test.go`
(`TestTransportOfASipsRequestWithoutATransportSignalIsTLS`, a table).

Mutation proof: deleting the `defaulted` branch reddens the two default rows;
applying it even with a Via reddens the Via-wins row.

Upstream status: not filed (owner-side); a re-vendor must re-apply this hunk.

## CF-194: a server transaction was deleted when its handler returned

`server.go` `handleRequest` called `tx.Terminate()` after every handler, which
deleted a non-INVITE transaction although `actFinal` had armed Timer J (RFC 3261
17.2.2: re-send the final on a request retransmission until Timer J) and an
INVITE transaction although `actRespondAccept` had armed Timer L (RFC 6026 7.1:
Accepted, 2xx retransmissions and ACKs pass through). A UDP retransmission
created a new transaction and re-ran the handler. New `ServerTx.TerminateAfterHandler`
(`sip/transaction_server_tx.go`) skips the deletion in exactly two cases: a
non-INVITE that passed a final over an unreliable transport (Timer J owns it),
and an INVITE that passed a 2xx, any transport (Timer L owns it); everything
else (reliable transport, no final yet, a non-2xx INVITE final, an ACK-origin
transaction) is deleted at once as before. `server.go` calls it for a
`*sip.ServerTx`, `Terminate()` for any other `ServerTransaction`. `Terminate`
is unchanged. Markers `SIPCLIENT-MCP DIVERGENCE (CF-194)` (one each in
`server.go` and `sip/transaction_server_tx.go`).

Tests (new file): `sip/transaction_server_tx_timerj_test.go`
(`TestTerminateAfterHandlerKeepsACompletedUDPNonInviteUntilTimerJ`,
`...KeepsAnAcceptedInviteUntilTimerL` (UDP and TCP),
`...DeletesAReliableNonInvite`, `...DeletesANonInviteWithoutFinal`,
`...DeletesARejectedInvite`); end to end through the real server in
`internal/sipua/server_tx_timerj_test.go` and
`TestRetransmittedReInviteIsAbsorbedByItsAcceptedTransaction`.

Mutation proof: replacing the call in `server.go` with `Terminate()` reddens the
three wire tests; dropping `!tx.reliable` reddens the reliable guard; keeping
every non-INVITE reddens the no-final guard; keeping every INVITE reddens the
rejected-INVITE guard; disabling the keep branch reddens both keep tests.

Cost (B-D1, accepted): each kept UDP non-INVITE transaction holds about 5 KB for
64*T1 (32 s) and each 2xx'd INVITE the same on any transport; uncapped in this
change (a server-transaction table cap is a candidate follow-up row).

Gate run: `go test -count=1 github.com/emiago/sipgo/sip` and the sipua wire tests
(this section's Tests); fork root package `go test -count=1 -run
'TestUDPUAS|TestTCPUAS' github.com/emiago/sipgo`: ok, 64 s (slow, not red:
`TestUDPUAS` now waits on `<-tx.Done()` for Timer J/L, about 32 s per server
transaction it observes).

Upstream status: not filed (owner-side); a re-vendor must re-apply this hunk.

## CF-212: the transactions CF-194 keeps had no cap

CF-194 keeps a UDP non-INVITE transaction that sent its final until Timer J and
a 2xx'd INVITE until Timer L, each 64*T1 (32 s) and about 5.4 KB, with no
bound: a flood of distinct-branch requests from spoofed sources pinned about
170 MB at 1k req/s, and each kept 2xx'd INVITE also kept its TU's ACK reader.
`TerminateAfterHandler` (`sip/transaction_server_tx.go`) now keeps at most
`maxKeptServerTx` (an unexported constant, 1024), counted in the `keptServerTx`
atomic. Bound: at most 1024 server transactions, process-wide, are alive after
their handler returns; the cap is shared by every UA in the process. Above it a
transaction is deleted at handler return, the pre-CF-194 behaviour: its `Done`
closes at once (so a TU goroutine waiting on it exits), a retransmission of the
request is handled again, and a re-INVITE's 2xx is not retransmitted by the
transaction (if its first 2xx is lost over UDP, the call ends at 64*T1). The
request is never rejected. A kept transaction's `delete` releases its slot
(field `ServerTx.kept`, set and read under `tx.mu`; a transaction already
deleted when its handler returns is not counted). Under the cap nothing
changes. Cap value: following `maxInboundTCPConns` (an unexported constant, no
config), but not its value 50: a kept transaction lives 32 s, so 50 would admit
only about 1.5 kept requests a second; 1024 admits about 32 a second sustained
and bounds the kept set near 5.5 MB. Marker `SIPCLIENT-MCP DIVERGENCE (CF-212)`
(one, `sip/transaction_server_tx.go`).

Tests (new file): `sip/transaction_server_tx_cap_test.go`
(`TestTerminateAfterHandlerCapsKeptTransactions`: with the limit at 2 the third
kept transaction is deleted at handler return, an ACK reader over an over-cap
2xx'd INVITE exits via `Done` well inside Timer L, a delete frees a slot).

Mutation proof: a `terminateAfterHandler` that ignores its limit reddens the
over-cap assertion, and, run alone, the ACK-reader exit assertion.

Gate run: root `go build ./...` and `go vet ./...`: ok; `go test
./internal/importguard/... ./internal/apierr/...`: ok; `git diff --
internal/sipengine/` empty; in this module `go vet` of every package: ok except
the root package, and `go test -race ./...`: `sip` ok except
`TestTransportLayerClientConnectionReuse`, `...NoReuse` and
`TestUDPWriteMsgResponseLimitIsTheDatagramMaximum`, root package setup failed
(`testdata/certs` not vendored), all identical before this change; the
CF-194 and CF-212 tests with `-race -count=3`: ok. `go run ./e2e/loop` not run:
the loop has no scenario with more than 1024 kept transactions.

Upstream status: not filed (owner-side); a re-vendor must re-apply this hunk.

## Release prep: `resolveAddrIP` missed an IPv4 address held in 16 bytes

`resolveAddrIP` (`sip/transport_layer.go`) prefers an IPv4 address, but tested
for it with `len(ip.IP) == net.IPv4len`. Go's resolver returns an IPv4 address
in the 16-byte form for an IPv4-mapped AAAA answer and for a hosts-file line
(the pure-Go resolver, the default on Linux, answers `localhost` from
`/etc/hosts`, sorted `::1` first), so the loop found no IPv4 and took `ips[0]`:
a UA bound to an IPv4 address then sent to `::1` and the write failed
(`address ::1: non-IPv4 address`). The test is now `ip.IP.To4() != nil`; the
chosen address is stored as returned. A 4-byte IPv4 (an ordinary A answer) and
an IPv6-only answer are unchanged. Marker `SIPCLIENT-MCP DIVERGENCE (release
prep, IPv4 preference)` (one, `sip/transport_layer.go`).

Tests (new file): `sip/transport_layer_ipv4_pref_test.go`
(`TestResolveAddrIPPrefersASixteenByteIPv4`: a fake DNS zone with only AAAA
`::1` and `::ffff:127.0.0.9`, so both addresses arrive 16 bytes long and `::1`
sorts first, independent of the host's `/etc/hosts`; the fixture premises are
asserted). RED before the change (`picked ::1, want the IPv4 address`), GREEN
after. End to end: the six `internal/sipua` digest-pin tests that resolve
`localhost` through a pure-Go resolver
(`TestChallengeFromAnUnpinnedSourceIsNotAnswered`,
`TestAnchorResolutionFailureWithholdsCredentials`,
`TestAnchorIsResolvedOncePerUA`, `TestEveryResolvedAddressIsPinned`,
`TestAuthAnyHostSkipsThePin`, `TestTwoSimultaneousFirstChallengesAreBothAnswered`)
failed before and pass after, with `-race`.

Gate run (shared with the next section): root `go build ./...` and `go vet
./...`: ok; `go test -count=1 ./internal/importguard/... ./internal/apierr/...`:
ok; `git diff -- internal/sipengine/` empty; in this module, with
`testdata/certs` generated by `cd testdata && bash ./generate_certs_rsa.sh`:
`go vet` of every package ok except the root package (upstream `lostcancel` in
`dialog_integration_test.go`, unchanged), `go test -race -count=1 ./...`: root
package ok, `sip` ok except `TestUDPWriteMsgResponseLimitIsTheDatagramMaximum`
(the host caps UDP datagrams at 9216 bytes, `net.inet.udp.maxdgram`; unchanged
and expected to pass on Linux). `go run ./e2e/loop` not
run.

Upstream status: not filed (owner-side); a re-vendor must re-apply this hunk.

## Release prep: two transport tests raced under `-race`

`TestTransportLayerClientConnectionReuse` and
`TestTransportLayerClientConnectionNoReuse` (`sip/transport_test.go`) compared
live connections with `require.Equal`/`require.NotEqual`, whose
`reflect.DeepEqual` reads the `net.UDPConn` internals while the connection's
read goroutine updates its fd mutex: the race detector failed both tests on
every platform. The six comparisons are now `require.Same`/`require.NotSame`,
pointer identity, which is what the tests mean (the same connection object is
reused, a different one is created) and is stricter than deep equality. Test
file only; no production code.

Gate run: `go test -race ./sip/ -run
'TestTransportLayerClientConnectionReuse|TestTransportLayerClientConnectionNoReuse'
-count=3`: ok, no race (before: both FAIL, 6 races); the rest as in the
previous section.

Upstream status: not filed (owner-side); a re-vendor must re-apply this hunk.

## Test-only addition

`sip/transaction_client_tx_fsm_guard_test.go` (new file, added — not present
upstream):

- `TestActResendNilTimerADoesNotPanic` — white-box repro: constructs a
  `ClientTx` with a nil `timer_a` and asserts no panic.
- `TestActInviteResendAfterTerminateDoesNotPanic` and
  `TestActResendAfterTerminateDoesNotPanic` (CF-050) — call the REAL
  `actInviteResend` / `actResend` on a `ClientTx` in the post-`delete()` state
  (`done` closed, `timer_a` nil). The copy-based test above cannot redden when
  `actResend`'s real guard is removed; the second of these does.
- `resendGuardForTest` — a test-only method on `ClientTx` (declared in the
  `_test.go` file, so it does not link into non-test builds) that runs
  exactly `actResend`'s timer-management prefix (lock, timer arithmetic,
  guarded `Reset`, unlock) without entering `tx.resend()`'s socket I/O, so the
  guard is exercised deterministically in a unit test.

`sip/parse_address_contact_comma_test.go` (new file, added — not present
upstream):

- `TestParseContactHeaderCommaCombinedKeepsPerContactParams` — drives the real
  `NewParser().ParseSIP` over a REGISTER `200 OK` whose Contact row is
  comma-combined, and asserts each split header carries its OWN `expires`. The
  two multi-contact subcases are ordered mirror images (ours first, ours last)
  so neither a first-wins nor a last-wins parser can satisfy both; the third
  subcase is a single-contact control proving the common path is unchanged.
- `TestParseContactHeaderCommaCombinedDoesNotLeakForeignParams` — the wider
  leak: a `q` param present on only one section must not appear on the other,
  and a quoted comma in a display name must not split the line.

`sip/parse_uri_ipv6_test.go` (new file, added — not present upstream;
Phase 4 M1 B7):

- `TestParseUriIPv6Literal` — table test over 6 bracketed-IPv6 forms (bare
  host+port, a longer literal, no-port, `;uri-params`, `?headers`, and
  userinfo+host+port), asserting `User`/`Host`/`Port` explicitly and that
  `String()` round-trips the exact input.
- `TestParseUriIPv6LiteralFullMessage` — the full-message proof: a real
  `sip.NewParser().ParseSIP` over a response whose `Contact` carries a
  bracketed IPv6 host, asserting the message parses at all and the Contact's
  `Address.Host`/`Port` come out correct.

`sip/parser_stream_headercap_test.go` (new file, added — not present upstream;
Phase 4 W3 P4-W1-N05):

- `TestParseSIPStreamCapsHeaderAccumulation` — drip-feeds 4KB chunks of
  CRLF-free bytes and asserts the parser returns `ErrParseHeaderTooLarge`
  within one chunk of `maxStreamHeaderBuf` AND releases `ParserStream.reader`.
  It is in `package sip` because both the cap constant and the `reader` field
  are unexported, and releasing the buffer is the half an exported-API test
  could not see.
- `TestParseSIPStreamRecoversAfterTheHeaderCap` — reset, not wedge: a
  well-formed `200 OK` fed immediately after the rejection parses normally.
- `TestParseSIPStreamCapDoesNotApplyToTheBody` — a 100000-byte body, its final
  99999 bytes delivered in ONE write, still parses. This passes because that
  second call completes the message successfully inside `parseSingle` and
  never reaches the partial-parse switch arm the cap is checked in at all —
  see the divergence entry above for why an earlier pre-parse-check draft
  failed the equivalent scenario in `internal/sipua`'s
  `TestHardenedParserBoundary`.

`sip/transport_tcp_accept_pool_test.go` (new file, added — not present upstream;
CF-058):

- `TestAcceptedTCPConnectionIsNotPooledUnderTheListenAddress` and
  `TestAcceptedTLSConnectionIsNotPooledUnderTheListenAddress` — a raw client
  dials a served listener; once the accepted connection is pooled under the
  client's address, nothing is pooled under the listener's address.
- `TestOutboundTCPConnectionIsStillPooledUnderBothAddresses` — pin: an outbound
  connection is still found under its local and its remote address.
- `TestClosingAnAcceptedConnectionLeavesTheListenAddressEntryAlone` — another
  connection owns the listen-address key; an accepted connection's exit leaves
  it in place over a 500 ms settle window (the defers run remote key first,
  listen key second, so one check could sample between them).

`sip/transport_layer_via_reuse_test.go` (new file, added — not present upstream;
N1):

- `TestStreamViaKeyHitIsUsedOnlyTowardsItsOwnDestination` (`tcp`, `tls`) — a
  `TransportLayer` serving a listener dials its own listen address (pooled under
  the Via key); a later request with the same Via to a different peer gets a
  connection to that peer and the peer reads its request line; a second request
  to the UA's own address still reuses the Via-key connection (legitimate reuse
  pin).
- `TestUDPViaKeyStillFindsTheListener` — pin: the UDP listener, pooled under its
  local address, is still what the Via lookup returns for any destination.

`sip/transport_layer_writemsg_deadline_test.go` (new file, added — not present
upstream; N2):

- `TestWriteMsgRequestDialIsBoundedByTimerB` — with `Timer_B` set to 200 ms
  (restored at cleanup), `TransportLayer.WriteMsg` of a `;transport=tls` request
  to a listener that accepts TCP and never answers the ClientHello returns an
  error wrapping `context.DeadlineExceeded`; the test fails if it has not
  returned within 5 s.

`sip/transport_tls_handshake_fail_test.go` (new file, added — not present upstream;
CF-066):

- `TestTLSHandshakeFailureClosesTheDialedConnection` — an untrusted-certificate
  handshake failure closes the dialed connection (the server's raw read ends in
  EOF or a reset, not a timeout) and pools nothing.
- `TestTLSHandshakeDeadlineStillClosesTheDialedConnection` — pin: the context
  deadline case is closed too (crypto/tls's own close).

`sip/transport_connection_pool_cad_test.go` (new file, added — not present
upstream; CF-064 part 1):

- `TestCloseAndDeleteLeavesANewerConnectionUnderTheSameKey` — the exiting
  connection is closed and the newer one keeps the key.
- `TestCloseAndDeleteStillRemovesItsOwnEntry` — pin: the own-key delete.
- `TestAnExitingOutboundConnectionKeepsANewerOnesRemoteKey` — the real reader-exit
  path: two outbound connections to one destination, the older one's server side
  closed, the remote key still maps to the newer one. (CF-064 part 2 changed its
  precondition: the second dial is tracked, not pooled, and receives the key when
  the first exits; the final assertion is unchanged.)

`sip/transport_connection_pool_identity_test.go` (new file, added — not present
upstream; CF-069 b/c): `TestAnExitingOutboundConnectionLeavesItsLocalKeyToANewerHolder`
and `TestAnExitingUDPListenerLeavesALearnedAddressToANewerHolder` (real
reader-exit paths), `TestDeleteLeavesAKeyHeldByAnotherConnection`,
`TestDeleteMultipleRemovesOnlyTheConnectionsOwnKeys`,
`TestAddIfNotExistsStoresUnderAFreeKey` and
`TestAddIfNotExistsLeavesAnExistingEntry`.

`sip/transport_connection_pool_unkeyed_test.go` (new file, added — not present
upstream; CF-064 part 2): pool-level tests of `AddOrTrack`, tracking, `Clear`,
promotion (only to a connection that wanted the key and is not closed, chained),
and a pin that readers exiting after `Clear` re-create nothing.

`sip/transport_tcp_listen_port_peer_test.go` (new file, added — not present
upstream; CF-064 part 2; linux build tag): a peer that dials from the port it
listens on keeps its accepted connection's key after our dial-back, the
connection survives our dialed one's exit, and closing the layer closes both.

`sip/transport_udp_response_size_test.go` (new file, added — not present
upstream; CF-168): `TestUDPWriteMsgSendsAResponseOver1300Bytes`,
`TestUDPWriteMsgResponseLimitIsTheDatagramMaximum` and
`TestUDPWriteMsgStillRefusesARequestOver1300Bytes`.

`sip/transport_layer_received_test.go`, `sip/transaction_key_2543_test.go`,
`sip/transport_layer_dns_test.go` (new files, added — not present upstream;
CF-077 and CF-081). The last holds `startFakeDNS`, a stdlib-only UDP DNS server
for `A`, `AAAA` and `SRV` that records the query order.

`sip/transaction_layer_arrival_conn_test.go` (new file, added — not present
upstream; CF-079): `TestServerTxRespondsOnTheArrivalConnection`,
`TestServerTxWithoutArrivalConnectionUsesThePool`,
`TestArrivalConnectionTakesOneReference`,
`TestCancelOKGoesOnTheCancelsArrivalConnection` and
`TestParseStreamTagsRequestsWithTheirConnection`.

## Diff-gate

Re-extracting a pristine `v0.24.1` copy and diffing against this tree
(excluding this file) shows exactly these hunks and no other byte difference
from upstream:

1. `sip/transaction_client_tx_fsm.go` — the P2 W2 one-line nil-guard, and the
   CF-050 nil-guard around `actInviteResend`'s `timer_a.Reset`.
2. `sip/transaction_client_tx_fsm_guard_test.go` — the P2 W2 guard test file
   (new), plus the two CF-050 real-method tests.
3. `ua.go` — P2 W2c B2: `dialEphemeralLocalPort` field,
   `WithDialEphemeralLocalPort()` option, threaded param on the
   `sip.NewTransportLayer(...)` call.
4. `sip/transport_layer.go` — P2 W2c B2: `NewTransportLayer`'s new
   `dialEphemeralLocalPort bool` parameter, set on the `tcp`/`tls`
   transport instances.
5. `sip/transport_tcp.go` — P2 W2c B2: `dialLocalAddr` helper,
   `dialEphemeralLocalPort` field, `dialLocalFor` method,
   `CreateConnection`'s `tladdr` build routed through it.
6. `sip/transport_tls.go` — P2 W2c B2: `CreateConnection`'s independent
   `tladdr` build routed through the same (embedded) `dialLocalFor`.
7. `sip/transport_test.go` — P2 W2c B2 + capture dial-wrap hook: mechanical
   call-site fix, the 4 `NewTransportLayer(...)` calls now pass `false, nil`
   as the two W2c parameters (B2's `false`, this hook's `nil`) —
   same-signature-change fix, not a new divergence category.
8. `sip/transport_b2_localport_test.go` — P2 W2c B2 test file (new).
9. `ua.go` — P2 W2c capture dial-wrap hook: `dialConnWrap` field,
   `WithDialConnWrap(...)` option, threaded as the new 5th param on the
   `sip.NewTransportLayer(...)` call (same file as hunk 3, additive).
10. `sip/transport_layer.go` — P2 W2c capture dial-wrap hook:
    `NewTransportLayer`'s new `dialConnWrap func(net.Conn) net.Conn`
    parameter, set on both the `tcp`/`tls` transport instances (same file as
    hunk 4, additive).
11. `sip/transport_tcp.go` — P2 W2c capture dial-wrap hook: `dialConnWrap`
    field, `createConnection` calling it on the dialed conn before
    `initConnection` (same file as hunk 5, additive).
12. `sip/transport_tls.go` — P2 W2c capture dial-wrap hook:
    `CreateConnection` calling the inherited `dialConnWrap` on the
    post-handshake `tlsConn` before `initConnection` (same file as hunk 6,
    additive).
13. `sip/transport_dialwrap_test.go` — P2 W2c capture dial-wrap hook test
    file (new).
14. `sip/transaction.go` — P2 W3: the `ServerTransaction` interface's new
    `OnCancel` method (additive; `*ServerTx` already implements it,
    `ServerTxRecorder` inherits it via embedding); since CF-096 its signature
    is `OnCancel(f func(r *Request) bool)` and its doc comment states the veto.
15. `sip/transaction_server_tx.go` — P2 W3 (Rule 13 Cycle 3 fix, commit
    `6593687`): `(*ServerTx).OnCancel`'s write of `tx.onCancel` now locks
    `tx.fsmMu` instead of `tx.mu`, matching `actCancel`'s
    (`sip/transaction_server_tx_fsm.go`) existing read of the same field
    under `tx.fsmMu`; since CF-096 the `onCancel` field and the method take a
    `func(r *Request) bool`.
16. `sip/parse_address.go` — P3: `parseContactHeader`'s comma branch now
    narrows `endInd` to the comma index, so each split `ContactHeader` carries
    only its own section's header params.
17. `sip/parse_address_contact_comma_test.go` — P3 comma-combined Contact test
    file (new).
18. `sip/parse_uri.go` — Phase 4 M1 B7: `uriStateHost` gains `[`/`]`
    bracket-awareness (`inBracket` flag), skipping the `:`/`;`/`?` boundary
    checks while inside an IPv6 reference host, at all four exits.
19. `sip/parse_uri_ipv6_test.go` — Phase 4 M1 B7 IPv6-literal test file
    (new).
20. `sip/parse_header.go` — Phase 4 M1 B1: `parseMsgHeader`'s header-parser
    lookup now reads its own receiver (`headersParser[lowerFieldName]`)
    instead of the package-level global `headersParsers`, so a custom map
    passed via `WithHeadersParsers`/`sipgo.WithUserAgentParser` is actually
    consulted.
21. `sip/parser_stream.go` — Phase 4 W3 P4-W1-N05: the `errors` import, the
    `ErrParseHeaderTooLarge` sentinel and `maxStreamHeaderBuf` const replacing
    the file's empty `var ()`, and the bounded-accumulator check on the
    partial-parse path inside `ParseSIPStream`'s outer loop.
22. `sip/parser_stream_headercap_test.go` — Phase 4 W3 P4-W1-N05 header-cap test
    file (new).
23. `sip/transport_tcp.go` — CF-058: `initConnection`'s `accepted` parameter
    (and its comment), the accept path's single pool key, `readConnection`'s
    guarded delete (same file as hunks 5 and 11, additive).
24. `sip/transport_tls.go` — CF-058: the outbound `initConnection` call passes
    `false` (same file as hunks 6 and 12, additive).
25. `sip/transport_tcp_accept_pool_test.go` — CF-058 test file (new).
26. `sip/transport_layer.go` — N1: `ClientRequestConnection`'s Via-key hit on a
    `*TCPConnection` is dropped unless its remote address is the request's
    destination (same file as hunks 4 and 10, additive).
27. `sip/transport_layer_via_reuse_test.go` — N1 test file (new).
28. `sip/transport_layer.go` — N2: `WriteMsgTo`'s request branch dials under a
    `Timer_B` deadline instead of `context.Background()` (same file as hunks 4,
    10 and 26, additive).
29. `sip/transport_layer_writemsg_deadline_test.go` — N2 test file (new).
30. `sip/transport_tls.go` — CF-066: `CreateConnection` closes the dialed
    connection when the handshake fails (same file as hunks 6, 12 and 24,
    additive).
31. `sip/transport_tls_handshake_fail_test.go` — CF-066 test file (new).
32. `sip/transport_connection_pool.go` — CF-064 part 1: `CloseAndDelete` deletes
    its key only while it still maps to the closed connection (and its doc
    comment).
33. `sip/transport_connection_pool_cad_test.go` — CF-064 part 1 test file (new).
34. `sip/transport_connection_pool.go` — CF-069: `AddIfNotExists` and its locked
    helper, identity-checked `Delete` and `DeleteMultiple` (same file as hunk 32).
35. `sip/transport_tcp.go` — CF-069: `readConnection`'s local-key
    `Delete(conn, laddr)`.
36. `sip/transport_udp.go` — CF-069: `Delete(conn, raddr)` and
    `DeleteMultiple(conn, ...)`.
37. `sip/transport_ws.go` — CF-069: `Delete(conn, laddr)`.
38. `sip/transport_connection_pool_identity_test.go` — CF-069 test file (new).
39. `sip/transport_connection_pool.go` — CF-064 part 2: `unkeyed`, `AddOrTrack`,
    `Clear`, `CloseAndDelete` promotion (same file as hunks 32 and 34).
40. `sip/transport_tcp.go` — CF-064 part 2: the outbound `AddOrTrack` (same file
    as hunk 35).
41. `sip/transport_connection_pool_cad_test.go` — CF-064 part 2: the changed
    precondition (same file as hunk 33).
42. `sip/transport_connection_pool_unkeyed_test.go` — CF-064 part 2 test file (new).
43. `sip/transport_tcp_listen_port_peer_test.go` — CF-064 part 2 test file (new).
44. `sip/utils.go` — CF-073: `randInt63`, `RandString` and `RandStringBytesMask`
    on `crypto/rand`, `init` seed deleted, `NonceWrite` compiles against it.
45. `sip/utils_crypto_test.go` — CF-073 test file (new).
46. `sip/transport_wss.go` — CF-069 (a): `CreateConnection` closes the dialed
    connection on the `ParseRequestURI` and `Upgrade` error paths.
47. `sip/transport_wss_upgrade_fail_test.go` — CF-069 (a) test file (new).
48. `sip/transport_tcp.go` — CF-069 (d): `TCPConnection.writeMu`; `Write` sets a
    `Timer_B` deadline per write and closes on `os.ErrDeadlineExceeded` before
    releasing `writeMu` (same
    file as hunks 35 and 40).
49. `sip/transport_tcp_write_deadline_test.go` — CF-069 (d) test file (new).
50. `sip/transport_layer.go` — CF-106: `ClientRequestConnection` switches an
    oversize UDP request to TCP; the 18.1.1 `TODO` in `WriteMsgTo` points to it
    (same file as hunks 4 and others).
51. `sip/transport_layer_size_switch_test.go` — CF-106 test file (new).
52. `sip/transaction_server_tx_fsm.go` — CF-096: `actCancel` returns
    `FsmInputNone` without building the 487 when the `OnCancel` hook returns
    false.
53. `sip/transaction_server_tx_cancel_veto_test.go` — CF-096 test file (new).
54. `sip/transport_udp.go` — CF-168: `udpMaxDatagramPayload` and a response
    branch in `UDPConnection.WriteMsg`'s size check; `sip/transport_layer.go`
    comment only.
55. `sip/transport_udp_response_size_test.go` — CF-168 test file (new).
56. `sip/transport_layer.go` — CF-077: `stampReceived`, called from `handleMessage`; the 18.2.1 comment in `WriteMsgTo` replaced by a pointer.
57. `sip/transaction.go` — CF-077: RFC 2543 branch of `makeServerTxKey` writes the top Via with sorted parameters, without `received`/`rport`.
58. `sip/transport_layer_received_test.go`, `sip/transaction_key_2543_test.go` — CF-077 test files (new).
59. `sip/transport_layer.go` — CF-081: `DNSPreferSRV` default true, `uriPortGiven`, `resolveAddr`'s `portGiven`, `resolveAddrSRV`'s service/proto and IPv4-preferring target lookup (same file as hunk above).
60. `sip/transport_layer_dns_test.go` — CF-081 test file (new).
61. `sip/message.go` — CF-079: `MessageData.rxConn`.
62. `sip/transport_tcp.go` — CF-079: `parseStream` takes the connection and sets `rxConn` on requests (same file as other hunks).
63. `sip/transaction_layer.go` — CF-079: `handleRequest` uses `rxConn` for the server transaction and the CANCEL's 200.
64. `server.go` — CF-079: `defaultUnhandledHandler` responds through the transaction.
65. `sip/transaction_layer_arrival_conn_test.go` — CF-079 test file (new).
66. `sip/transaction_client_tx_fsm.go` — CF-111: non-INVITE `client_input_1xx`
    routed to `actPassupProceeding`, `stateProceeding`'s Timer A case to
    `actResendProceeding`; both actions added (same file as hunk 1).
67. `sip/transaction_client_tx_proceeding_test.go` — CF-111 test file (new).
68. `sip/request.go` — CF-089: `newAckRequestNon2xx` sets the ACK's Recipient to
    a clone of the INVITE's.
69. `sip/request.go` — CF-172: `Request.Transport()` defaults an encrypted
    target with no transport signal to TLS (same file as hunk 68).
70. `sip/request_ack_non2xx_test.go` — CF-089 test file (new).
71. `sip/request_transport_sips_test.go` — CF-172 test file (new).
72. `server.go` — CF-194: `handleRequest` calls `ServerTx.TerminateAfterHandler`.
73. `sip/transaction_server_tx.go` — CF-194: new `ServerTx.TerminateAfterHandler`.
74. `sip/transaction_server_tx_timerj_test.go` — CF-194 test file (new).
75. `sip/parser_stream_test.go` — release prep: removed one SDP payload-type
    line and its format-parameter line from a parser test fixture, and lowered
    the fixture's Content-Length by the 45 bytes removed.
76. `icons/babelforce-logo.png`, `README.md` — release prep: removed a third
    party logo image and the README "Used By" block that referenced it.
77. `sip/transaction_server_tx.go` — CF-212: `maxKeptServerTx`, `keptServerTx`,
    `ServerTx.kept`, `terminateAfterHandler(limit)` behind `TerminateAfterHandler`,
    and the slot release in `delete` (same file as hunks 15 and 73); test file
    `sip/transaction_server_tx_cap_test.go` (new).
78. `sip/transport_layer.go` — release prep: `resolveAddrIP` prefers an IPv4
    address by `To4()`, not by length (same file as hunk 4 and others);
    test file `sip/transport_layer_ipv4_pref_test.go` (new).
79. `sip/transport_test.go` — release prep: the connection-reuse tests compare
    connections by identity (`require.Same`/`require.NotSame`).

See the P2 Wave 2 Task 1 report for the W2 diff output, the P2 Wave 2c
Task 1 report for the B2 diff output, and the P2 Wave 2c Task 5 report for
the capture dial-wrap hook diff output.

## Re-gate obligation

This fork changes the client-transaction FSM used by the whole stack, and
since the P3 divergence below it also changes the **header parser every
inbound message traverses** — which is now the widest-reaching divergence
here. Landing a change requires: full `go build ./...` and `go test ./...`;
`go vet ./...` clean; `go test ./internal/apierr/...` and
`go test ./internal/importguard/...` explicitly; and
`git diff -- internal/sipengine/` empty (this fork touches no file under
`internal/sipengine/`, which is a separate vendored tree, see its own
`VENDOR.md`).

The `go run ./e2e/loop` gate is **per-divergence, not a standing claim about
this file**: the "6/6" above was the result for the divergence that
introduced it, not for every later one. The P3 parser divergence did not run
the loop gate — its blast radius was established by a differential parse
corpus over pristine `v0.24.1` plus the full unit suite, and the loop gate
has no Contact-list scenario that would exercise it. Record the gate you
actually ran alongside each divergence rather than inheriting this line.

## Note on invoking the guard test directly

`third_party/sipgo/go.mod` makes this directory a **nested module** (the
`replace` target must be a module — see the "Upstream `go.mod` floor" row
above). Go's `./...`-style and literal relative-path package patterns
exclude directories that contain their own `go.mod` when resolved from the
parent module, so `go test ./third_party/sipgo/sip/ ...` run from the repo
root fails with "main module does not contain package ...". The equivalent
working invocation, since the `replace` directive resolves the import path
locally, is:

```sh
go test github.com/emiago/sipgo/sip -run 'TestActResendNilTimerADoesNotPanic|TestActInviteResendAfterTerminateDoesNotPanic|TestActResendAfterTerminateDoesNotPanic' -count=200
```

`go test ./...` and `go build ./...` from the repo root are unaffected —
those wildcard patterns simply skip the nested module, and the root module's
own packages resolve `github.com/emiago/sipgo` to this tree via the
`replace` directive as normal.
