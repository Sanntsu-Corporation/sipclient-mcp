package sipua

import (
	"bytes"
	"context"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// observingConn wraps a net.PacketConn so every datagram read or written is
// observed AT THE SOCKET: below sipgo's parser on the read path
// (sip/transport_udp.go:175-213, 391-399, before parseAndHandle) and after
// sipgo's final serialisation on the write path (:411, :448). That is D9d's
// UDP seam — the caller-supplied net.PacketConn handed to Server.ServeUDP,
// which Task 13 already constructs.
//
// IT LIVES IN sipua, NOT trace (contract Part 1.3). sipua already owns the
// socket, already owns the §3d concrete-bind constraint the seam depends on,
// and already imports sipgo. Putting it here removes BOTH of trace's problem
// edges at once — sipgo and sipua — leaving internal/trace a pure renderer
// over session.SIPRecord whose three renderers are testable against
// hand-built records.
//
// The WIRING layer composes it into sipua.Config.WrapConn:
//
//	cfg.WrapConn = func(pc net.PacketConn) net.PacketConn {
//		return sipua.ObservingConn(pc, sink, session.TransportUDP, clk.Now)
//	}
//
// Because WrapConn is a DECORATOR over a conn sipua has already bound to a
// concrete address, no caller can substitute a wildcard-bound socket and
// silently defeat the tap.
//
// Per-call attribution parses each datagram far enough to read its Call-ID —
// the demux D9d specifies, and which D9d notes runs IN THE TEE'S FAVOUR,
// because a tee is a per-UA object and demultiplexes only among that UA's
// calls rather than across every call on the server. A datagram that does not
// parse as SIP is not recorded: it is not a SIP message and has no place in a
// SIP ladder.
//
// sip.Parser is not documented as goroutine-safe and ReadFrom and WriteTo run
// on different goroutines, so the conn holds ONE PARSER PER DIRECTION, each
// used by exactly one goroutine. No lock is required and none is added — the
// affinity IS the synchronisation, the same reasoning O2 applies to
// srtp.Context.
type observingConn struct {
	net.PacketConn
	tap         session.Tap
	transport   session.Transport
	uaHandle    string
	now         func() time.Time
	readParser  *sip.Parser
	writeParser *sip.Parser
}

// ObservingConn wraps inner so every datagram read or written is observed and
// handed to tap as a fully-populated session.SIPRecord. now defaults to
// time.Now when nil.
//
// uaHandle is the owning UA's handle (HIGH-3). This decorator is a PER-UA
// object, so every record it produces carries exactly one UA identity, which
// the sink uses to namespace the peer-chosen Call-ID — without it a peer
// handing two UAs the same Call-ID would collide their ladders. It is stamped
// into SIPRecord.UAHandle; "" is a valid value that reproduces the old
// per-Call-ID keying for a tap wired without a handle.
func ObservingConn(inner net.PacketConn, tap session.Tap, transport session.Transport, now func() time.Time, uaHandle string) net.PacketConn {
	if now == nil {
		now = time.Now
	}
	return &observingConn{
		PacketConn:  inner,
		tap:         tap,
		transport:   transport,
		uaHandle:    uaHandle,
		now:         now,
		readParser:  sip.NewParser(),
		writeParser: sip.NewParser(),
	}
}

func (c *observingConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, addr)
	if err == nil && n > 0 {
		c.observe(c.writeParser, session.Outbound, b[:n], addr)
	}
	return n, err
}

func (c *observingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil && n > 0 {
		c.observe(c.readParser, session.Inbound, b[:n], addr)
	}
	return n, addr, err
}

// authHeaderNames are the header names (lower-cased) whose value may carry
// digest-auth params. HIGH-2: on a 401/407 challenge, DoRequestWithDigest
// resends the call's INVITE with an Authorization header carrying the
// credential, and the tap hands the byte-exact wire octets to a
// semi-trusted, possibly prompt-injected LLM agent via call_ladder. Redact
// here, at the producer, so every consumer (call_ladder AND P2's pcap
// writer, which reads Raw) inherits the fix instead of each needing its own.
var authHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"www-authenticate":    true,
	"proxy-authenticate":  true,
	// authentication-info is the SERVER's mutual-auth header on a 200 OK
	// (RFC 7616 §3.5): its rspauth is a digest derived from the shared
	// secret. On its own it is not the password, but combined with the
	// nonce/nc it is a partial offline-attack oracle — and the tap hands it
	// to the same semi-trusted agent as the request-side credential. Redact
	// rspauth (below) here too (Rule 13 Cycle 6 completeness pass, D391).
	"authentication-info": true,
}

// redactSecretParamRe matches response=, cnonce=, username= and rspauth= —
// the digest params that carry credential material (the client's digest hash,
// the client nonce, the identity, and — on the server's Authentication-Info
// mutual-auth header — the SERVER's response digest), each written as
// `param="value"` per RFC 7616. realm, nonce, nextnonce, algorithm, nc, qop,
// uri and opaque are peer-chosen or non-secret protocol scaffolding (useful
// for debugging: that a challenge occurred, the realm, the hash algorithm)
// and are left untouched.
//
// (?i) makes the param name match case-insensitively. \b anchors both ends
// of the alternation on a word boundary, which is what keeps "nonce" from
// being mistaken for the tail of "cnonce": \b only matches where a word
// character meets a non-word character (or string edge), and the 'c'
// immediately before "nonce" in "cnonce" is itself a word character, so
// \bnonce\b cannot match inside "cnonce" — while \bcnonce\b matches the
// whole word correctly.
var redactSecretParamRe = regexp.MustCompile(`(?i)\b(response|cnonce|username|rspauth)(\s*=\s*)"[^"]*"`)

// redactAuthHeaders scrubs response/cnonce/username/rspauth out of
// Authorization/Proxy-Authorization/WWW-Authenticate/Proxy-Authenticate/
// Authentication-Info header lines in raw, replacing each value with the fixed placeholder
// REDACTED and keeping the param key and quoting shape (e.g.
// response="REDACTED"). It operates line-by-line on \r\n-delimited raw SIP
// bytes; a header's name is the token before its first ':', trimmed and
// lower-cased.
//
// The same scrub runs on all four header names, even though a well-formed
// WWW-Authenticate/Proxy-Authenticate challenge never carries these three
// params: on a genuine challenge this is a no-op (the challenge stays
// byte-identical, keeping its byte_exact fidelity honest), and it defends
// against a malicious peer reflecting a response=/username= into a
// challenge header.
//
// No-op when no secret param is present: a message with no auth header, or
// a header with none of the three params, comes back byte-identical to raw.
// That is required — observe_test.go and render_test.go assert
// Serialized/Raw are byte-identical to non-auth fixtures.
func redactAuthHeaders(raw []byte) []byte {
	lines := strings.Split(string(raw), "\r\n")
	changed := false
	for i, line := range lines {
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:colon]))
		if !authHeaderNames[name] {
			continue
		}
		if scrubbed := redactSecretParamRe.ReplaceAllString(line, `$1$2"REDACTED"`); scrubbed != line {
			lines[i] = scrubbed
			changed = true
		}
	}
	if !changed {
		return raw
	}
	return []byte(strings.Join(lines, "\r\n"))
}

// sdpCryptoLineRe matches one whole RFC 4568 SDES a=crypto: attribute line
// ("a=crypto:<tag> <suite> <key-param>[;<key-param>]..."). (?m) anchors ^
// and $ at line boundaries, which is what lets this match a body line
// regardless of whether the SDP uses CRLF or bare-LF line endings —
// internal/media/sdp.go's own parser tolerates both, so a peer sending
// bare-LF body lines must not get a free pass on this redaction. \s+ (not a
// single literal space) between the tag and the suite matches
// internal/media/srtp.go's ParseCryptoAttr, which splits via
// strings.Fields — tolerant of any whitespace run, not just one space — so
// an RFC-legal but non-canonically-spaced line (double space, a tab) that
// ParseCryptoAttr accepts and uses for real SRTP negotiation cannot slip
// past this redaction unmatched. $ (not \r?$ or similar) stops before a
// trailing \r on a CRLF line, matching (?m)'s own line-ending handling. No
// new SDP grammar beyond what internal/media/sdp.go parses.
//
// \s* (not a bare colon) immediately after "a=crypto:" is the Rule 13 Cycle
// 6 fix (finding F1) for a THIRD blind spot in this same family: this line
// is only ever reached via internal/media/sdp.go's bare
// strings.HasPrefix(line, "a=crypto:") capture, with no field-shape check,
// and ParseCryptoAttr itself does TrimSpace -> TrimPrefix("a=crypto:") ->
// strings.Fields — which tolerates ANY whitespace run between the colon and
// the crypto tag, not just the whitespace already tolerated further along
// the line. A peer sending "a=crypto:  1 ..." (double space) or
// "a=crypto:\t1 ..." (tab) right after the colon is accepted and used for
// real SRTP negotiation, but the old `^a=crypto:\S+` anchor demanded a
// non-space character immediately after the colon and so failed to match
// the line at all, leaking the key verbatim.
var sdpCryptoLineRe = regexp.MustCompile(`(?m)^a=crypto:\s*\S+\s+\S+\s+\S.*$`)

// sdpCryptoInlineRe matches ONE "inline:<key>" occurrence within an
// already-isolated a=crypto: line (see redactSDPCrypto), capturing the key
// material up to the first "|", ";", whitespace, or line end. RFC 4568 §9.1
// allows a line to carry MULTIPLE semicolon-separated key-params for MKI
// negotiation ("inline:KEY1|2^20|1:4;inline:KEY2|2^20|2:4") — a REAL,
// specced shape, not a hypothetical — so this is applied per-line via
// FindAllSubmatchIndex rather than matching only the first "inline:". It
// also stops at whitespace, not just "|"/";", so a trailing non-secret
// session-param on the same line after the last key (e.g.
// "inline:KEY UNENCRYPTED_SRTCP") is not swept into the "secret" capture —
// only the key material itself is redacted, matching this function's own
// doc comment that everything else on the line stays visible.
var sdpCryptoInlineRe = regexp.MustCompile(`inline:([^|;\s\r\n]+)`)

// redactSDPCrypto replaces every "inline:<key>" occurrence's base64 key
// material, on every a=crypto: line, with same-length 'X' placeholders,
// leaving the crypto-suite tag, each key's own |lifetime|MKI:... suffix,
// and any trailing session-param visible (not secret, useful for
// debugging). Same-length replacement keeps a redacted message's total byte
// length — and therefore its Content-Length framing — unchanged, with no
// separate rewrite step. Covers both directions: the daemon's own generated
// offers/answers carry this line as much as a parsed peer SDP does, and
// this runs on every observed message regardless of direction.
//
// TWO-STAGE, NOT ONE REGEX. sdpCryptoLineRe first isolates each whole
// a=crypto: line, then sdpCryptoInlineRe is re-run WITHIN that line's byte
// range to redact every "inline:" key it contains — one or more, per RFC
// 4568 §9.1's MKI multi-key syntax above. A single combined regex can only
// ever capture the FIRST "inline:" per line (regexp does not repeat a
// capture group), which used to leave the second and later keys on a
// multi-key line unredacted.
func redactSDPCrypto(raw []byte) []byte {
	lineLocs := sdpCryptoLineRe.FindAllIndex(raw, -1)
	if lineLocs == nil {
		return raw
	}
	var out []byte
	last := 0
	for _, lineLoc := range lineLocs {
		lineStart, lineEnd := lineLoc[0], lineLoc[1]
		for _, keyLoc := range sdpCryptoInlineRe.FindAllSubmatchIndex(raw[lineStart:lineEnd], -1) {
			keyStart, keyEnd := lineStart+keyLoc[2], lineStart+keyLoc[3]
			out = append(out, raw[last:keyStart]...)
			out = append(out, bytes.Repeat([]byte("X"), keyEnd-keyStart)...)
			last = keyEnd
		}
	}
	out = append(out, raw[last:]...)
	return out
}

// redactWireSecrets is the one entry point both observe.go's UDP producer
// and observestream.go's TCP/TLS producer call before assigning the
// redacted bytes to SIPRecord.Serialized/Raw — the single place that scrubs
// every wire secret this codebase knows about (digest-auth header params,
// SRTP SDES key material) so call_ladder and the pcap writer both inherit
// the fix from one producer (Rule 16/18 reuse, no new call site per secret
// class). redactAuthHeaders keeps its own name and behavior unchanged; this
// only composes it with the newer SDP-body pass.
func redactWireSecrets(raw []byte) []byte {
	raw = redactAuthHeaders(raw)
	return redactSDPCrypto(raw)
}

func (c *observingConn) observe(parser *sip.Parser, dir session.Direction, wire []byte, remote net.Addr) {
	if c.tap == nil || len(wire) == 0 {
		return
	}
	// Copy: the caller reuses its buffer on the very next read.
	raw := make([]byte, len(wire))
	copy(raw, wire)

	msg, err := parser.ParseSIP(raw)
	if err != nil || msg == nil {
		return
	}
	remoteStr := ""
	if remote != nil {
		remoteStr = remote.String()
	}

	// HIGH-2: redact credential-bearing digest params AFTER parsing (msg's
	// header values were already extracted from the pristine bytes above)
	// but BEFORE building the record, so only the copy that becomes
	// Serialized/Raw is scrubbed. This never touches the socket: WriteTo and
	// ReadFrom above already completed against the real wire bytes.
	raw = redactWireSecrets(raw)

	// EXTRACT EVERY SCALAR THE RENDERER NEEDS, HERE. session.SIPRecord carries
	// no sip.Message and MUST NOT gain one: `session` would then import sipgo,
	// transport/mcp imports `session`, and §14.2's transport-boundary test
	// would fail. This is the load-bearing consequence of Part 1.3, and it is
	// forced rather than preferred.
	rec := session.SIPRecord{
		At:         c.now(),
		Direction:  dir,
		Transport:  c.transport,
		LocalAddr:  c.PacketConn.LocalAddr().String(),
		RemoteAddr: remoteStr,
		// HIGH-3: the owning UA handle namespaces the peer-chosen Call-ID in
		// the sink's keyspace, so an identical Call-ID reaching two UAs cannot
		// merge their ladders.
		UAHandle: c.uaHandle,
		// THE SAME VALUE, FROM THE SAME SOURCE, as dialog.callID — the SIP
		// Call-ID header, read verbatim. That identity is load-bearing: it is
		// the key session.Call hands to Tap.Ladder and Tap.Evict. If the tap
		// derived it differently from the value DialResult/UAEvent carried, the
		// ladder would key on one string while its records carried another and
		// call_ladder would return an empty ladder with nothing to explain it.
		CallID: headerValue(msg, "Call-ID"),
		CSeq:   headerValue(msg, "CSeq"),
		// FromURI/ToURI carry the RAW header value — e.g.
		// "<sip:alice@example>;tag=t1" — not a bare "sip:alice@example" URI
		// (D168): sipgo's Header.Value() returns the header's full field
		// value, name-addr wrapper and params included, and this producer
		// does not strip it. internal/trace's uriUser is the only consumer
		// and already cuts on "sip:" then "@", which survives both shapes.
		FromURI:   headerValue(msg, "From"),
		ToURI:     headerValue(msg, "To"),
		SDPCodecs: sdpCodecNames(msg.Body()),
		// D9d, NORMATIVE: UDP is a seam-backed path, so Serialized IS the
		// octets the socket actually read or wrote, Raw holds the same bytes
		// for P2's pcap writer, and fidelity is byte_exact. This is exactly the
		// point the roadmap's "(D9d canonical form)" note gets wrong (handoff
		// §6b item 6).
		Serialized: string(raw),
		Raw:        raw,
		Fidelity:   "byte_exact",
	}
	// Request or response: the record has no type to switch on, so the producer
	// decides by setting Method OR StatusCode/Reason, never both.
	switch m := msg.(type) {
	case *sip.Request:
		rec.Method = string(m.Method)
	case *sip.Response:
		// m.StatusCode is sip.StatusCode (type StatusCode int), not a plain
		// int — session.SIPRecord.StatusCode is int, so this needs an
		// explicit conversion. Found by probe; not one of M1-M8 but the same
		// class of defect (a type the plan text did not compile-check).
		rec.StatusCode, rec.Reason = int(m.StatusCode), m.Reason
	}
	c.tap.SIPMessage(daemonCtx(), rec)
}

// headerValue reads a single header's value off msg, or "" if absent.
//
// sip.Message declares GetHeaders(name string) []Header, NOT a singular
// GetHeader (sipgo v0.24.1's Message interface, sip/message.go:91-97):
// GetHeader exists only on the unexported embedded headers struct and is not
// promoted through the interface.
//
// Rule 16 reuse (Correction 13) delegated this to headerValues
// (sessiontimer.go), the canonical multi-value walk — but that regressed this
// function's allocation count (AllocsPerRun) on the observability hot path
// this is called from (every observed SIP message): 1 alloc/call, matching
// the original pre-Correction-13 implementation (`hs := msg.GetHeaders(name);
// return hs[0].Value()`, git history), became 2 — headerValues' own `out`
// slice on top of the one allocation already inherent to crossing the
// sip.Message interface via GetHeaders (sipgo's GetHeaders always builds a
// fresh []Header via append, even for a single match — see
// observe_internal_test.go's TestHeaderValueHasMinimalAllocationsAndIsCorrect
// for the measured numbers). headerValues' contract is fundamentally wider than this
// caller needs: it walks and collects EVERY value into a fresh slice so a
// repeated/comma-joined header is never missed, which is the right (and only)
// correct behaviour for its ten multi-value callers, but is pure waste for a
// function that only ever wants the first one. C-M3 reverts to a direct
// single-value walk instead: this is a narrower, different contract
// (first-value-or-empty) on a hot path, not a duplicate of headerValues'
// multi-value one, so keeping it separate is not a Rule 16/18 violation.
func headerValue(msg sip.Message, name string) string {
	for _, h := range msg.GetHeaders(name) {
		return h.Value()
	}
	return ""
}

// daemonCtx returns the context every tap call is made on. The tap is a
// sink, not a request handler, so it gets the DAEMON-scoped background
// context and never a request context: a client disconnect must not stop the
// ladder recording for a call that is still live.
func daemonCtx() context.Context { return context.Background() }
