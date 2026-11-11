package sipua_test

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
)

// inviteRaw and tryingRaw are the same two fixtures internal/trace's tests
// use. They are duplicated rather than shared: two string constants do not
// justify a testdata package (Rule 15).
const inviteRaw = "INVITE sip:bob@192.0.2.10:5060 SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-1;rport\r\n" +
	"From: <sip:alice@example>;tag=t1\r\n" +
	"To: <sip:bob@example>\r\n" +
	"Call-ID: c-1\r\n" +
	"CSeq: 1 INVITE\r\n" +
	"Max-Forwards: 70\r\n" +
	"Contact: <sip:alice@127.0.0.1:5066>\r\n" +
	"Content-Type: application/sdp\r\n" +
	"Content-Length: 145\r\n\r\n" +
	"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=sipclient-mcp\r\nc=IN IP4 127.0.0.1\r\n" +
	"t=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"

const tryingRaw = "SIP/2.0 100 Trying\r\n" +
	"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-1;rport\r\n" +
	"From: <sip:alice@example>;tag=t1\r\nTo: <sip:bob@example>\r\n" +
	"Call-ID: c-1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"

// authInviteRaw is the digest-retry INVITE HIGH-2 is about
// (internal/sipua/call.go:337 resends d.invite with an Authorization
// header once the peer challenges). username/response/cnonce are the
// credential-bearing params that must never reach the LLM agent via
// call_ladder; realm/nonce/algorithm/nc/qop/uri are kept for debugging.
const authInviteRaw = "INVITE sip:bob@192.0.2.10:5060 SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-2;rport\r\n" +
	"From: <sip:alice@example>;tag=t2\r\n" +
	"To: <sip:bob@example>\r\n" +
	"Call-ID: c-2\r\n" +
	"CSeq: 2 INVITE\r\n" +
	"Max-Forwards: 70\r\n" +
	"Authorization: Digest username=\"alice\", realm=\"sip.example\", nonce=\"abc123\", " +
	"uri=\"sip:bob@sip.example\", response=\"DEADBEEFdigesthash\", cnonce=\"CLIENTNONCE99\", " +
	"nc=00000001, qop=auth, algorithm=MD5\r\n" +
	"Contact: <sip:alice@127.0.0.1:5066>\r\n" +
	"Content-Type: application/sdp\r\n" +
	"Content-Length: 145\r\n\r\n" +
	"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=sipclient-mcp\r\nc=IN IP4 127.0.0.1\r\n" +
	"t=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"

// challengeRaw is a 401 challenge with NONE of the three secret params —
// the required negative control for the challenge-header side: redaction
// must be a no-op here, and "nonce" (not "cnonce") must survive untouched.
const challengeRaw = "SIP/2.0 401 Unauthorized\r\n" +
	"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-2;rport\r\n" +
	"From: <sip:alice@example>;tag=t2\r\nTo: <sip:bob@example>;tag=srv1\r\n" +
	"Call-ID: c-2\r\nCSeq: 2 INVITE\r\n" +
	"WWW-Authenticate: Digest realm=\"sip.example\", nonce=\"srvnonce\", algorithm=MD5\r\n" +
	"Content-Length: 0\r\n\r\n"

// authInfoOKRaw is a 200 OK carrying the SERVER's mutual-auth header
// (RFC 7616 §3.5). rspauth is the server's response digest and must be
// redacted; nextnonce and nc are peer-chosen/counter scaffolding and survive.
// D391 (Rule 13 Cycle 6 completeness pass): before the fix, Authentication-Info
// was not in authHeaderNames and rspauth reached the agent verbatim.
const authInfoOKRaw = "SIP/2.0 200 OK\r\n" +
	"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-2;rport\r\n" +
	"From: <sip:alice@example>;tag=t2\r\nTo: <sip:bob@example>;tag=srv1\r\n" +
	"Call-ID: c-2\r\nCSeq: 2 INVITE\r\n" +
	"Authentication-Info: nextnonce=\"NEXTNONCE7\", rspauth=\"SERVERRSPAUTHff\", " +
	"cnonce=\"CLIENTNONCE99\", nc=00000001, qop=auth\r\n" +
	"Content-Length: 0\r\n\r\n"

// sdesKeyMaterial stands in for a real RFC 4568 SDES key (internal/media/
// srtp.go emits 40 base64 characters for its 16-byte key + 14-byte salt).
// This fixture's exact length doesn't need to match that — the
// placeholder-length and Content-Length assertions below are computed via
// len(sdesKeyMaterial), not hardcoded — only that it is recognizable and
// that redaction removes every instance of it.
const sdesKeyMaterial = "ZmFrZVNSVFBrZXlNYXRlcmlhbEZvclRlc3RpbmcxMjM0"

// sdesInviteRaw is an INVITE offering PCMU with an RFC 4568 SDES crypto
// line, mirroring inviteRaw's shape (this file) but with the a=crypto: line
// internal/media/srtp.go actually emits. Content-Length is computed, not
// hardcoded, so the fixture stays correct if the body above is edited.
var sdesInviteRaw = buildSDESInviteRaw()

func buildSDESInviteRaw() string {
	body := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=sipclient-mcp\r\nc=IN IP4 127.0.0.1\r\n" +
		"t=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n" +
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + sdesKeyMaterial + "\r\n" +
		"a=sendrecv\r\n"
	return "INVITE sip:bob@192.0.2.10:5060 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-3;rport\r\n" +
		"From: <sip:alice@example>;tag=t3\r\n" +
		"To: <sip:bob@example>\r\n" +
		"Call-ID: c-3\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Max-Forwards: 70\r\n" +
		"Contact: <sip:alice@127.0.0.1:5066>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

// sdesInviteNonCanonicalSpacingRaw is the same offer as sdesInviteRaw but
// with a double space before the suite and a tab before "inline:" — RFC
// 4568 permits any whitespace run between an a=crypto: line's fields, and
// internal/media/srtp.go's ParseCryptoAttr (strings.Fields, srtp.go:45)
// accepts exactly this and uses it for real SRTP negotiation. Reuses
// sdesKeyMaterial rather than a new fixture constant (Rule 16).
var sdesInviteNonCanonicalSpacingRaw = buildSDESInviteRawWithSpacing("", "  ", "\t")

// sdesInviteColonDoubleSpaceRaw and sdesInviteColonTabRaw are the Rule 13
// Cycle 6 (finding F1) fixtures: whitespace immediately AFTER the
// "a=crypto:" colon, before the crypto tag, which ParseCryptoAttr's
// TrimSpace -> TrimPrefix -> strings.Fields chain also tolerates but the
// pre-fix sdpCryptoLineRe's `^a=crypto:\S+` anchor did not match at all.
var sdesInviteColonDoubleSpaceRaw = buildSDESInviteRawWithSpacing("  ", " ", " ")
var sdesInviteColonTabRaw = buildSDESInviteRawWithSpacing("\t", " ", " ")

// buildSDESInviteRawWithSpacing builds an sdesInviteRaw-shaped fixture with
// colonSep inserted between "a=crypto:" and the crypto tag, tagSuiteSep
// between the tag and the suite, and suiteInlineSep between the suite and
// "inline:" — every whitespace position ParseCryptoAttr's strings.Fields
// split tolerates, per RFC 4568.
func buildSDESInviteRawWithSpacing(colonSep, tagSuiteSep, suiteInlineSep string) string {
	body := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=sipclient-mcp\r\nc=IN IP4 127.0.0.1\r\n" +
		"t=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n" +
		"a=crypto:" + colonSep + "1" + tagSuiteSep + "AES_CM_128_HMAC_SHA1_80" + suiteInlineSep + "inline:" + sdesKeyMaterial + "\r\n" +
		"a=sendrecv\r\n"
	return "INVITE sip:bob@192.0.2.10:5060 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-4;rport\r\n" +
		"From: <sip:alice@example>;tag=t4\r\n" +
		"To: <sip:bob@example>\r\n" +
		"Call-ID: c-4\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Max-Forwards: 70\r\n" +
		"Contact: <sip:alice@127.0.0.1:5066>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

// sdesKeyMaterial2 is a SECOND, distinct SDES key, used only by
// sdesInviteMultiKeyRaw below to prove a multi-key a=crypto: line redacts
// every key, not just the first.
const sdesKeyMaterial2 = "U2Vjb25kRmFrZVNSVFBLZXlNYXRlcmlhbEZvck1LSTIzNDU"

// sdesInviteMultiKeyRaw is an INVITE whose a=crypto: line carries TWO
// semicolon-separated "inline:" key-params, RFC 4568 §9.1's MKI negotiation
// syntax ("a=crypto:<tag> <suite> inline:<key1>|<lifetime>|<MKI>;inline:
// <key2>|<lifetime>|<MKI>"), plus a trailing non-secret session-param after
// the last key. This is real, specced grammar — internal/media/srtp.go's
// ParseCryptoAttr accepts and uses lines shaped like this for actual SRTP
// negotiation — not a hypothetical: the single-capture regex this fixture
// was added to catch only ever redacted the FIRST "inline:" on a line,
// leaking the second key verbatim.
var sdesInviteMultiKeyRaw = buildSDESInviteMultiKeyRaw()

func buildSDESInviteMultiKeyRaw() string {
	body := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=sipclient-mcp\r\nc=IN IP4 127.0.0.1\r\n" +
		"t=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n" +
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + sdesKeyMaterial + "|2^20|1:4;" +
		"inline:" + sdesKeyMaterial2 + "|2^20|2:4 UNENCRYPTED_SRTCP\r\n" +
		"a=sendrecv\r\n"
	return "INVITE sip:bob@192.0.2.10:5060 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-5;rport\r\n" +
		"From: <sip:alice@example>;tag=t5\r\n" +
		"To: <sip:bob@example>\r\n" +
		"Call-ID: c-5\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Max-Forwards: 70\r\n" +
		"Contact: <sip:alice@127.0.0.1:5066>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

// capturingTap satisfies session.Tap. Only SIPMessage is exercised; the other
// six are present because the interface has SEVEN methods (U7 as amended by
// U18, which added Retain). If this fake is missing one it stops satisfying
// session.Tap and every ObservingConn test below fails to compile.
type capturingTap struct {
	mu   sync.Mutex
	recs []session.SIPRecord
}

func (c *capturingTap) SIPMessage(_ context.Context, rec session.SIPRecord) {
	c.mu.Lock()
	c.recs = append(c.recs, rec)
	c.mu.Unlock()
}

func (c *capturingTap) MediaFrame(context.Context, session.MediaRecord) {}
func (c *capturingTap) Ladder(context.Context, string, string, session.LadderFormat) (session.Ladder, error) {
	return session.Ladder{}, nil
}
func (c *capturingTap) Retain(context.Context, string, string) {}
func (c *capturingTap) Evict(context.Context, string, string)  {}
func (c *capturingTap) ArmCapture(context.Context, string, string, io.WriteCloser, session.CaptureConfig) error {
	return nil
}
func (c *capturingTap) DisarmCapture(context.Context, string, string) (session.CaptureResult, error) {
	return session.CaptureResult{}, nil
}

func (c *capturingTap) all() []session.SIPRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]session.SIPRecord, len(c.recs))
	copy(out, c.recs)
	return out
}

func TestObservingConnRecordsBothDirectionsByteExact(t *testing.T) {
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = inner.Close() }()
	far, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen far: %v", err)
	}
	defer func() { _ = far.Close() }()

	tap := &capturingTap{}
	now := time.Unix(0, 0)
	obs := sipua.ObservingConn(inner, tap, session.TransportUDP, func() time.Time { return now }, "")

	if _, err := obs.WriteTo([]byte(inviteRaw), far.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 65535)
	if err := far.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	n, from, err := far.ReadFrom(buf)
	if err != nil {
		t.Fatalf("far ReadFrom: %v", err)
	}
	// The decorator must be transparent on the wire.
	if string(buf[:n]) != inviteRaw {
		t.Fatal("ObservingConn altered the octets on the wire")
	}
	if _, err := far.WriteTo([]byte(tryingRaw), from); err != nil {
		t.Fatalf("far WriteTo: %v", err)
	}
	if err := obs.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, _, err := obs.ReadFrom(buf); err != nil {
		t.Fatalf("obs ReadFrom: %v", err)
	}

	recs := tap.all()
	if len(recs) != 2 {
		t.Fatalf("tap saw %d records, want 2", len(recs))
	}
	out, in := recs[0], recs[1]
	if out.Direction != session.Outbound || in.Direction != session.Inbound {
		t.Errorf("directions = %q/%q, want outbound/inbound", out.Direction, in.Direction)
	}
	for i, rec := range recs {
		// D9d: UDP is a SEAM-BACKED path, so fidelity is byte_exact.
		if rec.Fidelity != "byte_exact" {
			t.Errorf("record %d: fidelity = %q, want \"byte_exact\" (D9d)", i, rec.Fidelity)
		}
		if rec.Transport != session.TransportUDP {
			t.Errorf("record %d: transport = %q, want %q", i, rec.Transport, session.TransportUDP)
		}
		// The Call-ID demux D9d specifies, and which it notes runs in the
		// tee's favour because a tee is a per-UA object.
		if rec.CallID != "c-1" {
			t.Errorf("record %d: CallID = %q, want \"c-1\"", i, rec.CallID)
		}
		if !rec.At.Equal(now) {
			t.Errorf("record %d: At = %v, want the injected clock's %v", i, rec.At, now)
		}
		if rec.LocalAddr != inner.LocalAddr().String() {
			t.Errorf("record %d: LocalAddr = %q, want %q", i, rec.LocalAddr, inner.LocalAddr())
		}
		// EVERY SCALAR THE RENDERER NEEDS IS EXTRACTED HERE. This is the whole
		// reason ObservingConn lives in sipua: session.SIPRecord carries no
		// sip.Message, because a sip.Message field would make `session` import
		// sipgo — and transport/mcp imports session, so §14.2's
		// transport-boundary test would fail. If any of these is empty, the
		// renderer cannot recover it: it has no parser and no message.
		if rec.Serialized == "" {
			t.Errorf("record %d: Serialized is empty; it is ALWAYS set", i)
		}
		if rec.CSeq == "" {
			t.Errorf("record %d: CSeq was not extracted", i)
		}
		if rec.FromURI == "" || rec.ToURI == "" {
			t.Errorf("record %d: From/To URIs were not extracted (%q/%q)", i, rec.FromURI, rec.ToURI)
		}
		if rec.RemoteAddr == "" {
			t.Errorf("record %d: RemoteAddr was not recorded", i)
		}
	}
	// Requests carry Method with StatusCode 0; responses carry StatusCode and
	// Reason with Method "". That discrimination is the producer's job, because
	// the record has no type to switch on.
	if out.Method != "INVITE" || out.StatusCode != 0 {
		t.Errorf("outbound record = method %q code %d, want INVITE/0", out.Method, out.StatusCode)
	}
	if in.Method != "" || in.StatusCode != 100 || in.Reason != "Trying" {
		t.Errorf("inbound record = method %q code %d reason %q, want \"\"/100/Trying", in.Method, in.StatusCode, in.Reason)
	}
	// The SDP codec list comes off the offer's body, so the renderer never
	// parses SDP either.
	if len(out.SDPCodecs) != 1 || out.SDPCodecs[0] != "PCMU" {
		t.Errorf("outbound SDPCodecs = %v, want [PCMU]", out.SDPCodecs)
	}
	if len(in.SDPCodecs) != 0 {
		t.Errorf("100 Trying carries SDPCodecs %v, want none", in.SDPCodecs)
	}
	// Serialized IS the observed octets on a seam-backed path.
	if out.Serialized != inviteRaw {
		t.Errorf("outbound Serialized is not the observed octets:\n%q", out.Serialized)
	}
	if string(out.Raw) != inviteRaw {
		t.Errorf("outbound Raw is not the observed octets:\n%q", out.Raw)
	}
	if string(in.Raw) != tryingRaw {
		t.Errorf("inbound Raw is not the observed octets:\n%q", in.Raw)
	}
	// Raw must be a COPY: the caller reuses its buffer on the very next read.
	buf[0] = 'X'
	if string(in.Raw) != tryingRaw {
		t.Error("inbound Raw aliases the caller's buffer; it must be copied")
	}
}

func TestObservingConnIgnoresNonSIPDatagrams(t *testing.T) {
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = inner.Close() }()
	far, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen far: %v", err)
	}
	defer func() { _ = far.Close() }()

	tap := &capturingTap{}
	obs := sipua.ObservingConn(inner, tap, session.TransportUDP, time.Now, "")
	for _, junk := range []string{"\x00\x01not sip at all", "\r\n\r\n", ""} {
		if _, err := obs.WriteTo([]byte(junk), far.LocalAddr()); err != nil {
			t.Fatalf("WriteTo(%q): %v", junk, err)
		}
	}
	if got := len(tap.all()); got != 0 {
		t.Errorf("tap recorded %d records for non-SIP datagrams, want 0", got)
	}
}

// TestObservingConnRedactsDigestCredentials is HIGH-2's positive case: the
// digest-retry INVITE's Authorization header must reach the tap with
// response/cnonce/username scrubbed, while realm/nonce/algorithm — needed to
// see that a challenge happened, without exposing anything reusable —
// survive. The distinctive token values (DEADBEEFdigesthash, CLIENTNONCE99,
// username="alice") must not appear anywhere in the captured record.
func TestObservingConnRedactsDigestCredentials(t *testing.T) {
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = inner.Close() }()
	far, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen far: %v", err)
	}
	defer func() { _ = far.Close() }()

	tap := &capturingTap{}
	obs := sipua.ObservingConn(inner, tap, session.TransportUDP, time.Now, "")

	if _, err := obs.WriteTo([]byte(authInviteRaw), far.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1", len(recs))
	}
	rec := recs[0]

	// The real secret VALUES must be gone, from both Serialized and Raw.
	for _, secret := range []string{"DEADBEEFdigesthash", "CLIENTNONCE99", `username="alice"`} {
		if strings.Contains(rec.Serialized, secret) {
			t.Errorf("Serialized still leaks secret %q:\n%s", secret, rec.Serialized)
		}
		if strings.Contains(string(rec.Raw), secret) {
			t.Errorf("Raw still leaks secret %q:\n%s", secret, rec.Raw)
		}
	}
	// The challenge must still be visible for debugging.
	for _, kept := range []string{"Authorization", `realm="sip.example"`, "algorithm=MD5"} {
		if !strings.Contains(rec.Serialized, kept) {
			t.Errorf("Serialized lost %q, want it preserved:\n%s", kept, rec.Serialized)
		}
	}
	// The placeholder must be present for each scrubbed param, keying and
	// quoting shape intact.
	for _, placeholder := range []string{`response="REDACTED"`, `cnonce="REDACTED"`, `username="REDACTED"`} {
		if !strings.Contains(rec.Serialized, placeholder) {
			t.Errorf("Serialized missing %q:\n%s", placeholder, rec.Serialized)
		}
	}
	// THE ONE REAL TRAP: cnonce must be scrubbed but nonce must survive.
	// "cnonce" contains the substring "nonce" — a naive matcher would either
	// fail to redact cnonce or would mangle nonce's value as collateral.
	if !strings.Contains(rec.Serialized, `nonce="abc123"`) {
		t.Errorf("Serialized lost nonce=\"abc123\" (over-redacted the nonce/cnonce boundary?):\n%s", rec.Serialized)
	}
}

// TestObservingConnRedactsSDPCryptoKey is the production-hardening spec's
// Task 2: the SRTP SDES key in the SDP body must never reach call_ladder or
// the pcap artifact, exactly like a digest credential in a header.
func TestObservingConnRedactsSDPCryptoKey(t *testing.T) {
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = inner.Close() }()
	far, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen far: %v", err)
	}
	defer func() { _ = far.Close() }()

	tap := &capturingTap{}
	obs := sipua.ObservingConn(inner, tap, session.TransportUDP, time.Now, "")

	if _, err := obs.WriteTo([]byte(sdesInviteRaw), far.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1", len(recs))
	}
	rec := recs[0]

	if strings.Contains(rec.Serialized, sdesKeyMaterial) {
		t.Errorf("Serialized still leaks the SRTP key:\n%s", rec.Serialized)
	}
	if strings.Contains(string(rec.Raw), sdesKeyMaterial) {
		t.Errorf("Raw still leaks the SRTP key:\n%s", rec.Raw)
	}
	// The suite tag and the rest of the SDP must stay visible — useful for
	// debugging, not secret.
	for _, kept := range []string{"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:", "a=rtpmap:0 PCMU/8000"} {
		if !strings.Contains(rec.Serialized, kept) {
			t.Errorf("Serialized lost %q, want it preserved:\n%s", kept, rec.Serialized)
		}
	}
	wantPlaceholder := "inline:" + strings.Repeat("X", len(sdesKeyMaterial))
	if !strings.Contains(rec.Serialized, wantPlaceholder) {
		t.Errorf("Serialized missing length-preserving placeholder %q:\n%s", wantPlaceholder, rec.Serialized)
	}
	// Length preservation: the redacted message must be the exact same
	// number of bytes as the original, so a redacted TCP/TLS-stream export
	// still frames correctly under Content-Length.
	if len(rec.Serialized) != len(sdesInviteRaw) {
		t.Errorf("redaction changed message length: got %d bytes, want %d (length-preserving redaction)",
			len(rec.Serialized), len(sdesInviteRaw))
	}
}

// TestObservingConnRedactsSDPCryptoKeyWithNonCanonicalWhitespace is the
// Rule 13-review fix for TestObservingConnRedactsSDPCryptoKey's blind spot:
// internal/media/srtp.go's ParseCryptoAttr splits an a=crypto: line via
// strings.Fields, which is tolerant of ANY whitespace run (not just one
// space) between the tag, the suite, and "inline:". A peer sending an
// RFC-legal but non-canonically-spaced line is accepted and used for real
// SRTP negotiation by this codebase, so sdpCryptoInlineRe must redact it
// too — a regex that only matched single literal spaces would fail open on
// exactly this input (locs == nil -> return raw unchanged), leaking the key
// to call_ladder and the pcap artifact.
func TestObservingConnRedactsSDPCryptoKeyWithNonCanonicalWhitespace(t *testing.T) {
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = inner.Close() }()
	far, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen far: %v", err)
	}
	defer func() { _ = far.Close() }()

	tap := &capturingTap{}
	obs := sipua.ObservingConn(inner, tap, session.TransportUDP, time.Now, "")

	if _, err := obs.WriteTo([]byte(sdesInviteNonCanonicalSpacingRaw), far.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1", len(recs))
	}
	rec := recs[0]

	if strings.Contains(rec.Serialized, sdesKeyMaterial) {
		t.Errorf("Serialized still leaks the SRTP key on non-canonical whitespace:\n%s", rec.Serialized)
	}
	if strings.Contains(string(rec.Raw), sdesKeyMaterial) {
		t.Errorf("Raw still leaks the SRTP key on non-canonical whitespace:\n%s", rec.Raw)
	}
	wantPlaceholder := "inline:" + strings.Repeat("X", len(sdesKeyMaterial))
	if !strings.Contains(rec.Serialized, wantPlaceholder) {
		t.Errorf("Serialized missing length-preserving placeholder %q:\n%s", wantPlaceholder, rec.Serialized)
	}
	if len(rec.Serialized) != len(sdesInviteNonCanonicalSpacingRaw) {
		t.Errorf("redaction changed message length: got %d bytes, want %d (length-preserving redaction)",
			len(rec.Serialized), len(sdesInviteNonCanonicalSpacingRaw))
	}
}

// TestObservingConnRedactsAllKeysOnMultiKeyCryptoLine is the Rule 13 Cycle
// 3 fix for a second blind spot in TestObservingConnRedactsSDPCryptoKey:
// RFC 4568 §9.1 allows multiple semicolon-separated key-params on ONE
// a=crypto: line for MKI negotiation, and the original single-capture
// regex (sdpCryptoInlineRe.FindAllSubmatchIndex on the whole message) could
// only ever find the FIRST "inline:" per line, leaking every key after it.
// This also checks the OPPOSITE failure mode the same fix round found: a
// trailing non-secret session-param after the last key must not be swept
// into the redacted span.
func TestObservingConnRedactsAllKeysOnMultiKeyCryptoLine(t *testing.T) {
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = inner.Close() }()
	far, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen far: %v", err)
	}
	defer func() { _ = far.Close() }()

	tap := &capturingTap{}
	obs := sipua.ObservingConn(inner, tap, session.TransportUDP, time.Now, "")

	if _, err := obs.WriteTo([]byte(sdesInviteMultiKeyRaw), far.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1", len(recs))
	}
	rec := recs[0]

	// BOTH keys must be gone — the defect this test exists to catch is the
	// SECOND key leaking while the first is correctly redacted.
	if strings.Contains(rec.Serialized, sdesKeyMaterial) {
		t.Errorf("Serialized still leaks the FIRST SRTP key on a multi-key line:\n%s", rec.Serialized)
	}
	if strings.Contains(rec.Serialized, sdesKeyMaterial2) {
		t.Errorf("Serialized still leaks the SECOND SRTP key on a multi-key line:\n%s", rec.Serialized)
	}
	if strings.Contains(string(rec.Raw), sdesKeyMaterial) || strings.Contains(string(rec.Raw), sdesKeyMaterial2) {
		t.Errorf("Raw still leaks a multi-key line's SRTP key:\n%s", rec.Raw)
	}
	// The suite tag, each key's own |lifetime|MKI suffix, and the trailing
	// session-param after the LAST key must all stay visible — not secret,
	// useful for debugging, and NOT part of either key's redacted span.
	for _, kept := range []string{
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:",
		"|2^20|1:4;inline:",
		"|2^20|2:4 UNENCRYPTED_SRTCP",
	} {
		if !strings.Contains(rec.Serialized, kept) {
			t.Errorf("Serialized lost %q, want it preserved:\n%s", kept, rec.Serialized)
		}
	}
	wantPlaceholder1 := "inline:" + strings.Repeat("X", len(sdesKeyMaterial)) + "|2^20|1:4;"
	wantPlaceholder2 := "inline:" + strings.Repeat("X", len(sdesKeyMaterial2)) + "|2^20|2:4"
	if !strings.Contains(rec.Serialized, wantPlaceholder1) {
		t.Errorf("Serialized missing length-preserving placeholder for the FIRST key %q:\n%s", wantPlaceholder1, rec.Serialized)
	}
	if !strings.Contains(rec.Serialized, wantPlaceholder2) {
		t.Errorf("Serialized missing length-preserving placeholder for the SECOND key %q:\n%s", wantPlaceholder2, rec.Serialized)
	}
	if len(rec.Serialized) != len(sdesInviteMultiKeyRaw) {
		t.Errorf("redaction changed message length: got %d bytes, want %d (length-preserving redaction)",
			len(rec.Serialized), len(sdesInviteMultiKeyRaw))
	}
}

// TestObservingConnRedactsSDPCryptoKeyWithWhitespaceAfterColon is the Rule 13
// Cycle 6 fix (finding F1) for a THIRD blind spot in the a=crypto: redaction
// family, distinct from both TestObservingConnRedactsSDPCryptoKeyWithNonCanonicalWhitespace
// (whitespace BETWEEN fields) and TestObservingConnRedactsAllKeysOnMultiKeyCryptoLine
// (multiple keys on one line): whitespace immediately AFTER the "a=crypto:"
// colon, BEFORE the crypto tag. internal/media/sdp.go's SDP line capture is a
// bare strings.HasPrefix(line, "a=crypto:") with no field-shape check, and
// internal/media/srtp.go's ParseCryptoAttr does TrimSpace ->
// TrimPrefix("a=crypto:") -> strings.Fields — tolerant of ANY whitespace run
// right after the colon, not just further along the line — so a peer
// sending "a=crypto:  1 ..." (double space) or "a=crypto:\t1 ..." (tab) gets
// its key parsed and used for real SRTP negotiation. The pre-fix
// sdpCryptoLineRe anchor (`^a=crypto:\S+`) demanded a non-space character
// immediately after the colon and so failed to match either line at all,
// leaking the key verbatim into call_ladder output and pcap artifacts.
func TestObservingConnRedactsSDPCryptoKeyWithWhitespaceAfterColon(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"double space after colon", sdesInviteColonDoubleSpaceRaw},
		{"tab after colon", sdesInviteColonTabRaw},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = inner.Close() }()
			far, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen far: %v", err)
			}
			defer func() { _ = far.Close() }()

			tap := &capturingTap{}
			obs := sipua.ObservingConn(inner, tap, session.TransportUDP, time.Now, "")

			if _, err := obs.WriteTo([]byte(tc.raw), far.LocalAddr()); err != nil {
				t.Fatalf("WriteTo: %v", err)
			}

			recs := tap.all()
			if len(recs) != 1 {
				t.Fatalf("tap saw %d records, want 1", len(recs))
			}
			rec := recs[0]

			if strings.Contains(rec.Serialized, sdesKeyMaterial) {
				t.Errorf("Serialized still leaks the SRTP key with whitespace after the colon:\n%s", rec.Serialized)
			}
			if strings.Contains(string(rec.Raw), sdesKeyMaterial) {
				t.Errorf("Raw still leaks the SRTP key with whitespace after the colon:\n%s", rec.Raw)
			}
			wantPlaceholder := "inline:" + strings.Repeat("X", len(sdesKeyMaterial))
			if !strings.Contains(rec.Serialized, wantPlaceholder) {
				t.Errorf("Serialized missing length-preserving placeholder %q:\n%s", wantPlaceholder, rec.Serialized)
			}
			if len(rec.Serialized) != len(tc.raw) {
				t.Errorf("redaction changed message length: got %d bytes, want %d (length-preserving redaction)",
					len(rec.Serialized), len(tc.raw))
			}
		})
	}
}

// TestObservingConnChallengeHeaderNoSecretsIsNoOp is the required negative
// control on the challenge side: a WWW-Authenticate header carrying none of
// the three secret params must come through byte-identical, proving
// redaction is a no-op absent a secret param and that "nonce" is never
// mistaken for "cnonce".
func TestObservingConnChallengeHeaderNoSecretsIsNoOp(t *testing.T) {
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = inner.Close() }()
	far, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen far: %v", err)
	}
	defer func() { _ = far.Close() }()

	tap := &capturingTap{}
	obs := sipua.ObservingConn(inner, tap, session.TransportUDP, time.Now, "")

	if _, err := far.WriteTo([]byte(challengeRaw), inner.LocalAddr()); err != nil {
		t.Fatalf("far WriteTo: %v", err)
	}
	buf := make([]byte, 65535)
	if err := obs.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, _, err := obs.ReadFrom(buf); err != nil {
		t.Fatalf("obs ReadFrom: %v", err)
	}

	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Serialized != challengeRaw {
		t.Errorf("Serialized = %q, want byte-identical challengeRaw (no secret params -> no-op)", rec.Serialized)
	}
	if string(rec.Raw) != challengeRaw {
		t.Errorf("Raw is not byte-identical to challengeRaw")
	}
	if !strings.Contains(rec.Serialized, `nonce="srvnonce"`) {
		t.Errorf("Serialized lost the server nonce (over-redacted?):\n%s", rec.Serialized)
	}
}

// TestObservingConnRedactsAuthenticationInfoRspauth is D391: the server's
// mutual-auth rspauth (a digest of the shared secret) reaching the agent via
// call_ladder is a partial offline-attack oracle. It must be redacted; the
// non-secret nextnonce/nc scaffolding must survive.
func TestObservingConnRedactsAuthenticationInfoRspauth(t *testing.T) {
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = inner.Close() }()
	far, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen far: %v", err)
	}
	defer func() { _ = far.Close() }()

	tap := &capturingTap{}
	obs := sipua.ObservingConn(inner, tap, session.TransportUDP, time.Now, "")

	if _, err := far.WriteTo([]byte(authInfoOKRaw), inner.LocalAddr()); err != nil {
		t.Fatalf("far WriteTo: %v", err)
	}
	buf := make([]byte, 65535)
	if err := obs.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, _, err := obs.ReadFrom(buf); err != nil {
		t.Fatalf("obs ReadFrom: %v", err)
	}

	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1", len(recs))
	}
	rec := recs[0]

	// The server's response digest AND the client nonce must be gone, from
	// both Serialized and Raw.
	for _, secret := range []string{"SERVERRSPAUTHff", "CLIENTNONCE99"} {
		if strings.Contains(rec.Serialized, secret) {
			t.Errorf("Serialized still leaks %q:\n%s", secret, rec.Serialized)
		}
		if strings.Contains(string(rec.Raw), secret) {
			t.Errorf("Raw still leaks %q:\n%s", secret, rec.Raw)
		}
	}
	// The placeholder must be present with keying/quoting intact.
	for _, placeholder := range []string{`rspauth="REDACTED"`, `cnonce="REDACTED"`} {
		if !strings.Contains(rec.Serialized, placeholder) {
			t.Errorf("Serialized missing %q:\n%s", placeholder, rec.Serialized)
		}
	}
	// Non-secret scaffolding survives: nextnonce (peer-chosen) and the header
	// itself, so a challenge/response remains debuggable.
	for _, kept := range []string{"Authentication-Info", `nextnonce="NEXTNONCE7"`, "nc=00000001"} {
		if !strings.Contains(rec.Serialized, kept) {
			t.Errorf("Serialized lost %q, want it preserved:\n%s", kept, rec.Serialized)
		}
	}
}

func TestObservingConnIsRaceFreeAcrossDirections(t *testing.T) {
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = inner.Close() }()
	far, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen far: %v", err)
	}
	defer func() { _ = far.Close() }()

	tap := &capturingTap{}
	obs := sipua.ObservingConn(inner, tap, session.TransportUDP, time.Now, "")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _ = obs.WriteTo([]byte(inviteRaw), far.LocalAddr())
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		_ = obs.SetReadDeadline(time.Now().Add(2 * time.Second))
		for i := 0; i < 200; i++ {
			if _, _, err := obs.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	// Echo back so the read side has traffic.
	go func() {
		buf := make([]byte, 65535)
		_ = far.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			n, from, err := far.ReadFrom(buf)
			if err != nil {
				return
			}
			_ = n
			_, _ = far.WriteTo([]byte(tryingRaw), from)
		}
	}()
	wg.Wait()
}
