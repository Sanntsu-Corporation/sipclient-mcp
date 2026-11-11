package sip

// parser_stream_headercap_test.go — Phase 4 W3, P4-W1-N05.
//
// NEW FILE, NOT PRESENT UPSTREAM. It pins the header-accumulation cap
// ParseSIPStream gained as this fork's 8th sanctioned divergence (VENDOR.md).
//
// IT LIVES IN package sip, not sip_test, because both properties that matter
// are unexported: the cap constant itself, and ParserStream.reader — the field
// whose unbounded growth IS the defect, and whose release is what proves the
// fix does not merely error out while still holding the memory.

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseSIPStreamCapsHeaderAccumulation is the security property. A peer that
// completes the TCP/TLS handshake and then drip-feeds bytes containing no CRLF
// at all must be cut off at maxStreamHeaderBuf. Upstream v0.24.1 accumulates
// forever (measured live before the fix: 32MB fed in, 32MB retained), because
// the ErrParseLineNoCRLF path writes the whole unparsed remainder back into the
// buffer and waits for more.
func TestParseSIPStreamCapsHeaderAccumulation(t *testing.T) {
	p := NewParser()
	parser := p.NewSIPStream()

	chunk := bytes.Repeat([]byte("A"), 4096)
	fed := 0
	var err error
	// 64 iterations is 256KB — four times the cap, so a build with no bound at
	// all terminates this loop rather than hanging, and fails on the assertion
	// below instead of on the package timeout.
	for i := 0; i < 64; i++ {
		_, err = parser.ParseSIPStream(chunk)
		fed += len(chunk)
		if err != ErrParseSipPartial {
			break
		}
	}
	require.ErrorIs(t, err, ErrParseHeaderTooLarge,
		"after %d drip-fed bytes with no CRLF the parser returned %v; it must reject rather than "+
			"keep accumulating", fed, err)
	require.LessOrEqual(t, fed, maxStreamHeaderBuf+len(chunk),
		"the parser accepted %d bytes before rejecting; the cap is %d, so at most one chunk may "+
			"overshoot it", fed, maxStreamHeaderBuf)
	require.Nil(t, parser.reader,
		"the oversized accumulator must be RELEASED, not retained on the parser — an error return "+
			"that keeps the buffer alive fixes nothing")
}

// TestParseSIPStreamRecoversAfterTheHeaderCap pins RESET, not WEDGE. The cap
// drops the in-flight message's parser state; the connection stays open (the
// transport's parseStream simply returns on any non-partial error), so the very
// next chunk must be parsed as a fresh message rather than being appended to a
// poisoned buffer forever.
func TestParseSIPStreamRecoversAfterTheHeaderCap(t *testing.T) {
	p := NewParser()
	parser := p.NewSIPStream()

	_, err := parser.ParseSIPStream(bytes.Repeat([]byte("A"), maxStreamHeaderBuf+1))
	require.ErrorIs(t, err, ErrParseHeaderTooLarge)

	msgs, err := parser.ParseSIPStream([]byte(strings.Join([]string{
		"SIP/2.0 200 OK",
		"Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-headercap",
		"From: <sip:alice@127.0.0.1>;tag=abc",
		"To: <sip:bob@127.0.0.1>;tag=def",
		"Call-ID: headercap-recovery",
		"CSeq: 1 INVITE",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")))
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.Equal(t, "SIP/2.0 200 OK", msgs[0].(*Response).StartLine())
}

// TestParseSIPStreamCapDoesNotApplyToTheBody is the guard on the guard, and the
// mutation proof for the `p.state != stateContent` clause specifically.
//
// The cap bounds a HEADER block, which is un-drained: nextLine consumes a line
// only once its CRLF has arrived. A BODY is drained on every call (reader.Read
// copies into the message's body slice), and is legitimately allowed to be
// larger than any header block — Content-Length is bounded elsewhere, by
// internal/sipua/parserhardening.go's B1 cap. Dropping the stateContent clause
// reddens this test and nothing else in the tree.
func TestParseSIPStreamCapDoesNotApplyToTheBody(t *testing.T) {
	p := NewParser()
	parser := p.NewSIPStream()

	const bodyLen = 100000 // comfortably above maxStreamHeaderBuf (65536)
	body := bytes.Repeat([]byte("v"), bodyLen)

	head := []byte(strings.Join([]string{
		"INVITE sip:bob@127.0.0.1:5060 SIP/2.0",
		"Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-bodycap",
		"From: <sip:alice@127.0.0.1>;tag=abc",
		"To: <sip:bob@127.0.0.1>",
		"Call-ID: bodycap",
		"CSeq: 1 INVITE",
		"Content-Type: application/sdp",
		"Content-Length: " + strconv.Itoa(bodyLen),
		"",
		"",
	}, "\r\n"))

	// First call: the whole header block plus exactly ONE body byte, which is
	// what leaves the parser in stateContent still owing 99999 bytes. (Feeding
	// the headers with NO body byte would hit upstream's own empty-buffer read
	// path, which returns a different, unrelated error — not what this pins.)
	_, err := parser.ParseSIPStream(append(head, body[0]))
	require.ErrorIs(t, err, ErrParseSipPartial)

	// Second call delivers the remaining 99999 bytes in ONE write, so the
	// accumulator legitimately exceeds maxStreamHeaderBuf in a single step.
	msgs, err := parser.ParseSIPStream(body[1:])
	require.NoError(t, err, "a body larger than the HEADER cap must still parse")
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Body(), bodyLen)
}
