package sipua_test

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
)

// streamInviteRaw mirrors observe_test.go's inviteRaw fixture (same headers,
// same SDP body) but with Content-Length corrected to the body's actual byte
// length (134, not 145). observe_test.go's mismatch is harmless there — the
// UDP path parses the whole datagram and never slices by Content-Length —
// but the stream framer under test here MUST trust Content-Length to find a
// message's end within a byte stream that carries no datagram boundary, so
// it needs an accurate value. tryingRaw (Content-Length: 0, no body) is
// unaffected by this and is reused as-is from observe_test.go.
const streamInviteRaw = "INVITE sip:bob@192.0.2.10:5060 SIP/2.0\r\n" +
	"Via: SIP/2.0/TCP 127.0.0.1:5066;branch=z9hG4bK-1;rport\r\n" +
	"From: <sip:alice@example>;tag=t1\r\n" +
	"To: <sip:bob@example>\r\n" +
	"Call-ID: c-1\r\n" +
	"CSeq: 1 INVITE\r\n" +
	"Max-Forwards: 70\r\n" +
	"Contact: <sip:alice@127.0.0.1:5066>\r\n" +
	"Content-Type: application/sdp\r\n" +
	"Content-Length: 134\r\n\r\n" +
	"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=sipclient-mcp\r\nc=IN IP4 127.0.0.1\r\n" +
	"t=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"

// partialWriteConn caps every underlying Write at n bytes, simulating a short
// write so a test can assert the byte-preserving framer observes exactly what
// the wire actually accepted, not the caller's full buffer.
type partialWriteConn struct {
	net.Conn
	n int
}

func (p *partialWriteConn) Write(b []byte) (int, error) {
	if len(b) > p.n {
		b = b[:p.n]
	}
	return p.Conn.Write(b)
}

func TestObservingStreamConnInboundFullMessageOneRead(t *testing.T) {
	srv, cli := net.Pipe()
	defer func() { _ = srv.Close(); _ = cli.Close() }()

	tap := &capturingTap{}
	now := time.Unix(0, 0)
	wrapped := sipua.ObservingStreamConn(srv, tap, session.TransportTCP, func() time.Time { return now }, "ua-1")

	go func() { _, _ = cli.Write([]byte(streamInviteRaw)) }()

	buf := make([]byte, 65535)
	if _, err := wrapped.Read(buf); err != nil {
		t.Fatalf("Read: %v", err)
	}

	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Direction != session.Inbound {
		t.Errorf("Direction = %q, want inbound", rec.Direction)
	}
	if rec.Transport != session.TransportTCP {
		t.Errorf("Transport = %q, want tcp", rec.Transport)
	}
	if rec.UAHandle != "ua-1" {
		t.Errorf("UAHandle = %q, want ua-1", rec.UAHandle)
	}
	if rec.Fidelity != "byte_exact" {
		t.Errorf("Fidelity = %q, want byte_exact", rec.Fidelity)
	}
	if string(rec.Raw) != streamInviteRaw {
		t.Errorf("Raw = %q, want byte-exact %q", rec.Raw, streamInviteRaw)
	}
	if rec.CallID != "c-1" {
		t.Errorf("CallID = %q, want c-1", rec.CallID)
	}
}

func TestObservingStreamConnOutboundFullMessageOneWrite(t *testing.T) {
	srv, cli := net.Pipe()
	defer func() { _ = srv.Close(); _ = cli.Close() }()
	go func() { _, _ = io.Copy(io.Discard, cli) }()

	tap := &capturingTap{}
	now := time.Unix(0, 0)
	wrapped := sipua.ObservingStreamConn(srv, tap, session.TransportTCP, func() time.Time { return now }, "ua-1")

	if _, err := wrapped.Write([]byte(streamInviteRaw)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1", len(recs))
	}
	if recs[0].Direction != session.Outbound {
		t.Errorf("Direction = %q, want outbound", recs[0].Direction)
	}
	if string(recs[0].Raw) != streamInviteRaw {
		t.Errorf("Raw = %q, want byte-exact %q", recs[0].Raw, streamInviteRaw)
	}
}

// TestObservingStreamConnFragmentedHeaders splits the header block of a
// message across two separate Read calls (the \r\n\r\n terminator is not
// present in the first chunk) and asserts the framer waits for the second
// chunk before emitting exactly one, byte-exact record.
func TestObservingStreamConnFragmentedHeaders(t *testing.T) {
	srv, cli := net.Pipe()
	defer func() { _ = srv.Close(); _ = cli.Close() }()

	// Split inside the header terminator itself: chunk1 ends right after the
	// terminator's first CRLF, chunk2 starts with the second CRLF + body.
	term := strings.Index(streamInviteRaw, "\r\n\r\n")
	if term < 0 {
		t.Fatal("fixture has no header terminator")
	}
	split := term + 2
	chunk1, chunk2 := streamInviteRaw[:split], streamInviteRaw[split:]

	tap := &capturingTap{}
	now := time.Unix(0, 0)
	wrapped := sipua.ObservingStreamConn(srv, tap, session.TransportTCP, func() time.Time { return now }, "ua-1")

	go func() {
		_, _ = cli.Write([]byte(chunk1))
		_, _ = cli.Write([]byte(chunk2))
	}()

	buf := make([]byte, 65535)
	if _, err := wrapped.Read(buf); err != nil {
		t.Fatalf("Read 1: %v", err)
	}
	if recs := tap.all(); len(recs) != 0 {
		t.Fatalf("tap saw %d records after only the fragmented header chunk, want 0", len(recs))
	}
	if _, err := wrapped.Read(buf); err != nil {
		t.Fatalf("Read 2: %v", err)
	}

	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1", len(recs))
	}
	if string(recs[0].Raw) != streamInviteRaw {
		t.Errorf("Raw = %q, want byte-exact %q", recs[0].Raw, streamInviteRaw)
	}
}

// TestObservingStreamConnCoalescedMessages delivers two complete messages in
// a single Read call and asserts the framer emits two separate records, not
// one merged blob.
func TestObservingStreamConnCoalescedMessages(t *testing.T) {
	srv, cli := net.Pipe()
	defer func() { _ = srv.Close(); _ = cli.Close() }()

	tap := &capturingTap{}
	now := time.Unix(0, 0)
	wrapped := sipua.ObservingStreamConn(srv, tap, session.TransportTCP, func() time.Time { return now }, "ua-1")

	coalesced := streamInviteRaw + tryingRaw
	go func() { _, _ = cli.Write([]byte(coalesced)) }()

	buf := make([]byte, 65535)
	if _, err := wrapped.Read(buf); err != nil {
		t.Fatalf("Read: %v", err)
	}

	recs := tap.all()
	if len(recs) != 2 {
		t.Fatalf("tap saw %d records, want 2 (coalesced messages must not merge)", len(recs))
	}
	if string(recs[0].Raw) != streamInviteRaw {
		t.Errorf("record 0 Raw = %q, want %q", recs[0].Raw, streamInviteRaw)
	}
	if string(recs[1].Raw) != tryingRaw {
		t.Errorf("record 1 Raw = %q, want %q", recs[1].Raw, tryingRaw)
	}
}

// TestObservingStreamConnZeroLengthBody asserts a Content-Length: 0 message
// (tryingRaw) is emitted immediately after the header terminator, with no
// body bytes awaited.
func TestObservingStreamConnZeroLengthBody(t *testing.T) {
	srv, cli := net.Pipe()
	defer func() { _ = srv.Close(); _ = cli.Close() }()

	tap := &capturingTap{}
	now := time.Unix(0, 0)
	wrapped := sipua.ObservingStreamConn(srv, tap, session.TransportTCP, func() time.Time { return now }, "ua-1")

	go func() { _, _ = cli.Write([]byte(tryingRaw)) }()

	buf := make([]byte, 65535)
	if _, err := wrapped.Read(buf); err != nil {
		t.Fatalf("Read: %v", err)
	}

	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1", len(recs))
	}
	if string(recs[0].Raw) != tryingRaw {
		t.Errorf("Raw = %q, want byte-exact %q", recs[0].Raw, tryingRaw)
	}
	if recs[0].StatusCode != 100 {
		t.Errorf("StatusCode = %d, want 100", recs[0].StatusCode)
	}
}

// TestObservingStreamConnCRLFKeepalive asserts a bare CRLF-CRLF keepalive
// arriving between two messages (each in its own Read call) is silently
// skipped — not emitted as a spurious third record — while the surrounding
// messages are still recorded correctly.
func TestObservingStreamConnCRLFKeepalive(t *testing.T) {
	srv, cli := net.Pipe()
	defer func() { _ = srv.Close(); _ = cli.Close() }()

	tap := &capturingTap{}
	now := time.Unix(0, 0)
	wrapped := sipua.ObservingStreamConn(srv, tap, session.TransportTCP, func() time.Time { return now }, "ua-1")

	go func() {
		_, _ = cli.Write([]byte(streamInviteRaw))
		_, _ = cli.Write([]byte("\r\n\r\n")) // double-CRLF keepalive ping
		_, _ = cli.Write([]byte(tryingRaw))
	}()

	buf := make([]byte, 65535)
	for i := 0; i < 3; i++ {
		if _, err := wrapped.Read(buf); err != nil {
			t.Fatalf("Read %d: %v", i, err)
		}
	}

	recs := tap.all()
	if len(recs) != 2 {
		t.Fatalf("tap saw %d records, want 2 (the keepalive must not produce a record)", len(recs))
	}
	if string(recs[0].Raw) != streamInviteRaw {
		t.Errorf("record 0 Raw = %q, want %q", recs[0].Raw, streamInviteRaw)
	}
	if string(recs[1].Raw) != tryingRaw {
		t.Errorf("record 1 Raw = %q, want %q", recs[1].Raw, tryingRaw)
	}
}

// TestObservingStreamConnPartialWrite asserts that when the underlying conn
// only accepts part of a Write call (a short write), the framer observes
// exactly the bytes that were actually written, accumulating across
// multiple partial writes until the full message is on the wire — never the
// caller's full buffer up front.
func TestObservingStreamConnPartialWrite(t *testing.T) {
	srv, cli := net.Pipe()
	defer func() { _ = srv.Close(); _ = cli.Close() }()
	go func() { _, _ = io.Copy(io.Discard, cli) }()

	limited := &partialWriteConn{Conn: srv, n: 10}

	tap := &capturingTap{}
	now := time.Unix(0, 0)
	wrapped := sipua.ObservingStreamConn(limited, tap, session.TransportTCP, func() time.Time { return now }, "ua-1")

	msg := []byte(streamInviteRaw)
	remaining := msg
	firstN := -1
	for len(remaining) > 0 {
		n, err := wrapped.Write(remaining)
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if firstN == -1 {
			firstN = n
		}
		if n == 0 {
			t.Fatal("Write returned 0 with no error")
		}
		remaining = remaining[n:]
	}
	if firstN >= len(msg) {
		t.Fatalf("first Write returned %d, want a short write (< %d)", firstN, len(msg))
	}
	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1 (assembled across partial writes)", len(recs))
	}
	if string(recs[0].Raw) != streamInviteRaw {
		t.Errorf("Raw = %q, want byte-exact %q", recs[0].Raw, streamInviteRaw)
	}
	if recs[0].Direction != session.Outbound {
		t.Errorf("Direction = %q, want outbound", recs[0].Direction)
	}
}

// TestObservingStreamConnUnterminatedStreamPastCapIsDropped is the Rule 13
// Cycle 5 regression test for blocking issue 1: a peer that keeps the
// connection open and never sends the \r\n\r\n header terminator must not be
// allowed to grow the framer's accumulator without bound. It feeds a garbage
// stream (no CR or LF at all, so the terminator search never succeeds)
// larger than the framer's header cap, then a legitimate follow-up message,
// and asserts: (a) the garbage never produces a spurious record, and (b) the
// follow-up message is still captured byte-exact — proving the oversized
// accumulator was dropped/reset rather than left corrupting subsequent
// framing (which would otherwise be the observable symptom of unbounded
// growth: the garbage prefix would still be sitting in the buffer and would
// get glued onto the next message).
func TestObservingStreamConnUnterminatedStreamPastCapIsDropped(t *testing.T) {
	srv, cli := net.Pipe()
	defer func() { _ = srv.Close(); _ = cli.Close() }()

	tap := &capturingTap{}
	now := time.Unix(0, 0)
	wrapped := sipua.ObservingStreamConn(srv, tap, session.TransportTCP, func() time.Time { return now }, "ua-1")

	// 70000 bytes of 'A': no CR/LF anywhere, and larger than the 64KB header
	// cap, so the terminator search never succeeds and the cap must trip.
	garbage := bytes.Repeat([]byte("A"), 70000)
	go func() {
		_, _ = cli.Write(garbage)
		_, _ = cli.Write([]byte(streamInviteRaw))
	}()

	buf := make([]byte, 65535)
	total := 0
	for total < len(garbage) {
		n, err := wrapped.Read(buf)
		if err != nil {
			t.Fatalf("Read (garbage phase): %v", err)
		}
		total += n
	}
	if recs := tap.all(); len(recs) != 0 {
		t.Fatalf("tap saw %d records from garbage alone, want 0", len(recs))
	}

	for i := 0; i < 5 && len(tap.all()) == 0; i++ {
		if _, err := wrapped.Read(buf); err != nil {
			t.Fatalf("Read (message phase): %v", err)
		}
	}

	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1 (garbage over the header cap must be dropped, not merged into the next message)", len(recs))
	}
	if string(recs[0].Raw) != streamInviteRaw {
		t.Errorf("Raw = %q, want byte-exact %q (accumulator must have been reset after exceeding the header cap)", recs[0].Raw, streamInviteRaw)
	}
}

// TestObservingStreamConnMalformedContentLengthDoesNotPanic is the Rule 13
// Cycle 5 regression test for blocking issue 2: a Content-Length that is
// negative or absurdly large must never reach the make([]byte, total)
// allocation in streamFramer.feed, since make([]byte, negativeOrHuge) panics
// ("makeslice: len out of range"). It asserts the read itself doesn't panic
// (a panic would crash the test binary, not surface as a returned error),
// that no record is produced for the malformed message, and that a
// subsequent well-formed message is still framed correctly (proving the
// malformed accumulator was dropped rather than left corrupting the buffer).
func TestObservingStreamConnMalformedContentLengthDoesNotPanic(t *testing.T) {
	cases := []struct {
		name string
		cl   string
	}{
		{"negative", "-1"},
		{"tooLarge", "99999999"}, // exceeds the framer's 1MB body cap
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, cli := net.Pipe()
			defer func() { _ = srv.Close(); _ = cli.Close() }()

			tap := &capturingTap{}
			now := time.Unix(0, 0)
			wrapped := sipua.ObservingStreamConn(srv, tap, session.TransportTCP, func() time.Time { return now }, "ua-1")

			raw := "INVITE sip:bob@192.0.2.10:5060 SIP/2.0\r\n" +
				"Via: SIP/2.0/TCP 127.0.0.1:5066;branch=z9hG4bK-2;rport\r\n" +
				"From: <sip:alice@example>;tag=t2\r\n" +
				"To: <sip:bob@example>\r\n" +
				"Call-ID: c-2\r\n" +
				"CSeq: 1 INVITE\r\n" +
				"Max-Forwards: 70\r\n" +
				"Content-Length: " + tc.cl + "\r\n\r\n"

			go func() { _, _ = cli.Write([]byte(raw)) }()

			buf := make([]byte, 65535)
			if _, err := wrapped.Read(buf); err != nil {
				t.Fatalf("Read: %v", err)
			}
			if recs := tap.all(); len(recs) != 0 {
				t.Fatalf("tap saw %d records, want 0 (malformed Content-Length %q must not produce a record)", len(recs), tc.cl)
			}

			// The malformed message must not corrupt framing of what follows.
			go func() { _, _ = cli.Write([]byte(streamInviteRaw)) }()
			if _, err := wrapped.Read(buf); err != nil {
				t.Fatalf("Read 2: %v", err)
			}
			recs := tap.all()
			if len(recs) != 1 {
				t.Fatalf("tap saw %d records after the valid follow-up message, want 1", len(recs))
			}
			if string(recs[0].Raw) != streamInviteRaw {
				t.Errorf("Raw = %q, want byte-exact %q", recs[0].Raw, streamInviteRaw)
			}
		})
	}
}

// TestObservingStreamConnRedactsSDPCryptoKey proves the TCP/TLS producer
// (observestream.go) inherits the same SRTP SDES redaction as the UDP
// producer (observe_test.go's TestObservingConnRedactsSDPCryptoKey) — both
// call the same redactWireSecrets, but UDP and stream capture are
// independent producers, so the UDP test alone does not prove this call
// site was updated too.
func TestObservingStreamConnRedactsSDPCryptoKey(t *testing.T) {
	srv, cli := net.Pipe()
	defer func() { _ = srv.Close(); _ = cli.Close() }()
	go func() { _, _ = io.Copy(io.Discard, cli) }()

	tap := &capturingTap{}
	now := time.Unix(0, 0)
	wrapped := sipua.ObservingStreamConn(srv, tap, session.TransportTCP, func() time.Time { return now }, "ua-1")

	if _, err := wrapped.Write([]byte(sdesInviteRaw)); err != nil {
		t.Fatalf("Write: %v", err)
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
	wantPlaceholder := "inline:" + strings.Repeat("X", len(sdesKeyMaterial))
	if !strings.Contains(rec.Serialized, wantPlaceholder) {
		t.Errorf("Serialized missing length-preserving placeholder %q:\n%s", wantPlaceholder, rec.Serialized)
	}
}

// eofAfterDataConn wraps a net.Conn so its Read/Write returns the real data
// AND a non-nil error in the same call, simulating a valid io.Reader/
// io.Writer contract case: the final chunk of real data arriving as the
// connection closes (n>0, err=io.EOF).
type eofAfterDataConn struct {
	net.Conn
	readErr  error
	writeErr error
}

func (e *eofAfterDataConn) Read(b []byte) (int, error) {
	n, err := e.Conn.Read(b)
	if err == nil && e.readErr != nil {
		return n, e.readErr
	}
	return n, err
}

func (e *eofAfterDataConn) Write(b []byte) (int, error) {
	n, err := e.Conn.Write(b)
	if err == nil && e.writeErr != nil {
		return n, e.writeErr
	}
	return n, err
}

// TestObservingStreamConnReadCapturesBytesDespiteNonNilError is the Rule 13
// Cycle 5 regression test for blocking issue 3: a Read that returns n>0
// bytes alongside a non-nil error is valid per the io.Reader contract, and
// those bytes must still reach the framer — dropping them would silently
// break the byte_exact capture guarantee for exactly the data most likely to
// be the last thing a peer ever sends.
func TestObservingStreamConnReadCapturesBytesDespiteNonNilError(t *testing.T) {
	srv, cli := net.Pipe()
	defer func() { _ = srv.Close(); _ = cli.Close() }()

	wrappedConn := &eofAfterDataConn{Conn: srv, readErr: io.EOF}

	tap := &capturingTap{}
	now := time.Unix(0, 0)
	wrapped := sipua.ObservingStreamConn(wrappedConn, tap, session.TransportTCP, func() time.Time { return now }, "ua-1")

	go func() { _, _ = cli.Write([]byte(tryingRaw)) }()

	buf := make([]byte, 65535)
	n, err := wrapped.Read(buf)
	if err != io.EOF {
		t.Fatalf("Read err = %v, want io.EOF (n=%d)", err, n)
	}
	if n != len(tryingRaw) {
		t.Fatalf("Read n = %d, want %d", n, len(tryingRaw))
	}

	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1 (n>0 bytes delivered alongside a non-nil error must still be captured)", len(recs))
	}
	if string(recs[0].Raw) != tryingRaw {
		t.Errorf("Raw = %q, want byte-exact %q", recs[0].Raw, tryingRaw)
	}
}

// TestObservingStreamConnWriteCapturesBytesDespiteNonNilError mirrors
// TestObservingStreamConnReadCapturesBytesDespiteNonNilError for the Write
// direction (n>0, err=io.ErrClosedPipe simulating a peer closing mid-write).
func TestObservingStreamConnWriteCapturesBytesDespiteNonNilError(t *testing.T) {
	srv, cli := net.Pipe()
	defer func() { _ = srv.Close(); _ = cli.Close() }()
	go func() { _, _ = io.Copy(io.Discard, cli) }()

	wrappedConn := &eofAfterDataConn{Conn: srv, writeErr: io.ErrClosedPipe}

	tap := &capturingTap{}
	now := time.Unix(0, 0)
	wrapped := sipua.ObservingStreamConn(wrappedConn, tap, session.TransportTCP, func() time.Time { return now }, "ua-1")

	n, err := wrapped.Write([]byte(tryingRaw))
	if err != io.ErrClosedPipe {
		t.Fatalf("Write err = %v, want io.ErrClosedPipe (n=%d)", err, n)
	}
	if n != len(tryingRaw) {
		t.Fatalf("Write n = %d, want %d", n, len(tryingRaw))
	}

	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1 (n>0 bytes delivered alongside a non-nil error must still be captured)", len(recs))
	}
	if string(recs[0].Raw) != tryingRaw {
		t.Errorf("Raw = %q, want byte-exact %q", recs[0].Raw, tryingRaw)
	}
}

// TestObservingListenerWrapsAcceptedConns asserts Accept() wraps each
// accepted net.Conn in an ObservingStreamConn stamping session.Inbound on
// Read, so a real inbound stream connection is observed end-to-end.
func TestObservingListenerWrapsAcceptedConns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	tap := &capturingTap{}
	now := time.Unix(0, 0)
	wrapped := sipua.ObservingListener(ln, tap, session.TransportTCP, func() time.Time { return now }, "ua-2")

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := wrapped.Accept()
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 65535)
		if _, err := c.Read(buf); err != nil {
			t.Errorf("Read: %v", err)
		}
	}()

	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = cli.Close() }()
	if _, err := cli.Write([]byte(streamInviteRaw)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	<-done

	recs := tap.all()
	if len(recs) != 1 {
		t.Fatalf("tap saw %d records, want 1", len(recs))
	}
	if recs[0].Direction != session.Inbound {
		t.Errorf("Direction = %q, want inbound", recs[0].Direction)
	}
	if recs[0].UAHandle != "ua-2" {
		t.Errorf("UAHandle = %q, want ua-2", recs[0].UAHandle)
	}
	if string(recs[0].Raw) != streamInviteRaw {
		t.Errorf("Raw = %q, want byte-exact %q", recs[0].Raw, streamInviteRaw)
	}
}
