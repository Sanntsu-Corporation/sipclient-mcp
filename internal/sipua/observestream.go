package sipua

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// observingListener wraps a net.Listener so every accepted net.Conn is
// itself wrapped in an observingStreamConn (ObservingStreamConn), giving the
// INBOUND (accepted) side of a tcp/tls UA
// and of a UDP UA's TCP listener (CF-190) the same tap coverage ObservingConn
// gives the UDP path. This is the Config.WrapListener seam (T5/D3): no sipgo
// fork touch is needed here because net.Listener/net.Conn are stdlib
// interfaces sipua already controls before handing the listener to
// srv.ServeTCP/srv.ServeTLS.
type observingListener struct {
	net.Listener
	tap       session.Tap
	transport session.Transport
	now       func() time.Time
	uaHandle  string
}

// ObservingListener wraps inner so every net.Conn it Accepts is observed in
// both directions (see ObservingStreamConn). now defaults to time.Now when
// nil. uaHandle is stamped into every SIPRecord this listener's accepted
// conns produce (HIGH-3, same rationale as ObservingConn).
func ObservingListener(inner net.Listener, tap session.Tap, transport session.Transport, now func() time.Time, uaHandle string) net.Listener {
	if now == nil {
		now = time.Now
	}
	return &observingListener{
		Listener:  inner,
		tap:       tap,
		transport: transport,
		now:       now,
		uaHandle:  uaHandle,
	}
}

func (l *observingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return ObservingStreamConn(c, l.tap, l.transport, l.now, l.uaHandle), nil
}

// observingStreamConn wraps a net.Conn so every byte read or written is
// observed AT THE SOCKET, mirroring observingConn's role for the UDP
// PacketConn seam (observe.go). A stream conn is bidirectional and a single
// Read/Write call boundary carries no message-boundary meaning of its own
// (unlike a UDP datagram), so each direction owns a streamFramer that
// accumulates observed bytes until a complete SIP message can be sliced out.
//
// One instance serves BOTH the inbound-accepted case (via
// observingListener.Accept) and the outbound-dialed case (via the fork's
// dial-wrap hook, T5 Step 6): direction is stamped per-Read/Write, not
// per-conn-role (D3).
//
// Read runs on one goroutine, Write on another (sipgo's transport reads in
// its own accept/serve loop and writes from request-handling goroutines), so
// — exactly as observingConn reasons for its two sip.Parsers — each direction
// gets its own parser and its own streamFramer, touched by exactly one
// goroutine each. No lock is required and none is added.
type observingStreamConn struct {
	net.Conn
	tap         session.Tap
	transport   session.Transport
	now         func() time.Time
	uaHandle    string
	readParser  *sip.Parser
	writeParser *sip.Parser
	readFramer  streamFramer
	writeFramer streamFramer
}

// ObservingStreamConn wraps inner so every byte read or written is observed
// and, once a complete SIP message has been accumulated, handed to tap as a
// fully-populated session.SIPRecord. now defaults to time.Now when nil.
//
// Raw is the OBSERVED octets — headers + body exactly as they appeared on
// the wire, sliced by streamFramer, never re-serialized (L5) — redacted by
// the same redactWireSecrets() the UDP producer applies (observe.go) before
// being assigned to Raw/Serialized.
func ObservingStreamConn(inner net.Conn, tap session.Tap, transport session.Transport, now func() time.Time, uaHandle string) net.Conn {
	if now == nil {
		now = time.Now
	}
	return &observingStreamConn{
		Conn:        inner,
		tap:         tap,
		transport:   transport,
		now:         now,
		uaHandle:    uaHandle,
		readParser:  sip.NewParser(),
		writeParser: sip.NewParser(),
	}
}

func (c *observingStreamConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	// A Read may legitimately return n>0 together with a non-nil error (e.g.
	// the final chunk arriving as the peer closes the connection, n>0 with
	// err=io.EOF) — per the io.Reader contract that data is valid and MUST
	// be processed. Feed it to the framer whenever n>0, then propagate the
	// original (n, err) unchanged: this tap only observes, it never alters
	// what the caller (sipgo) sees.
	if n > 0 {
		c.readFramer.feed(b[:n], func(msg []byte) {
			c.emit(c.readParser, session.Inbound, msg)
		})
	}
	return n, err
}

func (c *observingStreamConn) Write(b []byte) (int, error) {
	// n may be less than len(b) on a partial write; observe exactly the
	// bytes that actually reached the wire, not the caller's full buffer.
	// As with Read, n>0 bytes are fed to the framer even when err != nil
	// (see Read's comment), and the original (n, err) is returned unchanged.
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.writeFramer.feed(b[:n], func(msg []byte) {
			c.emit(c.writeParser, session.Outbound, msg)
		})
	}
	return n, err
}

// emit parses msg (the OBSERVED bytes of one complete SIP message, already
// isolated by streamFramer) far enough to extract the scalar fields
// session.SIPRecord needs, redacts credential-bearing digest params
// (redactWireSecrets, HIGH-2, observe.go) and hands the record to the tap.
// msg is not re-serialized: Raw/Serialized are set from the redacted copy of
// the observed bytes, exactly as observingConn.observe does for UDP.
func (c *observingStreamConn) emit(parser *sip.Parser, dir session.Direction, msg []byte) {
	if c.tap == nil || len(msg) == 0 {
		return
	}
	parsed, err := parser.ParseSIP(msg)
	if err != nil || parsed == nil {
		return
	}
	raw := redactWireSecrets(msg)
	rec := session.SIPRecord{
		At:         c.now(),
		Direction:  dir,
		Transport:  c.transport,
		LocalAddr:  c.Conn.LocalAddr().String(),
		RemoteAddr: c.Conn.RemoteAddr().String(),
		UAHandle:   c.uaHandle,
		CallID:     headerValue(parsed, "Call-ID"),
		CSeq:       headerValue(parsed, "CSeq"),
		FromURI:    headerValue(parsed, "From"),
		ToURI:      headerValue(parsed, "To"),
		SDPCodecs:  sdpCodecNames(parsed.Body()),
		Serialized: string(raw),
		Raw:        raw,
		Fidelity:   "byte_exact",
	}
	switch m := parsed.(type) {
	case *sip.Request:
		rec.Method = string(m.Method)
	case *sip.Response:
		rec.StatusCode, rec.Reason = int(m.StatusCode), m.Reason
	}
	c.tap.SIPMessage(daemonCtx(), rec)
}

// streamFramer accumulates the bytes observed on ONE direction (Read or
// Write) of a stream conn and slices out each complete SIP message's
// OBSERVED bytes — headers + body, exactly as seen on the wire — without
// reconstructing or re-serializing anything (L5). One instance is owned by
// exactly one direction's goroutine (see observingStreamConn), so no lock is
// needed.
type streamFramer struct {
	buf []byte
}

// maxHeaderBuf bounds how many unterminated bytes a streamFramer will
// accumulate while searching for the \r\n\r\n header terminator. RFC 3261
// SIP headers are practically never anywhere close to this size (a few KB
// at most); 64KB is a generous cap that still protects against a peer that
// keeps a TCP/TLS connection open and drip-feeds non-terminated bytes
// forever, which would otherwise grow the accumulator without bound.
//
// SINCE PHASE 4 W3 (P4-W1-N05), third_party/sipgo/sip/parser_stream.go's
// maxStreamHeaderBuf restates this exact value for the identical hazard on the
// REAL parse path (this constant only bounds the passive observation tap's own
// side-buffer, which has zero influence on what the real stack parses from). If
// one of the two moves, move the other.
const maxHeaderBuf = 64 * 1024

// maxBodyLen bounds the Content-Length value the framer will trust when
// sizing the message allocation. SIP bodies (SDP offers/answers) are
// typically well under 1KB; 1MB is a generous cap that still prevents a
// malformed or hostile Content-Length from driving a huge or negative
// allocation (see contentLength).
const maxBodyLen = 1 * 1024 * 1024

// feed appends data (the bytes actually observed on this call — a partial
// write's returned n, not the caller's full buffer) to the accumulator, then
// invokes emit once per complete message it can now slice out, in wire
// order. Handles, within one feed call:
//   - fragmented headers: the \r\n\r\n terminator not yet in the buffer —
//     feed returns and waits for the next call to supply the rest.
//   - coalesced messages: two or more complete messages already in the
//     buffer — feed loops and emits each one separately.
//   - a zero-length body (Content-Length: 0) — emitted immediately after the
//     terminator, no body bytes awaited.
//
// A bare CRLF or CRLF CRLF appearing where a message start-line is expected
// is a keepalive (RFC 6223-style ping/pong): no SIP message ever starts with
// CRLF, so any such prefix is consumed and never emitted as a record.
func (f *streamFramer) feed(data []byte, emit func(msg []byte)) {
	f.buf = append(f.buf, data...)
	for {
		for len(f.buf) >= 2 && f.buf[0] == '\r' && f.buf[1] == '\n' {
			f.buf = f.buf[2:]
		}
		if len(f.buf) == 0 {
			return
		}
		idx := bytes.Index(f.buf, []byte("\r\n\r\n"))
		if idx < 0 {
			// No terminator yet. If we've accumulated more than
			// maxHeaderBuf without finding one, this direction's stream is
			// malformed (or a peer is drip-feeding garbage to grow our
			// buffer) — drop the accumulator and stop trying to frame it,
			// rather than growing without bound.
			if len(f.buf) > maxHeaderBuf {
				f.buf = nil
			}
			return
		}
		headerEnd := idx + 4
		cl, ok := contentLength(f.buf[:headerEnd])
		if !ok {
			// Content-Length was negative or absurdly large — untrustworthy
			// for sizing an allocation. Drop the accumulator and stop
			// framing this malformed stream rather than risk a panic.
			f.buf = nil
			return
		}
		total := headerEnd + cl
		if len(f.buf) < total {
			return
		}
		msg := make([]byte, total)
		copy(msg, f.buf[:total])
		f.buf = f.buf[total:]
		emit(msg)
	}
}

// contentLength reads the Content-Length header's value out of header (the
// accumulated bytes up to and including the \r\n\r\n terminator). It matches
// the header name case-insensitively, including the "l" compact form (RFC
// 3261 §7.3.3). Returns (0, true) if the header is absent or unparseable — a
// stream UA never legitimately omits Content-Length, so this is a defensive
// default rather than a case the plan's edge cases enumerate. Returns
// (0, false) if a Content-Length value IS present but is negative or exceeds
// maxBodyLen: such a value can never be trusted to size an allocation (a
// negative or huge total would panic or exhaust memory in feed), so the
// caller must treat it as malformed rather than use the returned length.
func contentLength(header []byte) (int, bool) {
	lines := strings.Split(string(header), "\r\n")
	for _, line := range lines {
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:colon]))
		if name != "content-length" && name != "l" {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(line[colon+1:]))
		if err != nil {
			return 0, true
		}
		if n < 0 || n > maxBodyLen {
			return 0, false
		}
		return n, true
	}
	return 0, true
}
