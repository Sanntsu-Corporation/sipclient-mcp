//go:build linux

package sipua_test

// Lane A (rfc-sweep-a) A-HDR pin that needs SO_REUSEADDR (linux): the peer
// dials the UA from the port it then listens on, as in
// third_party/sipgo/sip/transport_tcp_listen_port_peer_test.go.

import (
	"bufio"
	"context"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
)

// na9Topology builds the NEW-A-9 topology: two live connections join the UA
// and the peer, both with remote address 127.0.0.1:P: the peer's (in) and the
// UA's own (out, read through outR). Evidence: evidence/corpus-tcp/03/excerpt.txt
// frame 2-4.
func na9Topology(t *testing.T) (ua *sipua.UA, in, out net.Conn, outR *bufio.Reader, peerAddr string) {
	t.Helper()
	ua, _ = newTCPStubUA(t)
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}, Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	in, err := d.Dial("tcp", ua.LocalAddr().String())
	if err != nil {
		t.Fatalf("peer dial: %v", err)
	}
	t.Cleanup(func() { _ = in.Close() })
	ln, err := net.Listen("tcp", in.LocalAddr().String())
	if err != nil {
		t.Fatalf("peer listen on its dial port: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + ln.Addr().String()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	out, err = ln.Accept()
	if err != nil {
		t.Fatalf("the UA did not connect to the peer: %v", err)
	}
	t.Cleanup(func() { _ = out.Close() })
	_ = out.SetReadDeadline(time.Now().Add(3 * time.Second))
	outR = bufio.NewReader(out)
	if m, err := readStreamMsg(outR); err != nil || stubMethod(m) != "INVITE" {
		t.Fatalf("first message on the UA's connection = %q, %v; want its INVITE", m, err)
	}
	return ua, in, out, outR, ln.Addr().String()
}

// na9Probe writes a request of the given method on out and returns what
// arrived on out (within 2 s) and then on the peer's other connection (in).
func na9Probe(t *testing.T, method string) (onIn, onOut string) {
	ua, in, out, outR, peer := na9Topology(t)
	_, _ = out.Write([]byte(method + " sip:alice@" + ua.LocalAddr().String() + ";transport=tcp SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP " + peer + ";branch=z9hG4bKrfcsweepaNA9\r\n" +
		"From: <sip:probe@127.0.0.1>;tag=rfcsweepa\r\nTo: <sip:alice@example>\r\n" +
		"Call-ID: rfcsweepa-na9@127.0.0.1\r\nCSeq: 1 " + method + "\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"))
	_ = out.SetReadDeadline(time.Now().Add(2 * time.Second))
	onOut, _ = readStreamMsg(outR)
	_ = in.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	onIn, _ = readStreamMsg(bufio.NewReader(in))
	t.Logf("on the peer's connection: %.40q; on the UA's own: %.40q", onIn, onOut)
	return onIn, onOut
}

// TestRFC3261_NEWA9_ResponseLeavesOnTheArrivalConnection covers NEW-A-9
// (A-HDR-86, CF-079, RFC 3261 18.2.2: "If the "sent-protocol" is a reliable
// transport protocol such as TCP or SCTP, or TLS over those, the response MUST
// be sent using the existing connection to the source of the original request
// that created the transaction, if that connection is still open."
// rfc3261.txt:8144-8147). Fixed by cf5-f; was
// TestRFC3261Pin_NEWA9_ResponseLeavesOnAnotherTCPConnection. An INFO sent on
// out is answered on out.
func TestRFC3261_NEWA9_ResponseLeavesOnTheArrivalConnection(t *testing.T) {
	onIn, onOut := na9Probe(t, "INFO")
	if !strings.HasPrefix(onOut, "SIP/2.0 ") {
		t.Errorf("no response to the INFO on the connection it arrived on")
	}
	if onIn != "" {
		t.Errorf("the response also (or only) left on the peer's other connection: %.60q", onIn)
	}
}

// TestUnhandledMethodIsAnsweredOnTheArrivalConnection: a method no handler is
// registered for (the default 405) is answered on the connection it arrived on
// too (CF-079; the sipgo server's default handler used to look the connection up
// by source address).
func TestUnhandledMethodIsAnsweredOnTheArrivalConnection(t *testing.T) {
	onIn, onOut := na9Probe(t, "MESSAGE")
	if !strings.HasPrefix(onOut, "SIP/2.0 ") {
		t.Errorf("no response to the MESSAGE on the connection it arrived on")
	}
	if onIn != "" {
		t.Errorf("the response left on the peer's other connection: %.60q", onIn)
	}
}
