package sipua_test

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// CF-076 (RFC 3261 18.2.1): "For any port and interface that a server listens
// on for UDP, it MUST listen on that same port and interface for TCP."

func TestRFC3261_NEWA5_UDPUAListensOnTCPAtTheSameAddress(t *testing.T) {
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	c, err := net.DialTimeout("tcp", ua.BoundAddr().String(), time.Second)
	if err != nil {
		t.Fatalf("no TCP listener beside the UDP socket at %s: %v", ua.BoundAddr(), err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte(tcpOptions(c.LocalAddr().String(), ua.BoundAddr().String(), "z9hG4bKcf076a")))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := readStreamMsg(bufio.NewReader(c))
	if err != nil || !strings.HasPrefix(resp, "SIP/2.0 ") {
		t.Fatalf("no response on the TCP connection: %q, %v", resp, err)
	}
}

func tcpOptions(from, to, branch string) string {
	return "OPTIONS sip:alice@" + to + " SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP " + from + ";branch=" + branch + "\r\n" +
		"From: <sip:probe@127.0.0.1>;tag=cf076\r\nTo: <sip:alice@" + to + ">\r\n" +
		"Call-ID: " + branch + "@127.0.0.1\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
}

func TestUDPUATCPListenerIsNoWiderThanTheUDPBind(t *testing.T) {
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	_, port, _ := net.SplitHostPort(ua.BoundAddr().String())
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.2", port), time.Second); err == nil {
		_ = c.Close()
		t.Fatalf("a TCP connection to 127.0.0.2:%s succeeded: the listener is wider than the UDP bind on %s", port, ua.BoundAddr())
	}
}

// readUntil reads messages from r until one starts with prefix.
func readUntil(t *testing.T, r *bufio.Reader, prefix string) string {
	t.Helper()
	for i := 0; i < 8; i++ {
		m, err := readStreamMsg(r)
		if err != nil {
			t.Fatalf("waiting for %q: %v", prefix, err)
		}
		if strings.HasPrefix(m, prefix) {
			return m
		}
	}
	t.Fatalf("no message starting %q", prefix)
	return ""
}

func headerOf(msg, name string) string {
	for _, l := range strings.Split(msg, "\r\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func TestUDPUAAnswersAnInviteThatArrivesOverTCP(t *testing.T) {
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	c, err := net.DialTimeout("tcp", ua.BoundAddr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	stub, to := c.LocalAddr().String(), ua.BoundAddr().String()
	sdp := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=x\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
		"m=audio 20000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
	send := func(s string) { _, _ = c.Write([]byte(s)) }
	send("INVITE sip:alice@" + to + " SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP " + stub + ";branch=z9hG4bKcf076inv\r\n" +
		"From: <sip:stub@127.0.0.1>;tag=cf076s\r\nTo: <sip:alice@" + to + ">\r\n" +
		"Call-ID: cf076-inv@127.0.0.1\r\nCSeq: 1 INVITE\r\nMax-Forwards: 70\r\n" +
		"Contact: <sip:stub@" + stub + ";transport=tcp>\r\n" +
		"Content-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(len(sdp)) + "\r\n\r\n" + sdp)

	incoming := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	ok := readUntil(t, r, "SIP/2.0 200")
	toHdr := headerOf(ok, "To")

	send("ACK sip:alice@" + to + " SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP " + stub + ";branch=z9hG4bKcf076ack\r\n" +
		"From: <sip:stub@127.0.0.1>;tag=cf076s\r\nTo: " + toHdr + "\r\n" +
		"Call-ID: cf076-inv@127.0.0.1\r\nCSeq: 1 ACK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n")
	send("BYE sip:alice@" + to + " SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP " + stub + ";branch=z9hG4bKcf076bye\r\n" +
		"From: <sip:stub@127.0.0.1>;tag=cf076s\r\nTo: " + toHdr + "\r\n" +
		"Call-ID: cf076-inv@127.0.0.1\r\nCSeq: 2 BYE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n")
	bye := readUntil(t, r, "SIP/2.0 200")
	if !strings.Contains(bye, "CSeq: 2 BYE") {
		t.Fatalf("the response after the BYE is not its 200:\n%s", bye)
	}
}

func TestUDPUACloseReleasesTheTCPListenerAndItsConnections(t *testing.T) {
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	addr := ua.BoundAddr().String()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	// make sure the connection is accepted and pooled before closing
	_, _ = c.Write([]byte(tcpOptions(c.LocalAddr().String(), addr, "z9hG4bKcf076close")))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readStreamMsg(bufio.NewReader(c)); err != nil {
		t.Fatalf("no response before Close: %v", err)
	}

	if err := ua.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("the stub's connection was not closed: %v", err)
	}
	assertTCPRefused(t, addr)
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// assertTCPRefused expects a TCP dial to addr to fail; it retries once after
// 100 ms in case the kernel handed the freed port to another test.
func assertTCPRefused(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 2; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return
		}
		_ = c.Close()
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("a TCP dial to %s still connects: the listener is open", addr)
}

func TestUDPUAContextCancelReleasesTheTCPListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ua, err := sipua.New(ctx, sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	addr := ua.BoundAddr().String()
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return
		}
		_ = c.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the TCP listener at %s survived the daemon context's cancel", addr)
}

func TestNewUDPPinnedPortFailsWhenItsTCPTwinIsTaken(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = held.Close() }()
	addr := held.Addr().String()

	_, err = sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: addr,
	})
	var ae *apierr.Error
	if err == nil || !asAPIErr(err, &ae) || ae.Code != apierr.CodeInvalidArgument || !strings.Contains(err.Error(), "tcp") {
		t.Fatalf("want an invalid_argument error naming tcp, got %v", err)
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("the UDP half was not released: %v", err)
	}
	_ = pc.Close()
}

// The listener is capped (CF-076, owner ruling): connections over the cap are
// closed at accept.
func TestUDPUATCPListenerCapsConnections(t *testing.T) {
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	addr := ua.BoundAddr().String()
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	limit := sipua.MaxInboundTCPConnsForTest
	for i := 0; i < limit; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	// let the accept loop take every slot, then one more
	time.Sleep(200 * time.Millisecond)
	extra, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial extra: %v", err)
	}
	defer func() { _ = extra.Close() }()
	_ = extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("connection %d over the cap of %d was not closed: %v", limit+1, limit, err)
	}
}
