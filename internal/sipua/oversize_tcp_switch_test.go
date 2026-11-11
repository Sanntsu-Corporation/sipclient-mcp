package sipua_test

// CF-106 (RFC 3261 18.1.1): a request over 1300 bytes from a UDP UA is sent
// over TCP. The fork does the switch (third_party/sipgo/sip
// transport_layer_size_switch_test.go); these tests cover the two UA changes
// that make it usable and the end-to-end call. No test here calls t.Parallel.

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

var oversizeHeaders = map[string]string{"X-Rfcfix1-Pad": strings.Repeat("a", 1400)}

// tcpInviteSink listens on a loopback TCP port and delivers each accepted
// connection (after its first message, which must be read by the caller via
// the returned bufio.Reader) on conns.
func tcpInviteSink(t *testing.T) (addr string, conns <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ch := make(chan net.Conn, 4)
	acceptAll(t, ln, func(c net.Conn) {
		ch <- c
	})
	return ln.Addr().String(), ch
}

func TestOversizeInviteFromAUDPUAIsAnsweredOverTCP(t *testing.T) {
	ctx := context.Background()
	callee, err := sipua.New(ctx, sipua.Config{
		Transport: "tcp", Mode: "direct", AOR: "sip:bob@example",
		LocalAddr: "127.0.0.1:0", Timeout: 2 * time.Second,
		InboundRingTimeout: 2 * time.Second, Clock: clock.System(),
	})
	if err != nil {
		t.Fatalf("New(callee): %v", err)
	}
	t.Cleanup(func() { _ = callee.Close(ctx) })
	inbound := make(chan session.UAEvent, 1)
	callee.OnAdmit(ctx, func(_ context.Context, ev session.UAEvent) session.Admission {
		inbound <- ev
		return session.AdmitAccept()
	})

	caller, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, caller)

	if _, err := caller.Dial(ctx, session.DialRequest{
		ToURI:   "sip:bob@" + callee.LocalAddr().String(),
		Headers: oversizeHeaders,
	}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	var ev session.UAEvent
	select {
	case ev = <-inbound:
	case <-time.After(3 * time.Second):
		t.Fatal("the callee never saw the oversize INVITE")
	}
	waitFor(t, events, session.UAEventProvisional, 180)
	if err := callee.AnswerEventually(ctx, session.AnswerRequest{DialogID: ev.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
}

func TestUDPUAOversizeInvitesToTwoPeersBothDial(t *testing.T) {
	addrA, connsA := tcpInviteSink(t)
	addrB, connsB := tcpInviteSink(t)
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	_ = collect(t, ua)

	for _, tc := range []struct {
		name  string
		addr  string
		conns <-chan net.Conn
	}{{"first", addrA, connsA}, {"second", addrB, connsB}} {
		if _, err := ua.Dial(context.Background(), session.DialRequest{
			ToURI: "sip:bob@" + tc.addr, Headers: oversizeHeaders,
		}); err != nil {
			t.Fatalf("Dial %s: %v", tc.name, err)
		}
		select {
		case c := <-tc.conns:
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			msg, err := readStreamMsg(bufio.NewReader(c))
			if err != nil || !strings.HasPrefix(msg, "INVITE ") {
				t.Fatalf("%s peer: read %.60q, err %v; want an INVITE", tc.name, msg, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("the %s peer received no TCP connection", tc.name)
		}
	}
}

func TestUDPUACloseReleasesItsTCPConnections(t *testing.T) {
	addr, conns := tcpInviteSink(t)
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	_ = collect(t, ua)
	if _, err := ua.Dial(context.Background(), session.DialRequest{
		ToURI: "sip:bob@" + addr, Headers: oversizeHeaders,
	}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	var c net.Conn
	select {
	case c = <-conns:
	case <-time.After(3 * time.Second):
		t.Fatal("the peer received no TCP connection")
	}
	r := bufio.NewReader(c)
	if _, err := readStreamMsg(r); err != nil {
		t.Fatalf("read INVITE: %v", err)
	}

	if err := ua.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		// A CANCEL or BYE may precede the close; the read must end in EOF.
		if _, err := readStreamMsg(r); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("read after UA.Close: %v, want EOF (the UA's TCP connection stayed open)", err)
			}
			return
		}
	}
}
