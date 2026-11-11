package sipua_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
)

func newStreamUA(t *testing.T, transport, aor string, ring time.Duration) *sipua.UA {
	t.Helper()
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: transport, Mode: "direct", AOR: aor, LocalAddr: "127.0.0.1:0",
		Timeout: 2 * time.Second, InboundRingTimeout: ring, Clock: clock.System(),
	})
	if err != nil {
		t.Fatalf("New(%s): %v", transport, err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua
}

func fillSlots(t *testing.T, addr string) []net.Conn {
	t.Helper()
	var conns []net.Conn
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	for i := 0; i < sipua.MaxInboundTCPConnsForTest; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	time.Sleep(200 * time.Millisecond) // let the accept loop take every slot
	return conns
}

// CF-189: a tcp/tls UA's listener is capped like the UDP UA's.
func TestStreamUAListenerCapsConnections(t *testing.T) {
	for _, tr := range []string{"tcp", "tls"} {
		t.Run(tr, func(t *testing.T) {
			ua := newStreamUA(t, tr, "sip:bob@example", 0)
			addr := ua.LocalAddr().String()
			fillSlots(t, addr)
			extra, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Fatalf("dial extra: %v", err)
			}
			defer func() { _ = extra.Close() }()
			_ = extra.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := extra.Read(make([]byte, 1)); err == nil || isTimeout(err) {
				t.Fatalf("connection over the cap was not closed: %v", err)
			}
		})
	}
}

// D6C-8: at the cap, a connection silent for the floor makes room.
func TestStreamUAListenerEvictsAnIdleConnectionAtTheCap(t *testing.T) {
	restore := sipua.SetInboundTCPEvictIdleForTest(300 * time.Millisecond)
	defer restore()
	ua := newStreamUA(t, "tcp", "sip:bob@example", 0)
	addr := ua.LocalAddr().String()
	conns := fillSlots(t, addr)
	time.Sleep(400 * time.Millisecond)
	extra, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial extra: %v", err)
	}
	defer func() { _ = extra.Close() }()
	_ = conns[0].SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conns[0].Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("the oldest idle connection was not evicted: %v", err)
	}
	_ = extra.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := extra.Read(make([]byte, 1)); !isTimeout(err) {
		t.Fatalf("the new connection was not kept open: %v", err)
	}
}

// CF-080 regression: our tcp UA leaks a connection per request, so 20 calls to
// one of our own tcp UAs must still be answered with a capped listener.
func TestStreamUAListenerSurvivesTwentyCallsFromOurOwnTCPUA(t *testing.T) {
	restore := sipua.SetInboundTCPEvictIdleForTest(300 * time.Millisecond)
	defer restore()
	ctx := context.Background()
	callee := newStreamUA(t, "tcp", "sip:bob@example", 2*time.Second)
	inbound := make(chan session.UAEvent, 1)
	callee.OnAdmit(ctx, func(_ context.Context, ev session.UAEvent) session.Admission {
		if !ev.AdmitProbe {
			inbound <- ev
		}
		return session.AdmitAccept()
	})
	caller := newStreamUA(t, "tcp", "sip:alice@example", 0)
	events := collect(t, caller)

	for i := 0; i < 20; i++ {
		res, err := caller.Dial(ctx, session.DialRequest{ToURI: "sip:bob@" + callee.LocalAddr().String()})
		if err != nil {
			t.Fatalf("call %d: Dial: %v", i+1, err)
		}
		select {
		case ev := <-inbound:
			if err := callee.AnswerEventually(ctx, session.AnswerRequest{DialogID: ev.DialogID}); err != nil {
				t.Fatalf("call %d: Answer: %v", i+1, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("call %d: the callee never saw the INVITE", i+1)
		}
		deadline := time.Now().Add(3 * time.Second)
		for answered := false; !answered; {
			for _, ev := range events() {
				if ev.DialogID == res.DialogID && ev.Kind == session.UAEventFinal && ev.Code == 200 {
					answered = true
				}
			}
			if !answered && time.Now().After(deadline) {
				t.Fatalf("call %d was not answered", i+1)
			}
			time.Sleep(5 * time.Millisecond)
		}
		if err := caller.Hangup(ctx, res.DialogID, "local_hangup"); err != nil {
			t.Fatalf("call %d: Hangup: %v", i+1, err)
		}
		time.Sleep(400 * time.Millisecond)
	}
}
