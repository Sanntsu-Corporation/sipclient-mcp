package sipua

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

func TestTCPUABindsAndReportsTCPLocalAddr(t *testing.T) {
	ua, err := New(context.Background(), Config{
		Transport: "tcp",
		LocalAddr: "127.0.0.1:0", // ephemeral to avoid port conflicts in CI
		Logger:    testLogger(),
	})
	if err != nil {
		t.Fatalf("New(tcp): %v", err)
	}
	defer func() { _ = ua.Close(context.Background()) }()

	la := ua.LocalAddr()
	if la.Network() != "tcp" {
		t.Fatalf("LocalAddr().Network() = %q, want \"tcp\"", la.Network())
	}
	if _, ok := la.(*net.TCPAddr); !ok {
		t.Fatalf("LocalAddr() = %T, want *net.TCPAddr", la)
	}
	// BoundAddr stays the *net.UDPAddr IP/port convenience.
	if ua.BoundAddr().IP == nil || ua.BoundAddr().Port == 0 {
		t.Fatalf("BoundAddr() must carry a concrete IP:port, got %v", ua.BoundAddr())
	}
}

// TestTCPInboundAndOutboundCallsComplete drives a real loopback TCP call in
// both directions using two production UAs as each other's peer — the
// minimal test-only "TCP peer" this task needs (the shared internal/testutil/
// peer harness is UDP-only, and byte-level SIP framing over a raw net.Conn is
// T5's observestream concern, not this task's). It exercises T2's bind/
// listen/dial wiring end to end: the callee's ServeTCP accept loop, T1's B2
// ephemeral-dial-port opt-in on the caller's outbound leg (a UA that also
// listens must not EADDRINUSE dialing out), and the transport-correct
// LocalAddr both UAs report.
func TestTCPInboundAndOutboundCallsComplete(t *testing.T) {
	ctx := context.Background()

	callee, err := New(ctx, Config{
		Transport:          "tcp",
		Mode:               "direct",
		AOR:                "sip:bob@example",
		LocalAddr:          "127.0.0.1:0",
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              clock.System(),
		Logger:             testLogger(),
	})
	if err != nil {
		t.Fatalf("New(callee): %v", err)
	}
	defer func() { _ = callee.Close(ctx) }()

	caller, err := New(ctx, Config{
		Transport: "tcp",
		Mode:      "direct",
		AOR:       "sip:alice@example",
		LocalAddr: "127.0.0.1:0",
		Timeout:   2 * time.Second,
		Clock:     clock.System(),
		Logger:    testLogger(),
	})
	if err != nil {
		t.Fatalf("New(caller): %v", err)
	}
	defer func() { _ = caller.Close(ctx) }()

	// The callee's inbound INVITE arrives on the synchronous OnAdmit channel
	// (UAEventInbound is deliberately absent from OnEvent); capture its
	// DialogID so the test can Answer it.
	inbound := make(chan session.UAEvent, 1)
	callee.OnAdmit(ctx, func(_ context.Context, ev session.UAEvent) session.Admission {
		inbound <- ev
		return session.AdmitAccept()
	})

	callerEvents := make(chan session.UAEvent, 8)
	caller.OnEvent(ctx, func(_ context.Context, ev session.UAEvent) {
		callerEvents <- ev
	})

	// Outbound leg: the caller dials the callee over TCP.
	if _, err := caller.Dial(ctx, session.DialRequest{ToURI: "sip:bob@" + callee.LocalAddr().String()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Inbound leg: the callee's TCP listener accepted the INVITE.
	var ev session.UAEvent
	select {
	case ev = <-inbound:
	case <-time.After(3 * time.Second):
		t.Fatal("callee never observed an inbound INVITE over TCP")
	}
	if ev.Kind != session.UAEventInbound {
		t.Fatalf("callee admission event kind = %q, want inbound", ev.Kind)
	}
	if err := callee.AnswerEventually(ctx, session.AnswerRequest{DialogID: ev.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}

	// Both directions complete: the caller must observe the 200 OK.
	deadline := time.After(3 * time.Second)
	for {
		select {
		case cev := <-callerEvents:
			if cev.Kind == session.UAEventFinal && cev.Code == 200 {
				return
			}
		case <-deadline:
			t.Fatal("caller never observed a 200 OK over TCP")
		}
	}
}
