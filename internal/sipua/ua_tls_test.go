package sipua

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// TestTLSListenerCompletesHandshake dials the tls UA's listener directly with
// a bare crypto/tls client (InsecureSkipVerify, since the cert is
// self-signed) and asserts the TLS handshake itself completes — a
// transport-level check, independent of anything SIP, that the dual-role
// *tls.Config wired into tls.NewListener (T3 step 5) actually serves a
// working cert.
func TestTLSListenerCompletesHandshake(t *testing.T) {
	ua, err := New(context.Background(), Config{
		Transport: "tls",
		LocalAddr: "127.0.0.1:0", // ephemeral to avoid port conflicts in CI
		Logger:    testLogger(),
	})
	if err != nil {
		t.Fatalf("New(tls): %v", err)
	}
	defer func() { _ = ua.Close(context.Background()) }()

	conn, err := tls.Dial("tcp", ua.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.Handshake(); err != nil {
		t.Fatalf("Handshake: %v", err)
	}
}

// TestTLSInboundAndOutboundCallsComplete drives a real loopback TLS call in
// both directions using two production UAs as each other's peer, mirroring
// TestTCPInboundAndOutboundCallsComplete (T2). It exercises T3's wiring end
// to end and is the MANDATORY outbound-TLS coverage per spec §5: the caller's
// outbound Dial completes a real TLS handshake and INVITE against the
// callee's ServeTLS accept loop (the "loopback TLS SIP acceptor" is the
// callee UA itself), and the callee's inbound TLS handshake completes and its
// INVITE is answered, proving the SERVER *tls.Config serves the inbound
// listener and the SEPARATE CLIENT *tls.Config serves the outbound dialer
// (M7b's two-config split, §7 scope item 5).
func TestTLSInboundAndOutboundCallsComplete(t *testing.T) {
	ctx := context.Background()

	callee, err := New(ctx, Config{
		Transport:          "tls",
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
		Transport: "tls",
		Mode:      "direct",
		AOR:       "sip:alice@example",
		LocalAddr: "127.0.0.1:0",
		Timeout:   2 * time.Second,
		Clock:     clock.System(),
		Logger:    testLogger(),
		// The callee's cert is an ephemeral self-signed cert in no CA bundle,
		// so under the new default posture (M7b, RN-3) the caller's dial
		// would otherwise fail verification. This states in the test what was
		// previously implicit under the dual-role config's unconditional
		// InsecureSkipVerify.
		TLSInsecureSkipVerify: true,
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

	// Outbound leg: the caller dials the callee over TLS.
	if _, err := caller.Dial(ctx, session.DialRequest{ToURI: "sip:bob@" + callee.LocalAddr().String()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Inbound leg: the callee's TLS listener accepted the handshake and the
	// INVITE.
	var ev session.UAEvent
	select {
	case ev = <-inbound:
	case <-time.After(3 * time.Second):
		t.Fatal("callee never observed an inbound INVITE over TLS")
	}
	if ev.Kind != session.UAEventInbound {
		t.Fatalf("callee admission event kind = %q, want inbound", ev.Kind)
	}
	if err := callee.AnswerEventually(ctx, session.AnswerRequest{DialogID: ev.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}

	// Both directions complete: the caller must observe the 200 OK, proving
	// the outbound TLS dial completed end to end.
	deadline := time.After(3 * time.Second)
	for {
		select {
		case cev := <-callerEvents:
			if cev.Kind == session.UAEventFinal && cev.Code == 200 {
				return
			}
		case <-deadline:
			t.Fatal("caller never observed a 200 OK over TLS")
		}
	}
}
