package sipua_test

// P2 W2c T5, Step 7: the end-to-end both-direction capture test (Cycle B
// verify item 3 caveat: stream Raw is post-redaction, same as UDP) and the
// two-concurrent-UA attribution test (Cycle B item 1 — the highest-risk
// correctness property in the wave: the fork's dial-wrap hook, third_party/
// sipgo/sip/transport_tcp.go's/transport_tls.go's dialConnWrap field, is
// INSTANCE-scoped per transportTCP/transportTLS, never a package-level
// global, so two concurrently-running UAs' outbound captures cannot bleed
// into each other).
//
// Both tests wire sipua.Config.WrapListener/WrapDialConn exactly as
// cmd/sipclient-mcpd/run.go's composition root does for the real daemon
// (sipua.ObservingListener/ObservingStreamConn stamping a UA handle) —
// sipua.Config itself carries no UA handle (L5), so this file's
// newCaptureTCPUA is a test-only recreation of that one composition site,
// not a second production wiring path.

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/trace"
)

// newCaptureTCPUA builds a tcp UA with the T5 inbound+outbound capture seams
// wired, tee-ing every observed SIP message into tap with uaHandle stamped
// on every record.
func newCaptureTCPUA(ctx context.Context, t *testing.T, cfg sipua.Config, tap session.Tap, uaHandle string) *sipua.UA {
	t.Helper()
	cfg.Transport = "tcp"
	cfg.WrapListener = func(ln net.Listener) net.Listener {
		return sipua.ObservingListener(ln, tap, session.TransportTCP, clock.System().Now, uaHandle)
	}
	cfg.WrapDialConn = func(c net.Conn) net.Conn {
		return sipua.ObservingStreamConn(c, tap, session.TransportTCP, clock.System().Now, uaHandle)
	}
	ua, err := sipua.New(ctx, cfg)
	if err != nil {
		t.Fatalf("sipua.New(%s): %v", uaHandle, err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua
}

// driveCall dials callee (at toURI, which MUST address the callee's own AOR
// user — u.targets, call.go:1104, 404s an INVITE addressed to any other user)
// from caller and drives the exchange to a 200 OK, returning an error rather
// than calling t.Fatal — TestTCPTwoUAsDialWrap... below runs two of these
// concurrently in separate goroutines, and (*testing.T).FailNow (which
// t.Fatal calls) is documented as callable only from the goroutine running
// the test function itself.
func driveCall(ctx context.Context, caller, callee *sipua.UA, toURI string, calleeInbound <-chan session.UAEvent, callerEvents <-chan session.UAEvent) error {
	if _, err := caller.Dial(ctx, session.DialRequest{ToURI: toURI}); err != nil {
		return fmt.Errorf("Dial: %w", err)
	}

	var ev session.UAEvent
	select {
	case ev = <-calleeInbound:
	case <-time.After(3 * time.Second):
		return fmt.Errorf("callee never observed an inbound INVITE over TCP")
	}
	if ev.Kind != session.UAEventInbound {
		return fmt.Errorf("callee admission event kind = %q, want inbound", ev.Kind)
	}
	if err := callee.AnswerEventually(ctx, session.AnswerRequest{DialogID: ev.DialogID}); err != nil {
		return fmt.Errorf("Answer: %w", err)
	}

	deadline := time.After(3 * time.Second)
	for {
		select {
		case cev := <-callerEvents:
			if cev.Kind == session.UAEventFinal && cev.Code == 200 {
				return nil
			}
		case <-deadline:
			return fmt.Errorf("caller never observed a 200 OK over TCP")
		}
	}
}

// assertProtocol6 checks the IP protocol byte of a trace.Pcap() rendering
// that holds EXACTLY one record: 24-byte global file header, then a 16-byte
// pcap record header, then the 20-byte synthesised IPv4 header whose byte 9
// is the protocol field (mirrors internal/trace's own TestPcapFrameTCP...
// assertions, one level up through the exported Pcap() batch renderer rather
// than the unexported per-record encoder).
func assertProtocol6(t *testing.T, out []byte) {
	t.Helper()
	const globalHdr, recHdr, protocolOff = 24, 16, 9
	off := globalHdr + recHdr + protocolOff
	if len(out) <= off {
		t.Fatalf("pcap output too short (%d bytes) to hold an IPv4 header at offset %d", len(out), off)
	}
	if out[off] != 6 {
		t.Fatalf("IP protocol = %d, want 6 (TCP)", out[off])
	}
}

// TestTCPBothDirectionCaptureRendersProtocol6Frames drives a real loopback
// TCP call between two production UAs with the T5 seams wired (inbound via
// Config.WrapListener/ObservingListener, outbound via Config.WrapDialConn ->
// sipgo's instance-scoped WithDialConnWrap hook), collects the captured
// records, and asserts BOTH an inbound and an outbound SIP message render as
// protocol-6 (TCP) frames through internal/trace's Pcap() — the plan's T5
// Step 7 acceptance test.
func TestTCPBothDirectionCaptureRendersProtocol6Frames(t *testing.T) {
	ctx := context.Background()
	tap := &capturingTap{}

	callee := newCaptureTCPUA(ctx, t, sipua.Config{
		Mode: "direct", AOR: "sip:bob@example", LocalAddr: "127.0.0.1:0",
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second, Clock: clock.System(),
	}, tap, "ua-e2e")
	caller := newCaptureTCPUA(ctx, t, sipua.Config{
		Mode: "direct", AOR: "sip:alice@example", LocalAddr: "127.0.0.1:0",
		Timeout: 2 * time.Second, Clock: clock.System(),
	}, tap, "ua-e2e")

	inbound := make(chan session.UAEvent, 1)
	callee.OnAdmit(ctx, func(_ context.Context, ev session.UAEvent) session.Admission {
		inbound <- ev
		return session.AdmitAccept()
	})
	callerEvents := make(chan session.UAEvent, 8)
	caller.OnEvent(ctx, func(_ context.Context, ev session.UAEvent) { callerEvents <- ev })

	toURI := "sip:bob@" + callee.LocalAddr().String()
	if err := driveCall(ctx, caller, callee, toURI, inbound, callerEvents); err != nil {
		t.Fatalf("driveCall: %v", err)
	}

	recs := tap.all()
	if len(recs) == 0 {
		t.Fatal("tap recorded no messages at all")
	}

	// D3 note: a loopback self-call means BOTH the caller's outbound leg and
	// the callee's inbound leg (and their respective in-dialog responses)
	// land in the same tap, so both directions are expected among recs.
	var haveInbound, haveOutbound bool
	var inboundRec, outboundRec session.SIPRecord
	for _, rec := range recs {
		if rec.Transport != session.TransportTCP {
			t.Errorf("record Transport = %q, want tcp for every record in this test", rec.Transport)
		}
		switch rec.Direction {
		case session.Inbound:
			if !haveInbound {
				inboundRec, haveInbound = rec, true
			}
		case session.Outbound:
			if !haveOutbound {
				outboundRec, haveOutbound = rec, true
			}
		}
	}
	if !haveInbound {
		t.Fatal("no inbound SIP message was captured")
	}
	if !haveOutbound {
		t.Fatal("no outbound SIP message was captured")
	}

	inFrame, err := trace.Pcap([]session.SIPRecord{inboundRec})
	if err != nil {
		t.Fatalf("Pcap(inbound): %v", err)
	}
	assertProtocol6(t, inFrame)

	outFrame, err := trace.Pcap([]session.SIPRecord{outboundRec})
	if err != nil {
		t.Fatalf("Pcap(outbound): %v", err)
	}
	assertProtocol6(t, outFrame)

	// The full batch renders too (the acceptance criterion: "a pcap where a
	// tcp/tls call shows both directions as protocol-6 frames").
	if _, err := trace.Pcap(recs); err != nil {
		t.Fatalf("Pcap(all records): %v", err)
	}
}

// TestTCPTwoUAsDialWrapInstanceScopedNoCrossContamination is the Cycle B
// item 1 attribution test: two independent, CAPTURE-WIRED caller UAs (ua-A,
// ua-B), each with its own tap and its own handle-stamping WrapListener/
// WrapDialConn closures, dial two independent plain (uncaptured) peers
// CONCURRENTLY, so both UAs' outbound dial-wrap hooks (third_party/sipgo's
// per-instance transportTCP.dialConnWrap field) are live and dialing at the
// same time. If the hook were a package-level global rather than instance-
// scoped, the two concurrent dials would race and at least one UA's outbound
// records would misattribute to the other's handle. Each UA's tap must carry
// ONLY its own UAHandle — and, since ObservingStreamConn stamps direction
// per-Read/Write rather than per-conn-role (D3), a caller's own dial
// conn already carries BOTH directions (its INVITE write = outbound, the
// peer's 100 Trying/200 OK reads = inbound), so each UA satisfies "an
// inbound+outbound message" without needing to also act as a callee.
//
// Design note (why the peers are plain, uncaptured UAs, and why neither ua-A
// nor ua-B is ALSO dialed by its peer): when this test was written, an
// accepted connection was pooled under the UA's own listen address, so an
// inbound connection could carry the UA's next outbound dial. The CF-058
// divergence (third_party/sipgo/VENDOR.md) stopped pooling accepted
// connections under the listen address, so that hazard no longer exists. The
// test still keeps both UAs undialled by their peers, which keeps it focused
// on Cycle B item 1's target (the fork's dial-wrap hook being
// instance-scoped).
//
// Deviation from the plan's literal "same Call-ID" phrasing, documented per
// Rule 6c: session.DialRequest exposes no field to set an outbound Call-ID
// (sipua mints it internally, call.go), so two independent Dial calls cannot
// be forced onto one literal Call-ID without widening that struct — out of
// T5's scope. Running both dials concurrently exercises exactly the property
// Cycle B item 1 is guarding against (two simultaneously-active per-instance
// dial-wrap hooks not bleeding into each other); a coincidentally-matching
// Call-ID would not strengthen that assertion.
func TestTCPTwoUAsDialWrapInstanceScopedNoCrossContamination(t *testing.T) {
	ctx := context.Background()
	tapA := &capturingTap{}
	tapB := &capturingTap{}

	uaA := newCaptureTCPUA(ctx, t, sipua.Config{
		Mode: "direct", AOR: "sip:a@example", LocalAddr: "127.0.0.1:0",
		Timeout: 2 * time.Second, Clock: clock.System(),
	}, tapA, "ua-A")
	uaB := newCaptureTCPUA(ctx, t, sipua.Config{
		Mode: "direct", AOR: "sip:b@example", LocalAddr: "127.0.0.1:0",
		Timeout: 2 * time.Second, Clock: clock.System(),
	}, tapB, "ua-B")

	// peerX/peerY are plain production UAs with NO capture wiring — they are
	// dial TARGETS only, never dialed by ua-A/ua-B in return, so the
	// connection-reuse hazard documented above cannot arise.
	peerX, err := sipua.New(ctx, sipua.Config{
		Transport: "tcp", Mode: "direct", AOR: "sip:x@example", LocalAddr: "127.0.0.1:0",
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second, Clock: clock.System(),
	})
	if err != nil {
		t.Fatalf("sipua.New(peerX): %v", err)
	}
	t.Cleanup(func() { _ = peerX.Close(context.Background()) })
	peerY, err := sipua.New(ctx, sipua.Config{
		Transport: "tcp", Mode: "direct", AOR: "sip:y@example", LocalAddr: "127.0.0.1:0",
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second, Clock: clock.System(),
	})
	if err != nil {
		t.Fatalf("sipua.New(peerY): %v", err)
	}
	t.Cleanup(func() { _ = peerY.Close(context.Background()) })

	inboundX := make(chan session.UAEvent, 1)
	peerX.OnAdmit(ctx, func(_ context.Context, ev session.UAEvent) session.Admission {
		inboundX <- ev
		return session.AdmitAccept()
	})
	eventsA := make(chan session.UAEvent, 8)
	uaA.OnEvent(ctx, func(_ context.Context, ev session.UAEvent) { eventsA <- ev })

	inboundY := make(chan session.UAEvent, 1)
	peerY.OnAdmit(ctx, func(_ context.Context, ev session.UAEvent) session.Admission {
		inboundY <- ev
		return session.AdmitAccept()
	})
	eventsB := make(chan session.UAEvent, 8)
	uaB.OnEvent(ctx, func(_ context.Context, ev session.UAEvent) { eventsB <- ev })

	toX := "sip:x@" + peerX.LocalAddr().String()
	toY := "sip:y@" + peerY.LocalAddr().String()
	errs := make(chan error, 2)
	go func() { errs <- driveCall(ctx, uaA, peerX, toX, inboundX, eventsA) }() // ua-A dials peerX
	go func() { errs <- driveCall(ctx, uaB, peerY, toY, inboundY, eventsB) }() // ua-B dials peerY, concurrently
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent call: %v", err)
		}
	}

	recsA := tapA.all()
	recsB := tapB.all()
	if len(recsA) == 0 {
		t.Fatal("tapA recorded no messages")
	}
	if len(recsB) == 0 {
		t.Fatal("tapB recorded no messages")
	}

	var aHasInbound, aHasOutbound bool
	for _, rec := range recsA {
		if rec.UAHandle != "ua-A" {
			t.Errorf("tapA record carries UAHandle = %q, want exactly ua-A (cross-contamination)", rec.UAHandle)
		}
		aHasInbound = aHasInbound || rec.Direction == session.Inbound
		aHasOutbound = aHasOutbound || rec.Direction == session.Outbound
	}
	if !aHasInbound || !aHasOutbound {
		t.Fatalf("ua-A: haveInbound=%v haveOutbound=%v, want both (its own dial conn carries the INVITE it wrote and the responses it read)", aHasInbound, aHasOutbound)
	}

	var bHasInbound, bHasOutbound bool
	for _, rec := range recsB {
		if rec.UAHandle != "ua-B" {
			t.Errorf("tapB record carries UAHandle = %q, want exactly ua-B (cross-contamination)", rec.UAHandle)
		}
		bHasInbound = bHasInbound || rec.Direction == session.Inbound
		bHasOutbound = bHasOutbound || rec.Direction == session.Outbound
	}
	if !bHasInbound || !bHasOutbound {
		t.Fatalf("ua-B: haveInbound=%v haveOutbound=%v, want both (its own dial conn carries the INVITE it wrote and the responses it read)", bHasInbound, bHasOutbound)
	}
}
