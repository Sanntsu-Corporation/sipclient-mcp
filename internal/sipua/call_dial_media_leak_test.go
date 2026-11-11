package sipua_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// newDirectUANarrowMediaRange builds a direct-mode UA exactly like
// newDirectUACfg (call_outbound_test.go), but with a MediaPortRange
// containing exactly ONE even port — [16460,16460]. That makes bindMediaPort
// a strict single-socket resource: a SECOND Dial() on the SAME UA can only
// succeed if whatever socket the FIRST Dial bound was actually released.
// Local to this file because no other test needs a range this narrow (Rule
// 15/18: not promoted to a shared helper for a single caller).
func newDirectUANarrowMediaRange(t *testing.T, clk *fakeclock.Clock) *sipua.UA {
	t.Helper()
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport:          "udp",
		Mode:               "direct",
		AOR:                "sip:alice@example",
		ExpiresS:           300,
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              clk,
		LocalAddr:          "127.0.0.1:0",
		MediaPortRange:     [2]int{16460, 16460},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua
}

// TestDialSIPFailureReleasesMediaSocket is the regression gate for the media
// socket leak a Rule 9 verifier found in d5ba843 (Task 9: runDial's
// ACK-then-BYE wiring). Dial binds a real UDP media socket via bindMediaPort
// and stores it on d.mediaConn BEFORE the INVITE transaction even runs, so
// EVERY early-return branch in runDial that predates that change must also
// release it on the way out — not just the phaseMediaTeardown branch that
// teardownDialog already covers.
//
// This drives runDial's "SIP failure response" branch (res.StatusCode outside
// 2xx — here, 486 Busy) on a UA whose MediaPortRange holds exactly ONE port:
// a second Dial() on the SAME UA can only bind if the first call's socket was
// actually closed. Before the fix, the first Dial's socket leaks and the
// second Dial fails with apierr.Internal wrapping bindMediaPort's "no free
// even media port in range 16460-16460" — this test fails on that error.
func TestDialSIPFailureReleasesMediaSocket(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RejectStatus: 486}})
	ua := newDirectUANarrowMediaRange(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	firstDial, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("first Dial: %v", err)
	}
	// Scoped by DialogID (not just waitFor's kind+code) so this genuinely
	// blocks until THIS call's own runDial branch has run to completion —
	// including the mediaConn.Close() this test guards, which the fixed code
	// executes strictly before emitting this very event — so by the time this
	// returns, the first call's socket has already been released (or leaked,
	// pre-fix). Without the DialogID scope, a later occurrence of the same
	// kind+code (e.g. the second Dial's own 486) could satisfy this wait
	// instead, letting the test return before this dialog's own cleanup runs
	// and racing the port with whatever the next test binds.
	first := waitForDialog(t, events, firstDial.DialogID, session.UAEventFinal, 486)
	if first.Code != 486 {
		t.Fatalf("first call final code = %d, want 486", first.Code)
	}

	// The second Dial reuses the SAME single-port range. It can only succeed
	// if the first call's media socket was actually released.
	secondDial, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("second Dial failed — media socket leak from the first call's "+
			"SIP-failure-response branch: %v", err)
	}
	waitForDialog(t, events, secondDial.DialogID, session.UAEventFinal, 486)
}

// waitForDialog is waitFor (call_outbound_test.go), scoped additionally to a
// specific DialogID — needed whenever a test issues two calls on the SAME UA
// that can produce the SAME kind+code final, where waitFor's kind+code match
// alone cannot tell "the call I just issued finished" from "an EARLIER call's
// event is still sitting in the buffer".
func waitForDialog(t *testing.T, events func() []session.UAEvent, dialogID string, kind session.UAEventKind, code int) session.UAEvent {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range events() {
			if ev.DialogID == dialogID && ev.Kind == kind && (code == 0 || ev.Code == code) {
				return ev
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no %q event with code %d for dialog %q within 3s", kind, code, dialogID)
	return session.UAEvent{}
}

// TestDialTransportFaultReleasesMediaSocket is the same regression, driven
// through runDial's OTHER pre-existing early return: "no response at all" (a
// transport fault). It dials a closed UDP socket — nothing listens there, so
// the INVITE transaction times out with no response of any kind — the same
// construction TestDialTimeoutEmitsADialogScopedEndNotATransportFault (call_outbound_test.go)
// uses, here layered onto the single-port UA so a second Dial proves the
// first call's socket was released.
func TestDialTransportFaultReleasesMediaSocket(t *testing.T) {
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := dead.LocalAddr().String()
	_ = dead.Close()

	ua := newDirectUANarrowMediaRange(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	firstDial, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + addr})
	if err != nil {
		t.Fatalf("first Dial: %v", err)
	}
	waitForDialog(t, events, firstDial.DialogID, session.UAEventDialogEnded, 0)

	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	secondDial, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		if strings.Contains(err.Error(), "no free even media port") {
			t.Fatalf("second Dial failed — media socket leak from the first call's "+
				"transport-fault branch: %v", err)
		}
		t.Fatalf("second Dial: %v", err)
	}
	waitForDialog(t, events, secondDial.DialogID, session.UAEventFinal, 200)
}

// ackFailConn is a net.PacketConn decorator installed via Config.WrapConn
// (the same seam countingConn, countingconn_test.go, uses) that makes
// exactly ONE outbound ACK write fail with a synthetic error, while passing
// every other datagram — including a SECOND call's ACK — through to the real
// conn unchanged. It reuses firstLine (countingconn_test.go, same
// sipua_test package) rather than reimplementing the SIP-first-line parse.
//
// Single-shot by design (Rule 15): an unconditional ACK failure would also
// fail the second Dial's own ACK, forcing it down the SAME transport-fault
// branch and only letting this test assert "no port-exhaustion error" rather
// than a genuine completed call. A one-shot atomic.Bool is barely more code
// and buys the strictly stronger proof: the second Dial reaches a real 200
// OK, on the exact socket the first Dial's ACK-failure branch must have
// released.
type ackFailConn struct {
	net.PacketConn
	fired atomic.Bool
}

func (c *ackFailConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if strings.HasPrefix(firstLine(b), "ACK ") && c.fired.CompareAndSwap(false, true) {
		return 0, fmt.Errorf("injected ack write failure")
	}
	return c.PacketConn.WriteTo(b, addr)
}

// TestDialACKSendFailureReleasesMediaSocket is the third and last regression
// gate for the d5ba843/4fd3235 media-socket leak, covering the ONE early-exit
// branch in runDial the other two tests in this file do not: the mandatory
// ACK write (§11.2.1 step 1) failing after a genuine 2xx response. Unlike the
// SIP-failure-response and transport-fault branches, this one is reached only
// after a full, successful INVITE/200 OK exchange — the peer here uses the
// DEFAULT Behaviour (accepts, answers 200 OK) precisely so an earlier branch
// cannot intercept first.
//
// ackFailConn intercepts the ACK datagram one layer below
// Client().Raw().WriteRequest — at the UDP socket WrapConn already exposes —
// which sidesteps having to fake a WriteRequest-level failure sipgo's client
// does not offer a seam for.
//
// On a UA whose MediaPortRange holds exactly ONE port, a second Dial() can
// only bind if the first call's media socket was actually released by this
// branch's `d.mediaConn.Close()` guard. Before the fix, the first Dial's
// socket leaks and the second Dial fails with apierr.Internal wrapping
// bindMediaPort's "no free even media port in range 16462-16462".
func TestDialACKSendFailureReleasesMediaSocket(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})

	var fc *ackFailConn
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport:          "udp",
		Mode:               "direct",
		AOR:                "sip:alice@example",
		ExpiresS:           300,
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              fakeclock.New(time.Unix(0, 0)),
		LocalAddr:          "127.0.0.1:0",
		// A DIFFERENT single port than newDirectUANarrowMediaRange's 16460
		// (used by the two sibling tests above). This test's second Dial
		// deliberately completes with a genuine 200 OK and is never torn
		// down by an explicit BYE, so its media socket stays bound until
		// this UA's t.Cleanup(ua.Close) runs — and Close is documented
		// (ua.go) as "transport teardown only", not a synchronous per-dialog
		// media-socket release. Sharing 16460 with
		// TestDialTransportFaultReleasesMediaSocket (same lingering-socket
		// shape) produced an observed cross-test ordering flake when the two
		// ran back-to-back in one `go test` process: this test's first Dial
		// occasionally lost the bind race against the other test's
		// not-yet-released socket. A distinct port removes the collision
		// without touching that pre-existing test or any production code.
		MediaPortRange: [2]int{16462, 16462},
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			fc = &ackFailConn{PacketConn: pc}
			return fc
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	_ = fc // installed via WrapConn above; referenced only to avoid an unused-var trip if reordered
	events := collect(t, ua)

	firstDial, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("first Dial: %v", err)
	}
	// Scoped by DialogID, and waiting for UAEventDialogEnded (not
	// UAEventFinal) — this branch's product per call.go: on an ACK write
	// error, runDial emits a dialog-scoped UAEventDialogEnded with Reason "ack send: "
	// + err.Error(), never a UAEventFinal. Asserting the reason contains
	// "ack send" proves THIS branch fired, not the "no response at all"
	// transport-fault branch TestDialTransportFaultReleasesMediaSocket
	// already covers.
	first := waitForDialog(t, events, firstDial.DialogID, session.UAEventDialogEnded, 0)
	if !strings.Contains(first.Reason, "ack send") {
		t.Fatalf("first call dialog-end reason = %q, want it to contain %q", first.Reason, "ack send")
	}

	// The second Dial reuses the SAME single-port range. Its own ACK is NOT
	// intercepted (ackFailConn fires once), so it can only succeed — reaching
	// a genuine 200 OK — if the first call's media socket was actually
	// released.
	secondDial, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("second Dial failed — media socket leak from the first call's "+
			"ACK-send-failure branch: %v", err)
	}
	waitForDialog(t, events, secondDial.DialogID, session.UAEventFinal, 200)

	// Unlike the two sibling tests above, this call is explicitly hung up
	// rather than left for t.Cleanup(ua.Close) to reap. ua.Close is
	// documented (ua.go) as "transport teardown only" — it does not
	// synchronously release a still-answered dialog's media socket — so
	// leaving this call connected made this test's own port ordering-
	// dependent against whatever ran immediately before/after it in the same
	// `go test` process (observed directly: back-to-back runs of this test
	// via -count=2 intermittently lost the second port bind race). Hangup, by
	// contrast, synchronously closes d.mediaConn before returning (call.go),
	// so this cleanup is deterministic rather than relying on Close's async
	// teardown timing.
	if err := ua.Hangup(context.Background(), secondDial.DialogID, ""); err != nil {
		t.Fatalf("hangup second call: %v", err)
	}
}
