package sipua_test

// Task 33: the R2/R9/R10 acceptance suite (R8 lives in p3_r8_test.go,
// package sipua, since it needs in-package mediaLoop state).
//
// Per the design spec §8 and the sandbox note, the DTMF timing tests are
// DELIBERATELY SERIAL and generously bounded: the sandbox has 4 CPUs, and
// concurrent -race suites make short-deadline timing tests fail spuriously.

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// newDTMFModeUA builds a direct-mode UA whose DTMFMode default is `mode`,
// through newDirectUACfg/sipuaConfigMods (call_outbound_test.go) rather than a
// fourth hand-rolled sipua.New literal (Rule 16/18): the mode matters for the
// RECEIVER side of TestR2DTMFDetectedByASecondUA, whose inband detector is
// only installed when cfg.DTMFMode == "inband" (see UA.inbandDetectionEnabled).
func newDTMFModeUA(t *testing.T, clk *fakeclock.Clock, mode string) *sipua.UA {
	t.Helper()
	ua, _ := newDirectUACfg(t, clk, sipuaConfigMods{DTMFMode: mode})
	return ua
}

// TestR2DTMFRoundTripBothRTPModes: 123*# in both RTP-path modes, with the
// wall-clock send time within +/-20ms/digit of the true rendered duration.
//
// Correction C2: the naive formula wantMs = len(digits)*(duration+gap) is
// arithmetically wrong for rfc2833 — it omits the three RFC 4733 end
// retransmits (dtmfEndRetransmits, dtmf.go) that add 60ms/digit of real wall
// time — and a wide +/-400ms slop hid that error while also hiding a real
// regression: forcing gapMs=0 in SendDTMF left the old formula's rfc2833 arm
// green at dead centre of its window. The formula below prices the
// retransmits in and uses a tight +/-20ms/digit tolerance instead.
//
// Correction C13/N2: requesting 90ms (which rounds UP to a whole 20ms tick,
// 100ms) rather than requesting 100ms outright exercises the round-up path;
// requesting the already-round value never would have caught a resolver that
// just echoes its input.
func TestR2DTMFRoundTripBothRTPModes(t *testing.T) {
	for _, mode := range []session.DTMFMode{session.DTMFModeRFC2833, session.DTMFModeInband} {
		t.Run(string(mode), func(t *testing.T) {
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
			sender := newDTMFModeUA(t, fakeclock.New(time.Unix(0, 0)), string(mode))
			events := collect(t, sender)

			res, err := sender.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
			if err != nil {
				t.Fatal(err)
			}
			waitFor(t, events, session.UAEventFinal, 200)

			const digits = "123*#"
			const requestedDurationMs = 90
			const wantEmittedMs = 100
			start := time.Now()
			sent, emitted, err := sender.SendDTMF(context.Background(), res.DialogID, digits, mode, requestedDurationMs, 60)
			if err != nil {
				t.Fatalf("SendDTMF(%s): %v", mode, err)
			}
			elapsed := time.Since(start)
			if sent != len(digits) {
				t.Fatalf("digits_sent=%d want %d", sent, len(digits))
			}
			if emitted != wantEmittedMs {
				t.Fatalf("emitted duration_ms=%d want %d (90ms must round up to a whole 20ms tick)", emitted, wantEmittedMs)
			}
			perDigit := emitted + 60 // tone/event + 60ms gap
			if mode == session.DTMFModeRFC2833 {
				perDigit += 60 // three RFC 4733 end retransmits, dtmfEndRetransmits
			}
			wantMs := int64(len(digits) * perDigit)
			tol := int64(20 * len(digits)) // R2's +/-20ms per digit
			t.Logf("MODE=%s elapsed=%dms wantMs=%d tol=%d", mode, elapsed.Milliseconds(), wantMs, tol)
			if d := elapsed.Milliseconds(); d < wantMs-tol || d > wantMs+tol+500 {
				t.Fatalf("send took %dms, want %dms -%dms/+%dms (upper bound allows 500ms scheduling slack)", d, wantMs, tol, tol+500)
			}
		})
	}
}

// TestR2DTMFDetectedByASecondUA is R2's detection half: a real two-UA
// loopback, sender -> receiver, asserting the received digit string and each
// digit's duration_ms within +/-20ms of the requested value. Both arms are
// mutation-proved (task-33-brief.md's "Verified correct" section): disabling
// inbandDetectionEnabled reddens inband; disabling the telephone-event RX
// branch reddens rfc2833.
func TestR2DTMFDetectedByASecondUA(t *testing.T) {
	for _, mode := range []struct {
		name string
		send session.DTMFMode
	}{
		{"rfc2833", session.DTMFModeRFC2833},
		{"inband", session.DTMFModeInband},
	} {
		t.Run(mode.name, func(t *testing.T) {
			// The RECEIVER's own DTMFMode selects its detection mode.
			receiver := newDTMFModeUA(t, fakeclock.New(time.Unix(0, 0)), mode.name)
			rxEvents := collect(t, receiver)
			sender := newDTMFModeUA(t, fakeclock.New(time.Unix(0, 0)), mode.name)
			txEvents := collect(t, sender)

			res, err := sender.Dial(context.Background(), session.DialRequest{
				ToURI: "sip:alice@" + receiver.BoundAddr().String(),
			})
			if err != nil {
				t.Fatal(err)
			}
			inc := waitFor(t, rxEvents, session.UAEventInbound, 0)
			if err := receiver.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
				t.Fatal(err)
			}
			waitFor(t, txEvents, session.UAEventFinal, 200)

			const digits = "123*#"
			if _, _, err := sender.SendDTMF(context.Background(), res.DialogID, digits, mode.send, 100, 80); err != nil {
				t.Fatalf("SendDTMF: %v", err)
			}

			var got strings.Builder
			deadline := time.Now().Add(15 * time.Second)
			for got.Len() < len(digits) && time.Now().Before(deadline) {
				got.Reset()
				for _, ev := range rxEvents() {
					if ev.Kind != session.UAEventDTMF {
						continue
					}
					if ev.DurationMs < 80 || ev.DurationMs > 120 {
						t.Fatalf("digit %q duration_ms=%d, want 100 +/-20", ev.Digit, ev.DurationMs)
					}
					got.WriteString(ev.Digit)
				}
				time.Sleep(20 * time.Millisecond)
			}
			if got.String() != digits {
				t.Fatalf("received %q want %q", got.String(), digits)
			}
		})
	}
}

// TestR9SuppressedPeerReachesSessionTimerExpiredInTheLadder is R9's
// suppressed-peer half, asserted IN THE LADDER (design spec §8).
//
// Correction C3: Task 30's sessiontimer_watchdog_test.go:19
// (TestSuppressedPeerRefreshExpiresTheSessionWithCause408) already covers the
// timing (89s-then-2s-advance), the SessionTimerView, the event cause and the
// non-deadlocking Close — and covers it MORE STRICTLY, since a
// Fraction-1.0-to-0.5 mutant reddens that test but stays green here without a
// negative 89s advance first (this test jumps straight to 91s). This test's
// only NEW dimension is that the terminal BYE's Reason header is actually
// visible on the tap/observability path call_ladder reads — sipua.Config had
// a Tap field here once, but it was a dead field (zero readers in
// internal/sipua; C10/B13) removed outright in Task 11 (030d671), so the tap
// is wired the only way that reaches the wire: WrapConn + ObservingConn,
// reusing newSessionTimerUAFull's existing `wrap` parameter
// (sessiontimer_refresh_test.go) rather than a new constructor.
//
// Correction C13/N1: the poll deadline is 3s, matching waitFor's own default
// elsewhere in this package, not the brief's 32s — the BYE here is a
// fake-clock-driven watchdog expiry (lands within milliseconds of Advance
// returning), never the real Timer F.
func TestR9SuppressedPeerReachesSessionTimerExpiredInTheLadder(t *testing.T) {
	tap := &capturingTap{}
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: "90;refresher=uas"},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUAFull(t, clk, 1800, 90, "", 0, func(pc net.PacketConn) net.PacketConn {
		return sipua.ObservingConn(pc, tap, session.TransportUDP, clk.Now, "ua-r9")
	})
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	clk.BlockUntil(1)
	clk.Advance(91 * time.Second)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, rec := range tap.all() {
			if rec.Method == "BYE" && strings.Contains(rec.Serialized, "SIP;cause=408") {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no BYE carrying Reason: SIP;cause=408 in the ladder within 3s")
}

// TestR10RegisterRefreshesAppearInTheLadder is R10's ladder-level addition.
//
// Correction C4: R10's timing (30-54% of the granted expiry) and CSeq/nonce
// count assertions are Task 25's (register_refresh_test.go:17,47); this task
// does not re-assert them (Rule 18). The brief's promised "an incremented
// nonce-count across three cycles" is unachievable — Task 25's own test pins
// MaxNonceCount() == 1 as a KNOWN, DEFERRED LIMITATION of the vendored (G4)
// siptest.DoRequestWithDigest, which hardcodes nc=1 — so that phrase is
// dropped here rather than shipped as a failing test or a G4 edit. The one
// defensible addition is that all three REGISTER refreshes are actually
// visible on the tap/observability path, not just peer.Peer's own internal
// wire counters.
func TestR10RegisterRefreshesAppearInTheLadder(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
	})
	tap := &capturingTap{}
	clk := fakeclock.New(time.Unix(0, 0))
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "register", AOR: "sip:alice@example",
		Registrar: "sip:" + p.Addr(), AuthUser: "alice", AuthPass: "s3cr3t",
		ExpiresS: 60, Timeout: 2 * time.Second, Clock: clk, LocalAddr: "127.0.0.1:0",
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			return sipua.ObservingConn(pc, tap, session.TransportUDP, clk.Now, "ua-r10")
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatal(err)
	}

	initial := 0
	for _, rec := range tap.all() {
		if rec.Method == "REGISTER" {
			initial++
		}
	}
	if initial == 0 {
		t.Fatal("ladder shows no initial REGISTER; ObservingConn is not wired")
	}

	// Three refresh cycles (R10), matching Task 25's own loop — ONE REGISTER each
	// since P4-D07 presented the cached challenge preemptively. The `final-initial
	// >= 3` assertion below is unaffected: it counts REFRESHES reaching the tap,
	// and there are still three of them.
	for i := 0; i < 3; i++ {
		clk.BlockUntil(1)
		clk.Advance(60 * time.Second)
		want := 2 + (i + 1)
		waitForCond(t, func() bool { return p.Count("REGISTER") >= want })
	}

	final := 0
	for _, rec := range tap.all() {
		if rec.Method == "REGISTER" {
			final++
		}
	}
	if final-initial < 3 {
		t.Fatalf("ladder shows %d REGISTER requests across 3 refresh cycles, want >= 3 (every refresh must reach the tap)", final-initial)
	}
}
