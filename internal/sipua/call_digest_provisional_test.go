package sipua_test

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// newAuthUAWithTimeout is newDirectAuthUA with the digest credentials and the
// per-request Timeout (the PRE-ring budget) both parameterised, so a test can
// drive a small pre-ring window against a challenging peer.
func newAuthUAWithTimeout(t *testing.T, clk *fakeclock.Clock, user, pass string, timeout time.Duration) *sipua.UA {
	t.Helper()
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport:          "udp",
		Mode:               "direct",
		AOR:                "sip:alice@example",
		AuthUser:           user,
		AuthPass:           pass,
		AuthAnyHost:        true, // CF-046: the peer is on 127.0.0.1, not this AOR's host
		ExpiresS:           300,
		Timeout:            timeout,
		InboundRingTimeout: 2 * time.Second,
		Clock:              clk,
		LocalAddr:          "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua
}

// TestRunDial_DigestLegSurfaces180AndSurvivesPastPreRingBudget is D5: on a
// digest-challenged INVITE, the AUTHED (retry) leg must surface 180 Ringing as
// a UAEventProvisional — the vendored DoRequestWithDigest swallowed every 1xx,
// so it never did — AND the call must not be capped at the pre-ring budget once
// it is ringing: the peer answers at +300ms, well past the 150ms pre-ring, and
// the dial must still reach a 200 (not time out after 180).
func TestRunDial_DigestLegSurfaces180AndSurvivesPastPreRingBudget(t *testing.T) {
	restore := sipua.SetOutboundRingBudget(2 * time.Second)
	defer restore()

	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "bob", AuthPass: "pw",
		Behaviour: peer.Behaviour{AnswerAfter: 300 * time.Millisecond},
	})
	ua := newAuthUAWithTimeout(t, fakeclock.New(time.Unix(0, 0)), "bob", "pw", 150*time.Millisecond)
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// D5: the 180 is surfaced ON THE DIGEST LEG. Before the fix this never
	// arrives (DoRequestWithDigest's doTx swallows 1xx) and waitFor times out.
	ring := waitFor(t, events, session.UAEventProvisional, 180)
	if ring.Direction != session.Outbound {
		t.Errorf("provisional Direction = %q, want %q", ring.Direction, session.Outbound)
	}

	// Survives past the 150ms pre-ring budget: the +300ms answer must land as a
	// 200, not be killed by the single upfront timeout the old code applied.
	fin := waitFor(t, events, session.UAEventFinal, 200)
	if fin.Direction != session.Outbound {
		t.Errorf("final Direction = %q, want %q", fin.Direction, session.Outbound)
	}
}

// TestRunDial_RingThenSilentIsReapedAtPostRingBudget is B1: a challenging peer
// that rings and then goes silent (401 -> 100/180 -> NOTHING) must be REAPED at
// the finite post-ring budget, not parked forever. sipgo v0.24.1 stops Timer B
// on the first provisional and has no Timer C, so before the fix runDial parked
// on the hung DoRequestWithDigest until UA teardown, pinning the Call in
// ringing.
func TestRunDial_RingThenSilentIsReapedAtPostRingBudget(t *testing.T) {
	// postRing is deliberately LARGER than preRing (150ms): that gap is what
	// discriminates B1's re-arm from the old single-upfront-timeout path, which
	// capped the digest leg at cfg.Timeout (150ms) and reaped too early. The
	// fixed path must ring past 150ms and reap only at ~600ms.
	const preRing = 150 * time.Millisecond
	const postRing = 600 * time.Millisecond
	restore := sipua.SetOutboundRingBudget(postRing)
	defer restore()

	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "bob", AuthPass: "pw",
		Behaviour: peer.Behaviour{RingThenSilent: true},
	})
	ua := newAuthUAWithTimeout(t, fakeclock.New(time.Unix(0, 0)), "bob", "pw", preRing)
	events := collect(t, ua)

	start := time.Now()
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// It must ring on the DIGEST leg first (the old path swallowed this 180).
	if ring := waitFor(t, events, session.UAEventProvisional, 180); ring.Direction != session.Outbound {
		t.Errorf("provisional Direction = %q, want %q", ring.Direction, session.Outbound)
	}

	// It rang, then was reaped: the reaper surfaces as a dialog-scoped end (no
	// final response ever arrived).
	fault := waitFor(t, events, session.UAEventDialogEnded, 0)
	elapsed := time.Since(start)
	if fault.Direction != session.Outbound {
		t.Errorf("dialog-end Direction = %q, want %q", fault.Direction, session.Outbound)
	}
	// Re-armed PAST the pre-ring cap: had the budget not extended on the first
	// provisional, this would have died at ~150ms. It must survive to ~postRing.
	if elapsed < 400*time.Millisecond {
		t.Fatalf("ring-then-silent reaped after %s — earlier than the %s post-ring budget; the timer was not re-armed past the pre-ring cap", elapsed, postRing)
	}
	// Reaped at ~postRing, NOT parked forever: without the finite budget sipgo
	// never fires tx.Done (no Timer C) and runDial would park until UA teardown.
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("ring-then-silent not reaped: took %s (must be ~postRing %s, not parked)", elapsed, postRing)
	}
	// Must NOT have answered.
	for _, ev := range events() {
		if ev.Kind == session.UAEventFinal && ev.Code >= 200 && ev.Code < 300 {
			t.Fatalf("dial answered (%d) on a ring-then-silent peer; it must be reaped", ev.Code)
		}
	}

	// No leak: the runDial goroutine has exited and no Call is left in ringing.
	deadline := time.Now().Add(2 * time.Second)
	for sipua.RunDialGoroutinePresent() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if sipua.RunDialGoroutinePresent() {
		t.Error("a runDial goroutine is still running after the reap; the dial runner leaked")
	}
	if n := ua.RegisteredDialogCount(); n != 0 {
		t.Errorf("registry holds %d dialog(s) after the reap, want 0 — a Call was left parked in ringing", n)
	}
}
