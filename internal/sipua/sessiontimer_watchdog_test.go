package sipua_test

import (
	"context"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestSuppressedPeerRefreshExpiresTheSessionWithCause408 is R9's suppressed-peer
// half AND the watchdog's self-deadlock regression test. Every assertion below
// sits DOWNSTREAM of stopSessionTimer: the BYE is built after it, and the
// terminal event after that. So if expireSessionTimer ever runs inline on the
// watchdog goroutine again, p.WaitForBye's 5s bound is what reports it (and the
// process shows the watchdog goroutine parked in refresher.Stop on `<-r.done`).

// assertWatchdogRearmed pins the one thing the two "rearms the watchdog" tests
// below are named for and could not observe: that the watchdog's DEADLINE
// actually moved back to a fresh full interval.
//
// WHY A POSITIVE ASSERTION IS REQUIRED HERE. Both tests' only other check is
// `p.ByeCount() != 0`, and a watchdog that was stopped and never re-armed sends
// no BYE just as reliably as one that is correctly re-armed — the two coincide.
// The only thing that observed a missing re-arm was the NEXT round's
// clk.BlockUntil(1), which then has no waiter to count and blocks forever:
// MEASURED, deleting sessiontimer.go's `u.startSessionWatchdog(d, st)` failed
// this file only as `panic: test timed out after 1m30s`, taking the whole
// ~120 s package down with it and naming no property. With this call the same
// mutation fails as one located assertion in round 0.
//
// 90000 is exact, not approximate: the fake clock is advanced by whole seconds
// and SessionTimerView reads the watchdog's NextAt off that same clock, so a
// re-arm at t is always t+90s. The poll is for the WIRE round trip — the
// re-arm runs after the 200 leaves onUpdate/onInvite — not for clock slop.
func assertWatchdogRearmed(t *testing.T, ua *sipua.UA, dialogID string, round int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last int64
	for time.Now().Before(deadline) {
		v, ok := ua.SessionTimerView(dialogID)
		if ok && v.NextRefreshMs == 90000 {
			return
		}
		last = v.NextRefreshMs
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("round %d: next_refresh_ms=%d, want a full 90000 — the peer's refresh was "+
		"answered but the watchdog's deadline did not move, so it is either the ORIGINAL "+
		"timer still counting down to its first expiry or (at 0) no timer at all", round, last)
}

func TestSuppressedPeerRefreshExpiresTheSessionWithCause408(t *testing.T) {
	// The peer claims the refresher role and then never refreshes.
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: "90;refresher=uas"},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 90)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	if v, ok := ua.SessionTimerView(res.DialogID); !ok || v.Refresher != "uas" {
		t.Fatalf("view=%+v ok=%v want the peer as refresher", v, ok)
	}

	clk.BlockUntil(1)
	clk.Advance(89 * time.Second)
	// The BYE is sent asynchronously; without a settle the negative assertion
	// below reads ByeCount before an early expiry could possibly have landed
	// (C5: a watchdog mutated to fire at Fraction 0.5 — 45s instead of 90s —
	// stays green here without this sleep, because nothing waits for the BYE
	// to actually land before checking).
	time.Sleep(300 * time.Millisecond)
	if p.ByeCount() != 0 {
		t.Fatal("expired before the full interval")
	}
	clk.Advance(2 * time.Second)
	p.WaitForBye(t, 5*time.Second)
	if got := p.LastRequestHeader("BYE", "Reason"); got != "SIP;cause=408" {
		t.Fatalf("BYE Reason=%q want SIP;cause=408 (spec §5)", got)
	}
	ended := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ended.Cause != session.UACauseSessionTimerExpired {
		t.Fatalf("cause=%q want session_timer_expired", ended.Cause)
	}
	if ended.DialogID != res.DialogID {
		t.Fatalf("dialog_id=%q want %q", ended.DialogID, res.DialogID)
	}
	// The watchdog and the dialog are both released: nothing is parked waiting on
	// a goroutine that already returned, so Close completes promptly.
	done := make(chan error, 1)
	go func() { done <- ua.Close(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close after a watchdog expiry: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close parked after a watchdog expiry — a refresher goroutine is still held")
	}
}

// TestAnInboundRefreshRearmsTheWatchdog proves an inbound UPDATE refresh
// rearms the watchdog: peer.Behaviour.RefreshEvery does not exist (Task 15's
// peer.go surface for this is (*Peer).SendUPDATEToCaller instead, built for
// exactly this test), so the refresh is driven explicitly, once per round,
// with the wire round-trip confirmed before the fake clock advances again.
func TestAnInboundRefreshRearmsTheWatchdog(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: "90;refresher=uas"},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 90)
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	// Four peer refreshes across 200s: the watchdog must never fire.
	for i := 0; i < 4; i++ {
		// Checked BEFORE BlockUntil: once the watchdog has fired it deregisters
		// its waiter, and BlockUntil(1) would then block forever.
		if p.ByeCount() != 0 {
			t.Fatalf("round %d: the watchdog fired despite the peer refreshing", i)
		}
		clk.BlockUntil(1)
		clk.Advance(50 * time.Second)
		before := len(p.ResponseCodes())
		// Table 2 "Y, uac": the peer lists timer and names itself, so it keeps
		// refreshing and the watchdog is the timer that re-arms.
		p.SendUPDATEToCaller(t, "90;refresher=uac", sip.NewHeader("Supported", "timer"))
		deadline := time.Now().Add(3 * time.Second)
		for len(p.ResponseCodes()) <= before {
			if time.Now().After(deadline) {
				t.Fatalf("round %d: peer's UPDATE never reached the UA", i)
			}
			time.Sleep(2 * time.Millisecond)
		}
		assertWatchdogRearmed(t, ua, res.DialogID, i)
	}
	if p.ByeCount() != 0 {
		t.Fatalf("the watchdog fired despite 4 inbound refreshes; peer saw %v", p.ResponseCodes())
	}
}

// TestAnInboundReInviteRearmsTheWatchdog covers Step 4's onInvite hook: a peer
// that refreshes with re-INVITE rather than UPDATE must not have its dialog
// reaped.
func TestAnInboundReInviteRearmsTheWatchdog(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: "90;refresher=uas"},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 90)
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	for i := 0; i < 4; i++ {
		if p.ByeCount() != 0 {
			t.Fatalf("round %d: the watchdog fired despite the peer refreshing by re-INVITE", i)
		}
		clk.BlockUntil(1)
		clk.Advance(50 * time.Second)
		before := len(p.ResponseCodes())
		p.SendReInviteToCaller(t, sip.NewHeader("Supported", "timer"),
			sip.NewHeader("Session-Expires", "90;refresher=uac"))
		deadline := time.Now().Add(3 * time.Second)
		for len(p.ResponseCodes()) <= before {
			if time.Now().After(deadline) {
				t.Fatalf("round %d: no response to the peer's re-INVITE", i)
			}
			time.Sleep(2 * time.Millisecond)
		}
		assertWatchdogRearmed(t, ua, res.DialogID, i)
	}
}

// TestWatchdogExpiryMidDTMFStopsTheSendAndReportsIt is Cycle 4's group-B
// combination "watchdog expiry mid-DTMF", and it found a defect rather than
// confirming coverage — the LAYER-BLINDNESS shape this wave hit four times.
// Both layers were genuinely covered on their own terms: the watchdog's own
// expiry is pinned above, and DTMF ending mid-send is pinned for BOTH RTP-path
// arms (TestSendDTMFInbandReturnsAnErrorWhenTheCallEndsMidSend and its rfc2833
// twin, dtmf_test.go). Neither could see the seam, because those two arms are
// driven by the media loop that every teardown stops, while §2.2 keeps the
// INFO arm off the media loop entirely.
//
// MEASURED BEFORE THE FIX: the wire carried INVITE, ACK, INFO, BYE, INFO — an
// in-dialog request issued after our own BYE — and SendDTMF returned
// sent=2, err=nil. That is precisely the "fabricated success count" the two
// RTP-path tests exist to forbid, on the one arm that did not check.
//
// THE FIXTURE'S NUMBERS ARE WHAT MAKE IT DETERMINISTIC. The inter-digit gap
// (120 s) is longer than the negotiated session interval (90 s), so on the fake
// clock the watchdog's deadline strictly precedes the gap's: one Advance fires
// the watchdog with the send still parked, and only a second Advance releases
// it into the digit that must now be refused. Two waiters, so BlockUntil(2) —
// it is an exact-count wait.
func TestWatchdogExpiryMidDTMFStopsTheSendAndReportsIt(t *testing.T) {
	// The peer claims the refresher role and then never refreshes, so OUR
	// watchdog is what ends the call.
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: "90;refresher=uas"},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 90)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	type result struct {
		sent, emitted int
		err           error
	}
	done := make(chan result, 1)
	go func() {
		sent, emitted, err := ua.SendDTMF(context.Background(), res.DialogID, "12",
			session.DTMFModeInfo, 100, 120000)
		done <- result{sent, emitted, err}
	}()
	// The first digit lands on a healthy call; the send then parks in the gap.
	waitForCond(t, func() bool { return p.Count("INFO") >= 1 })

	clk.BlockUntil(2) // the watchdog and the inter-digit gap
	clk.Advance(91 * time.Second)
	p.WaitForBye(t, 5*time.Second)

	clk.Advance(40 * time.Second) // release the gap: the second digit is now due
	var got result
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SendDTMF never returned after the watchdog ended the call")
	}

	if got.err == nil {
		t.Fatalf("SendDTMF(info) reported sent=%d with no error after the watchdog BYE'd the call; "+
			"a send that outlived its own dialog must not report a fabricated success count "+
			"(the contract both RTP-path arms already hold)", got.sent)
	}
	if code := apierr.CodeOf(got.err); code != apierr.CodePreconditionFailed {
		t.Fatalf("code=%v want precondition_failed, matching the inband and rfc2833 arms", code)
	}
	if got.sent != 1 {
		t.Fatalf("sent=%d want 1 — only the digit that landed BEFORE the watchdog fired is known "+
			"to have reached the wire", got.sent)
	}
	if n := p.Count("INFO"); n != 1 {
		t.Fatalf("%d INFOs on the wire, want 1: an in-dialog request after our own BYE targets a "+
			"dialog we ourselves terminated, and a compliant peer answers it 481 — terminal per "+
			"RFC 3261 §12.2.1.2. Wire order was %v", n, p.Methods())
	}
	ended := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ended.Cause != session.UACauseSessionTimerExpired {
		t.Fatalf("cause=%q want session_timer_expired", ended.Cause)
	}
}
