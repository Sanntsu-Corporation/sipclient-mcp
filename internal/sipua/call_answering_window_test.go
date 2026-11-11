package sipua_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// THE ANSWER-TIME 481 RACE ON AN OUTBOUND DIALOG.
//
// runDial writes the ACK to the 200 OK and only reaches setPhase(phaseAnswered)
// after ParseAnswer has run. (The session timer is built and recorded earlier —
// in the critical section that claims phaseAnswering, before the ACK is even
// written — via buildOutboundSessionTimer, so it is no longer part of this
// window.) The peer is free to
// send in-dialog requests the moment that ACK is on the wire, and a real PBX
// does: with direct_media=yes Asterisk re-INVITEs the caller leg a MEASURED
// median of 0.785 ms — minimum 42 µs — after the ACK. Against the pre-fix code
// that request landed on a dialog still in phaseDialing/phaseRinging, so
// onInvite's in-dialog branch (and onUpdate's identical gate) answered 481
// Call/Transaction Does Not Exist. RFC 3261 §12.2.1.2 makes that terminal:
// Asterisk ACKs the 481 and BYEs both legs, which is how one §14.5 gate call in
// ~60 died with remote_bye on both sides.
//
// The two tests below drive the request INTO that window deterministically,
// through the dialAnsweringHook seam (call.go) — the same technique
// mediaTeardownHook already uses to prove a racing call_hangup is refused
// during phaseMediaTeardown. The hook runs ON runDial's goroutine, holding no
// lock, so the UA's server goroutine answers the in-dialog request while
// runDial is parked exactly where the race lives.

// answeringWindowProbe installs the seam, dials the peer, and returns the
// status code the peer got for the in-dialog request `send` put on the wire
// from INSIDE runDial's ACK -> phaseAnswered window.
//
// THE HOOK BODY ONLY PARKS runDial; IT PROBES NOTHING. The hook runs on
// runDial's goroutine, and every peer call this probe needs is a t.Fatalf-ing
// one — `send` is p.SendReInviteToCaller/SendUPDATEToCaller, and
// WaitForFinalAfter fatals on timeout. t.Fatalf off the test goroutine calls
// runtime.Goexit, so instead of failing the test it would KILL runDial from
// inside the very window under test, and the failure would surface as some
// later assertion's timeout rather than as the thing that actually went wrong.
// (peer.SendByeErr's doc comment names this hazard, and the sibling helper
// below avoids it by taking the error-returning twin — but no such twin exists
// for a re-INVITE, an UPDATE, or WaitForFinalAfter.)
//
// So the hook parks runDial in the window and hands the window to the test
// goroutine, which does the probing and releases it. This costs the window
// nothing: the old hook body was synchronous, so it already held runDial
// parked across the same send-and-wait. If anything it is tighter, since the
// request now lands inside a window held open until the probe is done rather
// than one racing the probe's own duration.
func answeringWindowProbe(t *testing.T, p *peer.Peer, ua *sipua.UA, send func()) int {
	t.Helper()
	opened, release := make(chan struct{}), make(chan struct{})
	sipua.SetDialAnsweringHook(func() {
		close(opened)
		<-release
	})
	t.Cleanup(func() { sipua.SetDialAnsweringHook(nil) })
	// Deferred, so the t.Fatalf paths below unpark runDial on their way out
	// through Goexit rather than stranding it in the window forever.
	defer close(release)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	select {
	case <-opened:
	case <-time.After(10 * time.Second):
		t.Fatal("dialAnsweringHook never ran: runDial never reached the ACK -> phaseAnswered window")
	}

	before := p.FinalResponseCount()
	send()
	return p.WaitForFinalAfter(t, before, 3*time.Second)
}

// A PEER BYE IN THE SAME WINDOW MUST END THE CALL, NOT BE OVERWRITTEN.
//
// The claim above makes the dialog answerable inside the window; it also means
// runDial's closing transition has to be a CLAIM rather than an assignment.
// onBye matches purely on Call-ID and is phase-blind, so a BYE landing here sets
// phaseDone and forgets the dialog — and the unconditional
// setPhase(phaseAnswered) that used to follow wrote phaseAnswered back over it,
// resurrecting a dialog no teardown path can reach again. Both session-timer
// arms guard on `phase != phaseAnswered` and so armed on the corpse; the
// watchdog then emitted a second, contradictory dialog_ended
// (session_timer_expired) 121 s after the peer_bye one.
//
// byePeerInsideTheAnsweringWindow lands the BYE inside the window and returns
// only once onBye has FULLY processed it (its dialog_ended is observable) and
// runDial's goroutine has gone — i.e. after the closing transition, and after
// the timer arms that a resurrected dialog would reach.
func byePeerInsideTheAnsweringWindow(t *testing.T, p *peer.Peer, ua *sipua.UA, events func() []session.UAEvent) {
	t.Helper()
	landed := make(chan bool, 1)
	sipua.SetDialAnsweringHook(func() {
		// Not SendBye: this runs on runDial's goroutine, and t.Fatal off the test
		// goroutine is a testing API violation.
		if err := p.SendByeErr(); err != nil {
			landed <- false
			return
		}
		landed <- pollUntil(3*time.Second, func() bool {
			return countKind(events(), session.UAEventDialogEnded) > 0
		})
	})
	t.Cleanup(func() { sipua.SetDialAnsweringHook(nil) })

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	select {
	case ok := <-landed:
		if !ok {
			t.Fatal("the peer BYE sent inside the answering window never reached onBye")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dialAnsweringHook never ran")
	}
	if !pollUntil(3*time.Second, func() bool { return !sipua.RunDialGoroutinePresent() }) {
		t.Fatal("runDial never returned after the peer BYE")
	}
}

func pollUntil(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(ciScaled(d))
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

// assertNoClockWaiter fails if anything is armed on the fake clock. It is the
// DIRECT signal that neither session-timer arm ran: with the dialog terminated
// this UA holds no other fake-clock waiter (the watchdog test's own
// clk.BlockUntil(1) after a normal dial pins that — BlockUntil waits for
// EXACTLY n). BlockUntil(1) returning at all therefore means a timer was armed
// on a dialog the peer already ended.
func assertNoClockWaiter(t *testing.T, clk *fakeclock.Clock) {
	t.Helper()
	armed := make(chan struct{})
	go func() { clk.BlockUntil(1); close(armed) }()
	select {
	case <-armed:
		// Error, not Fatal: the caller's remaining assertions cover the CONSEQUENCE
		// of that arming (the second dialog_ended, the refresh on the wire), and a
		// failing run should report both, not just the first one it reaches.
		t.Error("a session timer is armed after the peer BYE: runDial resurrected a dialog " +
			"onBye already terminated and forgot, and no teardown path can ever stop that timer")
	case <-time.After(time.Second):
	}
}

// TestPeerBYEInsideTheAnsweringWindowIsNotOverwritten is the uas half: the peer
// keeps the refresher role, so a resurrected dialog arms the WATCHDOG, and the
// watchdog is what emitted the second dialog_ended in the field.
func TestPeerBYEInsideTheAnsweringWindowIsNotOverwritten(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: answeringWindowNegotiatedSE},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1200, 120)
	events := collect(t, ua)

	byePeerInsideTheAnsweringWindow(t, p, ua, events)

	ended := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ended.Cause != session.UACausePeerBYE {
		t.Fatalf("dialog_ended cause=%q want peer_bye", ended.Cause)
	}
	assertNoClockWaiter(t, clk)

	// And the consequence: no watchdog expiry can be reached however far the
	// clock runs. Advancing repeatedly rather than once sweeps any waiter armed
	// late, which is precisely how a resurrected dialog's timer would appear.
	for i := 0; i < 5; i++ {
		clk.Advance(10 * 120 * time.Second)
		time.Sleep(20 * time.Millisecond)
	}
	if n := countKind(events(), session.UAEventDialogEnded); n != 1 {
		t.Fatalf("dialog_ended fired %d times, want exactly 1 (peer_bye): got %v", n, kinds(events()))
	}
	if n := countKind(events(), session.UAEventFinal); n != 0 {
		t.Fatalf("final fired %d times, want 0: the call ended with dialog_ended{peer_bye} before "+
			"runDial could answer it, so a trailing final/200 reports a call that is already over", n)
	}
}

// TestPeerBYEInsideTheAnsweringWindowArmsNoRefresher is the uac half: WE keep
// the refresher role, so a resurrected dialog arms the REFRESHER instead, which
// would put unsolicited in-dialog requests on the wire against a peer that has
// already BYE'd. Same window, different arm.
func TestPeerBYEInsideTheAnsweringWindowArmsNoRefresher(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: "120;refresher=uac"},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1200, 120)
	events := collect(t, ua)

	byePeerInsideTheAnsweringWindow(t, p, ua, events)
	waitFor(t, events, session.UAEventDialogEnded, 0)
	assertNoClockWaiter(t, clk)

	invites := p.InviteCount()
	for i := 0; i < 5; i++ {
		clk.Advance(10 * 120 * time.Second)
		time.Sleep(20 * time.Millisecond)
	}
	if got := p.InviteCount(); got != invites {
		t.Fatalf("the peer received %d INVITEs, want the original %d: a refresher armed on a "+
			"dialog the peer already ended is re-INVITEing a dead call", got, invites)
	}
	if got := p.Count("UPDATE"); got != 0 {
		t.Fatalf("the peer received %d UPDATEs, want 0 for the same reason", got)
	}
	if n := countKind(events(), session.UAEventSessionRefresh); n != 0 {
		t.Fatalf("session_refresh fired %d times on a terminated dialog, want 0", n)
	}
}

// TestInDialogReInviteInsideTheAnsweringWindowIs200Not481AndAValidAnswer pins the outbound
// re-INVITE case — the one the live gate actually failed on.
func TestInDialogReInviteInsideTheAnsweringWindowIs200Not481AndAValidAnswer(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	code := answeringWindowProbe(t, p, ua, func() { p.SendReInviteToCaller(t) })
	if code != 200 {
		t.Fatalf("re-INVITE arriving between the ACK and phaseAnswered drew %d, want 200: "+
			"a 481 to an in-dialog request is terminal (RFC 3261 §12.2.1.2) and the peer tears the call down", code)
	}
	// The dial itself must still complete normally — the claim must not have
	// broken the path it sits on.
	waitFor(t, events, session.UAEventFinal, 200)
	// CF-186: a valid answer built from the live session, never our original offer.
	got := string(p.LastFinalResponseBody())
	if got == string(p.LastInviteBody()) {
		t.Errorf("re-INVITE 200 SDP is our original offer %q, want an answer from the live session", got)
	}
	if n := strings.Count(got, "m=audio"); n != 1 {
		t.Errorf("re-INVITE 200 SDP has %d m=audio lines: %q", n, got)
	}
	if strings.Contains(got, "a=crypto") {
		t.Errorf("re-INVITE 200 SDP carries a key: %q", got)
	}
	want := strings.Fields(sdpField(string(p.LastInviteBody()), "o="))
	if f := strings.Fields(sdpField(got, "o=")); len(f) < 2 || len(want) < 2 || f[1] != want[1] {
		t.Errorf("re-INVITE 200 o= %q, want our session id %q", f, want)
	}
}

// TestInDialogUpdateInsideTheAnsweringWindowIs200Not481 pins the UPDATE case.
// onUpdate is new in this wave and carried the identical phaseAnswered gate, so
// it extended the same hazard to a refreshing peer's UPDATE.
func TestInDialogUpdateInsideTheAnsweringWindowIs200Not481(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	code := answeringWindowProbe(t, p, ua, func() { p.SendUPDATEToCaller(t, "1800;refresher=uas") })
	if code != 200 {
		t.Fatalf("UPDATE arriving between the ACK and phaseAnswered drew %d, want 200", code)
	}
	waitFor(t, events, session.UAEventFinal, 200)
}

// A 200 IS NOT ENOUGH: IT MUST CARRY THE NEGOTIATED Session-Expires.
//
// The two tests above assert only the STATUS CODE, and the header assertion
// that does exist — TestOutboundReInvite200CarriesContactAndTheNegotiated-
// SessionTimer — waits for the dial to COMPLETE before it sends, so it never
// enters this window. The defect lived at the intersection: d.sessionTimer used
// to be recorded past ParseAnswer, i.e. AFTER the phaseAnswering claim opened
// the window, so every 200 answering a session refresh that landed inside it
// went out with NO Session-Expires. RFC 4028 §7.4/§10 reads that as "the session
// timer is no longer in use": the peer stops refreshing while our own watchdog
// stays armed against the interval we just negotiated, and where the role is
// uas we then tear down a healthy call. Measured on the live rig at 0/2 with the
// window widened, against 20/20 outside it.
//
// THE FIXTURE IS SKEWED so neither a default nor a hardcoded value can pass:
// the UA PROPOSES 1200;refresher=uac (pinned by
// TestDialAdvertisesSessionTimerHeaders) and the peer ANSWERS
// 120;refresher=uas. The expected value therefore differs from our proposal, from
// RFC 4028's and our own defaults (1800/uac), and — deliberately — from the
// Session-Expires the refresh request itself carries, so echoing the request
// back fails too.
//
// A re-INVITE with no Session-Expires keeps the dialog's interval (120) and, listing
// no timer (Table 2 "N"), makes us the refresher: "uas" in that transaction.
const answeringWindowNegotiatedSE = "120;refresher=uas"

// answeringWindowUpdateSE is what the 200 to the UPDATE below carries: the request's
// 1800 reduced to our session_expires_s of 1200 (the UAS MAY reduce, MUST NOT
// increase, rfc4028.txt:847-851), with the role Table 2 "N" gives (us, "uas").
const answeringWindowUpdateSE = "1200;refresher=uas"

// TestReInviteInsideTheAnsweringWindowCarriesTheNegotiatedSessionTimer is the
// re-INVITE half: the case the live gate actually hit, since Asterisk's
// direct-media re-INVITE arrives a measured median of 0.8 ms after our ACK.
func TestReInviteInsideTheAnsweringWindowCarriesTheNegotiatedSessionTimer(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: answeringWindowNegotiatedSE},
	})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1200, 120)
	events := collect(t, ua)

	code := answeringWindowProbe(t, p, ua, func() { p.SendReInviteToCaller(t) })
	if code != 200 {
		t.Fatalf("re-INVITE inside the answering window drew %d, want 200", code)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	if got := p.LastResponseHeader("INVITE", 200, "Session-Expires"); got != answeringWindowNegotiatedSE {
		t.Errorf("the 200 answering a re-INVITE INSIDE the answering window carried Session-Expires %q, "+
			"want the dialog's negotiated %q (RFC 4028 §7.4: omitting it tells the peer the session "+
			"timer is off, and our watchdog then kills a healthy call)", got, answeringWindowNegotiatedSE)
	}
}

// TestUpdateInsideTheAnsweringWindowCarriesTheNegotiatedSessionTimer is the
// UPDATE half — onUpdate snapshots d.sessionTimer through the identical read.
// The UPDATE carries 1800;refresher=uac, differing from the negotiated answer in
// BOTH the interval and the role, so a response that echoed the request instead
// of the dialog's own state would fail here.
func TestUpdateInsideTheAnsweringWindowCarriesTheNegotiatedSessionTimer(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: answeringWindowNegotiatedSE},
	})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1200, 120)
	events := collect(t, ua)

	code := answeringWindowProbe(t, p, ua, func() { p.SendUPDATEToCaller(t, "1800;refresher=uac") })
	if code != 200 {
		t.Fatalf("UPDATE inside the answering window drew %d, want 200", code)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	if got := p.LastResponseHeader("UPDATE", 200, "Session-Expires"); got != answeringWindowUpdateSE {
		t.Errorf("the 200 answering an UPDATE INSIDE the answering window carried Session-Expires %q, "+
			"want %q (RFC 4028 §9)", got, answeringWindowUpdateSE)
	}
}
