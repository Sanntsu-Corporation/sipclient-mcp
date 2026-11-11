// internal/sipua/sessiontimer_refresh_test.go
package sipua_test

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// newSessionTimerUAFull is the ONE parameterised constructor behind
// newSessionTimerUA (sessiontimer_wire_test.go) and this file's
// WithMethod/WithTimeout/WithWrapConn variants below (Correction 7): the
// brief described three hand-rolled variants but never provided them, and a
// fourth near-identical sipua.New call site — or newSessionTimerUA keeping
// its own duplicate Config literal — would drift from this one the moment
// either changes. timeout <= 0 keeps the 2s default every other helper in
// this package uses; wrap == nil installs the same countingConn seam every
// caller of this constructor gets by default when it does not need a custom
// conn.
func newSessionTimerUAFull(t *testing.T, clk *fakeclock.Clock, ses, minSE int,
	method string, timeout time.Duration, wrap func(net.PacketConn) net.PacketConn) (*sipua.UA, *countingConn) {
	t.Helper()
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	var cc *countingConn
	wrapFn := wrap
	if wrapFn == nil {
		wrapFn = func(pc net.PacketConn) net.PacketConn {
			cc = &countingConn{PacketConn: pc}
			return cc
		}
	}
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport:            "udp",
		Mode:                 "direct",
		AOR:                  "sip:alice@example",
		ExpiresS:             300,
		Timeout:              timeout,
		InboundRingTimeout:   2 * time.Second,
		Clock:                clk,
		LocalAddr:            "127.0.0.1:0",
		SessionExpiresS:      ses,
		MinSES:               minSE,
		SessionRefreshMethod: method,
		WrapConn:             wrapFn,
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua, cc
}

// newSessionTimerUAWithMethod forces session_refresh_method (decision 11's
// per-profile override). It returns a single *sipua.UA — the brief's own call
// sites never use the countingConn this constructs (Correction 7).
func newSessionTimerUAWithMethod(t *testing.T, clk *fakeclock.Clock, ses, minSE int, method string) *sipua.UA {
	ua, _ := newSessionTimerUAFull(t, clk, ses, minSE, method, 0, nil)
	return ua
}

// newSessionTimerUAWithTimeout is newSessionTimerUA with an explicit
// Config.Timeout, for the in-dialog-timeout test below: sipgo's Timer B/F is a
// REAL timer no fake clock can advance, so the test needs a short real budget
// rather than production's 32s default.
func newSessionTimerUAWithTimeout(t *testing.T, clk *fakeclock.Clock, ses, minSE int, timeout time.Duration) (*sipua.UA, *countingConn) {
	return newSessionTimerUAFull(t, clk, ses, minSE, "", timeout, nil)
}

// newSessionTimerUAWithWrapConn is newSessionTimerUA with a caller-supplied
// Config.WrapConn, REPLACING the countingConn newSessionTimerUA installs by
// default (Correction 7) — the same seam countingConn and ackFailConn already
// use elsewhere in this package.
func newSessionTimerUAWithWrapConn(t *testing.T, clk *fakeclock.Clock, ses, minSE int,
	wrap func(net.PacketConn) net.PacketConn) (*sipua.UA, *countingConn) {
	return newSessionTimerUAFull(t, clk, ses, minSE, "", 0, wrap)
}

// waitForAtomic polls until v reaches want, or fails. refresher_test.go:422
// defines an identical helper, but that file is package sipua while this one
// is package sipua_test (Correction 7) — not reachable from here.
func waitForAtomic(t *testing.T, v *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if v.Load() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("counter reached %d, want %d", v.Load(), want)
}

func TestWeRefreshWithUPDATEAtHalfTheIntervalAndEmitTheEvent(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	// Review round 1, MINOR 1: MinSES is deliberately NOT 90 — 90 is also the
	// peer's negotiated Session-Expires above, so a bug that reported
	// u.minSES() instead of the actually-negotiated interval would have
	// passed the interval_s assertion below unnoticed.
	ua, _ := newSessionTimerUA(t, clk, 1800, 60)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	// RFC 4028 §10: we refresh at interval/2 = 45s.
	clk.BlockUntil(1)
	clk.Advance(44 * time.Second)
	if n := p.Count("UPDATE"); n != 0 {
		t.Fatal("refreshed before interval/2")
	}
	clk.Advance(2 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })

	ev := waitFor(t, events, session.UAEventSessionRefresh, 0)
	if ev.Detail["method"] != "UPDATE" || ev.Detail["refresher"] != "uac" ||
		ev.Detail["interval_s"] != 90 || ev.Detail["code"] != 200 {
		t.Fatalf("session_refresh detail=%+v want {UPDATE, uac, 90, 200}", ev.Detail)
	}
	// Correction 11: a survived mutant deleted every RFC 4028 header from the
	// refresh REQUEST itself (nothing inspected the wire, only the emitted
	// event). Without Session-Expires on the UPDATE the peer never re-bases
	// its own timer and BYEs at expiry while we log success.
	if got := p.LastRequestHeader("UPDATE", "Session-Expires"); got != "90;refresher=uac" {
		t.Fatalf("UPDATE Session-Expires=%q want 90;refresher=uac", got)
	}
	// Review round 1, CRITICAL 1: the refresh is a TARGET-REFRESH request
	// (RFC 3261 §12.2.2), so its Contact MUST be ours, not whatever
	// buildInDialogRequest's underlying builder cloned off the dialog INVITE.
	// This dialog is OUTBOUND, so the INVITE we sent already carried our own
	// Contact — this assertion is the control case for the inbound one below.
	wantContact := "<sip:alice@" + ua.BoundAddr().String() + ">"
	if got := p.LastRequestHeader("UPDATE", "Contact"); got != wantContact {
		t.Fatalf("UPDATE Contact=%q want %q (ours, not the peer's)", got, wantContact)
	}

	// Second cycle at ~90s, and the call is still alive past 180s.
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 2 })
	clk.Advance(100 * time.Second)
	time.Sleep(50 * time.Millisecond)
	if p.ByeCount() != 0 {
		t.Fatal("a refreshing call must stay up past 180s")
	}
	_ = res
}

// TestARefreshGrantRebasesTheRefreshersOwnInterval is the re-base's
// behavioural fence, and it did not exist: deleting the whole re-base block
// from refreshSession and returning 0 left the ENTIRE suite green. The
// mechanism was the test peer — buildRefreshResponse used to answer every
// refresh with the same AnswerSessionExpires it used on the INVITE, so every
// test reaching the success path already observed se.IntervalS == st.IntervalS,
// the write-back stored the value it already held, and the interval_s == 90
// assertion in TestWeRefreshWithUPDATEAtHalfTheIntervalAndEmitTheEvent passed
// either way. TestRefresherRebasesOnTheGrantedInterval covers the refresher
// PRIMITIVE only, not this consumer. Behaviour.RefreshSessionExpires is the
// knob that lifts the blindness.
//
// This is the mechanism the plan calls load-bearing for decision 8 (§2.4:
// refreshPolicy.Do returning the granted interval), so BOTH ends are pinned:
// the reported interval_s becomes the granted 120, AND the next refresh fires
// at 60s rather than the old 45s. The second assertion is the one that reaches
// the refresher rather than only the event payload — the first alone would
// stay green for a re-base that updated st but never returned `granted`.
//
// The granted role is deliberately the SAME "uac" the INVITE negotiated: this
// test is about the interval, and a flipped role is a separate open question.
func TestARefreshGrantRebasesTheRefreshersOwnInterval(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires:  "90;refresher=uac",
			RefreshSessionExpires: []string{"120;refresher=uac"},
			AnswerAllow:           "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 60)
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // the NEGOTIATED interval's half: 45s
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })

	ev := waitFor(t, events, session.UAEventSessionRefresh, 0)
	if ev.Detail["interval_s"] != 120 {
		t.Fatalf("session_refresh interval_s=%v want 120 (the peer's granted interval, not the negotiated 90)",
			ev.Detail["interval_s"])
	}

	// The event is emitted from inside Do, so the next timer is not armed yet;
	// BlockUntil(1) waits out the re-arm rather than racing it (fakeclock's
	// package doc).
	clk.BlockUntil(1)
	// 46s past the first refresh is COMFORTABLY past the old half-interval of
	// 45s and still short of the re-based 60s, so this window is what tells the
	// two cadences apart.
	clk.Advance(46 * time.Second)
	time.Sleep(300 * time.Millisecond)
	if n := p.Count("UPDATE"); n != 1 {
		t.Fatalf("UPDATE count=%d 46s after the first refresh, want 1 — the refresher is still "+
			"running on the negotiated 90 (45s) rather than the granted 120 (60s)", n)
	}
	clk.Advance(15 * time.Second) // now 61s past the first refresh
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 2 })

	// And what we advertise is the interval we are now actually running.
	if got := p.LastRequestHeader("UPDATE", "Session-Expires"); got != "120;refresher=uac" {
		t.Fatalf("second UPDATE Session-Expires=%q want 120;refresher=uac", got)
	}
}

// TestARefreshGrantBelowOurMinSEIsIgnored is the re-base site's half of
// Correction 11's floor. The INITIAL answer has always refused an undersized
// Session-Expires (buildOutboundSessionTimer), on the stated grounds that
// accepting one would arm us to refresh far more often than either bound
// allows — but the refresh re-base accepted anything parseSessionExpires did
// not reject outright, i.e. anything > 0. A peer answering our UPDATE with
// `Session-Expires: 1` therefore re-based us to a 500 ms refresh cadence
// (sessionRefreshFraction), permanently, one message after the guard that
// exists to prevent exactly that.
//
// Both halves of "ignored" are asserted: the reported interval stays 90, AND
// the next refresh fires at 45s rather than 0.5s. The second is the one that
// pins the REFRESHER's interval rather than just the event payload.
func TestARefreshGrantBelowOurMinSEIsIgnored(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			// Every refresh this peer answers grants 1 second — below the UA's
			// Min-SE of 60 below, and below RFC 4028's own 90s floor.
			RefreshSessionExpires: []string{"1"},
			AnswerAllow:           "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 60)
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // RFC 4028 §10: interval/2 = 45s
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })

	ev := waitFor(t, events, session.UAEventSessionRefresh, 0)
	if ev.Detail["interval_s"] != 90 {
		t.Fatalf("session_refresh interval_s=%v want 90 (the undersized grant of 1 must be ignored)",
			ev.Detail["interval_s"])
	}

	// The event above is emitted from inside the refresher's Do, so the next
	// timer is not armed yet: BlockUntil(1) waits out the re-arm rather than
	// racing it (fakeclock's package doc).
	clk.BlockUntil(1)
	clk.Advance(2 * time.Second)
	// A grant of 1 would have armed the next refresh 500 ms out, so it would
	// already have landed; the settle is what makes this negative assertion
	// mean something.
	time.Sleep(300 * time.Millisecond)
	if n := p.Count("UPDATE"); n != 1 {
		t.Fatalf("UPDATE count=%d 2s after the refresh, want 1 — we re-based onto the peer's undersized grant", n)
	}
	clk.Advance(44 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 2 })
	// And the interval we advertise is still the negotiated one, not the grant.
	if got := p.LastRequestHeader("UPDATE", "Session-Expires"); got != "90;refresher=uac" {
		t.Fatalf("second UPDATE Session-Expires=%q want 90;refresher=uac", got)
	}
}

func TestWeRefreshWithReINVITEWhenThePeerDoesNotAllowUPDATE(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 90)
	events := collect(t, ua)
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	before := p.Count("INVITE")
	beforeACK := p.Count("ACK")
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	waitForCond(t, func() bool { return p.Count("INVITE") > before })
	if p.Count("UPDATE") != 0 {
		t.Fatal("a peer whose Allow omits UPDATE must be refreshed with a re-INVITE")
	}
	ev := waitFor(t, events, session.UAEventSessionRefresh, 0)
	if ev.Detail["method"] != "INVITE" {
		t.Fatalf("method=%v want INVITE", ev.Detail["method"])
	}
	// Correction 11: a survived mutant dropped the re-INVITE refresh's ACK.
	// RFC 3261: an unACKed 2xx is retransmitted and the peer eventually BYEs.
	waitForCond(t, func() bool { return p.Count("ACK") > beforeACK })
}

func TestSessionRefreshMethodOverrideForcesInvite(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newSessionTimerUAWithMethod(t, clk, 1800, 90, "invite")
	events := collect(t, ua)
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	before := p.Count("INVITE")
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	waitForCond(t, func() bool { return p.Count("INVITE") > before })
	if p.Count("UPDATE") != 0 {
		t.Fatal("session_refresh_method: invite must override the peer's UPDATE support")
	}
}

// TestSessionRefreshMethodOverrideForcesUpdate is the other half of decision
// 11, and until it existed refreshMethodFor's `case "update"` arm had ZERO
// statement coverage: returning sip.INVITE from it left the entire
// internal/sipua package green. Only the "invite" arm was driven, and "auto"
// already yields INVITE against this peer, so the arm that DOWNGRADES an
// operator's explicit `session_refresh_method: update` to a re-INVITE was
// indistinguishable from correct behaviour.
//
// The peer's Allow deliberately OMITS UPDATE — the same fixture
// TestWeRefreshWithReINVITEWhenThePeerDoesNotAllowUPDATE uses. That is the
// discriminating input: it is the ONLY configuration where "auto" and "update"
// disagree, and it is the whole reason the override exists — an interop escape
// hatch for a peer that under-advertises its own Allow.
func TestSessionRefreshMethodOverrideForcesUpdate(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newSessionTimerUAWithMethod(t, clk, 1800, 90, "update")
	events := collect(t, ua)
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	beforeINVITE := p.Count("INVITE")
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	// The refresh event fires for EITHER method, so waiting on it first gives a
	// named diagnostic rather than a bare waitForCond timeout when the override
	// is ignored.
	ev := waitFor(t, events, session.UAEventSessionRefresh, 0)
	if ev.Detail["method"] != "UPDATE" {
		t.Fatalf("method=%v want UPDATE — session_refresh_method: update must override "+
			"a peer whose Allow omits UPDATE, which is the only case the override exists for",
			ev.Detail["method"])
	}
	waitForCond(t, func() bool { return p.Count("UPDATE") > 0 })
	if got := p.Count("INVITE"); got != beforeINVITE {
		t.Fatalf("INVITE count %d -> %d: the override must not fall back to a re-INVITE",
			beforeINVITE, got)
	}
}

func TestRejectedRefreshAppendsAnErrorAndTheCallSurvives(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, UPDATE",
			RejectUpdateStatus:   500,
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 90)
	events := collect(t, ua)
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)

	// A REJECTED refresh appends a non-terminal error with detail.kind
	// session_refresh_failed. The peer ANSWERED — it is reachable inside the
	// dialog — so this is not §11.3.1 case 2 and the call is NOT ended here; the
	// peer's own half-interval timer owns what happens next.
	waitForCond(t, func() bool {
		for _, ev := range events() {
			if ev.Kind == session.UAEventMediaError && ev.Detail["kind"] == "session_refresh_failed" {
				return true
			}
		}
		return false
	})
	// detail.code is ALWAYS present, and here it carries the peer's real status —
	// which is how an agent tells "the peer rejected us" from "our send failed
	// outright" (code 0) without probing for key absence.
	for _, ev := range events() {
		if ev.Kind == session.UAEventMediaError && ev.Detail["kind"] == "session_refresh_failed" {
			code, present := ev.Detail["code"]
			if !present {
				t.Fatalf("session_refresh_failed detail=%+v is missing `code`; it is ALWAYS "+
					"present, so an agent never has to test for key absence", ev.Detail)
			}
			if code != 500 {
				t.Fatalf("detail.code=%v want the peer's own 500", code)
			}
		}
	}
	for _, ev := range events() {
		if ev.Kind == session.UAEventDialogEnded {
			t.Fatalf("a rejected refresh must not end the dialog; cause=%q", ev.Cause)
		}
	}
}

// TestARefreshThatDrawsNoResponseEndsTheCallInDialogTimeout is R9's other half
// and §11.3.1 case 2: the peer goes silent INSIDE the dialog, our refresh draws
// no final response before the transaction budget (Timer B/F) expires, and the
// call must terminate transport_failure / in_dialog_timeout rather than sit
// `answered` forever.
//
// It is ALSO the deadlock regression test: the terminal event is emitted only
// AFTER endDialogInDialogTimeout's stopSessionTimer returns, so receiving the
// event at all proves the teardown did not self-join on the refresher goroutine
// that produced it (see runOffRefresherGoroutine). Under the inline form this
// test hangs on go-test's own -timeout rather than failing an assertion — Task
// 23's reentrancy guard converts that into an immediate, named panic instead
// (Correction 13); either way it does not read as a passing assertion.
func TestARefreshThatDrawsNoResponseEndsTheCallInDialogTimeout(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, UPDATE",
			SwallowUpdate:        true, // answers the INVITE, then goes silent
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	// An explicit SHORT transaction budget: sipgo's Timer B/F is a real timer, so
	// the fake clock cannot advance it. Production keeps ua.go:260's 32s default,
	// which is Timer B/F itself and what §11.3.1's "32s +/-2s" is measured against.
	// Correction 12: 500ms rather than the brief's 2s — nothing here depends on
	// the magnitude, and 2s left only 1s of headroom against waitFor's own 3s
	// poll deadline, stable at idle but able to flip under contention on this
	// 4-CPU sandbox.
	ua, _ := newSessionTimerUAWithTimeout(t, clk, 1800, 90, 500*time.Millisecond)
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // the refresh fires and draws nothing

	ended := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ended.Cause != session.UACauseTransportFailure {
		t.Fatalf("cause=%q want transport_failure (§11.3.1 case 2)", ended.Cause)
	}
	if ended.Detail["kind"] != "transport_failure" || ended.Detail["cause"] != "in_dialog_timeout" {
		t.Fatalf("detail=%+v want {kind:transport_failure, cause:in_dialog_timeout}", ended.Detail)
	}
	if ended.DialogID != res.DialogID {
		t.Fatalf("dialog_id=%q want %q — the fault is DIALOG-scoped, not UA-wide",
			ended.DialogID, res.DialogID)
	}
	for _, ev := range events() {
		if ev.Kind == session.UAEventTransportFault {
			t.Fatal("an in-dialog timeout must NOT emit the UA-wide UAEventTransportFault — " +
				"its handler would terminate this UA's other, healthy calls")
		}
	}
	// §11.3.1: "in case 2 the BYE has already been sent and gone unanswered; it is
	// not retried beyond Timer F". A peer that answered nothing for a full Timer F
	// gets no BYE; the dialog is torn down locally.
	if p.ByeCount() != 0 {
		t.Fatalf("%d BYEs sent; §11.3.1 case 2 tears the dialog down locally", p.ByeCount())
	}
	// The dialog is forgotten, so its view is gone — a second proof that the
	// teardown ran to completion.
	if _, ok := ua.SessionTimerView(res.DialogID); ok {
		t.Fatal("the dialog is still registered after an in-dialog timeout")
	}
}

// updateFailConn is a net.PacketConn decorator installed through Task 13's
// Config.WrapConn seam — the same seam countingConn (countingconn_test.go) and
// ackFailConn (call_dial_media_leak_test.go) already use — that fails every
// outbound UPDATE write with a synthetic error while passing the INVITE, the ACK
// and any BYE through unchanged. It reuses firstLine (countingconn_test.go, same
// sipua_test package) rather than reimplementing the SIP first-line parse.
//
// It is the deterministic way to reach the SEND-FAILED species: sipgo turns a
// conn write error at ClientTx.Init into an immediate TransactionRequest error
// (wrapTransportError -> sip.ErrTransactionTransport), which is exactly species 1
// above. Faking it any higher — an unroutable Request-URI, a stopped peer waiting
// on ICMP — is either impossible for an outbound dialog (the in-dialog
// Request-URI comes from the INVITE we already sent successfully) or timing
// dependent.
//
// NOT one-shot, unlike ackFailConn: the refresher's retry must fail the same way,
// so the test proves the classification holds across the whole retry budget and
// not just on the first attempt.
type updateFailConn struct {
	net.PacketConn
	writes atomic.Int64
}

func (c *updateFailConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if strings.HasPrefix(firstLine(b), "UPDATE ") {
		c.writes.Add(1)
		return 0, fmt.Errorf("injected UPDATE write failure")
	}
	return c.PacketConn.WriteTo(b, addr)
}

// TestARefreshWhoseSendFailsIsNotAnInDialogTimeout is the NEGATIVE half of
// §11.3.1 case 2, and it is about honesty in the event log rather than about
// liveness: when the transaction layer refuses the send OUTRIGHT, no Timer F ran
// and nothing was learned about the peer, so the call must NOT be terminated
// `transport_failure` / `in_dialog_timeout` — that detail would assert "we waited
// 32 s and heard nothing", which never happened.
//
// It is deliberately the mirror of TestARefreshThatDrawsNoResponse... above,
// which covers the ONE species that IS the deadline and stays as it is. What this
// one pins is the boundary between them, i.e. that refreshDrewNoResponse is
// consulted at all: under the over-broad first draft, which routed EVERY
// RawTransaction error to endDialogInDialogTimeout, this test fails on the
// UAEventDialogEnded assertion.
func TestARefreshWhoseSendFailsIsNotAnInDialogTimeout(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	var fc *updateFailConn
	ua, _ := newSessionTimerUAWithWrapConn(t, clk, 1800, 90, func(pc net.PacketConn) net.PacketConn {
		fc = &updateFailConn{PacketConn: pc}
		return fc
	})
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // the refresh fires and the WRITE fails

	// The refresh failure is reported the same way a REJECTED refresh is:
	// non-terminal, kind session_refresh_failed, carrying the error text.
	waitForCond(t, func() bool {
		for _, ev := range events() {
			if ev.Kind == session.UAEventMediaError && ev.Detail["kind"] == "session_refresh_failed" {
				return true
			}
		}
		return false
	})
	if n := fc.writes.Load(); n != 1 {
		t.Fatalf("%d UPDATE writes after the first failure, want exactly 1", n)
	}
	// detail.code is ALWAYS present and is 0 HERE, meaning "no response was ever
	// received" — the discriminator between this species and a peer rejection.
	// It is emitted as 0, never omitted.
	for _, ev := range events() {
		if ev.Kind == session.UAEventMediaError && ev.Detail["kind"] == "session_refresh_failed" {
			code, present := ev.Detail["code"]
			if !present {
				t.Fatalf("session_refresh_failed detail=%+v omits `code`; 0 means \"no response "+
					"was ever received\" and must be EMITTED, not left to key absence", ev.Detail)
			}
			if code != 0 {
				t.Fatalf("detail.code=%v want 0 — the send failed, so no status code exists", code)
			}
		}
	}

	// A send failure is retryable (Task 23's backoff{Attempts:2, Base:2s, Cap:8s},
	// startSessionRefresher — plan line ~8799), unlike a genuine Timer F timeout,
	// which is terminal on the FIRST occurrence (TestARefreshThatDrawsNoResponse...
	// above never reaches a second attempt). Advancing past Base proves the
	// refresher is actually still armed and retrying — not just that this one
	// failure was classified correctly, but that the whole retryable path stays
	// alive across it, exactly as the discriminator is supposed to guarantee.
	clk.BlockUntil(1)
	clk.Advance(2 * time.Second) // retry 1 at base
	waitForAtomic(t, &fc.writes, 2)

	for _, ev := range events() {
		if ev.Kind == session.UAEventDialogEnded {
			t.Fatalf("a refresh whose SEND failed must not end the dialog; cause=%q detail=%+v",
				ev.Cause, ev.Detail)
		}
		if ev.Detail["cause"] == "in_dialog_timeout" {
			t.Fatalf("detail=%+v claims in_dialog_timeout, but no Timer F ever ran — "+
				"the send failed immediately", ev.Detail)
		}
	}
	// The dialog is still LIVE and REGISTERED: nothing was torn down, across
	// BOTH the original failure and its retry. This does NOT prove the
	// refresher is still armed — Attempts:2 is exhausted by this point (the
	// initial attempt plus the one retry asserted above), so the refresher's
	// own goroutine has given up and exited permanently; the PEER's own
	// session timer owns the endgame from here, exactly as a rejected refresh
	// does. What this assertion pins is narrower: a send failure alone must
	// not release the dialog the way endDialogInDialogTimeout does.
	if _, ok := ua.SessionTimerView(res.DialogID); !ok {
		t.Fatal("the dialog was released by a send failure")
	}
	if p.ByeCount() != 0 {
		t.Fatalf("%d BYEs sent; a failed refresh SEND is not a teardown", p.ByeCount())
	}
}

// reInviteRingThenSilentSDP offers PCMU so the initial INVITE negotiates
// cleanly; only the refresh path this stub exists for matters.
const reInviteRingThenSilentSDP = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=x\r\nc=IN IP4 127.0.0.1\r\n" +
	"t=0 0\r\nm=audio 20112 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"

// reInviteRingThenSilentStub answers the FIRST INVITE of a Call-ID with a
// session timer naming US as refresher and Allow: INVITE, ACK, BYE (no
// UPDATE, so Task 28's refreshMethodFor falls back to re-INVITE), then
// answers every LATER in-dialog INVITE — the re-INVITE refresh itself — with
// 100 Trying and nothing else. It is not internal/testutil/peer (that
// package is owned by another task and is not extended here); it is a
// small, purpose-built fake matching this file's own updateFailConn
// precedent above.
type reInviteRingThenSilentStub struct {
	conn    net.PacketConn
	parser  *sip.Parser
	dialogs map[string]bool
}

func startReInviteRingThenSilentStub(t *testing.T) *reInviteRingThenSilentStub {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &reInviteRingThenSilentStub{conn: c, parser: sip.NewParser(), dialogs: map[string]bool{}}
	t.Cleanup(func() { _ = c.Close() })
	go s.serve()
	return s
}

func (s *reInviteRingThenSilentStub) Addr() string { return s.conn.LocalAddr().String() }

func (s *reInviteRingThenSilentStub) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		d := make([]byte, n)
		copy(d, buf[:n])
		m, err := s.parser.ParseSIP(d)
		if err != nil {
			continue
		}
		req, ok := m.(*sip.Request)
		if !ok {
			continue
		}
		callID := ""
		if h := req.CallID(); h != nil {
			callID = h.Value()
		}
		switch req.Method {
		case sip.INVITE:
			if s.dialogs[callID] {
				// The re-INVITE refresh: 100 Trying, then silence forever —
				// this is what stops sipgo's own timer_b (see the test's doc
				// comment).
				s.write(sip.NewResponseFromRequest(req, 100, "Trying", nil), from)
				continue
			}
			s.dialogs[callID] = true
			res := sip.NewSDPResponseFromRequest(req, []byte(reInviteRingThenSilentSDP))
			host, portS, _ := net.SplitHostPort(s.Addr())
			port, _ := strconv.Atoi(portS)
			res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "stub", Host: host, Port: port}})
			res.AppendHeader(sip.NewHeader("Session-Expires", "90;refresher=uac"))
			res.AppendHeader(sip.NewHeader("Allow", "INVITE, ACK, BYE"))
			s.write(res, from)
		case sip.ACK:
		default:
			s.write(sip.NewResponseFromRequest(req, 200, "OK", nil), from)
		}
	}
}

func (s *reInviteRingThenSilentStub) write(res *sip.Response, to net.Addr) {
	_, _ = s.conn.WriteTo([]byte(res.String()), to)
}

// TestAReInviteRefreshRingThenSilentEndsInDialogTimeoutViaTheCallerTimeoutAlone
// is Fix Round 1's Item 7 regression test, covering a class of §11.3.1 case 2
// the live Asterisk e2e gate PROVABLY CANNOT SEE: its own silent-refresh stub
// (e2e/loop/sessiontimer_silent_stub.go) never answers the refresh at all and
// negotiates UPDATE, and sipgo only stops Timer_B on a PROVISIONAL response —
// so that stub's silence still leaves sipgo's own Timer_B armed, and the gate
// scored 17/17 three runs in a row even while carrying the indefinite-hang
// design (removing doTx's caller-side tctx entirely) this test would have
// caught. This test forces the re-INVITE refresh path
// (session_refresh_method: "invite", so Task 28's refreshMethodFor never
// even considers UPDATE) against a peer that RINGS (100 Trying) before going
// silent — sipgo's actInviteProceeding stops AND NILS timer_b on that first
// provisional (third_party/sipgo/sip/transaction_client_tx_fsm.go).
//
// CORRECTED (fix round 2): with timer_b nilled, tctx is the ONLY surviving
// deadline, so doTx can only ever return via its tctx.Done() branch here —
// bare context.DeadlineExceeded, which the PRE-fix classifier already
// recognised correctly. Mutation-tested (fix round 2): reverting
// refreshDrewNoResponse's new substring check to its exact pre-fix form does
// NOT redden this test (still passes, ~32s) — dropping the
// context.DeadlineExceeded check instead (keeping only the new substring
// check) DOES redden it, proving this test exercises tctx.Done() exclusively.
// It remains a genuine and valuable regression guard for a DIFFERENT
// property — that removing the caller-side timeout (the refuted "rely on
// sipgo's timer alone" design) reintroduces an indefinite hang — but it is
// NOT coverage for Item 7's classifier fix. See
// TestARefreshWhoseTimeoutOutlivesTimerBEndsTheCallInDialogTimeout below for
// that.
//
// This runs on the REAL clock past the refresh's own transaction budget
// (cfg.Timeout = production's 32s): the fake clock only drives WHEN the
// refresh fires, not sipgo's real Timer_B/doTx's real tctx once it is in
// flight.
func TestAReInviteRefreshRingThenSilentEndsInDialogTimeoutViaTheCallerTimeoutAlone(t *testing.T) {
	s := startReInviteRingThenSilentStub(t)
	clk := fakeclock.New(time.Unix(0, 0))
	// "invite" forces the re-INVITE refresh method outright (Task 28's
	// refreshMethodFor override), independent of what the peer's Allow says.
	ua, _ := newSessionTimerUAFull(t, clk, 1800, 90, "invite", 32*time.Second, nil)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + s.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // the re-INVITE refresh fires

	// Poll on the REAL clock past cfg.Timeout (32s) for the terminal event.
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range events() {
			if ev.Kind == session.UAEventDialogEnded {
				if ev.DialogID != res.DialogID {
					t.Fatalf("dialog_id=%q want %q", ev.DialogID, res.DialogID)
				}
				if ev.Cause != session.UACauseTransportFailure {
					t.Fatalf("cause=%q want transport_failure (§11.3.1 case 2)", ev.Cause)
				}
				if ev.Detail["kind"] != "transport_failure" || ev.Detail["cause"] != "in_dialog_timeout" {
					t.Fatalf("detail=%+v want {kind:transport_failure, cause:in_dialog_timeout}", ev.Detail)
				}
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("no terminal event within 40s of a re-INVITE refresh that rang then went silent — " +
		"sipgo stopped timer_b on the 100 Trying, so only doTx's own tctx can end this, and it did not")
}

// TestARefreshWhoseTimeoutOutlivesTimerBEndsTheCallInDialogTimeout is fix
// round 2's discriminator test: the sibling test above cannot exercise
// doTx's tx.Done() branch at all (its 100-Trying stops sipgo's own timer_b,
// leaving tctx as the only surviving deadline), so Item 7's classifier fix —
// the new sip.ErrTransactionTimeout substring match in refreshDrewNoResponse
// — had NO unit-test coverage: reverting it to its pre-fix form left that
// sibling test green (mutation-tested, fix round 2).
//
// The deterministic way to make doTx return via tx.Done() instead is to make
// sipgo's own Timer_B ~32s (RFC 3261's 64*T1) the SHORTER of the two
// deadlines: Config.Timeout is set to 45s here, LONGER than Timer_B, so
// Timer_B always fires first — the exact ">32s Timeout" case an earlier
// version of refreshDrewNoResponse's own doc comment called a KNOWN
// LIMITATION never reachable in production (nothing sets Timeout that high)
// but entirely reachable, and useful, in a test. The peer answers the INVITE
// (arming the session timer) then goes FULLY SILENT on the UPDATE refresh —
// no provisional at all, unlike the re-INVITE sibling above — so sipgo's
// Timer_B for that UPDATE transaction stays armed throughout and wins the
// race every run.
//
// Mutation-tested (fix round 2): reverting refreshDrewNoResponse's substring
// check to its pre-fix form reddens this test (the refresh is misclassified
// as a retryable send failure and the dialog never terminates within the
// poll deadline below); restoring the fix greens it again.
func TestARefreshWhoseTimeoutOutlivesTimerBEndsTheCallInDialogTimeout(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, UPDATE",
			SwallowUpdate:        true, // answers the INVITE, then goes silent -- no provisional either
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	// 45s: LONGER than sipgo's own ~32s Timer_B, so Timer_B deterministically
	// fires first — the opposite choice from the sibling test's 500ms, which
	// deterministically makes tctx win instead.
	ua, _ := newSessionTimerUAWithTimeout(t, clk, 1800, 90, 45*time.Second)
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // the refresh fires and draws nothing

	// Poll on the REAL clock: Timer_B (~32s) must fire well before
	// Config.Timeout (45s), so 40s is ample margin for a correctly-classified
	// run and still short of the mutant's first retry cycle.
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range events() {
			if ev.Kind == session.UAEventDialogEnded {
				if ev.DialogID != res.DialogID {
					t.Fatalf("dialog_id=%q want %q", ev.DialogID, res.DialogID)
				}
				if ev.Cause != session.UACauseTransportFailure {
					t.Fatalf("cause=%q want transport_failure (§11.3.1 case 2)", ev.Cause)
				}
				if ev.Detail["kind"] != "transport_failure" || ev.Detail["cause"] != "in_dialog_timeout" {
					t.Fatalf("detail=%+v want {kind:transport_failure, cause:in_dialog_timeout}", ev.Detail)
				}
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("no terminal event within 40s of a refresh whose Timer_B (~32s) must already have fired " +
		"(Config.Timeout=45s) — refreshDrewNoResponse's tx.Done()/Timer_B branch did not classify it")
}

// TestPeerAsRefresherArmsNoRefresherOnOurSide is Correction 11's third closed
// mutant: dropping startSessionRefresher's `!st.weRefresh` gate would arm a
// refresher on a dialog where the PEER holds the refresh role, and Task 30's
// watchdog arms on exactly those dialogs instead.
//
// SessionTimerView.NextRefreshMs is populated when EITHER st.refresher or
// st.watchdog is non-nil (SessionTimerView, sessiontimer.go). Now that Task 30
// has landed, a refresher=uas dialog gets the WATCHDOG armed, not a refresher —
// so next_refresh_ms reports the watchdog's full-interval deadline (90000ms),
// and the ONE waiter BlockUntil(1) waits on below is that watchdog, not a
// wrongly-armed refresher. A wrongly-armed refresher would additionally send an
// UPDATE at interval/2, which the trailing assertion still rules out.
func TestPeerAsRefresherArmsNoRefresherOnOurSide(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uas",
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 90)
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	v, ok := ua.SessionTimerView(res.DialogID)
	if !ok {
		t.Fatal("the answer negotiated a session timer; SessionTimerView must report one")
	}
	if v.NextRefreshMs != 90000 {
		t.Fatalf("next_refresh_ms=%d want 90000 (the watchdog deadline, Task 30)", v.NextRefreshMs)
	}

	// Task 30: the WATCHDOG is armed (one waiter), our own refresher is not.
	clk.BlockUntil(1)
	before := p.Count("INVITE")
	time.Sleep(50 * time.Millisecond)
	if p.Count("INVITE") != before || p.Count("UPDATE") != 0 {
		t.Fatal("a dialog where the peer is the refresher must not send a refresh")
	}
}

// TestInboundRefreshSendsUPDATEWithOurContactAndSessionExpires is Correction
// 15's inbound coverage: the PEER dials US (p.DialWithHeaders), Task 27's
// default claims role "uas" for a call we accept, so weRefresh is true and OUR
// own timer fires the refresh. This IS wire-observable — review round 1's
// Important 2 established that the test peer's respond() answers ANY UPDATE
// it receives (buildRefreshResponse) regardless of which side dialled, so
// this report's earlier claim that the inbound arm was untestable was wrong.
func TestInboundRefreshSendsUPDATEWithOurContactAndSessionExpires(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 60)
	events := collect(t, ua)

	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Supported":       "timer",
		"Session-Expires": "90",
		"Allow":           "INVITE, ACK, BYE, CANCEL, UPDATE",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)
	// startSessionRefresher's r.Start(ctx) launches the timer-arming goroutine
	// asynchronously (refresher.go), so SessionTimerView's NextRefreshMs can
	// still read the zero value in the instant right after Answer returns.
	// clk.BlockUntil(1) is this file's established idiom for waiting out that
	// race — it returns only once the refresher has actually registered its
	// fake-clock timer.
	clk.BlockUntil(1)
	v, ok := ua.SessionTimerView(inc.DialogID)
	if !ok || v.Refresher != "uas" || v.NextRefreshMs <= 0 {
		t.Fatalf("view=%+v ok=%v want refresher=uas with our own timer armed", v, ok)
	}

	clk.Advance(46 * time.Second) // RFC 4028 §10: interval/2 = 45s
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })

	// CF-116 (RFC 4028 7.4): in the refresh transaction we are the UAC and we are
	// performing the refreshes, so the parameter is uac; the view's dialog-oriented
	// Refresher above stays uas.
	if got := p.LastRequestHeader("UPDATE", "Session-Expires"); got != "90;refresher=uac" {
		t.Fatalf("UPDATE Session-Expires=%q want 90;refresher=uac", got)
	}
	// Review round 1, CRITICAL 1: this dialog is INBOUND, so
	// buildInDialogRequest's underlying builder clones the PEER's own Contact
	// off the received INVITE unless refreshSession overrides it with
	// u.localContact() — the same direction-blindness species as Correction 6,
	// one header over.
	wantContact := "<sip:alice@" + ua.BoundAddr().String() + ">"
	if got := p.LastRequestHeader("UPDATE", "Contact"); got != wantContact {
		t.Fatalf("UPDATE Contact=%q want %q (ours, not the peer's)", got, wantContact)
	}
}

// TestInboundRefreshWithReINVITEUsesOurOwnSDP is Correction 6's regression
// fence — its previous absence was Important 2's second finding. The peer's
// Allow omits UPDATE, so refreshMethodFor falls back to a re-INVITE. On an
// INBOUND dialog ourReInviteSDPLocked must replay OUR OWN 200 OK's SDP
// (d.ok), never the PEER's original offer (d.invite) — buildInDialogRequest's
// shared builder does not distinguish direction for the body at all; only
// refreshSession's explicit override does. The outbound-only re-INVITE test
// (TestWeRefreshWithReINVITEWhenThePeerDoesNotAllowUPDATE) cannot catch a
// reverted Correction 6: for an outbound dialog d.ok and d.invite carry the
// SAME bytes (ours either way), so that test stays green regardless.
func TestInboundRefreshWithReINVITEUsesOurOwnSDP(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 60)
	events := collect(t, ua)

	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Supported":       "timer",
		"Session-Expires": "90",
		"Allow":           "INVITE, ACK, BYE, CANCEL", // no UPDATE: forces re-INVITE
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)
	ourAnswerSDP := p.LastFinalResponseBody()
	if len(ourAnswerSDP) == 0 {
		t.Fatal("our own 200 OK carried no SDP to compare the refresh against")
	}

	before, beforeACK := p.Count("INVITE"), p.Count("ACK")
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	waitForCond(t, func() bool { return p.Count("INVITE") > before })

	if got := p.LastRequestBody("INVITE"); got != string(ourAnswerSDP) {
		t.Fatalf("re-INVITE refresh body=%q want our own answer SDP %q (Correction 6)", got, ourAnswerSDP)
	}
	waitForCond(t, func() bool { return p.Count("ACK") > beforeACK })
}

// TestInDialogCSeqIsMonotonicAcrossINFOUpdateAndBYE is the CSeq half of this
// task's refactor, and it is the ONLY test that can catch the bug: each method's
// own CSeqs are trivially monotonic (there is one of each), so a per-method
// assertion passes even when BYE reuses a number UPDATE already spent. It drives
// all three in-dialog requests on ONE dialog, in order, and asserts the sequence
// space strictly increases ACROSS them (RFC 3261 §12.2.1.1).
//
// This pins the shared-allocator de-duplication (Rule 16/18), not a bug fix:
// Correction 8 established that the OLD hand-rolled BYE construction already
// derived its CSeq from d.localCSeq bit-identically to buildInDialogRequest (the
// pre-existing comment at the old call site said so explicitly, and reverting
// the refactor left this test green). What buildInDialogRequest's BYE actually
// closes are two latent edge cases: a nil panic when d.invite == nil, and a BYE
// that reused the answered INVITE's cloned Via branch. This test is the
// regression fence for the shared allocator staying shared, not a reproduction
// of a CSeq-reuse bug.
func TestInDialogCSeqIsMonotonicAcrossINFOUpdateAndBYE(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 90)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	// 1. INFO, through SendDTMF(info) — the first in-dialog request.
	if _, _, err := ua.SendDTMF(context.Background(), res.DialogID, "1",
		session.DTMFModeInfo, 100, 0); err != nil {
		t.Fatalf("SendDTMF(info): %v", err)
	}
	waitForCond(t, func() bool { return p.Count("INFO") >= 1 })

	// 2. UPDATE, through the session-timer refresh at interval/2.
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })

	// 3. BYE, through the ordinary hangup path.
	if err := ua.Hangup(context.Background(), res.DialogID, "done"); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	p.WaitForBye(t, 5*time.Second)

	var seen []peer.MethodCSeq
	for _, mc := range p.RequestCSeqs() {
		switch mc.Method {
		case "INFO", "UPDATE", "BYE":
			seen = append(seen, mc)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("in-dialog requests = %+v want exactly INFO, UPDATE, BYE", seen)
	}
	if seen[0].Method != "INFO" || seen[1].Method != "UPDATE" || seen[2].Method != "BYE" {
		t.Fatalf("arrival order = %+v want INFO, UPDATE, BYE", seen)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i].CSeq <= seen[i-1].CSeq {
			t.Fatalf("%s CSeq=%d is not greater than the preceding %s CSeq=%d — every "+
				"in-dialog request must allocate from d.localCSeq (RFC 3261 §12.2.1.1); "+
				"a BYE that derives its own CSeq re-sends a spent number: %+v",
				seen[i].Method, seen[i].CSeq, seen[i-1].Method, seen[i-1].CSeq, seen)
		}
	}
}

func TestHangupWithReasonPutsTheReasonHeaderOnTheBYE(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	if err := sipua.HangupWithReasonForTest(ua, res.DialogID, "SIP;cause=408"); err != nil {
		t.Fatalf("hangupWithReason: %v", err)
	}
	p.WaitForBye(t, 2*time.Second)
	if got := p.LastRequestHeader("BYE", "Reason"); got != "SIP;cause=408" {
		t.Fatalf("BYE Reason=%q want SIP;cause=408", got)
	}
}

func TestHangupStillSendsNoReasonHeader(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	// Agent-supplied free text must NEVER become a structured header.
	if err := ua.Hangup(context.Background(), res.DialogID, `SIP;cause=999\r\nX-Injected: yes`); err != nil {
		t.Fatal(err)
	}
	p.WaitForBye(t, 2*time.Second)
	if got := p.LastRequestHeader("BYE", "Reason"); got != "" {
		t.Fatalf("BYE Reason=%q must be absent — Hangup's reason is free text and never a header", got)
	}
	if got := p.LastRequestHeader("BYE", "X-Injected"); got != "" {
		t.Fatal("header injection through Hangup's reason parameter")
	}
}

// TestSessionRefreshLandsBetweenTwoDigitsOfOneINFOSend is Cycle 4's group-B
// combination "DTMF racing a session-timer refresh". The existing cross-feature
// test above drives INFO, UPDATE and BYE as three SEPARATE operations; this one
// lands the refresh INSIDE a single in-flight send, between digit 1 and digit 2,
// which is the interleaving a production call actually produces — a DTMF string
// entered at an IVR prompt routinely spans a refresh interval.
//
// WHAT IT ADDS OVER THE TWO TESTS EITHER SIDE OF IT. The refresh's UPDATE
// allocates a CSeq from d.localCSeq while sendDTMFInfo is parked in its
// inter-digit gap holding the dialog's dtmfInfoInFlight claim. A send that
// derived its digits' CSeqs once, up front, rather than per request would put
// digit 2 on the wire BEHIND the UPDATE's number — invisible to
// TestSendDTMFInfoThenHangupKeepsCSeqMonotonic (no refresh interleaves there)
// and to TestInDialogCSeqIsMonotonicAcrossINFOUpdateAndBYE (one INFO only).
// It also proves the refresher goroutine is not blocked by a send in progress:
// the two paths take u.calls.mu independently, and a refresh that could not run
// until the send finished would time out below rather than fail an assertion.
//
// DETERMINISTIC BY CONSTRUCTION: the gap (60 s) outlasts the refresh deadline
// (interval/2 = 45 s), so on the fake clock the refresh is strictly first. Two
// waiters — the refresher and the gap — so BlockUntil(2), an exact-count wait.
func TestSessionRefreshLandsBetweenTwoDigitsOfOneINFOSend(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac", // WE refresh, at 45s
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 60)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	type result struct {
		sent int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		sent, _, err := ua.SendDTMF(context.Background(), res.DialogID, "12",
			session.DTMFModeInfo, 100, 60000)
		done <- result{sent, err}
	}()
	waitForCond(t, func() bool { return p.Count("INFO") >= 1 })

	clk.BlockUntil(2) // the session refresher and the inter-digit gap
	clk.Advance(46 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })

	clk.Advance(20 * time.Second) // releases the gap at t=66s; digit 2 goes out
	var got result
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SendDTMF never returned: a session refresh landing mid-send blocked it")
	}
	if got.err != nil || got.sent != 2 {
		t.Fatalf("SendDTMF(info) sent=%d err=%v want 2/nil — a refresh mid-send must not "+
			"disturb the send", got.sent, got.err)
	}

	var seen []peer.MethodCSeq
	for _, mc := range p.RequestCSeqs() {
		if mc.Method == "INFO" || mc.Method == "UPDATE" {
			seen = append(seen, mc)
		}
	}
	if len(seen) != 3 || seen[0].Method != "INFO" || seen[1].Method != "UPDATE" || seen[2].Method != "INFO" {
		t.Fatalf("wire order = %+v want INFO, UPDATE, INFO — the refresh must land BETWEEN the "+
			"two digits for this test to mean anything", seen)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i].CSeq <= seen[i-1].CSeq {
			t.Fatalf("%s CSeq=%d is not greater than the preceding %s CSeq=%d: every in-dialog "+
				"request allocates from d.localCSeq AT SEND TIME (RFC 3261 §12.2.1.1), so a digit "+
				"whose number was reserved before the refresh re-sends a spent one: %+v",
				seen[i].Method, seen[i].CSeq, seen[i-1].Method, seen[i-1].CSeq, seen)
		}
	}
}

// TestAnAbsurdAnsweredSessionIntervalCannotFastFireTheRefresher is the answer
// path's half of the F1 overflow bound.
//
// `Session-Expires: 9999999999` survives every check the answer path had:
// parseSessionExpires rejects only `n <= 0`, and belowMinSE is a FLOOR. It then
// reached `time.Duration(intervalS) * time.Second` at startSessionRefresher,
// where the multiply wraps NEGATIVE (-2346317h47m54s). A negative delay is a
// deadline already in the past, so the refresh timer fires the instant it is
// armed, and re-arms into the past again after every refresh — an unbounded
// UPDATE flood on an established dialog, aimed at whichever host answered our
// INVITE.
//
// THE ASSERTION IS ON THE WIRE, NOT ON THE CLAMPED INTEGER. Checking only that
// the negotiated interval reads 7200 would stay green if some other path still
// overflowed; counting UPDATEs across an advanced clock is what actually pins
// "no fast-fire loop". Clamped to maxAcceptableSessionIntervalS the refresh is
// due at 7200/2 = 3600s, so the whole window before that must be silent.
func TestAnAbsurdAnsweredSessionIntervalCannotFastFireTheRefresher(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "9999999999;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 60)
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	clk.BlockUntil(1)
	// Unclamped, the refresher's deadline is already in the past, so this single
	// Advance crosses it and every re-arm it produces.
	clk.Advance(3599 * time.Second)
	time.Sleep(100 * time.Millisecond)
	if n := p.Count("UPDATE"); n != 0 {
		t.Fatalf("UPDATE count=%d 3599s into the dialog, want 0 — a peer-supplied "+
			"Session-Expires that overflows time.Duration has turned the refresher "+
			"into an immediate-fire loop", n)
	}
	if n := p.ByeCount(); n != 0 {
		t.Fatalf("BYE count=%d, want 0 — the dialog must stay up", n)
	}

	// And the clamped cadence is real rather than the timer simply being off.
	clk.Advance(2 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
	if got := p.LastRequestHeader("UPDATE", "Session-Expires"); got != "7200;refresher=uac" {
		t.Fatalf("UPDATE Session-Expires=%q want 7200;refresher=uac — the interval we "+
			"advertise must be the clamped one we are actually running", got)
	}
}

// TestAnAbsurdRefreshGrantCannotFastFireTheRefresher is the re-base path's half
// of the same bound, and it is a SEPARATE test because the re-base is a separate
// site with its own history: it shipped with no floor at all while the answer
// path had one (Correction 11), and its comment then declined an upper bound
// outright on the grounds that "an over-long grant makes us refresh less often".
// It does not — past the wrap it makes us refresh continuously.
//
// The dialog negotiates a benign 90 and only the REFRESH RESPONSE carries the
// absurd value, so nothing on the answer path can account for the result.
func TestAnAbsurdRefreshGrantCannotFastFireTheRefresher(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires:  "90;refresher=uac",
			RefreshSessionExpires: []string{"9999999999;refresher=uac"},
			AnswerAllow:           "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 60)
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // the negotiated 90's half
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })

	ev := waitFor(t, events, session.UAEventSessionRefresh, 0)
	if ev.Detail["interval_s"] != 7200 {
		t.Fatalf("session_refresh interval_s=%v want the clamped 7200", ev.Detail["interval_s"])
	}

	// The event is emitted from inside Do, so the re-arm has not happened yet.
	clk.BlockUntil(1)
	clk.Advance(3000 * time.Second)
	time.Sleep(100 * time.Millisecond)
	if n := p.Count("UPDATE"); n != 1 {
		t.Fatalf("UPDATE count=%d 3000s after the first refresh, want 1 — the granted "+
			"interval overflowed time.Duration and the refresher is fast-firing", n)
	}
	clk.Advance(700 * time.Second) // 3700s > the clamped half-interval of 3600s
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 2 })
}
