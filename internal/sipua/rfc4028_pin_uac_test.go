package sipua_test

// Lane C (rfc-sweep-c) pins for the C-UAC area (RFC 4028 section 7). Each passes
// today and must be inverted when its NEW-C finding is fixed. No test here calls t.Parallel
// (parallel_invariant_test.go). Every timer is the fake clock (6a D11), through
// newSessionTimerUA (sessiontimer_wire_test.go) against internal/testutil/peer.

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

// TestRFC4028_NEWC1_ByeCarriesSupportedTimer is NEW-C-1 / CF-113, fixed: RFC 4028
// 7.1: "A UAC that supports the session timer extension defined here MUST
// include a Supported header field in each request (except ACK), listing the
// option tag 'timer' [2]." rfc4028.txt:459-461. Was
// the old RFC4028 pin NEWC1_ByeCarriesNoSupportedTimer.
func TestRFC4028_NEWC1_ByeCarriesSupportedTimer(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 90, 90)
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	if got := p.LastRequestHeader("INVITE", "Supported"); !strings.Contains(got, "timer") {
		t.Fatalf("INVITE Supported=%q: the UA no longer advertises timer at all (precondition)", got)
	}
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	waitForCond(t, func() bool { return p.ByeCount() >= 1 })
	if got := p.LastRequestHeader("BYE", "Supported"); !strings.Contains(got, "timer") {
		t.Fatalf("BYE Supported=%q does not list timer", got)
	}
}

// TestRFC4028Pin_NEWC2_InitialInviteNamesTheRefresher pins NEW-C-2 (C-UAC-06,
// RFC 4028 7.1: "However, it is RECOMMENDED that the parameter be omitted so
// that it can be selected by the negotiation mechanisms described below."
// rfc4028.txt:489-491). Evidence: evidence/x-out-udp/excerpt.txt frame 1 and 4
// (Session-Expires: 90;refresher=uac); evidence/uac-422/excerpt.txt frame 4 (the
// 422 retry, 120;refresher=uac). It contradicts TestDialAdvertisesSessionTimerHeaders
// (sessiontimer_wire_test.go), which asserts the parameter (Phase 3 decision 12),
// and both pass today (6a D11, D20).
//
// PIN OF A DEVIATION: invert this assertion when NEW-C-2 is fixed.
func TestRFC4028Pin_NEWC2_InitialInviteNamesTheRefresher(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 90, 90)
	events := collect(t, ua)
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	if got := p.LastRequestHeader("INVITE", "Session-Expires"); !strings.Contains(got, "refresher=") {
		t.Fatalf("INVITE Session-Expires=%q has no refresher parameter: NEW-C-2 is fixed, invert this pin", got)
	}
}

// answerInboundSessionTimerCall has the peer dial a 90/90 UA with X-IN-UDP leg
// 2's and R-IN's request shape (Session-Expires 120, Min-SE 120, Allow listing
// UPDATE), answers it, and waits until the UA's refresh timer is armed.
func answerInboundSessionTimerCall(t *testing.T, p *peer.Peer, clk *fakeclock.Clock) {
	t.Helper()
	answerInboundSessionTimerCallUA(t, p, clk)
}

// answerInboundSessionTimerCallUA is answerInboundSessionTimerCall returning the
// UA, the dialog id and the event collector for tests that assert on them.
func answerInboundSessionTimerCallUA(t *testing.T, p *peer.Peer, clk *fakeclock.Clock) (*sipua.UA, string, func() []session.UAEvent) {
	t.Helper()
	ua, _ := newSessionTimerUA(t, clk, 90, 90)
	events := collect(t, ua)
	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Supported":       "timer",
		"Session-Expires": "120",
		"Min-SE":          "120",
		"Allow":           "INVITE, ACK, BYE, CANCEL, UPDATE",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)
	clk.BlockUntil(1)
	return ua, inc.DialogID, events
}

// TestRFC4028_NEWC3_InboundRefresh2xxNamingUasHandsRefreshingToThePeer (NEW-C-3,
// CF-115; inverted from its Pin): a refresh 2xx naming the peer is read in the
// refresh transaction, where we are the UAC (RFC 4028 7.2: "The UAC MUST set the
// identity of the refresher to the value of this parameter." rfc4028.txt:521-522).
// Evidence: evidence/x-in-udp/excerpt.txt frames 26-34. On a dialog we answered,
// `refresher=uas` in the answer to OUR UPDATE names Asterisk, so we stop
// refreshing and arm the session watchdog; the dialog-oriented view says "uac".
func TestRFC4028_NEWC3_InboundRefresh2xxNamingUasHandsRefreshingToThePeer(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{RefreshSessionExpires: []string{"120;refresher=uas"}},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, dialogID, events := answerInboundSessionTimerCallUA(t, p, clk)

	// Interval 120: our first refresh is due at 60 s; the peer answers it 200
	// Session-Expires: 120;refresher=uas.
	clk.Advance(61 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
	ev := waitFor(t, events, session.UAEventSessionRefresh, 0)
	if ev.Detail["refresher"] != "uac" {
		t.Fatalf("session_refresh refresher=%v want uac (dialog orientation: the peer, the initial UAC, refreshes)", ev.Detail["refresher"])
	}
	// The watchdog replaces the refresher: poll for its 120 s deadline (the waiter
	// count is 1 before and after the swap, so BlockUntil alone would not prove it).
	waitForCond(t, func() bool {
		v, ok := ua.SessionTimerView(dialogID)
		return ok && v.Refresher == "uac" && v.Armed && v.NextRefreshMs > 119_000 && v.NextRefreshMs <= 120_000
	})
	clk.BlockUntil(1)
	clk.Advance(61 * time.Second)
	time.Sleep(300 * time.Millisecond)
	if n := p.Count("UPDATE"); n != 1 {
		t.Fatalf("UPDATE count=%d, want 1: we kept refreshing after the peer took the role", n)
	}
	clk.Advance(60 * time.Second) // past the watchdog's 120 s: the peer never refreshed
	waitForCond(t, func() bool { return p.ByeCount() >= 1 })
}

// TestRFC4028_NEWC4_InboundDialogRefreshSaysUac (NEW-C-4, CF-116; inverted from
// its Pin): RFC 4028 7.4: "it is RECOMMENDED that the refresher parameter be set
// to 'uac' if the element sending the request is currently performing refreshes"
// (rfc4028.txt:633-636). Our refresh on a dialog we answered says uac.
func TestRFC4028_NEWC4_InboundDialogRefreshSaysUac(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	answerInboundSessionTimerCall(t, p, clk)

	clk.Advance(61 * time.Second) // we refresh: interval 120, due at 60 s
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
	if got := p.LastRequestHeader("UPDATE", "Session-Expires"); got != "120;refresher=uac" {
		t.Fatalf("our refresh UPDATE Session-Expires=%q want 120;refresher=uac", got)
	}
}

// TestInboundRefresh2xxNamingUacKeepsUsRefreshing: the agree path of CF-115: a
// refresh 2xx naming us (`refresher=uac`, read in our UAC orientation) leaves us
// refreshing.
func TestInboundRefresh2xxNamingUacKeepsUsRefreshing(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{RefreshSessionExpires: []string{"120;refresher=uac"}},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	answerInboundSessionTimerCall(t, p, clk)

	clk.Advance(61 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
	clk.BlockUntil(1)
	clk.Advance(61 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 2 })
}

// TestRFC4028_NEWC9_RefreshCarriesThePeersLargerMinSE (NEW-C-9, CF-121; inverted
// from its Pin): RFC 4028 7.4: the Min-SE of a refresh "MUST be the largest value
// among all Min-SE header field values returned in all 422 responses or received
// in session refresh requests, on the same dialog" (rfc4028.txt:600-603). The
// peer's INVITE carries Min-SE: 120 (the dialog's seed, Task 2), so our refresh
// carries 120, not our own 90.
func TestRFC4028_NEWC9_RefreshCarriesThePeersLargerMinSE(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	answerInboundSessionTimerCall(t, p, clk) // the peer's INVITE carries Min-SE: 120

	clk.Advance(61 * time.Second) // we refresh: interval 120, due at 60 s
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
	if got := p.LastRequestHeader("UPDATE", "Min-SE"); got != "120" {
		t.Fatalf("our refresh UPDATE Min-SE=%q want 120", got)
	}
}

// TestRFC4028_NEWC13_OutboundRefresh2xxNamingUasHandsRefreshingToThePeer (NEW-C-13,
// CF-125; inverted from its Pin): on a dialog we dialled, a refresh 2xx naming
// `refresher=uas` names the peer (rfc4028.txt:521-522), so we stop refreshing and
// arm the watchdog. Evidence: evidence/rfr-flip/excerpt.txt frames 4-6.
func TestRFC4028_NEWC13_OutboundRefresh2xxNamingUasHandsRefreshingToThePeer(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires:  "90;refresher=uac",
			RefreshSessionExpires: []string{"90;refresher=uas"},
			AnswerAllow:           "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 90, 90)
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // our first refresh; the peer's 200 names uas
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
	waitForCond(t, func() bool {
		v, ok := ua.SessionTimerView(res.DialogID)
		return ok && v.Refresher == "uas" && v.Armed && v.NextRefreshMs > 89_000 && v.NextRefreshMs <= 90_000
	})
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	time.Sleep(300 * time.Millisecond)
	if n := p.Count("UPDATE"); n != 1 {
		t.Fatalf("UPDATE count=%d, want 1: we kept refreshing after the peer took the role", n)
	}
}

// TestAHandoverAboveTheGrantCeilingKeepsTheAgreedWatchdog (K10, codex finding 4):
// the watchdog armed on a handover runs on the agreed interval (what we sent,
// reduced by the peer), not the 7200 s clamp of the grant. A 10000 s dialog
// (Min-SE 10000) whose refresh 2xx names the peer keeps a 10000 s watchdog.
func TestAHandoverAboveTheGrantCeilingKeepsTheAgreedWatchdog(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{RefreshSessionExpires: []string{"10000;refresher=uas"}},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, dialogID := answerBigMinSEDialog(t, p, clk)

	clk.Advance(5001 * time.Second) // our refresh, due at half of 10000 s
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
	waitForCond(t, func() bool {
		v, ok := ua.SessionTimerView(dialogID)
		return ok && v.Refresher == "uac" && v.Armed && v.NextRefreshMs > 9_990_000 && v.NextRefreshMs <= 10_000_000
	})
	clk.BlockUntil(1)
	clk.Advance(7300 * time.Second) // past a 7200 s watchdog, inside the agreed 10000 s
	time.Sleep(300 * time.Millisecond)
	if n := p.ByeCount(); n != 0 {
		t.Fatalf("BYE count=%d at 7300 s: the watchdog ran on the 7200 s clamp, not the agreed 10000 s", n)
	}
	clk.Advance(2800 * time.Second) // past 10000 s since the handover
	waitForCond(t, func() bool { return p.ByeCount() >= 1 })
}

// TestOurRefreshNeverCarriesASessionExpiresBelowItsMinSE (LB-D9): with a 10000 s
// dialog whose refresh grants clamp to 7200, the next refresh still carries
// Session-Expires 10000 under Min-SE 10000, not 7200 (RFC 4028 7.4: "it SHOULD be
// equal to the maximum of the Min-SE ... and the current session interval",
// rfc4028.txt:625-627).
func TestOurRefreshNeverCarriesASessionExpiresBelowItsMinSE(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{RefreshSessionExpires: []string{"10000;refresher=uac"}},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, dialogID := answerBigMinSEDialog(t, p, clk)

	clk.Advance(5001 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
	if got := p.LastRequestHeader("UPDATE", "Session-Expires"); got != "10000;refresher=uac" {
		t.Fatalf("first refresh Session-Expires=%q want 10000;refresher=uac", got)
	}
	if got := p.LastRequestHeader("UPDATE", "Min-SE"); got != "10000" {
		t.Fatalf("first refresh Min-SE=%q want 10000", got)
	}
	// The agree-path grant is clamped to 7200, so the next refresh is due at 3600 s.
	waitForCond(t, func() bool {
		v, ok := ua.SessionTimerView(dialogID)
		return ok && v.NextRefreshMs > 3_590_000 && v.NextRefreshMs <= 3_600_000
	})
	clk.BlockUntil(1)
	clk.Advance(3601 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 2 })
	if got := p.LastRequestHeader("UPDATE", "Session-Expires"); got != "10000;refresher=uac" {
		t.Fatalf("second refresh Session-Expires=%q want 10000;refresher=uac (never below Min-SE)", got)
	}
	if got := p.LastRequestHeader("UPDATE", "Min-SE"); got != "10000" {
		t.Fatalf("second refresh Min-SE=%q want 10000", got)
	}
}

// answerBigMinSEDialog has the peer dial a 90/90 UA with a 10000 s interval and a
// 10000 s Min-SE (honoured since CF-118), answers it and waits for our refresher.
func answerBigMinSEDialog(t *testing.T, p *peer.Peer, clk *fakeclock.Clock) (*sipua.UA, string) {
	t.Helper()
	ua, _ := newSessionTimerUA(t, clk, 90, 90)
	events := collect(t, ua)
	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Supported":       "timer",
		"Session-Expires": "10000",
		"Min-SE":          "10000",
		"Allow":           "INVITE, ACK, BYE, CANCEL, UPDATE",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)
	clk.BlockUntil(1)
	return ua, inc.DialogID
}
