package sipua_test

// Lane C (rfc-sweep-c) pins for the C-UAS area (RFC 4028 section 9). Each passes
// today and must be inverted when its NEW-C finding is fixed. No test here calls t.Parallel
// (parallel_invariant_test.go). Every timer is the fake clock (6a D11), through
// newSessionTimerUA (sessiontimer_wire_test.go) against internal/testutil/peer.

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestRFC4028_NEWC6_AnswerHonoursTheRequestsMinSE (NEW-C-6, CF-118; inverted from
// its Pin): RFC 4028 9: "The UAS response MAY reduce its value but MUST NOT set it
// to a duration lower than the value in the Min-SE header field in the request, if
// it is present" (rfc4028.txt:847-850). Evidence: evidence/uas-big-minse/excerpt.txt
// frame 1 (Session-Expires: 10000, Min-SE: 10000); our 200 used to say 7200, the F1
// overflow clamp applied to the request's Min-SE. The request's Min-SE is now
// honoured up to 86400.
func TestRFC4028_NEWC6_AnswerHonoursTheRequestsMinSE(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 90, 90)
	events := collect(t, ua)
	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Supported":       "timer",
		"Session-Expires": "10000",
		"Min-SE":          "10000",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)
	if se := p.LastResponseHeader("INVITE", 200, "Session-Expires"); se != "10000;refresher=uas" {
		t.Fatalf("200 Session-Expires=%q want 10000;refresher=uas", se)
	}
	if v, ok := ua.SessionTimerView(inc.DialogID); !ok || v.IntervalS != 10000 {
		t.Fatalf("SessionTimerView = %+v, %v; want IntervalS 10000", v, ok)
	}
}

// TestRFC4028_NEWC14_RefreshAnswerDoesNotRaiseTheRequestsInterval (NEW-C-14,
// CF-126; inverted from its Pin): RFC 4028 9: "The UAS MUST NOT increase the value
// of the Session-Expires header field." (rfc4028.txt:850-851). Evidence:
// evidence/rpr-peer/excerpt.txt frames 6-9 (an UPDATE asking 90 answered 120). The
// 200 to a refresh now carries the interval negotiated for THAT refresh: 90 here,
// on UA-5's settings (120/90). The Min-SE half is TestRefreshAnswerHonoursTheRequestsMinSE.
func TestRFC4028_NEWC14_RefreshAnswerDoesNotRaiseTheRequestsInterval(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 120, 90)
	events := collect(t, ua)
	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Supported":       "timer",
		"Session-Expires": "120;refresher=uac",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)
	p.SendUPDATE(t, "90;refresher=uac")
	waitForCond(t, func() bool { return p.LastResponseHeader("UPDATE", 200, "Session-Expires") != "" })
	se := p.LastResponseHeader("UPDATE", 200, "Session-Expires")
	interval, err := strconv.Atoi(strings.TrimSpace(strings.SplitN(se, ";", 2)[0]))
	if err != nil {
		t.Fatalf("200 to the UPDATE Session-Expires=%q has no interval", se)
	}
	if interval != 90 {
		t.Fatalf("200 to an UPDATE asking 90 says %q, want an interval of 90 (never above the request's)", se)
	}
}

// TestRFC4028_NEWC15_RefreshAnswerFollowsTheRequestsRefresher (NEW-C-15, CF-127;
// inverted from its Pin): RFC 4028 9 Table 2 (rfc4028.txt:873-881): a request that
// lists timer and names `refresher=uas` gets `uas` in the 2xx -- "the UAS cannot
// override the UAC's choice of refresher" (rfc4028.txt:889-890) -- plus Require:
// timer, a SHOULD when it lists Supported: timer. Evidence:
// evidence/rpr-role/excerpt.txt frames 4-5 (answered uac).
func TestRFC4028_NEWC15_RefreshAnswerFollowsTheRequestsRefresher(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: "90;refresher=uac"},
	})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 90, 90)
	events := collect(t, ua)
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	p.SendToCaller(t, sip.UPDATE, []sip.Header{
		sip.NewHeader("Supported", "timer"),
		sip.NewHeader("Session-Expires", "90;refresher=uas"),
	}, nil)
	waitForCond(t, func() bool { return p.LastResponseHeader("UPDATE", 200, "Session-Expires") != "" })
	if se := p.LastResponseHeader("UPDATE", 200, "Session-Expires"); se != "90;refresher=uas" {
		t.Fatalf("200 to an UPDATE naming uas says %q, want 90;refresher=uas", se)
	}
	if got := p.LastResponseHeader("UPDATE", 200, "Require"); !strings.Contains(got, "timer") {
		t.Fatalf("200 Require=%q, want timer (Supported: timer was listed)", got)
	}
}

// TestRFC4028_NEWC17_RefreshTimerIsRebasedOnOurRefreshAnswer (NEW-C-17, CF-129;
// inverted from its Pin, cf5-b LB-D4): RFC 4028 9 puts the session expiration at
// "the time of transmission of the last 2xx response to a session refresh request
// on that dialog plus the session interval" (rfc4028.txt:925-928) and recommends
// the refresh at half of it (rfc4028.txt:930-931). Our refresher is therefore
// re-armed from our 200 to the peer's UPDATE: INVITE 200 at 0 s, UPDATE answered at
// 15 s, so the next refresh is due at 15+45 = 60 s, not 45 s. The peer's UPDATE
// (peer.SendUPDATE) carries no Supported: timer; the timing does not depend on it.
func TestRFC4028_NEWC17_RefreshTimerIsRebasedOnOurRefreshAnswer(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 90, 90)
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
	clk.BlockUntil(1)
	clk.Advance(15 * time.Second)
	p.SendUPDATE(t, "90;refresher=uas")
	waitForCond(t, func() bool { return p.LastResponseStatus("UPDATE") == 200 })
	// The replacement timer must be armed before the clock moves again: a waiter
	// count of 1 holds before and after the swap, so poll the view for the new
	// deadline (45 s from our 200 to the UPDATE) instead of BlockUntil alone.
	waitForCond(t, func() bool {
		v, ok := ua.SessionTimerView(inc.DialogID)
		return ok && v.NextRefreshMs > 0 && v.NextRefreshMs <= 45000 && v.NextRefreshMs > 44000
	})
	clk.BlockUntil(1)
	clk.Advance(31 * time.Second) // 46 s after the INVITE's 200, 31 s after our 200 to the UPDATE
	time.Sleep(300 * time.Millisecond)
	if n := p.Count("UPDATE"); n != 0 {
		t.Fatalf("UPDATE count=%d at 46 s, want 0: our refresher kept the old schedule", n)
	}
	clk.Advance(15 * time.Second) // 61 s
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
}
