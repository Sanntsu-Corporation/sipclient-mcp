package sipua_test

// cf5-b Task 4: the 2xx to a peer's session refresh (CF-126, CF-127, CF-121 record).
// RFC 4028 9 applied to a refresh: interval = negotiatedInterval of the request,
// role = Table 2, both written to the dialog, then the matching timer re-armed.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

var timerSupported = sip.NewHeader("Supported", "timer")

// answerPeerDial has the peer dial a UA (ses/minSE) with the given headers, answers
// it, and waits for the 200. It returns the UA and the dialog id.
func answerPeerDial(t *testing.T, p *peer.Peer, clk *fakeclock.Clock, ses, minSE int, hdrs map[string]string) (*sipua.UA, string) {
	t.Helper()
	ua, _ := newSessionTimerUA(t, clk, ses, minSE)
	events := collect(t, ua)
	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), hdrs)
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)
	clk.BlockUntil(1)
	return ua, inc.DialogID
}

// dialPeer dials the peer from a new UA (ses/minSE) and waits for the 200.
func dialPeer(t *testing.T, p *peer.Peer, clk *fakeclock.Clock, ses, minSE int) (*sipua.UA, string) {
	t.Helper()
	ua, _ := newSessionTimerUA(t, clk, ses, minSE)
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	clk.BlockUntil(1)
	return ua, res.DialogID
}

// viewAt waits until the dialog's timer is armed with its next deadline in
// (loMs, hiMs] and the given dialog-oriented refresher: the waiter count is 1
// before and after a swap, so BlockUntil(1) alone does not prove a re-arm.
func viewAt(t *testing.T, ua *sipua.UA, id, refresher string, loMs, hiMs int64) {
	t.Helper()
	waitForCond(t, func() bool {
		v, ok := ua.SessionTimerView(id)
		return ok && v.Armed && v.Refresher == refresher && v.NextRefreshMs > loMs && v.NextRefreshMs <= hiMs
	})
}

// updateResponses counts the responses the peer has received for its own requests.
func updateResponses(p *peer.Peer) int { return len(p.ResponseCodes()) }

func TestRefreshAnswerHonoursTheRequestsMinSE(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	answerPeerDial(t, p, clk, 120, 90, map[string]string{
		"Supported": "timer", "Session-Expires": "120;refresher=uac",
		"Allow": "INVITE, ACK, BYE, CANCEL, UPDATE",
	})
	p.SendUPDATE(t, "150;refresher=uac", timerSupported, sip.NewHeader("Min-SE", "150"))
	waitForCond(t, func() bool { return p.LastResponseHeader("UPDATE", 200, "Session-Expires") != "" })
	if se := p.LastResponseHeader("UPDATE", 200, "Session-Expires"); se != "150;refresher=uac" {
		t.Fatalf("200 Session-Expires=%q want 150;refresher=uac", se)
	}
	if got := p.LastResponseHeader("UPDATE", 200, "Require"); !strings.Contains(got, "timer") {
		t.Fatalf("200 Require=%q want timer (refresher=uac)", got)
	}
}

// Table 2 "N, none": a refresh that lists no timer leaves the choice to us, and we
// choose to refresh (R-GLARE's input on a dialog we answered).
func TestRefreshAnswerWithoutSupportedTimerMakesUsTheRefresher(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, id := answerPeerDial(t, p, clk, 90, 90, map[string]string{
		"Supported": "timer", "Session-Expires": "90;refresher=uac",
		"Allow": "INVITE, ACK, BYE, CANCEL, UPDATE",
	})
	p.SendUPDATE(t, "90")
	waitForCond(t, func() bool { return p.LastResponseHeader("UPDATE", 200, "Session-Expires") != "" })
	if se := p.LastResponseHeader("UPDATE", 200, "Session-Expires"); se != "90;refresher=uas" {
		t.Fatalf("200 Session-Expires=%q want 90;refresher=uas", se)
	}
	if got := p.LastResponseHeader("UPDATE", 200, "Require"); got != "" {
		t.Fatalf("200 Require=%q want none (the peer never listed timer)", got)
	}
	viewAt(t, ua, id, "uas", 44_000, 45_000)
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
}

func TestPeerRefreshNamingItselfHandsRefreshingToThePeer(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, id := dialPeer(t, p, clk, 90, 90)
	clk.Advance(10 * time.Second)
	p.SendUPDATEToCaller(t, "90;refresher=uac", timerSupported)
	waitForCond(t, func() bool { return p.LastResponseHeader("UPDATE", 200, "Session-Expires") != "" })
	if se := p.LastResponseHeader("UPDATE", 200, "Session-Expires"); se != "90;refresher=uac" {
		t.Fatalf("200 Session-Expires=%q want 90;refresher=uac", se)
	}
	if got := p.LastResponseHeader("UPDATE", 200, "Require"); !strings.Contains(got, "timer") {
		t.Fatalf("200 Require=%q want timer", got)
	}
	viewAt(t, ua, id, "uas", 89_000, 90_000)
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	time.Sleep(300 * time.Millisecond)
	if n := p.Count("UPDATE"); n != 0 {
		t.Fatalf("UPDATE count=%d, want 0: we kept refreshing after the peer took the role", n)
	}
	clk.Advance(45 * time.Second) // 101 s: the peer never refreshed
	waitForCond(t, func() bool { return p.ByeCount() >= 1 })
}

func TestPeerRefreshRebasesTheWatchdogInterval(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "1800;refresher=uas",
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, id := dialPeer(t, p, clk, 1800, 90)
	p.SendUPDATEToCaller(t, "100;refresher=uac", timerSupported)
	waitForCond(t, func() bool { return p.LastResponseHeader("UPDATE", 200, "Session-Expires") != "" })
	if se := p.LastResponseHeader("UPDATE", 200, "Session-Expires"); se != "100;refresher=uac" {
		t.Fatalf("200 Session-Expires=%q want 100;refresher=uac", se)
	}
	viewAt(t, ua, id, "uas", 99_000, 100_000)
	clk.BlockUntil(1)
	clk.Advance(101 * time.Second)
	waitForCond(t, func() bool { return p.ByeCount() >= 1 })
}

func TestPeerRefreshMinSEIsCarriedInOurNextRefresh(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, id := answerPeerDial(t, p, clk, 90, 90, map[string]string{
		"Supported": "timer", "Session-Expires": "90",
		"Allow": "INVITE, ACK, BYE, CANCEL, UPDATE",
	})
	p.SendUPDATE(t, "150;refresher=uas", timerSupported, sip.NewHeader("Min-SE", "150"))
	waitForCond(t, func() bool { return p.LastResponseHeader("UPDATE", 200, "Session-Expires") != "" })
	if se := p.LastResponseHeader("UPDATE", 200, "Session-Expires"); se != "150;refresher=uas" {
		t.Fatalf("200 Session-Expires=%q want 150;refresher=uas", se)
	}
	viewAt(t, ua, id, "uas", 74_000, 75_000) // the re-armed refresher, not the old 45 s one
	clk.BlockUntil(1)
	clk.Advance(76 * time.Second) // half of 150, from the re-arm at 0 s
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
	if got := p.LastRequestHeader("UPDATE", "Session-Expires"); got != "150;refresher=uac" {
		t.Fatalf("our refresh Session-Expires=%q want 150;refresher=uac", got)
	}
	if got := p.LastRequestHeader("UPDATE", "Min-SE"); got != "150" {
		t.Fatalf("our refresh Min-SE=%q want 150", got)
	}
}

func TestPeerRefreshWithMinSEAboveTheCeilingDraws400(t *testing.T) {
	for _, tc := range []struct {
		name string
		send func(t *testing.T, p *peer.Peer)
		code func(p *peer.Peer) int
	}{
		{"UPDATE",
			func(t *testing.T, p *peer.Peer) {
				p.SendUPDATEToCaller(t, "86401", timerSupported, sip.NewHeader("Min-SE", "86401"))
			},
			func(p *peer.Peer) int { return p.LastResponseStatus("UPDATE") }},
		{"re-INVITE",
			func(t *testing.T, p *peer.Peer) {
				p.SendReInviteToCaller(t, timerSupported, sip.NewHeader("Session-Expires", "86401"), sip.NewHeader("Min-SE", "86401"))
			},
			func(p *peer.Peer) int { return p.LastResponseStatus("INVITE") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := peer.Start(t, peer.Config{
				Addr: "127.0.0.1:0",
				Behaviour: peer.Behaviour{
					AnswerSessionExpires: "90;refresher=uac",
					AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
				},
			})
			clk := fakeclock.New(time.Unix(0, 0))
			ua, id := dialPeer(t, p, clk, 90, 90)
			tc.send(t, p)
			waitForCond(t, func() bool { return tc.code(p) != 0 })
			if got := tc.code(p); got != 400 {
				t.Fatalf("response %d, want 400", got)
			}
			if v, ok := ua.SessionTimerView(id); !ok || v.IntervalS != 90 {
				t.Fatalf("view=%+v ok=%v, want IntervalS 90 (a refused refresh commits nothing)", v, ok)
			}
		})
	}
}

func lowIntervalDialog(t *testing.T) (*peer.Peer, *fakeclock.Clock, *sipua.UA, string) {
	t.Helper()
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "1800;refresher=uas",
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, id := dialPeer(t, p, clk, 1800, 120)
	return p, clk, ua, id
}

func TestPeerRefreshBelowOurMinSEDraws422(t *testing.T) {
	p, _, ua, id := lowIntervalDialog(t)
	p.SendUPDATEToCaller(t, "100;refresher=uac", timerSupported)
	waitForCond(t, func() bool { return p.LastResponseStatus("UPDATE") == 422 })
	if got := p.LastResponseHeader("UPDATE", 422, "Min-SE"); got != "120" {
		t.Fatalf("422 Min-SE=%q want 120", got)
	}
	if v, ok := ua.SessionTimerView(id); !ok || v.IntervalS != 1800 {
		t.Fatalf("view=%+v ok=%v, want IntervalS 1800 (a 422 commits nothing)", v, ok)
	}
}

// Table 2/LB-D7: a refresh that lists no timer cannot be sent a 422, and one with
// no Session-Expires of its own is not below anything (M5b).
func TestPeerRefreshBelowOurMinSEWithoutSupportedIsAccepted(t *testing.T) {
	p, _, _, _ := lowIntervalDialog(t)
	p.SendUPDATEToCaller(t, "100")
	waitForCond(t, func() bool { return p.LastResponseStatus("UPDATE") == 200 })
	if se := p.LastResponseHeader("UPDATE", 200, "Session-Expires"); se != "100;refresher=uas" {
		t.Fatalf("200 Session-Expires=%q want 100;refresher=uas", se)
	}
	before := updateResponses(p)
	p.SendUPDATEToCaller(t, "", timerSupported)
	waitForCond(t, func() bool { return updateResponses(p) > before })
	if p.LastResponseStatus("UPDATE") != 200 {
		t.Fatalf("a Session-Expires-less refresh drew %d, want 200 (M5b)", p.LastResponseStatus("UPDATE"))
	}
	if se := p.LastResponseHeader("UPDATE", 200, "Session-Expires"); se != "100;refresher=uas" {
		t.Fatalf("200 Session-Expires=%q want 100;refresher=uas", se)
	}
}

// A refresh we refuse still teaches us its Min-SE (rfc4028.txt:600-603).
func TestARefusedRefreshMinSEIsStillRemembered(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, id := answerPeerDial(t, p, clk, 300, 120, map[string]string{
		"Supported": "timer", "Session-Expires": "300",
		"Allow": "INVITE, ACK, BYE, CANCEL, UPDATE",
	})
	p.SendUPDATE(t, "100;refresher=uas", timerSupported, sip.NewHeader("Min-SE", "200"))
	waitForCond(t, func() bool { return p.LastResponseStatus("UPDATE") == 422 })
	if got := p.LastResponseHeader("UPDATE", 422, "Min-SE"); got != "120" {
		t.Fatalf("422 Min-SE=%q want our 120", got)
	}
	if v, ok := ua.SessionTimerView(id); !ok || v.IntervalS != 300 {
		t.Fatalf("view=%+v ok=%v, want IntervalS 300", v, ok)
	}
	clk.Advance(151 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
	if got := p.LastRequestHeader("UPDATE", "Min-SE"); got != "200" {
		t.Fatalf("our refresh Min-SE=%q want 200 (the refused request's)", got)
	}
	if got := p.LastRequestHeader("UPDATE", "Session-Expires"); got != "300;refresher=uac" {
		t.Fatalf("our refresh Session-Expires=%q want 300;refresher=uac", got)
	}
}

func bigMinSEHeaders() map[string]string {
	return map[string]string{
		"Supported": "timer", "Session-Expires": "10000", "Min-SE": "10000",
		"Allow": "INVITE, ACK, BYE, CANCEL, UPDATE",
	}
}

// M7: a refresh with no Session-Expires keeps the dialog's interval (LB-D6).
func TestARefreshWithoutSessionExpiresKeepsTheDialogsInterval(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, id := answerPeerDial(t, p, fakeclock.New(time.Unix(0, 0)), 90, 90, bigMinSEHeaders())
	p.SendUPDATE(t, "")
	waitForCond(t, func() bool { return p.LastResponseHeader("UPDATE", 200, "Session-Expires") != "" })
	if se := p.LastResponseHeader("UPDATE", 200, "Session-Expires"); se != "10000;refresher=uas" {
		t.Fatalf("200 Session-Expires=%q want 10000;refresher=uas", se)
	}
	if v, ok := ua.SessionTimerView(id); !ok || v.IntervalS != 10000 {
		t.Fatalf("view=%+v ok=%v, want IntervalS 10000", v, ok)
	}
}

// M7b: a refresh's interval is never reduced below the dialog's Min-SE.
func TestARefreshAnswerIsNotReducedBelowTheDialogsMinSE(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	answerPeerDial(t, p, fakeclock.New(time.Unix(0, 0)), 90, 90, bigMinSEHeaders())
	p.SendUPDATE(t, "10000;refresher=uac", timerSupported)
	waitForCond(t, func() bool { return p.LastResponseHeader("UPDATE", 200, "Session-Expires") != "" })
	if se := p.LastResponseHeader("UPDATE", 200, "Session-Expires"); se != "10000;refresher=uac" {
		t.Fatalf("200 Session-Expires=%q want 10000;refresher=uac", se)
	}
}
