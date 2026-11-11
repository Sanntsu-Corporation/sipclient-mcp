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

// answerWithTimerHeaders dials a 120/120 UA with the given INVITE headers and
// answers the call, returning the peer, the UA, the dialog id and Answer's error.
func answerWithTimerHeaders(t *testing.T, clk *fakeclock.Clock, hdr map[string]string) (*peer.Peer, *sipua.UA, string, error) {
	t.Helper()
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, clk, 120, 120)
	events := collect(t, ua)
	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), hdr)
	inc := waitFor(t, events, session.UAEventInbound, 0)
	err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID})
	waitForCond(t, func() bool { return p.LastResponseStatus("INVITE") >= 200 })
	return p, ua, inc.DialogID, err
}

// CF-120: RFC 3261 8.2.4 forbids applying an extension the request never listed
// in Supported; RFC 4028 7.2 reads a 2xx without Session-Expires as no timer.
func TestAnswerToASupportedLessInviteBelowMinSEIs200WithoutATimer(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	p, ua, id, err := answerWithTimerHeaders(t, clk, map[string]string{"Session-Expires": "100"})
	if err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if got := p.LastResponseStatus("INVITE"); got != 200 {
		t.Fatalf("final response %d want 200", got)
	}
	if got := p.LastResponseHeader("INVITE", 200, "Session-Expires"); got != "" {
		t.Fatalf("200 Session-Expires=%q want absent", got)
	}
	if got := p.LastResponseHeader("INVITE", 200, "Require"); got != "" {
		t.Fatalf("200 Require=%q want absent", got)
	}
	if _, ok := ua.SessionTimerView(id); ok {
		t.Fatal("a Supported-less below-minimum request must leave no timer on the dialog")
	}
	clk.Advance(150 * time.Second) // 1.5 x the requested interval
	time.Sleep(150 * time.Millisecond)
	for _, m := range []string{"INVITE", "UPDATE", "BYE"} {
		if n := p.Count(m); n != 0 {
			t.Fatalf("%d %s sent with no session timer armed", n, m)
		}
	}
}

// Require: timer indicates support, so the 422 stays.
func TestAnswerToARequireOnlyInviteBelowMinSEIs422(t *testing.T) {
	p, _, _, err := answerWithTimerHeaders(t, fakeclock.New(time.Unix(0, 0)), map[string]string{
		"Require":         "timer",
		"Session-Expires": "100",
	})
	if err == nil {
		t.Fatal("a Require: timer request below min_se_s must be refused")
	}
	if got := p.LastResponseStatus("INVITE"); got != 422 {
		t.Fatalf("final response %d want 422", got)
	}
	if got := p.LastResponseHeader("INVITE", 422, "Min-SE"); got != "120" {
		t.Fatalf("422 Min-SE=%q want 120", got)
	}
}

// CF-119: refresher=uac from a request without Supported is not honoured.
func TestAnswerToASupportedLessInviteNamingUacClaimsUAS(t *testing.T) {
	p, _, _, err := answerWithTimerHeaders(t, fakeclock.New(time.Unix(0, 0)), map[string]string{
		"Session-Expires": "120;refresher=uac",
	})
	if err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if got := p.LastResponseHeader("INVITE", 200, "Session-Expires"); got != "120;refresher=uas" {
		t.Fatalf("200 Session-Expires=%q want 120;refresher=uas", got)
	}
	if got := p.LastResponseHeader("INVITE", 200, "Require"); strings.Contains(strings.ToLower(got), "timer") {
		t.Fatalf("200 Require=%q must not name timer", got)
	}
}
