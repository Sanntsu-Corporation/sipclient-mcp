package sipua_test

// Lane D (cf5-d) Task 3: in-dialog matching on both tags (CF-176) and 491
// while our own offer is outstanding (CF-124, CF-166). No test calls
// t.Parallel.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// glareDial dials a swallowing (or, with swallow false, answering) peer on a
// UA whose session refresh is a re-INVITE, then fires the first refresh so our
// re-INVITE is in flight. It returns the peer and the UA's event collector.
func glareDial(t *testing.T, swallow bool, rejectStatus int) (*peer.Peer, func() []session.UAEvent, *fakeclock.Clock) {
	t.Helper()
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			SwallowUpdate:        swallow, // also swallows a re-INVITE refresh
			RejectUpdateStatus:   rejectStatus,
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newSessionTimerUAWithMethod(t, clk, 90, 90, "invite")
	events := collect(t, ua)
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // our re-INVITE refresh
	waitForCond(t, func() bool { return p.Count("INVITE") >= 2 })
	return p, events, clk
}

// RFC 3261 14.2: an INVITE received while an INVITE we sent on the dialog is in
// progress is 491.
func TestRFC3261_NEWC12_ReInviteDuringOurReInviteGets491(t *testing.T) {
	p, _, _ := glareDial(t, true, 0)
	p.SendReInviteToCaller(t)
	waitForCond(t, func() bool { return p.LastResponseStatus("INVITE") != 0 })
	if got := p.LastResponseStatus("INVITE"); got != 491 {
		t.Fatalf("a re-INVITE received while ours is in progress got %d, want 491 (RFC 3261 14.2)", got)
	}
}

// RFC 3311 5.2: an UPDATE with an offer while our offer is unanswered is 491.
func TestRFC3311_NEWD35_UpdateOfferDuringOurReInviteGets491(t *testing.T) {
	p, _, _ := glareDial(t, true, 0)
	p.SendToCaller(t, sip.UPDATE, laneDSDPHeader(), []byte(laneDUpdateOffer))
	waitForCond(t, func() bool { return p.LastResponseStatus("UPDATE") != 0 })
	if got := p.LastResponseStatus("UPDATE"); got != 491 {
		t.Fatalf("an UPDATE offer received while our re-INVITE is in progress got %d, want 491 (RFC 3311 5.2)", got)
	}
}

func TestUpdateWithoutOfferDuringOurReInviteGets200(t *testing.T) {
	p, _, _ := glareDial(t, true, 0)
	p.SendToCaller(t, sip.UPDATE, nil, nil)
	waitForCond(t, func() bool { return p.LastResponseStatus("UPDATE") != 0 })
	if got := p.LastResponseStatus("UPDATE"); got != 200 {
		t.Fatalf("a session-refresh UPDATE without an offer got %d, want 200", got)
	}
	if se := p.LastResponseHeader("UPDATE", 200, "Session-Expires"); se == "" {
		t.Error("the 200 carries no Session-Expires")
	}
}

func TestReInviteAfterOurReInviteCompletedGets200(t *testing.T) {
	p, _, _ := glareDial(t, false, 0)
	waitForCond(t, func() bool { return p.Count("ACK") >= 2 })
	p.SendReInviteToCaller(t)
	waitForCond(t, func() bool { return p.LastResponseStatus("INVITE") != 0 })
	if got := p.LastResponseStatus("INVITE"); got != 200 {
		t.Fatalf("a re-INVITE after our refresh completed got %d, want 200", got)
	}
}

// Our offer rides the 200 of an offerless INVITE and awaits the ACK's answer:
// an UPDATE offer meanwhile is glare, afterwards it is not.
func TestUpdateOfferWhileOurOfferAwaitsTheAckGets491(t *testing.T) {
	c := startOfferless(t, "glare")
	c.answer(t)
	upd := func(cseq int, br string) string {
		return c.r.request("UPDATE", c.ruri, c.cid, br, cseq, c.toTag(), "", laneDUpdateOffer)
	}
	c.r.send(upd(2, "z9hG4bKcf5dGU1"))
	if !stubWait(func() bool { return c.r.hasCode("UPDATE", 491) }, 3*time.Second) {
		codes, _ := c.r.responses("UPDATE")
		t.Fatalf("UPDATE offer before the ACK answered %v, want 491", codes)
	}
	c.goodAck(40010)
	time.Sleep(100 * time.Millisecond)
	c.r.send(upd(3, "z9hG4bKcf5dGU2"))
	if !stubWait(func() bool { return c.r.hasCode("UPDATE", 200) }, 3*time.Second) {
		codes, _ := c.r.responses("UPDATE")
		t.Fatalf("UPDATE offer after the ACK answered %v, want 200", codes)
	}
}

func TestReInviteWithForeignFromTagIs481(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "cf5d-foreign@127.0.0.1"
	tag := answeredTag(t, ua, events, r, ruri, cid)
	msg := r.request("INVITE", ruri, cid, "z9hG4bKcf5dFR", 11, tag, "", stubSDP)
	msg = strings.Replace(msg, "tag=rfcsweepa", "tag=intruder", 1)
	r.send(msg)
	if !stubWait(func() bool { return r.hasCode("INVITE", 481) }, 3*time.Second) {
		codes, _ := r.responses("INVITE")
		t.Fatalf("re-INVITE with a foreign From tag answered %v, want 481", codes)
	}
	for _, e := range events() {
		if e.Kind == session.UAEventSessionRefresh {
			t.Error("the foreign re-INVITE counted as a session refresh")
		}
	}
	// still answered: a correctly tagged INFO draws 200
	r.send(r.request("INFO", ruri, cid, "z9hG4bKcf5dFRi", 12, tag, "", ""))
	if !stubWait(func() bool { return r.hasCode("INFO", 200) }, 3*time.Second) {
		t.Fatal("the call did not stay answered")
	}
}

// TestReinviteInFlightIsClearedOnEveryExit: a stuck flag would draw 491 for a
// peer re-INVITE after our refresh finished.
func TestReinviteInFlightIsClearedOnEveryExit(t *testing.T) {
	retry := func(t *testing.T, p *peer.Peer) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for {
			p.SendReInviteToCaller(t)
			waitForCond(t, func() bool { return p.LastResponseStatus("INVITE") != 0 })
			got := p.LastResponseStatus("INVITE")
			if got == 200 {
				return
			}
			if time.Now().After(deadline) || got != 491 {
				t.Fatalf("peer re-INVITE after our refresh drew %d, want 200", got)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	t.Run("answered 200", func(t *testing.T) {
		p, _, _ := glareDial(t, false, 0)
		waitForCond(t, func() bool { return p.Count("ACK") >= 2 })
		retry(t, p)
	})
	t.Run("rejected 488", func(t *testing.T) {
		p, events, _ := glareDial(t, false, 488)
		waitFor(t, events, session.UAEventMediaError, 0) // the refresh failure, after the clear
		retry(t, p)
	})
}
