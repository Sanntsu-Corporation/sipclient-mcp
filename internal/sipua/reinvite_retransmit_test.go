package sipua_test

// CF-208 (Lane B Task 6): the 2xx to a peer's re-INVITE is retransmitted until
// its ACK (RFC 3261 13.3.1.4, 14.2), and a missing ACK ends the call after 64*T1.
// T1 is shortened through SetAck2xxT1. No test calls t.Parallel.

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
)

// reinviteRig is an answered, ACKed inbound dialog on a raw caller.
type reinviteRig struct {
	ua     *sipua.UA
	events func() []session.UAEvent
	r      *rawUAC
	ruri   string
	cid    string
	tag    string
}

func newReinviteRig(t *testing.T, cid string) *reinviteRig {
	t.Helper()
	t.Cleanup(sipua.SetAck2xxT1(20 * time.Millisecond))
	ua, events, r, ruri := uasUA(t)
	answerBye(t, r)
	tag := answeredTag(t, ua, events, r, ruri, cid)
	return &reinviteRig{ua: ua, events: events, r: r, ruri: ruri, cid: cid, tag: tag}
}

// reinvite sends a re-INVITE with the dialog's own SDP (an unchanged re-offer).
func (g *reinviteRig) reinvite(cseq int, branch string) {
	g.r.send(g.r.request("INVITE", g.ruri, g.cid, branch, cseq, g.tag, "", stubSDP))
}

func (g *reinviteRig) ack(cseq int, branch string) {
	g.r.send(g.r.request("ACK", g.ruri, g.cid, branch, cseq, g.tag, "", ""))
}

// twoxxCopies counts the 200s the caller received for the INVITE with this CSeq.
func twoxxCopies(r *rawUAC, cseq int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, m := range r.got {
		if strings.HasPrefix(m, "SIP/2.0 200") {
			if cs := stubHeaders(m, "CSeq"); len(cs) > 0 && cs[0] == strconv.Itoa(cseq)+" INVITE" {
				n++
			}
		}
	}
	return n
}

func (g *reinviteRig) byes() int {
	g.r.mu.Lock()
	defer g.r.mu.Unlock()
	n := 0
	for _, m := range g.r.got {
		if stubMethod(m) == "BYE" {
			n++
		}
	}
	return n
}

func (g *reinviteRig) ended() bool {
	for _, e := range g.events() {
		if e.Kind == session.UAEventDialogEnded {
			return true
		}
	}
	return false
}

func TestRFC3261_CF208_ReInviteTwoxxIsRetransmittedUntilAck(t *testing.T) {
	g := newReinviteRig(t, "cf208-retx@127.0.0.1")
	g.reinvite(11, "z9hG4bKcf208A")
	if !stubWait(func() bool { return twoxxCopies(g.r, 11) >= 4 }, 2*time.Second) {
		t.Fatalf("%d copies of the re-INVITE's 200, want the original and at least 3 retransmissions", twoxxCopies(g.r, 11))
	}
	g.ack(11, "z9hG4bKcf208AACK")
	time.Sleep(60 * time.Millisecond) // a tick already in flight
	n := twoxxCopies(g.r, 11)
	time.Sleep(300 * time.Millisecond)
	if got := twoxxCopies(g.r, 11); got != n {
		t.Errorf("%d further copies of the 200 after the ACK", got-n)
	}
	if g.byes() != 0 || g.ended() {
		t.Error("the call ended although the re-INVITE was ACKed")
	}
}

func TestReInviteNoAckEndsTheCallAfter64T1(t *testing.T) {
	g := newReinviteRig(t, "cf208-noack@127.0.0.1")
	g.reinvite(11, "z9hG4bKcf208N")
	if !stubWait(func() bool { return g.byes() > 0 }, 4*time.Second) {
		t.Fatal("no BYE from us although the re-INVITE's 2xx was never ACKed")
	}
	if !stubWait(g.ended, 2*time.Second) {
		t.Fatal("no dialog_ended event")
	}
	for _, e := range g.events() {
		if e.Kind == session.UAEventDialogEnded {
			if e.Cause != session.UACauseTransportFailure || e.Detail["cause"] != "no_ack" {
				t.Errorf("dialog_ended cause %q detail %v, want transport_failure / no_ack", e.Cause, e.Detail)
			}
		}
	}
}

func TestReInviteTwoxxRetransmittedOnAnOutboundDialog(t *testing.T) {
	t.Cleanup(sipua.SetAck2xxT1(20 * time.Millisecond))
	s := startUACStub(t, answer200())
	ua := newStubUA(t)
	dialStub(t, ua, s)
	inv := s.requests("INVITE")[0]
	re := "INVITE sip:alice@" + ua.BoundAddr().String() + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + s.addr() + ";branch=z9hG4bKcf208O\r\n" +
		"From: <sip:bob@" + s.addr() + ">;tag=stubtag\r\n" +
		"To: " + stubHeaders(inv, "From")[0] + "\r\n" +
		"Call-ID: " + stubHeaders(inv, "Call-ID")[0] + "\r\n" +
		"CSeq: 7 INVITE\r\nMax-Forwards: 70\r\nContact: <sip:stub@" + s.addr() + ">\r\n" +
		"Content-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(len(stubSDP)) + "\r\n\r\n" + stubSDP
	dst, _ := net.ResolveUDPAddr("udp", ua.BoundAddr().String())
	s.send(dst, re)
	copies := func() int {
		s.mu.Lock()
		defer s.mu.Unlock()
		n := 0
		for _, m := range s.got {
			if strings.HasPrefix(m, "SIP/2.0 200") && strings.Contains(m, "CSeq: 7 INVITE") {
				n++
			}
		}
		return n
	}
	if !stubWait(func() bool { return copies() >= 3 }, 2*time.Second) {
		t.Fatalf("%d copies of our 200, want the original and retransmissions", copies())
	}
	ack := "ACK sip:alice@" + ua.BoundAddr().String() + " SIP/2.0\r\nVia: SIP/2.0/UDP " + s.addr() + ";branch=z9hG4bKcf208OA\r\n" +
		"From: <sip:bob@" + s.addr() + ">;tag=stubtag\r\nTo: " + stubHeaders(inv, "From")[0] + "\r\n" +
		"Call-ID: " + stubHeaders(inv, "Call-ID")[0] + "\r\nCSeq: 7 ACK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
	s.send(dst, ack)
	time.Sleep(80 * time.Millisecond)
	n := copies()
	time.Sleep(300 * time.Millisecond)
	if got := copies(); got != n {
		t.Errorf("%d copies of our 200 after the ACK", got-n)
	}
}

func TestSameBranchReInviteAckStopsTheRetransmission(t *testing.T) {
	g := newReinviteRig(t, "cf208-sameb@127.0.0.1")
	g.reinvite(11, "z9hG4bKcf208S")
	if !stubWait(func() bool { return twoxxCopies(g.r, 11) >= 2 }, 2*time.Second) {
		t.Fatal("no retransmission")
	}
	g.ack(11, "z9hG4bKcf208S") // RFC 2543 style: the ACK reuses the re-INVITE's branch
	time.Sleep(80 * time.Millisecond)
	n := twoxxCopies(g.r, 11)
	time.Sleep(300 * time.Millisecond)
	if got := twoxxCopies(g.r, 11); got != n {
		t.Errorf("%d further copies after a same-branch ACK", got-n)
	}
}

func TestAckOfAnOlderReInviteDoesNotStopTheNewerRetransmission(t *testing.T) {
	g := newReinviteRig(t, "cf208-older@127.0.0.1")
	g.reinvite(11, "z9hG4bKcf208O7")
	if !stubWait(func() bool { return twoxxCopies(g.r, 11) >= 1 }, 2*time.Second) {
		t.Fatal("no 200 to re-INVITE 11")
	}
	g.reinvite(12, "z9hG4bKcf208O8")
	if !stubWait(func() bool { return twoxxCopies(g.r, 12) >= 1 }, 2*time.Second) {
		t.Fatal("no 200 to re-INVITE 12")
	}
	g.ack(11, "z9hG4bKcf208O7A")
	n := twoxxCopies(g.r, 12)
	if !stubWait(func() bool { return twoxxCopies(g.r, 12) >= n+2 }, 2*time.Second) {
		t.Fatal("the ACK of re-INVITE 11 stopped the retransmission of 12's 200")
	}
	g.ack(12, "z9hG4bKcf208O8A")
	time.Sleep(80 * time.Millisecond)
	n = twoxxCopies(g.r, 12)
	time.Sleep(300 * time.Millisecond)
	if got := twoxxCopies(g.r, 12); got != n {
		t.Errorf("%d further copies after 12's ACK", got-n)
	}
}

// Guard of B-D10: a later in-order re-INVITE supersedes an un-ACKed 2xx, so the
// earlier loop ends quietly at its deadline (no BYE).
func TestLaterReInviteSupersedesAnUnackedTwoxx(t *testing.T) {
	g := newReinviteRig(t, "cf208-super@127.0.0.1")
	g.reinvite(11, "z9hG4bKcf208P7")
	if !stubWait(func() bool { return twoxxCopies(g.r, 11) >= 1 }, 2*time.Second) {
		t.Fatal("no 200 to re-INVITE 11")
	}
	g.reinvite(12, "z9hG4bKcf208P8")
	if !stubWait(func() bool { return twoxxCopies(g.r, 12) >= 1 }, 2*time.Second) {
		t.Fatal("no 200 to re-INVITE 12")
	}
	g.ack(12, "z9hG4bKcf208P8A")
	time.Sleep(1800 * time.Millisecond) // past 11's 64*T1 deadline (1.28 s)
	if g.byes() != 0 || g.ended() {
		t.Fatal("the superseded re-INVITE's deadline ended the call")
	}
}

// Guard of B-D11: the peer-offer claim is released when the final is written, not
// when the ACK arrives.
func TestReInviteAwaitingAckDoesNotHoldThePeerOfferClaim(t *testing.T) {
	g := newReinviteRig(t, "cf208-claim@127.0.0.1")
	g.reinvite(11, "z9hG4bKcf208C")
	if !stubWait(func() bool { return twoxxCopies(g.r, 11) >= 1 }, 2*time.Second) {
		t.Fatal("no 200 to the re-INVITE")
	}
	// An offer-carrying UPDATE meanwhile: 200, not 500. A 500 is legal in the
	// instant before the handler's deferred release runs, so retry with new CSeqs.
	for i := 0; i < 5; i++ {
		cseq := 12 + i
		g.r.send(g.r.request("UPDATE", g.ruri, g.cid, "z9hG4bKcf208CU"+strconv.Itoa(i), cseq, g.tag, "", stubSDP))
		if stubWait(func() bool { c, _ := g.r.responses("UPDATE"); return len(c) > i }, time.Second) {
			codes, _ := g.r.responses("UPDATE")
			if codes[len(codes)-1] == 200 {
				return
			}
			if codes[len(codes)-1] != 500 {
				t.Fatalf("UPDATE answered %v", codes)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the peer-offer claim stayed held while the re-INVITE awaited its ACK")
}

// Guard of P8: the loop ends with the dialog.
func TestReInviteRetransmissionStopsWhenTheDialogEnds(t *testing.T) {
	g := newReinviteRig(t, "cf208-end@127.0.0.1")
	g.reinvite(11, "z9hG4bKcf208E")
	if !stubWait(func() bool { return twoxxCopies(g.r, 11) >= 2 }, 2*time.Second) {
		t.Fatal("no retransmission")
	}
	g.r.send(g.r.request("BYE", g.ruri, g.cid, "z9hG4bKcf208EB", 12, g.tag, "", ""))
	if !stubWait(func() bool { return g.r.hasCode("BYE", 200) }, 2*time.Second) {
		t.Fatal("no 200 to the BYE")
	}
	time.Sleep(60 * time.Millisecond)
	n := twoxxCopies(g.r, 11)
	time.Sleep(1500 * time.Millisecond) // past the 64*T1 deadline
	if got := twoxxCopies(g.r, 11); got != n {
		t.Errorf("%d copies of the 200 after the dialog ended", got-n)
	}
	if g.byes() != 0 {
		t.Error("we sent a BYE for a dialog the peer ended")
	}
}

// Guard of B-D11: the session-timer answer lock is released when the 2xx is
// written, so a refresh UPDATE is answered while the re-INVITE awaits its ACK.
func TestReInviteAwaitingAckDoesNotHoldTheSessionTimerLock(t *testing.T) {
	t.Cleanup(sipua.SetAck2xxT1(time.Hour)) // no retransmission noise: the ACK is never sent
	ua, events, r, ruri := uasUA(t)
	cid := "cf208-timer@127.0.0.1"
	timer := "Supported: timer\r\nSession-Expires: 600;refresher=uac\r\n"
	r.send(r.invite(ruri, cid, "z9hG4bKcf208TI", 10, timer))
	in := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if !stubWait(func() bool { return r.hasCode("INVITE", 200) }, 3*time.Second) {
		t.Fatal("no 200")
	}
	_, tag := toTagOfResponse(t, r, "INVITE", 200)
	r.send(r.request("ACK", ruri, cid, "z9hG4bKcf208TA", 10, tag, "", ""))
	r.send(r.request("INVITE", ruri, cid, "z9hG4bKcf208TR", 11, tag, timer, stubSDP))
	if !stubWait(func() bool { return twoxxCopies(r, 11) >= 1 }, 2*time.Second) {
		t.Fatal("no 200 to the re-INVITE")
	}
	r.send(r.request("UPDATE", ruri, cid, "z9hG4bKcf208TU", 12, tag, "Session-Expires: 600;refresher=uac\r\n", ""))
	if !stubWait(func() bool { return r.hasCode("UPDATE", 200) }, 200*time.Millisecond) {
		codes, _ := r.responses("UPDATE")
		t.Fatalf("the refresh UPDATE was not answered 200 within 200 ms (answers %v): the session-timer lock is held until the ACK", codes)
	}
}
