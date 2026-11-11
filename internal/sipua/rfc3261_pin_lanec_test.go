package sipua_test

// Lane C (rfc-sweep-c) pins for NEW-C findings that cite an earlier lane's RFC
// 3261 row (6a D8, D11). Each passes today and must be inverted when its finding
// is fixed. No test here calls
// t.Parallel (parallel_invariant_test.go). Every timer is the fake clock,
// through newSessionTimerUA (sessiontimer_wire_test.go) against
// internal/testutil/peer, whose DialWithHeaders adds no Supported of its own;
// the foreign-tag and lower-CSeq pins use Lane A's raw UAC
// (rfc3261_pin_uas_test.go), which can send those shapes.

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

// TestRFC3261_NEWC7_SupportedLessInviteNamingUacIsAnsweredAsUAS pins NEW-C-7
// (A-UAS-30, RFC 3261 8.2.2.3: "Of course, the server MUST NOT apply extensions
// not listed in the Supported header field in the request." rfc3261.txt:2711-2713;
// A-UAS-25, rfc3261.txt:2697-2699; A-UAC-164, rfc3261.txt:10487-10490).
// Evidence: evidence/uas-nosup-uac/excerpt.txt frame 1 (INVITE with no
// Supported and Session-Expires: 120;refresher=uac) and frame 4 (our 200:
// Session-Expires: 120;refresher=uac, Require: timer). Locus: inboundRefresherRole
// (sessiontimer.go :412-417) honours refresher=uac from a request that does not
// list timer; requireTimerInAnswer then correctly requires timer for role uac.
//
// PIN OF A DEVIATION: invert this assertion when NEW-C-7 is fixed.
func TestRFC3261_NEWC7_SupportedLessInviteNamingUacIsAnsweredAsUAS(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 120, 90)
	events := collect(t, ua)
	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Session-Expires": "120;refresher=uac",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)
	if got := p.LastResponseHeader("INVITE", 200, "Require"); strings.Contains(strings.ToLower(got), "timer") {
		t.Fatalf("200 Require=%q names timer for a Supported-less INVITE (NEW-C-7, CF-119)", got)
	}
	if got := p.LastResponseHeader("INVITE", 200, "Session-Expires"); got != "120;refresher=uas" {
		t.Fatalf("200 Session-Expires=%q want 120;refresher=uas for a Supported-less INVITE naming uac (NEW-C-7, CF-119)", got)
	}
}

// TestRFC3261_NEWC8_SupportedLessInviteBelowMinSEIsAnswered200 pins NEW-C-8 (A-UAS-25, RFC
// 3261 8.2.2.3: "A UAS that wishes to apply some extension when generating the
// response MUST NOT do so unless support for that extension is indicated in the
// Supported header field in the request." rfc3261.txt:2697-2699; A-UAS-30,
// rfc3261.txt:2711-2713; A-UAS-26, rfc3261.txt:2699-2701; A-UAC-164,
// rfc3261.txt:10487-10490; RFC 4028 9 allows the 422 only to a request whose
// Supported lists timer, rfc4028.txt:828-831). Evidence:
// evidence/uas-nosup-422/excerpt.txt frame 1 (INVITE with no Supported and
// Session-Expires: 100) and frame 4 (our 422 with Min-SE: 120).
//
// PIN OF A DEVIATION: invert this assertion when NEW-C-8 is fixed.
func TestRFC3261_NEWC8_SupportedLessInviteBelowMinSEIsAnswered200(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 120, 120)
	events := collect(t, ua)
	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Session-Expires": "100",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCond(t, func() bool { return p.LastResponseStatus("INVITE") != 0 })
	if got := p.LastResponseStatus("INVITE"); got != 200 {
		t.Fatalf("final response to a Supported-less INVITE is %d, want 200 (NEW-C-8, CF-120)", got)
	}
	if got := p.LastResponseHeader("INVITE", 200, "Session-Expires"); got != "" {
		t.Fatalf("200 Session-Expires=%q want absent", got)
	}
	if got := p.LastResponseHeader("INVITE", 200, "Require"); got != "" {
		t.Fatalf("200 Require=%q want absent", got)
	}
}

// TestRFC3261Pin_NEWC11_RetryAfter491IsAFixedTwoSeconds pins NEW-C-11
// (A-UAC-92, RFC 3261 14.1: "If a UAC receives a 491 response to a re-INVITE,
// it SHOULD start a timer with a value T chosen as follows: 1."
// rfc3261.txt:4879-4882, whose rules, rfc3261.txt:4882-4888, give the owner of
// the Call-ID a random T between 2.1 and 4 s). Evidence:
// evidence/rfr-491/excerpt.txt frame 5 (491 at 45.001513) and frame 7 (the
// retry at 47.003386, 2.001873 s later, on a dialog we dialled). The retry is
// on the wire once the fake clock has advanced exactly 2.0 s, below 2.1 s.
//
// PIN OF A DEVIATION: invert this assertion when NEW-C-11 is fixed.
func TestRFC3261Pin_NEWC11_RetryAfter491IsAFixedTwoSeconds(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			RejectUpdateStatus:   491, // also answers a re-INVITE refresh
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
	clk.Advance(46 * time.Second) // the re-INVITE refresh, answered 491
	waitForCond(t, func() bool { return p.Count("INVITE") >= 2 })
	n := p.Count("INVITE")
	clk.BlockUntil(1) // the refresher's retry timer is armed
	clk.Advance(2 * time.Second)
	waitForCond(t, func() bool { return p.Count("INVITE") > n })
}

// answeredTag brings up one answered inbound dialog through Lane A's raw UAC
// (answered, rfc3261_pin_uas_test.go), ACKs it and returns our To tag.
func answeredTag(t *testing.T, ua *sipua.UA, events func() []session.UAEvent, r *rawUAC, ruri, callID string) string {
	t.Helper()
	ok := answered(t, ua, events, r, ruri, callID, 10)
	to := stubHeaders(ok, "To")
	if len(to) == 0 || tagOf(to[0]) == "" {
		t.Fatal("precondition: the 200 carries no To tag")
	}
	r.send(r.request("ACK", ruri, callID, "z9hG4bKrfcsweepcA"+callID, 10, tagOf(to[0]), "", ""))
	return tagOf(to[0])
}

// TestRFC3261_NEWC18_ByeWithForeignToTagLeavesTheCallUp is NEW-C-18 (A-UAS-84,
// RFC 3261 15.1.2: "A UAS core receiving a BYE request for an existing dialog
// MUST follow the procedures of Section 12.2.2 to process the request."
// rfc3261.txt:5064-5065; 12.2.2 matches a request to a dialog by Call-ID and
// both tags). A BYE with the dialog's Call-ID but a foreign To tag is answered
// 481 and the call stays up; a correctly tagged BYE afterwards ends it (CF-130).
func TestRFC3261_NEWC18_ByeWithForeignToTagLeavesTheCallUp(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "rfcsweepc-tags@127.0.0.1"
	tag := answeredTag(t, ua, events, r, ruri, cid)
	ended := func() bool {
		for _, e := range events() {
			if e.Kind == session.UAEventDialogEnded {
				return true
			}
		}
		return false
	}
	r.send(r.request("BYE", ruri, cid, "z9hG4bKrfcsweepcBF", 11, "rfcsweep-c-foreign", "", ""))
	if !stubWait(func() bool { return r.hasCode("BYE", 481) }, 2*time.Second) {
		codes, _ := r.responses("BYE")
		t.Fatalf("the foreign-To-tag BYE was answered %v, want 481", codes)
	}
	if stubWaitFixed(ended, 2*time.Second) {
		t.Fatal("a BYE whose To tag matches no dialog of ours ended the call")
	}
	r.send(r.request("BYE", ruri, cid, "z9hG4bKrfcsweepcBG", 12, tag, "", ""))
	if !stubWait(ended, 2*time.Second) {
		t.Fatal("a correctly tagged BYE did not end the call")
	}
}

// TestRFC3261_ReobsCF101_UpdateLowerCSeqDraws500 is CF-101 in onUpdate, fixed
// (rfc3261.txt:4269-4272). Was the RFC3261 pin ReobsCF101_UpdateLowerCSeqIsNotRejected.
func TestRFC3261_ReobsCF101_UpdateLowerCSeqDraws500(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "rfcsweepc-cseq-u@127.0.0.1"
	tag := answeredTag(t, ua, events, r, ruri, cid)
	r.send(r.request("UPDATE", ruri, cid, "z9hG4bKrfcsweepcU5", 5, tag, "", ""))
	if !stubWait(func() bool { codes, _ := r.responses("UPDATE"); return len(codes) > 0 }, 2*time.Second) {
		t.Fatal("precondition: no response to the lower-CSeq UPDATE")
	}
	if !r.hasCode("UPDATE", 500) {
		codes, _ := r.responses("UPDATE")
		t.Fatalf("the lower-CSeq UPDATE is answered %v, want 500", codes)
	}
}

// TestRFC3261_ReobsCF101_ReInviteLowerCSeqDraws500 is CF-101 in onInvite's
// re-INVITE branch, fixed (rfc3261.txt:4269-4272). Was
// the old RFC3261 pin ReobsCF101_ReInviteLowerCSeqIsNotRejected.
func TestRFC3261_ReobsCF101_ReInviteLowerCSeqDraws500(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "rfcsweepc-cseq-i@127.0.0.1"
	tag := answeredTag(t, ua, events, r, ruri, cid)
	r.send(r.request("INVITE", ruri, cid, "z9hG4bKrfcsweepcI5", 5, tag, "", stubSDP))
	final := func() int { // the final response to the CSeq 5 re-INVITE, 0 until one arrives
		codes, msgs := r.responses("INVITE")
		for i, m := range msgs {
			if cs := stubHeaders(m, "CSeq"); len(cs) > 0 && cs[0] == "5 INVITE" && codes[i] >= 200 {
				return codes[i]
			}
		}
		return 0
	}
	if !stubWait(func() bool { return final() != 0 }, 2*time.Second) {
		t.Fatal("precondition: no final response to the lower-CSeq re-INVITE")
	}
	if got := final(); got != 500 {
		t.Fatalf("the lower-CSeq re-INVITE is answered %d, want 500", got)
	}
}
