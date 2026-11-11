package sipua_test

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// establishInboundAnswered dials p at ua's bound address, answers the
// resulting inbound dialog, and returns everything the D1/D2/D3 family of
// tests needs: the dialog ID (to drive further UA calls like Hangup), the
// peer's own INVITE as actually sent (to read the identity/tag the peer put
// on its own From header — siptest.BuildInvite mints a fresh random tag per
// call via sip.GenerateTagN, so no test can hardcode it), and this UA's tag
// on the 200 OK it sent back (the identity any in-dialog request FROM this
// UA must now carry). events must already be installed via collect(t, ua) —
// this helper does not install its own consumer, since OnEvent replaces
// rather than adds (a second collect() call here would silently steal event
// delivery from a consumer the caller installed for its own later
// assertions, e.g. on dialog_ended after Hangup).
func establishInboundAnswered(t *testing.T, ua *sipua.UA, p *peer.Peer, events func() []session.UAEvent) (dialogID string, invite *sip.Request, ourTag string) {
	t.Helper()
	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	incoming := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err != nil {
		t.Fatalf("establishInboundAnswered: Answer: %v", err)
	}
	waitForCode(t, p, 200)
	return incoming.DialogID, p.LastSentInvite(), p.LastFinalToTag()
}

func waitForCode(t *testing.T, p *peer.Peer, code int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, c := range p.ResponseCodes() {
			if c == code {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("peer never saw a %d; got %v", code, p.ResponseCodes())
}

func TestInboundInviteEmitsOneInboundEvent(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())

	// ONE protocol event, not two. R14's incoming_call-then-ringing ORDERING is
	// session's to produce from this single fact — which is strictly more
	// robust than two upward events that could interleave.
	incoming := waitFor(t, events, session.UAEventInbound, 0)
	if incoming.Direction != session.Inbound {
		t.Errorf("Direction = %q, want %q", incoming.Direction, session.Inbound)
	}
	if incoming.DialogID == "" {
		t.Error("inbound event carries no DialogID; session cannot key a call on it")
	}
	if n := countKind(events(), session.UAEventInbound); n != 1 {
		t.Errorf("one INVITE produced %d inbound events, want exactly 1", n)
	}
	// sipua emits NO provisional event for the 100/180 IT SENDS: those are its
	// own responses, not facts about the far end, and surfacing them would let
	// session double-count a ringing transition.
	for _, ev := range events() {
		if ev.Kind == session.UAEventProvisional {
			t.Errorf("sipua emitted a provisional event (%d) for a response it SENT; provisional is for responses RECEIVED", ev.Code)
		}
	}
	// R14's incoming_call detail is {from_uri, to_uri, offered_codecs}, and
	// sipua parses the SDP so session never has to.
	if incoming.FromURI == "" || incoming.ToURI == "" {
		t.Errorf("inbound detail = {from=%q to=%q}, want both populated", incoming.FromURI, incoming.ToURI)
	}
	if len(incoming.OfferedCodecs) == 0 {
		t.Error("inbound event carries no OfferedCodecs (R14 detail)")
	}
	if len(incoming.SDP) == 0 {
		t.Error("inbound event carries no SDP body")
	}
	// The far end sees 100 Trying IMMEDIATELY and 180 Ringing once the event
	// has been delivered — in that order.
	waitForCode(t, p, 180)
	codes := p.ResponseCodes()
	if len(codes) < 2 || codes[0] != 100 || codes[1] != 180 {
		t.Errorf("peer saw responses %v, want 100 then 180 (R14)", codes)
	}
}

func countKind(evs []session.UAEvent, k session.UAEventKind) int {
	n := 0
	for _, ev := range evs {
		if ev.Kind == k {
			n++
		}
	}
	return n
}

func TestInboundInviteToAForeignIdentityIs404(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	// D11 point 4: no live UA matches this identity. The answer is 404 Not
	// Found — NOT 480 — because the truthful statement is that the targeted
	// identity DOES NOT EXIST HERE, not that it exists and is unavailable.
	p.Dial(t, "sip:nobody@"+ua.BoundAddr().String())
	waitForCode(t, p, 404)

	for _, c := range p.ResponseCodes() {
		if c == 480 {
			t.Error("peer saw a 480; D11 point 4 requires 404 Not Found, never 480")
		}
	}
	if got := kinds(events()); len(got) != 0 {
		t.Errorf("a 404'd INVITE produced events %v; no dialog should exist", got)
	}
}

// D11 point 3, in its structural form: NOTHING in sipua's inbound path
// consults connection state of any kind, which is what makes "if the owning
// session has no connection attached but the UA is still live, the INVITE IS
// STILL ACCEPTED" true by construction rather than by a check that could be
// forgotten. The registry half of D11 — ownership, and R11's not_found for a
// foreign session — is `session`'s and is asserted at the tool level.
func TestInboundAcceptanceDoesNotDependOnAnyConnectionState(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))

	// No event consumer is installed at all — the closest this layer has to
	// "no connection attached". The INVITE is still accepted and still rung.
	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	waitForCode(t, p, 180)

	codes := p.ResponseCodes()
	if len(codes) < 2 || codes[0] != 100 || codes[1] != 180 {
		t.Errorf("peer saw %v, want 100 then 180 with no consumer attached (D11 point 3)", codes)
	}
	// The events are queued on the call, not dropped: installing a consumer
	// afterwards and answering still works.
	events := collect(t, ua)
	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	incoming := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err != nil {
		t.Fatalf("Answer after attaching a consumer: %v", err)
	}
}

func TestInboundReject(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		reason  string
		wantSt  int
		wantRsn string
		wantErr bool
	}{
		{name: "default is 486", status: 0, wantSt: 486, wantRsn: "Busy Here"},
		{name: "explicit 486", status: 486, wantSt: 486, wantRsn: "Busy Here"},
		{name: "603 decline", status: 603, wantSt: 603, wantRsn: "Decline"},
		{name: "custom reason", status: 486, reason: "On Another Call", wantSt: 486, wantRsn: "On Another Call"},
		{name: "lower bound 300", status: 300, wantSt: 300, wantRsn: "Rejected"},
		{name: "upper bound 699", status: 699, wantSt: 699, wantRsn: "Rejected"},
		{name: "200 is invalid", status: 200, wantErr: true},
		{name: "299 is invalid", status: 299, wantErr: true},
		{name: "700 is invalid", status: 700, wantErr: true},
		{name: "negative is invalid", status: -1, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
			ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
			events := collect(t, ua)

			p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
			incoming := waitFor(t, events, session.UAEventInbound, 0)
			waitForCode(t, p, 180)
			before := len(p.ResponseCodes())

			err := ua.Reject(context.Background(), incoming.DialogID, tc.status, tc.reason)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Reject(status=%d) = nil, want invalid_argument", tc.status)
				}
				time.Sleep(100 * time.Millisecond)
				if got := len(p.ResponseCodes()); got != before {
					t.Errorf("Reject(status=%d) sent %d further responses; an invalid status must send NOTHING", tc.status, got-before)
				}
				return
			}
			if err != nil {
				t.Fatalf("Reject: %v", err)
			}
			// The assertion is on the WIRE: the far end receives exactly the
			// requested final response. session records "rejected_locally"
			// because IT called Reject — sipua names no termination reason.
			waitForCode(t, p, tc.wantSt)
			if got := p.LastFinalStatus(); got != tc.wantSt {
				t.Errorf("peer's last final = %d, want %d", got, tc.wantSt)
			}
			// A second Reject on the same dialog is precondition_failed, which
			// is what makes the rejection a one-time claim (§6.3).
			if err := ua.Reject(context.Background(), incoming.DialogID, tc.wantSt, ""); err == nil {
				t.Error("second Reject succeeded; want precondition_failed")
			}
			// P1 starts no media at all, so the assertion is that the dialog
			// produced no further traffic beyond the final response (§15's R14
			// split — never packet counts).
			if n := countKind(events(), session.UAEventFinal); n != 0 {
				t.Errorf("a rejected inbound dialog emitted %d final events; the 4xx-6xx was one WE SENT, not one we received", n)
			}
		})
	}
}

func TestInboundRingTimeoutAutoRejects480(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newDirectUA(t, clk) // InboundRingTimeout: 2s
	events := collect(t, ua)

	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	incoming := waitFor(t, events, session.UAEventInbound, 0)

	// Drive limits.inbound_ring_timeout_s from the FAKE CLOCK, not wall time.
	// BlockUntil ensures the ring timer is registered before it is advanced,
	// so the test cannot race past a timer that has not been armed yet.
	clk.BlockUntil(1)
	clk.Advance(2 * time.Second)

	// The far end receives the 480 (R14).
	waitForCode(t, p, 480)
	if got := p.LastFinalStatus(); got != 480 {
		t.Errorf("peer's last final = %d, want 480", got)
	}
	// And session LEARNS WHY (U14). The cause, not a termination_reason:
	// session maps ring_timeout onto §10.3's "inbound_ring_timeout".
	ev := waitFor(t, events, session.UAEventDialogEnded, 480)
	if ev.Cause != session.UACauseRingTimeout {
		t.Errorf("Cause = %q, want %q", ev.Cause, session.UACauseRingTimeout)
	}
	if ev.CallID != incoming.CallID || ev.CallID == "" {
		t.Errorf("CallID = %q, want the inbound event's %q", ev.CallID, incoming.CallID)
	}
	if ev.DialogID != incoming.DialogID {
		t.Errorf("DialogID = %q, want %q", ev.DialogID, incoming.DialogID)
	}
}

// U14's REASON FOR EXISTING. The ring timer's 480 and call_reject(480)'s are
// indistinguishable on the wire — same code, same reason phrase, same
// direction, same dialog — so §10.3's "inbound_ring_timeout" and
// "rejected_locally" can only be told apart by what sipua reports upward.
//
// Without this test, "simplify" the sixth kind away and infer the cause from
// Direction instead and every assertion above still passes while the two
// termination reasons silently collapse into one.
func TestRingTimeoutAndCallRejectAreDistinguishable(t *testing.T) {
	// Case A: the ring timer fires.
	pA := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clkA := fakeclock.New(time.Unix(0, 0))
	uaA, _ := newDirectUA(t, clkA)
	eventsA := collect(t, uaA)
	pA.Dial(t, "sip:alice@"+uaA.BoundAddr().String())
	waitFor(t, eventsA, session.UAEventInbound, 0)
	clkA.BlockUntil(1)
	clkA.Advance(2 * time.Second)
	waitForCode(t, pA, 480)
	timedOut := waitFor(t, eventsA, session.UAEventDialogEnded, 480)

	// Case B: the caller rejects with the SAME status and reason phrase.
	pB := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	uaB, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	eventsB := collect(t, uaB)
	pB.Dial(t, "sip:alice@"+uaB.BoundAddr().String())
	incomingB := waitFor(t, eventsB, session.UAEventInbound, 0)
	if err := uaB.Reject(context.Background(), incomingB.DialogID, 480, "Temporarily Unavailable"); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	waitForCode(t, pB, 480)

	// Both peers saw the identical final response...
	if pA.LastFinalStatus() != pB.LastFinalStatus() {
		t.Fatalf("the two cases must be identical on the wire: %d vs %d",
			pA.LastFinalStatus(), pB.LastFinalStatus())
	}
	// ...and yet session can tell them apart, which is the whole point.
	if timedOut.Cause != session.UACauseRingTimeout {
		t.Errorf("ring-timeout Cause = %q, want %q", timedOut.Cause, session.UACauseRingTimeout)
	}
	time.Sleep(100 * time.Millisecond) // give any wrong emission time to arrive
	if n := countKind(eventsB(), session.UAEventDialogEnded); n != 0 {
		t.Errorf("call_reject emitted %d dialog_ended events; session INITIATED the "+
			"rejection and records rejected_locally itself — an event here would be "+
			"indistinguishable from the ring timeout's", n)
	}
}

// Cause is set IF AND ONLY IF Kind is dialog_ended (U14). A stray Cause on a
// provisional or final event would let session derive a termination from a
// message that terminated nothing.
func TestCauseIsSetOnlyOnDialogEnded(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	for _, ev := range events() {
		if ev.Kind != session.UAEventDialogEnded && ev.Cause != "" {
			t.Errorf("%s event carries Cause %q; Cause is set iff Kind is dialog_ended (U14)", ev.Kind, ev.Cause)
		}
		// Every event carries the ladder key, on every path.
		if ev.CallID == "" {
			t.Errorf("%s event carries no CallID; session cannot key its ladder", ev.Kind)
		}
	}
}

// The peer BYE half of U14, and the CallID channel end to end.
func TestPeerBYEEmitsDialogEndedWithPeerBYECause(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if res.CallID == "" {
		t.Fatal("DialResult carries no CallID; call_ladder cannot find this call's ladder")
	}
	waitFor(t, events, session.UAEventFinal, 200)

	p.SendBye(t)

	ev := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ev.Cause != session.UACausePeerBYE {
		t.Errorf("Cause = %q, want %q", ev.Cause, session.UACausePeerBYE)
	}
	// Direction is the DIALOG's, not the BYE's: we dialled this call.
	if ev.Direction != session.Outbound {
		t.Errorf("Direction = %q, want %q — it is the dialog's direction, not the BYE's", ev.Direction, session.Outbound)
	}
	// ONE SOURCE: DialResult.CallID and every UAEvent.CallID for this dialog
	// are the same value, so the ladder key and the tap records cannot diverge.
	if ev.CallID != res.CallID {
		t.Errorf("dialog_ended CallID = %q, want DialResult's %q — a ladder keyed on "+
			"one value while its records carry another renders empty", ev.CallID, res.CallID)
	}
}

func TestInboundRingTimerIsCancelledByAnswerAndReject(t *testing.T) {
	for _, act := range []string{"answer", "reject"} {
		t.Run(act, func(t *testing.T) {
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
			clk := fakeclock.New(time.Unix(0, 0))
			ua, _ := newDirectUA(t, clk)
			events := collect(t, ua)

			p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
			incoming := waitFor(t, events, session.UAEventInbound, 0)
			clk.BlockUntil(1)

			var err error
			if act == "answer" {
				err = ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID})
			} else {
				err = ua.Reject(context.Background(), incoming.DialogID, 486, "")
			}
			if err != nil {
				t.Fatalf("%s: %v", act, err)
			}
			clk.Advance(10 * time.Second)
			time.Sleep(100 * time.Millisecond)

			for _, c := range p.ResponseCodes() {
				if c == 480 {
					t.Errorf("a 480 was sent after %s; the ring timer must be cancelled", act)
				}
			}
		})
	}
}

func TestInboundAnswerErrors(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	incoming := waitFor(t, events, session.UAEventInbound, 0)

	// nil SDPAnswer means Answer synthesises the fixed PCMU body — P1's rule
	// for both AnswerRequest.SDPAnswer and DialRequest.SDPOffer. This test
	// does NOT assert the body itself (that would restate D148's comment
	// mismatch it once had); see TestInboundAnswerSendsPCMUBody for the wire
	// assertion. This test exercises Answer's phase-transition and error
	// paths below.
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)
	// §10.3: precondition_failed on a dialog not ringing.
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err == nil {
		t.Error("second Answer succeeded; want precondition_failed")
	}
	if err := ua.Reject(context.Background(), incoming.DialogID, 486, ""); err == nil {
		t.Error("Reject on an answered dialog succeeded; want precondition_failed")
	}
	// §10.3: not_found on an unknown handle.
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: "call-does-not-exist"}); err == nil {
		t.Error("Answer on an unknown handle succeeded; want not_found")
	}
}

// TestInboundAnswerSendsPCMUBody pins the SDP synthesis wiring on the Answer
// side (D148): FixedPCMUSDP is unit-tested in isolation (sdp_test.go), but
// nothing previously asserted that Answer actually attaches its output to
// the 200 OK — deleting the synthesis call site left the package green.
func TestInboundAnswerSendsPCMUBody(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	incoming := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)

	body := string(p.LastFinalResponseBody())
	if !strings.Contains(body, "a=rtpmap:0 PCMU/8000") {
		t.Errorf("inbound 200 OK body = %q, want it to carry the fixed PCMU rtpmap", body)
	}
}

// TestAnswerHangupRaceProducesConsistentToTag pins D147 (Answer racing
// Hangup mints a second To-tag) and D148 (C4's d.ok = res fix had zero test
// coverage: deleting it left the package green). It runs Answer and Hangup
// concurrently over 60 iterations — the reviewer reproduced the original
// defect in 57/60 — and asserts, from bytes actually observed on the wire,
// that the BYE's To-tag always equals the 200 OK's To-tag.
//
// Hangup requires phase == phaseAnswered to proceed past its precondition
// check, so it is retried in a tight loop racing Answer's own goroutine: this
// reliably lands the attempt in the narrowest possible window around
// Answer's phase/ok transition, which is exactly where the original defect
// lived. The loop holds off only while the call is still ringing (or being
// admitted), because Hangup now DECLINES such a call 603 instead of refusing,
// which would end it before Answer could run at all.
func TestAnswerHangupRaceProducesConsistentToTag(t *testing.T) {
	const iterations = 60
	for i := 0; i < iterations; i++ {
		p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
		ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
		events := collect(t, ua)

		p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
		incoming := waitFor(t, events, session.UAEventInbound, 0)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			// UAEventInbound is emitted before the 180, so a bare Answer can land in
			// the phaseAdmitting window (CF-052); Answer waits it out, and
			// AnswerEventually is kept here, harmlessly, for the retry.
			if err := ua.AnswerEventually(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err != nil {
				t.Errorf("iteration %d: Answer: %v", i, err)
			}
		}()
		go func() {
			defer wg.Done()
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if sipua.InboundNotYetAnsweringForTest(ua, incoming.DialogID) {
					runtime.Gosched() // yield: don't hot-spin u.calls.mu against Answer
					continue
				}
				if err := ua.Hangup(context.Background(), incoming.DialogID, ""); err == nil {
					return
				}
				// precondition_failed: Answer has not yet flipped the phase.
				// Retry immediately — the tight loop is what lands the
				// attempt inside the narrow race window.
			}
			t.Errorf("iteration %d: Hangup never succeeded within 2s", i)
		}()
		wg.Wait()

		waitForCode(t, p, 200)
		deadline := time.Now().Add(2 * time.Second)
		for p.Count("BYE") == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if p.Count("BYE") != 1 {
			t.Fatalf("iteration %d: peer saw %d BYEs, want 1", i, p.Count("BYE"))
		}

		// D1: BuildByeFromInvite's bye.To = ok.To is overridden for the UAS
		// orientation, so the identity this test pins now lives in the BYE's
		// From (this UA's own tag), not its To (now the peer's tag).
		okTag := p.LastFinalToTag()
		bye := p.LastBye()
		if bye == nil {
			t.Fatalf("iteration %d: peer never captured the BYE it received", i)
		}
		byeFrom := bye.From()
		if byeFrom == nil {
			t.Fatalf("iteration %d: BYE carries no From header", i)
		}
		byeFromTag, _ := byeFrom.Params.Get("tag")
		if okTag == "" || byeFromTag == "" {
			t.Fatalf("iteration %d: empty tag(s): 200 OK To=%q BYE From=%q", i, okTag, byeFromTag)
		}
		if okTag != byeFromTag {
			t.Fatalf("iteration %d: BYE From-tag %q != 200 OK To-tag %q — the BYE carries a tag the far end never issued (D147)", i, byeFromTag, okTag)
		}
	}
}

// TestHangup_InboundBYEHasUASFromToOrientation pins D1: BuildByeFromInvite
// orients From/To for a UAC (bye.From = inv.From, bye.To = ok.To), which is
// backwards when THIS UA is the callee — the UAS. Left uncorrected, the BYE
// this UA sends to end a call it ANSWERED carries the peer's identity in
// From and this UA's own identity in To, so a compliant far end (Asterisk
// included) cannot match it to the dialog and rejects it 481 Call/Transaction
// Does Not Exist. The correct orientation is this UA's own identity (the 200
// OK's To, with the tag this UA minted) in From, and the peer's identity (the
// received INVITE's From, with the peer's own tag) in To.
func TestHangup_InboundBYEHasUASFromToOrientation(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	dialogID, invite, ourTag := establishInboundAnswered(t, ua, p, events)
	peerFrom := invite.From()
	if peerFrom == nil {
		t.Fatal("peer's own INVITE carries no From header")
	}
	peerTag, _ := peerFrom.Params.Get("tag")
	if peerTag == "" {
		t.Fatal("peer's own INVITE From carries no tag")
	}

	if err := ua.Hangup(context.Background(), dialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	p.WaitForBye(t, 3*time.Second)
	bye := p.LastBye()
	if bye == nil {
		t.Fatal("peer never captured the BYE it received")
	}

	from, to := bye.From(), bye.To()
	if from == nil || to == nil {
		t.Fatal("BYE carries no From/To header")
	}
	if fromTag, _ := from.Params.Get("tag"); fromTag != ourTag {
		t.Errorf("BYE From tag = %q, want this UA's own tag %q (UAS orientation, D1)", fromTag, ourTag)
	}
	if toTag, _ := to.Params.Get("tag"); toTag != peerTag {
		t.Errorf("BYE To tag = %q, want the peer's tag %q — D1: From/To were swapped", toTag, peerTag)
	}
	if to.Address.User != peerFrom.Address.User {
		t.Errorf("BYE To user = %q, want %q (the peer, whose INVITE From this BYE's To must echo)", to.Address.User, peerFrom.Address.User)
	}
	// Contact is the SAME direction blindness one header over, and its absence
	// from this test is why it survived: BuildByeFromInvite clones the received
	// INVITE's Contact, which on a dialog we ANSWERED is the PEER's own URI, so
	// the BYE advertised the peer as our reachability. buildInDialogRequest now
	// derives it from u.localContact() for every in-dialog request it builds.
	wantContact := "<sip:alice@" + ua.BoundAddr().String() + ">"
	if got := p.LastRequestHeader("BYE", "Contact"); got != wantContact {
		t.Errorf("BYE Contact = %q, want %q (ours, not the peer's)", got, wantContact)
	}
}
