package sipua_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestOnInvite_ReInviteInDialogIs200NotNewCall pins D2's positive case: an
// in-dialog re-INVITE — Asterisk's connected-line/codec-lock renegotiation,
// carrying OUR OWN To-tag on an already-answered dialog — must be recognized
// and answered 200 with the CURRENT unchanged SDP, and must NOT run
// admission again. Before the guard, onInvite matched no dialog to any
// incoming INVITE: it built a fresh dialog and called u.admit(ev)
// unconditionally, so a re-INVITE produced a phantom ringing call exactly
// like a genuinely new call would.
func TestOnInvite_ReInviteInDialogIs200NotNewCall(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	establishInboundAnswered(t, ua, p, events)
	beforeInbound := countKind(events(), session.UAEventInbound)
	beforeSDP := p.LastFinalResponseBody()
	beforeFinals := p.FinalResponseCount()

	p.SendReInvite(t)

	code := p.WaitForFinalAfter(t, beforeFinals, 3*time.Second)
	if code != 200 {
		t.Fatalf("re-INVITE final = %d, want 200", code)
	}
	if got := p.LastFinalResponseBody(); string(got) != string(beforeSDP) {
		t.Errorf("re-INVITE 200 SDP = %q, want unchanged %q (W1 does not renegotiate)", got, beforeSDP)
	}
	// D2: no new call. A black-box test cannot read u.calls.byID directly
	// (package sipua_test — see call_cancel_test.go's identical constraint),
	// so the observable proxy is that admission did NOT run a second time: a
	// phantom dialog would have produced a second UAEventInbound exactly like
	// a genuinely new call does (collect's OnAdmit always accepts).
	if got := countKind(events(), session.UAEventInbound); got != beforeInbound {
		t.Errorf("re-INVITE produced %d inbound events (want %d): admission ran again, meaning a phantom dialog was created (D2)", got, beforeInbound)
	}
}

// TestOnInvite_UnknownToTagIs481 pins D2's negative case: an INVITE carrying
// a To-tag that matches no confirmed dialog on this UA gets 481 Call/
// Transaction Does Not Exist (RFC 3261 §12.2.2) and is never treated as a new
// call.
func TestOnInvite_UnknownToTagIs481(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	p.DialWithToTag(t, "sip:alice@"+ua.BoundAddr().String(), "nosuchtag")

	code := p.WaitForInviteFinal(t, 3*time.Second)
	if code != 481 {
		t.Fatalf("unknown-tag INVITE final = %d, want 481", code)
	}
	if n := countKind(events(), session.UAEventInbound); n != 0 {
		t.Errorf("unknown-tag INVITE produced %d inbound events, want 0 — it must never be treated as a new call", n)
	}
}

// TestOnInvite_OutboundReInviteInDialogIsAnsweredFromTheLiveSession is Task 11's
// outbound-leg counterpart to TestOnInvite_ReInviteInDialogIs200NotNewCall.
// The live §14.5 loop gate against a real Asterisk proved that
// direct_media=yes re-INVITEs BOTH legs after answer: D2's guard (Task 8)
// only recognized the re-INVITE on the INBOUND (callee) leg, because
// ourToTagLocked read d.ok.To()'s tag — the REMOTE (peer) tag on an outbound
// dialog, not ours. Here WE dial the peer (outbound); once answered, the
// peer sends an in-dialog re-INVITE carrying OUR OWN locally-generated tag
// (from our INVITE's From) as its To-tag — exactly what Asterisk sends the
// caller leg. It must be recognized as the SAME dialog (200, no new call,
// SDP unchanged), not misrouted to the unknown-tag 481 branch.
func TestOnInvite_OutboundReInviteInDialogIsAnsweredFromTheLiveSession(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	beforeCount := ua.RegisteredDialogCount()
	// ourOffer is the SDP WE sent in our own outbound INVITE (d.invite.Body())
	// — read back off what the peer actually received on the wire.
	ourOffer := p.LastInviteBody()
	beforeFinals := p.FinalResponseCount()

	p.SendReInviteToCaller(t)

	code := p.WaitForFinalAfter(t, beforeFinals, 3*time.Second)
	if code != 200 {
		t.Fatalf("outbound re-INVITE final = %d, want 200", code)
	}
	// CF-186: the peer's re-offer is unchanged, so the 200 is an answer built from
	// the live session (one audio codec), never our original offer.
	got := string(p.LastFinalResponseBody())
	if got == string(ourOffer) {
		t.Errorf("outbound re-INVITE 200 SDP is our original offer %q, want an answer from the live session", got)
	}
	if n := strings.Count(got, "m=audio"); n != 1 {
		t.Errorf("%d m=audio lines in %q, want 1", n, got)
	}
	if strings.Contains(got, "a=crypto") {
		t.Errorf("answer carries a key: %q", got)
	}
	want := strings.Fields(sdpField(string(ourOffer), "o="))
	if f := strings.Fields(sdpField(got, "o=")); len(f) < 3 || len(want) < 3 || f[1] != want[1] || f[2] != "2" {
		t.Errorf("answer o= %q, want our session id %q and version 2", f, want)
	}
	if got := ua.RegisteredDialogCount(); got != beforeCount {
		t.Errorf("outbound re-INVITE changed registered dialog count %d -> %d, want unchanged (no new dialog)", beforeCount, got)
	}
}

// TestOutboundReInvite200CarriesContactAndTheNegotiatedSessionTimer pins what
// the 200 answering a matched in-dialog re-INVITE must carry. It used to carry
// only the echoed Content-Type, which broke two things at once against a real
// PBX: RFC 3261 §12.2.2 requires a Contact on a 2xx to a target-refresh
// request, and RFC 4028 §7.4/§10 reads a 2xx to a session-refresh request
// WITHOUT Session-Expires as "the session timer is no longer in use" — so on
// every direct-media call the negotiated timer was silently cancelled at the
// peer while this side kept a refresher and watchdog armed against it.
//
// THE EXPECTED Session-Expires IS DERIVED FROM THE DIALOG'S OWN NEGOTIATED
// STATE (SessionTimerView), never a literal: the peer answers 120;refresher=uas
// while the UA proposed 1200;refresher=uac, so a response echoing a hardcoded
// value, our proposal, or the default role fails here.
func TestOutboundReInvite200CarriesContactAndTheNegotiatedSessionTimer(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: "120;refresher=uas"},
	})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1200, 120)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	v, ok := ua.SessionTimerView(res.DialogID)
	if !ok {
		t.Fatal("the answer's Session-Expires must have recorded a session timer for this test to mean anything")
	}

	beforeFinals := p.FinalResponseCount()
	p.SendReInviteToCaller(t)
	if code := p.WaitForFinalAfter(t, beforeFinals, 3*time.Second); code != 200 {
		t.Fatalf("re-INVITE final = %d, want 200", code)
	}

	if got := p.LastResponseHeader("INVITE", 200, "Contact"); got == "" {
		t.Error("the 200 answering an in-dialog re-INVITE carries no Contact (RFC 3261 §12.2.2)")
	}
	// The re-INVITE lists no timer: Table 2 "N, none" hands the choice to us and we
	// refresh, so the 2xx says uas (this transaction's orientation: us) on the
	// dialog's current interval. The view's Refresher is dialog-oriented.
	want := fmt.Sprintf("%d;refresher=uas", v.IntervalS)
	if got := p.LastResponseHeader("INVITE", 200, "Session-Expires"); got != want {
		t.Errorf("re-INVITE 200 Session-Expires = %q, want the dialog's negotiated %q "+
			"(RFC 4028 §7.4: omitting it tells the peer the session timer is off)", got, want)
	}
}
