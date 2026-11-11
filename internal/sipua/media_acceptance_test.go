package sipua_test

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// Offering side (§11.2.1): every reachable ACK-then-BYE kind. Each drives a
// non-compliant peer via Behaviour.AnswerSDP and asserts the dialog terminated
// as media_negotiation_failed with the right detail, ACK strictly before BYE,
// and exactly one BYE on the wire.
func TestOfferingSideNegotiationFailures(t *testing.T) {
	unsupported := []byte("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=x\r\nc=IN IP4 127.0.0.1\r\n" +
		"t=0 0\r\nm=audio 20000 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\na=sendrecv\r\n")
	cases := []struct {
		name      string
		answerSDP func(offer []byte) []byte
		wantKind  string
	}{
		{"answer_codec_not_offered", peer.AnswerWithBody(unsupported), "answer_codec_not_offered"},
		{"sdp_absent", peer.AnswerNoBody(), "sdp_absent"},
		{"sdp_unparseable", peer.AnswerRaw([]byte("garbage not sdp")), "sdp_unparseable"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{
				AnswerSDP: tc.answerSDP,
			}})
			ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "disabled")
			events := collect(t, ua)

			if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
				t.Fatalf("Dial: %v", err)
			}
			ended := waitFor(t, events, session.UAEventDialogEnded, 0)
			if ended.Cause != session.UACauseMediaNegotiationFailed {
				t.Fatalf("cause=%q", ended.Cause)
			}
			if ended.Detail["kind"] != tc.wantKind {
				t.Fatalf("detail.kind=%v want %q", ended.Detail["kind"], tc.wantKind)
			}
			// Offering-side detail: ack_then_bye, and sip_response_sent present-but-nil
			// (488 is a response and the transaction is already complete — §11.2.1).
			if ended.Detail["action"] != "ack_then_bye" {
				t.Fatalf("action=%v want ack_then_bye", ended.Detail["action"])
			}
			if v, present := ended.Detail["sip_response_sent"]; !present || v != nil {
				t.Fatalf("sip_response_sent must be present and nil, got (%v,%v)", v, present)
			}
			p.WaitForBye(t, 2*time.Second)
			if !p.AckBeforeBye() {
				t.Fatalf("ACK must precede BYE: %v", p.Methods())
			}
			if n := p.ByeCount(); n != 1 {
				t.Fatalf("want exactly one BYE on the wire, got %d: %v", n, p.Methods())
			}
		})
	}
}

// TestOfferingSideByeDoesNotReuseTheInvitesViaBranch is the regression pin for
// Cycle 5 finding B. The §11.2.1 ACK-then-BYE used to be built by calling
// siptest.BuildByeFromInvite directly, bypassing buildInDialogRequest. That
// builder clones the INVITE's Via WHOLESALE, branch included
// (sipengine/siptest/builders.go), where buildInDialogRequest strips it
// (dtmf.go) precisely so the transport mints a FRESH branch on dispatch. So this
// one BYE went onto the wire carrying the INVITE's own branch, violating RFC
// 3261 §8.1.1.7's uniqueness requirement. It never failed observably — a
// non-INVITE transaction is matched by branch|sent-by|METHOD (§17.1.3), so it
// cannot collide with the INVITE transaction — but it is a real divergence from
// the canonical builder, and exactly what a B2BUA or a loop-detecting proxy
// notices.
func TestOfferingSideByeDoesNotReuseTheInvitesViaBranch(t *testing.T) {
	unsupported := []byte("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=x\r\nc=IN IP4 127.0.0.1\r\n" +
		"t=0 0\r\nm=audio 20000 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\na=sendrecv\r\n")
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{
		AnswerSDP: peer.AnswerWithBody(unsupported),
	}})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "disabled")
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	ended := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ended.Cause != session.UACauseMediaNegotiationFailed {
		t.Fatalf("cause=%q", ended.Cause)
	}
	p.WaitForBye(t, 2*time.Second)

	inviteBranch := branchOf(p.LastRequestHeader("INVITE", "Via"))
	byeBranch := branchOf(p.LastRequestHeader("BYE", "Via"))
	if inviteBranch == "" || byeBranch == "" {
		t.Fatalf("a request's Via carried no branch: invite=%q bye=%q", inviteBranch, byeBranch)
	}
	if byeBranch == inviteBranch {
		t.Fatalf("the §11.2.1 BYE reused the INVITE's own branch %q — RFC 3261 §8.1.1.7 "+
			"requires every new transaction's branch to be unique", inviteBranch)
	}
}

// Answer side (§11.2): a UA with srtp="required" receiving a plain RTP/AVP offer
// (no a=crypto) must reject 488 and surface a media_negotiation error — the
// synchronous call_answer path, distinct from the offering-side ACK-then-BYE.
func TestAnswerSideSRTPRefusalSends488(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "required")
	events := collect(t, ua)

	// Peer offers plain RTP/AVP PCMU, no a=crypto.
	p.DialWithBody(t, "sip:alice@"+ua.BoundAddr().String(),
		[]byte("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=x\r\nc=IN IP4 127.0.0.1\r\n"+
			"t=0 0\r\nm=audio 20000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"))
	inc := waitFor(t, events, session.UAEventInbound, 0)
	err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID})
	if err == nil {
		t.Fatal("srtp=required against an RTP/AVP-only offer must fail")
	}
	waitForCode(t, p, 488)
}
