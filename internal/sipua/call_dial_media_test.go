package sipua_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// A peer whose 200 OK answers opus (PT 111) — a codec we never offer — must draw
// ACK strictly before BYE, exactly one BYE, and a
// dialog_ended{media_negotiation_failed} carrying detail.kind
// answer_codec_not_offered.
func TestDialAnswerCodecNotOfferedACKThenBYE(t *testing.T) {
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
	if ended.Detail["kind"] != "answer_codec_not_offered" {
		t.Fatalf("detail.kind=%v", ended.Detail["kind"])
	}
	p.WaitForBye(t, 2*time.Second)
	if !p.AckBeforeBye() {
		t.Fatalf("methods out of order (ACK must precede BYE): %v", p.Methods())
	}
	if n := p.ByeCount(); n != 1 {
		t.Fatalf("want exactly one BYE on the wire, got %d: %v", n, p.Methods())
	}
}

// A call_hangup racing in while runDial holds the dialog in phaseMediaTeardown
// (mid ACK-then-BYE) must be refused precondition_failed, and only the internal
// BYE — exactly one — may reach the wire. The teardown hook widens the window
// deterministically.
func TestHangupDuringMediaTeardownIsPreconditionFailed(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{
		AnswerSDP: peer.AnswerRaw([]byte("garbage not sdp")), // sdp_unparseable → ACK-then-BYE
	}})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "disabled")
	events := collect(t, ua)

	dialResult := make(chan session.DialResult, 1)
	hangupDone := make(chan error, 1)
	var once sync.Once
	sipua.SetMediaTeardownHook(func() {
		// Runs on runDial's goroutine while the dialog is held in
		// phaseMediaTeardown, BEFORE the internal BYE is sent. A racing
		// call_hangup must be refused here without touching the wire.
		once.Do(func() {
			dr := <-dialResult
			hangupDone <- ua.Hangup(context.Background(), dr.DialogID, "racing")
		})
	})
	t.Cleanup(func() { sipua.SetMediaTeardownHook(nil) })

	dr, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	dialResult <- dr

	select {
	case herr := <-hangupDone:
		if herr == nil || !isCode(herr, apierr.CodePreconditionFailed) {
			t.Fatalf("racing call_hangup during phaseMediaTeardown must be precondition_failed, got %v", herr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("teardown hook / racing hangup never ran")
	}

	ended := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ended.Cause != session.UACauseMediaNegotiationFailed {
		t.Fatalf("cause=%q", ended.Cause)
	}
	p.WaitForBye(t, 2*time.Second)
	if n := p.ByeCount(); n != 1 {
		t.Fatalf("want exactly one BYE (the internal one), got %d: %v", n, p.Methods())
	}
}

// An answer that rejects our only audio stream (m=audio 0, RFC 3264 6) ends the
// call (A-15): ACK, one BYE, and dialog_ended{media_negotiation_failed} with
// detail.kind answer_rejected_audio.
func TestOffererEndsTheCallWhenTheAnswerRejectsItsAudio(t *testing.T) {
	rejected := []byte("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=x\r\nc=IN IP4 127.0.0.1\r\n" +
		"t=0 0\r\nm=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{
		AnswerSDP: peer.AnswerWithBody(rejected),
	}})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "disabled")
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	ended := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ended.Cause != session.UACauseMediaNegotiationFailed || ended.Detail["kind"] != "answer_rejected_audio" {
		t.Fatalf("cause=%q detail=%v", ended.Cause, ended.Detail)
	}
	p.WaitForBye(t, 2*time.Second)
	if !p.AckBeforeBye() || p.ByeCount() != 1 {
		t.Fatalf("want ACK then exactly one BYE: %v", p.Methods())
	}
}
