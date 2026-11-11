package sipua_test

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// A UA whose only codec is PCMU, answering a PCMA-only offer, must reject 488
// and return a media_negotiation apierr with detail.kind no_common_codec.
func TestAnswerNoCommonCodecSends488(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "disabled")
	events := collect(t, ua)

	// Peer offers PCMA only (PT 8).
	pcmaOffer := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=x\r\nc=IN IP4 127.0.0.1\r\n" +
		"t=0 0\r\nm=audio 20000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n"
	p.DialWithBody(t, "sip:alice@"+ua.BoundAddr().String(), []byte(pcmaOffer))

	incoming := waitFor(t, events, session.UAEventInbound, 0)
	err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID})
	var ae *apierr.Error
	if err == nil || !asAPIErr(err, &ae) || ae.Code != apierr.CodeMediaNegotiation {
		t.Fatalf("want media_negotiation apierr, got %v", err)
	}
	if ae.Detail["kind"] != "no_common_codec" {
		t.Fatalf("detail.kind=%v", ae.Detail["kind"])
	}
	waitForCode(t, p, 488)
}

// Happy path: PCMU offer, PCMU-capable UA answers 200 with a single-codec body.
func TestAnswerNegotiatesPCMU(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU", "PCMA"}, "disabled")
	events := collect(t, ua)

	p.Dial(t, "sip:alice@"+ua.BoundAddr().String()) // peer's default offer is PCMU
	incoming := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)
	body := string(p.LastFinalResponseBody())
	if !contains2(body, "m=audio") || !contains2(body, "PCMU") {
		t.Fatalf("200 OK body not a PCMU answer:\n%s", body)
	}
}
