package sipua_test

// Lane A (cf6-a-sdp) Task 1 (CF-201, CF-210): a peer's media address must be a
// usable IPv4 literal and its port 0..65535, on every path that reads a peer
// SDP. No test calls t.Parallel.

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// inboundRefusedOffer dials a UA with offer and asserts Answer fails
// media_negotiation / no_common_codec and the peer sees 488 and no 200.
func inboundRefusedOffer(t *testing.T, offer string) {
	t.Helper()
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "disabled")
	events := collect(t, ua)
	p.DialWithBody(t, "sip:alice@"+ua.BoundAddr().String(), []byte(offer))
	incoming := waitFor(t, events, session.UAEventInbound, 0)
	err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID})
	var ae *apierr.Error
	if err == nil || !asAPIErr(err, &ae) || ae.Code != apierr.CodeMediaNegotiation || ae.Detail["kind"] != "no_common_codec" {
		t.Fatalf("want media_negotiation/no_common_codec, got %v", err)
	}
	waitForCode(t, p, 488)
	for _, c := range p.ResponseCodes() {
		if c == 200 {
			t.Fatal("a 200 was sent for a refused offer")
		}
	}
}

func TestInboundOfferWithAHostnameDraws488(t *testing.T) {
	inboundRefusedOffer(t, strings.Replace(laneDSDP(1, 20000), "c=IN IP4 127.0.0.1", "c=IN IP4 localhost", 1))
}

func TestInboundOfferWithAnOutOfRangePortDraws488(t *testing.T) {
	inboundRefusedOffer(t, laneDSDP(1, 99999))
}

func TestReOfferWithAHostnameDraws488AndKeepsTheMedia(t *testing.T) {
	r := newReofferRig(t)
	bad := strings.Replace(laneDSDP(2, r.aPort+2), "c=IN IP4 127.0.0.1", "c=IN IP4 localhost", 1)
	if st, _ := r.reoffer(t, bad); st != 488 {
		t.Fatalf("re-offer with a hostname answered %d, want 488", st)
	}
	if pt := rtpWithin(r.a, 2*time.Second); pt != 0 {
		t.Fatalf("RTP payload type %d at socket A after the refused re-offer, want 0 (media untouched)", pt)
	}
	if st, _ := r.reoffer(t, laneDSDP(3, r.aPort)); st != 200 {
		t.Fatalf("a following valid re-offer answered %d, want 200 (the offer claim was released)", st)
	}
}

func TestOutboundAnswerWithAHostnameEndsTheCall(t *testing.T) {
	bad := strings.Replace(earlySDP(40000, "0"), "c=IN IP4 127.0.0.1", "c=IN IP4 localhost", 1)
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{earlyContact(s)}, bad))
	})
	ua := newStubUA(t)
	events := collect(t, ua)
	dialStub(t, ua, s)
	waitFor(t, events, session.UAEventFinal, 200)
	ev := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ev.Cause != session.UACauseMediaNegotiationFailed {
		t.Errorf("dialog_ended cause = %q, want media_negotiation_failed", ev.Cause)
	}
	settle(s, 1, 1)
	if n := len(s.requests("ACK")); n != 1 {
		t.Errorf("ACKs = %d, want 1", n)
	}
	if n := len(s.requests("BYE")); n != 1 {
		t.Errorf("BYEs = %d, want 1", n)
	}
}
