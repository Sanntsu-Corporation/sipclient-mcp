package sipua_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// CF-187: an offer that lists an unsupported suite first (FreeSWITCH's order)
// is answered with the first supported line, its tag echoed.
func TestInboundSDESOfferInFreeSWITCHOrderNegotiatesSRTP(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "required")
	events := collect(t, ua)
	k, _, err := media.GenerateCryptoAttr()
	if err != nil {
		t.Fatal(err)
	}
	good := strings.Replace(k.AttrLine(), "a=crypto:1", "a=crypto:2", 1)
	offer := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=x\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 20000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n" +
		"a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:" + strings.Repeat("A", 62) + "\r\n" + good + "\r\na=sendrecv\r\n"
	p.DialWithBody(t, "sip:alice@"+ua.BoundAddr().String(), []byte(offer))
	incoming := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)
	if body := string(p.LastFinalResponseBody()); !strings.Contains(body, "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:") {
		t.Fatalf("200 does not echo tag 2:\n%s", body)
	}
	if mv, ok := ua.MediaView(incoming.DialogID); !ok || !mv.SRTP {
		t.Fatalf("MediaView %+v ok=%v, want SRTP", mv, ok)
	}
}
