package sipua_test

// Lane D (rfc-sweep-d) pins for RFC 3311 deviations (6a D11). Each passes today
// and must be inverted when its finding is fixed. No t.Parallel. The timer pins use the fake clock
// through newSessionTimerUAWithMethod against internal/testutil/peer, as Lane C's
// NEWC11 and NEWC12 do.

import (
	"context"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

const laneDUpdateOffer = "v=0\r\no=probe 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
	"m=audio 15284 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n"

var laneDSDPHeader = func() []sip.Header {
	return []sip.Header{sip.NewHeader("Content-Type", "application/sdp")}
}

// TestRFC3311Pin_NEWD36_Retry491OfUpdateIsAFixedTwoSeconds pins NEW-D-36 (L29,
// D-UPD-12, RFC 3311 5.3: "If a UAC receives a 491 response to a UPDATE, it
// SHOULD start a timer with a value T chosen as follows:" rfc3311.txt:320-321,
// whose rules give the owner of the Call-ID a random T between 2.1 and 4 s).
// Evidence: evidence/m-u491/excerpt.txt (the 491 and the retry 2.0 s apart).
// Locus: internal/sipua/sessiontimer.go:startSessionRefresher; same symbol as
// CF-123. The retry leaves once the fake clock has advanced exactly 2 s, below
// 2.1 s.
//
// PIN OF A DEVIATION: invert this assertion when NEW-D-36 is fixed.
func TestRFC3311Pin_NEWD36_Retry491OfUpdateIsAFixedTwoSeconds(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
			RejectUpdateStatus:   491,
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newSessionTimerUAWithMethod(t, clk, 90, 90, "update")
	events := collect(t, ua)
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // the UPDATE refresh, answered 491
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
	n := p.Count("UPDATE")
	clk.BlockUntil(1) // the refresher's retry timer is armed
	clk.Advance(2 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") > n }) // fails once T is at least 2.1 s
}
