package sipua_test

// Lane C (rfc-sweep-c) pins for the C-RFR area (RFC 4028 section 10). Each
// passes today and must be inverted when its NEW-C finding is fixed. No test here calls t.Parallel
// (parallel_invariant_test.go). Every timer is the fake clock (6a D11). NEW-C-10's
// peer is Lane A's raw UDP stub (rfc3261_pin_uac_test.go), because
// internal/testutil/peer has no knob for a challenged UPDATE (6a D12);
// NEW-C-16's is internal/testutil/peer through newSessionTimerUA.

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestRFC4028Pin_NEWC16_WatchdogByeLeavesAtTheExpiration pins NEW-C-16
// (C-RFR-03, RFC 4028 10: "Similarly, if the side not performing refreshes does
// not receive a session refresh request before the session expiration, it
// SHOULD send a BYE to terminate the session, slightly before the session
// expiration." rfc4028.txt:965-968; C-RFR-04: "The minimum of 32 seconds and
// one third of the session interval is RECOMMENDED." rfc4028.txt:968-969).
// Evidence: evidence/rpr-peer/excerpt.txt frame 8-9 (our 200 to the peer's last
// refresh, Session-Expires: 120) and frame 10 (our BYE 120.0 s later, Reason:
// SIP;cause=408), not min(32, 40) = 32 s before the expiration. On a 90 s
// interval the recommended BYE is due 30 s before the expiration, at 60 s; at
// 61 s none has left (an absence assertion, with the BYE past 90 s as its
// positive control). It contradicts TestAnInboundRefreshRearmsTheWatchdog
// (sessiontimer_watchdog_test.go) and the Phase 3 design's full-interval
// watchdog (Phase 3 DTMF/session-timers design,
// lines 108, 187), 6a D20 item 3.
//
// PIN OF A DEVIATION: invert this assertion when NEW-C-16 is fixed.
func TestRFC4028Pin_NEWC16_WatchdogByeLeavesAtTheExpiration(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 90, 90)
	events := collect(t, ua)
	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Supported":       "timer",
		"Session-Expires": "90;refresher=uac",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)

	clk.BlockUntil(1)
	clk.Advance(61 * time.Second) // past min(32, 90/3) = 30 s before the expiration
	time.Sleep(300 * time.Millisecond)
	if n := p.ByeCount(); n != 0 {
		t.Fatalf("a BYE left %d s before the 90 s expiration: NEW-C-16 is fixed, invert this pin", 90-61)
	}
	clk.BlockUntil(1)
	clk.Advance(30 * time.Second) // 91 s: past the expiration
	waitForCond(t, func() bool { return p.ByeCount() >= 1 })
	time.Sleep(100 * time.Millisecond)
	if n := p.ByeCount(); n != 1 {
		t.Fatalf("precondition: %d BYEs after the expiration, want exactly 1", n)
	}
}
