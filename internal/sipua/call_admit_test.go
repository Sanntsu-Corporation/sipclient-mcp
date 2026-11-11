package sipua

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	sippeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestOnInvite_RejectVerdictSendsFinalAndDoesNotRingOrLeak pins I2's sipua
// half: a SYNCHRONOUS admission Reject (the session decides over the cap or
// during shutdown) sends the SIP final IMMEDIATELY, sends NO 180 Ringing (the
// call never rings), and leaves NO dialog registered (no leak).
//
// It is an in-package test because the no-leak assertion reads u.calls, which
// call_inbound_test.go's black-box sipua_test package cannot.
func TestOnInvite_RejectVerdictSendsFinalAndDoesNotRingOrLeak(t *testing.T) {
	p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newClaimTestUA(t, clk)

	ua.OnAdmit(context.Background(), func(_ context.Context, _ session.UAEvent) session.Admission {
		return session.AdmitReject(486, "Busy Here")
	})

	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())

	if code := p.WaitForInviteFinal(t, 3*time.Second); code != 486 {
		t.Fatalf("INVITE final = %d, want 486 (the admission Reject's status)", code)
	}
	// Must NOT have rung: no 180 anywhere in the response stream. The 100 Trying
	// still precedes the reject (it is sent before admission), so the codes are
	// [100, 486] with no 180.
	for _, c := range p.ResponseCodes() {
		if c == 180 {
			t.Errorf("a 180 Ringing was sent on a rejected admission; the call must not ring (I2)")
		}
	}
	// No leak: the just-registered dialog must have been forgotten on reject.
	cid := ""
	if inv := p.LastSentInvite(); inv != nil {
		if h := inv.CallID(); h != nil {
			cid = h.Value()
		}
	}
	if d := ua.findByCallID(cid); d != nil {
		t.Fatalf("rejected INVITE left dialog %q registered (leak, I2)", d.id)
	}
	ua.calls.mu.Lock()
	n := len(ua.calls.byID)
	ua.calls.mu.Unlock()
	if n != 0 {
		t.Fatalf("rejected INVITE left %d dialogs in the registry (leak, I2)", n)
	}
}
