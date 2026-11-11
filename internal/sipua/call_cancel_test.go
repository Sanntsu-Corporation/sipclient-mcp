package sipua_test

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestOnCancel_Sends487AndEmitsCancelledCause is D3's sipua-side half. RFC
// 3261 §9.2: a CANCEL for a still-ringing INVITE draws a 200 on the CANCEL
// TRANSACTION ITSELF and a 487 Request Terminated on the PENDING INVITE
// transaction — two distinct finals on one Call-ID. Before this fix, onCancel
// only sent the 200: the INVITE was left ringing forever and no
// UAEventDialogEnded ever reached session, so a CANCELled inbound call never
// terminated.
func TestOnCancel_Sends487AndEmitsCancelledCause(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	incoming := waitFor(t, events, session.UAEventInbound, 0)
	waitForCode(t, p, 180) // ringing, deliberately NOT answered

	p.SendCancel(t)

	if code := p.WaitForCancelFinal(t, 3*time.Second); code != 200 {
		t.Fatalf("CANCEL transaction final = %d, want 200", code)
	}
	if code := p.WaitForInviteFinal(t, 3*time.Second); code != 487 {
		t.Fatalf("INVITE transaction final = %d, want 487 (D3)", code)
	}

	ev := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ev.Cause != session.UACauseCancelled {
		t.Errorf("Cause = %q, want %q", ev.Cause, session.UACauseCancelled)
	}
	if ev.DialogID != incoming.DialogID {
		t.Errorf("DialogID = %q, want %q", ev.DialogID, incoming.DialogID)
	}
	if ev.CallID != incoming.CallID || ev.CallID == "" {
		t.Errorf("CallID = %q, want the inbound event's %q", ev.CallID, incoming.CallID)
	}

	// The dialog must be terminated AND forgotten (Task 1's registry): a
	// black-box test cannot read u.calls.byID directly (package sipua_test),
	// so the observable proxy is that the dialog handle no longer resolves —
	// Answer on it must fail not_found rather than race a second 200 onto the
	// same INVITE transaction the 487 already closed.
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err == nil {
		t.Error("Answer succeeded on a CANCELled dialog; want not_found — the dialog must be forgotten")
	}
}
