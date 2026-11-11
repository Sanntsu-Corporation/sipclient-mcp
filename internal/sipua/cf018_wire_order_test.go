// internal/sipua/cf018_wire_order_test.go — CF-018's caller-level tests: a
// sender blocked on its dialog's send-order token, already past its own
// pre-token liveness check, must send nothing once the dialog is torn down.
package sipua_test

import (
	"context"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

func waitDialogEnded(t *testing.T, events func() []session.UAEvent, dialogID string) {
	t.Helper()
	waitForCond(t, func() bool {
		for _, ev := range events() {
			if ev.Kind == session.UAEventDialogEnded && ev.DialogID == dialogID {
				return true
			}
		}
		return false
	})
}

// endDialogWhenBlocked holds dialogID's send-order token. When a send of method
// finds it held, the hook has the peer BYE the call, waits until the UA has
// ended the dialog, and only then frees the token. So that sender resumes on a
// dialog that is already dead, AFTER its own caller-side liveness check passed.
func endDialogWhenBlocked(t *testing.T, ua *sipua.UA, p *peer.Peer,
	events func() []session.UAEvent, dialogID string, method sip.RequestMethod) {
	t.Helper()
	release := sipua.HoldSendOrderTokenForTest(t, ua, dialogID)
	t.Cleanup(release)
	sipua.SetInDialogSendContendedHookForTest(func(m sip.RequestMethod) {
		if m != method {
			return
		}
		p.SendBye(t)
		waitDialogEnded(t, events, dialogID)
		release()
	})
	t.Cleanup(func() { sipua.SetInDialogSendContendedHookForTest(nil) })
}

// TestAPeerBYEWhileTheREFERWaitsItsTurnSendsNoREFER is CF-018 for REFER: the
// residual window CF-008's pre-dispatch check could not cover.
func TestAPeerBYEWhileTheREFERWaitsItsTurnSendsNoREFER(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
	ua, cc := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)
	endDialogWhenBlocked(t, ua, p, events, res.DialogID, sip.REFER)

	out, err := ua.Transfer(context.Background(), session.TransferRequest{
		DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("Transfer=(%+v, %v), want precondition_failed", out, err)
	}
	if n := cc.Sent("REFER"); n != 0 {
		t.Fatalf("REFER dispatched %d time(s) on a dialog the peer had already ended", n)
	}
	if evs := transferEvents(events, res.DialogID); len(evs) != 0 {
		t.Fatalf("a REFER that was never sent reported %d transfer event(s): %+v", len(evs), evs)
	}
}

// TestAPeerBYEWhileTheINFOWaitsItsTurnSendsNoINFO is CF-018 for INFO: the
// wire once carried INVITE, ACK, INFO, BYE, INFO (sendDTMFInfo's comment), and
// its per-digit pre-check narrowed that window without closing it.
func TestAPeerBYEWhileTheINFOWaitsItsTurnSendsNoINFO(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{})
	ua, cc := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)
	endDialogWhenBlocked(t, ua, p, events, res.DialogID, sip.INFO)

	sent, _, err := ua.SendDTMF(context.Background(), res.DialogID, "1", session.DTMFModeInfo, 100, 0)
	if sent != 0 || apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("SendDTMF=(sent %d, %v), want (0, precondition_failed)", sent, err)
	}
	if n := cc.Sent("INFO"); n != 0 {
		t.Fatalf("INFO dispatched %d time(s) on a dialog the peer had already ended", n)
	}
}
