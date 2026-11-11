// internal/sipua/controlop_test.go
package sipua_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// dialAnswered dials the peer and waits for THIS dialog's 200 — not merely the
// first 200 in the buffer, which is what waitFor would return on a UA that
// already has an answered call (the attended-transfer tests dial twice).
func dialAnswered(t *testing.T, ua *sipua.UA, p *peer.Peer, events func() []session.UAEvent) session.DialResult {
	t.Helper()
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitForCond(t, func() bool {
		for _, ev := range events() {
			if ev.Kind == session.UAEventFinal && ev.Code == 200 && ev.DialogID == res.DialogID {
				return true
			}
		}
		return false
	})
	return res
}

// inControlOp reports whether a call control operation (of any kind) holds
// dialogID — ControlOpState's inFlight half, for the many tests that only care
// whether the dialog is held, not by what.
func inControlOp(ua *sipua.UA, dialogID string) bool {
	_, inFlight := ua.ControlOpState(dialogID)
	return inFlight
}

// claimControlOp claims phaseControlOp through the export_test seam exactly as
// a production control operation (call_transfer) does, failing on error.
func claimControlOp(t *testing.T, ua *sipua.UA, dialogID string) (<-chan struct{}, func()) {
	t.Helper()
	ended, release, err := sipua.ClaimControlOpForTest(ua, dialogID)
	if err != nil {
		t.Fatalf("ClaimControlOpForTest: %v", err)
	}
	return ended, release
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s: the control operation's ended channel was not closed within 3s — "+
			"its owner would wait out its full timeout on a dead dialog", what)
	}
}

func TestControlOpClaimIsExclusiveAndVisible(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)

	if kind, held := ua.ControlOpState(res.DialogID); held || kind != "" {
		t.Fatalf("ControlOpState=(%q,%v) before any claim, want (\"\",false)", kind, held)
	}
	_, release := claimControlOp(t, ua, res.DialogID)
	// D15: the guard reports WHICH operation holds the dialog, not just that one does.
	if kind, held := ua.ControlOpState(res.DialogID); !held || kind != sipua.TestControlOpKind {
		t.Fatalf("ControlOpState=(%q,%v) while held, want (%q,true)", kind, held, sipua.TestControlOpKind)
	}
	// D17: a fresh claim blocks call_hangup until its OWNER says otherwise.
	if kind, blocked := ua.ControlOpBlocksHangup(res.DialogID); !blocked || kind != sipua.TestControlOpKind {
		t.Fatalf("ControlOpBlocksHangup=(%q,%v) right after the claim, want (%q,true)", kind, blocked, sipua.TestControlOpKind)
	}
	_, _, err := sipua.ClaimControlOpForTest(ua, res.DialogID)
	if err == nil || apierr.CodeOf(err) != apierr.CodePreconditionFailed ||
		!strings.Contains(err.Error(), "control operation is in progress") {
		t.Fatalf("second claim err=%v want precondition_failed naming the in-progress control operation", err)
	}
	release()
	if kind, held := ua.ControlOpState(res.DialogID); held || kind != "" {
		t.Fatalf("ControlOpState=(%q,%v) after release, want the kind cleared too", kind, held)
	}
	if kind, blocked := ua.ControlOpBlocksHangup(res.DialogID); blocked || kind != "" {
		t.Fatalf("ControlOpBlocksHangup=(%q,%v) after release, want (\"\",false)", kind, blocked)
	}
	_, release2 := claimControlOp(t, ua, res.DialogID) // released -> claimable again
	release2()
	if inControlOp(ua, "no-such-dialog") {
		t.Fatal("ControlOpState reports an unknown dialog as held")
	}
}

func TestSendDTMFIsRefusedDuringAControlOp(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)

	_, release := claimControlOp(t, ua, res.DialogID)
	defer release()
	_, _, err := ua.SendDTMF(context.Background(), res.DialogID, "1", session.DTMFModeInfo, 100, 0)
	if err == nil || apierr.CodeOf(err) != apierr.CodePreconditionFailed ||
		!strings.Contains(err.Error(), "control operation is in progress") {
		t.Fatalf("SendDTMF during a control op err=%v want precondition_failed", err)
	}
	if n := p.Count("INFO"); n != 0 {
		t.Fatalf("%d INFO on the wire; a refused dtmf_send must send nothing", n)
	}
}

// TestAControlOpIsRefusedWhileADTMFSendIsInFlight is D10's other direction:
// the claim is refused while dtmfSendInFlight. The INFO send is parked on its
// inter-digit gap (the fake clock's ONE waiter, as in
// TestSendDTMFInfoHonoursANonzeroGapBetweenDigits) so the claim lands
// deterministically inside the send.
func TestAControlOpIsRefusedWhileADTMFSendIsInFlight(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newDirectUA(t, clk)
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)

	done := make(chan error, 1)
	go func() {
		_, _, err := ua.SendDTMF(context.Background(), res.DialogID, "12", session.DTMFModeInfo, 100, 20)
		done <- err
	}()
	clk.BlockUntil(1)
	_, _, err := sipua.ClaimControlOpForTest(ua, res.DialogID)
	if err == nil || apierr.CodeOf(err) != apierr.CodePreconditionFailed ||
		!strings.Contains(err.Error(), "dtmf_send is in progress") {
		t.Fatalf("claim during dtmf_send err=%v want precondition_failed naming dtmf_send", err)
	}
	clk.Advance(20 * time.Millisecond)
	if err := <-done; err != nil {
		t.Fatalf("SendDTMF: %v", err)
	}
	if inControlOp(ua, res.DialogID) {
		t.Fatal("a refused claim left the dialog in phaseControlOp")
	}
}

// TestPeerInDialogRequestsAreAnsweredDuringAControlOp is Review Focus #5 and
// D4: a 481 to any of these is TERMINAL to the dialog (RFC 3261 §12.2.1.2),
// and Asterisk re-INVITEs during transfers.
func TestPeerInDialogRequestsAreAnsweredDuringAControlOp(t *testing.T) {
	for _, tc := range []struct {
		method string
		send   func(t *testing.T, p *peer.Peer)
	}{
		{"UPDATE", func(t *testing.T, p *peer.Peer) { p.SendUPDATEToCaller(t, "") }},
		{"INVITE", func(t *testing.T, p *peer.Peer) { p.SendReInviteToCaller(t) }},
		{"INFO", func(t *testing.T, p *peer.Peer) { p.SendToCaller(t, sip.INFO, nil, nil) }},
	} {
		t.Run(tc.method, func(t *testing.T) {
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
			ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
			events := collect(t, ua)
			res := dialAnswered(t, ua, p, events)
			_, release := claimControlOp(t, ua, res.DialogID)
			defer release()

			tc.send(t, p)
			waitForCond(t, func() bool { return p.LastResponseStatus(tc.method) != 0 })
			if got := p.LastResponseStatus(tc.method); got != 200 {
				t.Fatalf("in-dialog %s during a control op drew %d, want 200 — a 481 here "+
					"tears the call down in the middle of the transfer", tc.method, got)
			}
		})
	}
}

// TestTeardownDuringAControlOpClosesItsEndedChannel pins endControlOpLocked at
// every teardown path reachable from phaseControlOp, and D2's "internal
// teardown preempts": a local Hangup during a control op SUCCEEDS and puts a
// BYE on the wire.
func TestTeardownDuringAControlOpClosesItsEndedChannel(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(t *testing.T, ua *sipua.UA, p *peer.Peer, dialogID string)
	}{
		{"peer BYE", func(t *testing.T, _ *sipua.UA, p *peer.Peer, _ string) { p.SendBye(t) }},
		{"local hangup", func(t *testing.T, ua *sipua.UA, p *peer.Peer, dialogID string) {
			if err := ua.Hangup(context.Background(), dialogID, ""); err != nil {
				t.Fatalf("Hangup during a control op: %v — shutdown, ua_destroy and the "+
					"session-timer watchdog must still be able to end the dialog (D2)", err)
			}
			if p.ByeCount() != 1 {
				t.Fatalf("%d BYEs, want 1", p.ByeCount())
			}
		}},
		{"UA close", func(_ *testing.T, ua *sipua.UA, _ *peer.Peer, _ string) {
			_ = ua.Close(context.Background())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
			ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
			events := collect(t, ua)
			res := dialAnswered(t, ua, p, events)
			ended, _ := claimControlOp(t, ua, res.DialogID)

			tc.end(t, ua, p, res.DialogID)
			waitClosed(t, ended, tc.name)
			if inControlOp(ua, res.DialogID) {
				t.Fatal("ControlOpState reports the dialog held after it was torn down")
			}
		})
	}
}

// TestWeStillRefreshTheSessionDuringAControlOp is D4: if our RFC 4028 refresh
// were refused during a control op, the refresher would give up silently and
// the peer would end the call at expiry.
func TestWeStillRefreshTheSessionDuringAControlOp(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 60)
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)
	_, release := claimControlOp(t, ua, res.DialogID)
	defer release()

	clk.BlockUntil(1) // the session refresher is the only fake-clock waiter
	clk.Advance(46 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
	if ev := waitFor(t, events, session.UAEventSessionRefresh, 0); ev.Detail["code"] != 200 {
		t.Fatalf("session_refresh detail=%+v want code 200", ev.Detail)
	}
}

// TestPeerRefreshRearmsTheWatchdogDuringAControlOp: startSessionWatchdog stops
// the old watchdog BEFORE its store re-check, so an un-widened re-check would
// leave the dialog with no watchdog at all.
func TestPeerRefreshRearmsTheWatchdogDuringAControlOp(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: "90;refresher=uas"},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 90)
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)
	_, release := claimControlOp(t, ua, res.DialogID)
	defer release()

	clk.BlockUntil(1) // the watchdog
	clk.Advance(50 * time.Second)
	before := len(p.ResponseCodes())
	p.SendUPDATEToCaller(t, "90;refresher=uac", sip.NewHeader("Supported", "timer"))
	waitForCond(t, func() bool { return len(p.ResponseCodes()) > before })
	assertWatchdogRearmed(t, ua, res.DialogID, 0)
}

// TestInDialogTimeoutDuringAControlOpStillReleasesTheDialog mirrors
// TestARefreshThatDrawsNoResponseEndsTheCallInDialogTimeout with a control op
// held across the unanswered refresh.
func TestInDialogTimeoutDuringAControlOpStillReleasesTheDialog(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, UPDATE",
			SwallowUpdate:        true,
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUAWithTimeout(t, clk, 1800, 90, 500*time.Millisecond)
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)
	ended, _ := claimControlOp(t, ua, res.DialogID)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	ev := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ev.Cause != session.UACauseTransportFailure {
		t.Fatalf("cause=%q want transport_failure", ev.Cause)
	}
	waitClosed(t, ended, "in-dialog timeout")
}
