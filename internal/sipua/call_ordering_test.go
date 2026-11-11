package sipua_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// isCode reports whether err is an *apierr.Error carrying code c.
func isCode(err error, c apierr.Code) bool {
	var ae *apierr.Error
	return errors.As(err, &ae) && ae.Code == c
}

// A call_answer that races in during phaseAdmitting (an admit handler that
// blocks until the test releases it, i.e. before the 180 is on the wire) waits
// for the admission to finish and then answers: no 200 may precede the 180
// (M2), and the call is answerable the moment the session can see it (CF-052).
func TestAnswerDuringAdmittingWaitsAndAnswersAfterThe180(t *testing.T) {
	h := holdAdmission(t)

	res := h.goAnswer(context.Background())
	h.requireStillWaiting(t, res)

	h.open()
	if err := h.await(t, res); err != nil {
		t.Fatalf("Answer after the admission finished = %v, want nil", err)
	}
	h.waitCodes(t, 100, 180, 200)
	if got := h.p.InviteFinalCode(); got != 200 {
		t.Fatalf("INVITE final = %d, want 200", got)
	}
}

// A CANCEL arriving while the dialog is held in phaseAdmitting (admit still
// blocked, no 180 yet) must terminate the pending call and emit
// UACauseCancelled. The 200-on-CANCEL and 487-on-INVITE seen on the wire are
// sipgo's OWN transaction-layer output (actCancel), because the INVITE
// ServerTx is still registered while onInvite is blocked in admit() — the
// srv-level onCancel is never reached for this case. sipua's contribution is
// the tx.OnCancel hook onInvite registers: it claims the dialog and emits
// UACauseCancelled (and deliberately sends NO 487 of its own). Before this
// fix, no hook was registered, so the wire got sipgo's auto-487/200 but
// session never learned the call ended and any call_wait hung forever.
func TestCancelDuringAdmitting487sAndEmitsCancelled(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	release := make(chan struct{})
	defer close(release)
	admitted := make(chan struct{}, 1)
	ua.OnAdmit(context.Background(), func(_ context.Context, _ session.UAEvent) session.Admission {
		select {
		case admitted <- struct{}{}:
		default:
		}
		<-release // widen the phaseAdmitting window deterministically
		return session.AdmitAccept()
	})

	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	select {
	case <-admitted:
	case <-time.After(2 * time.Second):
		t.Fatal("admit handler never ran")
	}

	// CANCEL arrives while admit is still blocked (dialog is phaseAdmitting,
	// INVITE ServerTx still registered -> intercepted by sipgo's actCancel).
	p.SendCancel(t)

	if code := p.WaitForCancelFinal(t, 2*time.Second); code != 200 {
		t.Fatalf("CANCEL transaction: want 200 (sipgo auto), got %d", code)
	}
	if code := p.WaitForInviteFinal(t, 2*time.Second); code != 487 {
		t.Fatalf("pending INVITE: want 487 Request Terminated (sipgo auto), got %d", code)
	}
	// sipua's own bookkeeping: the tx.OnCancel hook must emit this, or session
	// never learns the call ended.
	ended := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ended.Cause != session.UACauseCancelled {
		t.Fatalf("cause=%q want cancelled", ended.Cause)
	}
}
