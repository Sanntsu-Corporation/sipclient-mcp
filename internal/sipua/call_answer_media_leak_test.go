package sipua

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	sippeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// failOnceRespondSpy wraps the dialog's real sip.ServerTransaction and fails
// the FIRST final (>=200) response written to it, then behaves exactly like
// the real transaction on every subsequent call. Embedding — not
// reimplementation — is what makes this safe, mirroring
// call_answerclaim_test.go's respondSpy and call_transport_param_test.go's
// contactCaptureSpy: only Respond is observed/altered, and only once.
type failOnceRespondSpy struct {
	sip.ServerTransaction
	failed bool
}

func (s *failOnceRespondSpy) Respond(res *sip.Response) error {
	if res.StatusCode >= 200 && !s.failed {
		s.failed = true
		return errors.New("simulated wire-write failure")
	}
	return s.ServerTransaction.Respond(res)
}

// waitForPhaseRinging polls d.phase (under ua.calls.mu, matching every other
// phase read in this file) until it observes phaseRinging or the timeout
// elapses, then fails the test. It exists because OnAdmit's callback fires —
// and can unblock this test's goroutine — BEFORE the dialog's
// phaseAdmitting -> phaseRinging flip (see export_test.go's AnswerEventually
// doc comment for the window). Answer now waits that window out itself, so
// waiting for phaseRinging here is redundant; it is kept so the test's first
// Answer() call is the first and only claim, and observes the real tx.Respond
// failure it is testing for.
func waitForPhaseRinging(t *testing.T, ua *UA, d *dialog) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		ua.calls.mu.Lock()
		phase := d.phase
		ua.calls.mu.Unlock()
		if phase == phaseRinging {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("dialog did not reach phaseRinging within timeout; phase = %d", phase)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestAnswerClosesMediaSocketWhenRespondFails is the regression gate for the
// resource leak a Rule 9 verifier found in e4b726e ("feat(sipua): Answer()
// negotiates via media.BuildAnswer, 488 via teardownDialog (M5)").
//
// Answer binds a real UDP media socket via bindMediaPort and stores it on
// d.mediaConn BEFORE calling media.BuildAnswer, so that teardownDialog can
// release it on the media.NegotiationError / plain-error paths. That part is
// correct. But on the FINAL happy-path branch — negotiation succeeds, the 200
// OK is built, and tx.Respond(res) itself then fails (a wire-write error) —
// the pre-fix code reset d.phase back to phaseRinging (via
// releaseAnsweringClaim) and returned the error WITHOUT closing or clearing
// d.mediaConn. Consequences: (a) the bound socket leaked forever, since
// nothing closes it while the dialog sits phaseRinging in the registry rather
// than being torn down; (b) a retried Answer() on the same dialog would bind
// a SECOND socket via bindMediaPort and unconditionally overwrite
// d.mediaConn, permanently leaking the first.
//
// This test drives that exact path with a spy that fails only the first
// Respond (the 200 OK write) and asserts d.mediaConn/d.mediaSession are nil
// immediately afterward — proving the fix closes and clears them — then
// retries Answer() on the SAME dialog and asserts it succeeds cleanly,
// proving no permanent state corruption (the leaked-socket-overwrite hazard)
// survives the first failure. Before the fix, the FIRST assertion below
// (leaked == nil) fails: d.mediaConn is left populated with a socket nothing
// will ever close.
func TestAnswerClosesMediaSocketWhenRespondFails(t *testing.T) {
	p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newClaimTestUA(t, clk)

	inbound := make(chan session.UAEvent, 8)
	ua.OnAdmit(context.Background(), func(_ context.Context, ev session.UAEvent) session.Admission {
		inbound <- ev
		return session.AdmitAccept()
	})

	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	var in session.UAEvent
	select {
	case in = <-inbound:
	case <-time.After(3 * time.Second):
		t.Fatal("no inbound event; the peer's INVITE never reached the UA")
	}

	d, err := ua.lookup(in.DialogID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	// Install the spy in place of the dialog's real server transaction, as
	// call_answerclaim_test.go and call_transport_param_test.go both do.
	spy := &failOnceRespondSpy{}
	ua.calls.mu.Lock()
	spy.ServerTransaction = d.serverTx
	d.serverTx = spy
	ua.calls.mu.Unlock()

	// Wait for the dialog to actually reach phaseRinging (the 180 confirmed on
	// the wire) before issuing the spy-guarded Answer below, kept for
	// determinism: Answer would wait out the admission itself, but the test
	// wants the first Answer to be the first and only claim.
	waitForPhaseRinging(t, ua, d)

	// First Answer: media negotiation succeeds (default PCMU offer/answer),
	// but the spy fails the 200 OK write.
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err == nil {
		t.Fatal("Answer succeeded despite the spy failing tx.Respond; test setup is broken")
	}

	ua.calls.mu.Lock()
	leakedConn, leakedSession, gotPhase := d.mediaConn, d.mediaSession, d.phase
	ua.calls.mu.Unlock()
	if leakedConn != nil {
		t.Errorf("d.mediaConn = %v after a failed tx.Respond, want nil: the socket bound "+
			"before BuildAnswer leaks because nothing else closes it while the dialog "+
			"stays phaseRinging", leakedConn)
	}
	if leakedSession != nil {
		t.Errorf("d.mediaSession = %v after a failed tx.Respond, want nil", leakedSession)
	}
	if gotPhase != phaseRinging {
		t.Fatalf("phase after a failed tx.Respond = %d, want phaseRinging (%d) so the "+
			"dialog stays retryable via call_answer", gotPhase, phaseRinging)
	}

	// Retried Answer on the SAME dialog. Without the fix, bindMediaPort would
	// bind a second socket here and unconditionally overwrite d.mediaConn,
	// permanently leaking the first (already-leaked) one; that corruption
	// wouldn't necessarily fail this retry, which is why the direct nil
	// assertion above is the load-bearing check. This second half instead
	// pins that the retry itself still succeeds cleanly.
	if err := ua.AnswerEventually(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("retried Answer failed: %v", err)
	}

	ua.calls.mu.Lock()
	finalConn, finalPhase := d.mediaConn, d.phase
	ua.calls.mu.Unlock()
	if finalConn == nil {
		t.Error("d.mediaConn is nil after a successful retried Answer; want the newly bound socket")
	}
	if finalPhase != phaseAnswered {
		t.Errorf("phase after retried Answer = %d, want phaseAnswered (%d)", finalPhase, phaseAnswered)
	}
}
