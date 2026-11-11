package sipua

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// CF-096 (I7): with the inbound INVITE transaction live until it ends, a
// CANCEL that lands after Answer or Reject has claimed its final but before
// writing it reaches the transaction's OnCancel hook. The hook's claim fails,
// so it vetoes sipgo's automatic 487 and the TU's final wins: the CANCEL gets
// its 200 and nothing else. The window is forced through respondSpy
// (call_answerclaim_test.go) on the raceRig (call_answer_hangup_race_test.go).

// cancelInsideTheWrite sends the peer's CANCEL from inside the first final's
// Respond and waits for the CANCEL's 200, so the CANCEL is fully handled
// before the final is written. No t.Fatal: this runs inside Answer/Reject.
func (r *raceRig) cancelInsideTheWrite() {
	r.spy.duringFirstRespond = func() {
		r.p.SendCancel(r.t)
		deadline := time.Now().Add(2 * time.Second)
		for r.p.CancelFinalCode() == 0 {
			if time.Now().After(deadline) {
				r.t.Error("no final to the CANCEL within 2s")
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
}

func (r *raceRig) assertTUFinalWon(want int) {
	t := r.t
	t.Helper()
	if code := r.p.CancelFinalCode(); code != 200 {
		t.Errorf("CANCEL final = %d, want 200", code)
	}
	if code := r.p.WaitForInviteFinal(t, 2*time.Second); code != want {
		t.Errorf("INVITE final = %d, want %d (the TU's final must win)", code, want)
	}
	time.Sleep(100 * time.Millisecond) // bounded window for a stray 487 or event
	if hasCode(r.p.ResponseCodes(), 487) {
		t.Errorf("a 487 went out (codes %v); the hook must veto sipgo's 487 when its claim fails", r.p.ResponseCodes())
	}
	for _, ev := range r.dialogEnded() {
		if ev.Cause == session.UACauseCancelled {
			t.Errorf("a cancelled event was emitted (%v); the TU's final won", ev)
		}
	}
}

func TestCancelDuringAnswerWriteLetsThe200Win(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	r.cancelInsideTheWrite()
	if err := r.answer(); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	r.assertTUFinalWon(200)
	r.ua.calls.mu.Lock()
	phase := r.d.phase
	r.ua.calls.mu.Unlock()
	if phase != phaseAnswered {
		t.Errorf("phase = %d, want phaseAnswered", phase)
	}
}

func TestCancelDuringRejectWriteLetsTheRejectWin(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	r.cancelInsideTheWrite()
	if err := r.ua.Reject(context.Background(), r.id, 486, ""); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	r.assertTUFinalWon(486)
}
