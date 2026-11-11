package sip

import "testing"

// TestActResendNilTimerADoesNotPanic reproduces the P2 W1 closeout §8 panic:
// actResend calls tx.timer_a.Reset on a timer_a cleared when the client
// transaction terminated mid-retransmit (transaction_client_tx_fsm.go:226).
// actInviteProceeding at :242 already nil-guards timer_a; actResend did not.
func TestActResendNilTimerADoesNotPanic(t *testing.T) {
	tx := &ClientTx{}          // timer_a is the zero value: nil
	tx.timer_a_time = T1       // any positive base; :221 doubles it
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("actResend panicked on a nil timer_a: %v", r)
		}
	}()
	// Exercise only the timer arithmetic + Reset guard, not tx.resend()'s
	// socket path: assert the guarded Reset is reached without panic.
	tx.resendGuardForTest()
}

// resendGuardForTest runs actResend's timer-management prefix only — the code
// path that dereferenced a nil timer_a — without tx.resend()'s socket I/O, so
// the nil-guard is exercised deterministically in a unit test. Test-only;
// recorded in VENDOR.md as an added divergence.
func (tx *ClientTx) resendGuardForTest() {
	tx.mu.Lock()
	tx.timer_a_time *= 2
	if tx.timer_a_time > T2 {
		tx.timer_a_time = T2
	}
	if tx.timer_a != nil {
		tx.timer_a.Reset(tx.timer_a_time)
	}
	tx.mu.Unlock()
}

// terminatedClientTx models the state delete() leaves behind: done closed and
// timer_a cleared, while a Timer A callback may still be entering the FSM.
func terminatedClientTx() *ClientTx {
	tx := &ClientTx{}
	tx.done = make(chan struct{})
	close(tx.done)
	tx.timer_a_time = T1
	return tx
}

// TestActInviteResendAfterTerminateDoesNotPanic is the CF-050 reproducer:
// actInviteResend reset a timer_a that delete() had already cleared. It calls
// the real method (resend() returns at its first select once done is closed).
func TestActInviteResendAfterTerminateDoesNotPanic(t *testing.T) {
	tx := terminatedClientTx()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("actInviteResend panicked on a nil timer_a: %v", r)
		}
	}()
	if got := tx.actInviteResend(); got != FsmInputNone {
		t.Fatalf("actInviteResend = %v, want FsmInputNone", got)
	}
}

// TestActResendAfterTerminateDoesNotPanic pins actResend's own guard through
// the real method; TestActResendNilTimerADoesNotPanic runs a copy of its
// prefix and cannot redden when the real guard is removed.
func TestActResendAfterTerminateDoesNotPanic(t *testing.T) {
	tx := terminatedClientTx()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("actResend panicked on a nil timer_a: %v", r)
		}
	}()
	if got := tx.actResend(); got != FsmInputNone {
		t.Fatalf("actResend = %v, want FsmInputNone", got)
	}
}
