package sipua

import (
	"net"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// teardownDialog is the single resource-release path shared by the W3 rejection
// sites (M1): admission-reject in onInvite, the answer-side 488 in Answer, and
// the offering-side ACK-then-BYE in runDial. It releases the SAME resources —
// the registry entry, the ring timer, and the media socket — through one code
// path, even though each caller writes different bytes on the wire itself. It
// puts NO bytes on the wire and emits NO UAEvent: those are the caller's,
// precisely because they differ per site.
//
// It returns d.cancelRequested as read inside its own critical section — the
// timeout/hangup linearization point endFailedDial relies on. Its other callers
// discard it, Answer's included: an inbound phaseAnswering dialog can carry
// cancelRequested (CF-041) and Answer's sections have already ended the call.
func (u *UA) teardownDialog(d *dialog) bool {
	u.calls.mu.Lock()
	d.phase = phaseDone
	hungUp := d.cancelRequested
	u.forgetLocked(d.id)
	if d.ringTimer != nil {
		d.ringTimer.Stop()
	}
	ml, conn := d.mediaLoop, d.mediaConn
	d.mediaLoop, d.mediaConn = nil, nil
	// The dial settled without a deferred CANCEL: wake the Hangup waiting for one.
	if d.cancelWait != nil {
		close(d.cancelWait)
		d.cancelWait = nil
	}
	u.calls.mu.Unlock()
	// stop() closes the conn; only close directly on the pre-answer paths that
	// bound a socket but never started a loop.
	if ml != nil {
		ml.stop()
	} else if conn != nil {
		_ = conn.Close()
	}
	// Step 6/Correction 9: disarm the session timer alongside the media loop,
	// OUTSIDE u.calls.mu — refresher.Stop() waits for a goroutine that may be
	// inside refreshSession, which takes that lock.
	u.stopSessionTimer(d)
	return hungUp
}

// endFailedDial ends an outbound dial that drew no usable final response (the
// INVITE transaction timed out, or the mandatory ACK could not be written). It
// releases ONLY this dialog and emits a DIALOG-SCOPED end, so a sibling call on
// the same UA and its media are untouched (CF-037, D-A); the UA-wide
// UAEventTransportFault is not used. session maps the end onto
// terminated/transport_failure with a nil-detail error event, the same outcome
// the UA-wide sweep gave the timed-out call itself.
//
// When the caller already hung up (cancelRequested, read at teardownDialog's
// linearization point) session has claimed the call and nothing is emitted. A
// hangup the session claimed first but that reached sipua only after this
// teardown is unknowable here; session drops the end (live-only lookup and
// TryTransportFailure's terminal() guard).
func (u *UA) endFailedDial(d *dialog, reason string, err error) {
	if failedDialHook != nil {
		failedDialHook()
	}
	hungUp := u.teardownDialog(d)
	u.log().Warn("dial ended without a usable final response; dialog released",
		"dialog_id", d.id, "call_id", d.callID, "reason", reason, "err", err)
	if hungUp {
		return
	}
	u.emit(session.UAEvent{Kind: session.UAEventDialogEnded, Cause: session.UACauseTransportFailure,
		DialogID: d.id, CallID: d.callID, Direction: session.Outbound,
		Reason: reason, Err: err, At: u.cfg.Clock.Now()})
}

// stopAllMediaLoops tears down every phaseAnswered dialog's media loop when the
// UA's own lifetime ends: Close calls it directly (closing=true), and the
// uaCtx.Done() watcher calls it (closing=false) when the daemonCtx uaCtx is
// derived from is cancelled directly, which is how the loopback test harness
// tears down. It is the 4th teardown call site:
// mediaLoop's own doc comment names only teardownDialog/Hangup/onBye as
// "every current call site" — that enumeration was incomplete. A dialog that
// reached phaseAnswered and was never explicitly hung up or peer-BYE'd kept its
// mediaLoop's two goroutines (and UDP media socket) running forever, past the
// UA's own teardown, because none of those three ever ran for it. Found via
// TestConflictingToolCallPairsResolveToExactlyOneWinner: its
// two_call_answer_on_one_ringing_call and call_answer_racing_call_reject
// subtests never hang up their winning call, so every iteration leaked a
// mediaLoop; over 1000 iterations sharing one test binary process that starved
// the process enough to cause real UDP retransmissions (observed at the peer as
// duplicate final responses / duplicate BYEs) and outright hangs in later
// subtests.
//
// Snapshot-and-nil every live dialog's media fields under u.calls.mu, release
// the lock, THEN stop()/Close() outside it — mirrors
// teardownDialog/Hangup/onBye exactly and preserves stop()'s own invariant
// (never called while holding u.calls.mu).
//
// closing is true only from Close (CF-061): in the same critical section it
// sets u.calls.closed and, if it is the sweep that set it, TAKES OVER every
// established dialog it ends: each one's BYE is counted in u.calls.byes and the
// dialog is returned, for Close to send that one BYE while the transport is
// still open. The watcher passes false: no BYE, closed left unset, as before.
// Every non-established phase is skipped either way.
func (u *UA) stopAllMediaLoops(closing bool) []*dialog {
	// Correction 9: pending carries *dialog too, alongside ml/conn — without
	// it there is nothing left to pass to stopSessionTimer once the critical
	// section below has released d back out of the registry.
	type pending struct {
		d    *dialog
		ml   *mediaLoop
		conn *net.UDPConn
	}
	u.calls.mu.Lock()
	takeOver := closing && !u.calls.closed
	if closing {
		u.calls.closed = true
	}
	var toClose []pending
	var owed []*dialog
	for _, d := range u.calls.byID {
		if !dialogEstablished(d.phase) {
			continue
		}
		d.phase = phaseDone
		endControlOpLocked(d)
		u.forgetLocked(d.id)
		ml, conn := d.mediaLoop, d.mediaConn
		d.mediaLoop, d.mediaConn = nil, nil
		toClose = append(toClose, pending{d, ml, conn})
		if takeOver {
			owed = append(owed, d)
			u.calls.byes.Add(1)
		}
	}
	u.calls.mu.Unlock()
	for _, p := range toClose {
		if p.ml != nil {
			p.ml.stop()
		} else if p.conn != nil {
			_ = p.conn.Close()
		}
		u.stopSessionTimer(p.d)
	}
	return owed
}

// claimAdmitting atomically wins an inbound dialog still in phaseAdmitting for
// the caller, marking it phaseDone so the other transitioners reachable before
// the ring timer is armed — a concurrent tx.OnCancel hook or an early BYE —
// cannot also resolve it. It returns false when the dialog is no longer
// phaseAdmitting, meaning one of them already claimed it and writes the 487
// itself (finishInboundCancel, onBye), so the caller must send no second
// final. The caller still calls teardownDialog to forget the registry
// entry and stop the timer.
func (u *UA) claimAdmitting(d *dialog) bool {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if d.phase != phaseAdmitting {
		return false
	}
	d.phase = phaseDone
	return true
}

// claimForCancel is the tx.OnCancel hook's atomic claim-AND-teardown. sipgo's
// actCancel (third_party/sipgo/sip/transaction_server_tx_fsm.go) runs the hook
// under the transaction's FSM lock, and the hook always vetoes sipgo's own 487
// (CF-096), so nothing is on the wire for the INVITE here (the CANCEL's own 200
// is written by the transaction layer after tx.Receive returns,
// transaction_layer.go handleRequest); this only settles sipua's own state. It
// wins a dialog in phaseAdmitting or phaseRinging: onInvite holds an initial
// INVITE's transaction until it ends, so a CANCEL in either phase routes
// through actCancel to the hook rather than to srv-level onCancel. On a win it
// marks the dialog phaseDone, forgets the registry entry and stops the ring
// timer in ONE critical section, and returns true so the hook hands exactly one
// 487 and one UACauseCancelled to finishInboundCancel. It returns false when a
// concurrent terminator — Answer, Reject, the reject path's claimAdmitting, the
// ring timeout, a 603, an early BYE or srv-level onCancel — already resolved
// the dialog, so the hook sends nothing and that terminator's final goes out.
func (u *UA) claimForCancel(d *dialog) bool {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if d.phase != phaseAdmitting && d.phase != phaseRinging {
		return false
	}
	d.phase = phaseDone
	u.forgetLocked(d.id)
	if d.ringTimer != nil {
		d.ringTimer.Stop()
	}
	return true
}
