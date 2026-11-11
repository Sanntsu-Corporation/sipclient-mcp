package sipua

// The shared call-control-operation guard (spec 2026-09-26 §3). ONE phase,
// phaseControlOp (call.go), held by whichever control operation is running on a
// dialog: call_transfer today (transfer.go), call-hold's re-INVITE next. Every
// helper here requires the caller to hold u.calls.mu, except ControlOpState and
// ControlOpBlocksHangup, which take it themselves.
//
// OPERATION-NEUTRAL BY CONSTRUCTION (plan D15): nothing in this file names a
// specific operation. The owner passes its session.ControlOpKind when it claims,
// and ControlOpState/ControlOpBlocksHangup report it. Wording specific to one
// tool, such as a transfer's "retry once call_transfer has returned", belongs
// to the caller that explains a refusal (session's controlOpHangupRefusal),
// never here.

import (
	"fmt"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// controlOpBusyMsg is the precondition_failed text every refused operation
// carries, prefixed with its own tool name. Generic on purpose: the operation
// holding the dialog may be a transfer or (from the hold plan) a hold.
const controlOpBusyMsg = "a call control operation is in progress on this call"

// dialogEstablished reports whether a dialog is live and confirmed: answered,
// or answered and running a control operation. It is the predicate every "is
// this dialog still up?" check uses — peer in-dialog requests are answered,
// session-timer maintenance proceeds, and teardown paths still claim the
// dialog. Operator-initiated "may I start X now?" checks require phaseAnswered
// exactly and are NOT expressed with it.
func dialogEstablished(p phase) bool { return p == phaseAnswered || p == phaseControlOp }

// claimControlOpLocked moves an answered dialog into phaseControlOp for the
// caller, recording kind (reported by ControlOpState), and returns the channel a
// teardown closes if the dialog ends while the operation runs. op prefixes the
// error, e.g. "call_transfer". Refused with precondition_failed when another
// control operation holds the dialog, when the dialog is not answered, when a
// dtmf_send is in flight (D10 — SendDTMF refuses phaseControlOp under this same
// lock, so the two exclude each other), or while an offerless INVITE's answer
// is still awaited in its ACK or its media loop is still starting.
func claimControlOpLocked(d *dialog, kind session.ControlOpKind, op string) (<-chan struct{}, error) {
	switch {
	case d.phase == phaseControlOp:
		return nil, apierr.PreconditionFailed(op + ": " + controlOpBusyMsg)
	case d.phase != phaseAnswered:
		return nil, apierr.PreconditionFailed(fmt.Sprintf(
			"%s: dialog is in phase %d; only an answered call can run a control operation", op, d.phase))
	case d.dtmfSendInFlight:
		return nil, apierr.PreconditionFailed(op + ": a dtmf_send is in progress on this call")
	case d.mediaAwaitingAnswer:
		// CF-145: onAck ignores an ACK in phaseControlOp, so a claim before
		// the ACK of an offerless INVITE would lose its answer (no media).
		return nil, apierr.PreconditionFailed(op +
			": the caller's ACK carrying the media answer has not arrived yet; retry once it has")
	case d.mediaStarting:
		// A claim before startMediaLoop publishes would make it drop the loop.
		return nil, apierr.PreconditionFailed(op +
			": media for this call is still starting; retry shortly")
	}
	d.phase = phaseControlOp
	d.controlOpKind = kind
	d.controlOpBlocksHangup = true // D17: until the owner says otherwise
	d.controlOpEnded = make(chan struct{})
	return d.controlOpEnded, nil
}

// releaseControlOpLocked is the owner's release when its operation concludes
// (success, failure or timeout): back to phaseAnswered — never straight to
// phaseDone. On a dialog a teardown already ended (phaseDone) it only clears
// the already-cleared state, so a late release is harmless. It also ends the
// dialog's arrival-order gate scope (arrival.go; Rule 13 fix batch A, finding 4).
func releaseControlOpLocked(d *dialog) {
	if d.phase == phaseControlOp {
		d.phase = phaseAnswered
	}
	d.arrivals.resetLocked()
	d.controlOpEnded = nil
	d.controlOpKind = ""
	d.controlOpBlocksHangup = false
}

// allowHangupDuringControlOpLocked is the OWNER's statement that the call_hangup
// tool may end the dialog from now on, although the operation is still running
// (plan D17, spec §3 amendment). The dialog stays in phaseControlOp, so every
// other guarded operation is still refused. A hangup then ends the dialog through
// hangupWithReason, which settles the owner via endControlOpByLocalHangupLocked.
// A no-op outside phaseControlOp, so an owner racing a teardown is harmless.
// Called from transfer.go's Transfer once its REFER is accepted.
func allowHangupDuringControlOpLocked(d *dialog) {
	if d.phase == phaseControlOp {
		d.controlOpBlocksHangup = false
	}
}

// endControlOpLocked is every teardown path's half: called in the SAME critical
// section that sets phaseDone, it wakes the operation's owner. A no-op when no
// control operation is running.
func endControlOpLocked(d *dialog) {
	if d.controlOpEnded != nil {
		close(d.controlOpEnded)
		d.controlOpEnded = nil
	}
	d.controlOpKind = ""
	d.controlOpBlocksHangup = false
}

// endControlOpByLocalHangupLocked is hangupWithReason's variant of
// endControlOpLocked: it first records that THIS UA's own BYE is what ended the
// dialog, so an owner woken by controlOpEnded can report that distinctly (plan
// D17). The record is written before the close, under the same lock, so an owner
// that reads it under u.calls.mu after <-ended always sees it.
func endControlOpByLocalHangupLocked(d *dialog) {
	if d.controlOpEnded != nil {
		d.controlOpEndedByHangup = true
	}
	endControlOpLocked(d)
}

// ControlOpState reports which call control operation currently holds
// dialogID, if any. ("", false) for an unknown dialog or one no operation holds.
// It is the broad, operation-neutral view (plan D15). session's call_hangup
// deliberately does NOT use it: it uses the narrower ControlOpBlocksHangup
// below (D17).
func (u *UA) ControlOpState(dialogID string) (kind session.ControlOpKind, inFlight bool) {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	d, ok := u.calls.byID[dialogID]
	if !ok || d.phase != phaseControlOp {
		return "", false
	}
	return d.controlOpKind, true
}

// ControlOpBlocksHangup implements session.UserAgent.ControlOpBlocksHangup: the
// control operation holding dialogID, if it currently needs the call_hangup
// TOOL refused (plan D17). This is narrower than ControlOpState. A transfer
// blocks hangup only until its REFER is accepted, then keeps the dialog in
// phaseControlOp for the NOTIFY outcome with hangup allowed. ("", false) for an
// unknown dialog, one no operation holds, or one whose owner allowed hangup.
// session's call_hangup reads it BEFORE its own termination claim (D2) and
// phrases the refusal from kind (D15).
func (u *UA) ControlOpBlocksHangup(dialogID string) (kind session.ControlOpKind, blocked bool) {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	d, ok := u.calls.byID[dialogID]
	if !ok || d.phase != phaseControlOp || !d.controlOpBlocksHangup {
		return "", false
	}
	return d.controlOpKind, true
}
