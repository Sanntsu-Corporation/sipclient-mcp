package sipua

// Rule 16 reuse decision for this file:
//
//   REUSED: sendInDialog (indialog.go) — the REFER's CSeq, Via, Contact and
//           From/To orientation (buildInDialogRequest, UNCHANGED) AND its
//           wire-order guarantee against every other in-dialog request on the
//           dialog, exactly as BYE/INFO/UPDATE use it (plan D12);
//           claimControlOpLocked/releaseControlOpLocked (controlop.go) — the
//           shared guard; consultReferToLocked, peerTagLocked and friends
//           (refer.go); findByCallIDLocked/callIDOf/toTagOf/fromTagOf/
//           ourReInviteTagLocked (call.go) — onNotify's dialog match, onUpdate's
//           match plus the From-tag (D13); classifyCtxErr (dtmf.go).
//   NOT REUSED: sipgo's DialogClientSession / newByeRequestUAC — mirrored
//           natively (spec §2, locked decision 6).

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// The six "no wire status" final reasons, reported with status_code 0. They
// are part of the documented contract (master spec §10.14); tests assert them
// verbatim.
const (
	referReasonNoResponse = "REFER drew no final response"
	referReasonNotSent    = "the REFER could not be dispatched"
	referReasonTimeout    = "no final NOTIFY before the transfer outcome deadline"
	referReasonEnded      = "the dialog ended before a final NOTIFY"
	// referReasonHungUp: THIS UA's own BYE ended the call while the outcome was
	// pending — call_hangup (allowed once the REFER is accepted, plan D17),
	// ua_destroy/shutdown, or the RFC 4028 watchdog.
	referReasonHungUp   = "the transferor hung up before a final NOTIFY"
	referReasonUAClosed = "the user agent closed before a final NOTIFY"
)

// referReasonMaxLen bounds any peer-supplied reason text (a REFER's own final
// response reason phrase, or a NOTIFY's parseSipfrag reason) before it reaches
// a transfer event's Detail or the ring-log — a hostile or misbehaving peer
// could otherwise send an arbitrarily large sipfrag reason line (CF-006).
// Truncated, not rejected: unlike timeout_ms (dtmf.go's dtmfMaxDurationMs
// comment states this codebase's "reject, never silently clamp" convention
// for load-bearing API parameters), a reason phrase is advisory text that must
// still be accepted and reported on a live dialog (D6) — 256 bytes
// comfortably fits any real status phrase or sipfrag reason line while
// bounding the worst case.
const referReasonMaxLen = 256

// capReferReason truncates s to at most referReasonMaxLen bytes, backing off
// to the last full rune boundary at or before the cut (Cycle C round 4 fix):
// a raw byte-offset cut (s[:referReasonMaxLen]) can split a multi-byte UTF-8
// rune in half, leaving an invalid string that later JSON serialization would
// silently mangle. CF-019: this is applied exactly ONCE at each of the two
// points where a peer-supplied reason string enters this subsystem — Transfer's
// own read of a REFER response's res.Reason, and onNotify's read of a NOTIFY's
// parsed sipfrag reason — so every downstream consumer (both of Transfer's
// branches, concludeRefer, emitReferProvisional) already holds a safe value and
// none of them cap it again.
func capReferReason(s string) string {
	return capAtRuneBoundary(s, referReasonMaxLen)
}

// capAtRuneBoundary truncates s to at most maxLen bytes, backing off to the last
// full rune boundary at or before the cut, exactly as capReferReason needs —
// factored out (Rule 16 reuse) so a second peer-controlled value that is not a
// "reason" (onNotify's from_tag logging, CF-021) can share the same safe
// truncation under a name that fits it. utf8.RuneStart (Rule 16 reuse — the
// standard library already solves this) reports whether a byte could begin an
// encoded rune, so scanning backward from the cut point for the first such
// byte finds the nearest safe boundary without hand-decoding UTF-8.
func capAtRuneBoundary(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	cut := maxLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// The transfer OUTCOME deadline (plan D14) — deliberately NOT u.cfg.Timeout,
// which is the REFER transaction's own budget (Timer F). These are internal
// constants, not configuration (spec §4.3's "no new config knob" is about the
// user-facing Config surface), and deliberately NOT multiples of u.cfg.Timeout:
// coupling the subscription lifetime to the transaction timer is exactly the
// defect D14 removes.
const (
	// referOutcomeDefaultWait applies until a NOTIFY states the subscription's
	// duration: >= 2x typical PBX no-answer timers (20-60 s) plus the
	// transferee's own call setup, and inside our own outboundRingBudget (180 s).
	referOutcomeDefaultWait = 120 * time.Second
	// referOutcomeMaxWait is the ABSOLUTE ceiling from the REFER's 2xx, however
	// often a notifier re-states expires: past RFC 3261's Timer C floor (> 3 min,
	// the longest an INVITE may stay in progress at a proxy) and our 180 s ring
	// budget, so any outcome a compliant notifier can still report arrives
	// first — and a misbehaving one cannot hold the dialog in phaseControlOp
	// indefinitely.
	referOutcomeMaxWait = 300 * time.Second
)

// referOutcomeArmHook is a TEST-ONLY seam (export_test.go's
// SetReferOutcomeArmHook), nil in production — the mediaTeardownHook precedent
// (call.go). awaitReferOutcome calls it with the window each time it (re)arms
// its timer, AFTER arming, so a test can Advance the fake clock without racing
// the arm.
//
// UNLIKE mediaTeardownHook and its siblings, this one is an atomic.Pointer,
// not a plain var: awaitReferOutcome runs in a goroutine spawned by Transfer
// that outlives the test call that started it (it waits on w.resolved/ended/
// the outcome timer), so it can still be reading this hook after its
// originating test has returned and the NEXT test's SetReferOutcomeArmHook
// call is writing it — a real, reproducible data race under -race, not the
// "tests do not run in parallel" case the plain-var hooks rely on.
var referOutcomeArmHook atomic.Pointer[func(time.Duration)]

// transferBeforeSendHook is a TEST-ONLY seam (export_test.go's
// SetTransferBeforeSendHookForTest), nil in production — the
// referOutcomeArmHook precedent. Transfer calls it, if set, with the control
// op's ended channel right after claiming it and before dispatching the
// REFER, so a test can deterministically end the dialog in that exact window
// (CF-008).
var transferBeforeSendHook func(ended <-chan struct{})

// referWaiter tracks ONE call_transfer's implicit subscription (RFC 3515 §2.4.4)
// — the digitWaiter shape: a single in-flight slot per dialog, cleared on the
// outcome.
//
// TWO LOCKS, TWO JOBS (plan D16). The OUTCOME (settled/code/reason and
// subscriptionOver) is guarded by u.calls.mu, not by mu. onNotify records a
// final NOTIFY's outcome in the SAME critical section that confirms the dialog
// is still established, and onBye's teardown takes that same lock, so a peer
// BYE racing right behind the final NOTIFY cannot slip its teardown in between.
// mu only orders EMISSION: a provisional event and the final event are each
// emitted under mu, so no provisional can follow the final. It also makes
// rebase the only sender on rearm.
//
// THE DEADLINE LIVES UNDER u.calls.mu TOO (Rule 13 fix batch A, finding 1).
// onNotify records a provisional NOTIFY's stated expiry (extendGen/extendExp/
// extendAt) in the SAME critical section that accepts it; rearm is only a
// wake-up. awaitReferOutcome's timer path re-checks extendGen under u.calls.mu
// and records the timeout outcome in that same section. So an extension
// accepted before the old deadline's settle can never lose to the stale timer,
// whatever the goroutine scheduling.
//
// LOCK ORDER: mu -> u.calls.mu (emit takes u.calls.mu briefly). Nothing takes
// mu while holding u.calls.mu, and nothing holding mu takes the send-order
// token. Taking mu inside u.calls.mu, e.g. to resolve under onNotify's lock,
// would deadlock against a concurrent provisional NOTIFY, which is why the
// outcome lives under u.calls.mu instead.
type referWaiter struct {
	cseq uint32               // the REFER's wire CSeq number: the Event id
	mode session.TransferMode // immutable after construction

	resolved chan struct{} // closed once, by resolveLocked, when a final outcome is recorded
	rearm    chan struct{} // 1-slot wake-up: a newer extension is recorded (D14)

	// Guarded by u.calls.mu (see above).
	settled bool
	code    int
	reason  string
	// subscriptionOver is true once this REFER's subscription is known not to
	// exist any more: the REFER drew a non-2xx (none was ever created, RFC 3515
	// §2.4.2), or a NOTIFY routed here carried Subscription-State: terminated.
	// concludeRefer records an earlier subscription that may be live on the
	// dialog unless it is true (D13, CF-012).
	subscriptionOver bool
	// The latest notifier-stated subscription duration a routed PROVISIONAL
	// NOTIFY carried, and that NOTIFY's arrival time (D14). extendGen counts
	// them, so awaitReferOutcome can tell whether its armed timer predates the
	// latest one.
	extendGen uint64
	extendExp time.Duration
	extendAt  time.Time

	mu sync.Mutex // emission order and rearm sends ONLY; see above
}

func newReferWaiter(cseq uint32, mode session.TransferMode) *referWaiter {
	return &referWaiter{cseq: cseq, mode: mode,
		resolved: make(chan struct{}), rearm: make(chan struct{}, 1)}
}

// extendLocked records a routed PROVISIONAL NOTIFY's stated subscription
// duration and its arrival time as the authoritative deadline (D14). Caller
// MUST hold u.calls.mu, in the same critical section that accepts the NOTIFY.
func (w *referWaiter) extendLocked(expires time.Duration, at time.Time) {
	w.extendGen++
	w.extendExp, w.extendAt = expires, at
}

// rebase wakes awaitReferOutcome to re-arm from the extension extendLocked
// already recorded. The send never blocks: under w.mu this is the only sender
// and a pending wake-up already covers the latest extension. A rebase after the
// waiter settled is harmless: nobody reads the channel any more. Only a
// PROVISIONAL NOTIFY rebases (D16).
func (w *referWaiter) rebase() {
	w.mu.Lock()
	defer w.mu.Unlock()
	select {
	case w.rearm <- struct{}{}:
	default:
	}
}

// resolveLocked records a final outcome — a final NOTIFY's status, or the
// timeout outcome when the notifier ends the subscription with no final status
// — and wakes awaitReferOutcome. The FIRST outcome recorded is authoritative
// (locked decision 5); a later one is ignored. Caller MUST hold u.calls.mu.
func (w *referWaiter) resolveLocked(code int, reason string) {
	if w.settled {
		return
	}
	w.settled, w.code, w.reason = true, code, reason
	close(w.resolved)
}

// settleLocked settles the waiter with (code, reason) unless an outcome is
// already recorded, and returns the authoritative outcome either way —
// first-settle-wins, so a teardown's "dialog ended" can never override a final
// NOTIFY that resolveLocked recorded first (D16). Caller MUST hold u.calls.mu.
func (w *referWaiter) settleLocked(code int, reason string) (int, string) {
	if !w.settled {
		w.settled, w.code, w.reason = true, code, reason
	}
	return w.code, w.reason
}

// Transfer implements session.UserAgent.Transfer (spec 2026-09-26 §4, master
// spec §10.14). It sends a REFER in the answered dialog req.DialogID and BLOCKS
// only for the REFER's own final response; the NOTIFY-reported outcome arrives
// later as UAEventTransfer.
//
// ERROR MAP (errors are input/state problems only, §11.1):
//   - invalid_argument    — bad mode, a missing/contradictory target or
//     consult_call, a target that is not a safe sip:/sips: URI
//   - not_found           — either dialog is unknown to this UA
//   - precondition_failed — the dialog is not answered, a control operation
//     or a dtmf_send holds it, the consult dialog is not answered/confirmed,
//     or the consult dialog's own peer URI failed the same CF-005 sanitization
//     validReferTarget applies to any REFER target
//   - cancelled/internal  — ctx ended before the REFER's response
//
// Everything the PEER decides is a RESULT: a non-2xx REFER response, no response
// at all (StatusCode 0; since CF-110 reverses D8 sendInDialog also ends the
// dialog locally, RFC 3261 12.2.1.2), and every NOTIFY outcome.
func (u *UA) Transfer(ctx context.Context, req session.TransferRequest) (session.TransferResult, error) {
	if err := validateTransferRequest(req); err != nil {
		return session.TransferResult{}, err
	}
	d, err := u.lookup(req.DialogID)
	if err != nil {
		return session.TransferResult{}, err
	}
	var cd *dialog
	if req.Mode == session.TransferAttended {
		if cd, err = u.lookup(req.ConsultDialogID); err != nil {
			return session.TransferResult{}, err
		}
	}

	// The consult dialog is checked and READ before the transferred dialog is
	// claimed, in ONE critical section, so a refused attended transfer never
	// holds the transferred call even momentarily.
	u.calls.mu.Lock()
	referTo := "<" + req.Target + ">"
	if cd != nil {
		if cd.phase != phaseAnswered {
			p := cd.phase
			u.calls.mu.Unlock()
			return session.TransferResult{}, apierr.PreconditionFailed(fmt.Sprintf(
				"call_transfer: consult_call's dialog is in phase %d; it must be answered", p))
		}
		var ok bool
		if referTo, ok = consultReferToLocked(cd); !ok {
			u.calls.mu.Unlock()
			return session.TransferResult{}, apierr.PreconditionFailed(
				"call_transfer: consult_call has no confirmed dialog to replace, " +
					"or its own URI could not be sanitized")
		}
	}
	ended, err := claimControlOpLocked(d, session.ControlOpTransfer, "call_transfer")
	u.calls.mu.Unlock()
	if err != nil {
		return session.TransferResult{}, err
	}
	if transferBeforeSendHook != nil {
		transferBeforeSendHook(ended)
	}
	select {
	case <-ended:
		// Nothing was sent, same as the refer == nil path below: release the
		// claim now rather than leaving it for the dialog's later teardown
		// (releaseControlOpLocked's own doc comment: a late/redundant release
		// is harmless).
		u.calls.mu.Lock()
		releaseControlOpLocked(d)
		u.calls.mu.Unlock()
		return session.TransferResult{}, apierr.PreconditionFailed(
			"call_transfer: dialog ended before the REFER could be sent")
	default:
	}
	referredBy := "<" + u.referredBy() + ">"

	// Sent through the ONE in-dialog send seam (plan D12): the CSeq reserved
	// here reaches the wire before any later-reserved in-dialog request on this
	// dialog — a periodic session refresh cannot overtake the REFER, or be
	// overtaken by it. ctx IS the caller's, like hangupWithReason's: the REFER
	// is a synchronous request whose result the caller is waiting for.
	var w *referWaiter
	refer, res, err := u.sendInDialog(ctx, d, sip.REFER, func(refer *sip.Request) {
		refer.AppendHeader(sip.NewHeader("Refer-To", referTo))
		refer.AppendHeader(sip.NewHeader("Referred-By", referredBy))
		// The Event id a NOTIFY will carry is the REFER's WIRE CSeq: the value
		// buildInDialogRequest set PLUS ONE, because sendInDialog's option-less
		// TransactionRequest bumps it once more before sending (see
		// dialog.localCSeq's comment; transfer_test.go's referEventHeader reads
		// the peer-observed CSeq, so a drift here fails every NOTIFY test). The
		// waiter is installed BEFORE the dispatch so a NOTIFY racing the REFER's
		// own 202 is matched. Whether an id-less NOTIFY may route here is decided
		// when each NOTIFY arrives (referIdlessAmbiguousLocked), from the dialog's
		// record of earlier subscriptions: every earlier REFER on this dialog has
		// concluded by now, because concludeRefer records it in the same critical
		// section that releases the control op this REFER then claimed (D13).
		u.calls.mu.Lock()
		w = newReferWaiter(refer.CSeq().SeqNo+1, req.Mode)
		d.referWaiter = w
		u.calls.mu.Unlock()
	})
	if refer == nil {
		// Nothing was sent (sendInDialog's contract): ctx ended while waiting
		// for the dialog's send-order token, or buildInDialogRequest refused. No
		// waiter was installed and no REFER can have a subscription; release the
		// claim.
		u.calls.mu.Lock()
		releaseControlOpLocked(d)
		u.calls.mu.Unlock()
		if ctx.Err() != nil {
			return session.TransferResult{}, classifyCtxErr(ctx, "call_transfer")
		}
		return session.TransferResult{}, err
	}
	if err != nil {
		// TWO DIFFERENT CASES (CF-009). Ordinarily the REFER was dispatched
		// but drew no final response (a genuine Timer F timeout, or ctx ended
		// while waiting for one): the peer may have accepted it, so
		// concludeRefer records an earlier subscription that may be live (D13). But
		// noTransactionErr(err) means the REFER was NEVER SENT AT ALL — an
		// immediate transport/routing failure inside sendInDialog's own
		// TransactionRequest call, before any transaction started — so no
		// subscription can possibly exist for it; w.subscriptionOver is set
		// under u.calls.mu before concludeRefer runs, exactly as the non-2xx
		// branch below does, so no earlier subscription is recorded. (A REFER
		// that drew no response ended the dialog inside sendInDialog already,
		// CF-110: this branch only reports the transfer's result.)
		if ctx.Err() != nil {
			u.concludeRefer(d, w, 0, "the call_transfer request was cancelled") //nolint:contextcheck // same u.emit-on-retained-evCtx pattern as sessiontimer.go: concludeRefer's final UAEventTransfer is delivered on the long-lived evCtx/u.uaCtx (see emit), not this ctx, which is already done by the time this runs.
			return session.TransferResult{}, classifyCtxErr(ctx, "call_transfer")
		}
		reason := referReasonNoResponse
		if noTransactionErr(err) {
			reason = referReasonNotSent
			u.calls.mu.Lock()
			w.subscriptionOver = true
			u.calls.mu.Unlock()
		}
		u.concludeRefer(d, w, 0, reason) //nolint:contextcheck // same u.emit-on-retained-evCtx pattern as sessiontimer.go: see the comment above.
		return session.TransferResult{Reason: reason}, nil
	}
	// res.Reason is peer-supplied wire text (the REFER's own final response's
	// reason phrase) — one of CF-019's two ingestion points. Capped exactly
	// once, here, the moment it is read off res, so both branches below (and
	// concludeRefer, in the non-2xx one) already hold a safe value.
	resReason := capReferReason(res.Reason)
	if !res.IsSuccess() {
		// A non-2xx creates no subscription (RFC 3515 §2.4.2): nothing of this
		// REFER can still send NOTIFYs, so a retry may correlate id-less ones (D13).
		u.calls.mu.Lock()
		w.subscriptionOver = true
		u.calls.mu.Unlock()
		u.concludeRefer(d, w, int(res.StatusCode), resReason) //nolint:contextcheck // same u.emit-on-retained-evCtx pattern as sessiontimer.go: concludeRefer's final UAEventTransfer is delivered on the long-lived evCtx/u.uaCtx (see emit), not this request's ctx.
		return session.TransferResult{StatusCode: int(res.StatusCode), Reason: resReason}, nil
	}
	// Accepted: the NOTIFY outcome is still pending and the dialog stays in
	// phaseControlOp, but call_hangup is allowed from here on (plan D17, spec §3
	// amendment) — BEFORE Transfer returns, so a hangup issued right after
	// call_transfer answers is never refused. A hangup then settles this
	// transfer as referReasonHungUp (awaitReferOutcome).
	u.calls.mu.Lock()
	allowHangupDuringControlOpLocked(d)
	u.calls.mu.Unlock()
	go u.awaitReferOutcome(d, w, ended) //nolint:contextcheck // the NOTIFY wait deliberately outlives the call_transfer request (decision 17): it ends on the final NOTIFY, the dialog's teardown, the outcome deadline (plan D14) or u.uaCtx — never on the caller's ctx.
	return session.TransferResult{Accepted: true, StatusCode: int(res.StatusCode), Reason: resReason}, nil
}

// validateTransferRequest is Transfer's input gate; it runs before any lookup,
// so a bad request touches neither the registry nor the wire.
func validateTransferRequest(req session.TransferRequest) error {
	switch req.Mode {
	case session.TransferBlind:
		if req.ConsultDialogID != "" {
			return apierr.InvalidArgument("call_transfer: consult_call must not be set when mode is blind")
		}
		if req.Target == "" {
			return apierr.InvalidArgument("call_transfer: target is required when mode is blind")
		}
		if !validReferTarget(req.Target) {
			return apierr.InvalidArgument("call_transfer: target must be a sip: or sips: URI safe to use as a REFER target")
		}
	case session.TransferAttended:
		if req.Target != "" {
			return apierr.InvalidArgument(
				"call_transfer: target must not be set when mode is attended; the consult call is the target")
		}
		if req.ConsultDialogID == "" {
			return apierr.InvalidArgument("call_transfer: consult_call is required when mode is attended")
		}
		if req.ConsultDialogID == req.DialogID {
			return apierr.InvalidArgument("call_transfer: consult_call must be a different call from call")
		}
	default:
		return apierr.InvalidArgument(fmt.Sprintf("call_transfer: mode %q must be blind or attended", req.Mode))
	}
	return nil
}

// awaitReferOutcome waits for the transfer's final outcome after a 2xx REFER:
// the first final NOTIFY (or a notifier-ended subscription), the dialog's
// teardown (ended — closed by endControlOpLocked or, for our own BYE,
// endControlOpByLocalHangupLocked), the outcome deadline (plan D14), or the
// UA's own end. It never outlives any of them. When several are ready at once
// the select's choice does not matter: concludeRefer's settleLocked keeps an
// outcome onNotify already recorded (D16).
//
// THE DEADLINE IS THE SUBSCRIPTION'S, NOT THE TRANSACTION'S (D14). It starts at
// referOutcomeDefaultWait; every routed PROVISIONAL NOTIFY stating
// `Subscription-State: active|pending;expires=N` re-arms it to N from that
// NOTIFY's arrival (a final NOTIFY never re-arms, and a stated expires=0 or
// terminated is settled in onNotify directly — D16), bounded by hardStop (acceptedAt + referOutcomeMaxWait) so
// re-stated expiries can never extend the wait without limit. The REFER's 2xx
// carries no Subscription-State (RFC 3515), so the first NOTIFY is the earliest
// source. A re-arm REPLACES the timer (Stop, then a fresh NewTimer) rather than
// Reset-ing it, so no stale fire from the old deadline can be read.
//
// A timer that fires is still re-checked under u.calls.mu (finding 1): if
// onNotify recorded a newer extension after the timer was armed, the fire is
// stale and the wait re-arms instead. Otherwise the timeout is recorded in that
// same critical section, so a NOTIFY accepted later finds the waiter settled.
func (u *UA) awaitReferOutcome(d *dialog, w *referWaiter, ended <-chan struct{}) {
	clk := u.cfg.Clock
	if clk == nil {
		clk = clock.System()
	}
	hardStop := clk.Now().Add(referOutcomeMaxWait)
	tm := u.armReferOutcomeTimer(clk, referOutcomeDefaultWait)
	defer func() { tm.Stop() }()
	var uaDone <-chan struct{}
	if u.uaCtx != nil {
		uaDone = u.uaCtx.Done()
	}
	var armedGen uint64
	// extendedWindowLocked reports the window left under the latest recorded
	// extension, if it is newer than the armed timer, and marks it armed.
	// Caller MUST hold u.calls.mu; the caller re-arms after unlocking.
	extendedWindowLocked := func() (time.Duration, bool) {
		if w.extendGen == armedGen {
			return 0, false
		}
		armedGen = w.extendGen
		now := clk.Now()
		return referOutcomeWindow(w.extendExp-now.Sub(w.extendAt), now, hardStop), true
	}
	rearm := func(win time.Duration) {
		tm.Stop()
		tm = u.armReferOutcomeTimer(clk, win)
	}
	reason := ""
wait:
	for {
		select {
		case <-w.resolved:
			break wait
		case <-ended:
			// Closed by a teardown. D17: if it was THIS UA's own BYE (call_hangup
			// once the REFER was accepted, ua_destroy/shutdown, the watchdog),
			// say so. endControlOpByLocalHangupLocked wrote the record before the
			// close, under this lock.
			reason = referReasonEnded
			u.calls.mu.Lock()
			if d.controlOpEndedByHangup {
				reason = referReasonHungUp
			}
			u.calls.mu.Unlock()
			break wait
		case <-uaDone:
			reason = referReasonUAClosed
			break wait
		case <-w.rearm:
			u.calls.mu.Lock()
			win, ok := extendedWindowLocked()
			u.calls.mu.Unlock()
			if ok {
				rearm(win)
			}
		case <-tm.C():
			u.calls.mu.Lock()
			if win, ok := extendedWindowLocked(); ok {
				u.calls.mu.Unlock()
				rearm(win) // the fire predates an accepted extension: stale
				continue
			}
			w.resolveLocked(0, referReasonTimeout)
			u.calls.mu.Unlock()
			reason = referReasonTimeout
			break wait
		}
	}
	u.concludeRefer(d, w, 0, reason)
}

// armReferOutcomeTimer arms one outcome-deadline timer and reports the window
// to the test seam, AFTER arming.
func (u *UA) armReferOutcomeTimer(clk clock.Clock, wait time.Duration) clock.Timer {
	tm := clk.NewTimer(wait)
	if hook := referOutcomeArmHook.Load(); hook != nil {
		(*hook)(wait)
	}
	return tm
}

// referOutcomeWindow bounds a notifier-stated subscription duration by what
// remains before the absolute ceiling (D14). Never negative: a NOTIFY stating
// expires=0, or one arriving past hardStop, ends the wait at once.
func referOutcomeWindow(expires time.Duration, now, hardStop time.Time) time.Duration {
	if rem := hardStop.Sub(now); expires > rem {
		expires = rem
	}
	if expires < 0 {
		return 0
	}
	return expires
}

// parseSubscriptionExpires reads the expires parameter of a Subscription-State
// value — the notifier's statement of the subscription's remaining life (RFC
// 6665 §4.1.3). ok is false when the state is not active/pending (a terminated
// subscription states no remaining life), or when expires is absent or not a
// non-negative integer.
func parseSubscriptionExpires(v string) (time.Duration, bool) {
	parts := strings.Split(v, ";")
	state := strings.ToLower(strings.TrimSpace(parts[0]))
	if state != "active" && state != "pending" {
		return 0, false
	}
	for _, p := range parts[1:] {
		k, val, found := strings.Cut(strings.TrimSpace(p), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(k), "expires") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(val), 10, 32)
		if err != nil {
			return 0, false
		}
		return time.Duration(n) * time.Second, true
	}
	return 0, false
}

// subscriptionTerminated reports whether a Subscription-State value says the
// subscription is over (RFC 6665 §4.1.3's "terminated" state, parameters
// ignored). The final NOTIFY of a refer subscription MUST carry it (RFC 3515
// §2.4.7).
func subscriptionTerminated(v string) bool {
	state, _, _ := strings.Cut(v, ";")
	return strings.EqualFold(strings.TrimSpace(state), "terminated")
}

// concludeRefer is the ONE final path: settle the waiter (an outcome onNotify
// already recorded wins — D16), record whether this REFER's subscription may
// outlive it (D13, bounded by CF-012), clear the waiter, release the control op, and emit the final
// UAEventTransfer — exactly once per REFER. The final emit happens under w.mu,
// so it cannot interleave with a provisional one (emitReferProvisional).
//
// reason is trusted to already be safe (CF-019): every caller either passes
// one of this package's own fixed reason constants, or a value already run
// through capReferReason at the REFER-response ingestion point (Transfer's
// resReason) — concludeRefer itself no longer re-caps it.
func (u *UA) concludeRefer(d *dialog, w *referWaiter, code int, reason string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	u.calls.mu.Lock()
	code, reason = w.settleLocked(code, reason)
	if !w.subscriptionOver {
		// The notifier may still consider this REFER's subscription active, so an
		// id-less NOTIFY on this dialog is ambiguous until a stray from it is no
		// longer plausible (D13, CF-012): the ceiling of the outcome window plus
		// the notifier's client-transaction lifetime (Timer F, RFC 3261
		// 17.1.2.2), or the end the notifier stated (RFC 6665 4.1.3) plus the
		// same lifetime, whichever is later. A window that has already ended
		// stops counting its subscriptions; a later window is never shortened.
		now := u.now()
		if !now.Before(d.referSubsLiveUntil) {
			d.referSubsMaybeLive = 0
		}
		d.referSubsMaybeLive++
		until := now.Add(referOutcomeMaxWait + sip.Timer_F)
		if w.extendGen > 0 {
			if stated := w.extendAt.Add(w.extendExp + sip.Timer_F); stated.After(until) {
				until = stated
			}
		}
		if until.After(d.referSubsLiveUntil) {
			d.referSubsLiveUntil = until
		}
	}
	if d.referWaiter == w {
		d.referWaiter = nil
	}
	releaseControlOpLocked(d)
	u.calls.mu.Unlock()
	u.emitTransfer(d, w.mode, code, reason, true)
}

// emitReferProvisional emits one provisional (final:false) UAEventTransfer
// unless the waiter already has its outcome. It holds w.mu across the check and
// the emit, and concludeRefer emits the final event under w.mu too, so no
// provisional event can follow the final one. Lock order w.mu -> u.calls.mu (D16).
func (u *UA) emitReferProvisional(d *dialog, w *referWaiter, code int, reason string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	u.calls.mu.Lock()
	done := w.settled
	u.calls.mu.Unlock()
	if !done {
		u.emitTransfer(d, w.mode, code, reason, false)
	}
}

// emitTransfer delivers one UAEventTransfer. d.id/d.callID/d.direction are set
// at dialog creation and never mutated, so reading them unlocked is safe.
func (u *UA) emitTransfer(d *dialog, mode session.TransferMode, code int, reason string, final bool) {
	u.emit(session.UAEvent{
		Kind: session.UAEventTransfer, DialogID: d.id, CallID: d.callID, Direction: d.direction,
		Code: code, Reason: reason, At: u.now(),
		Detail: map[string]any{
			"mode": string(mode), "status_code": code, "reason": reason,
			"final": final, "success": final && code >= 200 && code < 300,
		},
	})
}

// referredBy is the Referred-By URI: our AOR (with a sip: scheme if it was
// configured without one), or our Contact URI when no AOR is configured.
func (u *UA) referredBy() string {
	aor := strings.TrimSpace(u.cfg.AOR)
	if aor == "" {
		c := u.localContact()
		return c.Address.String()
	}
	if l := strings.ToLower(aor); !strings.HasPrefix(l, "sip:") && !strings.HasPrefix(l, "sips:") {
		aor = "sip:" + aor
	}
	return aor
}

// onNotify answers an in-dialog NOTIFY and routes a refer-package NOTIFY to the
// dialog's referWaiter (spec §4.3, D6, D13, D16). Dialog matching for the
// RESPONSE is onUpdate's: the Call-ID finds the dialog and the To-tag must be
// our local tag on an ESTABLISHED dialog; anything else is 481 (RFC 3261
// §12.2.2). A matched NOTIFY is ALWAYS answered 200 OK, whatever its content
// (locked decision 5).
//
// ROUTING to the waiter is stricter (D13, routeReferNotifyLocked): the From-tag
// must also be the peer's tag on the dialog, and the Event id must equal the
// REFER's CSeq — except that an id-less NOTIFY is accepted once no earlier
// REFER's subscription on the dialog is plausibly still live (CF-012: a bounded
// window, evaluated here, ended early by a terminated NOTIFY from the peer).
//
// ORDER MATTERS (D16, D18; Cycle C rounds 2 and 3). Asterisk sends the final
// NOTIFY and then immediately a BYE, and sipgo runs each on its own goroutine.
// So:
//  0. arrivalEnter runs first (D18). If a BYE reached the transport before this
//     NOTIFY, the BYE is applied first. If this NOTIFY reached it first, the BYE
//     waits for it. Either way, the order in which sipgo schedules the two
//     goroutines does not matter;
//  1. the sipfrag status and Subscription-State are parsed BEFORE the lock;
//  2. a FINAL outcome is recorded (resolveLocked) inside the SAME u.calls.mu
//     critical section that confirms the dialog is established. onBye sets
//     phaseDone under that lock, so either this NOTIFY sees the dialog gone
//     (481, nothing recorded) or its outcome is recorded strictly before the
//     BYE's teardown, and settleLocked's first-settle-wins keeps it. The
//     request's arrival ticket leaves the gate in that same critical section;
//  3. only THEN is the 200 OK written, and only a PROVISIONAL NOTIFY emits an
//     event and re-arms the deadline. A final NOTIFY never re-arms, so a final
//     NOTIFY stating active;expires=0 cannot fire as a timeout first.
//
// WIRE ORDER, NOT LOCK ORDER. Step 2 alone only means "whichever goroutine
// locks first wins". Step 0 makes the winner the request that reached the
// transport first. A BYE that really arrives first, followed by a stale or
// duplicate NOTIFY, settles "the dialog ended before a final NOTIFY" and the
// NOTIFY draws 481. That is correct, because the dialog was gone when the NOTIFY
// arrived. The guarantee holds per transport connection (one UDP listener is one
// read loop). Two TCP connections have no wire order between them.
func (u *UA) onNotify(req *sip.Request, tx sip.ServerTransaction) {
	// D18: first, wait until every gated request that reached the transport
	// before this NOTIFY on its dialog (a BYE, in practice) has been applied.
	// No lock is held while waiting.
	tk := u.arrivalEnter(req)
	isRefer, id, hasID := false, uint32(0), false
	if h := req.GetHeader("Event"); h != nil {
		isRefer, id, hasID = parseReferEvent(h.Value())
	}
	toTag, fromTag := toTagOf(req), fromTagOf(req)
	code, reason, fragOK := parseSipfrag(req.Body())
	reason = capReferReason(reason)
	subState := ""
	if h := req.GetHeader("Subscription-State"); h != nil {
		subState = h.Value()
	}
	exp, hasExp := parseSubscriptionExpires(subState)
	terminated := subscriptionTerminated(subState)

	u.calls.mu.Lock()
	d := u.findDialogForRequestLocked(req) // CF-176: Call-ID and both tags
	known := d != nil && dialogEstablished(d.phase) && toTag != "" && ourReInviteTagLocked(d) == toTag
	var w *referWaiter
	var miss referNotifyMiss
	// CF-101: only a NOTIFY from the dialog's own peer is in this dialog's CSeq
	// space; one with a foreign From tag matches no dialog (CF-176) and draws 481. An
	// out-of-order NOTIFY applies nothing (no routing, no accounting) but still
	// leaves its arrival ticket below.
	outOfOrder := known && fromTag == peerTagLocked(d) && !remoteCSeqInOrderLocked(d, req)
	if known && isRefer && !outOfOrder {
		now := u.now()
		w, miss = routeReferNotifyLocked(d, id, hasID, fromTag, now)
		// A terminated refer NOTIFY from the peer with no transfer in flight
		// cannot be the current transfer's, so it ends one earlier subscription
		// (RFC 3515 2.4.7: one terminated per subscription, CF-012). A
		// retransmission re-runs this handler (sipgo terminates the server
		// transaction when it returns), so only a CSeq above the last counted
		// one is evidence.
		if cs := req.CSeq(); terminated && d.referWaiter == nil && fromTag == peerTagLocked(d) &&
			cs != nil && cs.SeqNo > d.referEndedCSeq {
			d.referEndedCSeq = cs.SeqNo
			noteReferSubEndedLocked(d)
		}
	}
	provisional, subEnded := false, false
	if w != nil {
		if terminated {
			w.subscriptionOver = true // the notifier says it is done (D13)
		}
		switch {
		case fragOK && code >= 200:
			w.resolveLocked(code, reason) // D16: recorded before any BYE can tear down
		case terminated || (hasExp && exp == 0):
			// The notifier ended the subscription with no final status, so none
			// will come. End the wait now, as expires=0 does (D14; Cycle C round
			// 2, non-blocking 2), rather than running out the deadline.
			w.resolveLocked(0, referReasonTimeout)
			subEnded = true
		case fragOK:
			provisional = true
			if hasExp {
				w.extendLocked(exp, u.now()) // D14, finding 1: recorded as it is accepted
			}
		}
	}
	arrivalLeaveLocked(tk) // D18: in the SAME critical section that recorded the outcome
	u.calls.mu.Unlock()

	if !known {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
		return
	}
	if outOfOrder {
		respondOutOfOrder(req, tx)
		return
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	if miss.why != "" {
		// Cycle C round 2, non-blocking 3: a refer NOTIFY on a LIVE dialog that
		// matched no live waiter. Answered 200 as always, but logged at Warn, so
		// a real tag-derivation or id bug shows in production instead of a
		// silent timeout. fromTag itself (used above for routing) is left
		// uncapped — routing needs the real value — but it is peer-controlled
		// (parsed off the NOTIFY's From header) with no length bound of its
		// own, so it is capped here, ONLY for this log line (CF-021), the same
		// way a peer-supplied reason phrase is capped before it reaches a log
		// or event. miss.wantFromTag is this UA's own expected value, not
		// peer-controlled, and needs no cap.
		u.log().Warn("refer NOTIFY on a live dialog matched no in-flight transfer; ignored",
			"dialog_id", d.id, "call_id", d.callID, "why", miss.why,
			"from_tag", capAtRuneBoundary(fromTag, referReasonMaxLen), "expected_from_tag", miss.wantFromTag,
			"has_id", hasID, "id", id, "expected_id", miss.wantID,
			"prior_subscription_may_be_live", miss.priorSubMaybeLive)
	}
	if w == nil {
		return
	}
	if !provisional {
		if !fragOK && !subEnded {
			u.log().Debug("refer NOTIFY carried no parseable sipfrag status line; ignored",
				"dialog_id", d.id, "call_id", d.callID)
		}
		return
	}
	// Emit BEFORE re-arming: the re-arm is what a test (and awaitReferOutcome)
	// observes next, so the provisional event is already out by then.
	u.emitReferProvisional(d, w, code, reason)
	if hasExp {
		w.rebase() // D14: only a PROVISIONAL NOTIFY wakes awaitReferOutcome to re-arm from the extension extendLocked already recorded above
	}
}

// referNotifyMiss explains why a refer NOTIFY on a live dialog was routed to no
// waiter, for onNotify's Warn log. why is "" when it was routed, or when no
// transfer is in flight at all (a duplicate or late NOTIFY after the settle is
// normal, not a mismatch).
type referNotifyMiss struct {
	why               string
	wantFromTag       string
	wantID            uint32
	priorSubMaybeLive bool
}

// routeReferNotifyLocked picks the waiter a refer NOTIFY belongs to, or says why
// it belongs to none (D13). Caller MUST hold u.calls.mu.
func routeReferNotifyLocked(d *dialog, id uint32, hasID bool, fromTag string, now time.Time) (*referWaiter, referNotifyMiss) {
	w := d.referWaiter
	if w == nil {
		return nil, referNotifyMiss{}
	}
	ambiguous := referIdlessAmbiguousLocked(d, now)
	miss := referNotifyMiss{wantFromTag: peerTagLocked(d), wantID: w.cseq, priorSubMaybeLive: ambiguous}
	switch {
	case fromTag != miss.wantFromTag:
		miss.why = "From-tag is not the peer's tag on this dialog"
	case hasID && id != w.cseq:
		miss.why = "Event id is not the in-flight REFER's CSeq"
	case !hasID && ambiguous:
		miss.why = "no Event id, and an earlier REFER's subscription on this dialog may still be live"
	default:
		return w, referNotifyMiss{}
	}
	return nil, miss
}

// referIdlessAmbiguousLocked reports whether a NOTIFY without an Event id could
// still belong to an earlier REFER's subscription on d (D13, bounded by CF-012).
// Caller MUST hold u.calls.mu.
func referIdlessAmbiguousLocked(d *dialog, now time.Time) bool {
	return d.referSubsMaybeLive > 0 && now.Before(d.referSubsLiveUntil)
}

// noteReferSubEndedLocked records that one earlier subscription was terminated
// by the notifier, and forgets the window once none is left. Caller MUST hold
// u.calls.mu.
func noteReferSubEndedLocked(d *dialog) {
	if d.referSubsMaybeLive > 0 {
		d.referSubsMaybeLive--
		if d.referSubsMaybeLive == 0 {
			d.referSubsLiveUntil = time.Time{}
		}
	}
}
