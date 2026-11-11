package session

import (
	"context"
	"fmt"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// terminationReasonFor maps a PROTOCOL fact onto §10.3's termination_reason
// enum (U14).
//
// THIS IS THE ONLY PLACE IN THE PROJECT WHERE THAT TRANSLATION HAPPENS.
// `sipua` never names a termination_reason — it reports what the wire did, and
// `session` decides what that means. It is the same Rule 18 reasoning that
// keeps CallState out of sipua: one canonical mapping, in the package that owns
// §10.3's state machine. Do not inline this at the call sites; two copies drift.
//
// IT IS TOTAL AND IT RETURNS AN ERROR RATHER THAN A DEFAULT. A switch falling
// through to the zero value would hand a call an EMPTY termination_reason,
// which §10.3's exhaustive enum does not admit and no consumer can interpret. A
// cause we do not recognise means sipua gained one that session was never
// taught — a build-time inconsistency, loud rather than silent.
func terminationReasonFor(cause UADialogEndCause) (string, error) {
	switch cause {
	case UACausePeerBYE:
		return "remote_bye", nil
	case UACauseRingTimeout:
		return "inbound_ring_timeout", nil
	case UACauseCancelled:
		return string(apierr.CodeCancelled), nil
	case UACauseMediaNegotiationFailed:
		return "media_negotiation_failed", nil
	case UACauseTransportFailure:
		return "transport_failure", nil
	case UACauseSessionTimerExpired:
		return "session_timer_expired", nil
	default:
		// NOT a default reason. See the doc comment.
		return "", apierr.Internal("", fmt.Sprintf(
			"unrecognised UADialogEndCause %q: sipua emits a cause session cannot map "+
				"onto §10.3's termination_reason enum", cause))
	}
}

// handleUAEvent is the single upward callback session registers on every UA
// (UserAgent.OnEvent). ctx is the LONG-LIVED DAEMON context — decision 17;
// never an HTTP request context, or a client disconnect would stop a live
// call's events being processed.
func (m *Manager) handleUAEvent(ctx context.Context, uaHandle Handle, ev UAEvent) {
	switch ev.Kind {
	case UAEventDialogEnded:
		m.handleDialogEnded(ctx, uaHandle, ev)
	// UAEventInbound is DELIBERATELY absent: an inbound INVITE is admitted
	// SYNCHRONOUSLY through the OnAdmit channel (I2, admitInbound), not delivered
	// one-way here. sipua carries UAEventInbound on the AdmitFunc's UAEvent.
	case UAEventProvisional, UAEventFinal:
		m.handleResponse(ctx, uaHandle, ev)
	case UAEventRefresh:
		// R10 registration refresh: bookkeeping only, no call is involved.
		m.handleRefresh(ctx, uaHandle, ev)
	case UAEventRegisterFailed:
		// R10's give-up. REGISTRATION BOOKKEEPING ONLY — deliberately NOT routed
		// to handleTransportFault, which would terminate every live call on the UA.
		m.handleRegisterFailed(ctx, uaHandle, ev)
	case UAEventRegisterRemoved:
		// The registrar removed the binding on a 200 OK. REGISTRATION BOOKKEEPING
		// ONLY, for the same reason as UAEventRegisterFailed above.
		m.handleRegisterRemoved(ctx, uaHandle, ev)
	case UAEventTransportFault:
		// §11.3.1. STILL ITS OWN KIND AT P1 — it is NOT a UADialogEndCause and
		// must not be folded into one until P4.
		m.handleTransportFault(ctx, uaHandle, ev)
	case UAEventMediaError:
		m.handleMediaError(ctx, uaHandle, ev)
	case UAEventMediaStart:
		m.handleMediaStart(ctx, uaHandle, ev)
	case UAEventPlanStep:
		m.handlePlanStep(ctx, uaHandle, ev)
	case UAEventRecordStart:
		m.handlePlanRecordEvent(ctx, uaHandle, ev, EventRecordStart)
	case UAEventRecordStop:
		m.handlePlanRecordEvent(ctx, uaHandle, ev, EventRecordStop)
	case UAEventDTMF:
		m.handleDTMF(ctx, uaHandle, ev)
	case UAEventSessionRefresh:
		m.handleSessionRefresh(ctx, uaHandle, ev)
	case UAEventTransfer:
		m.handleTransfer(ctx, uaHandle, ev)
	}
}

// handleResponse is Task 11c's real implementation: a provisional or final
// response on an OUTBOUND call's INVITE. §10.3: 180/183 -> StateRinging, a 2xx
// -> StateAnswered (legal on the wire with no preceding 180/183 — D96, hence
// TryRemoteAnswer rather than TryAnswer), and a 3xx-6xx final -> StateFailed.
// On a well-formed wire sequence this only happens for a call that never
// reached answered; TryFail's own guard is only `terminal()` (call.go), so it
// does not itself enforce that precondition — it is the caller's job never to
// feed it an illegal 6xx-after-2xx sequence.
//
// The last_response record happens FIRST, before any Try* claim, and that
// order is load-bearing rather than stylistic: §6.0b INV-1 Form A requires
// `defer m.RecordTermination(c)` to follow the successful TryFail claim
// "before any other statement whatsoever", which leaves no room to record
// last_response between the claim and the defer.
//
// A losing Try* (the call already moved on — a concurrent call_reject, a
// duplicate 180 after 2xx, etc.) is dropped silently: §6.3, at most one
// transition wins, and the response was still observed and recorded above.
func (m *Manager) handleResponse(_ context.Context, uaHandle Handle, ev UAEvent) {
	c := m.callByDialogID(uaHandle, ev.DialogID)
	if c == nil {
		// The response is for a call we no longer hold — already torn down by
		// a concurrent hangup, or evicted. Nothing to record it against.
		return
	}

	c.recordLastResponse(ev.Code, ev.Reason)

	switch {
	case ev.Code == 180 || ev.Code == 183:
		// TryProgress appends the EventRinging itself, so there is no second
		// Append here: one event per response, exactly as the 3xx-6xx branch's
		// TryFail below is the sole emitter for its EventError.
		if err := c.TryProgress(ev.At); err != nil {
			return
		}

	case ev.Code >= 200 && ev.Code < 300:
		// TryRemoteAnswer appends the EventAnswered itself, so there is no
		// second Append here: one event per response, exactly as the 3xx-6xx
		// branch's TryFail below is the sole emitter for its EventError.
		if err := c.TryRemoteAnswer(ev.At); err != nil {
			return
		}

	case ev.Code >= 300:
		// D98: EventBye would be a lie — no BYE is sent on a rejected INVITE.
		// D97: reason is "" here — §10.3's rejected_locally is the REJECTING
		// side's reason (ToolService.CallReject), not this one, and the
		// spec's own worked wire result for exactly this case carries no
		// termination_reason key at all; the failure is described by
		// last_response, recorded above. The detail map is hoisted into its
		// own variable so the claim below is a single line (D94): gate B's
		// awk is line-based and cannot see a multi-line literal.
		detail := map[string]any{"kind": "invite_rejected", "sip_code": ev.Code, "reason": ev.Reason}
		if err := c.TryFail(ev.At, "", EventError, detail); err != nil {
			return
		}
		// §6.0b INV-1, on the line immediately following the successful claim
		// with no statement in between.
		defer m.RecordTermination(c)
	}
}

// handleRefresh is R10's registration refresh: bookkeeping only, no call is
// involved. It records that the UA is (still) registered and the countdown
// NextRefreshMS reports against the newly granted expiry.
func (m *Manager) handleRefresh(_ context.Context, uaHandle Handle, ev UAEvent) {
	m.mu.RLock()
	u, ok := m.uas[uaHandle]
	m.mu.RUnlock()
	if !ok {
		// The UA was destroyed between the refresh firing and this callback
		// running. Nothing to update.
		return
	}
	u.recordRefresh(ev.ExpiresS, ev.At)
}

// handleRegisterFailed is R10's give-up counterpart to handleRefresh: the
// registration refresh exhausted its retries, so the UA is no longer registered.
//
// IT TOUCHES NO CALL, AND THAT IS THE ENTIRE POINT (see UAEventRegisterFailed).
// handleTransportFault's live-call sweep is the WRONG response to a registrar
// outage: an answered dialog's media and in-dialog signalling flow to the peer,
// not through the registrar, so those calls are still up and must stay up. Do
// not "unify" this handler with handleTransportFault.
//
// The log line is the operator-visible half — an unregistered UA stops receiving
// inbound calls, which is worth an Error even though no call ended.
func (m *Manager) handleRegisterFailed(_ context.Context, uaHandle Handle, ev UAEvent) {
	m.mu.RLock()
	u, ok := m.uas[uaHandle]
	m.mu.RUnlock()
	if !ok {
		// The UA was destroyed between the give-up and this callback running.
		return
	}
	u.recordRegistrationLost()
	m.log.Error("registration refresh gave up; ua is no longer registered",
		"ua_handle", uaHandle, "err", ev.Err)
}

// handleRegisterRemoved is the registrar's side of the same outcome
// handleRegisterFailed reports: the UA is no longer registered. Here the
// registrar answered 200 OK and granted expires=0, so the binding was REMOVED
// rather than lost — see UAEventRegisterRemoved for why that is a separate kind.
//
// IT REUSES recordRegistrationLost (Rule 16) AND MUST. registered=false,
// expires_s=0 and register_code=0 is one ua_status shape, not two: a second
// writer would be a second chance for the three fields to drift apart. Only the
// LOG LINE differs, because only the FACT differs — Warn, not Error, and no Err:
// nothing malfunctioned, so an operator reading Error here would go looking for a
// broken registrar that answered them correctly.
func (m *Manager) handleRegisterRemoved(_ context.Context, uaHandle Handle, ev UAEvent) {
	m.mu.RLock()
	u, ok := m.uas[uaHandle]
	m.mu.RUnlock()
	if !ok {
		// The UA was destroyed between the refresh and this callback running.
		return
	}
	u.recordRegistrationLost()
	m.log.Warn("registrar removed the binding on a refresh; ua is no longer registered",
		"ua_handle", uaHandle, "reason", ev.Reason)
}

// handleDialogEnded is U14's entry to termination.
//
// IT IS AN ENTRY TO THE EXISTING TERMINAL PATH, NOT A SECOND ONE (Rule 18).
// TryTerminate claims the transition atomically and appends the terminal event,
// which is what triggers §6.3 rule 2's broadcast to EVERY parked waiter
// regardless of its `until`. RecordTermination frees the §12.2.2 concurrency
// slot IMMEDIATELY — at termination, not at eviction — and emitCallLog writes
// the N5 line ONCE, from the same place a local hangup does (decision 6).
// Nothing about a remotely-ended call is special downstream, and nothing here
// may grow a parallel version of any of it.
func (m *Manager) handleDialogEnded(_ context.Context, uaHandle Handle, ev UAEvent) {
	c := m.callByDialogID(uaHandle, ev.DialogID)
	if c == nil {
		// The dialog ended for a call we no longer hold — already torn down by
		// a concurrent hangup, or evicted. Nothing to do; §6.3 says exactly one
		// actor wins a termination.
		return
	}

	if ev.Cause == UACauseMediaNegotiationFailed {
		// §11.2.1: terminated (a dialog existed), reason media_negotiation_failed,
		// terminal event is an EventError carrying detail.kind — NOT EventBye.
		if err := c.TryMediaNegotiationFailed(ev.At, ev.Detail); err != nil {
			return
		}
		defer m.RecordTermination(c)
		return
	}

	if ev.Cause == UACauseTransportFailure {
		// §11.3.1 case 2: state `terminated`, NOT `failed` — the call did reach
		// answered, and §10.3 reserves `failed` for calls that never did. (A
		// dial that drew no usable final response also arrives here, never
		// having answered, and lands `terminated` too, keeping the outcome it
		// had before it became dialog-scoped: CF-037, D-A.) The
		// terminal event is an EventError carrying detail.kind/detail.cause, NOT
		// an EventBye: no BYE was sent, so an EventBye would be a lie (the same
		// D98 reasoning handleResponse's 3xx-6xx branch records).
		//
		// This is DIALOG-SCOPED by construction: c is this dialog's call, so no
		// other call on the UA is touched — unlike handleTransportFault.
		if err := c.TryTransportFailure(ev.At, ev.Detail); err != nil {
			return
		}
		// §6.0b INV-1 Form A, on the line immediately following the successful
		// claim with no statement in between.
		defer m.RecordTermination(c)
		return
	}

	reason, err := terminationReasonFor(ev.Cause)
	if err != nil {
		// The call is NOT terminated with a fabricated reason. It is recorded
		// as an error event so the fault is visible in call_events, not only in
		// the server log, and the call remains reapable by the duration cap and
		// by §11.4's shutdown.
		m.log.Error("unmappable dialog-end cause",
			"ua_handle", uaHandle, "dialog_id", ev.DialogID, "cause", ev.Cause, "err", err)
		c.Append(ev.At, EventError, map[string]any{
			"kind":  "unmappable_dialog_end_cause",
			"cause": string(ev.Cause),
		})
		return
	}

	if err := c.TryTerminate(ev.At, reason, EventBye); err != nil {
		// A concurrent call_hangup won. §6.3: the call terminates once, with
		// one termination_reason. Nothing to correct.
		return
	}
	// §6.0b INV-1, on the line immediately following the successful claim with
	// no statement in between.
	//
	// RecordTermination emits the N5 per-call log line (decision 6). DO NOT add
	// an emitCallLog call here: this path is one of six, and the line belongs at
	// the single terminal transition, not at each entry to it.
	defer m.RecordTermination(c)
}

// handleTransportFault is §11.3.1: a transport fault on a UA terminates every
// live call on that UA with `transport_failure`. UAEventTransportFault REMAINS
// ITS OWN KIND AT P1 — it is not a UADialogEndCause and does not go through
// terminationReasonFor, which is why this handler names the reason directly.
//
// ctx is the DAEMON context (decision 17) and is unused: nothing here does I/O.
// It is kept in the signature so every handler in handleUAEvent's switch has one
// shape.
//
// §6.0b INV-1, **FORM B** (contract §5.6, U23) — the loop form. Form A
// (`defer m.RecordTermination(c)`) is FORBIDDEN here for the same reason it is
// forbidden in destroyUA's and HangupAllLive's loops: a defer fires at FUNCTION
// exit, so call 1's accounting would land only after the last call on the UA had
// been processed, holding every concurrency slot, every active_calls count and
// every ladder retention until then. Form B's three requirements are met below:
//
//  1. the literal marker `// INV-1 LOOP FORM:` is the line IMMEDIATELY
//     following the successful TryTerminate — the token itself is load-bearing,
//     because Task 24's gate B branches on it and without it this site is
//     indistinguishable from an unrecorded claim;
//  2. between that claim and the plain m.RecordTermination(c) there is NO
//     `return`, `continue`, `break`, `goto` or `panic`, and no nested
//     for/switch/select that could contain one;
//  3. m.RecordTermination(c) is the LAST statement of the iteration, so any
//     per-call statement is placed BEFORE it.
//
// The `continue` in the failed-claim branch is OUTSIDE that span and is
// permitted: a TryTerminate that returns non-nil claimed nothing, so there is
// nothing to record.
func (m *Manager) handleTransportFault(_ context.Context, uaHandle Handle, ev UAEvent) {
	// Snapshot the UA's live calls under the registry READ lock and release it
	// before touching any of them. TryTerminate takes the CALL mutex and
	// RecordTermination re-takes m.mu, so neither may run under this hold —
	// §6.3's lock order and INV-2. Same shape as HangupAllLive's snapshot.
	m.mu.RLock()
	var live []*Call
	if u, ok := m.uas[uaHandle]; ok {
		if s := m.sessions[u.sid]; s != nil {
			live = make([]*Call, 0, len(s.liveCalls))
			for _, c := range s.liveCalls {
				if c.uaHandle == uaHandle {
					live = append(live, c)
				}
			}
		}
	}
	m.mu.RUnlock()
	// ---- registry lock released; nothing below runs under it ---------------

	// One log line for the fault itself, outside the INV-1 span. A per-call line
	// would have to sit between the claim and the record, and requirement 3
	// leaves no room for it.
	m.log.Error("transport fault on ua",
		"ua_handle", uaHandle, "live_calls", len(live), "err", ev.Err)

	for _, c := range live {
		// TryTerminate appends the terminal EventError itself, so there is no
		// second Append here: one terminal event per call (§10.5).
		if err := c.TryTerminate(ev.At, "transport_failure", EventError); err != nil {
			continue // already terminated; §6.3 says exactly one caller wins
		}
		// INV-1 LOOP FORM: per-iteration record; a defer here would fire at
		// handleTransportFault's exit and hold every slot until the last call on
		// the UA had been processed.
		m.RecordTermination(c)
	}
}

// handleMediaError records a non-terminal media-loop error (tx_underrun today)
// as an EventError. It uses m.clk.Now() for the timestamp, not ev.At, because
// the TX goroutine that emits UAEventMediaError never sets ev.At (Task 8).
func (m *Manager) handleMediaError(_ context.Context, uaHandle Handle, ev UAEvent) {
	// ForEvent: plan_aborted_call_terminated arrives BECAUSE the call
	// terminated, so the live-only lookup could never deliver it at all.
	c := m.callByDialogIDForEvent(uaHandle, ev.DialogID)
	if c == nil {
		return
	}
	c.applyPlanError(ev.Detail)
	c.Append(m.clk.Now(), EventError, ev.Detail)
}

// handleMediaStart appends §10.5's media_start event (R7/R10). The codec comes
// from the negotiated MediaView; the addresses and latch flag from the event.
func (m *Manager) handleMediaStart(_ context.Context, uaHandle Handle, ev UAEvent) {
	// ForEvent, not callByDialogID. handleMediaStart APPENDS (c.Append below), and
	// "a terminated call has no media loop left to receive on" describes when a
	// media_start can be EMITTED, not when it is HANDLED: the media goroutine's
	// media_start can reach this handler after a remote BYE has already driven
	// RecordTermination, and the live-only lookup would then discard the call's
	// only record of its negotiated codec and latched remote address. Same race,
	// same fix, as the final plan_step and record_stop above.
	c := m.callByDialogIDForEvent(uaHandle, ev.DialogID)
	if c == nil {
		return
	}
	detail := map[string]any{
		"local_media_addr":  ev.LocalMediaAddr,
		"remote_media_addr": ev.RemoteMediaAddr,
		"media_latched":     ev.MediaLatched,
	}
	// Same registry-map access as handleRefresh above: read m.uas under the
	// registry RLock, release it before calling into the UA, per §6.3's lock
	// order (Agent().MediaView must never run while m.mu is held).
	m.mu.RLock()
	u, ok := m.uas[uaHandle]
	m.mu.RUnlock()
	if ok {
		if mv, mvOK := u.Agent().MediaView(ev.DialogID); mvOK {
			detail["codec"] = mv.Codec
			if detail["local_media_addr"] == "" {
				detail["local_media_addr"] = mv.LocalMediaAddr
			}
		}
	}
	c.Append(m.clk.Now(), EventMediaStart, detail)
}

// handlePlanStep appends a §10.7 plan_step event. The executor never sets ev.At,
// so m.clk.Now() timestamps it, same as handleMediaError.
func (m *Manager) handlePlanStep(_ context.Context, uaHandle Handle, ev UAEvent) {
	// ForEvent, not callByDialogID: a plan's FINAL step races the terminal
	// live->terminated move and would otherwise be dropped (see
	// callByDialogIDForEvent).
	c := m.callByDialogIDForEvent(uaHandle, ev.DialogID)
	if c == nil {
		return
	}
	// The event is BOTH appended to the log and folded into the call's own
	// media_plan view (§2.3). Two effects, one event, one handler — the view is
	// derived from the event stream, not from a second channel.
	c.applyPlanStep(ev.Detail)
	c.Append(m.clk.Now(), EventPlanStep, ev.Detail)
}

// handlePlanRecordEvent appends record_start/record_stop for a media_plan's
// record step (UAEventRecordStart/UAEventRecordStop, §10.5) — the discrete
// media_record_start/stop tools append these directly from ToolService instead
// (they already hold the *Call) and never reach this handler.
func (m *Manager) handlePlanRecordEvent(_ context.Context, uaHandle Handle, ev UAEvent, t EventType) {
	// ForEvent: a media_plan's record step is stopped BY the executor during
	// teardown, so record_stop is in exactly the same race as the final
	// plan_step above. The discrete media_record_* tools never reach here.
	c := m.callByDialogIDForEvent(uaHandle, ev.DialogID)
	if c == nil {
		return
	}
	c.Append(m.clk.Now(), t, ev.Detail)
}

// handleInbound was R14's incoming_call path. Its body now lives in
// admitInbound (internal/session/admission.go), reached through the SYNCHRONOUS
// OnAdmit channel (I2): admission decides accept/reject BEFORE sipua rings,
// rather than creating the Call one-way after the ring. There is deliberately
// no handleInbound and no UAEventInbound case in handleUAEvent.
