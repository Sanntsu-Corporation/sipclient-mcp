package session

import (
	"context"
	"fmt"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// UADestroy is ua_destroy (§10.2). OWNER-CHECKED: a handle owned by another
// session returns not_found, never denied — `denied` would disclose that the
// handle exists, which is exactly what §12.2's not_found posture prevents (R11).
//
// IT DESTROYS ONLY h (multi-UA-per-session wave). Phase 1's whole-session
// deletion is reversed: the session record, and every OTHER UA it still
// holds, are untouched. If h was the session's last live UA, the resulting
// empty record is governed by limits.session_resume_window (JanitorSweep),
// not deleted here — restoring the pre-Phase-1 rule call.go's `expiresAt`
// doc comment already names.
//
// THIS PATH NOW PRESERVES §N3's `gone`-FOR-registry_retention CONTRACT, THE
// SAME AS THE ADMIN-FACING DestroyUA PATH. destroyUA's step 4 leaves a
// terminated-UA entry behind either way; the only reason the agent-facing
// path used to answer `not_found` immediately was that UADestroy deleted the
// whole session record a moment later, taking the entry with it. It no
// longer does, so the two entry points now differ in NO observable respect
// for this handle — both are pinned by destroy_test.go.
//
// h's ownership check still runs first (destroyUA's requireSession != nil
// branch), so a foreign handle still returns not_found.
func (m *Manager) UADestroy(ctx context.Context, sid string, h Handle) (AdminDestroyed, error) {
	// The ownership check is destroyUA's own (requireSession != nil): a
	// handle belonging to another session, or no live handle at all, returns
	// not_found before anything is torn down or deleted.
	//
	// MULTI-UA-PER-SESSION WAVE: this now destroys ONLY h. The session and
	// every sibling UA it still holds are untouched; if h was the session's
	// last live UA, the now-empty record is left in place for
	// limits.session_resume_window to govern (JanitorSweep), not deleted
	// here. This restores the pre-Phase-1 rule call.go's expiresAt doc
	// comment already names, and it is why destroyUA no longer needs to set
	// sessionRecord.closing on this path (see that field's own doc comment
	// in call.go) — there is no longer a session deletion for a racing
	// ua_create to land inside.
	return m.destroyUA(ctx, h, &sid)
}

// DestroyUA is §12.7's admin DELETE: THE SAME TEARDOWN with the ownership check
// omitted (Rule 16). The operator is not a session and holds no handles.
//
// A SECOND TEARDOWN PATH IS A DEFECT. §12.7: "Reusing ua_destroy's
// implementation is deliberate: a second teardown path would be a second set of
// bugs." §14.2's acceptance drives both entry points against one fixture and
// requires the observed BYE and Expires: 0 sequences to be IDENTICAL.
//
// THIS PATH HAS NEVER DELETED THE SESSION RECORD. It is an operator escape
// hatch, not the agent-facing session lifecycle; making it delete a session
// an operator never opened would be a surprising semantic on a second
// caller. The session (if it still exists) is simply left to its own TTL —
// THE SAME RULE UADestroy NOW FOLLOWS TOO (multi-UA-per-session wave), so
// this is no longer something that sets the two entry points apart.
//
// THIS PATH SATISFIES §N3's `gone`-FOR-registry_retention CONTRACT, THE SAME
// AS THE AGENT-FACING UADestroy PATH: the record it leaves in place is what
// holds the retention set and the tombstone ring, so ua_status on a handle
// destroyed HERE answers `gone`, not `not_found`, for the retention window
// (bounded in practice by the session's own TTL — see
// policy.Limits.RegistryRetention). See UADestroy's own doc comment: the two
// entry points now differ in NO observable respect for a destroyed handle.
func (m *Manager) DestroyUA(ctx context.Context, uaHandle string) (AdminDestroyed, error) {
	return m.destroyUA(ctx, Handle(uaHandle), nil)
}

// destroyUA is the ONE implementation. requireSession is non-nil for
// ua_destroy and nil for the admin DELETE; that pointer is the ONLY difference
// between the two entry points.
//
// LOCK DISCIPLINE — THE POINT OF THIS FUNCTION. The registry lock is taken to
// resolve the UA and claim the transition, and RELEASED BEFORE ANY NETWORK
// WRITE. The BYE grace period is 10s by default; holding m.mu across it inside
// an HTTP handler stalls EVERY CONCURRENT TOOL CALL ON THE SERVER for ten
// seconds — an OUTAGE, not a latency blip. This is §6.3's "no lock is held
// across a network write" applied to the admin plane (§12.7).
//
// THE TEARDOWN RUNS ON THE DAEMON CONTEXT, NEVER ON THE CALLER'S. This is
// LOCKED DECISION 17's third path, and it is the one the plan previously got
// wrong. The caller's ctx is an HTTP request context — `r.Context()` for the
// admin DELETE, the tool call's context for ua_destroy — and it is therefore
// DELIBERATELY NOT ACCEPTED as a parameter here, so it cannot be threaded into
// the teardown by mistake. It governs the RESPONSE and nothing else.
//
// WHAT GOES WRONG IF IT IS THREADED IN, spelled out because "use the daemon
// context" reads as a style note until you see the state it leaves behind. The
// operator's curl times out, or any reverse proxy gives up below the 10s grace
// period — the EXPECTED case on an endpoint deliberately designed to take up to
// ten seconds, not an exotic one. Then:
//
//  1. MarkDestroyed has ALREADY been claimed under the registry lock above, so
//     the UA is off the live path and no retry can re-enter this function.
//  2. The BYE context is already cancelled, so Hangup errors. Survivable: the
//     call is terminated locally either way.
//  3. Unregister errors IMMEDIATELY, so NO `REGISTER Expires: 0` IS EVER SENT
//     and setRegistered(false) is skipped. The registration stays live at the
//     registrar.
//  4. Close errors, so the UDP SOCKET MAY NEVER BE RELEASED.
//  5. RecordUADestroyed still runs: the handle leaves the live registry and the
//     max_uas_total slot frees.
//  6. A repeat DELETE returns 404, because the UA is no longer UALive.
//
// The UA is now absent from every view, still holds a registration and possibly
// its bound port, and NO PATH IN THE DESIGN CAN RECLAIM IT — which is precisely
// the state §12.7 exists to make exitable, re-created one level down, this time
// with a 200 response and a decremented active_uas telling the operator it
// worked. P1d Task 19's TestAdminDeleteCompletesAfterAdminClientDisconnects is
// the wire-level assertion of this property, and P1d Step 14 states in terms
// that the fix belongs HERE and that the handler must not grow its own
// goroutine, context or timeout to work around it.
func (m *Manager) destroyUA(_ context.Context, h Handle, requireSession *string) (AdminDestroyed, error) {
	grace := m.limits().ShutdownGracePeriod.Duration()

	// ONE teardown context, derived from the DAEMON context, covering all three
	// network steps below: the BYEs, the Expires: 0 and the transport close. A
	// client disconnect cannot cancel it; the grace period alone bounds it.
	tdCtx, cancelTeardown := context.WithTimeout(m.daemonCtx, grace)
	defer cancelTeardown()

	// ---- phase 1: under the registry lock, and NOTHING ELSE under it -------
	m.mu.Lock()
	u, ok := m.uas[h]
	if !ok || u.State() != UALive {
		m.mu.Unlock()
		// §12.7: 404 for an unknown handle OR one already destroyed. §10.2 R11:
		// not_found for another session's handle, indistinguishable from this.
		return AdminDestroyed{}, apierr.NotFound(fmt.Sprintf("no live ua bears handle %s", h))
	}
	if requireSession != nil && u.sid != *requireSession {
		m.mu.Unlock()
		return AdminDestroyed{}, apierr.NotFound(fmt.Sprintf("no live ua bears handle %s", h))
	}
	// MarkDestroyed claims live -> destroyed. Exactly one caller wins, so
	// ua_destroy and the admin DELETE cannot both tear down; the loser observes
	// the winner's result (§6.3's invariant at the UA level).
	if !u.MarkDestroyed(m.clk.Now()) {
		m.mu.Unlock()
		return AdminDestroyed{}, apierr.NotFound(fmt.Sprintf("no live ua bears handle %s", h))
	}
	// Take references to everything the teardown needs while we still hold the
	// lock, so nothing below has to reach back for it.
	//
	// `s` MAY BE NIL: a session record can be deleted while one of its UAs is
	// still live and mid-teardown (destroySessionAndDelete deletes the record
	// without waiting for an already-claimed teardown to report back — see
	// RecordUADestroyed). The teardown itself needs no record; only the
	// live-call sweep below does.
	s := m.sessions[u.sid]
	var live []*Call
	if s != nil {
		live = make([]*Call, 0, len(s.liveCalls))
		for _, c := range s.liveCalls {
			if c.uaHandle == h {
				live = append(live, c)
			}
		}
	}
	agent, registered, sid := u.agent, u.Registered(), u.sid
	m.mu.Unlock()
	// ---- THE REGISTRY LOCK IS NOW RELEASED. Everything below is I/O. -------

	res := AdminDestroyed{UAHandle: string(h), Session: sid}

	// Step 1: BYE every live dialog, bounded by the grace period.
	//
	// termination_reason is "local_hangup" — §10.3's enum gains NO new value.
	// §12.7 and §11.4 both say so: call_hangup, the shutdown BYE and the admin
	// DELETE's BYE are one act, a locally-initiated BYE.
	// §6.0b INV-1, **FORM B** (contract §5.6, U23) — the sanctioned loop form.
	// Form A — deferring RecordTermination(c) until function exit — is
	// FORBIDDEN here, not merely discouraged: a defer fires at FUNCTION exit, so
	// it would not run until destroyUA returned, after every other call had
	// been BYEd — the accounting for call 1 would land after call N's BYE, and a
	// slow far end would hold every concurrency slot, every active_calls count
	// and every ladder retention open for the full grace period. That is a
	// worse outage than the leak Form A prevents. Form B's three requirements
	// are met below and each is mechanically checkable by Task 24's gate:
	//
	//   1. the marker comment below is the line IMMEDIATELY following the
	//      successful TryHangup;
	//   2. between the successful TryHangup and the plain RecordTermination(c)
	//      there is NO `return`, `continue`, `break`, `goto` or `panic`, and no
	//      nested for/switch/select that could contain one — Hangup's error is
	//      LOGGED AND FALLEN THROUGH, because an unconfirmed BYE is expected, not
	//      exceptional;
	//   3. RecordTermination(c) is the LAST statement of the iteration for that
	//      call. `res.CallsTerminated++` is therefore counted BEFORE it, not
	//      after — the counter is a pure increment on an already-decided outcome,
	//      and putting it after the record would break requirement 3.
	//
	// The `continue` inside the failed-claim branch is not in that span: it is on
	// the path where TryHangup did NOT succeed, so nothing was claimed and there
	// is nothing to record. This is exactly the shape of contract §6.0b's worked
	// Form B example.
	for _, c := range live {
		if err := c.TryHangup(m.clk.Now(), "local_hangup"); err != nil {
			continue // a concurrent hangup won; §6.3 says exactly one does
		}
		// INV-1 LOOP FORM: per-iteration record; a defer here would fire at
		// destroyUA's exit and hold every slot until the whole loop finished.
		res.CallsTerminated++
		if err := agent.Hangup(tdCtx, c.DialogID(), "local_hangup"); err != nil {
			// A far end that never 200s its BYE is expected, not exceptional:
			// §11.4's grace period exists for exactly this. The call is already
			// terminated locally, so the teardown proceeds.
			m.log.Warn("bye not confirmed within the grace period",
				"ua_handle", h, "call_handle", c.Handle(), "err", err)
		}
		m.RecordTermination(c)
	}

	// Step 2: REGISTER Expires: 0, only if the UA was registered.
	//
	// ORDER IS LOAD-BEARING: unregistering first would leave the in-dialog BYEs
	// above routing to an address the registrar no longer advertises.
	if registered {
		if err := agent.Unregister(tdCtx); err != nil {
			m.log.Warn("unregister failed during teardown", "ua_handle", h, "err", err)
		} else {
			res.Unregistered = true
			u.setRegistered(false)
		}
	}

	// Step 3: close the transport. On tdCtx, so a disconnected client cannot
	// leave the bound socket behind.
	if err := agent.Close(tdCtx); err != nil {
		m.log.Warn("ua close failed during teardown", "ua_handle", h, "err", err)
	}

	// Step 4: leave the §N3 terminated registry entry behind, so the handle
	// answers `gone` rather than `not_found` for limits.registry_retention.
	//
	// THAT ENTRY NOW SURVIVES ON BOTH PATHS (multi-UA-per-session wave).
	// UADestroy no longer deletes the session record: it destroys only h, so
	// this entry and its tombstone outlive the call the same way they do on
	// the admin DestroyUA path — see UADestroy's own doc comment. This line is
	// unconditional regardless: it is the ONE teardown implementation (Rule
	// 18), and making it branch on which entry point called it would be
	// exactly the second teardown path §12.7 names as a defect.
	m.RecordUADestroyed(u)
	return res, nil
}
