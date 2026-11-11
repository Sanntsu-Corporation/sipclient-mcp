package session

import (
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// ---- N5 per-call log (decision 6) ------------------------------------------
//
// `CallLogRecord` is transcribed VERBATIM from contract §2.5.5. `buildCallLog`
// and `emitCallLog` below are their REAL implementation (Task 11b Step 6,
// §2.5.5, U25/U26) — see each function's own doc comment for the §6.0b INV-2
// class 1 split between them.

// CallLogRecord is the N5 per-call log line's shape.
type CallLogRecord struct {
	// P1.
	CallHandle        string `json:"call_handle"`
	UAHandle          string `json:"ua_handle"`
	Session           string `json:"session"`
	Direction         string `json:"direction"`
	ToURI             string `json:"to_uri"` // destination only; NEVER credentials
	Transport         string `json:"transport"`
	State             string `json:"state"`
	TerminationReason string `json:"termination_reason"`
	SIPCode           int    `json:"sip_code"`
	DurationMS        int64  `json:"duration_ms"`

	// P2 (media). Zero/nil at P1 — decision 6: the line gains columns across four
	// phases, and the "no credential in any log line" test asserts ONE code path.
	Codec           string   `json:"codec"`
	SRTP            bool     `json:"srtp"`
	PacketsSent     int64    `json:"packets_sent"`
	PacketsReceived int64    `json:"packets_received"`
	LossPct         *float64 `json:"loss_pct"`
	Tier            string   `json:"tier"`
	MOSEstimate     *float64 `json:"mos_estimate"`
	MOSLQO          *float64 `json:"mos_lqo"`
}

// buildCallLog is PURE (contract §2.5.5, U26): it reads the call and the clock
// and returns a value, performing no I/O and taking no lock outside this
// package — which is why RecordTermination may call it from inside m.mu.
//
// IT READS THROUGH Call's OWN MUTEX-GUARDED GETTERS, never c's raw fields
// directly — the same registry-then-call nesting CreateCall already uses for
// u.State() under m.mu.Lock(). m.uas IS READ DIRECTLY, because buildCallLog's
// one caller (RecordTermination) already holds m.mu when it calls this.
//
// Keep it PURE. Anything that writes, logs or reaches into another package's
// synchronisation belongs in emitCallLog below, not here.
func (m *Manager) buildCallLog(c *Call) CallLogRecord {
	var transport string
	if u, ok := m.uas[c.UAHandle()]; ok {
		transport = string(u.Config().Transport)
	}
	return CallLogRecord{
		CallHandle:        string(c.Handle()),
		UAHandle:          string(c.UAHandle()),
		Session:           c.SessionID(),
		Direction:         string(c.Direction()),
		ToURI:             SanitizeToURI(c.ToURI()),
		Transport:         transport,
		State:             string(c.State()),
		TerminationReason: c.TerminationReason(),
		SIPCode:           c.LastResponseCode(),
		DurationMS:        c.DurationMS(m.clk.Now()),
	}
}

// emitCallLog performs the actual slog write. IT IS CALLED WITH NO LOCK HELD,
// from exactly one call site: RecordTermination, after m.mu is released
// (§6.0b INV-2 class 1).
//
// It takes the RECORD, not the *Call, and that signature is the enforcement:
// with the value already assembled there is nothing left for this function to
// read under a lock, so the emit-after-release structure cannot be quietly
// reverted by someone moving the call back up a few lines — it would no
// longer have anything to build from.
func (m *Manager) emitCallLog(rec CallLogRecord) {
	m.log.Info("call terminated",
		"call_handle", rec.CallHandle, "ua_handle", rec.UAHandle, "session", rec.Session,
		"direction", rec.Direction, "to_uri", rec.ToURI, "transport", rec.Transport,
		"state", rec.State, "termination_reason", rec.TerminationReason,
		"sip_code", rec.SIPCode, "duration_ms", rec.DurationMS,
		"codec", rec.Codec, "srtp", rec.SRTP,
		"packets_sent", rec.PacketsSent, "packets_received", rec.PacketsReceived,
		"loss_pct", rec.LossPct, "tier", rec.Tier,
		"mos_estimate", rec.MOSEstimate, "mos_lqo", rec.MOSLQO)
}

// RecordTermination moves a call from its session's LIVE set to its TERMINATED
// set and stamps the §N3 retention clock, which is measured FROM THE
// TRANSITION TO TERMINATED.
//
// This runs IMMEDIATELY on termination, not at eviction, which is also what
// makes §12.2.2's concurrency slots free up immediately (Task 11).
//
// It also performs the IMMEDIATE CAP CHECK, so a burst of terminations cannot
// outrun the hourly ticker.
//
// IT IS ALSO THE ONE PLACE THE N5 PER-CALL LOG LINE IS EMITTED (locked decision
// 6: "a single emitCallLog() called at the terminal transition"). The call sits
// here rather than at each caller because P1 has SIX termination paths —
// call_hangup, call_reject, the §11.3 duration cap, Task 11a's ua_destroy /
// admin DELETE teardown, §11.4's HangupAllLive, and U14's remote BYE / ring
// timeout — and decision 6's stated rationale is that "no credential ever
// appears in any log line" must be assertable against ONE code path rather than
// six. Six call sites is also six chances to forget one, which is exactly the
// defect this arrangement prevents: §5 N5's acceptance requires EXACTLY ONE
// line per terminated call, and a path that skips the call emits zero.
//
// THE FIRES-EXACTLY-ONCE GUARD IS THE `c.accounted` FLAG BELOW. A second
// RecordTermination for the same call returns before logging, so a duplicated
// line is unrepresentable — which matters because N5's per-call accounting
// reads two lines as two calls. That guard is ALSO what makes this function
// IDEMPOTENT WITH RESPECT TO THE ACCOUNTING, which §6.0b INV-1 now requires:
// INV-1's deferred call can race the janitor's own eviction path, and a double
// decrement of m.liveTotal would corrupt exactly the §12.2.2 caps the invariant
// exists to protect.
//
// THE GLOBAL DECREMENT IS NOT GATED ON THE SESSION RECORD STILL EXISTING, and
// that is the point of the flag: the guard used to be
// `m.sessions[c.sess.id]` plus `s.liveCalls[c.handle]`, which made the
// m.liveTotal decrement conditional on a record a concurrent
// destroySessionAndDelete may already have deleted out from under an
// IN-FLIGHT teardown. A real termination that finished a moment too late was
// then never accounted for, permanently burning a
// max_concurrent_calls_total slot for the life of the daemon. Only the
// PER-SESSION bookkeeping (the move into s.terminatedCalls, the tombstone
// ring, the terminated-call cap) genuinely needs the record, and only that
// part is skipped when it is gone — the call's registry entry is evicted
// outright instead, because nothing would ever visit it again.
//
// §6.0b INV-2, CLASS 1 — THE RECORD IS BUILT UNDER m.mu AND WRITTEN AFTER IT IS
// RELEASED. As first drafted this function called m.emitCallLog(c) INSIDE the
// lock hold, and emitCallLog has exactly one call site, so that was EVERY call
// termination on the server serialising a JSON marshal plus a synchronous
// io.Writer write inside the global registry write lock. slog's JSONHandler
// writes synchronously: point it at a pipe to a stalled log shipper, an
// NFS-mounted file or a slow terminal and one log write stalls every tool call
// on the server. That is the identical outage shape §12.7's registry-lock-release
// property spends a whole task, a unit test and a wire test defending against,
// on a hotter path — §12's exit criterion terminates fifty calls this way.
//
// NOTE THERE IS DELIBERATELY NO `defer m.mu.Unlock()`. The unlock must precede
// the write, and a defer would put it after. The metrics calls stay INSIDE the
// hold: they are pure atomics, not I/O (INV-2's carve-out), and moving them
// would be Rule 19 scope creep that costs the accounting its atomicity.
//
// I1: the termination-reason increment is guarded by Registry.HasReason
// before it fires. IncTerminationReason PANICS BY DESIGN on a label outside
// the set metrics.New was given (see its own comment) — and with no
// defer m.mu.Unlock() above, an unguarded panic here would fire UNDER m.mu
// and never release it, wedging every subsequent m.mu operation on the
// daemon. HasReason skips an unregistered label instead of calling into the
// panic path. This is a guard on the LABEL only: the increment itself is
// unmoved and stays inside the hold for the same atomicity reason as before.
func (m *Manager) RecordTermination(c *Call) {
	// INV-2 class 4: the policy read happens BEFORE m.mu is acquired, never from
	// inside the critical section.
	lim := m.policy.Current().Limits
	m.mu.Lock()
	if c.accounted {
		m.mu.Unlock()
		return // already recorded; termination wins exactly once (§6.3)
	}
	c.accounted = true
	// buildCallLog is PURE: it reads the call and the clock and returns a value.
	// It performs no I/O and takes no lock outside this package.
	rec := m.buildCallLog(c)
	// THE GLOBAL COUNT IS DECREMENTED UNCONDITIONALLY — see the doc comment.
	m.liveTotal--
	if m.metrics != nil {
		m.metrics.AddActiveCalls(-1)
		// handleResponse's TryFail branch is, as of Task 11c, the one caller
		// that can leave TerminationReason() "" (D97: the spec's own worked
		// wire result for a rejected outbound INVITE carries no
		// termination_reason at all). IncTerminationReason PANICS on a label
		// outside the enum metrics.New was constructed with, by design — so
		// "" must not reach it. HasReason(r) generalises the same guard (I1):
		// it also skips any OTHER label the Registry was never given a
		// counter for, so a termination path that produces an unregistered
		// reason is skipped rather than panicking under m.mu.
		if r := c.TerminationReason(); r != "" && m.metrics.HasReason(r) {
			m.metrics.IncTerminationReason(r)
		}
	}
	// ---- PER-SESSION bookkeeping: needs the record, and ONLY this needs it --
	if s, ok := m.sessions[c.sess.id]; ok {
		delete(s.liveCalls, c.handle)
		s.terminatedCalls = append(s.terminatedCalls, c) // oldest-terminated first
		m.enforceTerminatedCallCapLocked(s, lim)
	} else {
		// The session record was deleted while this teardown was in flight
		// (destroySessionAndDelete racing an already-claimed termination).
		// There is no retention set to move the call into and no tombstone
		// ring to record it in, and nothing else ever visits a session that
		// is no longer in m.sessions — JanitorSweep only walks m.sessions —
		// so the registry entry is reclaimed here rather than orphaned. The
		// handle answers not_found from now on, which is what ResolveCall
		// already returns for a call whose session is gone.
		m.evictCallLocked(nil, c)
	}
	m.mu.Unlock()

	// ---- THE REGISTRY LOCK IS RELEASED. The N5 write happens out here. ------

	// Close any active pcap capture PROMPTLY at the terminal transition, so an
	// armed call that terminates without an explicit capture_stop does not hold
	// its file handle until registry eviction (tap.Evict, up to
	// registry_retention later). Out of m.mu (a Sink edge, not a registry one).
	// Idempotent: DisarmCapture caches its result, so a later capture_stop
	// still returns the counters, and tap.Evict remains the final cleanup.
	// Unarmed calls just get not_found here, discarded.
	if m.tap != nil {
		_, _ = m.tap.DisarmCapture(m.daemonCtx, string(c.UAHandle()), c.CallID())
	}

	m.emitCallLog(rec)
}

// RecordUADestroyed is the UA counterpart. It performs no I/O at all, so the
// defer form is correct here and the asymmetry with RecordTermination above is
// deliberate rather than an oversight.
//
// IT SPLITS GLOBAL FROM PER-SESSION ACCOUNTING FOR THE SAME REASON
// RecordTermination DOES, and this is the path the leak was actually
// reproduced on: a ua_destroy that has already won MarkDestroyed can sit
// inside agent.Close() for the whole grace period while a concurrent TTL reap
// (ExpireSessions -> destroySessionAndDelete) sees the handle still in
// s.liveUAs, loses its own claim, and deletes the session record anyway. When
// the original teardown finally got here the record was gone, this function
// early-returned, and m.liveUATotal was NEVER decremented — one
// max_uas_total slot burned for the life of the daemon, with m.uas[handle]
// orphaned beside it where no sweep would ever find it again. The global
// decrement below therefore runs off u.accounted alone, and the missing
// record costs only the per-session retention entry.
func (m *Manager) RecordUADestroyed(u *UA) {
	lim := m.policy.Current().Limits // INV-2 class 4: policy read BEFORE the lock
	now := m.clk.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if u.accounted {
		return // already recorded; destruction wins exactly once (§6.3)
	}
	u.accounted = true
	// THE max_uas_total SLOT FREES HERE, AT DESTRUCTION, NOT AT EVICTION —
	// exactly as RecordTermination frees the max_concurrent_calls_total slot
	// above, and for the same reason. §12.7's exhaustion recovery ("with
	// limits.max_uas_total: 2 and both UAs stranded … after the two admin
	// DELETEs it succeeds") is satisfiable ONLY if this decrement is here: the
	// handle stays in m.uas for the whole registry_retention window so ua_status
	// can still answer, and evictUALocked is what finally removes it.
	m.liveUATotal--
	if m.metrics != nil {
		m.metrics.AddActiveUAs(-1)
	}
	// ---- PER-SESSION bookkeeping: needs the record, and ONLY this needs it --
	s, ok := m.sessions[u.sid]
	if !ok {
		// The session record was deleted while this teardown was in flight.
		// Nothing will ever visit this UA again (JanitorSweep only walks
		// m.sessions), so reclaim its registry entry here instead of leaving
		// it orphaned in m.uas forever. No tombstone is possible or needed —
		// ResolveUA already answers not_found once the session is gone.
		m.evictUALocked(nil, u)
		return
	}
	delete(s.liveUAs, u.handle)
	s.terminatedUAs = append(s.terminatedUAs, u)
	m.enforceTerminatedUACapLocked(s, lim)

	// The session just transitioned to empty (multi-UA-per-session wave):
	// refresh lastSeen to NOW so sessionUsableLocked's resume-window clock
	// (registry.go) starts at the moment of transition, not at whatever
	// Seen() last recorded — which the admin-facing teardown path never
	// touches on its own. See TestAdminDestroyOfTheLastUARefreshesTheResumeWindowEvenWhenIdle.
	if m.sessionHasNoLiveObjectsLocked(s) {
		s.lastSeen = now
	}
}

// enforceTerminatedCallCapLocked evicts OLDEST-TERMINATED FIRST, ahead of the
// retention window, when max_terminated_calls_per_session is exceeded.
//
// LIVE CALLS DO NOT COUNT: only s.terminatedCalls is measured here.
// Caller holds m.mu.
//
// §6.0b INV-2, CLASS 4 — IT TAKES `lim` AS A PARAMETER AND DOES NOT CALL
// m.limits(). m.limits() is m.policy.Current(), and calling it from inside the
// m.mu critical section is a lock nesting from the top of §6.3's declared
// hierarchy into a package whose internal synchronisation is unspecified in
// every document in this wave (policy.Store is declared only as
// `type Store struct{ /* ... */ }`). Hoisting the read to the caller REMOVES the
// nesting instead of documenting it, costs one parameter, and is exactly what
// CreateCall already does correctly. Do not "simplify" this back to m.limits().
func (m *Manager) enforceTerminatedCallCapLocked(s *sessionRecord, lim policy.Limits) {
	maxTerminated := lim.MaxTerminatedCallsPerSession
	for len(s.terminatedCalls) > maxTerminated {
		oldest := s.terminatedCalls[0]
		s.terminatedCalls = s.terminatedCalls[1:]
		m.evictCallLocked(s, oldest)
	}
}

// enforceTerminatedUACapLocked is the UA counterpart. LIVE UAS DO NOT COUNT.
// It takes `lim` for the same INV-2 class 4 reason.
func (m *Manager) enforceTerminatedUACapLocked(s *sessionRecord, lim policy.Limits) {
	maxTerminated := lim.MaxTerminatedUAsPerSession
	for len(s.terminatedUAs) > maxTerminated {
		oldest := s.terminatedUAs[0]
		s.terminatedUAs = s.terminatedUAs[1:]
		m.evictUALocked(s, oldest)
	}
}

// evictCallLocked removes a terminated call's registry entry. Caller holds
// m.mu — this is the registry -> call order the §6.3 rule 5 leaf declaration
// exists to keep safe.
//
// INTEGRATION WITH §6.3 RULE 3: MarkGoneAndWake sets the terminal `gone` flag
// UNDER THE CALL MUTEX and THEN wakes the remaining waiters, in that order,
// under that one hold. Eviction is NOT merely a map deletion.
//
// A NIL `s` IS LEGAL and means "the owning session record is already gone"
// (RecordTermination's late-teardown path). Everything registry-wide still
// runs; only the per-session tombstone is skipped, because a handle whose
// session no longer exists answers not_found from ResolveCall regardless of
// any ring it could have been written into.
func (m *Manager) evictCallLocked(s *sessionRecord, c *Call) {
	c.MarkGoneAndWake()
	delete(m.calls, c.handle)
	// The tombstone is what makes §N3's gone-vs-not_found distinction survive
	// eviction. It is BOUNDED (U10): see newHandleRing.
	if s != nil {
		s.callTombstones.add(c.handle)
	}
	// U7: free the call's LADDER RING too. A registry entry and a ladder ring
	// are TWO allocations with ONE lifetime; freeing the first and leaking the
	// second is invisible to every retention test — the handle still answers
	// `gone` correctly — while the process grows by one ladder per call
	// forever. Evict exists on session.Tap for this one caller, and Task 10
	// Step 9 asserts the reclamation rather than trusting this line.
	//
	// THE TAP IS KEYED BY SIP Call-ID, NOT BY THE CALL HANDLE: it is a
	// server-wide sink fed by sipua, which never learns a handle (§6.2.1).
	// c.CallID() is populated from DialResult.CallID outbound and UAEvent.CallID
	// inbound — the channel the contract's §2.5 amendment added, without which
	// this call had nothing to pass and reclaimed nothing.
	//
	// The empty-string guard is NOT defensive padding: a call that failed before
	// its INVITE went out has no dialog and no Call-ID, and Evict("") would
	// collide across every such call.
	//
	// Evict ALSO RELEASES THE Tap.Retain taken at dialog establishment (U18).
	// It is the ONLY release — there is no Release method, because a retention
	// is exactly as long-lived as the ring it protects. This line is therefore
	// no longer merely an optimisation: skipping it leaks a RETAINED ring, which
	// the least-recently-written policy can never reclaim because retained rings
	// are excluded from its candidate set (contract §2.7). Every path by which a
	// call leaves the registry — the janitor sweep, the terminated-call cap and
	// EvictCallForTest — runs through here, which is what makes the release
	// unconditional.
	//
	// Tap.Evict runs under m.mu. That is sound and deliberate, and §6.0b INV-2
	// now SANCTIONS IT BY NAME as class 3: it is an IN-MEMORY ring delete, not a
	// network or artifact write, so §6.3's "no lock is held across a network
	// write" is not engaged, and the edge is ONE-DIRECTIONAL — the datagram path
	// takes trace.Sink.mu and never reaches back for m.mu — so it cannot close a
	// cycle. Task 24's lock-order review gate records this as a declared
	// registry -> Sink edge. THE REVERSE EDGE MUST NEVER BE ADDED. Note that
	// U18's Tap.Retain does NOT use this sanction: it is called holding no lock
	// at all (see setDialogIdentity), and moving it under a lock is the tempting
	// "tidy" the gate names it in order to prevent.
	if m.tap != nil {
		if id := c.CallID(); id != "" {
			// HIGH-3: evict the ring under the SAME (ua_handle, call_id) key it
			// was retained/written under, so the release still names the right
			// ring and the U18 retained-ring bound still holds.
			m.tap.Evict(m.daemonCtx, string(c.UAHandle()), id)
		}
	}
}

// evictUALocked removes a UA's registry entry. A NIL `s` is legal and means
// the owning session record is already gone — see evictCallLocked.
func (m *Manager) evictUALocked(s *sessionRecord, u *UA) {
	delete(m.uas, u.handle)
	if s != nil {
		s.uaTombstones.add(u.handle)
	}
}

// SweepResult reports what one retention pass reclaimed. §11.4's final janitor
// pass logs these counts, which is why JanitorSweep returns rather than being
// the void SweepNow() an earlier draft declared.
type SweepResult struct {
	CallsEvicted    int
	UAsEvicted      int
	SessionsExpired int
}

// JanitorSweep runs one retention pass: every terminated entry whose retention
// window has elapsed is evicted, and every EMPTY session past its resume window
// is expired.
//
// LIVE CALLS AND LIVE UAS ARE NEVER VISITED. registry_retention is a
// terminated-entry clock and nothing else: it never starts, and never expires,
// for anything still live. A live UA therefore has no time-based destruction
// trigger at all (D11 point 5).
//
// `now` is a parameter rather than an m.clk.Now() read internally so a test
// can assert against an instant it chose. TODAY the hourly tick
// (StartJanitor below) is the only caller that exists, and it passes
// m.clk.Now() rather than the tick's own instant — decision D56 sanctions
// this as unobservable at P1, so this is not a bug to fix here. A startup
// sweep and §11.4's final pass are the two remaining callers this
// parameterisation is designed for; neither is wired up yet.
func (m *Manager) JanitorSweep(now time.Time) SweepResult {
	lim := m.limits()
	retention := lim.RegistryRetention.Duration()
	resumeWindow := lim.SessionResumeWindow.Duration()

	var res SweepResult
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		keptCalls := s.terminatedCalls[:0]
		for _, c := range s.terminatedCalls {
			if now.Sub(c.TerminatedAt()) >= retention {
				m.evictCallLocked(s, c)
				res.CallsEvicted++
				continue
			}
			keptCalls = append(keptCalls, c)
		}
		s.terminatedCalls = keptCalls

		keptUAs := s.terminatedUAs[:0]
		for _, u := range s.terminatedUAs {
			if now.Sub(u.DestroyedAt()) >= retention {
				m.evictUALocked(s, u)
				res.UAsEvicted++
				continue
			}
			keptUAs = append(keptUAs, u)
		}
		s.terminatedUAs = keptUAs

		// §12.6's Lifetime rule. A session record NEVER ages out while it owns
		// ANY live UA or call — that is what keeps the identity needed to
		// resume control from expiring out from under a live UA, and it is why
		// D11 point 5's "no time-based destruction" is reachable at all. ONLY
		// AN EMPTY RECORD ages out, and only after session_resume_window.
		//
		// "Empty" includes the retention sets: a session still holding a
		// terminated call owes that handle a `gone`, and dropping the record
		// would answer `not_found` instead.
		if m.sessionEmptyLocked(s) && now.Sub(s.lastSeen) >= resumeWindow {
			delete(m.sessions, id)
			res.SessionsExpired++
		}
	}
	if m.metrics != nil {
		m.metrics.IncJanitorSweeps()
	}
	return res
}

func (m *Manager) sessionEmptyLocked(s *sessionRecord) bool {
	return len(s.liveCalls) == 0 && len(s.liveUAs) == 0 &&
		len(s.terminatedCalls) == 0 && len(s.terminatedUAs) == 0
}

// StartJanitor runs JanitorSweep hourly on the DAEMON context (locked decision
// 17). The ticker comes from the injected Clock, so tests drive it
// deterministically rather than by sleeping.
//
// The hourly ticker alone is not sufficient: RecordTermination performs an
// IMMEDIATE cap check so a burst of terminations cannot outrun it.
func (m *Manager) StartJanitor() {
	tk := m.clk.NewTicker(time.Hour)
	go func() {
		defer tk.Stop()
		for {
			select {
			case <-tk.C():
				m.JanitorSweep(m.clk.Now())
			case <-m.daemonCtx.Done():
				return
			}
		}
	}()
}
