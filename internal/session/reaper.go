package session

import (
	"context"
	"sync"
	"time"
)

// ---- Session reaper: session_ttl clock for sessions holding a live UA,
// full teardown of every live UA then delete the record on expiry --------

// sessionReaperInterval is how often ExpireSessions runs. 30s (TTL/10) bounds
// the worst case where a session is already unusable at the Alive() gate
// (§12.6's transport choke point) but its UA is still registered at the far
// end and its slot is still held, without ticking so often the sweep costs
// anything real over a map max_sessions_total already bounds.
const sessionReaperInterval = 30 * time.Second

// ExpireSessions tears down and deletes every session whose TTL has passed as
// of now. It returns the number of sessions it processed (test/diagnostic
// use).
//
// Session TEARDOWN REUSES destroyUA — THE ONE UA TEARDOWN IMPLEMENTATION
// (Rule 18) — rather than a second copy of the BYE / REGISTER Expires: 0 /
// Close sequence, once per live UA the session holds (multi-UA-per-session
// wave: no longer at most one). Only a session with at least one live UA
// is selected here at all — an EMPTY session (no live UA/call) is left to
// JanitorSweep's session_resume_window instead (janitor.go's "§12.6
// Lifetime rule"), and destroySessionAndDelete itself bails out without
// deleting anything if a race empties a session between selection and this
// call actually reaching it (see that function's own doc comment).
func (m *Manager) ExpireSessions(ctx context.Context, now time.Time) int {
	m.mu.RLock()
	var ids []string
	for id, s := range m.sessions {
		// A session with NO LIVE UA/call is never reaped by the TTL clock —
		// it is left to JanitorSweep's session_resume_window rule (CF-002)
		// and its own registry_retention handling for anything still
		// pending. Deliberately sessionHasNoLiveObjectsLocked, not
		// sessionEmptyLocked — see that function's own doc comment.
		if sessionExpiredLocked(s, now) && !m.sessionHasNoLiveObjectsLocked(s) {
			ids = append(ids, id)
		}
	}
	m.mu.RUnlock()

	for _, id := range ids {
		m.destroySessionAndDelete(ctx, id)
	}
	return len(ids)
}

// destroySessionAndDelete is the reaper's own full-teardown-then-delete path
// (Rule 18) — the ONLY caller is ExpireSessions now; multi-UA-per-session
// wave: agent-facing ua_destroy (destroy.go) no longer calls this, since it
// destroys only its own handle and leaves the session and any sibling UAs
// alone. This still tears down EVERY live UA the session holds (not just
// one) before every trace of the record is removed from the registry-wide
// maps and the record itself is deleted — but ONLY when there was at least
// one live UA to tear down. If the session was already empty by the time
// this call actually reaches it (a race against a concurrent ua_destroy),
// it bails out without deleting anything, leaving the (now correctly
// unclaimed) record for JanitorSweep's session_resume_window rule instead —
// deleting it here regardless would discard that entitlement.
//
// WHAT GOES WRONG IF THE registry-wide CLEANUP IS SKIPPED: destroyUA already
// moves a destroyed UA from s.liveUAs into s.terminatedUAs (and decrements
// liveUATotal via RecordUADestroyed) but LEAVES it in m.uas and s.uaTombstones
// unset — by design, so ua_status can still answer `gone` for
// limits.registry_retention. Deleting the session record without first
// running it through evictUALocked/evictCallLocked would leak that m.uas
// entry (and any retained ladder ring) forever: nothing else ever visits a
// session that is no longer in m.sessions, so the hourly JanitorSweep — which
// only walks m.sessions — would never reach it either.
// WHAT GOES WRONG IF THE RECORD IS NOT MARKED `closing` FIRST: the teardown
// below runs with m.mu RELEASED, and it ends by emptying s.liveUAs — which
// frees the max_uas_per_session slot again while the record is still in
// m.sessions and (on the ua_destroy path) still unexpired. A ua_create landing
// in that window inserts a FRESH LIVE UA into a session that is about to be
// deleted, and the deletion below then drops it on the floor: never torn down,
// never Closed, orphaned in m.uas and holding a max_uas_total slot forever.
// Setting the flag before the lock is released closes the window outright
// rather than trying to re-check for it afterwards.
func (m *Manager) destroySessionAndDelete(ctx context.Context, sid string) {
	// A WRITE lock, not the read lock this used to take: `closing` is set here.
	m.mu.Lock()
	s, ok := m.sessions[sid]
	var liveUAs []Handle
	if ok {
		liveUAs = make([]Handle, 0, len(s.liveUAs))
		for h := range s.liveUAs {
			liveUAs = append(liveUAs, h)
		}
		if len(liveUAs) == 0 {
			// A race already emptied this session between ExpireSessions'
			// selection (under an RLock, since released) and this call — a
			// concurrent ua_destroy (Task 5) landed on this session's last
			// live UA in between. There is nothing left for the reaper to
			// tear down, and deleting the record anyway would discard the
			// session_resume_window entitlement decision 5 gives an empty
			// session: that decision now belongs to JanitorSweep, not the
			// TTL reaper. Bail out WITHOUT setting closing — nothing was
			// claimed, so nothing needs unclaiming, and sessionRecord.closing's
			// own invariant ("never cleared: the record is deleted at the end
			// of that same call") stays true because this path never sets it.
			m.mu.Unlock()
			return
		}
		s.closing = true
	}
	m.mu.Unlock()
	if !ok {
		return
	}

	// destroyUA re-acquires m.mu itself and does the network I/O (BYE,
	// REGISTER Expires: 0, Close) with NO lock held, on the daemon context it
	// derives internally — exactly HangupAllLive/UnregisterAllUAs' discipline.
	// Ownership is already established: every handle here was read out of
	// THIS session's own s.liveUAs above, so no session/ownership check is
	// needed (unlike ua_destroy's own entry point, which is caller-facing and
	// must reject a foreign handle).
	//
	// CONCURRENT, NOT SEQUENTIAL (Cycle C architectural-review finding).
	// destroyUA's own BYE/Unregister/Close sequence is bounded by
	// shutdown_grace_period (default 10s) PER CALL. A sequential loop over
	// EVERY live UA the session held would let one session's worst-case
	// teardown time multiply by its UA count — up to 8x the grace period at
	// the default max_uas_per_session=8 — which stalls this reaper's single
	// goroutine (and, transitively, every OTHER expired session waiting
	// behind it, and graceful shutdown's DrainSessionReaper) far beyond the
	// one-grace-period bound §11.4 and ShutdownGracePeriod's own contract
	// promise. Tearing down every UA IN PARALLEL bounds one session's total
	// teardown time to roughly ONE grace period regardless of how many UAs
	// it holds. Each destroyUA call is already safe to run concurrently with
	// another on a DIFFERENT handle — MarkDestroyed's single-winner claim and
	// RecordUADestroyed's own m.mu-guarded bookkeeping are exactly what
	// already make concurrent ua_destroy/admin-DELETE/reaper attempts safe
	// today; this is the same property applied across handles instead of
	// across entry points.
	//
	// AN ERROR ON ANY ONE CALL IS EXPECTED AND DELIBERATELY IGNORED: it means
	// a DIFFERENT teardown (an explicit ua_destroy, or the admin DELETE)
	// already won MarkDestroyed for that handle and is still in flight, so
	// this pass has nothing to tear down for it. The record is deleted below
	// regardless, and that is safe ONLY because RecordUADestroyed/
	// RecordTermination decrement the GLOBAL counters off their own
	// accounted flags rather than off the session record — see
	// RecordUADestroyed's doc comment for the leak that gating them on the
	// record used to cause.
	var wg sync.WaitGroup
	wg.Add(len(liveUAs))
	for _, h := range liveUAs {
		go func(h Handle) {
			defer wg.Done()
			_, _ = m.destroyUA(ctx, h, nil)
		}(h)
	}
	wg.Wait()

	m.mu.Lock()
	if s, ok := m.sessions[sid]; ok {
		// Every terminated call/UA this session was still retaining is
		// released HERE, at session death, rather than left for the hourly
		// janitor (which will never see this session again once it is
		// deleted below).
		for _, c := range s.terminatedCalls {
			m.evictCallLocked(s, c)
		}
		for _, u := range s.terminatedUAs {
			m.evictUALocked(s, u)
		}
		delete(m.sessions, sid)
	}
	m.mu.Unlock()
}

// StartSessionReaper runs ExpireSessions every sessionReaperInterval on the
// DAEMON context (locked decision 17), mirroring StartJanitor's shape but on
// its OWN separate ticker: JanitorSweep runs entirely under m.mu, while a
// reaper tick must do network I/O (destroyUA's BYE/Unregister/Close) with the
// lock released, so folding the two together would force one of them to
// break its own locking discipline.
//
// THE reaperWG.Add IS SCOPED TO THE GOROUTINE'S WHOLE LIFETIME, NOT TO ONE
// TICK, and that is what makes DrainSessionReaper's wait mean anything.
//
// THE BUG IT FIXES — Add(1) used to run INSIDE the tick branch, i.e. after the
// select had already committed to it. sync.WaitGroup only guarantees anything
// when an Add happens-before a concurrent Wait, and that one did not:
// StopSessionReaper's close(reaperStop), and the DrainSessionReaper Wait behind
// it, could both land in the window between "this iteration chose the tick
// branch" and "Add ran". Wait then returned immediately on a zero counter while
// a teardown was about to start, gracefulShutdown moved on, and the daemon
// cancelled the daemon context mid-BYE — the exact truncation the
// shutdown-ownership fix exists to prevent. The window was not only the
// instruction gap: a tick delivered but not yet CONSUMED left the counter at
// zero for as long as the goroutine was unscheduled, and the select could then
// still pick the tick branch over an already-closed reaperStop (select chooses
// uniformly among ready cases) and tear a session down well after the drain had
// reported everything finished.
//
// THE SEQUENCING NOW. Add(1) runs in StartSessionReaper, on the CALLER's
// goroutine, before the reaper goroutine exists — so it happens-before any Wait
// any other goroutine can issue, unconditionally, with no window to lose. The
// matching Done is deferred to the goroutine's return, so the counter drops to
// zero only once the reaper has left the loop for good, and any teardown it was
// running has therefore returned. Wait now means "the reaper is finished", which
// is strictly what shutdown needs.
//
// It also means exactly ONE Add and ONE Done per reaper, never a reused
// WaitGroup: an Add racing a Wait that has been woken but has not yet re-read
// the counter is a "WaitGroup is reused before previous Wait has returned"
// panic, which a per-tick Add/Done pair invites by construction.
//
// stopRequested() re-checks the stop channels after a tick is received, so a
// tick that was already in the ticker's buffer when shutdown began cannot start
// a fresh teardown and stretch the drain out behind it.
func (m *Manager) StartSessionReaper() {
	tk := m.clk.NewTicker(sessionReaperInterval)
	// Registered HERE, before the goroutine starts: see the doc comment above.
	m.reaperWG.Add(1)
	go func() {
		defer m.reaperWG.Done()
		defer tk.Stop()
		for {
			select {
			case <-tk.C():
				// Shutdown may have closed reaperStop while this branch was
				// being chosen, or before the tick was consumed at all.
				if m.stopRequested() {
					return
				}
				m.ExpireSessions(m.daemonCtx, m.clk.Now())
			case <-m.reaperStop:
				return
			case <-m.daemonCtx.Done():
				return
			}
		}
	}()
}

// stopRequested reports whether the reaper has been told to stop, without
// blocking: either StopSessionReaper closed reaperStop or the daemon context
// was cancelled.
func (m *Manager) stopRequested() bool {
	select {
	case <-m.reaperStop:
		return true
	case <-m.daemonCtx.Done():
		return true
	default:
		return false
	}
}

// StopSessionReaper stops the reaper's ticker. Idempotent (reaperStopOnce),
// and safe to call on a Manager whose reaper was never started — every unit
// fixture and the loopback harness do exactly that.
//
// IT DOES NOT WAIT for an in-flight tick to finish; DrainSessionReaper does
// that, separately, as its own shutdown step (see cmd/sipclient-mcpd/shutdown.go).
// Splitting the two keeps this call non-blocking, which is what lets
// gracefulShutdown call it unconditionally and early (right after
// RefuseNewDials) without itself risking a wait.
func (m *Manager) StopSessionReaper() {
	m.reaperStopOnce.Do(func() { close(m.reaperStop) })
}

// DrainSessionReaper waits for the reaper goroutine to finish — which includes
// any teardown a tick already in flight is running — or for ctx to expire,
// whichever comes first. It returns true if the wait completed cleanly
// (nothing was still outstanding at the deadline).
//
// IT MUST BE CALLED AFTER StopSessionReaper (or after the daemon context is
// cancelled), which is exactly what gracefulShutdown does, and after the
// registry-visible teardown steps (HangupAllLive, UnregisterAllUAs), so an
// in-flight reaper teardown is the only thing left this step can still be
// waiting on. Since StartSessionReaper's Add covers the goroutine's whole
// lifetime (see its doc comment), a drain issued while the reaper is still
// armed has nothing to make it return and simply waits out ctx.
//
// A Manager whose reaper was never started drains instantly: nothing ever
// added to reaperWG, so Wait returns at once — which is what every unit
// fixture and the loopback harness rely on.
func (m *Manager) DrainSessionReaper(ctx context.Context) bool {
	done := make(chan struct{})
	go func() {
		m.reaperWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}
