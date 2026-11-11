package session

import (
	"fmt"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// checkConcurrencyLocked enforces §12.2.2's TWO INDEPENDENT CAPS. Caller holds
// m.mu (write), so the check and the registration that follows it are atomic —
// there is no window in which two dials both observe a free slot.
//
// PER-SESSION IS CHECKED FIRST. An agent over both bounds is told about its
// own first, so it learns "I am using too much" rather than "the server is
// full" and hangs up its own calls instead of backing off.
//
// CONTENTION AGAINST THE SERVER-WIDE CAP IS FIRST-COME-FIRST-SERVED. There is
// deliberately NO reservation, NO per-session quota carved out of the total, NO
// queueing and NO fair-share scheduler. A dial arriving when the server-wide
// cap is full is DENIED IMMEDIATELY, whichever session it came from and however
// few calls that session holds.
//
// DO NOT "IMPROVE" THIS INTO A WAITING OR FAIR-SHARE ALLOCATOR:
//   - a call_dial that sometimes waits for a slot violates D2's
//     async-returns-immediately invariant and N2's 50ms budget;
//   - a fair-share allocator makes one session's observed capacity depend on
//     other sessions' behaviour — non-determinism in exactly the place a test
//     harness must not have it.
//
// A denial is a fact an agent can act on; a wait is not.
//
// The accepted consequence is that a busy server can starve a session well
// under its own cap. That is VISIBLE rather than silent, because the denial
// names which bound was hit: the rule field carries the exact policy key, and
// limit and current are THAT KEY's values.
//
// LIMITS ARE READ LIVE from the policy store (U9), so a SIGHUP that tightens
// either cap binds the very next dial with no push path and nothing to refresh.
//
// §6.0b INV-2, CLASS 4 — THE POLICY VALUE IS A PARAMETER, READ BY THE CALLER
// BEFORE m.mu IS ACQUIRED. Calling m.limits() (which is m.policy.Current()) from
// inside this critical section is a lock nesting from the top of §6.3's declared
// hierarchy into a package whose internal synchronisation is unspecified
// everywhere in this wave. Live-ness is unaffected: CreateCall already reads
// `lim := m.limits()` on its very first line, one statement before it takes the
// lock, so the value is still read fresh on every dial and a SIGHUP still binds
// the next one. Do not "simplify" this back to reading m.limits() here.
func (m *Manager) checkConcurrencyLocked(s *sessionRecord, lim policy.Limits) error {
	// §11.4 step 2: once RefuseNewDials has run, every subsequent CreateCall
	// is denied here — the ONE gate on call creation (Rule 18), rather than a
	// second check duplicated at call_dial's call site.
	if m.refusing {
		return apierr.ResourceLimit("shutdown", 0, 0,
			"server is shutting down and is not accepting new calls")
	}
	if n := len(s.liveCalls); n >= lim.MaxConcurrentCallsPerSession {
		return apierr.DeniedLimit("max_concurrent_calls_per_session",
			lim.MaxConcurrentCallsPerSession, n,
			fmt.Sprintf("session already holds %d concurrent calls "+
				"(policy max_concurrent_calls_per_session=%d)",
				n, lim.MaxConcurrentCallsPerSession))
	}
	if m.liveTotal >= lim.MaxConcurrentCallsTotal {
		return apierr.DeniedLimit("max_concurrent_calls_total",
			lim.MaxConcurrentCallsTotal, m.liveTotal,
			fmt.Sprintf("server already holds %d concurrent calls "+
				"(policy max_concurrent_calls_total=%d)",
				m.liveTotal, lim.MaxConcurrentCallsTotal))
	}
	return nil
}

// checkUACapsLocked enforces §12.3's TWO UA CAPS. Caller holds m.mu (write), so
// the check and the insert that follows it are atomic — there is no window in
// which two ua_creates both observe a free slot.
//
// IT IS STRUCTURALLY IDENTICAL TO checkConcurrencyLocked, AND THAT IS THE POINT
// (Rule 16, Rule 18). Before this, the UA caps were checked nowhere: a
// read-lock pre-check, released before the socket bind and (in register mode)
// a full digest REGISTER round trip against a possibly-slow or unreachable
// registrar, with the write-lock insert re-checking nothing. That race window
// is a full network round trip, not nanoseconds, so two concurrent creates
// reliably overshoot max_uas_total. §12.7's exhaustion-recovery exit criterion
// is written directly against this key: "with limits.max_uas_total: 2 and both
// UAs stranded, ua_create from a fresh session returns resource_limit naming
// max_uas_total."
//
// PER-SESSION IS CHECKED FIRST, for the same reason checkConcurrencyLocked does
// it: an agent over both bounds learns about its own first.
//
// `lim` IS A PARAMETER, read by the caller before m.mu was acquired — §6.0b
// INV-2 class 4. Do not call m.limits() here.
func (m *Manager) checkUACapsLocked(s *sessionRecord, lim policy.Limits) error {
	if n := len(s.liveUAs); n >= lim.MaxUAsPerSession {
		return apierr.DeniedLimit("max_uas_per_session",
			lim.MaxUAsPerSession, n,
			fmt.Sprintf("session already holds %d user agents "+
				"(policy max_uas_per_session=%d)", n, lim.MaxUAsPerSession))
	}
	if n := m.liveUATotal; n >= lim.MaxUAsTotal {
		return apierr.DeniedLimit("max_uas_total",
			lim.MaxUAsTotal, n,
			fmt.Sprintf("server already holds %d user agents "+
				"(policy max_uas_total=%d)", n, lim.MaxUAsTotal))
	}
	return nil
}

// DebugLiveCallCounts reports live-call counts. Test-only.
func (m *Manager) DebugLiveCallCounts(sid string) (perSession, total int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s, ok := m.sessions[sid]; ok {
		perSession = len(s.liveCalls)
	}
	return perSession, m.liveTotal
}
