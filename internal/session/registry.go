package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/metrics"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// NOTE: `session` declares NO DialRequest. session.DialRequest is P1a Task 7's
// (contract §2.5.3) and carries NO Call/Handle field: THE UA NEVER LEARNS A
// HANDLE, which is exactly the layering §6.2.1 exists to protect. CreateCall
// already holds the handle on this side of the boundary.
//
// sessionRecord (§12.6's logical-session bookkeeping) is declared in call.go,
// not here (D31): moving it there gives call_test.go's &sessionRecord{id: "s1"}
// literal a type. That alone does not make the package build in isolation,
// though — sessionRecord's own fields (liveUAs map[Handle]*UA, callTombstones
// *handleRing) forward-reference UA and handleRing, both declared in THIS
// file. The package first builds green at Step 9, when this file lands.

// ManagerConfig is the contract's §2.5.5 struct constructor. It wins over a
// positional NewManager(ctx, clk, lim): it carries six fields a positional form
// cannot, and it is the only form admitting the NewUA factory the layering
// requires.
//
// This declaration is transcribed from the brief's top-of-document Produces
// preview, which the brief's Step 9 code block omits despite NewManager
// requiring it — a brief defect beyond D29-D33, fixed here rather than left
// as an undefined symbol.
type ManagerConfig struct {
	// Ctx is the LONG-LIVED DAEMON context — NEVER an http.Request context.
	// LOCKED DECISION 17, flagged as the most likely P1 correctness bug.
	Ctx     context.Context
	Clock   clock.Clock
	Policy  *policy.Store
	Logger  *slog.Logger
	Metrics *metrics.Registry
	Tap     Tap
	// Artifacts is [P2]'s per-call artifact store (capture_start/capture_stop,
	// D9b). nil is legal — it disables capture the same way a nil Tap disables
	// the ladder — because P1 wires no artifacts at all (§6.2.1 rule 4).
	Artifacts ArtifactStore

	// NewUA is the UA factory. Its parameter is session.UAConfig, NOT
	// sipua.Config: `session` MUST NEVER import `sipua` — that is the one edge
	// §6.2 absolutely forbids. The WIRING layer (cmd/ and the loopback harness)
	// translates UAConfig -> sipua.Config inside this closure and captures the
	// WrapConn seam, the logger and the tap.
	NewUA func(ctx context.Context, cfg UAConfig) (UserAgent, error)
}

// Manager owns the UA and call registries.
//
// LOCK ORDER (total, normative — §6.3): registry (m.mu) -> UA (UA.mu) ->
// call (Call.mu). NO LOCK IS HELD ACROSS A NETWORK WRITE OR AN ARTIFACT WRITE.
// Every tool call resolves its handle under the registry READ lock, takes a
// reference, and releases before doing any work.
//
// `-race` CANNOT DETECT LOCK-ORDER INVERSIONS. It detects data races. This
// order is held by the §6.3 rule 5 review gate plus Task 9's deterministic
// mass-cancellation-concurrent-with-eviction test.
type Manager struct {
	daemonCtx context.Context
	clk       clock.Clock
	policy    *policy.Store
	log       *slog.Logger
	metrics   *metrics.Registry
	tap       Tap
	// artifacts is [P2]'s per-call artifact store. nil disables capture,
	// exactly as a nil tap disables the ladder (see ManagerConfig.Artifacts).
	artifacts ArtifactStore
	newUA     func(context.Context, UAConfig) (UserAgent, error)

	mu        sync.RWMutex
	sessions  map[string]*sessionRecord
	uas       map[Handle]*UA
	calls     map[Handle]*Call
	liveTotal int
	// liveUATotal is the server-wide count of LIVE UAs, and is the basis
	// max_uas_total is measured against. It is the exact UA counterpart of
	// liveTotal: incremented at insert in CreateUA, decremented in
	// RecordUADestroyed — AT DESTRUCTION, NOT AT EVICTION.
	//
	// IT IS NOT len(m.uas). m.uas retains a destroyed UA for the whole
	// registry_retention window (default 1h) so ua_status can still answer, and
	// only evictUALocked removes it. Measuring the cap over that map would count
	// destroyed-but-retained handles against a LIVE bound, which spec §N3 states
	// directly: "the number of LIVE UAs is bounded instead by
	// limits.max_uas_per_session and limits.max_uas_total, enforced at
	// ua_create". It would also make §12.7's exhaustion recovery unsatisfiable —
	// an operator who admin-DELETEs a stranded UA to escape max_uas_total would
	// stay exhausted for up to registry_retention, which is precisely the
	// unexitable state the admin plane exists to escape.
	liveUATotal int

	capGoroutines atomic.Int64

	// refusing is §11.4 step 2's shutdown flag (RefuseNewDials, shutdown.go).
	// Guarded by m.mu like every other Manager field except the atomics above
	// and `waiters`. Read by checkConcurrencyLocked, which runs under the
	// same write-lock hold that sets it — one function is the gate on call
	// creation (Rule 18).
	refusing bool

	// reaperStop and reaperStopOnce let cmd/sipclient-mcpd's graceful
	// shutdown stop the session reaper's ticker deterministically, rather
	// than relying solely on daemonCtx.Done() (which is cancelled only AFTER
	// gracefulShutdown returns — see StopSessionReaper's doc comment).
	// reaperStopOnce makes a second Stop call, or a Stop on a Manager whose
	// reaper was never started, a no-op rather than a panic on a closed
	// channel.
	reaperStop     chan struct{}
	reaperStopOnce sync.Once
	// reaperWG tracks in-flight reaper-triggered teardowns so shutdown can
	// wait for one to finish rather than truncating it (DrainSessionReaper).
	reaperWG sync.WaitGroup
}

// limits reads §12.3's limits block LIVE from the policy store, on every call.
//
// IT IS NEVER SNAPSHOTTED. That is the whole point of U9: §12.2.1's SIGHUP
// reload takes effect with no push path, no hook and no duplicated type to keep
// in sync (Rule 18). A snapshot taken in NewManager would silently ignore every
// reload, which is a security bug whenever the reloaded value is a cap.
func (m *Manager) limits() policy.Limits { return m.policy.Current().Limits }

// NewManager builds the Manager. It returns an error rather than panicking so
// the daemon reports a misconfiguration at startup instead of at first use.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Ctx == nil {
		return nil, errors.New("session: ManagerConfig.Ctx is required (the DAEMON context)")
	}
	if cfg.Clock == nil {
		return nil, errors.New("session: ManagerConfig.Clock is required")
	}
	if cfg.Policy == nil {
		return nil, errors.New("session: ManagerConfig.Policy is required (limits are read live)")
	}
	if cfg.NewUA == nil {
		return nil, errors.New("session: ManagerConfig.NewUA is required")
	}
	if cfg.Logger == nil {
		return nil, errors.New("session: ManagerConfig.Logger is required")
	}
	return &Manager{
		daemonCtx:  cfg.Ctx,
		clk:        cfg.Clock,
		policy:     cfg.Policy,
		log:        cfg.Logger,
		metrics:    cfg.Metrics,   // nil is legal: tests that assert no counters pass none
		tap:        cfg.Tap,       // nil is legal: disables ladder eviction, nothing else
		artifacts:  cfg.Artifacts, // nil is legal: disables capture, nothing else
		newUA:      cfg.NewUA,
		sessions:   make(map[string]*sessionRecord),
		uas:        make(map[Handle]*UA),
		calls:      make(map[Handle]*Call),
		reaperStop: make(chan struct{}),
	}, nil
}

// sessionExpiredLocked reports whether s's TTL has passed now. Caller holds
// m.mu (read or write).
//
// A ZERO expiresAt is NEVER expired: it means "no TTL has been set", which
// cannot happen for a record Open produced (Open always renews immediately)
// but IS the correct behaviour for a bare &sessionRecord{} test fixture that
// never called through Open — treating it as already-expired would silently
// break constructions the existing test suite already relies on.
func sessionExpiredLocked(s *sessionRecord, now time.Time) bool {
	return !s.expiresAt.IsZero() && !now.Before(s.expiresAt)
}

// sessionHasNoLiveObjectsLocked reports whether s currently owns any live UA
// or live call. Caller holds m.mu (read or write).
//
// THIS IS NOT janitor.go's sessionEmptyLocked, AND THAT IS DELIBERATE.
// sessionEmptyLocked ALSO requires terminatedCalls/terminatedUAs to be
// empty, because JanitorSweep uses it to decide when the WHOLE record —
// including retained gone-tombstones — may be deleted. Every consumer here
// (this file's sessionUsableLocked, and Task 4's reaper) asks a narrower
// question: does session_ttl even apply to this record right now, or has it
// already handed off to session_resume_window? A session holding a pending
// tombstone but no live UA must still be governed by session_resume_window,
// not session_ttl.
func (m *Manager) sessionHasNoLiveObjectsLocked(s *sessionRecord) bool {
	return len(s.liveCalls) == 0 && len(s.liveUAs) == 0
}

// sessionUsableLocked is the multi-UA-per-session wave's replacement for a
// bare sessionExpiredLocked check at every client-facing liveness gate
// (Alive, CreateUA, RenewSession). Caller holds m.mu (read or write).
//
// A session holding at least one live UA or call is governed by its
// session_ttl-based expiresAt deadline, EXACTLY as before. An EMPTY session
// (sessionHasNoLiveObjectsLocked) is governed by session_resume_window
// instead, measured from lastSeen — the SAME "§12.6 Lifetime rule" clock
// JanitorSweep already uses (janitor.go's JanitorSweep/sessionEmptyLocked).
// Reusing lastSeen rather than inventing a second "became empty at" clock
// means a session that NEVER created any UA and one that just lost its last
// UA are treated identically: both get session_resume_window of idle time,
// not the (typically much shorter) session_ttl — Seen() already updates
// lastSeen on every request regardless of UA history, so this needs no new
// bookkeeping anywhere else.
func (m *Manager) sessionUsableLocked(s *sessionRecord, now time.Time, lim policy.Limits) bool {
	if !m.sessionHasNoLiveObjectsLocked(s) {
		return !sessionExpiredLocked(s, now)
	}
	return now.Sub(s.lastSeen) < lim.SessionResumeWindow.Duration()
}

// renewTTLLocked resets s's deadline to now+ttl. Caller holds m.mu (write).
// ttl is the caller's live limits.session_ttl read (Manager.limits()), never
// re-read here — same "read live before the lock, pass it in" discipline
// checkUACapsLocked already follows for lim (§6.0b INV-2 class 4). Called
// from EXACTLY THREE sites — Open, CreateUA and SessionKeepalive (via
// RenewSession) — and nowhere else: Seen() and CreateCall deliberately do
// NOT renew (D7). Renewing on ordinary traffic (Seen) or on call creation
// (CreateCall) would make a chatty or call-heavy agent's session immortal
// and defeat the whole point of a fixed TTL — see Seen's and CreateCall's
// own comments for the two negative tests this reasoning is pinned by.
func renewTTLLocked(s *sessionRecord, now time.Time, ttl time.Duration) {
	s.expiresAt = now.Add(ttl)
}

// DaemonContext is the LONG-LIVED context that owns UA and call goroutines.
//
// LOCKED DECISION 17 — THE MOST LIKELY P1 CORRECTNESS BUG. UA and call
// goroutines, duration-cap timers, registration refresh and the janitor MUST
// hang off THIS context. The HTTP REQUEST context belongs to call_wait waiters
// alone (§6.3 rule 4). Wiring a request context into a call's lifetime breaks
// D11 point 5 and R8: a client disconnect would kill a live call. Never pass a
// request ctx here.
func (m *Manager) DaemonContext() context.Context { return m.daemonCtx }

// sessionEvictionGracePeriod is the minimum time an EMPTY session record
// (per sessionEmptyLocked) must have sat idle, measured from its lastSeen,
// before Open may evict it to admit a new session under max_sessions_total
// pressure (Rule 13 Cycle 5, closing the P4-W6-N04 "retained-not-live
// lockout" finding). It is a HARDCODED constant, not a new policy field —
// an owner-approved, deliberate scope decision: adding a new
// SIGHUP-reloadable key this late in the wave was judged out of scope, and a
// generously-sized constant is the minimal, safe fix.
//
// WHY A GRACE PERIOD AT ALL — sessionEmptyLocked cannot tell a session
// opened milliseconds ago, before its first ua_create, from one abandoned for
// an hour: both are "empty". Evicting ANY empty record on sight would let a
// burst of session_open calls evict the immediately-preceding batch's still-
// forming sessions rather than ever being denied, defeating the cap's
// churn-limiting purpose — and could let one tenant's burst evict another
// tenant's in-flight session_open -> ua_create setup, a gap that for an
// LLM-driven MCP client can plausibly run tens of seconds, not milliseconds.
//
// WHY 60s SPECIFICALLY — generous enough to comfortably clear that setup
// gap for a legitimate client, while staying far short of
// session_resume_window's default 1h, so a genuinely stale/idle session
// becomes evictable reasonably soon after the registry comes under pressure
// rather than only after a full resume window.
//
// WHAT THIS DOES NOT SOLVE — a sustained, high-volume attacker opening empty
// sessions faster than they age past this grace period can still eventually
// contest or exhaust slots; that residual risk is inherent to any capacity
// limit, not eliminated by this fix. See P4-W6-N04 for the
// recorded tradeoff.
const sessionEvictionGracePeriod = 60 * time.Second

// Open creates a logical session record under a server-issued id (§12.6). It is
// IDEMPOTENT: re-opening an existing id refreshes its last-seen stamp and
// returns nil, which is what makes §12.6's resumption work.
//
// RENAMED from EnsureSession so *Manager satisfies mcp.Sessions with NO adapter
// (contract Part 3). An adapter forwarding three calls unchanged would be a
// layer with no behaviour, which Rule 15 forbids.
func (m *Manager) Open(_ context.Context, id string) error {
	lim := m.limits()
	now := m.clk.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok {
		s.lastSeen, s.connected = now, true
		renewTTLLocked(s, now, lim.SessionTTL.Duration()) // D7: Open renews the TTL, on birth AND on reopen
		return nil
	}
	if n := len(m.sessions); n >= lim.MaxSessionsTotal {
		// PRESSURE-TRIGGERED EVICTION (Rule 13 Cycle 5, P4-W6-N04): before
		// denying outright, look for an eviction-eligible record — EMPTY
		// (sessionEmptyLocked, the same predicate JanitorSweep uses to decide
		// what may age out) AND idle past sessionEvictionGracePeriod (see
		// that constant's doc comment for why both conditions are required).
		// Among all eligible candidates, evict the one with the OLDEST
		// lastSeen — the stalest first, matching the oldest-first idiom this
		// package already uses (enforceTerminatedCallCapLocked,
		// enforceTerminatedUACapLocked).
		var victimID string
		var victimLastSeen time.Time
		found := false
		for sid, s := range m.sessions {
			if !m.sessionEmptyLocked(s) {
				continue // a live session is NEVER evicted, no matter its age
			}
			if now.Sub(s.lastSeen) < sessionEvictionGracePeriod {
				continue // still inside its setup grace window
			}
			if !found || s.lastSeen.Before(victimLastSeen) {
				victimID, victimLastSeen, found = sid, s.lastSeen, true
			}
		}
		if !found {
			return apierr.DeniedLimit("max_sessions_total", lim.MaxSessionsTotal, n,
				fmt.Sprintf("server already holds %d sessions (policy max_sessions_total=%d)",
					n, lim.MaxSessionsTotal))
		}
		// Evicting frees the slot; fall through and create the new record
		// below rather than returning early.
		delete(m.sessions, victimID)
		// Rule 13 Cycle 6 (finding F2): the sibling denial path just above
		// IS observable (the caller logs the DeniedLimit error), but this
		// eviction previously had no signal at all — an operator had no way
		// to see the registry was under max_sessions_total pressure and
		// reclaiming legitimate idle sessions. A pure atomic counter, like
		// every other metrics call already inside this lock hold (§6.0b
		// INV-2's explicit carve-out).
		if m.metrics != nil {
			m.metrics.IncSessionsEvicted()
		}
	}
	m.sessions[id] = &sessionRecord{
		id:             id,
		liveCalls:      make(map[Handle]*Call),
		liveUAs:        make(map[Handle]*UA),
		callTombstones: newHandleRing(lim.MaxTerminatedCallsPerSession),
		uaTombstones:   newHandleRing(lim.MaxTerminatedUAsPerSession),
		lastSeen:       now,
		connected:      true,
		expiresAt:      now.Add(lim.SessionTTL.Duration()), // D7: Open renews on birth too
	}
	return nil
}

// Alive reports whether a record with this id currently exists AND has not
// passed its TTL (§12.6, Phase 1 — owner-locked decision).
//
// THIS IS THE TRANSPORT'S CHOKE POINT (see registry.go's package-level
// design note in the Phase 1 plan): internal/transport/mcp 404s every
// non-initialize request whose session is not Alive and drops the identity
// binding for it, so consulting sessionExpiredLocked HERE is what makes a
// session unusable the instant its TTL passes, with no separate "gone" flag
// and no second gate to keep in sync. The reaper (ExpireSessions) does the
// actual teardown I/O and deletes the record; this predicate is what makes
// the session LOOK dead immediately, before the reaper ever runs.
func (m *Manager) Alive(id string) bool {
	lim := m.limits()
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	if !ok {
		return false
	}
	return m.sessionUsableLocked(s, m.clk.Now(), lim)
}

// Seen records that the session was contacted, feeding §12.7's
// session_last_seen_at and §12.6's resume-window clock.
//
// IT DELIBERATELY DOES NOT RENEW THE TTL (D7). Every tool call reaches Seen
// (see the transport's resolve path), so renewing here would make ordinary
// traffic — not just an explicit session_keepalive — keep a session alive
// forever, defeating the fixed 5-minute TTL entirely. See
// TestSeenDoesNotRenewTTL in registry_test.go, which is a mutation-pinned
// negative: add a renewTTLLocked call here and it reddens.
func (m *Manager) Seen(id string) {
	now := m.clk.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok {
		s.lastSeen, s.connected = now, true
	}
}

// SessionExpiresAt returns the session's current TTL deadline. ok is false
// for an unknown or already-expired session id.
func (m *Manager) SessionExpiresAt(id string) (time.Time, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	if !ok || sessionExpiredLocked(s, m.clk.Now()) {
		return time.Time{}, false
	}
	return s.expiresAt, true
}

// RenewSession is session_keepalive's implementation (D2/D7): reset the
// session's TTL to now+session_ttl and return the new deadline. An unknown or
// already-expired session returns apierr.NotFound — a keepalive cannot
// resurrect a session that is already gone at the transport gate.
func (m *Manager) RenewSession(id string) (time.Time, error) {
	lim := m.limits()
	now := m.clk.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || !m.sessionUsableLocked(s, now, lim) {
		return time.Time{}, apierr.NotFound(fmt.Sprintf("unknown session %s", id))
	}
	s.lastSeen, s.connected = now, true
	renewTTLLocked(s, now, lim.SessionTTL.Duration())
	return s.expiresAt, nil
}

// CreateUA builds the UA THROUGH THE INJECTED FACTORY and registers it.
//
// The factory takes a session.UAConfig, never a sipua.Config: `session` must
// never import `sipua` (contract Part 1 — the one edge §6.2 absolutely
// forbids). The wiring layer translates inside the closure.
//
// The UA is constructed on the DAEMON context, not the caller's request context
// (locked decision 17): a dropped client connection must never tear down a UA.
//
// §6.0b INV-2, CLASS 2 — THE ROLLBACK Close HAPPENS AFTER THE LOCK IS RELEASED.
// UserAgent.Close shuts down the sipgo server and releases the bound socket: an
// actual transport operation, literally the thing §6.3's "no lock is held across
// a network write" names, and worse in kind than a log write. The rollback path
// is COLD — it needs an unknown session id — which is exactly why closing under
// m.mu is easy to miss and why it is written out explicitly here. Note there is
// deliberately NO `defer m.mu.Unlock()` in this function: the unlock must happen
// BEFORE the Close, and a defer would put it after.
func (m *Manager) CreateUA(_ context.Context, sid string, cfg UAConfig) (*UA, error) {
	// §6.0b INV-2 class 4: the policy read happens BEFORE m.mu is acquired.
	lim := m.policy.Current().Limits

	// HIGH-3: mint the handle BEFORE the factory builds the agent, and thread
	// it through cfg so the per-UA tap (ObservingConn) stamps it into every
	// SIPRecord. The factory (cmd/ and the loopback harness) reads cfg.Handle
	// when composing ObservingConn; the same handle becomes u.handle below, so
	// the value the producer stamps and the value call_ladder resolves are one
	// string. Minting early is safe: handles are 64 random bits with no shared
	// state, so discarding one on a factory error costs nothing.
	handle := newUAHandle()
	cfg.Handle = handle

	agent, err := m.newUA(m.daemonCtx, cfg)
	if err != nil {
		return nil, err
	}
	now := m.clk.Now()
	m.mu.Lock()
	// s.closing is checked beside the existence and TTL tests, and answers with
	// the SAME not_found: a session whose teardown has already begun is, from
	// this caller's point of view, indistinguishable from one already deleted.
	// Without it, a ua_create landing in the window between the teardown
	// emptying s.liveUAs (which frees the max_uas_per_session slot again) and
	// destroySessionAndDelete re-taking m.mu to delete the record would insert
	// a FRESH LIVE UA that is then deleted along with the record — never torn
	// down, never Closed, its m.uas entry orphaned and its max_uas_total slot
	// burned. See sessionRecord.closing.
	s, ok := m.sessions[sid]
	if !ok || s.closing || !m.sessionUsableLocked(s, now, lim) {
		m.mu.Unlock()
		// Release the socket we just bound rather than leaking it — with the
		// registry lock already dropped (INV-2 class 2).
		_ = agent.Close(m.daemonCtx)
		return nil, apierr.NotFound(fmt.Sprintf("unknown session %s", sid))
	}
	// checkUACapsLocked (D63/Step 5c-5d): the check and the insert below are
	// now ONE critical section, closing the check-then-act race a read-lock
	// pre-check left open across the socket bind and the REGISTER round trip.
	// max_uas_per_session (configurable, default 8) is enforced here, so this
	// is also where a ua_create past the cap is refused.
	if err := m.checkUACapsLocked(s, lim); err != nil {
		m.mu.Unlock()
		_ = agent.Close(m.daemonCtx) // same rollback, same reason
		return nil, err
	}
	u := &UA{
		handle:    handle,
		sid:       sid,
		agent:     agent,
		cfg:       cfg,
		state:     UALive,
		createdAt: m.clk.Now(),
	}
	m.uas[u.handle] = u
	s.liveUAs[u.handle] = u
	// D7: a session that just acquired a resource gets a full TTL window —
	// otherwise an agent that spends minutes on initialize -> ua_create would
	// receive an expires_at already close to expiry.
	renewTTLLocked(s, now, lim.SessionTTL.Duration())
	// The LIVE server-wide count, incremented in the same lock hold as the
	// insert. This — not len(m.uas) — is what max_uas_total is measured against
	// (spec §N3), for the reason liveUATotal's declaration gives.
	m.liveUATotal++
	// The metrics counters are pure atomics, NOT I/O, so they stay inside the
	// lock hold (INV-2's explicit carve-out; moving them would be Rule 19 scope
	// creep and would cost the accounting its atomicity).
	if m.metrics != nil {
		m.metrics.AddActiveUAs(1)
	}
	m.mu.Unlock()
	// DEFECT DISCOVERED BY P1e Task 22's loopback harness (Rule 6c), fixed
	// here as the minimal, correctly-scoped point: `agent.OnEvent` was NEVER
	// CALLED anywhere in production code (only in sipua's and fakes' own
	// package tests). handleUAEvent and its handlers (handleResponse,
	// handleRefresh, handleDialogEnded, handleTransportFault; inbound INVITEs
	// now admit through admitInbound via OnAdmit, I2)
	// were consequently dead code from the shipped daemon's perspective: no
	// SIP-driven event — 180 Ringing, a final response, a BYE, an inbound
	// INVITE — ever reached a *Call, so no outbound call could leave
	// `dialing` and no inbound call could ever be discovered. Proved live:
	// the harness's own first end-to-end `call_dial` completed the full
	// INVITE/180/200/ACK exchange on the wire (confirmed via the peer's own
	// Methods()) while call_wait(answered) still read `dialing` forever.
	// ctx is m.daemonCtx (locked decision 17: never an HTTP request
	// context), matching the doc comment on handleUAEvent itself.
	//
	// REGISTERED AFTER m.mu IS RELEASED (Rule 13 Cycle 5, two independent
	// reviews): the concrete OnEvent (sipua's UA.OnEvent, call.go) takes
	// u.calls.mu, so calling it from inside m.mu's hold was an undeclared
	// cross-package lock edge m.mu -> sipua.calls.mu — exactly what §6.0b
	// INV-2 forbids, and one a static lock-order scan cannot see
	// because it never walks internal/sipua. It was safe only by accident:
	// sipua.emit (call.go) copies the callback out under u.calls.mu and
	// invokes it AFTER releasing that lock, so the reverse edge never
	// existed — but a future change to emit or OnEvent could add a real
	// deadlock with no gate to catch it. Moving the call here costs nothing:
	// nothing between the old call site and this one reads agent.OnEvent's
	// effect, the insert above has already completed, and sipua.emit's
	// `if fn == nil { return }` guarantees no event can reach handleUAEvent
	// before this line runs — so no event can ever observe a UA missing from
	// m.uas. (This does not touch the separate, already-known, P2-deferred
	// gap where an event emitted before THIS line still drops silently.)
	agent.OnEvent(m.daemonCtx, func(ctx context.Context, ev UAEvent) {
		m.handleUAEvent(ctx, u.handle, ev)
	})
	// The SYNCHRONOUS inbound-admission channel (I2), registered beside OnEvent
	// and for the same reasons: AFTER m.mu is released (the concrete OnAdmit
	// takes u.calls.mu, so calling it under m.mu would add the forbidden
	// m.mu -> sipua.calls.mu edge) and on the DAEMON context (decision 17).
	// admitInbound is now the SOLE inbound Call creator — a UA with OnEvent but
	// no OnAdmit would ring inbound INVITEs into the void (N4).
	agent.OnAdmit(m.daemonCtx, func(ctx context.Context, ev UAEvent) Admission {
		return m.admitInbound(ctx, u.handle, ev)
	})
	return u, nil
}

// CreateCall registers a call. Task 11 layers the §12.2.2 concurrency caps on
// top of this, inserting checkConcurrencyLocked immediately before the call is
// registered.
func (m *Manager) CreateCall(_ context.Context, sid string, ua Handle, dir Direction, initial CallState) (*Call, error) {
	lim := m.limits()
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sid]
	if !ok || sessionExpiredLocked(s, m.clk.Now()) {
		return nil, apierr.NotFound(fmt.Sprintf("unknown session %s", sid))
	}
	// CreateCall DELIBERATELY DOES NOT RENEW THE TTL (D7). It sits one line
	// from CreateUA above and returns no expires_at an agent could act on, so
	// renewing here would silently extend the session through ordinary call
	// traffic — the same immortal-session failure Seen's comment names, from
	// the other direction. See TestCreateCallDoesNotRenewTTL, a mutation-
	// pinned negative: add a renewTTLLocked call here and it reddens.
	//
	// u.State() != UALive closes a hole Task 11a's destroyUA created: MarkDestroyed
	// removes nothing from s.liveUAs (RecordUADestroyed does that, only at
	// teardown step 4, after the up-to-10s BYE grace period), so without this
	// check a call could be admitted on a UA that is already mid-teardown and
	// will never be BYEd, holding a max_concurrent_calls_total slot forever with
	// no UA left to hang up through (D63). Nothing could MarkDestroyed a UA
	// before destroyUA existed, so this is an orphan this task's own change
	// created (Rule 19), not scope creep.
	u, ok := s.liveUAs[ua]
	if !ok || u.State() != UALive {
		return nil, apierr.NotFound(fmt.Sprintf("unknown ua handle %s", ua))
	}
	// `lim` is CreateCall's existing first-line policy read, taken before m.mu
	// was acquired — §6.0b INV-2 class 4. It is passed in rather than re-read.
	if err := m.checkConcurrencyLocked(s, lim); err != nil {
		return nil, err
	}
	c := newCall(newCallHandle(), ua, s, dir, initial, lim.EventLogSize, m.clk.Now())
	m.calls[c.handle] = c
	s.liveCalls[c.handle] = c
	m.liveTotal++
	if m.metrics != nil {
		m.metrics.IncCallsTotal()
		m.metrics.AddActiveCalls(1)
	}
	return c, nil
}

// ResolveCall returns the call under the registry READ lock and releases it
// before the caller does any work.
//
// AUTHORIZATION IS REGISTRY MEMBERSHIP, NOT THE HANDLE PREFIX. This function
// never inspects the handle string (locked decision 12).
func (m *Manager) ResolveCall(_ context.Context, sid string, h Handle) (*Call, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sid]
	if !ok {
		return nil, apierr.NotFound(fmt.Sprintf("unknown call handle %s", h))
	}
	if c, ok := s.liveCalls[h]; ok {
		return c, nil
	}
	for _, c := range s.terminatedCalls {
		if c.handle == h {
			return c, nil
		}
	}
	if s.callTombstones.has(h) {
		return nil, apierr.Gone(fmt.Sprintf("call handle %s has been reclaimed", h))
	}
	return nil, apierr.NotFound(fmt.Sprintf("unknown call handle %s", h))
}

// ResolveUA returns the UA under the registry READ lock, releasing it before
// the caller does any work. Authorization is registry membership, not the
// handle prefix (locked decision 12), exactly as ResolveCall.
func (m *Manager) ResolveUA(_ context.Context, sid string, h Handle) (*UA, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sid]
	if !ok {
		return nil, apierr.NotFound(fmt.Sprintf("unknown ua handle %s", h))
	}
	if u, ok := s.liveUAs[h]; ok {
		return u, nil
	}
	for _, u := range s.terminatedUAs {
		if u.handle == h {
			return u, nil
		}
	}
	if s.uaTombstones.has(h) {
		return nil, apierr.Gone(fmt.Sprintf("ua handle %s has been reclaimed", h))
	}
	return nil, apierr.NotFound(fmt.Sprintf("unknown ua handle %s", h))
}

// session looks up a session record by id under the registry read lock.
// Unexported seam: the production consumer is Task 9's waiter lifecycle
// (Wait, SessionWaiterCount). Task 10's tests also call it directly, as a
// seam to inspect sessionRecord state (e.g. the tombstone-ring boundary) —
// but JanitorSweep itself does not use it: it iterates m.sessions directly
// under m.mu, so "Task 10's janitor" would overstate what actually calls in.
func (m *Manager) session(sid string) *sessionRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[sid]
}

// forceRegisterCallForTest registers an existing call under an additional
// handle. Test-only seam for the decision-12 prefix assertion.
func (m *Manager) forceRegisterCallForTest(sid string, h Handle, c *Call) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls[h] = c
	m.sessions[sid].liveCalls[h] = c
}

// StartDurationCap arms the §11.3 policy duration cap for a call.
//
// LOCKED DECISION 17. The goroutine hangs off m.daemonCtx and NOTHING ELSE.
// The request context of the call_dial or call_answer that armed it is
// deliberately not accepted as a parameter, so it cannot be passed by mistake:
// a dropped client connection must never terminate a live call (D11 point 5,
// R8).
func (m *Manager) StartDurationCap(c *Call, d time.Duration, onCap func()) {
	// Record the deadline this timer enforces, so a later §12.2.1 reload can
	// tell whether its recomputed deadline is EARLIER than what is already
	// armed. tightenCapDeadline can only ratchet earlier, so arming is
	// idempotent-safe and never loosens an existing cap.
	c.tightenCapDeadline(m.clk.Now().Add(d))
	t := m.clk.NewTimer(d)
	m.capGoroutines.Add(1)
	go func() {
		defer m.capGoroutines.Add(-1)
		defer t.Stop()
		select {
		case <-t.C():
			// §6.0b INV-1: the terminal claim and its bookkeeping are ONE UNIT.
			// The defer is on the line IMMEDIATELY following the successful
			// TryTerminate with NO statement in between, and it fires when this
			// goroutine returns — after capHangup's BYE (CF-092), which is bounded
			// by one shutdown grace period. Written as a defer rather than a plain
			// call so the pairing is greppable and survives anyone later adding a
			// statement, a log line or an early return between the two.
			if err := c.TryTerminate(m.clk.Now(), "policy_timeout", EventPolicyTimeout); err == nil {
				defer onCap()
				m.capHangup(c)
			}
			// A non-nil error means the call already terminated; the concurrent
			// hangup won and there is nothing to do (§6.3).
		case <-c.done:
			// D382: the call already terminated by another path (hangup,
			// BYE, ...) — exit now instead of parking until t.C() or
			// m.daemonCtx.Done(), which could be hours away for a long cap.
		case <-m.daemonCtx.Done():
		}
	}()
}

// capHangup ends the dialog of a call the duration cap just claimed, on the
// wire (RFC 3261 13.2.2: BYE for an established dialog, CANCEL for an early
// outbound one; UserAgent.Hangup picks). It is called only by the claim's
// winner. The context is bounded by one shutdown grace period, as destroyUA's
// is, so a peer that never answers the BYE cannot hold the caller longer.
func (m *Manager) capHangup(c *Call) {
	m.mu.RLock()
	u, ok := m.uas[c.UAHandle()]
	m.mu.RUnlock()
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(m.daemonCtx, m.limits().ShutdownGracePeriod.Duration())
	defer cancel()
	if err := u.agent.Hangup(ctx, c.DialogID(), "policy_timeout"); err != nil {
		m.log.Warn("bye not confirmed after the duration cap",
			"ua_handle", c.UAHandle(), "call_handle", c.Handle(), "err", err)
	}
}

// RecomputeDurationCaps applies §12.2.1's ONE exception to "a live call
// continues under the policy in force when it started": a changed
// max_call_duration_s is evaluated against every live call's CURRENT ELAPSED
// TIME, at once.
//
// It is registered as the policy Store's reload hook by the composition root
// and runs on a SUCCESSFUL reload only — a failed reload swaps nothing, fires
// no hook, and leaves every armed cap exactly as it was.
//
// §12.2.1's worked acceptance: with max_call_duration_s 300 and two live calls
// at elapsed 30 s and 120 s, lowering the cap to 60 force-terminates the 120 s
// call at once with a policy_timeout event, while the 30 s call survives and
// is terminated at elapsed 60 s. Raising the cap back to 300 extends neither —
// tightenCapDeadline is a one-way ratchet.
//
// A reload-triggered termination is INDISTINGUISHABLE DOWNSTREAM from a
// timer-triggered one, deliberately: it is the same TryTerminate with the same
// "policy_timeout" reason and the same EventPolicyTimeout, so §10.5's event
// log, the N5 per-call record and every §12.2.2 counter see one shape, not two.
//
// §6.0b INV-2: the registry hold below BUILDS ONLY. It performs no I/O, takes
// no other package's lock, and every terminal claim, record and timer arm
// happens after it is released — the same shape RecordTermination follows.
func (m *Manager) RecomputeDurationCaps(next *policy.Policy) {
	now := m.clk.Now()

	m.mu.RLock()
	live := make([]*Call, 0, len(m.calls))
	for _, s := range m.sessions {
		for _, c := range s.liveCalls {
			live = append(live, c)
		}
	}
	m.mu.RUnlock()
	// ---- registry lock released; everything below acts ---------------------

	var overdue []*Call
	type rearm struct {
		c  *Call
		in time.Duration
	}
	var rearms []rearm
	for _, c := range live {
		// The deadline is computed from startedAt, NOT from now: the new cap
		// must be measured against elapsed time, or every live call would be
		// granted a fresh full duration by each reload.
		recomputed, ok := next.CallDeadline(c.StartedAt())
		if !ok {
			continue // the new policy configures no cap; nothing to apply
		}
		if !c.tightenCapDeadline(recomputed) {
			continue // not earlier than what is armed: a raise never extends
		}
		if recomputed.After(now) {
			rearms = append(rearms, rearm{c: c, in: recomputed.Sub(now)})
			continue
		}
		overdue = append(overdue, c)
	}

	// Calls ALREADY PAST the new cap: force-terminated AT ONCE, not at the
	// next timer tick. "Applies immediately" is the spec's wording and a
	// zero-length timer would make it depend on the clock being advanced.
	for _, c := range overdue {
		if err := c.TryTerminate(now, "policy_timeout", EventPolicyTimeout); err != nil {
			continue // already terminated; §6.3 says exactly one caller wins
		}
		// INV-1 LOOP FORM: per-iteration record. Form A is FORBIDDEN here —
		// a defer fires at THIS FUNCTION's exit, so over N over-cap calls it
		// would hold call 1's §12.2.2 slot, its active_calls count and its
		// ladder retention until call N had been recorded.
		// The BYE runs on its own goroutine: the reload hook is synchronous
		// and must not wait on a peer (CF-092).
		go m.capHangup(c)
		m.RecordTermination(c)
	}

	// Survivors whose deadline moved earlier: re-armed for the REMAINING
	// time. The previously armed timer is left to fire harmlessly later —
	// TryTerminate lets exactly one of them win (§6.3), so a stale timer
	// costs one refused claim and nothing else.
	for _, r := range rearms {
		c := r.c
		m.StartDurationCap(c, r.in, func() { m.RecordTermination(c) })
	}
}

// DurationCapGoroutinesForTest reports armed duration-cap goroutines. Test-only.
func (m *Manager) DurationCapGoroutinesForTest() int64 { return m.capGoroutines.Load() }

// IsLive reports whether a non-terminal call with this handle is in the registry.
// It satisfies artifact.LiveCallChecker (§13.3): the janitor calls it to protect
// a running test's artifacts. Keyed by CALL handle, which is the artifact store's
// per-call dir name.
func (m *Manager) IsLive(callHandle string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.calls[Handle(callHandle)]
	if !ok {
		return false
	}
	return !c.State().terminal()
}

// sessionUAs returns every LIVE UA owned by sid, under the registry read
// lock, released before the caller does anything with the result (ToolService
// Rule 15 accessor: ua_status's "ua omitted" case). A copy, not a live view.
func (m *Manager) sessionUAs(sid string) []*UA {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sid]
	if !ok {
		return nil
	}
	out := make([]*UA, 0, len(s.liveUAs))
	for _, u := range s.liveUAs {
		out = append(out, u)
	}
	return out
}

// sessionCalls returns every LIVE call owned by sid, under the registry read
// lock, released before the caller does anything with the result
// (ToolService's call_list, R11 isolation).
func (m *Manager) sessionCalls(sid string) []*Call {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sid]
	if !ok {
		return nil
	}
	out := make([]*Call, 0, len(s.liveCalls))
	for _, c := range s.liveCalls {
		out = append(out, c)
	}
	return out
}

// activeCallCount reports how many of sid's LIVE calls are on ua (ua_status's
// active_calls field), under the registry read lock.
func (m *Manager) activeCallCount(sid string, ua Handle) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sid]
	if !ok {
		return 0
	}
	n := 0
	for _, c := range s.liveCalls {
		if c.uaHandle == ua {
			n++
		}
	}
	return n
}

// THE EVENT-LOOKUP INVARIANT (both halves stated on both lookups):
//
//	Any handler that APPENDS an event to a Call — Call.Append, Call.RecordDigit,
//	Call.applyPlanStep, Call.applyPlanError — MUST resolve its *Call through
//	callByDialogIDForEvent.
//
//	Any handler that CLAIMS or MUTATES live call state — a Try* transition —
//	MUST use this live-only callByDialogID, and may append only on the path it
//	has just claimed.
//
// The rule is not advisory prose: eventlookup_invariant_test.go walks every
// `handle*` method on *Manager in this package and fails the build when one
// appends through the live-only lookup. The ONE documented exception lives in
// that test's `eventAppendingLookupExceptions` map with its reason, so adding a
// second is a deliberate, reviewable edit rather than a silent one.
// Tasks after this one add handler branches (29, 30); the test is what makes 33
// separate implementer sessions classify them correctly without re-reading this
// comment.
//
// callByDialogID looks up uaHandle's own LIVE call by sipua's dialog key,
// under the registry read lock. nil means the call is already gone — a
// concurrent hangup won, or the call was evicted — which every caller of this
// function treats as "a concurrent actor won" rather than as an error (§6.3).
func (m *Manager) callByDialogID(uaHandle Handle, dialogID string) *Call {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.uas[uaHandle]
	if !ok {
		return nil
	}
	s, ok := m.sessions[u.sid]
	if !ok {
		return nil
	}
	for _, c := range s.liveCalls {
		if c.uaHandle == uaHandle && c.DialogID() == dialogID {
			return c
		}
	}
	return nil
}

// callByDialogIDForEvent looks up uaHandle's call by sipua's dialog key across
// BOTH the live set and the session's TERMINATED set, under the registry read
// lock. It is the lookup EVERY EVENT-APPENDING handler must use — see THE
// EVENT-LOOKUP INVARIANT on callByDialogID above.
//
// WHY IT EXISTS — callByDialogID's live-only search DROPS A CALL'S LAST EVENTS.
// RecordTermination (janitor.go) MOVES a call from s.liveCalls to
// s.terminatedCalls at the terminal transition, and the media-plan executor and
// the DTMF RX path emit on their OWN goroutines: a remote BYE that wins the race
// moves the call out from under an in-flight final `plan_step`, `record_stop` or
// `dtmf` event, which then resolves to nil and is discarded in silence. The
// aborted case is not even a race — `plan_aborted_call_terminated` is emitted
// BECAUSE the call terminated, so a live-only lookup can never deliver it.
//
// THE TWO-SET SEARCH IS THE REGISTRY'S OWN EXISTING PATTERN, not a new one:
// ResolveCall does exactly this for the tool surface (liveCalls, then a linear
// scan of terminatedCalls). No new lock, no new ordering rule and no grace timer
// enters §6.3, and the window is bounded by registry eviction — once the call is
// evicted this misses again, which is correct, because nothing can read its log
// after that either.
//
// STATE-CLAIMING HANDLERS KEEP callByDialogID: handleResponse and
// handleDialogEnded resolve their races through Try*'s own terminal() guard, and
// handleDialogEnded is part of the termination sequence itself rather than a
// bystander racing it.
//
// EVERY EVENT-APPENDING HANDLER USES THIS ONE, INCLUDING handleMediaStart.
// "media_start can only precede termination" is true of EMISSION and irrelevant
// to DELIVERY: the media goroutine's media_start can be handled after a remote
// BYE has already driven RecordTermination, and under a live-only lookup the
// call's codec and latched remote address would then never reach its log.
func (m *Manager) callByDialogIDForEvent(uaHandle Handle, dialogID string) *Call {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.uas[uaHandle]
	if !ok {
		return nil
	}
	s, ok := m.sessions[u.sid]
	if !ok {
		return nil
	}
	for _, c := range s.liveCalls {
		if c.uaHandle == uaHandle && c.DialogID() == dialogID {
			return c
		}
	}
	// The call terminated between the emitting goroutine's send and this
	// lookup. Its Call is still registry-resident for the whole §N3 retention
	// window and every append path below is c.mu-guarded and specified to work
	// after termination, so the event still lands where a reader can see it.
	for _, c := range s.terminatedCalls {
		if c.uaHandle == uaHandle && c.DialogID() == dialogID {
			return c
		}
	}
	return nil
}

// handleRing remembers evicted handles so §N3's `gone`-vs-`not_found`
// distinction survives eviction. It is BOUNDED, because an unbounded tombstone
// map would reintroduce exactly the growth §N3 exists to prevent. Sized to the
// matching terminated-handle cap, so it holds one full generation beyond the
// retained set.
//
// LOCKED DECISION U10 — APPROVED, INCLUDING ITS COST. A handle evicted more
// than one generation past the cap answers `not_found` rather than `gone`: a
// handle that should report "reclaimed" instead reports "never existed". This
// WEAKENS AN OBSERVABLE §13.5 GUARANTEE and is a deliberate, accepted trade,
// not an oversight — §13.5 wants the distinction, §N3 forbids the unbounded
// memory it would need, and no implementation satisfies both. Do not "fix" it
// by unbounding the ring. Task 10 Step 8 asserts the degradation at its exact
// boundary, so the accepted cost is pinned by a test rather than by prose.
type handleRing struct {
	size int // Task 9: the eviction bound EvictCallForTest and Task 10's janitor add() against.
	// buf is written and read only inside add, below. It is used: Task 9's
	// EvictCallForTest (waiter.go:344) evicts a handle into the ring via add.
	// (D33-class deferral golangci-lint names but D33's prediction list
	// omits; flagged in the Task 8 report.)
	buf []Handle
	set map[Handle]struct{}
}

func newHandleRing(size int) *handleRing {
	if size <= 0 {
		size = 1
	}
	return &handleRing{size: size, set: make(map[Handle]struct{}, size)}
}

// add records h as evicted. Unexported, first consumed by Task 9's
// EvictCallForTest (waiter.go:344); Task 10's registry eviction path
// (evictCallLocked / evictUALocked) becomes the production caller later.
func (r *handleRing) add(h Handle) {
	if _, ok := r.set[h]; ok {
		return
	}
	r.buf = append(r.buf, h)
	r.set[h] = struct{}{}
	for len(r.buf) > r.size {
		delete(r.set, r.buf[0])
		r.buf = r.buf[1:]
	}
}

func (r *handleRing) has(h Handle) bool {
	_, ok := r.set[h]
	return ok
}
