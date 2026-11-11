package session

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// TestExpireSessionsTearsDownTheUAAndDeletesTheSession is Phase 1's core TTL
// contract (owner-locked decision): once a session's fixed 5-minute deadline
// passes, ExpireSessions runs the SAME teardown ua_destroy uses (Rule 18 — one
// implementation, reused) on the session's UA, then removes every trace of
// the record from the registry.
//
// Mutation check: comment out ExpireSessions' call into
// destroySessionAndDelete and this test reddens (the agent's teardown
// sequence never fires and Alive stays true past the deadline).
func TestExpireSessionsTearsDownTheUAAndDeletesTheSession(t *testing.T) {
	agent := &recordingAgent{}
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, nil), Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "register", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	ua.setRegistered(true)

	// Well past the 5-minute fixed TTL.
	fc.Advance(policy.Defaults().Limits.SessionTTL.Duration() + time.Second)

	// The CHOKE-POINT half is immediate and needs no reaper tick at all.
	if m.Alive("s1") {
		t.Fatal("Alive(s1) = true past the TTL deadline, want false (the transport choke point)")
	}

	n := m.ExpireSessions(ctx, fc.Now())
	if n != 1 {
		t.Fatalf("ExpireSessions processed %d sessions, want 1", n)
	}

	// The UA was torn down through the ONE teardown implementation: same
	// REGISTER Expires: 0 + Close sequence ua_destroy/admin DELETE use.
	if len(agent.seq) == 0 || agent.seq[len(agent.seq)-1] != "CLOSE" {
		t.Fatalf("agent sequence = %v, want it to end with CLOSE", agent.seq)
	}
	found := false
	for _, s := range agent.seq {
		if s == "REGISTER-Expires-0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("agent sequence = %v, want REGISTER-Expires-0 (the UA was registered)", agent.seq)
	}

	// The session record itself is gone outright — no lingering empty
	// session subject to the old resume window (owner-locked decision).
	if _, err := m.ResolveUA(ctx, "s1", ua.Handle()); err == nil {
		t.Fatal("ResolveUA succeeded after session expiry, want an error — the record is deleted")
	} else {
		assertCode(t, err, apierr.CodeNotFound) // the SESSION is gone, not merely the UA
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open(s1) after expiry (re-mint): %v", err)
	}
}

// TestSessionKeepaliveExtendsTTL is D2/D7's session_keepalive contract:
// RenewSession resets the deadline, and does so REPEATEDLY — a session kept
// alive by keepalives every 4 minutes must never die at the 5-minute mark.
//
// Mutation check: remove renewTTLLocked from RenewSession and this test
// reddens (Alive flips false at the original 5-minute deadline regardless of
// the keepalives).
func TestSessionKeepaliveExtendsTTL(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, nil), Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	// A live UA is required for this test's premise: session_ttl only
	// governs a session that holds at least one live UA/call (multi-UA-per-
	// session wave, sessionUsableLocked) — an EMPTY session is instead
	// governed by session_resume_window (default 1h) from lastSeen, which
	// would keep this bare session alive well past the assertions below and
	// defeat the point of this test (proving session_ttl renewal via
	// keepalive, not proving session_resume_window's much longer survival).
	if _, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP}); err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	// Two keepalives four minutes apart keep the session alive past the
	// original 5-minute deadline.
	fc.Advance(4 * time.Minute)
	if _, err := m.RenewSession("s1"); err != nil {
		t.Fatalf("RenewSession #1: %v", err)
	}
	fc.Advance(4 * time.Minute) // 8m since Open; would be dead at 5m with no keepalive
	if !m.Alive("s1") {
		t.Fatal("Alive(s1) = false after a keepalive renewed the TTL, want true")
	}
	if _, err := m.RenewSession("s1"); err != nil {
		t.Fatalf("RenewSession #2: %v", err)
	}

	// No further keepalive: the session dies 5 minutes after the LAST renewal.
	fc.Advance(policy.Defaults().Limits.SessionTTL.Duration() + time.Second)
	if m.Alive("s1") {
		t.Fatal("Alive(s1) = true past a keepalive's own TTL window, want false")
	}
}

// TestUADestroyLeavesTheSessionAliveForTheResumeWindow is the multi-UA-per-
// session wave's reversal of Phase 1's "ua_destroy tears down the whole
// session" decision: destroying a session's ONLY UA leaves the (now empty)
// session record alive, resolvable, and reusable within session_resume_window
// — exactly CF-002's fix, and the pre-Phase-1 rule call.go's own `expiresAt`
// doc comment already names ("empty sessions age out after
// session_resume_window, a session owning a live UA never ages out").
//
// Mutation check: restore destroyUA's old `s.closing = true` assignment on
// the ua_destroy path (requireSession != nil) and this test reddens — not
// via Alive flipping false, but because closing is never cleared and the
// second CreateUA below then returns not_found instead of succeeding.
// Restoring the old destroySessionAndDelete call inside UADestroy alone does
// NOT redden this test: Task 4's bail-out in destroySessionAndDelete already
// makes that call a no-op once destroyUA has emptied s.liveUAs. That half of
// the revert is instead pinned by
// TestUADestroyOnOneUALeavesSiblingUAsAndTheSessionLive, which reddens on it
// (Alive(s1) flips false after destroying the callee sibling UA).
func TestUADestroyLeavesTheSessionAliveForTheResumeWindow(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	if _, err := m.UADestroy(ctx, "s1", ua.Handle()); err != nil {
		t.Fatalf("UADestroy: %v", err)
	}

	if !m.Alive("s1") {
		t.Fatal("Alive(s1) = false after ua_destroy, want true — the session survives its last UA")
	}
	// Immediately after destroy, the handle is still resolvable — it sits in
	// terminatedUAs (RecordUADestroyed's step 4 tombstone) until
	// registry_retention elapses and JanitorSweep evicts it; ResolveUA
	// returns the terminated UA, not an error, until then (see
	// TestUADestroyAndAdminDestroyBothAnswerGoneForTheRetentionWindow for the
	// eventual not_found/gone transition).
	if _, err := m.ResolveUA(ctx, "s1", ua.Handle()); err != nil {
		t.Fatalf("ResolveUA immediately after ua_destroy: %v, want ok — the session "+
			"was not deleted", err)
	}
	// A fresh ua_create on the same, still-alive session id adds a UA to the
	// EXISTING record rather than needing a re-mint.
	ua2, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA after ua_destroy on the same session: %v", err)
	}
	if ua2.Handle() == ua.Handle() {
		t.Fatal("the new UA reused the destroyed handle, want a fresh one")
	}
}

// TestDrainSessionReaperWaitsForInFlightTeardown is D11's shutdown-ownership
// contract (simplified for Phase 1's synchronous reaper — see reaper.go):
// DrainSessionReaper does not return while a reaper-triggered teardown is
// still in flight, and the agent's teardown sequence is NOT truncated by the
// drain — the whole BYE/REGISTER-Expires-0/Close sequence completes before
// Drain unblocks.
//
// Mutation check: return immediately from DrainSessionReaper without waiting
// on reaperWG and this test reddens (it observes the drain returning before
// the blocked Close call is released).
func TestDrainSessionReaperWaitsForInFlightTeardown(t *testing.T) {
	release := make(chan struct{})
	agent := &blockingCloseAgent{release: release, started: make(chan struct{})}
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, nil), Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP}); err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	m.StartSessionReaper()
	fc.BlockUntil(1) // the reaper's ticker is registered

	fc.Advance(policy.Defaults().Limits.SessionTTL.Duration() + sessionReaperInterval) // crosses the TTL AND fires a tick

	// Wait for the tick's goroutine to actually ENTER the blocked Close call
	// before draining — fc.Advance only guarantees the ticker channel SEND,
	// not that the consuming goroutine has received it yet. Synchronizing on
	// `started` here is a TEST concern; it deterministically produces the
	// "teardown already in flight" state this test means to exercise, rather
	// than probing that delivery race itself (TestDrainSessionReaperCovers-
	// ATickRacingShutdown below is the test for that).
	select {
	case <-agent.started:
	case <-time.After(2 * time.Second):
		t.Fatal("the reaper tick never reached the blocking Close call")
	}

	// StopSessionReaper first, as DrainSessionReaper's own contract requires
	// and gracefulShutdown actually does: reaperWG now covers the reaper
	// goroutine's whole lifetime, so a drain issued while the reaper is still
	// armed has nothing to make it return.
	m.StopSessionReaper()

	drainDone := make(chan bool, 1)
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer drainCancel()
	go func() { drainDone <- m.DrainSessionReaper(drainCtx) }()

	select {
	case ok := <-drainDone:
		t.Fatalf("DrainSessionReaper returned (ok=%v) before the blocked teardown was released", ok)
	case <-time.After(150 * time.Millisecond):
		// still blocked, as expected
	}

	close(release) // let the teardown's Close call return

	select {
	case ok := <-drainDone:
		if !ok {
			t.Fatal("DrainSessionReaper reported outstanding work after the teardown finished")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DrainSessionReaper did not return after the in-flight teardown was released")
	}

	if !agent.closed.Load() {
		t.Fatal("the agent's Close was never observed to complete")
	}
}

// TestDrainSessionReaperCoversATickRacingShutdown is the regression pin for
// reaperWG's Add/Wait ordering (see StartSessionReaper's doc comment).
//
// THE BUG IT PINS — reaperWG.Add(1) ran INSIDE the tick branch, after the
// select had already committed to it, so nothing ordered it before a
// concurrent DrainSessionReaper Wait. A tick that had been delivered but not
// yet consumed left the counter at zero; the drain's Wait then returned
// immediately, gracefulShutdown moved on and cancelled the daemon context,
// and the reaper picked the tick branch anyway (select chooses uniformly
// among ready cases, and reaperStop being closed does not make the buffered
// tick unready) and started tearing a session down AFTER shutdown had been
// told there was nothing left to wait for — a BYE truncated mid-write.
//
// The race is driven, not simulated: each round fires the tick from one
// goroutine while another stops and drains, which is precisely the
// interleaving gracefulShutdown hits. Two things are asserted per round —
// no teardown may BEGIN after the drain returned, and none may still be in
// flight AT the moment it returned.
//
// Mutation check (verified): move m.reaperWG.Add(1)/Done() back inside the
// tick branch and drop the stopRequested() re-check, and this test reddens
// with "a teardown STARTED after DrainSessionReaper had already returned".
func TestDrainSessionReaperCoversATickRacingShutdown(t *testing.T) {
	const rounds = 60
	for round := 0; round < rounds; round++ {
		agent := &slowCloseAgent{}
		fc := newFakeClock()
		ctx, cancel := context.WithCancel(context.Background())
		m, err := NewManager(ManagerConfig{
			Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, nil), Logger: testLogger(),
			NewUA: func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
		})
		if err != nil {
			cancel()
			t.Fatalf("round %d: NewManager: %v", round, err)
		}
		if err := m.Open(ctx, "s1"); err != nil {
			cancel()
			t.Fatalf("round %d: Open: %v", round, err)
		}
		if _, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP}); err != nil {
			cancel()
			t.Fatalf("round %d: CreateUA: %v", round, err)
		}

		m.StartSessionReaper()
		fc.BlockUntil(1) // the reaper's ticker is registered

		var (
			wg           sync.WaitGroup
			drainedOK    bool
			inFlightThen bool
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			// Crosses the TTL and fires a tick. The reaper goroutine may or may
			// not have been scheduled to consume it before the drain below runs
			// -- that is the race.
			fc.Advance(policy.Defaults().Limits.SessionTTL.Duration() + sessionReaperInterval)
		}()
		go func() {
			defer wg.Done()
			m.StopSessionReaper()
			dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer dcancel()
			drainedOK = m.DrainSessionReaper(dctx)
			agent.drained.Store(true)
			inFlightThen = agent.inFlight.Load()
		}()
		wg.Wait()
		// Give a teardown that the drain failed to cover time to actually
		// start, so startedLate below observes it rather than racing it. With
		// the fix there is nothing left to run: the reaper goroutine has
		// already returned, which is what the drain waited for.
		time.Sleep(10 * time.Millisecond)
		cancel()

		if !drainedOK {
			t.Fatalf("round %d: DrainSessionReaper timed out", round)
		}
		if inFlightThen {
			t.Fatalf("round %d: DrainSessionReaper returned while a teardown was still in flight -- "+
				"shutdown will cancel the daemon context mid-BYE", round)
		}
		if agent.startedLate.Load() {
			t.Fatalf("round %d: a teardown STARTED after DrainSessionReaper had already returned -- "+
				"the drain's Wait was not ordered after the tick's Add", round)
		}
	}
}

// slowCloseAgent's Close takes long enough to be observable and records two
// things the drain must never allow: that a teardown was running at the moment
// the drain returned (inFlight), and that one began afterwards (startedLate).
type slowCloseAgent struct {
	nopAgent
	drained     atomic.Bool
	inFlight    atomic.Bool
	startedLate atomic.Bool
}

func (a *slowCloseAgent) Close(context.Context) error {
	if a.drained.Load() {
		a.startedLate.Store(true)
	}
	a.inFlight.Store(true)
	time.Sleep(2 * time.Millisecond)
	a.inFlight.Store(false)
	return nil
}

// blockingCloseAgent's Close blocks until release is closed, modelling a slow
// teardown so DrainSessionReaper's wait can be observed directly rather than
// inferred from timing alone.
type blockingCloseAgent struct {
	nopAgent
	release     chan struct{}
	started     chan struct{}
	startedOnce sync.Once
	closed      atomic.Bool
}

func (a *blockingCloseAgent) Close(ctx context.Context) error {
	a.startedOnce.Do(func() { close(a.started) })
	select {
	case <-a.release:
	case <-ctx.Done():
	}
	a.closed.Store(true)
	return nil
}

// TestExpireSessionsTearsDownEveryLiveUAInASession is the multi-UA-per-session
// wave's core reaper contract: a session holding SEVERAL live UAs past its
// session_ttl has ALL of them torn down, not just one.
//
// Mutation check: restore the old "break after the first handle" loop in
// destroySessionAndDelete and this test reddens (the second UA's agent never
// sees CLOSE).
func TestExpireSessionsTearsDownEveryLiveUAInASession(t *testing.T) {
	agent1, agent2 := &recordingAgent{}, &recordingAgent{}
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	calls := 0
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, func(l *policy.Limits) {
			l.MaxUAsPerSession = 4
		}), Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) {
			calls++
			if calls == 1 {
				return agent1, nil
			}
			return agent2, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua1, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA ua1: %v", err)
	}
	ua2, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA ua2: %v", err)
	}

	fc.Advance(policy.Defaults().Limits.SessionTTL.Duration() + time.Second)
	n := m.ExpireSessions(ctx, fc.Now())
	if n != 1 {
		t.Fatalf("ExpireSessions processed %d sessions, want 1", n)
	}

	for i, agent := range []*recordingAgent{agent1, agent2} {
		if len(agent.seq) == 0 || agent.seq[len(agent.seq)-1] != "CLOSE" {
			t.Errorf("agent %d sequence = %v, want it to end with CLOSE", i+1, agent.seq)
		}
	}
	if _, err := m.ResolveUA(ctx, "s1", ua1.Handle()); err == nil {
		t.Fatal("ResolveUA(ua1) succeeded after session expiry, want an error")
	}
	if _, err := m.ResolveUA(ctx, "s1", ua2.Handle()); err == nil {
		t.Fatal("ResolveUA(ua2) succeeded after session expiry, want an error")
	}
}

// TestExpireSessionsLeavesAnEmptyExpiredSessionForJanitorSweep is CF-002's
// reaper-side half: a session with NO live UA is left alone by the TTL
// reaper, however long past session_ttl it is — its fate belongs to
// JanitorSweep and session_resume_window instead (janitor.go's existing
// "§12.6 Lifetime rule").
//
// Mutation check: remove the sessionHasNoLiveObjectsLocked guard from
// ExpireSessions' selection and this test reddens (the empty session is
// deleted at session_ttl instead of surviving to session_resume_window).
func TestExpireSessionsLeavesAnEmptyExpiredSessionForJanitorSweep(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Empty from birth: never created a UA. Well past session_ttl.
	fc.Advance(policy.Defaults().Limits.SessionTTL.Duration() + time.Second)
	n := m.ExpireSessions(ctx, fc.Now())
	if n != 0 {
		t.Fatalf("ExpireSessions processed %d sessions, want 0 (empty session must survive)", n)
	}
	if !m.Alive("s1") {
		t.Fatal("Alive(s1) = false, want true — an empty session is not bound by session_ttl")
	}
}

// TestExpireSessionsDoesNotCutShortAPendingRetentionWindow is the reaper/
// JanitorSweep split's sharpest edge: a session that holds a pending gone-
// tombstone (a terminated UA still inside its registry_retention window) but
// no LIVE UA is NOT "empty" by sessionEmptyLocked's stricter definition (it
// requires terminatedUAs to be empty too, since JanitorSweep uses it to
// decide when the WHOLE record — including retained tombstones — may be
// deleted). If ExpireSessions used sessionEmptyLocked as its skip guard,
// this session would still look "non-empty" to it and get torn down on the
// session_ttl clock the moment that (short) TTL elapses — deleting the
// tombstone and cutting registry_retention's window short, even though
// registry_retention (typically much longer than session_ttl) has not
// elapsed. The reaper must skip any session with no LIVE UA/call, regardless
// of what it is still retaining.
//
// This uses the admin DestroyUA path (unaffected by this wave — see the
// design's locked decision 7) to reach "session survives, one pending
// tombstone, no live UA" without depending on Task 5's agent-path change,
// since this task (Task 4) runs before Task 5.
//
// Mutation check: change sessionHasNoLiveObjectsLocked's use back to
// sessionEmptyLocked in ExpireSessions and this test reddens (the session is
// deleted and the tombstone's gone answer is lost early).
func TestExpireSessionsDoesNotCutShortAPendingRetentionWindow(t *testing.T) {
	m, fc := newManagerWith(t, func(l *policy.Limits) {
		l.RegistryRetention = policy.Duration(time.Hour) // long
	})
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	if _, err := m.DestroyUA(ctx, string(ua.Handle())); err != nil {
		t.Fatalf("admin DestroyUA: %v", err)
	}

	// Past session_ttl (short, default 5m), well short of the 1h
	// registry_retention configured above.
	fc.Advance(policy.Defaults().Limits.SessionTTL.Duration() + time.Second)
	n := m.ExpireSessions(ctx, fc.Now())
	if n != 0 {
		t.Fatalf("ExpireSessions processed %d sessions, want 0 — a pending "+
			"retention tombstone must not be cut short by session_ttl", n)
	}
	// registry_retention (1h) has NOT elapsed and JanitorSweep never ran, so
	// the terminated UA is still sitting in s.terminatedUAs, not yet evicted
	// into s.uaTombstones — ResolveUA finds it there directly and returns it,
	// nil error. There is no "gone" case to assert here; that transition
	// only happens once retention elapses. This test's only claim is that
	// the record was NOT deleted early by the reaper.
	if _, err := m.ResolveUA(ctx, "s1", ua.Handle()); err != nil {
		t.Fatalf("ResolveUA after session_ttl (but before registry_retention): %v, "+
			"want ok — the pending tombstone must not be deleted early", err)
	}
}

// TestDestroySessionAndDeleteDoesNotDeleteARecordARaceAlreadyEmptied is the
// regression for the race Cycle B's plan review found: ExpireSessions can
// select a session while it still holds a live UA, then a concurrent
// ua_destroy can empty that UA before destroySessionAndDelete actually runs
// for that session id. The reaper must not delete the record anyway — that
// would discard the session_resume_window entitlement decision 5 gives an
// empty session. This test calls destroySessionAndDelete directly (same
// package) to deterministically reach "already empty when the reaper gets
// there" without relying on real goroutine timing, and uses the ADMIN
// DestroyUA path (unaffected by this wave, already leaves the session
// record in place today) to empty the UA without depending on Task 5's
// agent-path change, since this task runs before Task 5.
//
// Mutation check: remove the len(liveUAs)==0 bail-out and this test reddens
// (the session is deleted even though nothing was torn down).
func TestDestroySessionAndDeleteDoesNotDeleteARecordARaceAlreadyEmptied(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	// Simulates the race: the admin DestroyUA path empties s.liveUAs for
	// this session WITHOUT deleting the record — exactly what a concurrent
	// agent ua_destroy will also do once Task 5 lands.
	if _, err := m.DestroyUA(ctx, string(ua.Handle())); err != nil {
		t.Fatalf("admin DestroyUA: %v", err)
	}

	// The reaper's own teardown call, arriving "too late" — as if
	// ExpireSessions had selected s1 while it still had a live UA.
	m.destroySessionAndDelete(ctx, "s1")

	if !m.Alive("s1") {
		t.Fatal("Alive(s1) = false — destroySessionAndDelete deleted a record a race " +
			"had already emptied, discarding its session_resume_window entitlement")
	}
}

// TestExpireSessionsHonorsAConfiguredSessionTTL is CF-002's first named
// regression (design §6): a NON-default session_ttl must actually change
// when the reaper reaps. Every other reaper test in this file advances the
// clock by policy.Defaults().Limits.SessionTTL.Duration() — the default —
// which would still pass even if Task 3's wiring silently kept reading the
// old hardcoded 5-minute constant instead of the live policy value. This
// test configures a SHORTER TTL and checks the session is dead at a time
// that is past the configured value but short of the old default, so it can
// only pass if the live value is what the reaper actually reads.
//
// Mutation check: hardcode 5*time.Minute back into renewTTLLocked's caller
// sites (Task 3) instead of reading lim.SessionTTL.Duration() and this test
// reddens (the session is still alive at t=3m).
func TestExpireSessionsHonorsAConfiguredSessionTTL(t *testing.T) {
	m, fc := newManagerWith(t, func(l *policy.Limits) {
		l.SessionTTL = policy.Duration(2 * time.Minute)
	})
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP}); err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	fc.Advance(3 * time.Minute) // past the configured 2m, short of the old 5m default
	if m.Alive("s1") {
		t.Fatal("Alive(s1) = true past a configured 2-minute session_ttl, want false — " +
			"the reaper must read session_ttl live from policy, not a hardcoded default")
	}
	if n := m.ExpireSessions(ctx, fc.Now()); n != 1 {
		t.Fatalf("ExpireSessions processed %d sessions, want 1", n)
	}
}

// TestEmptySessionIsDeletedOnceSessionResumeWindowElapses is CF-002's second
// named regression (design §6): a NON-default session_resume_window must
// actually change when an empty session is deleted, and JanitorSweep — not
// the TTL reaper — must be what deletes it.
//
// Mutation check: hardcode SessionResumeWindow's read in JanitorSweep to a
// fixed value and this test reddens (the session outlives the configured
// 10-minute window because JanitorSweep is still using some other value).
func TestEmptySessionIsDeletedOnceSessionResumeWindowElapses(t *testing.T) {
	m, fc := newManagerWith(t, func(l *policy.Limits) {
		l.SessionResumeWindow = policy.Duration(20 * time.Minute)
	})
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Empty from birth. Past session_ttl (5m default) but short of the
	// configured 20-minute session_resume_window — two DISTINCT checkpoints,
	// not one combined jump: Alive itself is now resume-window-gated for an
	// empty session (Task 3), so advancing past BOTH clocks in a single jump
	// would make this checkpoint's own Alive check fail for the wrong reason.
	fc.Advance(policy.Defaults().Limits.SessionTTL.Duration() + time.Minute)

	if n := m.ExpireSessions(ctx, fc.Now()); n != 0 {
		t.Fatalf("ExpireSessions processed %d sessions, want 0 (the reaper must still skip it)", n)
	}
	if !m.Alive("s1") {
		t.Fatal("Alive(s1) = false after ExpireSessions alone — the reaper must not be what deletes an empty session")
	}

	// Now past the configured 20-minute session_resume_window (total elapsed
	// since Open: session_ttl+1m+15m = 21m).
	fc.Advance(15 * time.Minute)

	res := m.JanitorSweep(fc.Now())
	if res.SessionsExpired != 1 {
		t.Fatalf("JanitorSweep expired %d sessions, want 1", res.SessionsExpired)
	}
	if m.Alive("s1") {
		t.Fatal("Alive(s1) = true after JanitorSweep past a configured session_resume_window, want false")
	}
}

// TestDestroySessionAndDeleteTearsDownUAsConcurrentlyNotSequentially is
// Cycle C's regression for the sequential-teardown latency finding: with N
// live UAs, teardown must not wait for UA 1's full shutdown_grace_period
// before even STARTING UA 2's. This holds UA 1's Close blocked indefinitely
// (never releases it) and observes UA 2's Close still begins — a sequential
// loop could never reach UA 2 until UA 1's Close returned. Uses
// blockingCloseAgent (already defined in this file, reused from
// TestDrainSessionReaperWaitsForInFlightTeardown) for deterministic,
// non-sleep-based synchronization — no wall-clock race.
//
// Mutation check: revert the goroutine+WaitGroup fan-out to a plain
// sequential for-loop and this test reddens (agent2.started never fires
// within the timeout, because the loop is still blocked inside agent1's
// Close).
func TestDestroySessionAndDeleteTearsDownUAsConcurrentlyNotSequentially(t *testing.T) {
	release := make(chan struct{}) // deliberately never closed in this test
	agent1 := &blockingCloseAgent{release: release, started: make(chan struct{})}
	agent2 := &blockingCloseAgent{release: release, started: make(chan struct{})}
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	calls := 0
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, func(l *policy.Limits) {
			l.MaxUAsPerSession = 4
		}), Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) {
			calls++
			if calls == 1 {
				return agent1, nil
			}
			return agent2, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP}); err != nil {
		t.Fatalf("CreateUA ua1: %v", err)
	}
	if _, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP}); err != nil {
		t.Fatalf("CreateUA ua2: %v", err)
	}

	done := make(chan struct{})
	go func() {
		m.destroySessionAndDelete(ctx, "s1") // blocks on agent1/agent2's Close, neither ever released here
		close(done)
	}()

	for i, agent := range []*blockingCloseAgent{agent1, agent2} {
		select {
		case <-agent.started:
		case <-time.After(2 * time.Second):
			t.Fatalf("agent %d's Close never started within 2s — teardown is still sequential", i+1)
		}
	}

	select {
	case <-done:
		t.Fatal("destroySessionAndDelete returned before either blocked Close was released")
	case <-time.After(50 * time.Millisecond):
		// Still correctly blocked on both unreleased Close calls — expected.
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("destroySessionAndDelete never returned after release")
	}
}
