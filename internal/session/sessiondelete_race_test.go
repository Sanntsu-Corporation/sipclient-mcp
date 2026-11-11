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

// closeCountingAgent records how many times it was Closed, without blocking.
// (blockingCloseAgent, reaper_test.go, is the parking counterpart these tests
// reuse for the interleaving half — Rule 16: no second copy of either.)
type closeCountingAgent struct {
	nopAgent
	closes atomic.Int64
}

func (a *closeCountingAgent) Close(context.Context) error {
	a.closes.Add(1)
	return nil
}

// registryTotalsForTest reads the two SERVER-WIDE counters plus the raw
// registry map sizes under m.mu. Same-package test seam: these are precisely
// the fields the leak below corrupts, and no exported accessor reports them.
func registryTotalsForTest(m *Manager) (liveUATotal, liveTotal, uas, calls, sessions int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.liveUATotal, m.liveTotal, len(m.uas), len(m.calls), len(m.sessions)
}

// TestSessionDeletionRacingAnInFlightUATeardownDoesNotLeakCapacity is the
// regression test for the CONFIRMED capacity leak this wave's session-deletion
// redesign introduced.
//
// THE RACE, EXACTLY AS REPRODUCED:
//
//  1. ua_destroy wins MarkDestroyed under the registry lock, releases it, and
//     parks inside agent.Close() — past the claim, short of RecordUADestroyed,
//     so the handle is STILL in s.liveUAs.
//  2. The session's fixed TTL passes and the reaper runs. ExpireSessions'
//     snapshot still sees that handle as live, so destroySessionAndDelete
//     calls destroyUA for it, LOSES the claim (not_found — step 1 already
//     took it), and deletes the session record anyway.
//  3. Close finally returns and step 1's teardown calls RecordUADestroyed.
//     The record is gone.
//
// Before the fix, step 3 early-returned on the missing record, so
// m.liveUATotal was never decremented — one max_uas_total slot burned for the
// life of the daemon — and m.uas[handle] was orphaned where nothing would ever
// find it again (JanitorSweep only walks m.sessions).
//
// MUTATION CHECK: in RecordUADestroyed, move the `m.liveUATotal--` and the
// m.uas reclamation back behind an `s, ok := m.sessions[u.sid]; if !ok {
// return }` gate and this test reddens on both assertions at once —
// live_ua_total = 1 and one orphaned m.uas entry, which is the leak's exact
// signature.
func TestSessionDeletionRacingAnInFlightUATeardownDoesNotLeakCapacity(t *testing.T) {
	// blockingCloseAgent (reaper_test.go) parks inside Close until `release`
	// closes: the ONE point a teardown sits between winning the MarkDestroyed
	// claim (taken under the registry lock, before any I/O) and reporting back
	// through RecordUADestroyed. That interval IS this race.
	agent := &blockingCloseAgent{release: make(chan struct{}), started: make(chan struct{})}
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
	// Release the parked Close even if an assertion below fails, so a failure
	// is a failure rather than a hung test binary.
	released := false
	t.Cleanup(func() {
		if !released {
			close(agent.release)
		}
	})

	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	// ---- step 1: ua_destroy parks inside Close, past its MarkDestroyed claim.
	destroyDone := make(chan struct{})
	go func() {
		defer close(destroyDone)
		_, _ = m.UADestroy(ctx, "s1", ua.Handle())
	}()
	select {
	case <-agent.started:
	case <-time.After(5 * time.Second):
		t.Fatal("ua_destroy never reached agent.Close: the race cannot be set up")
	}

	// ---- step 2: the TTL passes and the reaper deletes the record out from
	// under that in-flight teardown.
	fc.Advance(policy.Defaults().Limits.SessionTTL.Duration() + time.Second)
	if n := m.ExpireSessions(ctx, fc.Now()); n != 1 {
		t.Fatalf("ExpireSessions processed %d sessions, want 1 (the expired s1)", n)
	}
	if _, _, _, _, sessions := registryTotalsForTest(m); sessions != 0 {
		t.Fatalf("m.sessions holds %d records after the reap, want 0 — the race "+
			"requires the record to be gone before the teardown reports back", sessions)
	}

	// ---- step 3: the teardown finishes and reports into a session that no
	// longer exists.
	released = true
	close(agent.release)
	select {
	case <-destroyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("ua_destroy never returned after Close was released")
	}

	liveUATotal, liveTotal, uas, calls, _ := registryTotalsForTest(m)
	if liveUATotal != 0 {
		t.Errorf("m.liveUATotal = %d after a completed teardown, want 0 — a real "+
			"teardown that finished after its session record was deleted burned a "+
			"max_uas_total slot permanently", liveUATotal)
	}
	if uas != 0 {
		t.Errorf("m.uas holds %d entries, want 0 — the handle is orphaned: its "+
			"session is gone, so JanitorSweep (which only walks m.sessions) can "+
			"never reach it again", uas)
	}
	if liveTotal != 0 || calls != 0 {
		t.Errorf("m.liveTotal = %d, len(m.calls) = %d, want 0 and 0", liveTotal, calls)
	}

	// The leak is a CAPACITY leak, so prove the capacity actually came back:
	// a fresh session can create a UA again, which is what the burned
	// max_uas_total slot would eventually have prevented.
	if err := m.Open(ctx, "s2"); err != nil {
		t.Fatalf("Open(s2): %v", err)
	}
	if _, err := m.CreateUA(ctx, "s2", UAConfig{Mode: "direct", Transport: TransportUDP}); err != nil {
		t.Fatalf("CreateUA on a fresh session after the race: %v", err)
	}
}

// TestUACreateCannotRaceIntoASessionBeingDestroyed is the second, structurally
// identical hole: not a teardown finishing late, but a ua_create landing
// EARLY — in the window between a UA teardown emptying s.liveUAs (which frees
// the max_uas_per_session slot again) and the session-deletion critical
// section acquiring the lock to delete the record.
//
// MULTI-UA-PER-SESSION WAVE: this window no longer exists on the agent
// ua_destroy path at all — UADestroy is now a single call straight into
// destroyUA, which no longer sets sessionRecord.closing for that path (see
// destroy.go). sessionRecord.closing is now set ONLY by
// destroySessionAndDelete, the reaper's own full-teardown-then-delete path —
// so this test now drives the window THERE instead: a blockingCloseAgent
// holds destroySessionAndDelete's teardown I/O open (closing is already true
// by the time Close blocks, since it is set under the SAME lock hold that
// collects the live-UA snapshot, before the lock is released for I/O — see
// reaper.go), and the racing ua_create is attempted while that I/O is still
// in flight.
//
// MUTATION CHECK: delete `s.closing = true` from destroySessionAndDelete (or
// drop `s.closing` from CreateUA's guard) and this test reddens — the
// in-window ua_create is admitted, its fresh LIVE UA is deleted along with
// the record moments later, and it is left orphaned in m.uas, never torn
// down, never Closed, holding a max_uas_total slot forever.
func TestUACreateCannotRaceIntoASessionBeingDestroyed(t *testing.T) {
	release := make(chan struct{})
	first := &blockingCloseAgent{release: release, started: make(chan struct{})}
	second := &closeCountingAgent{}
	agents := []UserAgent{first, second}
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, nil), Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) {
			a := agents[0]
			if len(agents) > 1 {
				agents = agents[1:]
			}
			return a, nil
		},
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

	// The reaper's own full-session teardown, started on its own goroutine so
	// its blocked Close call holds the window open deterministically.
	done := make(chan struct{})
	go func() {
		m.destroySessionAndDelete(ctx, "s1")
		close(done)
	}()
	select {
	case <-first.started:
	case <-time.After(2 * time.Second):
		t.Fatal("destroySessionAndDelete's teardown never reached the blocking Close call")
	}

	// ---- THE WINDOW. Teardown I/O is in flight; closing is already true.
	_, createErr := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if createErr == nil {
		t.Fatal("CreateUA succeeded on a session whose destruction is already " +
			"under way: the fresh UA is deleted with the record moments later " +
			"and orphaned — never torn down, never Closed, its max_uas_total " +
			"slot burned")
	}
	assertCode(t, createErr, apierr.CodeNotFound)

	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("destroySessionAndDelete never returned after release")
	}

	liveUATotal, _, uas, _, sessions := registryTotalsForTest(m)
	if liveUATotal != 0 {
		t.Errorf("m.liveUATotal = %d, want 0", liveUATotal)
	}
	if uas != 0 {
		t.Errorf("m.uas holds %d entries, want 0 — nothing may be left behind "+
			"once the session record is gone", uas)
	}
	if sessions != 0 {
		t.Errorf("m.sessions holds %d records, want 0", sessions)
	}
	// Whatever the refused ua_create bound, it was released: CreateUA closes
	// the agent it just built when it refuses (INV-2 class 2 rollback), so no
	// socket is left behind either.
	if n := second.closes.Load(); n != 1 {
		t.Errorf("the refused ua_create closed its agent %d times, want 1 — a "+
			"refusal that skips the rollback Close leaks the bound socket", n)
	}
	if !first.closed.Load() {
		t.Error("the destroyed UA's agent Close was never observed to complete")
	}
}

// blockingHangupAgent is blockingCloseAgent's call-side twin: its Hangup parks
// until release is closed, which is the one point a CALL teardown sits between
// winning TryHangup (claimed under no lock, before any I/O) and reporting back
// through RecordTermination. That interval IS the race below. Close is left as
// nopAgent's so the teardown finishes promptly once the BYE is let go.
type blockingHangupAgent struct {
	nopAgent
	release     chan struct{}
	started     chan struct{}
	startedOnce sync.Once
}

func (a *blockingHangupAgent) Hangup(ctx context.Context, _, _ string) error {
	a.startedOnce.Do(func() { close(a.started) })
	select {
	case <-a.release:
	case <-ctx.Done():
	}
	return nil
}

// TestSessionDeletionRacingAnInFlightCallTeardownDoesNotLeakCapacity is the
// CALL-side half of the capacity leak
// TestSessionDeletionRacingAnInFlightUATeardownDoesNotLeakCapacity pins for
// UAs. RecordTermination and RecordUADestroyed got the same fix — decrement the
// server-wide counter off the call's own `accounted` flag rather than off the
// session record still existing, and reclaim the registry entry when the record
// is gone — but only the UA half had a test that ever executed the new branch.
//
// THE RACE, EXACTLY AS REPRODUCED:
//
//  1. The ADMIN DELETE (DestroyUA — the entry point that deliberately does NOT
//     delete the session record) wins MarkDestroyed, claims the live call with
//     TryHangup, and parks inside agent.Hangup for the BYE grace period. The
//     call is therefore still in s.liveCalls and still unaccounted.
//  2. The session's fixed TTL passes and the reaper runs. destroySessionAndDelete
//     finds the UA still in s.liveUAs, loses its own MarkDestroyed claim (step 1
//     took it), and deletes the session record anyway — with the live call still
//     hanging off it.
//  3. The BYE returns and step 1's loop calls RecordTermination. The record is
//     gone.
//
// Before the fix, step 3 skipped BOTH the m.liveTotal decrement and the
// registry eviction, so one max_concurrent_calls_total slot was burned for the
// life of the daemon and m.calls[handle] was orphaned where nothing would ever
// find it again (JanitorSweep only walks m.sessions).
//
// MUTATION CHECK (verified): in RecordTermination, move `m.liveTotal--` and the
// evictCallLocked(nil, c) reclamation back behind the `if s, ok :=
// m.sessions[c.sess.id]; ok` gate and this test reddens on both assertions at
// once — live_total = 1 and one orphaned m.calls entry, the same leak signature
// the UA-side test demonstrates.
func TestSessionDeletionRacingAnInFlightCallTeardownDoesNotLeakCapacity(t *testing.T) {
	agent := &blockingHangupAgent{release: make(chan struct{}), started: make(chan struct{})}
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
	// Release the parked BYE even if an assertion below fails, so a failure is a
	// failure rather than a hung test binary.
	released := false
	t.Cleanup(func() {
		if !released {
			close(agent.release)
		}
	})

	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	if _, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered); err != nil {
		t.Fatalf("CreateCall: %v", err)
	}
	if _, liveTotal, _, calls, _ := registryTotalsForTest(m); liveTotal != 1 || calls != 1 {
		t.Fatalf("m.liveTotal = %d, len(m.calls) = %d before the race, want 1 and 1 — "+
			"the scenario needs a genuinely live call or its assertions are vacuous",
			liveTotal, calls)
	}

	// ---- step 1: the admin DELETE parks inside the call's BYE, past its
	// TryHangup claim. THE ADMIN ENTRY POINT IS THE REACHABLE ONE: ua_destroy
	// marks the record `closing` and deletes it itself, while DestroyUA leaves
	// the record for its own TTL — which is exactly what lets the reaper delete
	// it underneath this teardown.
	destroyDone := make(chan struct{})
	go func() {
		defer close(destroyDone)
		_, _ = m.DestroyUA(ctx, string(ua.Handle()))
	}()
	select {
	case <-agent.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the admin DELETE never reached agent.Hangup: the race cannot be set up")
	}

	// ---- step 2: the TTL passes and the reaper deletes the record out from
	// under that in-flight call teardown.
	fc.Advance(policy.Defaults().Limits.SessionTTL.Duration() + time.Second)
	if n := m.ExpireSessions(ctx, fc.Now()); n != 1 {
		t.Fatalf("ExpireSessions processed %d sessions, want 1 (the expired s1)", n)
	}
	if _, _, _, _, sessions := registryTotalsForTest(m); sessions != 0 {
		t.Fatalf("m.sessions holds %d records after the reap, want 0 — the race "+
			"requires the record to be gone before the teardown reports back", sessions)
	}

	// ---- step 3: the BYE completes and the teardown reports into a session
	// that no longer exists.
	released = true
	close(agent.release)
	select {
	case <-destroyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the admin DELETE never returned after the BYE was released")
	}

	liveUATotal, liveTotal, uas, calls, _ := registryTotalsForTest(m)
	if liveTotal != 0 {
		t.Errorf("m.liveTotal = %d after a completed call teardown, want 0 — a real "+
			"termination that finished after its session record was deleted burned a "+
			"max_concurrent_calls_total slot permanently", liveTotal)
	}
	if calls != 0 {
		t.Errorf("m.calls holds %d entries, want 0 — the call handle is orphaned: its "+
			"session is gone, so JanitorSweep (which only walks m.sessions) can never "+
			"reach it again", calls)
	}
	if liveUATotal != 0 || uas != 0 {
		t.Errorf("m.liveUATotal = %d, len(m.uas) = %d, want 0 and 0 — the UA half of the "+
			"same teardown must still be reclaimed", liveUATotal, uas)
	}

	// The leak is a CAPACITY leak, so prove the capacity actually came back: a
	// fresh session can place a call again, which is what the burned
	// max_concurrent_calls_total slot would eventually have prevented.
	if err := m.Open(ctx, "s2"); err != nil {
		t.Fatalf("Open(s2): %v", err)
	}
	ua2, err := m.CreateUA(ctx, "s2", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA on a fresh session after the race: %v", err)
	}
	if _, err := m.CreateCall(ctx, "s2", ua2.Handle(), Outbound, StateAnswered); err != nil {
		t.Fatalf("CreateCall on a fresh session after the race: %v", err)
	}
}
