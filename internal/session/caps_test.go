package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

func dial(t *testing.T, m *Manager, sid string, ua Handle) (*Call, error) {
	t.Helper()
	return m.CreateCall(context.Background(), sid, ua, Outbound, StateDialing)
}

func setupSessions(t *testing.T, m *Manager, sids ...string) map[string]Handle {
	t.Helper()
	ctx := context.Background()
	uas := make(map[string]Handle, len(sids))
	for _, sid := range sids {
		if err := m.Open(ctx, sid); err != nil {
			t.Fatalf("Open(%q): %v", sid, err)
		}
		ua, err := m.CreateUA(ctx, sid, UAConfig{Mode: "direct", Transport: TransportUDP})
		if err != nil {
			t.Fatalf("CreateUA(%q): %v", sid, err)
		}
		uas[sid] = ua.Handle()
	}
	return uas
}

func assertDenied(t *testing.T, err error, wantRule string, wantLimit, wantCurrent int) {
	t.Helper()
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want *apierr.Error", err)
	}
	if ae.Code != apierr.CodeDenied {
		t.Fatalf("code = %q, want denied", ae.Code)
	}
	if ae.Rule != wantRule {
		t.Fatalf("rule = %q, want %q — the denial must NAME the bound", ae.Rule, wantRule)
	}
	if ae.Limit == nil {
		t.Fatalf("limit is nil, want %d", wantLimit)
	}
	if *ae.Limit != wantLimit {
		t.Errorf("limit = %d, want %d", *ae.Limit, wantLimit)
	}
	if ae.Current == nil {
		t.Fatalf("current is nil, want %d", wantCurrent)
	}
	if *ae.Current != wantCurrent {
		t.Errorf("current = %d, want %d", *ae.Current, wantCurrent)
	}
}

func TestConcurrencyCapsGrid(t *testing.T) {
	tests := []struct {
		name        string
		perSession  int
		total       int
		preS1       int // live calls already held by S1
		preS2       int // live calls already held by S2
		dialAs      string
		wantRule    string
		wantLimit   int
		wantCurrent int
	}{
		{"under both bounds", 2, 3, 1, 0, "s1", "", 0, 0},
		{"per-session bound binds", 2, 3, 2, 0, "s1", "max_concurrent_calls_per_session", 2, 2},
		{"server-wide bound binds a session holding one call", 2, 3, 2, 1, "s2",
			"max_concurrent_calls_total", 3, 3},
		{"both bounds: per-session is reported FIRST", 2, 2, 2, 0, "s1",
			"max_concurrent_calls_per_session", 2, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newRetentionManager(t, func(l *policy.Limits) {
				l.MaxConcurrentCallsPerSession = tc.perSession
				l.MaxConcurrentCallsTotal = tc.total
			})
			uas := setupSessions(t, m, "s1", "s2")
			for i := 0; i < tc.preS1; i++ {
				if _, err := dial(t, m, "s1", uas["s1"]); err != nil {
					t.Fatalf("s1 pre-dial %d: %v", i, err)
				}
			}
			for i := 0; i < tc.preS2; i++ {
				if _, err := dial(t, m, "s2", uas["s2"]); err != nil {
					t.Fatalf("s2 pre-dial %d: %v", i, err)
				}
			}

			_, err := dial(t, m, tc.dialAs, uas[tc.dialAs])
			if tc.wantRule == "" {
				if err != nil {
					t.Fatalf("dial: %v, want success", err)
				}
				return
			}
			assertDenied(t, err, tc.wantRule, tc.wantLimit, tc.wantCurrent)
		})
	}
}

// TestSection1222Acceptance reproduces §12.2.2's acceptance criterion.
func TestSection1222Acceptance(t *testing.T) {
	m, _ := newRetentionManager(t, func(l *policy.Limits) {
		l.MaxConcurrentCallsPerSession = 2
		l.MaxConcurrentCallsTotal = 3
	})
	uas := setupSessions(t, m, "s1", "s2")

	// S1 dials two calls successfully.
	s1a, err := dial(t, m, "s1", uas["s1"])
	if err != nil {
		t.Fatalf("s1 dial 1: %v", err)
	}
	if _, err := dial(t, m, "s1", uas["s1"]); err != nil {
		t.Fatalf("s1 dial 2: %v", err)
	}

	// S1's third is denied naming the PER-SESSION key.
	_, err = dial(t, m, "s1", uas["s1"])
	assertDenied(t, err, "max_concurrent_calls_per_session", 2, 2)

	// ...WHILE S2's first dial SUCCEEDS. The caps are independent: S1's
	// exhaustion does not consume S2's allowance.
	if _, err := dial(t, m, "s2", uas["s2"]); err != nil {
		t.Fatalf("s2 dial 1 after s1 exhausted its own cap: %v — the caps are independent", err)
	}

	// Three calls now live across S1 and S2. S2's second is denied naming the
	// SERVER-WIDE key EVEN THOUGH S2 HOLDS ONLY ONE CALL — the
	// first-come-first-served consequence, asserted rather than merely described.
	_, err = dial(t, m, "s2", uas["s2"])
	assertDenied(t, err, "max_concurrent_calls_total", 3, 3)
	if per, _ := m.DebugLiveCallCounts("s2"); per != 1 {
		t.Fatalf("s2 holds %d calls, want 1 — the starvation case must be exactly this", per)
	}

	// Hanging up one S1 call makes S2's next dial succeed, with NO reservation
	// having been held for S1.
	if err := s1a.TryHangup(time.Unix(1_700_000_001, 0), "local_hangup"); err != nil {
		t.Fatalf("s1 hangup: %v", err)
	}
	m.RecordTermination(s1a)
	if _, err := dial(t, m, "s2", uas["s2"]); err != nil {
		t.Fatalf("s2 dial after an S1 hangup: %v, want success with no reservation held", err)
	}
}

// TestBothBoundsReportsPerSessionFirst pins §12.2.2's check ORDER: a session
// at both bounds is told about its own first.
func TestBothBoundsReportsPerSessionFirst(t *testing.T) {
	m, _ := newRetentionManager(t, func(l *policy.Limits) {
		l.MaxConcurrentCallsPerSession = 2
		l.MaxConcurrentCallsTotal = 2
	})
	uas := setupSessions(t, m, "s1")
	for i := 0; i < 2; i++ {
		if _, err := dial(t, m, "s1", uas["s1"]); err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
	}
	// Both bounds are now full. The per-session key must be the one reported.
	_, err := dial(t, m, "s1", uas["s1"])
	assertDenied(t, err, "max_concurrent_calls_per_session", 2, 2)
}

// TestTerminationFreesSlotsImmediately asserts the §12.2.2 clause that a
// terminated call stops counting against BOTH caps IMMEDIATELY ON TERMINATION,
// not at registry eviction (§N3).
//
// registry_retention is 1h here deliberately: the entry is still fully
// resolvable when the slot must already be free, so the test cannot pass by
// accident through an eviction that has not happened.
func TestTerminationFreesSlotsImmediately(t *testing.T) {
	tests := []struct {
		name       string
		perSession int
		total      int
	}{
		{"per-session slot", 1, 50},
		{"server-wide slot", 50, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, fc := newRetentionManager(t, func(l *policy.Limits) {
				l.MaxConcurrentCallsPerSession = tc.perSession
				l.MaxConcurrentCallsTotal = tc.total
				l.RegistryRetention = policy.Duration(time.Hour)
				l.MaxTerminatedCallsPerSession = 500
			})
			uas := setupSessions(t, m, "s1")

			c, err := dial(t, m, "s1", uas["s1"])
			if err != nil {
				t.Fatalf("first dial: %v", err)
			}
			if _, err := dial(t, m, "s1", uas["s1"]); err == nil {
				t.Fatal("second dial succeeded at the cap, want denied")
			}

			if err := c.TryHangup(fc.Now(), "local_hangup"); err != nil {
				t.Fatalf("hangup: %v", err)
			}
			m.RecordTermination(c)

			// The slot is free NOW, with no janitor pass and the retention
			// window nowhere near elapsed.
			if _, err := dial(t, m, "s1", uas["s1"]); err != nil {
				t.Fatalf("dial immediately after hangup: %v — terminated calls must stop "+
					"counting at TERMINATION, not at registry eviction", err)
			}
			// ...and the terminated entry is still resolvable, proving the slot
			// was not freed by eviction.
			if _, err := m.ResolveCall(context.Background(), "s1", c.Handle()); err != nil {
				t.Fatalf("terminated call resolve: %v — it must still be inside its 1h "+
					"retention window", err)
			}
		})
	}
}

// TestConcurrencyCapsUnderRace asserts the caps are never overshot when many
// dials race, AND that the server-wide cap is actually REACHED (total == 6,
// the MaxConcurrentCallsTotal configured below): with a per-session cap of 4
// across two sessions (8 possible admits) and ample demand (20 racing dials),
// correct code always lands on exactly 6 live calls. Without that exact check,
// an implementation that silently denies every dial — granted == 0, total ==
// 0 — would satisfy every upper-bound assertion below. The check and the
// registration are both under the registry write lock, so unlike the §10.5
// waiter caps there is NO permitted overshoot here: the counts are exact,
// never merely bounded.
func TestConcurrencyCapsUnderRace(t *testing.T) {
	const iterations = 200
	for i := 0; i < iterations; i++ {
		m, _ := newRetentionManager(t, func(l *policy.Limits) {
			l.MaxConcurrentCallsPerSession = 4
			l.MaxConcurrentCallsTotal = 6
		})
		uas := setupSessions(t, m, "s1", "s2")

		var barrier sync.WaitGroup
		barrier.Add(1)
		var wg sync.WaitGroup
		const callers = 20
		errs := make([]error, callers)
		for j := 0; j < callers; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				sid := "s1"
				if j%2 == 1 {
					sid = "s2"
				}
				barrier.Wait()
				_, errs[j] = dial(t, m, sid, uas[sid])
			}(j)
		}
		barrier.Done()
		wg.Wait()

		s1, total := m.DebugLiveCallCounts("s1")
		s2, _ := m.DebugLiveCallCounts("s2")
		if s1 > 4 || s2 > 4 {
			t.Fatalf("iteration %d: per-session counts %d/%d exceed the cap of 4", i, s1, s2)
		}
		if total > 6 {
			t.Fatalf("iteration %d: server-wide count %d exceeds the cap of 6", i, total)
		}
		if s1+s2 != total {
			t.Fatalf("iteration %d: %d+%d != %d — the two accountings diverged", i, s1, s2, total)
		}
		if total != 6 {
			t.Fatalf("iteration %d: total live calls = %d, want exactly 6 — with a per-session "+
				"cap of 4 across two sessions (8 possible admits) and 20 racing dials, the "+
				"server-wide cap of 6 must actually bind; a cap that grants nothing would "+
				"otherwise satisfy every bound checked above with total == 0", i, total)
		}
		granted := 0
		for j, err := range errs {
			if err == nil {
				granted++
				continue
			}
			var ae *apierr.Error
			if !errors.As(err, &ae) || ae.Code != apierr.CodeDenied {
				t.Fatalf("iteration %d caller %d: err = %v, want denied", i, j, err)
			}
			if ae.Rule != "max_concurrent_calls_per_session" &&
				ae.Rule != "max_concurrent_calls_total" {
				t.Fatalf("iteration %d caller %d: rule = %q, not a §12.2.2 key", i, j, ae.Rule)
			}
		}
		if granted != total {
			t.Fatalf("iteration %d: %d dials granted but %d calls live", i, granted, total)
		}
	}
}

// TestUACapsAreNotCheckThenAct is §12.7's exhaustion-recovery criterion applied
// to the cap itself: with max_uas_total: 2, N concurrent creates yield EXACTLY
// two live UAs, never three.
//
// THE FACTORY SLEEPS ON A CHANNEL THE TEST CONTROLS, standing in for the socket
// bind and digest REGISTER that make the real window wide. Before blocking, the
// factory signals `entered`; the test drains exactly one signal per goroutine
// before closing `release`. THAT DRAIN IS THE BARRIER: it guarantees every
// goroutine has already reached the factory call — and so is past the old
// read-lock pre-check, which happens before the factory runs — before any of
// them is allowed to proceed to the insert. Without this drain, close(release)
// could race ahead of a not-yet-scheduled goroutine, letting it perform its
// pre-check AFTER the winners have already inserted, see a full cap, and be
// (correctly, but coincidentally) denied — masking the defect this test exists
// to catch. With the drain, that interleaving is impossible: this is precisely
// the interleaving the defect needs, deterministically, which a bare -race run
// would almost never produce on its own.
func TestUACapsAreNotCheckThenAct(t *testing.T) {
	const goroutines = 8

	release := make(chan struct{})
	entered := make(chan struct{}, goroutines)
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p := policy.Defaults()
	p.Limits.MaxUAsTotal = 2
	p.Limits.MaxUAsPerSession = 100 // the TOTAL is what this test binds on
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: policy.NewStaticStore(p, fc, testLogger()),
		Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) {
			entered <- struct{}{} // signal we've reached the factory, then block
			<-release             // every caller is now past any pre-lock check
			return nopAgent{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var okCount int
	var denials []*apierr.Error

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				okCount++
				return
			}
			var ae *apierr.Error
			if !errors.As(err, &ae) {
				t.Errorf("CreateUA error is not *apierr.Error: %v", err)
				return
			}
			denials = append(denials, ae)
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-entered // block until every goroutine is past its pre-lock check
	}
	close(release)
	wg.Wait()

	if okCount != 2 {
		t.Fatalf("successful ua_creates = %d, want exactly 2. max_uas_total was checked "+
			"under a READ lock that was released before the socket bind and the REGISTER, "+
			"then the insert took the write lock with NO re-check — so every goroutine "+
			"observed a free slot", okCount)
	}
	if got := len(m.LiveUAs(ctx)); got != 2 {
		t.Fatalf("live UAs = %d, want 2 — the registry itself is over the cap", got)
	}
	if len(denials) != goroutines-2 {
		t.Fatalf("denials = %d, want %d", len(denials), goroutines-2)
	}
	for _, ae := range denials {
		if ae.Code != apierr.CodeDenied {
			t.Errorf("denial code = %q, want %q", ae.Code, apierr.CodeDenied)
		}
		if ae.Rule != "max_uas_total" {
			t.Errorf("denial rule = %q, want %q — §12.2.2's discipline is that the "+
				"denial NAMES the bound key", ae.Rule, "max_uas_total")
		}
		if ae.Limit == nil || *ae.Limit != 2 {
			t.Errorf("denial limit = %v, want 2", ae.Limit)
		}
		if ae.Current == nil || *ae.Current != 2 {
			t.Errorf("denial current = %v, want 2 — an accurate current is what lets an "+
				"agent tell 'the server is full' from 'I asked for something impossible'",
				ae.Current)
		}
	}
}

// TestUADestroyFreesTheMaxUAsTotalSlotImmediately is §N3's "the number of LIVE
// UAs is bounded … by limits.max_uas_total" and §12.7's exhaustion-recovery
// criterion, at the unit level: the slot frees at DESTRUCTION, not at eviction.
//
// The clock is NEVER ADVANCED and JanitorSweep is NEVER CALLED. That is the
// whole assertion: the destroyed handle is still in m.uas — registry_retention
// has not elapsed and ua_status must still answer on it — and the create must
// succeed anyway. Measure the cap with len(m.uas) and this fails, because the
// operator who deleted a UA to escape max_uas_total stays exhausted for the
// whole retention window, which is the state §12.7 exists to make exitable.
func TestUADestroyFreesTheMaxUAsTotalSlotImmediately(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p := policy.Defaults()
	p.Limits.MaxUAsTotal = 1
	p.Limits.MaxUAsPerSession = 100 // the TOTAL is what this test binds on
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: policy.NewStaticStore(p, fc, testLogger()),
		Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) {
			return nopAgent{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	u, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("first CreateUA: %v", err)
	}

	// The cap is real: the second create is denied while the first is LIVE.
	if _, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP}); err == nil {
		t.Fatal("second CreateUA succeeded while the first UA was still live: " +
			"max_uas_total is not being enforced at all, so the rest of this " +
			"test would pass vacuously")
	}

	// Destroy it. This is what §12.7's admin DELETE reaches, through destroyUA.
	u.MarkDestroyed(fc.Now())
	m.RecordUADestroyed(u)

	// The handle is STILL RETAINED: registry_retention has not elapsed and
	// nothing has swept. This is the condition that makes the basis observable.
	if _, err := m.ResolveUA(ctx, "s1", u.Handle()); err != nil {
		t.Fatalf("ResolveUA on the destroyed handle: %v — the handle must stay "+
			"resolvable for registry_retention so ua_status can answer; if it is "+
			"already gone this test is no longer measuring what it claims", err)
	}

	// THE ASSERTION. No clock advance, no JanitorSweep.
	if _, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP}); err != nil {
		t.Fatalf("ua_create after the destroy: %v — the max_uas_total slot did NOT "+
			"free at destruction. §N3 bounds LIVE UAs by this key, and §12.7's "+
			"recovery case requires ua_create to succeed after the admin DELETEs; "+
			"counting destroyed-but-retained handles keeps the operator exhausted "+
			"for the whole registry_retention window (default 1h)", err)
	}
}
