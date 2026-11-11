package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/metrics"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// newRetentionManager is a named wrapper over Task 8's newManagerWith (Rule 18).
func newRetentionManager(t *testing.T, mut func(*policy.Limits)) (*Manager, *fakeclock.Clock) {
	t.Helper()
	return newManagerWith(t, mut)
}

func assertCode(t *testing.T, err error, want apierr.Code) {
	t.Helper()
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want *apierr.Error with code %q", err, want)
	}
	if ae.Code != want {
		t.Fatalf("code = %q, want %q", ae.Code, want)
	}
}

func TestRetentionWindow(t *testing.T) {
	m, fc := newRetentionManager(t, func(l *policy.Limits) { l.RegistryRetention = policy.Duration(5 * time.Second) })
	ctx := context.Background()
	c := mustCall(t, m, "s1")

	if err := c.TryAnswer(fc.Now()); err != nil {
		t.Fatalf("answer: %v", err)
	}
	if err := c.TryHangup(fc.Now(), "local_hangup"); err != nil {
		t.Fatalf("hangup: %v", err)
	}
	m.RecordTermination(c)

	// Immediately after termination the handle still resolves.
	if _, err := m.ResolveCall(ctx, "s1", c.Handle()); err != nil {
		t.Fatalf("resolve immediately after termination: %v, want ok", err)
	}

	fc.Advance(4 * time.Second)
	m.JanitorSweep(fc.Now())
	if _, err := m.ResolveCall(ctx, "s1", c.Handle()); err != nil {
		t.Fatalf("resolve inside the retention window: %v, want ok", err)
	}

	fc.Advance(2 * time.Second) // now 6s > 5s
	m.JanitorSweep(fc.Now())
	_, err := m.ResolveCall(ctx, "s1", c.Handle())
	assertCode(t, err, apierr.CodeGone)
}

// TestRetentionNeverAppliesToLiveObjects is D11 point 5 and §N3's
// "terminated-entry clock and nothing else".
func TestRetentionNeverAppliesToLiveObjects(t *testing.T) {
	m, fc := newRetentionManager(t, func(l *policy.Limits) { l.RegistryRetention = policy.Duration(5 * time.Second) })
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	ua := c.UAHandle()

	fc.Advance(72 * time.Hour)
	m.JanitorSweep(fc.Now())

	if _, err := m.ResolveCall(ctx, "s1", c.Handle()); err != nil {
		t.Fatalf("live call evicted after 72h: %v — registry_retention must never start "+
			"for anything still live", err)
	}
	if _, err := m.ResolveUA(ctx, "s1", ua); err != nil {
		t.Fatalf("live UA destroyed after 72h: %v — a live UA has NO time-based "+
			"destruction trigger at all (D11 point 5)", err)
	}
	if got := c.State(); got != StateRinging {
		t.Fatalf("live call state = %q after 72h, want ringing", got)
	}
}

func TestTerminatedCapsEvictOldestFirst(t *testing.T) {
	tests := []struct {
		name     string
		cap      int
		total    int
		wantGone int
	}{
		{"under the cap", 5, 3, 0},
		{"at the cap", 3, 3, 0},
		{"over the cap by two", 3, 5, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, fc := newRetentionManager(t, func(l *policy.Limits) {
				l.MaxTerminatedCallsPerSession = tc.cap
				l.RegistryRetention = policy.Duration(time.Hour) // the window must NOT be what evicts here
			})
			ctx := context.Background()
			if err := m.Open(ctx, "s1"); err != nil {
				t.Fatalf("Open: %v", err)
			}
			ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
			if err != nil {
				t.Fatalf("CreateUA: %v", err)
			}

			handles := make([]Handle, tc.total)
			for i := 0; i < tc.total; i++ {
				c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
				if err != nil {
					t.Fatalf("CreateCall %d: %v", i, err)
				}
				handles[i] = c.Handle()
				fc.Advance(time.Second) // distinct termination times, oldest first
				if err := c.TryHangup(fc.Now(), "local_hangup"); err != nil {
					t.Fatalf("hangup %d: %v", i, err)
				}
				m.RecordTermination(c) // immediate cap check, no janitor pass
			}

			for i, h := range handles {
				_, err := m.ResolveCall(ctx, "s1", h)
				if i < tc.wantGone {
					assertCode(t, err, apierr.CodeGone)
					continue
				}
				if err != nil {
					t.Errorf("call %d (of %d, cap %d): %v, want resolvable", i, tc.total, tc.cap, err)
				}
			}
		})
	}
}

func TestLiveCallsDoNotCountAgainstTerminatedCaps(t *testing.T) {
	m, fc := newRetentionManager(t, func(l *policy.Limits) {
		l.MaxTerminatedCallsPerSession = 2
		l.MaxConcurrentCallsPerSession = 50
	})
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	var live []Handle
	for i := 0; i < 5; i++ {
		c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
		if err != nil {
			t.Fatalf("CreateCall %d: %v", i, err)
		}
		live = append(live, c.Handle())
	}
	// Terminate two others; the cap must bind on those alone.
	for i := 0; i < 2; i++ {
		c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
		if err != nil {
			t.Fatalf("CreateCall extra %d: %v", i, err)
		}
		fc.Advance(time.Second)
		if err := c.TryHangup(fc.Now(), "local_hangup"); err != nil {
			t.Fatalf("hangup extra %d: %v", i, err)
		}
		m.RecordTermination(c)
	}
	for i, h := range live {
		if _, err := m.ResolveCall(ctx, "s1", h); err != nil {
			t.Fatalf("live call %d evicted by a TERMINATED-handle cap: %v", i, err)
		}
	}
}

// TestGoneVsNotFound pins the distinction §N3 calls load-bearing.
//
// `not_found` is what a handle from ANOTHER SESSION returns (§12.2 isolation),
// so an agent must be able to tell "my call finished and its record aged out"
// (gone) from "that handle was never mine" (not_found). A handle the server
// has NEVER ISSUED returns not_found, never gone.
func TestGoneVsNotFound(t *testing.T) {
	m, fc := newRetentionManager(t, func(l *policy.Limits) { l.RegistryRetention = policy.Duration(5 * time.Second) })
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	if err := c.TryAnswer(fc.Now()); err != nil {
		t.Fatalf("answer: %v", err)
	}
	if err := c.TryHangup(fc.Now(), "local_hangup"); err != nil {
		t.Fatalf("hangup: %v", err)
	}
	m.RecordTermination(c)
	fc.Advance(10 * time.Second)
	m.JanitorSweep(fc.Now())

	if err := m.Open(ctx, "s2"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Every §N3 tool surface resolves through the one shared path, so the code
	// cannot answer differently per tool. §10.3 names call_hangup explicitly.
	toolNames := []string{"call_status", "call_ladder", "quality_get", "call_events",
		"dtmf_received", "call_hangup"}
	for _, name := range toolNames {
		t.Run(name+" on an evicted handle", func(t *testing.T) {
			_, err := m.ResolveCall(ctx, "s1", c.Handle())
			assertCode(t, err, apierr.CodeGone)
		})
	}

	t.Run("never-issued handle", func(t *testing.T) {
		_, err := m.ResolveCall(ctx, "s1", Handle("call_0123456789abcdef"))
		assertCode(t, err, apierr.CodeNotFound)
	})
	t.Run("another session's evicted handle", func(t *testing.T) {
		_, err := m.ResolveCall(ctx, "s2", c.Handle())
		assertCode(t, err, apierr.CodeNotFound)
	})
	t.Run("destroyed UA after eviction", func(t *testing.T) {
		u, err := m.ResolveUA(ctx, "s1", c.UAHandle())
		if err != nil {
			t.Fatalf("UA resolve before destroy: %v", err)
		}
		if !u.MarkDestroyed(fc.Now()) {
			t.Fatal("MarkDestroyed returned false on a live UA")
		}
		m.RecordUADestroyed(u)
		fc.Advance(10 * time.Second)
		m.JanitorSweep(fc.Now())
		_, err = m.ResolveUA(ctx, "s1", c.UAHandle())
		assertCode(t, err, apierr.CodeGone)
	})
}

func TestJanitorTickerDrivesEviction(t *testing.T) {
	m, fc := newRetentionManager(t, func(l *policy.Limits) { l.RegistryRetention = policy.Duration(30 * time.Minute) })
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	if err := c.TryAnswer(fc.Now()); err != nil {
		t.Fatalf("answer: %v", err)
	}
	if err := c.TryHangup(fc.Now(), "local_hangup"); err != nil {
		t.Fatalf("hangup: %v", err)
	}
	m.RecordTermination(c)

	m.StartJanitor()
	fc.BlockUntil(1) // the janitor's ticker is registered

	fc.Advance(time.Hour) // one tick; 60m elapsed > 30m retention
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := m.ResolveCall(ctx, "s1", c.Handle()); err != nil {
			assertCode(t, err, apierr.CodeGone)
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the hourly janitor tick did not evict the expired entry")
}

// TestEvictionWakesParkedWaitersWithGone is §6.3 rule 3 driven through the
// PRODUCTION janitor path (JanitorSweep -> evictCallLocked -> MarkGoneAndWake)
// rather than the EvictCallForTest seam.
//
// Getting a waiter GENUINELY still parked at eviction time is not achievable
// through m.Wait/register(): register() (rule 1) never parks a waiter on a
// call that is already terminal — it always returns immediately, either with
// the terminal event or, once evicted, with apierr.Gone. And rule 2's
// terminal broadcast reaches every waiter already parked the instant
// TryHangup runs, so a waiter registered through m.Wait before termination is
// never observably still parked by the time RecordTermination — let alone
// JanitorSweep — runs later: its buffered channel already holds the terminal
// signal. That is exactly why an earlier version of this test, which parked
// four m.Wait callers and then drained them after TryHangup before calling
// RecordTermination, passed even with rule 3's wake loop deleted: all four
// waiters were already gone from c.waiters by the time JanitorSweep ran, so
// MarkGoneAndWake had nothing left to wake.
//
// This test file is in package session, so it can construct a *waiter and
// insert it into c.waiters directly — bypassing register()'s terminal
// short-circuit — which is the only way to hold a waiter that has NEVER
// received any signal on a call that is ALREADY terminated and
// retention-expired by the time the production JanitorSweep runs. That is
// exactly the state rule 3 exists to handle.
func TestEvictionWakesParkedWaitersWithGone(t *testing.T) {
	m, fc := newRetentionManager(t, func(l *policy.Limits) {
		l.RegistryRetention = policy.Duration(5 * time.Second)
	})
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	if err := c.TryAnswer(fc.Now()); err != nil {
		t.Fatalf("answer: %v", err)
	}
	if err := c.TryHangup(fc.Now(), "local_hangup"); err != nil {
		t.Fatalf("hangup: %v", err)
	}
	m.RecordTermination(c)

	// The call is terminal but still retained: a fresh wait returns the
	// terminal event immediately per rule 2's existing-log application.
	if _, err := m.Wait(ctx, WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "dtmf", TimeoutMs: 300000, Since: 0}); err != nil {
		t.Fatalf("wait on a terminated-but-retained call: %v, want the terminal event", err)
	}

	// Park four waiters DIRECTLY on the call, never through register(): they
	// have never been signalled, so they are the genuine article this test
	// needs — still blocked, still in c.waiters, when the sweep below evicts
	// the call.
	const n = 4
	ws := make([]*waiter, n)
	c.mu.Lock()
	for i := range ws {
		w := &waiter{until: EventDTMF, ch: make(chan waitSignal, 1)}
		c.waiters[w] = struct{}{}
		ws[i] = w
	}
	c.mu.Unlock()
	if got := c.waiterCount(); got != n {
		t.Fatalf("waiterCount = %d, want %d parked before the sweep", got, n)
	}

	fc.Advance(10 * time.Second)
	m.JanitorSweep(fc.Now())

	for i, w := range ws {
		select {
		case sig := <-w.ch:
			if !sig.gone {
				t.Fatalf("waiter %d: signal = %+v, want gone=true", i, sig)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("waiter %d: not woken within 100ms of the janitor sweep evicting the call", i)
		}
	}

	// The eviction is also observable through the normal API surface: a
	// fresh wait against the now-evicted handle returns gone.
	_, err := m.Wait(ctx, WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "dtmf", TimeoutMs: 300000, Since: 0})
	assertCode(t, err, apierr.CodeGone)
	if got := m.SessionWaiterCount("s1"); got != 0 {
		t.Fatalf("session waiter count = %d, want 0", got)
	}
}

// TestSection135Acceptance reproduces §13.5's acceptance for the registry half.
// The artifact half (recordings remain fetchable) belongs to internal/artifact
// and is asserted there; this test pins the registry side, which is what
// §13.5's "registry entry" column governs.
func TestSection135Acceptance(t *testing.T) {
	m, fc := newRetentionManager(t, func(l *policy.Limits) {
		l.RegistryRetention = policy.Duration(5 * time.Second)
		l.MaxTerminatedCallsPerSession = 3
	})
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	handles := make([]Handle, 5)
	for i := range handles {
		c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
		if err != nil {
			t.Fatalf("CreateCall %d: %v", i, err)
		}
		handles[i] = c.Handle()
		fc.Advance(time.Second)
		if err := c.TryHangup(fc.Now(), "local_hangup"); err != nil {
			t.Fatalf("hangup %d: %v", i, err)
		}
		m.RecordTermination(c)
	}

	// Exactly the three most recently terminated remain resolvable; the two
	// oldest return gone.
	for i, h := range handles {
		_, err := m.ResolveCall(ctx, "s1", h)
		if i < 2 {
			assertCode(t, err, apierr.CodeGone)
			continue
		}
		if err != nil {
			t.Errorf("call %d: %v, want resolvable", i, err)
		}
	}

	// A handle the server never issued returns not_found, never gone.
	_, err = m.ResolveCall(ctx, "s1", Handle("call_aaaaaaaaaaaaaaaa"))
	assertCode(t, err, apierr.CodeNotFound)

	// After the window elapses, the remaining three go too.
	fc.Advance(10 * time.Second)
	m.JanitorSweep(fc.Now())
	for _, h := range handles[2:] {
		_, err := m.ResolveCall(ctx, "s1", h)
		assertCode(t, err, apierr.CodeGone)
	}
}

// TestEmptySessionAgesOut is §12.6's Lifetime acceptance, driven by the fake
// clock. The two halves are a matched pair and neither is meaningful alone:
// an EMPTY record ages out after session_resume_window, and a record owning ANY
// live object NEVER does, no matter how long its connection has been gone.
//
// The second half is what makes D11 point 5 reachable. If a session owning a
// live UA could age out, the identity needed to control that UA would expire
// out from under it and the UA would be unreachable by anything except §12.7 —
// which is precisely the stranded state §12.7 exists to REMEDY, not to create.
func TestEmptySessionAgesOut(t *testing.T) {
	m, fc := newRetentionManager(t, func(l *policy.Limits) {
		l.SessionResumeWindow = policy.Duration(5 * time.Second)
		l.RegistryRetention = policy.Duration(time.Second)
	})
	ctx := context.Background()

	// s_empty: opened, never given a UA or call.
	if err := m.Open(ctx, "s_empty"); err != nil {
		t.Fatalf("Open(s_empty): %v", err)
	}
	// s_live: opened and holding one LIVE UA for the whole test.
	if err := m.Open(ctx, "s_live"); err != nil {
		t.Fatalf("Open(s_live): %v", err)
	}
	liveUA, err := m.CreateUA(ctx, "s_live", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	// Inside the window, both survive.
	fc.Advance(4 * time.Second)
	if res := m.JanitorSweep(fc.Now()); res.SessionsExpired != 0 {
		t.Fatalf("SessionsExpired = %d inside the resume window, want 0", res.SessionsExpired)
	}
	if !m.Alive("s_empty") {
		t.Fatal("s_empty expired inside its resume window")
	}

	// Past the window: the empty one goes, the one holding a live UA does not.
	fc.Advance(2 * time.Second) // 6s > 5s
	res := m.JanitorSweep(fc.Now())
	if res.SessionsExpired != 1 {
		t.Fatalf("SessionsExpired = %d, want exactly 1 (only s_empty)", res.SessionsExpired)
	}
	if m.Alive("s_empty") {
		t.Fatal("s_empty did not age out past session_resume_window")
	}
	if !m.Alive("s_live") {
		t.Fatal("s_live aged out while owning a LIVE UA — §12.6 forbids this, and it would " +
			"strand the UA that D11 point 5 guarantees stays controllable")
	}

	// ...and 60s after its connection closed, s_live still resolves its handles.
	fc.Advance(60 * time.Second)
	m.JanitorSweep(fc.Now())
	if _, err := m.ResolveUA(ctx, "s_live", liveUA.Handle()); err != nil {
		t.Fatalf("live UA unresolvable 66s after its session's last contact: %v", err)
	}
}

// TestSeenRefreshesTheResumeWindow proves Seen is wired to the same clock the
// sweep reads: a session contacted inside its window survives indefinitely.
func TestSeenRefreshesTheResumeWindow(t *testing.T) {
	m, fc := newRetentionManager(t, func(l *policy.Limits) {
		l.SessionResumeWindow = policy.Duration(5 * time.Second)
	})
	if err := m.Open(context.Background(), "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := 0; i < 4; i++ {
		fc.Advance(4 * time.Second)
		m.Seen("s1")
		m.JanitorSweep(fc.Now())
		if !m.Alive("s1") {
			t.Fatalf("round %d: session expired despite being seen inside its window", i)
		}
	}
	fc.Advance(6 * time.Second) // not seen this time
	m.JanitorSweep(fc.Now())
	if m.Alive("s1") {
		t.Fatal("session survived a full resume window with no contact")
	}
}

// TestTombstoneRingBoundary pins U10's ACCEPTED DEGRADATION at its exact
// boundary. This is not a test of a bug; it is the test that stops a future
// reader "fixing" a deliberate trade.
//
// §13.5 wants an evicted handle to answer `gone` and a never-issued handle to
// answer `not_found`. §N3 forbids the unbounded memory that distinction needs.
// U10 resolves it with a bounded per-session ring sized to the terminated-call
// cap, ACCEPTING that a handle pushed out of the ring answers `not_found` —
// reporting "never existed" for something that did exist.
//
// The boundary must be CROSSED for the assertion to mean anything. An earlier
// draft evicted 2 handles against a cap of 3 and never filled the ring, so it
// asserted only the happy path and would have passed against an unbounded map,
// against a ring of any size >= 2, and against no ring at all.
//
// D52: the local constant is named ringCap, not cap — cap is a Go builtin and
// golangci-lint's revive redefines-builtin-id flags shadowing it.
func TestTombstoneRingBoundary(t *testing.T) {
	const ringCap = 3
	m, fc := newRetentionManager(t, func(l *policy.Limits) {
		l.MaxTerminatedCallsPerSession = ringCap
		l.RegistryRetention = policy.Duration(time.Hour) // the window must NOT evict here
	})
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	// Terminate 2*ringCap + 1 calls. The cap evicts oldest-first as we go, so
	// the ring receives ringCap+1 handles and OVERFLOWS by exactly one.
	const total = 2*ringCap + 1 // 7 calls -> 4 evicted -> ring of 3 overflows by 1
	handles := make([]Handle, total)
	for i := range handles {
		c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
		if err != nil {
			t.Fatalf("CreateCall %d: %v", i, err)
		}
		handles[i] = c.Handle()
		fc.Advance(time.Second)
		if err := c.TryHangup(fc.Now(), "local_hangup"); err != nil {
			t.Fatalf("hangup %d: %v", i, err)
		}
		m.RecordTermination(c)
	}

	// total - ringCap = 4 handles were evicted; the ring holds only ringCap = 3
	// of them. So handle 0 — the OLDEST evicted, pushed out of the ring —
	// degrades.
	evicted := total - ringCap // 4
	for i, h := range handles {
		_, err := m.ResolveCall(ctx, "s1", h)
		switch {
		case i == 0:
			// THE ACCEPTED DEGRADATION, ASSERTED. This handle genuinely
			// existed and was genuinely reclaimed, and the server now says
			// not_found — indistinguishable from a handle it never issued.
			assertCode(t, err, apierr.CodeNotFound)
		case i < evicted:
			// Still inside the ring: the §13.5 distinction holds.
			assertCode(t, err, apierr.CodeGone)
		default:
			// Still retained: fully resolvable.
			if err != nil {
				t.Errorf("call %d: %v, want resolvable (inside the terminated cap)", i, err)
			}
		}
	}

	// The ring holds AT MOST ringCap handles — the property that makes it
	// bounded, and the one §N3 actually requires.
	s := m.session("s1")
	if got := len(s.callTombstones.buf); got > ringCap {
		t.Fatalf("tombstone ring holds %d handles, want at most %d — an unbounded ring "+
			"reintroduces exactly the growth §N3 exists to prevent", got, ringCap)
	}
}

// recordingTap is a session.Tap that remembers which call-IDs it holds a ladder
// for, which were RETAINED, and which were evicted. It implements all SEVEN
// methods of U7 as amended by U18; the ones a given test does not drive are
// present because the interface requires them.
//
// IT MODELS THE REAL RETENTION SEMANTICS, not just a call recorder: Retain marks
// the ring (creating an empty one if none exists, per contract §2.5.3) and Evict
// both drops the ring AND releases the retention. A fake that only appended to a
// slice would let a test pass while trace.Sink's actual exclusion rule was
// wrong, and the whole point of U18 is that the exclusion is what makes the LRU
// point the right way round.
// ladderArg records one (uaHandle, callID) pair passed to Tap.Ladder, so a
// test can assert call_ladder resolved the OWNING UA server-side (HIGH-3)
// rather than colliding two UAs' identical peer-chosen Call-IDs.
type ladderArg struct{ ua, callID string }

type recordingTap struct {
	mu         sync.Mutex
	ladders    map[string]int  // callID -> messages recorded
	retained   map[string]bool // callID -> excluded from LRU eviction
	evicted    []string        // callIDs passed to Evict, in order
	ladderArgs []ladderArg     // (uaHandle, callID) passed to Ladder, in order

	// onRetain, when non-nil, is called with the callID AFTER the retention is
	// recorded. It exists so a test can synchronise on Retain actually being
	// called by production code — never on a sleep, which would pass on a
	// build where Retain is never called at all.
	onRetain func(callID string)
}

func newRecordingTap() *recordingTap {
	return &recordingTap{
		ladders:  make(map[string]int),
		retained: make(map[string]bool),
	}
}

func (tp *recordingTap) SIPMessage(_ context.Context, rec SIPRecord) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.ladders[rec.CallID]++
}

func (tp *recordingTap) MediaFrame(context.Context, MediaRecord) {}

func (tp *recordingTap) Ladder(_ context.Context, uaHandle, callID string, f LadderFormat) (Ladder, error) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.ladderArgs = append(tp.ladderArgs, ladderArg{ua: uaHandle, callID: callID})
	n, ok := tp.ladders[callID]
	if !ok {
		return Ladder{}, apierr.NotFound("no ladder for call-id " + callID)
	}
	return Ladder{Format: f, Messages: n}, nil
}

// ladderArgsSnapshot returns a copy of the (uaHandle, callID) pairs Ladder was
// called with, in order.
func (tp *recordingTap) ladderArgsSnapshot() []ladderArg {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	out := make([]ladderArg, len(tp.ladderArgs))
	copy(out, tp.ladderArgs)
	return out
}

// Retain marks the ring as belonging to a live call so the LRU may never evict
// it (U18). A Retain for a callID with no ring yet creates an empty retained
// one, exactly as contract §2.5.3 specifies.
func (tp *recordingTap) Retain(_ context.Context, _ /*uaHandle*/, callID string) {
	tp.mu.Lock()
	if _, ok := tp.ladders[callID]; !ok {
		tp.ladders[callID] = 0
	}
	tp.retained[callID] = true
	cb := tp.onRetain
	tp.mu.Unlock()
	if cb != nil {
		cb(callID) // outside the fake's own lock, so a callback cannot deadlock it
	}
}

// Evict drops the ring AND releases the retention (U18). It is the only release.
func (tp *recordingTap) Evict(_ context.Context, _ /*uaHandle*/, callID string) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	delete(tp.ladders, callID)
	delete(tp.retained, callID)
	tp.evicted = append(tp.evicted, callID)
}

func (tp *recordingTap) ArmCapture(context.Context, string, string, io.WriteCloser, CaptureConfig) error {
	return apierr.NotSupported("capture arrives at P2")
}
func (tp *recordingTap) DisarmCapture(context.Context, string, string) (CaptureResult, error) {
	return CaptureResult{}, apierr.NotSupported("capture arrives at P2")
}

func (tp *recordingTap) has(callID string) bool {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	_, ok := tp.ladders[callID]
	return ok
}

// isRetained reports whether callID's ring is currently excluded from the LRU.
func (tp *recordingTap) isRetained(callID string) bool {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.retained[callID]
}

// retainedCount mirrors trace.Sink.DebugRetainedCount (contract §2.7), so a test
// can assert that no retention leaked.
func (tp *recordingTap) retainedCount() int {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return len(tp.retained)
}

// TestEvictionReclaimsTheLadder asserts that eviction frees the ladder PROMPTLY.
//
// A registry entry and a ladder ring are TWO allocations with ONE lifetime.
// Freeing the first and not the second is invisible to every other test in this
// package — the handle correctly answers `gone` and every retention assertion
// passes — while the ring sits there holding memory it no longer owes anyone.
// That is what U7 put Evict on the interface for.
//
// IT IS NOT AN ASSERTION ABOUT §N3's UNRETAINED BOUND (U15 as amended by U18).
// That bound is limits.max_ladders + least-recently-written eviction OVER THE
// UNRETAINED RINGS, in trace (contract §2.7). Evict cannot be it: ObservingConn
// taps the SOCKET, not the dialog, so REGISTER refreshes, OPTIONS keepalives, a
// failed Dial and a pre-Call inbound INVITE are all tapped under Call-IDs this
// registry never learns, and no janitor can evict a key it cannot name.
func TestEvictionReclaimsTheLadder(t *testing.T) {
	tp := newRecordingTap()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p := policy.Defaults()
	p.Limits.RegistryRetention = policy.Duration(5 * time.Second)
	m, err := NewManager(ManagerConfig{
		Ctx:    ctx,
		Clock:  fc,
		Policy: policy.NewStaticStore(p, fc, testLogger()),
		Logger: testLogger(),
		Tap:    tp,
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
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}
	// The Call-ID channel the contract amendment added. Without it the call
	// carries "" and the eviction below silently reclaims nothing.
	const callID = "callid-abc@203.0.113.7"
	c.setDialogIdentity("dlg-1", callID)

	// sipua feeds the tap directly (§6.2.1's tap-wiring exception); simulate
	// two observed messages for this call.
	tp.SIPMessage(ctx, SIPRecord{CallID: callID, Method: "INVITE"})
	tp.SIPMessage(ctx, SIPRecord{CallID: callID, StatusCode: 200})
	if !tp.has(callID) {
		t.Fatal("the tap holds no ladder for the call; the fixture is wrong")
	}

	if err := c.TryHangup(fc.Now(), "local_hangup"); err != nil {
		t.Fatalf("hangup: %v", err)
	}
	m.RecordTermination(c)

	// Still inside the retention window: the ladder MUST survive, because
	// call_ladder is answerable for as long as the registry entry is.
	fc.Advance(2 * time.Second)
	m.JanitorSweep(fc.Now())
	if !tp.has(callID) {
		t.Fatal("the ladder was reclaimed while the call was still retained — call_ladder " +
			"must answer for as long as the registry entry resolves (§13.5)")
	}

	// Past the window: registry entry AND ladder both go.
	fc.Advance(10 * time.Second)
	m.JanitorSweep(fc.Now())

	_, err = m.ResolveCall(ctx, "s1", c.Handle())
	assertCode(t, err, apierr.CodeGone)

	if tp.has(callID) {
		t.Fatal("the registry entry was evicted but the LADDER SURVIVED — a terminated " +
			"call's ring now lingers until U15's least-recently-written pressure reclaims " +
			"it under limits.max_ladders — and if the ring was RETAINED (U18) the LRU " +
			"can never reclaim it at all, because retained rings are excluded from its " +
			"candidate set. §N3's unretained bound still HOLDS (it is max_ladders + LRU " +
			"over the unretained rings, in trace); what is lost is the prompt " +
			"reclamation U7 added Tap.Evict for and the retention release U18 added.")
	}
	if len(tp.evicted) != 1 || tp.evicted[0] != callID {
		t.Fatalf("Evict calls = %v, want exactly one for %q — keyed by SIP Call-ID, never by "+
			"the call handle (U7: the tap is a server-wide sink fed by sipua, which never "+
			"learns a handle)", tp.evicted, callID)
	}
}

// TestEvictionWithNoCallIDDoesNotCallEvict pins the one legitimate skip: a call
// that never reached a dialog has no Call-ID and therefore no ladder, so there
// is nothing to evict and Evict("") must not be called — a tap keyed by "" would
// collide across every such call.
func TestEvictionWithNoCallIDDoesNotCallEvict(t *testing.T) {
	tp := newRecordingTap()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p := policy.Defaults()
	p.Limits.RegistryRetention = policy.Duration(time.Second)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: policy.NewStaticStore(p, fc, testLogger()),
		Logger: testLogger(), Tap: tp,
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	// A dial that failed before the INVITE went out: no dialog, no Call-ID.
	c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateDialing)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}
	if err := c.TryTerminate(fc.Now(), "transport_failure", EventError); err != nil {
		t.Fatalf("terminate: %v", err)
	}
	m.RecordTermination(c)

	fc.Advance(5 * time.Second)
	m.JanitorSweep(fc.Now())

	// POSITIVE CONTROL: eviction actually ran for this call — otherwise
	// len(tp.evicted) == 0 passes just as well if JanitorSweep silently did
	// nothing at all, proving nothing about the "no Call-ID, no Evict" rule
	// this test exists to pin.
	if _, err := m.ResolveCall(ctx, "s1", c.Handle()); err == nil {
		t.Fatal("the registry entry was not evicted past its retention window; " +
			"JanitorSweep did not run, so the len(tp.evicted) == 0 assertion " +
			"below proves nothing")
	} else {
		assertCode(t, err, apierr.CodeGone)
	}

	if len(tp.evicted) != 0 {
		t.Fatalf("Evict called with %v for a call that never had a Call-ID; an Evict(\"\") "+
			"would collide across every dialogless call", tp.evicted)
	}
}

// TestRetentionIsReleasedAtEvictionAndNotAtTermination pins the exact lifecycle
// stage at which U18's Tap.Retain is released.
//
// IT DRIVES THE REAL *Manager. The tap is a fake because trace.Sink is P1c's,
// but every transition below — RecordTermination, JanitorSweep, evictCallLocked
// — is the production code path, and the assertions read the fake only to
// observe what the production path did to it.
func TestRetentionIsReleasedAtEvictionAndNotAtTermination(t *testing.T) {
	tp := newRecordingTap()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p := policy.Defaults()
	p.Limits.RegistryRetention = policy.Duration(5 * time.Second)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: policy.NewStaticStore(p, fc, testLogger()),
		Logger: testLogger(), Tap: tp,
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}

	// Dialog establishment, as Task 11b performs it: set the identity, then
	// Retain holding no lock.
	const callID = "callid-retained@203.0.113.9"
	c.setDialogIdentity("dlg-r", callID)
	tp.Retain(ctx, "", callID)
	tp.SIPMessage(ctx, SIPRecord{CallID: callID, Method: "INVITE"})

	if !tp.isRetained(callID) {
		t.Fatal("the ring is not retained after establishment; the fixture is wrong")
	}

	if err := c.TryHangup(fc.Now(), "local_hangup"); err != nil {
		t.Fatalf("hangup: %v", err)
	}
	m.RecordTermination(c)

	// PROPERTY 1. The call is terminated but still inside the retention window,
	// so both the registry entry and the ladder must still be there.
	if !tp.isRetained(callID) {
		t.Fatal("RecordTermination released the U18 retention. It must not: §N3 " +
			"(spec:227) requires call_ladder to answer for a terminated call until its " +
			"registry entry is evicted, and Tap.Evict DROPS the ring as well as " +
			"releasing the retention, so releasing here makes call_ladder answer " +
			"not_found on a call §13.5 requires to answer ok")
	}
	if !tp.has(callID) {
		t.Fatal("the ladder was dropped at termination; call_ladder on a terminated " +
			"call inside the retention window must still render (§13.5)")
	}
	if _, err := m.ResolveCall(ctx, "s1", c.Handle()); err != nil {
		t.Fatalf("resolve immediately after termination: %v, want ok", err)
	}

	// PROPERTY 2. Past the window, the janitor evicts the registry entry — and
	// that is what releases the retention.
	fc.Advance(10 * time.Second)
	m.JanitorSweep(fc.Now())

	if _, err := m.ResolveCall(ctx, "s1", c.Handle()); err == nil {
		t.Fatal("the registry entry survived the retention window")
	}
	if tp.isRetained(callID) {
		t.Fatal("the registry entry was evicted but the U18 RETENTION SURVIVED — a " +
			"retained ring is excluded from the least-recently-written candidate set, " +
			"so nothing in the process can ever reclaim it. Tap.Evict is the ONLY " +
			"release (contract §2.5.3): this is a permanent leak, not a delay")
	}
	if n := tp.retainedCount(); n != 0 {
		t.Fatalf("retained rings = %d after eviction, want 0", n)
	}
}

// TestRecordTerminationIsIdempotent pins §6.0b INV-1's RT-IDEMPOTENCE
// requirement directly: if the call is already absent from s.liveCalls,
// RecordTermination performs NO decrement, NO metrics update and NO second
// log line. Required because INV-1's deferred call can race the janitor's
// own eviction path, and a double decrement corrupts exactly the caps
// §12.2.2 enforces.
//
// This is not one of the brief's own steps; it is added because the
// property is real (§6.0b INV-1, contract:3804) and the brief's steps never
// call RecordTermination twice on the same call to pin it. The `live` guard
// that makes this true already exists in the implementation landed above
// (janitor.go's `if _, live := s.liveCalls[c.handle]; !live { ...; return }`);
// this test is new, the guard is not.
//
// It reads the accounting through a REAL metrics.Registry rather than a
// mock, because Manager holds a concrete *metrics.Registry, not an
// interface — WriteText is the only observable surface.
func TestRecordTerminationIsIdempotent(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	reg := metrics.New(TerminationReasons)
	p := policy.Defaults()
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: policy.NewStaticStore(p, fc, testLogger()),
		Logger: testLogger(), Metrics: reg,
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	c := mustCall(t, m, "s1")
	if err := c.TryAnswer(fc.Now()); err != nil {
		t.Fatalf("answer: %v", err)
	}
	if err := c.TryHangup(fc.Now(), "local_hangup"); err != nil {
		t.Fatalf("hangup: %v", err)
	}

	// Simulate the INV-1 race: two independent paths both call
	// RecordTermination for the same call (e.g. the deferred caller and the
	// janitor's own eviction path racing it).
	m.RecordTermination(c)
	m.RecordTermination(c) // must be a no-op: c is already absent from liveCalls

	var buf bytes.Buffer
	if err := reg.WriteText(&buf); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	// active_calls is a gauge: CreateCall took it to 1, and ONE decrement must
	// bring it back to 0. A double decrement would drive it to -1.
	if !strings.Contains(out, "active_calls 0\n") {
		t.Errorf("metrics output = %q, want active_calls back to exactly 0 (one "+
			"increment from CreateCall, one decrement from RecordTermination), "+
			"not a double decrement", out)
	}
	if !strings.Contains(out, `calls_by_termination_reason{reason="local_hangup"} 1`+"\n") {
		t.Errorf("metrics output = %q, want calls_by_termination_reason{reason=\"local_hangup\"} "+
			"incremented exactly once, not twice", out)
	}
	if got := len(m.session("s1").terminatedCalls); got != 1 {
		t.Fatalf("terminatedCalls has %d entries after two RecordTermination calls "+
			"on the same call, want exactly 1 (a second recording must be unrepresentable)", got)
	}
}

// TestRecordTerminationUnknownReasonDoesNotPanicOrWedge pins I1:
// RecordTermination calls metrics.IncTerminationReason while holding m.mu
// (janitor.go:134-137, deliberately, for accounting atomicity), and
// IncTerminationReason panics by design on a label outside the set
// metrics.New was given. Before the I1 fix, a termination path that produces
// a reason metrics doesn't know about panics UNDER m.mu, which is never
// unlocked on this path (there is deliberately no defer m.mu.Unlock() in
// RecordTermination) — wedging every subsequent m.mu operation on the
// daemon. The fix guards the increment with Registry.HasReason so an
// unregistered label is skipped rather than panicked on, while the increment
// itself stays inside the lock hold.
func TestRecordTerminationUnknownReasonDoesNotPanicOrWedge(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// "weird_unregistered" is deliberately NOT in this set.
	reg := metrics.New([]string{"local_hangup"})
	p := policy.Defaults()
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: policy.NewStaticStore(p, fc, testLogger()),
		Logger: testLogger(), Metrics: reg,
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	c := mustCall(t, m, "s1")
	if err := c.TryAnswer(fc.Now()); err != nil {
		t.Fatalf("answer: %v", err)
	}
	// TryTerminate accepts any reason string with no enum validation at the
	// Call layer (§10.3) — this is how a termination path can reach
	// RecordTermination carrying a label the metrics Registry was never given.
	if err := c.TryTerminate(fc.Now(), "weird_unregistered", EventBye); err != nil {
		t.Fatalf("TryTerminate: %v", err)
	}

	m.RecordTermination(c) // must NOT panic (pre-fix: panics under m.mu)

	// Prove m.mu is free and the daemon is still healthy: a subsequent m.mu
	// operation must succeed, not hang or find the registry corrupted.
	if _, err := m.ResolveCall(ctx, "s1", c.Handle()); err != nil {
		t.Fatalf("m.mu op after RecordTermination failed: %v", err)
	}
}
