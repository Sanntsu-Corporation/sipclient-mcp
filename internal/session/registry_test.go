package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// nopAgent satisfies session.UserAgent (contract §2.5.3) and does nothing. It
// is the default agent for tests that care about the registries, not about
// signalling. Tests needing behaviour use internal/testutil/fakes.UserAgent or
// the blockingAgent of Task 11a.
//
// NOTE THE SHAPE: result types on Register and Dial, an AnswerRequest rather
// than a Handle, dialogID strings on Reject and Hangup, plus LocalAddr and
// OnEvent. A UA NEVER RECEIVES A HANDLE — that is the layering §6.2.1 protects.
type nopAgent struct{}

func (nopAgent) Register(context.Context) (RegisterResult, error) {
	return RegisterResult{Registered: true, Code: 200, ExpiresS: 3600}, nil
}
func (nopAgent) Unregister(context.Context) error { return nil }
func (nopAgent) Dial(context.Context, DialRequest) (DialResult, error) {
	return DialResult{DialogID: "dlg-nop"}, nil
}
func (nopAgent) Answer(context.Context, AnswerRequest) error       { return nil }
func (nopAgent) Reject(context.Context, string, int, string) error { return nil }
func (nopAgent) Hangup(context.Context, string, string) error      { return nil }
func (nopAgent) Close(context.Context) error                       { return nil }

// LocalAddr's RESULT TYPE IS net.Addr (U17), not *net.UDPAddr. The value
// returned is still a *net.UDPAddr — a UDP fake binds a UDP address — but the
// STATIC type is the transport-neutral one the interface declares, so a P4 fake
// returning a *net.TCPAddr satisfies the same method with no signature change.
func (nopAgent) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060}
}
func (nopAgent) TLSVerified() (bool, bool)                                      { return false, false }
func (nopAgent) OnEvent(context.Context, UAEventFunc)                           {}
func (nopAgent) OnAdmit(context.Context, AdmitFunc)                             {}
func (nopAgent) MediaView(string) (MediaView, bool)                             { return MediaView{}, false }
func (nopAgent) QualityView(string) (QualityView, bool)                         { return QualityView{}, false }
func (nopAgent) Play(context.Context, string, string, int, bool) (int64, error) { return 0, nil }
func (nopAgent) RecordStart(context.Context, string, string, string) (string, error) {
	return "", nil
}
func (nopAgent) RecordStop(context.Context, string, string, string) (ArtifactInfo, int64, error) {
	return ArtifactInfo{}, 0, nil
}
func (nopAgent) MediaPlanView(string) (MediaPlanView, bool) { return MediaPlanView{}, false }
func (nopAgent) SendDTMF(context.Context, string, string, DTMFMode, int, int) (int, int, error) {
	return 0, 0, nil
}
func (nopAgent) DTMFMode(string) (string, bool)                   { return "", false }
func (nopAgent) SessionTimerView(string) (SessionTimerView, bool) { return SessionTimerView{}, false }
func (nopAgent) Transfer(context.Context, TransferRequest) (TransferResult, error) {
	return TransferResult{}, nil
}
func (nopAgent) ControlOpBlocksHangup(string) (ControlOpKind, bool) { return "", false }

func testLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

// newTestStore builds a *policy.Store with no file on disk (contract §2.4).
// mut mutates policy.Defaults()'s limits before the store is frozen.
func newTestStore(t *testing.T, clk *fakeclock.Clock, mut func(*policy.Limits)) *policy.Store {
	t.Helper()
	p := policy.Defaults()
	if mut != nil {
		mut(&p.Limits)
	}
	return policy.NewStaticStore(p, clk, testLogger())
}

// newManagerWith is the ONE manager constructor every test in Tasks 8-11b uses
// (Rule 18). Task 9's newWaiterManager and Task 10's newRetentionManager are
// thin named wrappers over it, kept only because their names document intent.
func newManagerWith(t *testing.T, mut func(*policy.Limits)) (*Manager, *fakeclock.Clock) {
	t.Helper()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx:    ctx,
		Clock:  fc,
		Policy: newTestStore(t, fc, mut),
		Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) {
			return nopAgent{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, fc
}

func newTestManager(t *testing.T) (*Manager, *fakeclock.Clock) {
	t.Helper()
	return newManagerWith(t, nil)
}

// newFakeClock is the ONE fake-clock constructor for the package (Rule 18).
// Task 11a's tests build a Manager by hand and need a bare clock.
func newFakeClock() *fakeclock.Clock {
	return fakeclock.New(time.Unix(1_700_000_000, 0))
}

func mustCall(t *testing.T, m *Manager, sid string) *Call {
	t.Helper()
	ctx := context.Background()
	if err := m.Open(ctx, sid); err != nil {
		t.Fatalf("Open(%q): %v", sid, err)
	}
	ua, err := m.CreateUA(ctx, sid, UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	c, err := m.CreateCall(ctx, sid, ua.Handle(), Inbound, StateRinging)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}
	return c
}

func TestResolveIsolation(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	if err := m.Open(ctx, "s2"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	if _, err := m.ResolveCall(ctx, "s1", c.Handle()); err != nil {
		t.Fatalf("owner resolve: %v", err)
	}
	tests := []struct {
		name string
		sid  string
		h    Handle
	}{
		{"another session's handle", "s2", c.Handle()},
		{"never-issued handle", "s1", Handle("call_ffffffffffffffff")},
		{"unknown session", "s3", c.Handle()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := m.ResolveCall(ctx, tc.sid, tc.h)
			var ae *apierr.Error
			if !errors.As(err, &ae) || ae.Code != apierr.CodeNotFound {
				t.Fatalf("err = %v, want not_found", err)
			}
		})
	}
}

// TestResolveIgnoresHandlePrefix is the behavioural half of locked decision 12.
// A call registered under a handle carrying the WRONG prefix still resolves for
// its owner, and a correctly-prefixed handle from another session still does
// not — proving authorization consults registry membership only.
func TestResolveIgnoresHandlePrefix(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")

	odd := Handle("ua_deadbeefdeadbeef") // a UA-shaped handle in the CALL registry
	m.forceRegisterCallForTest("s1", odd, c)

	if _, err := m.ResolveCall(ctx, "s1", odd); err != nil {
		t.Fatalf("owner resolve of oddly-prefixed handle: %v, want success", err)
	}
	if err := m.Open(ctx, "s2"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	_, err := m.ResolveCall(ctx, "s2", odd)
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != apierr.CodeNotFound {
		t.Fatalf("foreign resolve = %v, want not_found", err)
	}
}

// TestCreateCallUsesPolicyEventLogSize pins CreateCall's wiring of
// limits.EventLogSize into the new call's log (registry.go's
// `newCall(..., lim.EventLogSize)`). It uses a distinguishing cap (4, not the
// 1024 every other test in this package passes) so a regression that
// hardcodes 1024 instead of reading the live policy value fails visibly here.
func TestCreateCallUsesPolicyEventLogSize(t *testing.T) {
	m, _ := newManagerWith(t, func(lim *policy.Limits) { lim.EventLogSize = 4 })
	c := mustCall(t, m, "s1")

	base := time.Unix(1000, 0)
	for i := 0; i < 6; i++ {
		c.Append(base, EventBye, nil)
	}

	evs, truncatedBefore, nextSince := c.Events(0)
	if len(evs) != 4 {
		t.Fatalf("len(evs) = %d, want 4 (policy.Limits.EventLogSize=4)", len(evs))
	}
	if truncatedBefore != 3 {
		t.Fatalf("truncatedBefore = %d, want 3", truncatedBefore)
	}
	if nextSince != 6 {
		t.Fatalf("nextSince = %d, want 6", nextSince)
	}
}

// TestDurationCapExitsEarlyOnConcurrentTerminate is D382: before this fix,
// StartDurationCap's goroutine selected only on its own timer and the daemon
// ctx, so a call that terminated by another path (hangup, BYE, ...) left the
// goroutine parked until the cap timer eventually fired — up to hours later
// with a long cap. That is a goroutine leak for the lifetime of every call
// that ends before its cap. The fix adds a third select case on a per-call
// done channel closed once in terminateLocked, so the goroutine exits
// promptly instead of at cap expiry.
func TestDurationCapExitsEarlyOnConcurrentTerminate(t *testing.T) {
	m, fc := newTestManager(t)
	c := mustCall(t, m, "s1")

	before := m.DurationCapGoroutinesForTest()
	m.StartDurationCap(c, time.Hour, func() {
		t.Error("onCap must not fire: the call terminated by another path before the cap")
	})
	fc.BlockUntil(1)
	if got := m.DurationCapGoroutinesForTest(); got != before+1 {
		t.Fatalf("armed duration-cap goroutines = %d, want %d", got, before+1)
	}

	// Terminate via the normal path (closes c.done), long before the 1h cap.
	if err := c.TryTerminate(fc.Now(), "local_hangup", EventBye); err != nil {
		t.Fatalf("TryTerminate: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.DurationCapGoroutinesForTest() == before {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("duration-cap goroutine still running after concurrent terminate "+
		"(count=%d, want %d): it should exit promptly, not park until the 1h cap",
		m.DurationCapGoroutinesForTest(), before)
}

// probeAgent captures the OnEvent callback CreateUA registers, so a test can
// fire an event exactly as sipua's own goroutines would — from OUTSIDE
// CreateUA, with no synchronisation beyond CreateUA having already returned —
// and prove the callback is actually wired by then. nopAgent's own OnEvent is
// a no-op, which is why every other registry test that only cares about the
// registries (not signalling) leaves it untouched.
type probeAgent struct {
	nopAgent
	mu      sync.Mutex
	fn      UAEventFunc
	hctx    context.Context
	admitFn AdmitFunc
	actx    context.Context
}

func (a *probeAgent) OnEvent(ctx context.Context, fn UAEventFunc) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hctx, a.fn = ctx, fn
}

// OnAdmit captures the synchronous admission callback CreateUA registers (I2),
// so a test can prove BOTH channels are wired and drive the admit path exactly
// as sipua's onInvite would — from OUTSIDE CreateUA, after it has returned.
func (a *probeAgent) OnAdmit(ctx context.Context, fn AdmitFunc) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.actx, a.admitFn = ctx, fn
}

// admit delivers ev on the admission callback CreateUA registered, returning
// the verdict. It panics rather than silently accepting when no callback was
// registered, so a regression that drops the OnAdmit call fails loudly here.
func (a *probeAgent) admit(ev UAEvent) Admission {
	a.mu.Lock()
	fn, ctx := a.admitFn, a.actx
	a.mu.Unlock()
	if fn == nil {
		panic("probeAgent.admit: OnAdmit was never registered by CreateUA")
	}
	return fn(ctx, ev)
}

// fire delivers ev on the callback CreateUA registered. It panics rather than
// silently no-oping when no callback was ever registered, so a regression
// that drops the OnEvent call shows up as a clear failure at this line
// instead of a confusing zero-value assertion below.
func (a *probeAgent) fire(ev UAEvent) {
	a.mu.Lock()
	fn, ctx := a.fn, a.hctx
	a.mu.Unlock()
	if fn == nil {
		panic("probeAgent.fire: OnEvent was never registered by CreateUA")
	}
	fn(ctx, ev)
}

// TestCreateUARegistersOnEventBeforeReturning is Rule 13 Cycle 5's
// discriminating test for hoisting agent.OnEvent out of CreateUA's m.mu
// critical section (registry.go): an event fired the INSTANT CreateUA
// returns must already reach (*Manager).handleUAEvent. A regression that
// drops the OnEvent call, moves it somewhere it can run too late, or skips it
// on some path leaves probeAgent.fn nil and this test fails — either via
// fire's panic or via the UA's registration state never updating below.
func TestCreateUARegistersOnEventBeforeReturning(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	agent := &probeAgent{}
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

	agent.fire(UAEvent{Kind: UAEventRefresh, ExpiresS: 3600, At: fc.Now()})

	if got := ua.ExpiresS(); got != 3600 {
		t.Fatalf("ExpiresS() = %d, want 3600: an event fired immediately after "+
			"CreateUA returned did not reach the manager", got)
	}
}

// TestCreateUAWiresBothOnEventAndOnAdmit is N4: CreateUA must register BOTH the
// one-way OnEvent callback AND the synchronous OnAdmit channel (I2). A UA wired
// with OnEvent but no OnAdmit would ring inbound INVITEs into the void, since
// admitInbound — reached only through OnAdmit — is now the SOLE inbound Call
// creator. The admit path is exercised end to end: firing it must create the
// ringing Call, proving OnAdmit is wired to admitInbound and not merely stored.
func TestCreateUAWiresBothOnEventAndOnAdmit(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	agent := &probeAgent{}
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

	// BOTH channels captured by the time CreateUA returned.
	agent.mu.Lock()
	haveOnEvent, haveOnAdmit := agent.fn != nil, agent.admitFn != nil
	agent.mu.Unlock()
	if !haveOnEvent {
		t.Error("CreateUA did not register OnEvent")
	}
	if !haveOnAdmit {
		t.Fatal("CreateUA did not register OnAdmit: inbound INVITEs would ring into the void (N4)")
	}

	// OnAdmit is wired to admitInbound, not merely stored: firing it creates the
	// ringing Call.
	v := agent.admit(inboundEvent("callid-n4"))
	if !v.Accept {
		t.Fatalf("admit verdict = %+v, want Accept under default limits", v)
	}
	if perSession, total := m.DebugLiveCallCounts("s1"); perSession != 1 || total != 1 {
		t.Fatalf("live call counts = (%d, %d), want (1, 1): OnAdmit is not wired to admitInbound", perSession, total)
	}
}

// TestOpenRejectsBeyondMaxSessionsTotal is the production-hardening spec's
// Task 3: an unbounded number of concurrent sessions compounds a
// bearer-token-compromise blast radius into unbounded server-side resource
// growth. The cap is rejected, never silently clamped, matching every
// other admission gate in this package.
func TestOpenRejectsBeyondMaxSessionsTotal(t *testing.T) {
	m, _ := newManagerWith(t, func(l *policy.Limits) { l.MaxSessionsTotal = 2 })
	ctx := context.Background()

	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open(s1): %v", err)
	}
	if err := m.Open(ctx, "s2"); err != nil {
		t.Fatalf("Open(s2): %v", err)
	}
	assertDenied(t, m.Open(ctx, "s3"), "max_sessions_total", 2, 2)

	// Re-opening an ALREADY-open session is not a new session and must not
	// be denied even while the registry is at the cap.
	if err := m.Open(ctx, "s1"); err != nil {
		t.Errorf("re-Open(s1) at cap = %v, want nil (existing session, not a new one)", err)
	}
}

// TestOpenExactlyAdmitsMaxSessionsTotalUnderRace is caps_test.go's
// TestConcurrencyCapsUnderRace applied to Task 3's max_sessions_total: the
// count-check-then-insert in Open happens entirely under m.mu.Lock(), so with
// 30 goroutines racing to open 30 DISTINCT session ids against a cap of 10,
// correct code always admits EXACTLY 10 — never more (a race in the
// check-then-insert would overshoot) and never fewer (a locking bug that
// serializes on the wrong scope, or a broken comparison, would starve
// admissions below the cap). A test that only checked "at most 10" would be
// satisfied by an implementation that silently denies everything.
func TestOpenExactlyAdmitsMaxSessionsTotalUnderRace(t *testing.T) {
	const iterations = 200
	for i := 0; i < iterations; i++ {
		m, _ := newManagerWith(t, func(l *policy.Limits) { l.MaxSessionsTotal = 10 })
		ctx := context.Background()

		var barrier sync.WaitGroup
		barrier.Add(1)
		var wg sync.WaitGroup
		const callers = 30
		errs := make([]error, callers)
		for j := 0; j < callers; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				barrier.Wait()
				errs[j] = m.Open(ctx, fmt.Sprintf("s%d", j))
			}(j)
		}
		barrier.Done()
		wg.Wait()

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
			if ae.Rule != "max_sessions_total" {
				t.Fatalf("iteration %d caller %d: rule = %q, want %q", i, j, ae.Rule, "max_sessions_total")
			}
		}
		if granted != 10 {
			t.Fatalf("iteration %d: %d Open calls granted, want exactly 10 — with a cap of 10 "+
				"and 30 racing distinct session ids, the cap must actually bind (not more, "+
				"a check-then-insert race outside the lock; not fewer, a starvation bug)", i, granted)
		}
	}
}

// TestOpenEvictsStaleEmptySessionAtCap is Rule 13 Cycle 5's fix for P4-W6-N04:
// max_sessions_total previously denied outright once the registry held
// MaxSessionsTotal RECORDS, even when some of those records were empty and
// long idle — a retained-not-live lockout. Open now evicts the oldest
// eviction-eligible (empty AND idle past sessionEvictionGracePeriod) record
// instead of denying, when one exists.
func TestOpenEvictsStaleEmptySessionAtCap(t *testing.T) {
	m, fc := newManagerWith(t, func(l *policy.Limits) { l.MaxSessionsTotal = 3 })
	ctx := context.Background()

	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open(s1): %v", err)
	}
	// s2 and s3 each get a live UA, so they are NOT eviction candidates —
	// s1 is the only empty (and therefore only eligible) record.
	setupSessions(t, m, "s2", "s3")
	// s1 stays EMPTY (no ua_create, no call) for the rest of the test — the
	// eviction candidate. Advance the clock past the grace period so s1
	// becomes eligible.
	fc.Advance(sessionEvictionGracePeriod)

	if err := m.Open(ctx, "s4"); err != nil {
		t.Fatalf("Open(s4) at cap with an evictable stale-empty session, want nil: %v", err)
	}
	if !m.Alive("s4") {
		t.Fatalf("s4 not registered after Open succeeded")
	}
	if m.Alive("s1") {
		t.Fatalf("s1 still alive after eviction — the stale-empty session should have been evicted")
	}
	// The registry is back at the cap (s2, s3, s4). A re-Open("s1") must now
	// behave like a BRAND-NEW session admission — subject to the cap exactly
	// like any other unseen id — not an idempotent re-open of the evicted
	// record (idempotent re-open never denies, per Open's own doc comment).
	// s4 is itself empty but still within its own grace period, so no further
	// eviction candidate exists and this correctly denies.
	assertDenied(t, m.Open(ctx, "s1"), "max_sessions_total", 3, 3)
}

// TestOpenDoesNotEvictFreshEmptySessionWithinGracePeriod proves the grace
// period actually gates eviction: a burst of fresh, still-forming empty
// sessions must not evict each other, or the cap's churn-limiting purpose is
// defeated (see sessionEvictionGracePeriod's doc comment).
func TestOpenDoesNotEvictFreshEmptySessionWithinGracePeriod(t *testing.T) {
	m, _ := newManagerWith(t, func(l *policy.Limits) { l.MaxSessionsTotal = 3 })
	ctx := context.Background()

	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open(s1): %v", err)
	}
	if err := m.Open(ctx, "s2"); err != nil {
		t.Fatalf("Open(s2): %v", err)
	}
	if err := m.Open(ctx, "s3"); err != nil {
		t.Fatalf("Open(s3): %v", err)
	}
	// No clock advance: s1-s3 are all still within the grace period.
	assertDenied(t, m.Open(ctx, "s4"), "max_sessions_total", 3, 3)
	if !m.Alive("s1") || !m.Alive("s2") || !m.Alive("s3") {
		t.Fatalf("a fresh empty session was evicted within its grace period")
	}
}

// TestOpenDoesNotEvictLiveSessionRegardlessOfAge proves a session owning any
// live UA or call is NEVER a pressure-eviction candidate, no matter how old —
// the original blast-radius protection for genuinely active sessions is
// unchanged by this fix.
//
// PHASE 1 NOTE (owner-locked decision, session-scoped UA lifecycle): this
// test's clock advance is kept WELL PAST sessionEvictionGracePeriod but
// WITHIN sessionTTL. Past the fixed 5-minute TTL, Alive() itself starts
// reporting false for EVERY session regardless of emptiness (that is the new
// choke-point invariant — see Alive's own doc comment) — a fact this test
// must not be conflated with. What this test pins is narrower and unchanged:
// Open's own PRESSURE-EVICTION scan (the sessionEmptyLocked branch below)
// never selects a live session as a victim, so s1-s3 remain in the registry
// (and therefore Alive) across a long-but-sub-TTL idle period.
func TestOpenDoesNotEvictLiveSessionRegardlessOfAge(t *testing.T) {
	m, fc := newManagerWith(t, func(l *policy.Limits) { l.MaxSessionsTotal = 3 })
	ctx := context.Background()

	setupSessions(t, m, "s1", "s2", "s3") // each gets a live UA

	// Advance well past the grace period (60s) but short of the 5-minute TTL,
	// so this stays a pure pressure-eviction assertion.
	fc.Advance(2 * sessionEvictionGracePeriod)

	assertDenied(t, m.Open(ctx, "s4"), "max_sessions_total", 3, 3)
	if !m.Alive("s1") || !m.Alive("s2") || !m.Alive("s3") {
		t.Fatalf("a live session was evicted — live sessions must never be evicted regardless of age")
	}
}

// TestSeenDoesNotRenewTTL is the mutation-pinned negative Seen's own doc
// comment names.
//
// WHY IT MATTERS — every tool call reaches Seen through the transport's
// resolve path. If Seen renewed, ordinary traffic would keep a session alive
// forever and D7's fixed 5-minute TTL would exist only on paper: a chatty
// agent would never expire, which is precisely the immortal-session failure
// the fixed TTL was introduced to end. lastSeen (the §12.6 resume-window
// clock) MUST still move, so this asserts both halves — one field advances,
// the other does not.
//
// Mutation check: add renewTTLLocked(s, now) to Seen and this reddens.
func TestSeenDoesNotRenewTTL(t *testing.T) {
	m, fc := newManagerWith(t, nil)
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	before, ok := m.SessionExpiresAt("s1")
	if !ok {
		t.Fatal("SessionExpiresAt right after Open: not ok")
	}

	// Far enough into the TTL that a renewal would be unmistakable, but not
	// past it — an expired session is a different code path.
	fc.Advance(policy.Defaults().Limits.SessionTTL.Duration() / 2)
	m.Seen("s1")

	after, ok := m.SessionExpiresAt("s1")
	if !ok {
		t.Fatal("SessionExpiresAt after Seen: not ok")
	}
	if !after.Equal(before) {
		t.Fatalf("Seen moved expiresAt from %s to %s: ordinary traffic must NEVER renew the TTL (D7), "+
			"or a chatty agent's session becomes immortal", before, after)
	}

	// The half Seen DOES own: the resume-window clock moved.
	m.mu.RLock()
	lastSeen := m.sessions["s1"].lastSeen
	m.mu.RUnlock()
	if !lastSeen.Equal(fc.Now()) {
		t.Fatalf("lastSeen = %s, want %s: Seen must still feed §12.6's resume-window clock", lastSeen, fc.Now())
	}
}

// TestCreateCallDoesNotRenewTTL is the mutation-pinned negative CreateCall's
// own doc comment names — the same D7 rule as TestSeenDoesNotRenewTTL, from
// the other direction. CreateCall sits one line from CreateUA (which DOES
// renew, and returns an expires_at the agent can act on) and returns no
// deadline of its own, so renewing here would silently extend a session
// through ordinary call traffic.
//
// Mutation check: add renewTTLLocked(s, m.clk.Now()) to CreateCall and this
// reddens.
func TestCreateCallDoesNotRenewTTL(t *testing.T) {
	m, fc := newManagerWith(t, nil)
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	// CreateUA renews (D7), so the baseline is read AFTER it, not after Open.
	before, ok := m.SessionExpiresAt("s1")
	if !ok {
		t.Fatal("SessionExpiresAt right after CreateUA: not ok")
	}

	fc.Advance(policy.Defaults().Limits.SessionTTL.Duration() / 2)
	if _, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateDialing); err != nil {
		t.Fatalf("CreateCall: %v", err)
	}

	after, ok := m.SessionExpiresAt("s1")
	if !ok {
		t.Fatal("SessionExpiresAt after CreateCall: not ok")
	}
	if !after.Equal(before) {
		t.Fatalf("CreateCall moved expiresAt from %s to %s: call traffic must NEVER renew the TTL (D7) — "+
			"only Open, CreateUA and session_keepalive do", before, after)
	}
}

// TestAdminDestroyOfTheLastUARefreshesTheResumeWindowEvenWhenIdle is Cycle
// C round 2's finding: admin DestroyUA never goes through the MCP
// transport's Seen() middleware, so it never touches lastSeen on its own.
// Without RecordUADestroyed explicitly refreshing lastSeen at the moment a
// session transitions to empty, a long-idle-but-live session that gets
// admin-destroyed would inherit its STALE lastSeen and could look already
// past session_resume_window — becoming unusable immediately instead of
// receiving the full window decision 5 promises.
//
// Mutation check: remove the lastSeen refresh from RecordUADestroyed and
// this test reddens (Alive flips false immediately after the admin
// destroy, because lastSeen is still the 30-minute-old value from CreateUA).
func TestAdminDestroyOfTheLastUARefreshesTheResumeWindowEvenWhenIdle(t *testing.T) {
	m, fc := newManagerWith(t, func(l *policy.Limits) {
		l.SessionTTL = policy.Duration(time.Hour) // long: keeps the live-UA session
		// alive through the idle window below on session_ttl alone, isolating
		// the resume-window behavior this test actually exercises.
		l.SessionResumeWindow = policy.Duration(10 * time.Minute)
	})
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	// The session sits idle for far longer than session_resume_window WHILE
	// its UA is still live — lastSeen goes stale, but the session stays
	// alive throughout because session_ttl (configured long above) governs
	// it, not session_resume_window, while it still holds a live UA.
	fc.Advance(30 * time.Minute)

	// Admin (NOT agent) destroys the last UA — bypasses Seen() entirely.
	if _, err := m.DestroyUA(ctx, string(ua.Handle())); err != nil {
		t.Fatalf("admin DestroyUA: %v", err)
	}

	// Immediately after: the session must be freshly resumable for the FULL
	// 10-minute window, not already-expired against its stale 30-minute-old
	// lastSeen.
	if !m.Alive("s1") {
		t.Fatal("Alive(s1) = false immediately after admin-destroying an idle session's " +
			"last UA, want true — the resume window must start fresh at the transition, " +
			"not be measured against a stale lastSeen from before the session went idle")
	}
	if _, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP}); err != nil {
		t.Fatalf("CreateUA immediately after the admin destroy: %v, want ok", err)
	}
}

// TestEmptySessionStaysAliveAndUsablePastSessionTTL is Cycle C's regression:
// an EMPTY session (no live UA, never had one OR just lost its last one)
// must stay Alive, and accept a fresh ua_create, for session_resume_window
// — not merely session_ttl, which is what a bare sessionExpiredLocked check
// would still enforce. This is the gate-level half of decision 5; Task 4/5
// cover the reaper/ua_destroy half.
//
// Mutation check: revert Alive/CreateUA to a bare sessionExpiredLocked check
// and this test reddens (Alive flips false, and the second CreateUA is
// refused with not_found, at t = old session_ttl + 1s).
func TestEmptySessionStaysAliveAndUsablePastSessionTTL(t *testing.T) {
	m, fc := newManagerWith(t, func(l *policy.Limits) {
		l.SessionResumeWindow = policy.Duration(20 * time.Minute)
	})
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Empty from birth: never created a UA. Well past session_ttl (the old,
	// pre-fix gate), short of the configured 20-minute resume window.
	fc.Advance(policy.Defaults().Limits.SessionTTL.Duration() + time.Second)
	if !m.Alive("s1") {
		t.Fatal("Alive(s1) = false past session_ttl on an empty session, want true — " +
			"an empty session is governed by session_resume_window, not session_ttl")
	}
	if _, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP}); err != nil {
		t.Fatalf("CreateUA past session_ttl on an empty-but-resumable session: %v, want ok", err)
	}
}
