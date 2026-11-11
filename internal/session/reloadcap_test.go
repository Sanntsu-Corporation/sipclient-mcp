package session

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// newReloadManager builds a Manager over a REAL FILE-BACKED policy Store with
// the reload hook wired exactly as cmd/sipclient-mcpd wires it.
//
// A file-backed store is not a detail here, it is the whole point:
// NewStaticStore's Reload ALWAYS FAILS by design, so a §12.2.1 acceptance
// driven through a static store would assert against a reload that never
// happened.
func newReloadManager(t *testing.T, capS int) (*Manager, *policy.Store, *fakeclock.Clock, string) {
	t.Helper()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("bearer-token-value\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	path := filepath.Join(dir, "policy.yaml")
	writeCap := func(s int) {
		body := fmt.Sprintf("auth:\n  bearer_token_file: %s\nlimits:\n  max_call_duration_s: %d\n", tokenPath, s)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write policy: %v", err)
		}
	}
	writeCap(capS)

	fc := newFakeClock()
	store, err := policy.NewStore(path, fc, testLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx:    ctx,
		Clock:  fc,
		Policy: store,
		Logger: testLogger(),
		NewUA:  func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	// THE PRODUCTION WIRING, verbatim from cmd/sipclient-mcpd/run.go. A test
	// that registered some other closure would be proving its own arithmetic
	// again rather than the daemon's behaviour.
	store.SetReloadHook(func(_, next *policy.Policy) { m.RecomputeDurationCaps(next) })
	return m, store, fc, path
}

// answeredCall creates a live answered call in sid and arms its duration cap
// the way CallDial does — through the policy clamp in force right now.
func answeredCall(t *testing.T, m *Manager, sid string) *Call {
	t.Helper()
	ctx := context.Background()
	if err := m.Open(ctx, sid); err != nil {
		t.Fatalf("Open(%q): %v", sid, err)
	}
	ua, err := m.CreateUA(ctx, sid, UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	c, err := m.CreateCall(ctx, sid, ua.Handle(), Outbound, StateAnswered)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}
	if d := m.policy.Current().ClampDuration(0); d > 0 {
		m.StartDurationCap(c, d, func() { m.RecordTermination(c) })
	}
	return c
}

func rewriteCap(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("rewrite policy: %v", err)
	}
}

// capBody rebuilds a policy file body carrying the same bearer token file the
// original had, with a new cap.
func capBody(t *testing.T, path string, capS int) string {
	t.Helper()
	tokenPath := filepath.Join(filepath.Dir(path), "token")
	return fmt.Sprintf("auth:\n  bearer_token_file: %s\nlimits:\n  max_call_duration_s: %d\n", tokenPath, capS)
}

// TestReloadLoweredCapTerminatesTheOverCapCallAndReschedulesTheOther is
// §12.2.1's WORKED ACCEPTANCE, driven end to end through the real Manager, a
// real file-backed policy.Store and a real Reload.
//
// The spec's own words (§12.2.1): with max_call_duration_s: 300 and two live
// calls at elapsed 30 s and 120 s, editing the file to max_call_duration_s: 60
// and sending SIGHUP force-terminates the 120 s call at once with a
// policy_timeout event, while the 30 s call survives and is terminated at
// elapsed 60 s.
//
// WHY THIS TEST REPLACED THE OLD ONE. internal/policy's
// reload_acceptance_test.go declared its OWN liveCall struct and its OWN
// recomputeDeadlines helper and then asserted that helper's arithmetic. Its
// subject was not the shipped object: SetReloadHook, CallDeadline and
// EarlierDeadline had ZERO production callers, the daemon's SIGHUP handler
// called only store.Reload(), and the cap was armed once at dial time from a
// snapshot and never re-evaluated. The old test passed throughout. Everything
// below goes through the code the daemon actually runs.
func TestReloadLoweredCapTerminatesTheOverCapCallAndReschedulesTheOther(t *testing.T) {
	m, store, fc, path := newReloadManager(t, 300)

	older := answeredCall(t, m, "s1") // starts now
	fc.Advance(90 * time.Second)
	newer := answeredCall(t, m, "s2") // starts at +90 s
	fc.Advance(30 * time.Second)      // now = +120 s

	// Elapsed: older 120 s, newer 30 s. Both live under the 300 s cap.
	if got := older.State(); got != StateAnswered {
		t.Fatalf("older state before the reload = %q, want %q", got, StateAnswered)
	}
	if got := newer.State(); got != StateAnswered {
		t.Fatalf("newer state before the reload = %q, want %q", got, StateAnswered)
	}

	rewriteCap(t, path, capBody(t, path, 60))
	if err := store.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// 1. The 120 s call is already past the new 60 s cap: force-terminated AT
	//    ONCE, with no clock advance at all. The spec's acceptance allows 1 s;
	//    the hook is synchronous, so by the time Reload returns it is done.
	if got := older.State(); got != StateTerminated {
		t.Errorf("the elapsed-120s call is %q after a reload lowering the cap to 60 s, "+
			"want %q: §12.2.1 force-terminates a call already past the new cap at once",
			got, StateTerminated)
	}
	if got := older.TerminationReason(); got != "policy_timeout" {
		t.Errorf("older termination_reason = %q, want %q — a reload-triggered "+
			"termination must be indistinguishable from a timer-triggered one",
			got, "policy_timeout")
	}
	if !hasEvent(older, EventPolicyTimeout) {
		t.Error("the force-terminated call logged no policy_timeout event (§10.5)")
	}
	// INV-1: RecordTermination followed the claim, so the §12.2.2 concurrency
	// slot is freed IMMEDIATELY rather than at the next janitor pass.
	if perSession, total := m.DebugLiveCallCounts("s1"); perSession != 0 || total != 1 {
		t.Errorf("live call counts after the force-termination = (%d, %d), want (0, 1) "+
			"— s1's over-cap call recorded, s2's survivor still live: "+
			"RecordTermination did not follow the terminal claim (INV-1)", perSession, total)
	}

	// 2. The 30 s call SURVIVES the same reload — untouched.
	if got := newer.State(); got != StateAnswered {
		t.Fatalf("the elapsed-30s call is %q, want %q: it is under the new cap and "+
			"must not be terminated", got, StateAnswered)
	}

	// 3. And it is rescheduled to its OWN elapsed 60 s — start+90+60 = +150 s.
	//    One second short: still live. This is what proves the survivor was
	//    re-armed rather than merely spared; without the re-arm it would run
	//    to the ORIGINAL 300 s deadline and this advance would find it live at
	//    +150 s and still live long after.
	fc.Advance(29 * time.Second) // now = +149 s
	if got := newer.State(); got != StateAnswered {
		t.Fatalf("the survivor died at +149s (%q); its recomputed deadline is +150s", got)
	}
	fc.Advance(time.Second) // now = +150 s == the survivor's elapsed 60 s
	waitForState(t, newer, StateTerminated)
	if got := newer.TerminationReason(); got != "policy_timeout" {
		t.Errorf("survivor termination_reason = %q, want %q", got, "policy_timeout")
	}
}

// TestReloadRaisedCapNeverExtendsALiveCall is §12.2.1's other half: "Raising
// the cap back to 300 s by a second SIGHUP does not extend any call already
// live."
//
// It also pins the ratchet's second job — a raising reload must arm NO new cap
// goroutine. Without tightenCapDeadline's bool, every SIGHUP would add one
// timer per live call, and a daemon reloaded repeatedly would accumulate them.
func TestReloadRaisedCapNeverExtendsALiveCall(t *testing.T) {
	m, store, fc, path := newReloadManager(t, 60)

	c := answeredCall(t, m, "s1")
	fc.BlockUntil(1)
	armed := m.DurationCapGoroutinesForTest()
	if armed != 1 {
		t.Fatalf("armed cap goroutines = %d, want 1", armed)
	}

	fc.Advance(10 * time.Second)
	rewriteCap(t, path, capBody(t, path, 300))
	if err := store.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if got := m.DurationCapGoroutinesForTest(); got != armed {
		t.Errorf("armed cap goroutines = %d after a RAISING reload, want %d unchanged: "+
			"a raised cap must not re-arm anything", got, armed)
	}

	// The call still dies at its ORIGINAL 60 s deadline, not at 300 s.
	fc.Advance(49 * time.Second) // now = +59 s
	if got := c.State(); got != StateAnswered {
		t.Fatalf("state at +59s = %q, want %q", got, StateAnswered)
	}
	fc.Advance(time.Second) // now = +60 s, the original deadline
	waitForState(t, c, StateTerminated)
	if got := c.TerminationReason(); got != "policy_timeout" {
		t.Errorf("termination_reason = %q, want %q — the raised cap extended the call",
			got, "policy_timeout")
	}
}

// TestFailedReloadLeavesArmedCapsUntouched: a malformed policy file swaps
// nothing and fires no hook, so no live call may be re-evaluated against it.
func TestFailedReloadLeavesArmedCapsUntouched(t *testing.T) {
	m, store, fc, path := newReloadManager(t, 300)

	c := answeredCall(t, m, "s1")
	fc.BlockUntil(1)
	fc.Advance(120 * time.Second)

	// Malformed regex: Load fails, the previous policy stays in force.
	tokenPath := filepath.Join(filepath.Dir(path), "token")
	rewriteCap(t, path, fmt.Sprintf(
		"auth:\n  bearer_token_file: %s\nlimits:\n  max_call_duration_s: 60\ndestinations:\n  deny: ['^sip:[0-9']\n",
		tokenPath))
	if err := store.Reload(); err == nil {
		t.Fatal("want the malformed-regex reload to fail, got nil")
	}

	// The 60 s cap in that file must NOT have reached this elapsed-120s call.
	if got := c.State(); got != StateAnswered {
		t.Errorf("state after a FAILED reload = %q, want %q: a reload that swapped "+
			"nothing must apply nothing", got, StateAnswered)
	}
}

// hasEvent reports whether the call's §10.5 event log carries an event of the
// given type.
func hasEvent(c *Call, want EventType) bool {
	evs, _, _ := c.Events(0)
	for _, e := range evs {
		if e.Type == want {
			return true
		}
	}
	return false
}
