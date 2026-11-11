package loopback_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// TestClientDisconnectDeregistersWaiter is §10.5's cancellation acceptance
// asserted against a TRANSPORT-LEVEL abort, which is the only form of it that
// discriminates.
//
// Why transport-level: the go-sdk wraps the jsonrpc2 connection context in
// notDone{} (go-sdk@v1.6.1/internal/jsonrpc2/conn.go:198), whose Done()
// returns nil and whose Err() returns nil. Every in-flight request context is
// derived from that dead parent, so nothing the HTTP layer does can cancel a
// handler; the ONE channel the SDK honours is conn.Cancel(id), driven by the
// notifications/cancelled preempter (go-sdk mcp/transport.go:215). A test that
// merely cancels a Go MCP-client context makes that client EMIT
// notifications/cancelled, which releases the waiter even on the broken
// server — so such a test passes against the defect and proves nothing.
//
// Cancelling the *http.Request context instead makes net/http tear down the
// POST itself, so the server sees a bare disconnect with no notification. That
// is the case §6.3 rule 4 promises ("client disconnect ... removed from the
// call's waiter set immediately") and the case that leaked.
func TestClientDisconnectDeregistersWaiter(t *testing.T) {
	h := loopback.New(t)
	defer h.Close()
	c := h.MustDialAnswered(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		// 300000ms: a leaked waiter parks for five minutes rather than being
		// masked by a short timeout expiring on its own.
		h.CallWaitCtx(ctx, c, "terminated", 300000)
	}()
	h.WaitForWaiterCount(t, c, 1, 5*time.Second)

	cancel()
	h.WaitForWaiterCount(t, c, 0, 3*time.Second)
	if n := h.SessionWaiterCount(); n != 0 {
		t.Fatalf("session waiter count after client disconnect = %d, want 0 "+
			"(§6.3 rule 5 releases BOTH accounts)", n)
	}
	<-done
}

func TestWaiterBounds(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]any
		run       func(*testing.T, *loopback.Harness, string)
	}{
		{
			name:      "max_wait_timeout_ms rejected not clamped",
			overrides: map[string]any{"limits.max_wait_timeout_ms": 5000},
			run: func(t *testing.T, h *loopback.Harness, c string) {
				res := h.CallWait(c, "answered", 5001)
				if loopback.ErrorCodeOf(res) != "resource_limit" {
					t.Fatalf("code = %q, want resource_limit", loopback.ErrorCodeOf(res))
				}
				if loopback.ErrorRuleOf(res) != "max_wait_timeout_ms" {
					t.Fatalf("rule = %q, want max_wait_timeout_ms", loopback.ErrorRuleOf(res))
				}
				// A rejected wait consumes nothing (§10.5).
				if n := h.WaiterCount(c); n != 0 {
					t.Fatalf("call waiter count = %d, want 0", n)
				}
				if n := h.SessionWaiterCount(); n != 0 {
					t.Fatalf("session waiter count = %d, want 0", n)
				}
				if got := h.CallWait(c, "terminated", 5000); loopback.ErrorCodeOf(got) == "resource_limit" {
					t.Fatal("timeout_ms exactly at the cap was rejected; the cap is inclusive")
				}
			},
		},
		{
			name:      "max_waiters_per_call",
			overrides: map[string]any{"limits.max_waiters_per_call": 2},
			run: func(t *testing.T, h *loopback.Harness, c string) {
				for i := 0; i < 2; i++ {
					go h.CallWait(c, "terminated", 5000)
				}
				h.WaitForWaiterCount(t, c, 2, time.Second)
				res := h.CallWait(c, "terminated", 5000)
				if loopback.ErrorRuleOf(res) != "max_waiters_per_call" {
					t.Fatalf("third concurrent wait rule = %q, want max_waiters_per_call",
						loopback.ErrorRuleOf(res))
				}
				h.MustHangup(t, c)
			},
		},
		{
			name:      "max_waiters_per_session across different calls",
			overrides: map[string]any{"limits.max_waiters_per_session": 3},
			run:       runSessionWaiterCapAcrossCalls, // 3 calls, 1 waiter each, 4th denied
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := loopback.New(t, loopback.WithPolicyOverrides(tt.overrides))
			defer h.Close()
			tt.run(t, h, h.MustDialAnswered(t))
		})
	}
}

// Rule 5's stated bound, asserted on the SETTLED excess (the cap plus one
// call's max_waiters_per_call) — the quantity an acceptance criterion may use.
// The transient overshoot "by the number of racing callers" is deliberately
// NOT asserted: it lasts only until the losers unwind.
func TestSessionCapOvershootIsBounded(t *testing.T) {
	h := loopback.New(t,
		loopback.WithPolicyOverride("limits.max_waiters_per_session", 4),
		loopback.WithPolicyOverride("limits.max_waiters_per_call", 8))
	defer h.Close()

	// Phase 1's STRICT one-UA-per-session model (owner-locked decision): all
	// four calls share ONE UA — the session-wide waiter cap this test
	// exercises is unaffected by how many UAs the calls are spread across.
	ua := h.MustCreateUA(t, "direct")
	calls := make([]string, 4)
	for i := range calls {
		calls[i] = h.MustDialAnsweredOn(t, ua)
	}
	var barrier sync.WaitGroup
	barrier.Add(1)
	results := make(chan loopback.WaitResult, 16)
	for i := 0; i < 16; i++ {
		go func(c string) { barrier.Wait(); results <- h.CallWait(c, "dtmf", 300000) }(calls[i%4])
	}
	barrier.Done()

	time.Sleep(300 * time.Millisecond)
	if total := h.TotalWaiterCount(calls...); total > 4+8 {
		t.Fatalf("registered waiters = %d, want at most 4+8 (rule 5's settled bound)", total)
	}
	for _, c := range calls {
		h.MustHangup(t, c)
	}
	for i := 0; i < 16; i++ {
		got := <-results
		if loopback.ErrorCodeOf(got) == "resource_limit" && loopback.ErrorRuleOf(got) != "max_waiters_per_session" {
			t.Fatalf("rejected waiter rule = %q, want max_waiters_per_session", loopback.ErrorRuleOf(got))
		}
	}
	if n := h.SessionWaiterCount(); n != 0 {
		t.Fatalf("session waiter count after all sixteen returned = %d, want exactly 0", n)
	}
}

// ---- three tests rewritten to the SHIPPED semantics (D377, user decision) --
//
// The plan's original Steps 3-4 expected all three of the following to
// surface as bugs. On inspection each is a defensible, intended property of
// the shipped code, so the code is treated as correct and the tests below
// are written to what it actually does — recording, per test, *why* that is
// the right behaviour rather than only the corrected assertion. A test
// asserting the plan's original expectations would be asserting a server
// defect that does not exist.

// TestUntilAnyMatchesExistingLogEntryWithoutRegistering is D377 point 1.
//
// register (waiter.go:103) matches until:"any" against the FIRST EXISTING
// log entry, not against future events only: by the time MustDialRinging
// returns, the call's log already carries its EventRinging entry — appended
// in the SAME critical section that satisfied MustDialRinging's own wait
// (Call.appendLocked calls signalLocked before returning, waiter.go/call.go)
// — so an until:"any" wait resolves against it IMMEDIATELY and is never
// added to c.waiters. It is an event LOG that matches existing entries, not
// a subscription that only sees the future.
//
// The plan's original TestTerminalStateBroadcastsToEveryWaiter expected all
// four `untils` (including "any") to register, so WaiterCount would reach
// 4; asserting that here fails forever with "observed 3, want 4", because
// "any" never joins the waiter set. This test asserts the three GENUINE
// subscriptions instead, plus "any"'s own immediate, non-timed-out result.
func TestUntilAnyMatchesExistingLogEntryWithoutRegistering(t *testing.T) {
	// AnswerAfter: time.Hour (peer_test.go's own convention for "never fires
	// on its own") — MustDialRinging's doc warns a zero AnswerAfter races the
	// peer's own automatic response; here the call must stay ringing until
	// PeerSendFinal below finalizes it explicitly.
	h := loopback.New(t, loopback.WithPeerBehaviour(
		loopback.PeerBehaviour{AnswerAfter: time.Hour, RejectStatus: 486}))
	defer h.Close()

	c := h.MustDialRinging(t)
	untils := []string{"answered", "dtmf", "terminated", "any"}
	results := make(chan loopback.WaitResult, len(untils))
	for _, until := range untils {
		go func(u string) { results <- h.CallWait(c, u, 300000) }(until)
	}

	// Only the three genuine subscriptions register; "any" resolves off the
	// existing "ringing" log entry and never joins c.waiters.
	h.WaitForWaiterCount(t, c, 3, time.Second)

	start := time.Now()
	h.PeerSendFinal(t, c, 486)
	for range untils {
		res := <-results
		if res.TimedOut {
			t.Fatal("a waiter timed out; rule 2 requires the terminal broadcast to wake all")
		}
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("waiter returned after %v, want within 100ms of the final response", elapsed)
		}
	}
	if n := h.WaiterCount(c); n != 0 {
		t.Fatalf("call waiter count = %d after broadcast, want 0", n)
	}
}

// TestEvictCallForTestNotFoundOnTerminatedCall is D377 point 2.
//
// EvictCallForTest (waiter.go:332) looks the handle up in s.liveCalls ONLY.
// A hung-up call has already left s.liveCalls — MustHangup moves it into
// s.terminatedCalls (janitor.go) — so evicting it this way returns
// not_found, not "gone". This is correct, not a bug: EvictCallForTest is
// the direct registry->call eviction path a LIVE call takes (mirrored by
// Harness.EvictNow, used throughout this suite's races); the path that
// evicts a TERMINATED call's registry entry is the janitor's retention
// sweep, funnelling into evictCallLocked (janitor.go:249). The plan's
// original TestEvictionWhileRegistering raced exactly this — MustDialAnswered,
// MustHangup, then EvictNow(c) — and expected "gone"; EvictNow t.Fatals on
// EvictCallForTest's error, so that test failed at iteration 0. This test
// asserts the real return value directly, without EvictNow's t.Fatal
// wrapper.
func TestEvictCallForTestNotFoundOnTerminatedCall(t *testing.T) {
	h := loopback.New(t)
	defer h.Close()

	sess := h.NewSession(t)
	c := sess.MustDialAnswered(t)
	sess.MustHangup(t, c)

	err := h.Manager().EvictCallForTest(context.Background(), sess.ID(), session.Handle(c))
	if loopback.ErrorCode(err) != "not_found" {
		t.Fatalf("EvictCallForTest on a hung-up call returned code %q, want not_found — "+
			"it is keyed on s.liveCalls, which a hung-up call has already left", loopback.ErrorCode(err))
	}
}

// TestHangupWakesParkedWaiterBeforeEviction is D377 point 3.
//
// call_hangup's own transition to terminated broadcasts to every waiter
// under the call mutex it holds while making the transition (signalLocked,
// waiter.go) — including a waiter parked on "dtmf", a non-terminal until,
// because rule 2 makes a TERMINAL state wake every waiter regardless of its
// until. That broadcast happens synchronously inside MustHangup's own tool
// call, before the call is ever evicted. The plan's original
// TestEvictionWhileParkedReturnsGone expected the SAME setup (park on
// "dtmf", then hang up) to return "gone", as if eviction raced the hangup
// and won; it cannot, because nothing in this test evicts the call at all —
// the parked waiter simply receives the ordinary terminal event. Waking
// waiters before teardown is the intended order.
func TestHangupWakesParkedWaiterBeforeEviction(t *testing.T) {
	h := loopback.New(t)
	defer h.Close()
	c := h.MustDialAnswered(t)

	res := make(chan loopback.WaitResult, 1)
	go func() { res <- h.CallWait(c, "dtmf", 300000) }()
	h.WaitForWaiterCount(t, c, 1, time.Second)

	h.MustHangup(t, c)

	select {
	case got := <-res:
		if loopback.ErrorCodeOf(got) != "" {
			t.Fatalf("parked waiter returned code %q, want \"\" (the ordinary terminal "+
				"event, not gone) — the hangup broadcast wakes it before any eviction runs",
				loopback.ErrorCodeOf(got))
		}
		if got.CallState != "terminated" {
			t.Fatalf("parked waiter's call_state = %q, want terminated", got.CallState)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parked waiter did not return on hangup; rule 2's terminal broadcast must wake it")
	}
}
