package loopback_test

import (
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// Task 35 (D382, user decision): StartDurationCap (registry.go:411, armed
// from call_dial at toolservice.go:310) spawns ONE GOROUTINE PER DIALED
// CALL. Its select (registry.go:414) has only two cases — cap expiry and
// daemon shutdown — and NO CASE for the call terminating early (hangup,
// reject, a remote BYE, ...), so it parks for the FULL max_call_duration_s
// (default 300s) after the call ends. Probed at that default cap, this
// reads exactly like an unbounded leak — every batch plateaus and never
// drops, whatever the test does to the calls or UAs.
//
// The investigation (progress.md D382) established it is bounded and
// self-draining instead: steady state ≈ call_rate × max_call_duration_s,
// flat across batches at the default cap, and fully drained at a SHORT cap
// — the discriminator that separates "parked" from "leaked". It used
// DurationCapGoroutinesForTest() (registry.go:434), NOT
// runtime.NumGoroutine(), which is polluted by unrelated infrastructure
// (the httptest server, sipgo's transaction workers, listener read loops)
// and is what made the original "returns to baseline" clause untestable in
// 23b.
//
// THE FIX IS DEFERRED TO P2 (user decision), recorded here rather than
// applied: a per-call `chan struct{}` closed in terminateLocked
// (call.go:295) — the one funnel every terminal transition passes through —
// selected on alongside the timer. This does NOT violate locked decision
// 17, which forbids arming the cap off the REQUEST context of the
// call_dial/call_answer that started it; a terminal signal sourced from the
// call's own state machine is not that context.
//
// This file asserts the CURRENT, shipped lifecycle deterministically
// instead of fixing it.

// TestDurationCapGoroutinesTrackLiveCalls is the steady-state half: one
// armed goroutine per dialed call, for as long as the call is up.
func TestDurationCapGoroutinesTrackLiveCalls(t *testing.T) {
	h := loopback.New(t)
	defer h.Close()

	// Phase 1's STRICT one-UA-per-session model (owner-locked decision): ONE
	// UA dials all N calls — the property under test is one goroutine PER
	// LIVE CALL, which is exercised identically whether the calls share a UA
	// or not.
	const n = 3
	ua := h.MustCreateUA(t, "direct")
	for i := 0; i < n; i++ {
		h.MustDialAnsweredOn(t, ua)
	}

	if got := h.Manager().DurationCapGoroutinesForTest(); got != int64(n) {
		t.Fatalf("duration-cap goroutines = %d, want %d (one per dialed call)", got, n)
	}
}

// TestDurationCapGoroutinesDrainAtCapExpiry is the short-cap half. With
// limits.max_call_duration_s overridden down to 5s, the fake clock COMPOSES
// with the duration cap cleanly: StartDurationCap arms its timer off
// m.clk.NewTimer (registry.go), the harness's own fake clock, so
// h.Clock().Advance fires every armed timer directly — fakeclock.Advance
// sends each waiter its deadline as it crosses it (fakeclock.go) — and
// StartDurationCap's goroutine does the rest: TryTerminate, then its
// deferred capGoroutines.Add(-1). No janitor sweep is needed here, unlike
// TripDurationCap's per-call termination check: DurationCapGoroutinesForTest
// reads the counter the goroutine itself decrements on exit, not
// registry/call state.
//
// The wait below POLLS rather than asserting immediately after Advance:
// Advance only guarantees the channel send: it does not wait for the
// consuming goroutine's select to run and its defer to fire.
func TestDurationCapGoroutinesDrainAtCapExpiry(t *testing.T) {
	h := loopback.New(t,
		loopback.WithFakeClock(),
		loopback.WithPolicyOverride("limits.max_call_duration_s", 5))
	defer h.Close()

	// Phase 1's STRICT one-UA-per-session model (owner-locked decision): ONE
	// UA dials all N calls, exactly as in TestDurationCapGoroutinesTrackLiveCalls.
	const n = 3
	ua := h.MustCreateUA(t, "direct")
	for i := 0; i < n; i++ {
		h.MustDialAnsweredOn(t, ua)
	}
	if got := h.Manager().DurationCapGoroutinesForTest(); got != int64(n) {
		t.Fatalf("duration-cap goroutines before cap expiry = %d, want %d", got, n)
	}

	h.Clock().Advance(6 * time.Second)

	deadline := time.Now().Add(2 * time.Second)
	for {
		got := h.Manager().DurationCapGoroutinesForTest()
		if got == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("duration-cap goroutines = %d after the cap elapsed, want 0", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
