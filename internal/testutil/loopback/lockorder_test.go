package loopback_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// dialAnsweredWaitMs is a LOCAL, LOAD-TOLERANT substitute for
// (*Session).MustDialAnsweredOn's hardcoded 5000ms `answered` budget — NOT a
// widening of that shared, package-wide default (D345/Rule 19 forbids
// touching it, and it is untouched: MustDialAnsweredOn is not called below).
// call_wait's own timeout_ms is itself the wait mechanism (no busy-loop), so
// a fast answer still returns immediately regardless of this value. Both
// tests already override limits.max_wait_timeout_ms to 300000, so 30000 is
// comfortably inside the policy cap.
const dialAnsweredWaitMs = 30000

// waiterRegisterDeadline: poll deadline only; returns as soon as the count is reached, generous for slow CI runners under -race.
const waiterRegisterDeadline = 15 * time.Second

// mustDialAnswered creates a UA, dials it and waits up to dialAnsweredWaitMs
// for `answered`. The stall this used to retry against was
// internal/sipua's lost-event race between Dial and dialog binding (Task 31,
// commit 9c29e6d): a 200 OK arriving before Dial returned was dropped
// silently because nothing had bound the dialog id to the call yet. That
// race is now closed at its source (session.DialRequest.OnDialogBound, fired
// synchronously before `go u.runDial(d)` — see internal/sipua/call.go and
// internal/session/collaborators.go), so a straightforward dial-and-wait is
// correct again; Rule 9's independent full-stack probe (30,000 dials across
// two runs against the fixed code, 0 stalls) is what re-licenses this.
func mustDialAnswered(t *testing.T, h *loopback.Harness, sess *loopback.Session) (uaHandle, callHandle string) {
	t.Helper()
	ua := sess.MustCreateUA(t, "direct")
	call, err := sess.Dial(ua, h.PeerURI())
	if err != nil {
		t.Fatalf("loopback: call_dial: %v", err)
	}
	res := sess.CallWait(call, "answered", dialAnsweredWaitMs)
	if res.Err != nil {
		t.Fatalf("loopback: dial+answered: %v", res.Err)
	}
	if res.TimedOut {
		t.Fatalf("loopback: dial+answered timed out after %dms", dialAnsweredWaitMs)
	}
	return ua, call
}

// waitForSessionWaiterCount polls sess.WaiterCount() until it reads n or the
// deadline expires. See its one call site's comment for why this exists
// instead of an instantaneous assertion.
func waitForSessionWaiterCount(t *testing.T, sess *loopback.Session, n int64, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		got := sess.WaiterCount()
		if got == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("session waiter count = %d after %s, want %d — rule 5 releases "+
				"the session account on EVERY exit path", got, d, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// THE §6.3 LOCK-ORDER GATE, deliberate half two.
//
// `-race` CANNOT SEE LOCK-ORDER INVERSIONS: it detects data races, and an ABBA
// deadlock has none — every access is correctly held under a lock. So this
// property is held by the review gate
// PLUS this test, and by nothing else.
//
// This test is DETERMINISTIC precisely because a deadlock manifests as the
// per-iteration DEADLINE EXPIRING rather than as a probabilistic missed
// wakeup. That is what makes it a usable gate where -race is blind.
//
// The participants it collides:
//  1. rule 5's waiter decrement, under the CALL mutex, reaching the session
//     waiter counter — an atomic.Int64 LEAF, so it acquires nothing;
//  2. rule 3's janitor eviction, holding the REGISTRY lock and then taking
//     the CALL mutex to set `gone` and broadcast.
func TestMassCancellationConcurrentWithEviction(t *testing.T) {
	const (
		iterations       = 1000
		perIterationWait = 5 * time.Second
	)
	h := loopback.New(t,
		loopback.WithPolicyOverride("limits.max_waiters_per_call", 8),
		loopback.WithPolicyOverride("limits.max_wait_timeout_ms", 300000),
		loopback.WithPolicyOverride("limits.registry_retention", "0s"),
		// limits.max_sessions_total defaults to 1000, exactly this test's
		// `iterations`. limits.session_resume_window (not overridden above,
		// separate from registry_retention) defaults to 1h, so the janitor
		// never ages out the accumulating empty session records within this
		// test's lifetime — all 1000 sequential sessions pile up live in the
		// registry with zero headroom against the cap. Give this harness
		// generous headroom so it stays independent of the admission cap;
		// this test is a pure lock-order regression test and has nothing to
		// do with exercising limits.max_sessions_total.
		loopback.WithPolicyOverride("limits.max_sessions_total", iterations*2))
	defer h.Close()

	waiters := h.PolicyLimits(t).MaxWaitersPerCall

	for i := 0; i < iterations; i++ {
		sess := h.NewSession(t)
		// UA CAPTURED AND EXPLICITLY DESTROYED BELOW (R2, task brief) — NOT
		// sess.MustDialAnswered(t), which discards the ua handle. §12.6 (contract
		// Part 4.5): "a session owning any live UA or call NEVER ages out", and no
		// production code wires an MCP session DELETE to any UA teardown (grepped
		// internal/transport/mcp/ — there is no such hook by design: UA lifecycle
		// is independent of session identity, which is the whole point of "UAs
		// survive connection loss"). sess.Close below therefore does not free this
		// iteration's UA; without an explicit ua_destroy, 1000 iterations leak
		// 1000 UAs against max_uas_total=200 and the run dies at iteration ~200
		// with an unrelated resource_limit error that reads like a lock-order
		// finding but isn't one. mustDialAnswered creates the UA itself (and may
		// retry against a fresh one — see its doc comment), so it returns the
		// handle that actually ended up answered.
		ua, call := mustDialAnswered(t, h, sess)

		// Park exactly limits.max_waiters_per_call waiters on one call.
		type parked struct {
			cancel context.CancelFunc
			result chan loopback.WaitResult
		}
		all := make([]parked, waiters)
		for w := 0; w < waiters; w++ {
			ctx, cancel := context.WithCancel(context.Background())
			res := make(chan loopback.WaitResult, 1)
			all[w] = parked{cancel: cancel, result: res}
			go func() { res <- sess.CallWaitCtx(ctx, call, "dtmf", 300000) }()
		}
		h.WaitForWaiterCount(t, call, waiters, waiterRegisterDeadline)

		// From a common barrier release BOTH:
		//   (a) cancellation of EVERY waiter's request context, and
		//   (b) registry EVICTION of that call.
		var barrier sync.WaitGroup
		barrier.Add(1)
		var released sync.WaitGroup
		released.Add(waiters + 1)
		for _, p := range all {
			go func(cancel context.CancelFunc) {
				defer released.Done()
				barrier.Wait()
				cancel()
			}(p.cancel)
		}
		go func() {
			defer released.Done()
			barrier.Wait()
			h.EvictNow(call) // janitor path: registry lock, then the call mutex
		}()

		done := make(chan struct{})
		go func() { released.Wait(); close(done) }()
		barrier.Done()

		// A deadlock shows up HERE, as the deadline expiring.
		select {
		case <-done:
		case <-time.After(perIterationWait):
			t.Fatalf("iteration %d: did not complete within %v — this is the ABBA "+
				"deadlock between rule 5's waiter decrement under the call mutex and "+
				"rule 3's eviction (registry lock then call mutex). `-race` cannot see "+
				"it; this deadline is the detector. Re-run the lock-order review gate.", i, perIterationWait)
		}

		// Every waiter returned its cancellation error or `gone` — NEVER a timeout.
		for w, p := range all {
			select {
			case got := <-p.result:
				if got.TimedOut {
					t.Fatalf("iteration %d waiter %d timed out; it must return either "+
						"its cancellation error or `gone`", i, w)
				}
				if code := loopback.ErrorCodeOf(got); code != "gone" && !got.Cancelled() {
					t.Fatalf("iteration %d waiter %d returned code %q (cancelled=%v); "+
						"want `gone` or a cancellation error", i, w, code, got.Cancelled())
				}
			case <-time.After(perIterationWait):
				t.Fatalf("iteration %d waiter %d never returned", i, w)
			}
		}

		// Rule 5's dual release: BOTH accounts read zero.
		//
		// POLLED, NOT ASSERTED INSTANTANEOUSLY — deliberately, and not a lock-order
		// concern. Collecting every p.result above proves the CLIENT's HTTP round
		// trip completed; it does not prove the SERVER's defer c.remove(w) has run
		// for every waiter. Canceling the Go http.Client's request context aborts
		// the client-side wait locally (net/http does not wait for a server
		// response — see TestClientDisconnectDeregistersWaiter's own doc comment
		// in internal/testutil/loopback/waiter_acceptance_test.go for the same
		// gap), while the server only notices the severed connection and cancels
		// its own r.Context() slightly afterward. h.WaitForWaiterCount(call, ...)
		// cannot substitute for the call-level read here: evictCallLocked deletes
		// the call from m.calls BEFORE this point in the iteration, so
		// h.WaiterCount(call) already reads 0 trivially regardless of whether any
		// waiter has unwound. The call-level and session-level accounts ARE
		// decremented together, under c.mu, inside (*Call).remove (waiter.go) —
		// so polling the session-level account is the correct and sufficient
		// substitute, and it is bounded by the same perIterationWait deadline
		// every other synchronisation point in this test uses.
		waitForSessionWaiterCount(t, sess, 0, perIterationWait)
		// Explicit teardown (see the ua_create comment above): the call is
		// already evicted, so this only releases the UA's max_uas_total slot.
		sess.MustCallTool(t, "ua_destroy", map[string]any{"ua": ua})
		sess.Close(t)
	}
}

// The THIRD participant of handoff §3d: §12.7's admin DELETE walks the same
// registry -> UA -> call path as the janitor, so it collides with rule 5's
// waiter unwinding on exactly the same ordering.
//
// 200 ITERATIONS AGAINST THE JANITOR CASE'S 1000, AND THAT ASYMMETRY IS
// DELIBERATE. Each iteration here creates a UA, dials a real call, parks eight
// waiters and then drives a real HTTP DELETE through the admin handler, whose
// teardown BYEs the live dialog and waits for the far end — roughly an order of
// magnitude more wall-clock per iteration than the janitor case's in-process
// EvictNow. 1000 iterations would put this single test past an hour under
// `-race` for no additional detection power: the deadline detector below fires
// on the FIRST inverted iteration, so iteration count buys schedule diversity,
// not sensitivity, and 200 already covers it. The 1000-iteration figure is
// reserved for the criteria §15 names at 1000 — the §6.3 conflicting-pair test,
// eviction-while-registering and register-concurrent-with-terminate — none of
// which is this one. If a reviewer wants parity, raise the janitor case rather
// than this one; do NOT lower any of the three §15 names.
func TestMassCancellationConcurrentWithAdminDelete(t *testing.T) {
	const (
		iterations       = 200
		perIterationWait = 5 * time.Second
	)
	h := loopback.New(t,
		loopback.WithAdminToken("admin-secret"),
		loopback.WithPolicyOverride("limits.max_waiters_per_call", 8),
		loopback.WithPolicyOverride("limits.max_wait_timeout_ms", 300000))
	defer h.Close()

	waiters := h.PolicyLimits(t).MaxWaitersPerCall

	for i := 0; i < iterations; i++ {
		sess := h.NewSession(t)
		ua, call := mustDialAnswered(t, h, sess)

		cancels := make([]context.CancelFunc, waiters)
		results := make(chan loopback.WaitResult, waiters)
		for w := 0; w < waiters; w++ {
			ctx, cancel := context.WithCancel(context.Background())
			cancels[w] = cancel
			go func() { results <- sess.CallWaitCtx(ctx, call, "dtmf", 300000) }()
		}
		h.WaitForWaiterCount(t, call, waiters, waiterRegisterDeadline)

		var barrier sync.WaitGroup
		barrier.Add(1)
		var released sync.WaitGroup
		released.Add(waiters + 1)
		for _, cancel := range cancels {
			go func(cancel context.CancelFunc) {
				defer released.Done()
				barrier.Wait()
				cancel()
			}(cancel)
		}
		go func() {
			defer released.Done()
			barrier.Wait()
			_, _ = h.AdminDelete(ua) // registry -> UA -> call, then a BYE wait
		}()

		done := make(chan struct{})
		go func() { released.Wait(); close(done) }()
		barrier.Done()

		select {
		case <-done:
		case <-time.After(perIterationWait):
			t.Fatalf("iteration %d: did not complete within %v — the admin DELETE is "+
				"the THIRD path (handoff §3d) that walks registry -> UA -> call and can "+
				"deadlock against a waiter unwinding under the call mutex", i, perIterationWait)
		}
		for w := 0; w < waiters; w++ {
			got := <-results
			if got.TimedOut {
				t.Fatalf("iteration %d waiter %d timed out", i, w)
			}
		}
		// POLLED, NOT ASSERTED INSTANTANEOUSLY — same gap as the eviction test
		// above (see its comment): collecting every result proves the CLIENT's
		// HTTP round trip completed, not that the SERVER's defer c.remove(w) has
		// run for every waiter. Unlike the eviction test, the admin DELETE here
		// does NOT evict the call from m.calls (destroyUA only claims TryHangup +
		// RecordTermination; eviction is a separate, later janitor pass this test
		// never triggers), so h.WaitForWaiterCount(call, ...) — the existing
		// call-level helper (Rule 16) — IS a valid, live signal here, exactly as
		// TestClientDisconnectDeregistersWaiter uses it. remove() decrements both
		// the call-level and session-level accounts together under c.mu (waiter.go),
		// so once the call-level count settles the session-level read below is
		// correct rather than racy.
		h.WaitForWaiterCount(t, call, 0, perIterationWait)
		if n := sess.WaiterCount(); n != 0 {
			t.Fatalf("iteration %d: session waiter count = %d, want 0", i, n)
		}
		sess.Close(t)
	}
}
