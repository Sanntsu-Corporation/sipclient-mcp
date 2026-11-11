// internal/sipua/refresher_test.go
package sipua

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// TestBackoffDelayDoublesAndClampsAtCap pins backoff.delay directly, because
// no timing test can. Every consumer test advances the fake clock by MORE than
// the delay it is waiting on (2s against a 2s/4s schedule in refresher_test,
// 30s against the same schedule in register_refresh_test) and then asserts a
// `>=` count — and fakeclock.Advance fires every waiter it crosses, so an early
// fire is indistinguishable from an on-time one. Correct and incorrect answers
// differ only on an advance strictly BETWEEN two delays, which no test makes.
//
// Mutation-proven: replacing delay's whole body with `return b.Base` — no
// exponential growth, no Cap clamp at all — left the entire internal/sipua
// package green. Cap in particular was never reached by any consumer, since
// backoff{Attempts: 3} only ever calls delay(1) and delay(2).
//
// BASE IS 3s AND NOT A DIVISOR OF Cap, DELIBERATELY. With the powers-of-two
// fixture this test shipped with (Base 2s, Cap 8s) the growth loop's own
// `d < b.Cap` guard stopped at exactly 8s, so `if b.Cap > 0 && d > b.Cap` was
// never the binding constraint and the rows below were produced by the growth
// guard rather than the clamp this test is named for — measured: deleting the
// clamp alone left internal/sipua green. 3s doubles to 12s at n=3, which only
// the clamp can bring back to 8s.
func TestBackoffDelayDoublesAndClampsAtCap(t *testing.T) {
	b := backoff{Base: 3 * time.Second, Cap: 8 * time.Second}
	for n, want := range map[int]time.Duration{
		1: 3 * time.Second,
		2: 6 * time.Second,
		3: 8 * time.Second, // 12s, clamped
		4: 8 * time.Second, // still clamped
		9: 8 * time.Second, // still clamped
	} {
		if got := b.delay(n); got != want {
			t.Errorf("delay(%d) = %v, want %v", n, got, want)
		}
	}
	// Recorded, not asserted as desirable: because the growth loop's guard is
	// `d < b.Cap`, a backoff with Cap UNSET never grows at all — delay(n) is
	// Base for every n. Both production consumers (register.go, sessiontimer.go)
	// set a Cap, so no caller is affected; this line exists so the next reader
	// discovers the coupling here rather than in a stalled retry loop.
	if got := (backoff{Base: time.Second}).delay(4); got != time.Second {
		t.Errorf("delay(4) with Cap unset = %v, want 1s (no Cap => no growth)", got)
	}
}

func TestRefresherFiresAtTheConfiguredFraction(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	var fired atomic.Int64
	r := newRefresher(clk, slog.Default(), refreshPolicy{
		Name: "register", Fraction: 0.5, Initial: 100 * time.Second,
		Do: func(context.Context) (int, error) { fired.Add(1); return 0, nil },
	})
	r.Start(context.Background())
	defer r.Stop()

	clk.BlockUntil(1)
	clk.Advance(49 * time.Second)
	if fired.Load() != 0 {
		t.Fatal("fired before 50% of the interval")
	}
	clk.Advance(2 * time.Second)
	waitForAtomic(t, &fired, 1)
}

func TestRefresherRebasesOnTheGrantedInterval(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	var fired atomic.Int64
	r := newRefresher(clk, slog.Default(), refreshPolicy{
		Name: "register", Fraction: 0.5, Initial: 100 * time.Second,
		Do: func(context.Context) (int, error) {
			// The registrar grants a SHORTER expiry than we asked for; the next
			// fire must be at 50% of 20s, not of 100s (D24's whole point).
			fired.Add(1)
			return 20, nil
		},
	})
	r.Start(context.Background())
	defer r.Stop()

	clk.BlockUntil(1)
	clk.Advance(50 * time.Second)
	waitForAtomic(t, &fired, 1)
	clk.BlockUntil(1)
	clk.Advance(9 * time.Second)
	if fired.Load() != 1 {
		t.Fatal("fired before 50% of the newly GRANTED 20s")
	}
	clk.Advance(2 * time.Second)
	waitForAtomic(t, &fired, 2)
}

func TestRefresherRetriesWithBackoffThenGivesUp(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	var attempts atomic.Int64
	gaveUp := make(chan error, 1)
	r := newRefresher(clk, slog.Default(), refreshPolicy{
		Name: "register", Fraction: 1.0, Initial: 10 * time.Second,
		Do: func(context.Context) (int, error) {
			attempts.Add(1)
			return 0, errors.New("registrar unreachable")
		},
		Retry:    backoff{Attempts: 3, Base: time.Second, Cap: 4 * time.Second},
		OnGiveUp: func(err error) { gaveUp <- err },
	})
	r.Start(context.Background())
	defer r.Stop()

	clk.BlockUntil(1)
	clk.Advance(10 * time.Second) // first attempt
	waitForAtomic(t, &attempts, 1)
	clk.BlockUntil(1)
	clk.Advance(time.Second) // retry 1 at base
	waitForAtomic(t, &attempts, 2)
	clk.BlockUntil(1)
	clk.Advance(2 * time.Second) // retry 2 at 2x base
	waitForAtomic(t, &attempts, 3)

	select {
	case err := <-gaveUp:
		if err == nil {
			t.Fatal("OnGiveUp must receive the last error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnGiveUp never fired after the attempt cap")
	}
}

// TestAttemptShortCircuitsWhenDoWrapsErrRefresherStopped is C4's acceptance
// criterion: a Do error that ALREADY wraps errRefresherStopped (e.g.
// refreshRegister's opening guard, or registrationRemoved after a clean
// de-registration) must not be retried — attempt used to spend the whole
// backoff schedule on it anyway, logging a stale "retrying" WARN per
// remaining attempt.
//
// attempt() is called DIRECTLY, not through Start/a live refresher goroutine,
// and the fake clock is never advanced: without the early-exit, attempt would
// block forever on r.clk.NewTimer's backoff wait between attempt 1 and 2 (no
// Advance ever arrives to fire it), so the completion channel below times out
// — proving the fix's absence as a genuine backoff wait, not merely a slower
// pass.
func TestAttemptShortCircuitsWhenDoWrapsErrRefresherStopped(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	var calls atomic.Int64
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	wrapped := fmt.Errorf("refresh: %w", errRefresherStopped)

	r := newRefresher(clk, log, refreshPolicy{
		Name: "register", Fraction: 1.0, Initial: 10 * time.Second,
		Do: func(context.Context) (int, error) {
			calls.Add(1)
			return 0, wrapped
		},
		Retry: backoff{Attempts: 3, Base: time.Second, Cap: 4 * time.Second},
	})

	done := make(chan struct {
		granted int
		err     error
	}, 1)
	go func() {
		granted, err := r.attempt(context.Background())
		done <- struct {
			granted int
			err     error
		}{granted, err}
	}()

	select {
	case res := <-done:
		if !errors.Is(res.err, errRefresherStopped) {
			t.Fatalf("attempt() err=%v, want errRefresherStopped", res.err)
		}
		if res.granted != 0 {
			t.Fatalf("attempt() granted=%d, want 0", res.granted)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("attempt() blocked on a backoff wait for a Do error that already wraps " +
			"errRefresherStopped — the fake clock was never advanced, so only a real " +
			"(unwanted) retry wait explains a timeout here")
	}

	if calls.Load() != 1 {
		t.Fatalf("Do called %d times, want exactly 1 (no retry once Do itself reports a clean stop)",
			calls.Load())
	}
	if strings.Contains(logBuf.String(), "retrying") {
		t.Fatalf("attempt logged a %q WARN for a Do error that already wraps errRefresherStopped: %s",
			"retrying", logBuf.String())
	}
}

// TestStopDuringRetryDoesNotFireOnGiveUp pins the difference between an
// INTENTIONAL shutdown and genuine exhaustion. Do fails, the refresher parks in
// its backoff wait, and Stop() is called from outside — the ordinary UA-teardown
// and Unregister shape. OnGiveUp must NOT fire: for the register consumer it
// would emit UAEventRegisterFailed and mark the UA unregistered in the middle of
// a clean shutdown, reporting a registration failure that never happened.
func TestStopDuringRetryDoesNotFireOnGiveUp(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	var attempts atomic.Int64
	gaveUp := make(chan error, 1)
	r := newRefresher(clk, slog.Default(), refreshPolicy{
		Name: "register", Fraction: 1.0, Initial: 10 * time.Second,
		Do: func(context.Context) (int, error) {
			attempts.Add(1)
			return 0, errors.New("registrar unreachable")
		},
		// A GENEROUS budget: the point is that Stop cuts the retries short, so the
		// cap must not be reachable within the test.
		Retry:    backoff{Attempts: 10, Base: time.Minute, Cap: time.Minute},
		OnGiveUp: func(err error) { gaveUp <- err },
	})
	r.Start(context.Background())

	clk.BlockUntil(1)
	clk.Advance(10 * time.Second) // first attempt, which fails
	waitForAtomic(t, &attempts, 1)
	clk.BlockUntil(1) // now parked in the backoff wait

	r.Stop()

	select {
	case err := <-gaveUp:
		t.Fatalf("OnGiveUp fired on an intentional Stop (err=%v); it must fire ONLY when "+
			"every attempt in the configured budget was genuinely exhausted", err)
	default:
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts=%d want 1 — Stop must abort the retry, not run the budget out", got)
	}
}

// TestContextCancelDuringRetryDoesNotFireOnGiveUp is the same property for the
// other quiet path: the OWNER's lifetime ended (UA Close, daemon ctx cancelled),
// which is not a peer failure and must not be escalated as one. It passes because
// attempt's ctx.Done() arm WRAPS errRefresherStopped rather than returning
// ctx.Err() bare — quietStop reads nothing but the error, so a cancellation that
// is not visible in the error is not visible at all.
func TestContextCancelDuringRetryDoesNotFireOnGiveUp(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	ctx, cancel := context.WithCancel(context.Background())
	var attempts atomic.Int64
	gaveUp := make(chan error, 1)
	r := newRefresher(clk, slog.Default(), refreshPolicy{
		Name: "register", Fraction: 1.0, Initial: 10 * time.Second,
		Do: func(context.Context) (int, error) {
			attempts.Add(1)
			return 0, errors.New("registrar unreachable")
		},
		Retry:    backoff{Attempts: 10, Base: time.Minute, Cap: time.Minute},
		OnGiveUp: func(err error) { gaveUp <- err },
	})
	r.Start(ctx)
	defer r.Stop()

	clk.BlockUntil(1)
	clk.Advance(10 * time.Second)
	waitForAtomic(t, &attempts, 1)
	clk.BlockUntil(1)
	cancel()
	time.Sleep(50 * time.Millisecond)

	select {
	case err := <-gaveUp:
		t.Fatalf("OnGiveUp fired on ctx cancellation (err=%v)", err)
	default:
	}
}

// TestGenuineFinalFailureEscalatesEvenWhenAShutdownRacesTheClassification is the
// REGRESSION PIN for the mis-classification that a live-state recheck in quietStop
// used to cause — the inverse, and worse, form of the bug the two tests above
// cover. There, a shutdown was reported as a failure. Here, a real FAILURE was
// reported as a shutdown and vanished entirely.
//
// THE SHAPE. attempt's final attempt has no select: it returns the genuine error
// from the last real Do call. If quietStop then re-derived "was this a shutdown?"
// from live state — ctx.Err() != nil, or a select on r.stop — an unrelated teardown
// landing in the window between Do returning and Start classifying would make that
// genuine error look quiet. OnGiveUp never fires; for the register consumer a real
// registrar rejection is silently swallowed during what looks like a clean close.
//
// IT IS DETERMINISTIC, NOT TIMING-DEPENDENT. Do blocks on a channel immediately
// before returning its final error, so the test controls the ordering exactly: the
// shutdown is made to happen FIRST and Do only then hands back the genuine error,
// which is the worst case for classification. No sleeps, no fake-clock advance
// races. Under the correct design the shutdown is invisible to the classifier,
// because attempt tagged nothing — the error came from Do.
func TestGenuineFinalFailureEscalatesEvenWhenAShutdownRacesTheClassification(t *testing.T) {
	realErr := errors.New("registrar rejected the refresh: 403 Forbidden")

	// newBlockingFailure builds a refresher whose SINGLE (therefore final) attempt
	// fails with realErr, but not until the test releases it.
	newBlockingFailure := func(inDo, release chan struct{}, gaveUp chan error,
		clk *fakeclock.Clock) *refresher {
		return newRefresher(clk, slog.Default(), refreshPolicy{
			Name: "register", Fraction: 1.0, Initial: 10 * time.Second,
			Do: func(context.Context) (int, error) {
				close(inDo)
				<-release // the shutdown is arranged HERE, before we have returned
				return 0, realErr
			},
			// Attempts 1 => this IS the final attempt, so attempt() returns realErr
			// straight out of the loop with no intervening select to tag it.
			Retry:    backoff{Attempts: 1},
			OnGiveUp: func(err error) { gaveUp <- err },
		})
	}

	assertEscalated := func(t *testing.T, gaveUp chan error) {
		t.Helper()
		select {
		case err := <-gaveUp:
			if !errors.Is(err, realErr) {
				t.Fatalf("OnGiveUp err=%v, want the genuine %v", err, realErr)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("a GENUINE final-attempt failure was SWALLOWED because a shutdown " +
				"arrived before Start could classify it. Classification must depend only " +
				"on the error's own identity (errors.Is(err, errRefresherStopped)) — never " +
				"on a live read of ctx.Err() or r.stop, which describe when the teardown " +
				"happened and not what caused the error")
		}
	}

	t.Run("Stop lands after Do produced the error", func(t *testing.T) {
		clk := fakeclock.New(time.Unix(0, 0))
		inDo, release := make(chan struct{}), make(chan struct{})
		gaveUp := make(chan error, 1)
		r := newBlockingFailure(inDo, release, gaveUp, clk)
		r.Start(context.Background())
		clk.BlockUntil(1)
		clk.Advance(10 * time.Second)
		<-inDo

		// Stop blocks on the refresher goroutine, so it runs concurrently — but it
		// closes r.stop SYNCHRONOUSLY, and waitForStopClosed below observes that
		// before Do is released. The ordering is therefore fixed, not raced:
		// r.stop closed -> Do returns realErr -> Start classifies.
		stopped := make(chan struct{})
		go func() { r.Stop(); close(stopped) }()
		waitForStopClosed(t, r)
		close(release)

		assertEscalated(t, gaveUp)
		<-stopped
	})

	t.Run("ctx cancellation lands after Do produced the error", func(t *testing.T) {
		clk := fakeclock.New(time.Unix(0, 0))
		ctx, cancel := context.WithCancel(context.Background())
		inDo, release := make(chan struct{}), make(chan struct{})
		gaveUp := make(chan error, 1)
		r := newBlockingFailure(inDo, release, gaveUp, clk)
		r.Start(ctx)
		defer r.Stop()
		clk.BlockUntil(1)
		clk.Advance(10 * time.Second)
		<-inDo

		// cancel() is synchronous: ctx.Err() is non-nil the moment it returns, and
		// only THEN does Do hand back its genuine error. Fully deterministic.
		cancel()
		close(release)

		assertEscalated(t, gaveUp)
	})
}

// waitForStopClosed blocks until Stop has closed r.stop. It is not a timing
// tolerance — it is the ORDERING POINT the test above needs: once it returns, the
// shutdown has definitively happened, so releasing Do afterwards reproduces the
// race scenario every run rather than occasionally. Receiving from a closed
// channel consumes nothing, so this does not disturb the refresher.
func waitForStopClosed(t *testing.T, r *refresher) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-r.stop:
			return
		default:
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Stop never closed the stop channel")
}

// TestStopFromInsideDoPanicsRatherThanDeadlocking pins the reentrancy guard.
// Stop() waits on the goroutine Do runs on, so calling it from inside Do is a
// self-join deadlock — a hang with no failing assertion, which is how this exact
// bug survived a review pass once already. The guard converts it into an
// immediate, located panic, matching this codebase's fail-fast convention for
// internal misuse (fakeclock, netfault, metrics all panic this way).
//
// Production code NEVER does this: a callback that must end its own dialog goes
// through Task 29's runOffRefresherGoroutine.
func TestStopFromInsideDoPanicsRatherThanDeadlocking(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	panicked := make(chan any, 1)
	var r *refresher
	r = newRefresher(clk, slog.Default(), refreshPolicy{
		Name: "session_timer", Fraction: 1.0, Initial: 10 * time.Second,
		Do: func(context.Context) (int, error) {
			defer func() { panicked <- recover() }()
			r.Stop() // THE BUG, committed on purpose
			return 0, nil
		},
	})
	// A-M3 (D20): this test used context.Background() with no cancel and no
	// external Stop(), so its refresher goroutine outlived the test — a leak that
	// only did not matter because the process exits. It asserts a PANIC path, so
	// the goroutine cannot be stopped from inside do(); an external cancel via
	// t.Cleanup is the one mechanism that reaches it.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r.Start(ctx)
	clk.BlockUntil(1)
	clk.Advance(10 * time.Second)

	select {
	case p := <-panicked:
		if p == nil {
			t.Fatal("Stop() from inside Do returned instead of panicking — the next such " +
				"regression will deadlock silently instead of failing a test")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() from inside Do neither panicked nor returned: it self-joined")
	}
}

// TestStopFromAnotherGoroutineStillBlocks is the guard's other half: the
// reentrancy check must not have weakened Stop for EXTERNAL callers, whose
// blocking wait is what Tasks 25 and 26 rely on to guarantee no timer fires a
// REGISTER or an OPTIONS onto a transport that is closing.
func TestStopFromAnotherGoroutineStillBlocks(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	inDo := make(chan struct{})
	release := make(chan struct{})
	r := newRefresher(clk, slog.Default(), refreshPolicy{
		Name: "keepalive", Fraction: 1.0, Initial: 10 * time.Second,
		Do: func(context.Context) (int, error) {
			close(inDo)
			<-release
			return 0, nil
		},
	})
	r.Start(context.Background())
	clk.BlockUntil(1)
	clk.Advance(10 * time.Second)
	<-inDo

	stopped := make(chan struct{})
	go func() { r.Stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Stop returned while Do was still running; its blocking contract is load-bearing")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop never returned after Do completed")
	}
}

func TestRefresherStopIsIdempotentAndLeaksNoGoroutine(t *testing.T) {
	before := runtime.NumGoroutine()
	clk := fakeclock.New(time.Unix(0, 0))
	r := newRefresher(clk, slog.Default(), refreshPolicy{
		Name: "keepalive", Fraction: 1.0, Initial: 30 * time.Second,
		Do: func(context.Context) (int, error) { return 0, nil },
	})
	r.Start(context.Background())
	clk.BlockUntil(1)
	r.Stop()
	r.Stop() // idempotent
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > before {
		t.Fatalf("goroutines: %d -> %d; the refresher leaked one", before, got)
	}
}

func TestRefresherStopsWithTheContext(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	ctx, cancel := context.WithCancel(context.Background())
	var fired atomic.Int64
	r := newRefresher(clk, slog.Default(), refreshPolicy{
		Name: "keepalive", Fraction: 1.0, Initial: 10 * time.Second,
		Do: func(context.Context) (int, error) { fired.Add(1); return 0, nil },
	})
	r.Start(ctx)
	defer r.Stop()
	clk.BlockUntil(1)
	cancel()
	time.Sleep(50 * time.Millisecond)
	clk.Advance(20 * time.Second)
	time.Sleep(50 * time.Millisecond)
	if fired.Load() != 0 {
		t.Fatal("a cancelled context must stop the refresher")
	}
}

func TestNextAtReportsTheUpcomingFire(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	r := newRefresher(clk, slog.Default(), refreshPolicy{
		Name: "register", Fraction: 0.5, Initial: 100 * time.Second,
		Do: func(context.Context) (int, error) { return 0, nil },
	})
	r.Start(context.Background())
	defer r.Stop()
	clk.BlockUntil(1)
	if got := r.NextAt(); !got.Equal(time.Unix(50, 0)) {
		t.Fatalf("NextAt=%v want %v", got, time.Unix(50, 0))
	}
}

// waitForAtomic polls until the counter reaches want, or fails.
func waitForAtomic(t *testing.T, v *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if v.Load() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("counter reached %d, want %d", v.Load(), want)
}
