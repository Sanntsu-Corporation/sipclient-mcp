// Package fakeclock is a deterministic clock.Clock for tests (locked decision 18).
//
// Time moves only when Advance is called. Advance wakes every waiter whose
// deadline it crosses — including waiters armed before the call — in
// chronological order, delivering each waiter its own deadline instant on its
// channel rather than the advance target. That ordering is what lets a test
// assert on instants (spec §14.2's session_resume_window, §6.5.2's per-frame
// deadlines) instead of on elapsed wall time.
//
// Use BlockUntil to synchronise with code under test before advancing: advancing
// before the code has armed its timer makes the test race the code it is meant to
// drive.
package fakeclock

import (
	"slices"
	"sync"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
)

// Clock is a controllable clock.Clock. The zero value is not usable; call New.
type Clock struct {
	mu      sync.Mutex
	cond    *sync.Cond
	now     time.Time
	waiters []*waiter
}

type waiter struct {
	at      time.Time
	period  time.Duration // zero for a one-shot timer
	ch      chan time.Time
	stopped bool
}

// New returns a Clock reading now, with no waiters.
func New(now time.Time) *Clock {
	c := &Clock{now: now}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// Now returns the fake's current time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// After returns a channel that receives the fake's time once it has been
// advanced past d from the current fake time.
func (c *Clock) After(d time.Duration) <-chan time.Time {
	return c.arm(d, 0).ch
}

// NewTimer returns a Timer that fires once the fake has been advanced past d
// from the current fake time.
func (c *Clock) NewTimer(d time.Duration) clock.Timer {
	return &fakeTimer{c: c, w: c.arm(d, 0)}
}

// NewTicker returns a Ticker that fires every d as the fake is advanced.
func (c *Clock) NewTicker(d time.Duration) clock.Ticker {
	if d <= 0 {
		panic("fakeclock: non-positive interval for NewTicker")
	}
	return &fakeTicker{c: c, w: c.arm(d, d)}
}

// arm registers a waiter due d from the current fake time. The channel is
// buffered by one and sent to without blocking, matching time.Timer/time.Ticker:
// a tick nobody is ready to receive is dropped rather than stalling Advance.
func (c *Clock) arm(d time.Duration, period time.Duration) *waiter {
	c.mu.Lock()
	defer c.mu.Unlock()

	w := &waiter{
		at:     c.now.Add(d),
		period: period,
		ch:     make(chan time.Time, 1),
	}
	c.waiters = append(c.waiters, w)
	c.cond.Broadcast()
	return w
}

// Advance moves the clock forward by d, firing every waiter it crosses in
// deadline order. It returns once every such waiter has been sent its deadline.
func (c *Clock) Advance(d time.Duration) {
	if d < 0 {
		panic("fakeclock: negative Advance")
	}

	c.mu.Lock()
	target := c.now.Add(d)
	c.mu.Unlock()

	for {
		c.mu.Lock()

		var next *waiter
		for _, w := range c.waiters {
			if w.stopped || w.at.After(target) {
				continue
			}
			if next == nil || w.at.Before(next.at) {
				next = w
			}
		}

		if next == nil {
			c.now = target
			c.mu.Unlock()
			return
		}

		// Now() reads this waiter's own deadline while it runs.
		c.now = next.at
		fireAt := next.at
		ch := next.ch

		if next.period > 0 {
			next.at = next.at.Add(next.period)
		} else {
			next.stopped = true
			c.remove(next)
		}
		c.mu.Unlock()

		// Sent outside the lock so a waiter that calls Now() on wake-up cannot
		// deadlock against Advance.
		select {
		case ch <- fireAt:
		default:
		}
	}
}

// BlockUntil blocks until exactly n waiters (timers plus tickers) are registered.
//
// It exists so a test can synchronise with the code under test before advancing:
// an Advance issued before the code has armed its timer crosses a deadline that
// does not yet exist, the timer is then armed against the post-advance time, and
// it never fires. That is a flaky test, not a failing one.
//
// The count is of currently registered waiters, not a cumulative count of every
// waiter ever armed: a ticker counts once for its lifetime and does not
// re-register each time it re-arms after firing, and a fired one-shot timer
// leaves the count (it is removed on fire, same as on Stop).
//
// It blocks forever if the waiter count passes n without ever equalling it, which
// is a genuine mismatch between the test's expectation and the code's behaviour
// and should surface as a test timeout rather than be silently tolerated.
func (c *Clock) BlockUntil(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for len(c.waiters) != n {
		c.cond.Wait()
	}
}

// remove drops w from the waiter list. The caller must hold c.mu.
func (c *Clock) remove(w *waiter) {
	c.waiters = slices.DeleteFunc(c.waiters, func(x *waiter) bool { return x == w })
	c.cond.Broadcast()
}

type fakeTimer struct {
	c *Clock
	w *waiter
}

func (t *fakeTimer) C() <-chan time.Time { return t.w.ch }

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()

	active := !t.w.stopped
	t.w.stopped = true
	t.c.remove(t.w)
	return active
}

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()

	active := !t.w.stopped
	t.w.at = t.c.now.Add(d)
	if t.w.stopped {
		t.w.stopped = false
		t.c.waiters = append(t.c.waiters, t.w)
		t.c.cond.Broadcast()
	}
	return active
}

type fakeTicker struct {
	c *Clock
	w *waiter
}

func (t *fakeTicker) C() <-chan time.Time { return t.w.ch }

func (t *fakeTicker) Stop() {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()

	t.w.stopped = true
	t.c.remove(t.w)
}
