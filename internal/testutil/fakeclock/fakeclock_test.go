package fakeclock_test

import (
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

var epoch = time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)

// The fake must satisfy the production interface, or injection is a fiction.
var _ clock.Clock = (*fakeclock.Clock)(nil)

func recvWithin(t *testing.T, ch <-chan time.Time) (time.Time, bool) {
	t.Helper()
	select {
	case v := <-ch:
		return v, true
	case <-time.After(time.Second):
		return time.Time{}, false
	}
}

func assertNoFire(t *testing.T, ch <-chan time.Time) {
	t.Helper()
	select {
	case v := <-ch:
		t.Fatalf("channel fired unexpectedly at %v", v)
	default:
	}
}

func TestNowStartsAtEpochAndOnlyMovesOnAdvance(t *testing.T) {
	c := fakeclock.New(epoch)

	if got := c.Now(); !got.Equal(epoch) {
		t.Fatalf("Now() = %v, want %v", got, epoch)
	}
	time.Sleep(5 * time.Millisecond)
	if got := c.Now(); !got.Equal(epoch) {
		t.Fatalf("Now() = %v after a real sleep, want %v (the fake must ignore wall time)", got, epoch)
	}

	c.Advance(90 * time.Second)
	if got, want := c.Now(), epoch.Add(90*time.Second); !got.Equal(want) {
		t.Errorf("Now() = %v after Advance, want %v", got, want)
	}
}

// Waiters created BEFORE the advance must be woken by it. This is the property
// §14.2's session_resume_window cases depend on: the timer is armed when the
// session record is created, and the test then jumps past the window.
func TestAdvanceWakesTimersCreatedBeforeIt(t *testing.T) {
	tests := []struct {
		name string
		arm  func(c *fakeclock.Clock) <-chan time.Time
	}{
		{"After", func(c *fakeclock.Clock) <-chan time.Time { return c.After(30 * time.Second) }},
		{"NewTimer", func(c *fakeclock.Clock) <-chan time.Time { return c.NewTimer(30 * time.Second).C() }},
		{"NewTicker", func(c *fakeclock.Clock) <-chan time.Time { return c.NewTicker(30 * time.Second).C() }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fakeclock.New(epoch)
			ch := tt.arm(c)

			assertNoFire(t, ch)

			c.Advance(29 * time.Second)
			assertNoFire(t, ch)

			c.Advance(time.Second)
			got, ok := recvWithin(t, ch)
			if !ok {
				t.Fatalf("%s did not fire after the advance reached its deadline", tt.name)
			}
			if want := epoch.Add(30 * time.Second); !got.Equal(want) {
				t.Errorf("fired with %v, want the deadline instant %v", got, want)
			}
		})
	}
}

// A waiter armed before an Advance that crosses its deadline must be delivered
// its own deadline instant on the channel, not the advance target. Without this
// a component that timestamps work from the received value records the wrong
// instant, and §6.5.2's per-frame deadline assertion is unimplementable.
//
// This asserts the value delivered on the channel rather than what c.Now()
// returns inside the woken goroutine. The two are not the same observation: the
// buffered, non-blocking send in Advance (see fakeclock.go's arm doc) makes the
// receiver runnable without guaranteeing the runtime schedules it before
// Advance's loop continues and moves c.now to the advance target (or a later
// waiter's deadline). The channel value is fixed at send time and is already
// deterministic; asserting on it is what makes this test meaningful without
// racing the goroutine scheduler.
func TestFiringWaiterObservesItsOwnDeadline(t *testing.T) {
	c := fakeclock.New(epoch)
	ch := c.After(10 * time.Second)
	observed := make(chan time.Time, 1)

	go func() {
		observed <- <-ch
	}()

	// Wait until the goroutine is parked on the channel before advancing, so the
	// advance genuinely wakes a pre-existing waiter.
	time.Sleep(20 * time.Millisecond)
	c.Advance(time.Minute)

	got, ok := recvWithin(t, observed)
	if !ok {
		t.Fatal("waiter never woke")
	}
	if want := epoch.Add(10 * time.Second); !got.Equal(want) {
		t.Errorf("waiter received %v on the channel, want its own deadline %v", got, want)
	}
}

func TestTickerFiresOncePerPeriod(t *testing.T) {
	c := fakeclock.New(epoch)
	tk := c.NewTicker(20 * time.Millisecond)
	defer tk.Stop()

	for i := 1; i <= 3; i++ {
		c.Advance(20 * time.Millisecond)
		got, ok := recvWithin(t, tk.C())
		if !ok {
			t.Fatalf("tick %d never arrived", i)
		}
		if want := epoch.Add(time.Duration(i) * 20 * time.Millisecond); !got.Equal(want) {
			t.Errorf("tick %d = %v, want %v", i, got, want)
		}
	}
}

func TestStopPreventsFiring(t *testing.T) {
	c := fakeclock.New(epoch)

	tm := c.NewTimer(time.Second)
	if !tm.Stop() {
		t.Error("Timer.Stop() = false on an armed timer, want true")
	}
	if tm.Stop() {
		t.Error("Timer.Stop() = true on an already-stopped timer, want false")
	}

	tk := c.NewTicker(time.Second)
	tk.Stop()

	c.Advance(time.Hour)

	assertNoFire(t, tm.C())
	assertNoFire(t, tk.C())

	if got, want := c.Now(), epoch.Add(time.Hour); !got.Equal(want) {
		t.Errorf("Now() = %v, want %v (a stopped waiter must not block the advance)", got, want)
	}
}

func TestResetRearmsFromTheCurrentFakeTime(t *testing.T) {
	c := fakeclock.New(epoch)
	tm := c.NewTimer(10 * time.Second)

	c.Advance(5 * time.Second)
	if !tm.Reset(10 * time.Second) {
		t.Error("Reset() = false on an active timer, want true")
	}

	c.Advance(9 * time.Second) // now epoch+14s; the reset deadline is epoch+15s
	assertNoFire(t, tm.C())

	c.Advance(time.Second)
	got, ok := recvWithin(t, tm.C())
	if !ok {
		t.Fatal("reset timer never fired")
	}
	if want := epoch.Add(15 * time.Second); !got.Equal(want) {
		t.Errorf("fired at %v, want %v", got, want)
	}
}

func TestConcurrentWaitersAndAdvanceAreRaceFree(t *testing.T) {
	c := fakeclock.New(epoch)
	const waiters = 32

	done := make(chan struct{}, waiters)
	for i := 0; i < waiters; i++ {
		ch := c.After(time.Duration(i+1) * time.Millisecond)
		go func() {
			<-ch
			_ = c.Now()
			done <- struct{}{}
		}()
	}

	c.Advance(time.Second)

	for i := 0; i < waiters; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of %d waiters woke", i, waiters)
		}
	}
}

func TestBlockUntilReturnsImmediatelyWhenTheCountAlreadyMatches(t *testing.T) {
	c := fakeclock.New(epoch)

	done := make(chan struct{})
	go func() {
		c.BlockUntil(0)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("BlockUntil(0) blocked on a clock with no waiters")
	}
}

func TestBlockUntilWaitsForAWaiterToBeArmed(t *testing.T) {
	c := fakeclock.New(epoch)

	returned := make(chan struct{})
	go func() {
		c.BlockUntil(1)
		close(returned)
	}()

	select {
	case <-returned:
		t.Fatal("BlockUntil(1) returned before any waiter was armed")
	case <-time.After(20 * time.Millisecond):
	}

	_ = c.After(time.Minute)

	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("BlockUntil(1) did not return after a waiter was armed")
	}
}

// The reason BlockUntil exists: without it, Advance races the code under test.
// Here the "code under test" arms its timer only after a delay; the test must
// still be deterministic.
func TestBlockUntilMakesAdvanceDeterministicAgainstLateArming(t *testing.T) {
	c := fakeclock.New(epoch)
	fired := make(chan time.Time, 1)

	go func() {
		time.Sleep(30 * time.Millisecond) // the code under test is slow to arm
		fired <- <-c.After(30 * time.Second)
	}()

	blockUntilWithin(t, c, 1, "before Advance in TestBlockUntilMakesAdvanceDeterministicAgainstLateArming")
	c.Advance(30 * time.Second)

	got, ok := recvWithin(t, fired)
	if !ok {
		t.Fatal("timer never fired; Advance raced the arming goroutine")
	}
	if want := epoch.Add(30 * time.Second); !got.Equal(want) {
		t.Errorf("fired at %v, want %v", got, want)
	}
}

// blockUntilWithin runs c.BlockUntil(n) in its own goroutine and fails the
// test if it does not return within a short deadline, naming which call
// stalled and the count it was waiting for. Without this, a wrong count
// makes BlockUntil hang silently until Go's 10-minute test timeout instead
// of reporting itself.
func blockUntilWithin(t *testing.T, c *fakeclock.Clock, n int, label string) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		c.BlockUntil(n)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("BlockUntil(%d) stalled: %s", n, label)
	}
}

func TestBlockUntilTracksStopAndReset(t *testing.T) {
	c := fakeclock.New(epoch)

	tm := c.NewTimer(time.Minute)
	tk := c.NewTicker(time.Minute)
	blockUntilWithin(t, c, 2, "after NewTimer + NewTicker")

	tk.Stop()
	blockUntilWithin(t, c, 1, "after tk.Stop()")

	tm.Stop()
	blockUntilWithin(t, c, 0, "after tm.Stop()")

	tm.Reset(time.Minute)
	blockUntilWithin(t, c, 1, "after tm.Reset(time.Minute)")
}
