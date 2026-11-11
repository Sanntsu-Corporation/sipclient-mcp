// Package clock is the time source every stateful sipclient-mcp component takes
// at construction (locked decision 18).
//
// session, sipua, policy and artifact accept a Clock as a constructor parameter
// and call no time package function directly. Production wiring passes System();
// tests pass internal/testutil/fakeclock. This is what makes spec §14.2's
// session_resume_window cases deterministic rather than timed, and what makes
// §6.5.2's 90 000-frame TX-drift test feasible at P2 without reopening every P1
// timer.
package clock

import "time"

// Clock is a source of time and of timers.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
	NewTimer(d time.Duration) Timer
	NewTicker(d time.Duration) Ticker
}

// Timer mirrors *time.Timer. The channel is a method rather than a field so a
// fake can implement it.
type Timer interface {
	// C is the channel on which the time is delivered.
	C() <-chan time.Time
	// Stop prevents the timer from firing, reporting whether it had not already
	// fired or been stopped.
	Stop() bool
	// Reset changes the timer to expire after d, reporting whether it was active.
	Reset(d time.Duration) bool
}

// Ticker mirrors *time.Ticker.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// System returns a Clock backed by the time package.
func System() Clock { return systemClock{} }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

func (systemClock) NewTimer(d time.Duration) Timer { return systemTimer{t: time.NewTimer(d)} }

func (systemClock) NewTicker(d time.Duration) Ticker { return systemTicker{t: time.NewTicker(d)} }

type systemTimer struct{ t *time.Timer }

func (s systemTimer) C() <-chan time.Time        { return s.t.C }
func (s systemTimer) Stop() bool                 { return s.t.Stop() }
func (s systemTimer) Reset(d time.Duration) bool { return s.t.Reset(d) }

type systemTicker struct{ t *time.Ticker }

func (s systemTicker) C() <-chan time.Time { return s.t.C }
func (s systemTicker) Stop()               { s.t.Stop() }
