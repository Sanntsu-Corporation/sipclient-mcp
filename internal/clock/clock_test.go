package clock_test

import (
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
)

func TestSystemNowTracksWallClock(t *testing.T) {
	c := clock.System()

	before := time.Now()
	got := c.Now()
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Errorf("Now() = %v, want between %v and %v", got, before, after)
	}
}

func TestSystemTimersFire(t *testing.T) {
	c := clock.System()

	tests := []struct {
		name string
		recv func() <-chan time.Time
	}{
		{"After", func() <-chan time.Time { return c.After(time.Millisecond) }},
		{"NewTimer", func() <-chan time.Time { return c.NewTimer(time.Millisecond).C() }},
		{"NewTicker", func() <-chan time.Time { return c.NewTicker(time.Millisecond).C() }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			select {
			case <-tt.recv():
			case <-time.After(2 * time.Second):
				t.Fatalf("%s did not fire within 2s", tt.name)
			}
		})
	}
}

func TestSystemTimerStopPreventsFire(t *testing.T) {
	tm := clock.System().NewTimer(time.Hour)

	if !tm.Stop() {
		t.Error("Stop() = false on a timer that has not fired, want true")
	}

	select {
	case <-tm.C():
		t.Error("stopped timer fired")
	case <-time.After(10 * time.Millisecond):
	}
}
