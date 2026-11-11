package media

import (
	"testing"
	"time"
)

// §6.5.2: frame n is due at t0 + n*20ms and carries RTP timestamp ts0 + n*160,
// computed from the cumulative frame count — never accumulated.
func TestTXTickerDeadlineAndTimestampIdentity(t *testing.T) {
	t0 := time.Unix(0, 0)
	tk := NewTXTicker(t0, 1000)
	for n := int64(0); n < 90000; n++ {
		if got, want := tk.Deadline(), t0.Add(time.Duration(n)*FrameDuration); !got.Equal(want) {
			t.Fatalf("frame %d deadline=%v want %v", n, got, want)
		}
		if got, want := tk.Timestamp(), uint32(1000+n*160); got != want {
			t.Fatalf("frame %d ts=%d want %d", n, got, want)
		}
		tk.Advance()
	}
	if tk.FrameIndex() != 90000 {
		t.Fatalf("frame index=%d want 90000", tk.FrameIndex())
	}
}

// §6.5.2: a stall longer than 3 frames resyncs by skipping missed frames (never
// bursting), advancing n to the current time.
func TestTXTickerResyncSkipsRatherThanBursts(t *testing.T) {
	t0 := time.Unix(0, 0)
	tk := NewTXTicker(t0, 0)
	tk.Advance() // now at frame 1, due at 20ms
	// A 200 ms stall: frame 1's deadline is 20ms, now is 220ms => 10 frames
	// behind, well over the 3-frame threshold.
	now := t0.Add(220 * time.Millisecond)
	skipped := tk.Resync(now)
	if skipped == 0 {
		t.Fatal("Resync must skip frames after a 200ms stall")
	}
	// After resync the next deadline is at or after now, not a catch-up burst.
	if tk.Deadline().Before(now) {
		t.Fatalf("post-resync deadline %v is before now %v (would burst)", tk.Deadline(), now)
	}
}

func TestTXTickerNoResyncWithinThreshold(t *testing.T) {
	t0 := time.Unix(0, 0)
	tk := NewTXTicker(t0, 0)
	tk.Advance()
	// Only 40 ms late on frame 1 (due 20ms, now 60ms) => 2 frames, under the
	// 3-frame threshold: absorbed, not resynced.
	if skipped := tk.Resync(t0.Add(60 * time.Millisecond)); skipped != 0 {
		t.Fatalf("Resync skipped %d within threshold, want 0", skipped)
	}
}
