package media

import "time"

// FrameDuration is the 20 ms TX/playout cadence (§6.5.2).
const FrameDuration = 20 * time.Millisecond

// FrameTimestampStep is the 8 kHz sample advance per 20 ms frame (160).
const FrameTimestampStep = 160

// ResyncThresholdFrames is §6.5.2's stall bound: more than 3 frames (60 ms)
// behind is a starved host, not jitter, and triggers a skip-not-burst resync.
const ResyncThresholdFrames = 3

// TXTicker is PURE deadline math (§6.5.2): it computes the absolute deadline and
// RTP timestamp of frame n from the cumulative frame count. It owns NO goroutine
// and NO clock — internal/sipua's TX goroutine reads Deadline(), sleeps against
// it, sends, then Advance()s. Scheduling against t0 + n*20ms bounds drift at one
// scheduling quantum regardless of call length, unlike an accumulating Ticker.
type TXTicker struct {
	t0  time.Time
	ts0 uint32
	n   int64
}

// NewTXTicker builds a TXTicker starting at wall-clock t0 and RTP timestamp ts0.
func NewTXTicker(t0 time.Time, ts0 uint32) *TXTicker { return &TXTicker{t0: t0, ts0: ts0} }

// Deadline returns the current frame's absolute send deadline.
func (tk *TXTicker) Deadline() time.Time { return tk.t0.Add(time.Duration(tk.n) * FrameDuration) }

// Timestamp returns the current frame's RTP timestamp.
func (tk *TXTicker) Timestamp() uint32 { return tk.ts0 + uint32(tk.n*FrameTimestampStep) }

// FrameIndex returns the current frame count since t0.
func (tk *TXTicker) FrameIndex() int64 { return tk.n }

// Advance moves the ticker to the next frame.
func (tk *TXTicker) Advance() { tk.n++ }

// Resync implements §6.5.2's starved-host path. If the current frame's deadline
// is more than ResyncThresholdFrames behind now, it advances n to the frame due
// at or after now and returns how many frames were skipped (so the caller counts
// them in tx_underruns and emits one error event). Within the threshold it does
// nothing and returns 0 — a single late wake-up is absorbed by sleeping to the
// existing deadline, not skipped.
func (tk *TXTicker) Resync(now time.Time) (skipped int64) {
	behind := now.Sub(tk.Deadline())
	if behind <= ResyncThresholdFrames*FrameDuration {
		return 0
	}
	// Frames elapsed between t0 and now; jump n forward to it.
	target := int64(now.Sub(tk.t0) / FrameDuration)
	if target <= tk.n {
		return 0
	}
	skipped = target - tk.n
	tk.n = target
	return skipped
}

// Clock is the time source mediaLoop's RX playout drain loop reads through
// (Task 9), instead of calling time.Now() directly, so a test can inject an
// accelerated fake clock and keep pace with the fixed 20ms/frame drain
// cadence without sleeping real wall-clock time between injected packets.
// TXTicker itself needs no Clock — it already takes now/t0 as plain
// parameters.
type Clock interface{ Now() time.Time }

// RealClock is the production Clock: real wall-clock time.
type RealClock struct{}

// Now returns the current wall-clock time.
func (RealClock) Now() time.Time { return time.Now() }
