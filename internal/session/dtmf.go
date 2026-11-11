package session

import (
	"context"
	"time"
)

// DTMFDigit is one RECEIVED digit, in dtmf_received's element shape (decision
// 16): at_ms is WALL-CLOCK UnixMilli — not the event log's call-relative
// AtMs — and Seq is the cursor next_since pages on, matching call_events'
// existing pagination pattern.
type DTMFDigit struct {
	Seq        int64  `json:"-"`
	Digit      string `json:"digit"`
	AtMs       int64  `json:"at_ms"`
	DurationMs int    `json:"duration_ms"`
	Mode       string `json:"mode"`
}

// RecordDigit appends one received digit to the call's bounded ring AND appends
// the matching §10.5 dtmf event, IN ONE CRITICAL SECTION (§6.3 rule 1) — so a
// call_wait(until="dtmf") that wakes on the event can never observe a ring that
// does not yet contain the digit that woke it.
//
// Only RECEIVED digits land here. Sent digits are already observable through
// dtmf_send's own response and through plan_step, so appending them too would
// make call_wait(until="dtmf") fire on our own transmission (decision 16).
func (c *Call) RecordDigit(now time.Time, digit, mode string, durationMs int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.digitSeq++
	c.digits = append(c.digits, DTMFDigit{
		Seq: c.digitSeq, Digit: digit, AtMs: now.UnixMilli(),
		DurationMs: durationMs, Mode: mode,
	})
	if over := len(c.digits) - c.digitCap; over > 0 {
		c.digits = append(c.digits[:0], c.digits[over:]...)
	}
	c.appendLocked(now, EventDTMF, map[string]any{
		"digit": digit, "mode": mode, "duration_ms": durationMs,
	})
}

// DigitsSince returns every digit whose Seq is greater than `since`, plus the
// cursor to page from next. The cursor is the HIGH-WATER seq, not the last
// surviving element's, so a ring that has dropped entries still advances.
func (c *Call) DigitsSince(since int64) ([]DTMFDigit, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]DTMFDigit, 0, len(c.digits))
	for _, d := range c.digits {
		if d.Seq > since {
			out = append(out, d)
		}
	}
	return out, c.digitSeq
}

// handleDTMF is the UAEventDTMF handler: sipua reports the protocol fact, the
// call records it. It uses m.clk.Now() rather than ev.At for the same reason
// handleMediaError does — the RX goroutine that emits the event sets no At.
//
// It resolves the call through callByDialogIDForEvent (Task 5), not
// callByDialogID: detection runs on the RX goroutine, so the LAST digit of a
// call — the one a peer sends immediately before hanging up, and the one an
// agent most often waits on — races RecordTermination's live->terminated move
// and would be dropped by a live-only lookup.
func (m *Manager) handleDTMF(_ context.Context, uaHandle Handle, ev UAEvent) {
	c := m.callByDialogIDForEvent(uaHandle, ev.DialogID)
	if c == nil {
		return
	}
	c.RecordDigit(m.clk.Now(), ev.Digit, ev.DTMFMode, ev.DurationMs)
}

// handleSessionRefresh appends §10.5's session_refresh event (R9). The detail
// is sipua's, passed through unchanged — the same flat-scalar convention
// plan_step uses (decision 16). ForEvent for the same reason as handleDTMF: a
// refresh in flight when the peer BYEs must still appear in the log that
// explains why the call ended.
func (m *Manager) handleSessionRefresh(_ context.Context, uaHandle Handle, ev UAEvent) {
	c := m.callByDialogIDForEvent(uaHandle, ev.DialogID)
	if c == nil {
		return
	}
	c.Append(m.clk.Now(), EventSessionRefresh, ev.Detail)
}
