package loopback_test

import (
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// TestCallLogHelpersFindTheN5Line guards D335. The three call-log helpers
// filtered on m["event"] == "call_log", but session.Manager.emitCallLog
// writes the record as slog's MESSAGE — Info("call terminated", ...) — which
// slog renders under "msg", with no "event" key on that line at all. All
// three therefore returned empty UNCONDITIONALLY.
//
// That is a could-only-pass generator in shared infrastructure: any consumer
// asserting the ABSENCE of a call-log line would have passed vacuously. It
// also broke P1e Task 23, which asserts CallLogLineCountFor(c) == 1.
//
// Mutation-proved: reverting the helpers to the "event"-only match fails this
// test with `CallLogLineCountFor(...) = 0, want 1`.
func TestCallLogHelpersFindTheN5Line(t *testing.T) {
	h := loopback.New(t)
	ua := h.MustCreateUA(t, "direct")
	c := h.MustDial(t, ua, h.PeerURI())
	h.MustWait(t, c, "answered", 2000)
	h.MustHangup(t, c)

	// The record is emitted from RecordTermination after the lock is
	// released, so poll to a bounded deadline rather than reading eagerly.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && h.CallLogLineCountFor(c) == 0 {
		time.Sleep(20 * time.Millisecond)
	}

	if n := h.CallLogLineCountFor(c); n != 1 {
		t.Fatalf("CallLogLineCountFor(%s) = %d, want exactly 1 (§5 N5: a call "+
			"terminates once, with one termination_reason)", c, n)
	}
	if len(h.CallLogLines(t)) == 0 {
		t.Fatalf("CallLogLines returned empty although a call terminated")
	}
	m, ok := h.CallLogLineFor(t, c)
	if !ok {
		t.Fatalf("CallLogLineFor(%s) found nothing", c)
	}
	if got := m["termination_reason"]; got != "local_hangup" {
		t.Fatalf("termination_reason = %v, want local_hangup", got)
	}
}
