package loopback_test

import (
	"net"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// closedUDPURI is a SIP URI at a loopback UDP port nothing listens on, so a
// dial to it draws no response at all.
func closedUDPURI(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a udp port: %v", err)
	}
	addr := c.LocalAddr().String()
	_ = c.Close()
	return "sip:nobody@" + addr
}

func waitTerminated(t *testing.T, h *loopback.Harness, call string, d time.Duration) loopback.CallStatus {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		st := h.MustCallStatus(t, call)
		if st.State == "terminated" {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("call %s not terminated within %s: state %q", call, d, st.State)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A dial that draws no response ends terminated/transport_failure with a
// terminal error event carrying no detail. This is the observable outcome the
// dialog-scoped end (CF-037, D-A) must keep.
func TestCallDialThatDrawsNoResponseEndsTerminatedTransportFailure(t *testing.T) {
	h := loopback.New(t, loopback.WithUATimeout(300*time.Millisecond))
	defer h.Close()
	ua := h.MustCreateUA(t, "direct")
	c := h.MustDial(t, ua, closedUDPURI(t))

	st := waitTerminated(t, h, c, 3*time.Second)
	if st.TerminationReason != "transport_failure" {
		t.Fatalf("termination_reason = %q, want transport_failure", st.TerminationReason)
	}
	env := h.MustCallTool(t, "call_events", map[string]any{"call": c, "since": 0})
	evs, _ := env["events"].([]any)
	if len(evs) == 0 {
		t.Fatal("call_events returned no events")
	}
	last, _ := evs[len(evs)-1].(map[string]any)
	if last["type"] != "error" {
		t.Fatalf("last event type = %v, want error", last["type"])
	}
	if _, has := last["detail"]; has {
		t.Fatalf("terminal error event carries a detail: %v", last["detail"])
	}
}

// One call's dial timeout must not touch its siblings: an answered call on the
// same UA stays answered and live, and its sipua dialog can still be hung up.
func TestDialTimeoutLeavesAnAnsweredSiblingCallUp(t *testing.T) {
	// Not 500/1500/3500 ms: those are Timer A retransmit instants (vendored sipgo nil timer_a race).
	h := loopback.New(t, loopback.WithUATimeout(1000*time.Millisecond))
	defer h.Close()
	ua := h.MustCreateUA(t, "direct")
	a := h.MustDialAnsweredOn(t, ua)
	b := h.MustDial(t, ua, closedUDPURI(t))

	waitTerminated(t, h, b, 8*time.Second)

	if st := h.MustCallStatus(t, a); st.State != "answered" {
		t.Fatalf("sibling call A state = %q (reason %q), want answered", st.State, st.TerminationReason)
	}
	// The harness has one session, so the total is the per-session count.
	if _, total := h.Manager().DebugLiveCallCounts(""); total != 1 {
		t.Fatalf("live calls = %d, want 1", total)
	}
	h.MustHangup(t, a)
	if n := h.Peer().Count("BYE"); n != 1 {
		t.Fatalf("peer received %d BYE, want exactly 1", n)
	}
}
