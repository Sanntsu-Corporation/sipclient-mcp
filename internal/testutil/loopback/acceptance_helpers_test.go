package loopback_test

import (
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// setupInboundRinging drives a real INVITE from the far end at the given UA
// and returns the resulting call handle, parked in `ringing`. The far end is
// left with its default behaviour: it has already sent nothing, so BOTH
// racers in a conflicting pair see a genuinely ringing inbound call.
func setupInboundRinging(t *testing.T, h *loopback.Harness, ua string) string {
	t.Helper()
	h.Peer().Dial(t, h.UAContactURI(t, ua))
	c := h.MustWaitForInboundCall(t, 2*time.Second)
	if st := h.MustCallStatus(t, c); st.State != "ringing" {
		t.Fatalf("setup: inbound call state = %q, want ringing", st.State)
	}
	return c
}

// setupOutboundAnswered dials the far end and returns the handle of a call in
// `answered`, so a hangup pair races on a live dialog rather than on setup.
func setupOutboundAnswered(t *testing.T, h *loopback.Harness, ua string) string {
	t.Helper()
	c := h.MustDial(t, ua, h.PeerURI())
	h.MustWait(t, c, "answered", 2000)
	return c
}

// runSessionWaiterCapAcrossCalls is TestWaiterBounds' third row: the SESSION
// cap binds across DIFFERENT calls, which is what distinguishes it from
// max_waiters_per_call. Three calls carry one waiter each against
// max_waiters_per_session=3; the fourth, on a fourth call whose own per-call
// count is zero, is denied naming the SESSION key.
//
// ALL FOUR CALLS SHARE ONE UA (Phase 1's STRICT one-UA-per-session model,
// owner-locked decision) — the property under test is the SESSION-wide
// waiter cap across calls, which one UA dialing four times exercises
// identically to four UAs each dialing once.
func runSessionWaiterCapAcrossCalls(t *testing.T, h *loopback.Harness, c0 string) {
	t.Helper()
	var ua string
	for _, entry := range h.MustCallList(t) {
		if entry.CallHandle == c0 {
			ua = entry.UAHandle
			break
		}
	}
	if ua == "" {
		t.Fatalf("could not resolve the UA handle owning call %s via call_list", c0)
	}
	calls := make([]string, 4)
	calls[0] = c0
	for i := 1; i < 4; i++ {
		calls[i] = h.MustDialAnsweredOn(t, ua)
	}
	for i := 0; i < 3; i++ {
		go h.CallWait(calls[i], "dtmf", 300000)
		h.WaitForWaiterCount(t, calls[i], 1, time.Second)
	}
	res := h.CallWait(calls[3], "dtmf", 5000)
	if loopback.ErrorCodeOf(res) != "resource_limit" {
		t.Fatalf("fourth wait code = %q, want resource_limit", loopback.ErrorCodeOf(res))
	}
	if loopback.ErrorRuleOf(res) != "max_waiters_per_session" {
		t.Fatalf("fourth wait rule = %q, want max_waiters_per_session — the fourth call's "+
			"OWN waiter count is 0, so only the session cap can have bound", loopback.ErrorRuleOf(res))
	}
	for _, c := range calls[:3] {
		h.MustHangup(t, c)
	}
}
