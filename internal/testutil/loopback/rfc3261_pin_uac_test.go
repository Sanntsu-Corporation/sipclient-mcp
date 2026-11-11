package loopback_test

// Lane A (rfc-sweep-a) pin for the A-UAC area that crosses internal/session and
// internal/sipua. Passes today; invert when NEW-A-23 is fixed.

import (
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// TestRFC3261_NEWA23_PolicyCapSendsBye covers NEW-A-23 (A-UAC-86, RFC 3261
// 13.2.2: "If, after acknowledging any 2xx response to an INVITE, the UAC does
// not want to continue with that dialog, then the UAC MUST terminate the dialog
// by sending a BYE request as described in Section 15." rfc3261.txt:4605-4607).
// The cap ends the call locally (termination_reason policy_timeout) and the
// peer sees exactly one BYE. The fake clock fires the cap at once, so the BYE
// is on the wire well inside the 1.5 s real-time window.
func TestRFC3261_NEWA23_PolicyCapSendsBye(t *testing.T) {
	h := loopback.New(t,
		loopback.WithFakeClock(),
		loopback.WithPolicyOverride("limits.max_call_duration_s", 5))
	defer h.Close()

	ua := h.MustCreateUA(t, "direct")
	c := h.MustDialAnsweredOn(t, ua)
	if err := h.TripDurationCap(c); err != nil {
		t.Fatalf("TripDurationCap: %v", err)
	}
	if got := h.MustCallStatus(t, c).TerminationReason; got != "policy_timeout" {
		t.Fatalf("termination_reason = %q, want policy_timeout", got)
	}
	h.Peer().WaitForBye(t, 1500*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	if n := h.Peer().ByeCount(); n != 1 {
		t.Errorf("the peer received %d BYE(s) after the duration cap, want exactly 1 (RFC 3261 13.2.2)", n)
	}
}
