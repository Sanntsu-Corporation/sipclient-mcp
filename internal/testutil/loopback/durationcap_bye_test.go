package loopback_test

import (
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// CF-092: the policy duration cap ends the dialog on the wire (RFC 3261
// 13.2.2), not only in the registry.

func waitByeCount(t *testing.T, h *loopback.Harness, want int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for h.Peer().ByeCount() < want {
		if time.Now().After(deadline) {
			t.Fatalf("peer saw %d BYE(s) within %s, want %d", h.Peer().ByeCount(), d, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPolicyCapOnAnAnsweredInboundCallSendsBye(t *testing.T) {
	h := loopback.New(t,
		loopback.WithFakeClock(),
		loopback.WithPolicyOverride("limits.max_call_duration_s", 5))
	defer h.Close()

	ua := h.MustCreateUA(t, "direct")
	c := setupInboundRinging(t, h, ua)
	if err := h.Answer(c); err != nil {
		t.Fatalf("call_answer: %v", err)
	}
	if err := h.TripDurationCap(c); err != nil {
		t.Fatalf("TripDurationCap: %v", err)
	}
	if got := h.MustCallStatus(t, c).TerminationReason; got != "policy_timeout" {
		t.Fatalf("termination_reason = %q, want policy_timeout", got)
	}
	waitByeCount(t, h, 1, 1500*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	if n := h.Peer().ByeCount(); n != 1 {
		t.Errorf("peer saw %d BYE(s), want exactly 1", n)
	}
}

func TestPolicyCapWhileRingingCancelsTheInvite(t *testing.T) {
	h := loopback.New(t,
		loopback.WithFakeClock(),
		loopback.WithPolicyOverride("limits.max_call_duration_s", 5),
		loopback.WithPeerBehaviour(loopback.PeerBehaviour{AnswerAfter: time.Hour}))
	defer h.Close()

	c := h.MustDialRinging(t)
	if err := h.TripDurationCap(c); err != nil {
		t.Fatalf("TripDurationCap: %v", err)
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	for h.Peer().Count("CANCEL") < 1 {
		if time.Now().After(deadline) {
			t.Fatalf("peer saw no CANCEL after the cap fired on a ringing call; methods %v", h.Peer().Methods())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := h.Peer().ByeCount(); n != 0 {
		t.Errorf("peer saw %d BYE(s) for an unanswered call, want 0", n)
	}
	if got := h.MustCallStatus(t, c).TerminationReason; got != "policy_timeout" {
		t.Errorf("termination_reason = %q, want policy_timeout", got)
	}
}

// TestPolicyCapRacingHangupSendsOneBye races the cap against call_hangup and
// against a peer BYE, 200 iterations each: at most one BYE per call from us,
// exactly one terminal reason.
func TestPolicyCapRacingHangupSendsOneBye(t *testing.T) {
	const iterations = 200
	// Each iteration advances the fake clock by the cap; a long session TTL
	// keeps the session alive across all of them.
	h := loopback.New(t,
		loopback.WithFakeClock(),
		loopback.WithPolicyOverrides(map[string]any{
			"limits.max_call_duration_s": 5,
			"limits.session_ttl":         "24h",
		}))
	defer h.Close()
	ua := h.MustCreateUA(t, "direct")

	for _, tc := range []struct {
		name    string
		racer   func(c string)
		wantOne bool
	}{
		{"call_hangup", func(c string) { _ = h.Hangup(c) }, true},
		{"peer_bye", func(c string) { _ = h.PeerSendBye(c) }, false},
	} {
		for i := 0; i < iterations; i++ {
			c := h.MustDialAnsweredOn(t, ua)
			before := h.Peer().ByeCount()
			done := make(chan struct{})
			go func() { defer close(done); tc.racer(c) }()
			_ = h.TripDurationCap(c)
			<-done
			// An empty state means the janitor sweeps the fake clock drives
			// already evicted the terminated call.
			var st loopback.CallStatus
			deadline := time.Now().Add(2 * time.Second)
			for st = h.MustCallStatusRaw(c); st.State != "terminated" && st.State != ""; st = h.MustCallStatusRaw(c) {
				if time.Now().After(deadline) {
					t.Fatalf("%s iteration %d: call never terminated: %+v", tc.name, i, st)
				}
				time.Sleep(2 * time.Millisecond)
			}
			if tc.wantOne {
				waitByeCount(t, h, before+1, 1500*time.Millisecond)
			}
			time.Sleep(20 * time.Millisecond)
			if n := h.Peer().ByeCount() - before; n > 1 || (tc.wantOne && n != 1) {
				t.Fatalf("%s iteration %d: peer saw %d BYE(s)", tc.name, i, n)
			}
			if st.State == "terminated" && st.TerminationReason == "" {
				t.Fatalf("%s iteration %d: no termination_reason", tc.name, i)
			}
		}
	}
}
