package session

import (
	"context"
	"testing"
	"time"
)

// TestCallAnswerArmsTheDurationCap is §11.3 on the INBOUND path.
//
// THE DEFECT THIS GATE EXISTS FOR. CallAnswerInput declared max_duration_s and
// nothing ever read it: the only reader of MaxDurationS, and the only caller
// of StartDurationCap, were both inside CallDial. An inbound call answered
// through call_answer was therefore subject to NEITHER the agent's requested
// max_duration_s NOR the policy cap max_call_duration_s — it ran forever,
// while the identical outbound call was bounded.
//
// The two subtests are the two ways that shows up, and BOTH are needed: the
// first proves the agent's request is read at all, the second proves the
// policy default binds a call that made no request. A fix that armed only
// when in.MaxDurationS > 0 would pass the first and fail the second, which is
// the more dangerous half — an agent that omits the field is exactly the
// caller with no other bound.
func TestCallAnswerArmsTheDurationCap(t *testing.T) {
	tests := []struct {
		name string
		// requested is call_answer's max_duration_s, in seconds.
		requested int
		// wantCap is when the call must be force-terminated, measured from
		// the answer.
		wantCap time.Duration
	}{
		{
			// Clamped DOWN is not at issue here: 60 is under the 7200 default,
			// so the agent's own request is what binds.
			name: "agent supplies max_duration_s", requested: 60, wantCap: 60 * time.Second,
		},
		{
			// The case that ran forever. No request, so §12.2's cap is the
			// only bound there is. 7200s is policy.Defaults()' current
			// max_call_duration_s (Phase 4 W1 M2, Inputs §3: raised from 300).
			name: "no request falls back to the policy cap", requested: 0, wantCap: 7200 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, fc := newTestManager(t) // policy.Defaults(): max_call_duration_s 7200
			ts := NewToolService(m)
			ctx := context.Background()
			c := mustCall(t, m, "s1") // inbound, ringing

			if _, err := ts.CallAnswer(ctx, "s1", CallAnswerInput{
				Call: string(c.Handle()), MaxDurationS: tc.requested,
			}); err != nil {
				t.Fatalf("CallAnswer: %v", err)
			}
			if got := c.State(); got != StateAnswered {
				t.Fatalf("state after call_answer = %q, want %q", got, StateAnswered)
			}

			// A cap goroutine must exist at all. Without this the two clock
			// assertions below would both hold VACUOUSLY on an unarmed call:
			// a call nothing ever terminates is not terminated at wantCap-1s
			// either.
			if n := m.DurationCapGoroutinesForTest(); n != 1 {
				t.Fatalf("armed duration-cap goroutines = %d, want 1: call_answer "+
					"accepted max_duration_s and never armed anything, so this "+
					"inbound call has no bound at all", n)
			}
			// BlockUntil ensures the timer is registered before the clock
			// moves, so the test cannot race past a timer not yet armed.
			fc.BlockUntil(1)

			// One second SHORT of the cap: still live.
			fc.Advance(tc.wantCap - time.Second)
			if got := c.State(); got != StateAnswered {
				t.Fatalf("state at cap-1s = %q, want %q — the cap fired early", got, StateAnswered)
			}

			// And at the cap: force-terminated with policy_timeout.
			fc.Advance(time.Second)
			waitForState(t, c, StateTerminated)
			if got := c.TerminationReason(); got != "policy_timeout" {
				t.Errorf("termination_reason = %q, want %q", got, "policy_timeout")
			}
		})
	}
}

// offerAgent reports a media session with no codec yet: the offer in the 200 to
// an INVITE without SDP, before the caller's ACK answers it (CF-145).
type offerAgent struct{ nopAgent }

func (offerAgent) MediaView(string) (MediaView, bool) {
	return MediaView{LocalMediaAddr: "127.0.0.1:16384"}, true
}

// TestCallAnswerOmitsAnEmptyCodec: call_answer's result carries codec only once
// one is negotiated (D-MCP item 1).
func TestCallAnswerOmitsAnEmptyCodec(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, nil), Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return offerAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	c := mustCall(t, m, "s1")
	out, err := NewToolService(m).CallAnswer(ctx, "s1", CallAnswerInput{Call: string(c.Handle())})
	if err != nil {
		t.Fatalf("CallAnswer: %v", err)
	}
	if v, ok := out.(map[string]any)["codec"]; ok {
		t.Fatalf("call_answer result carries codec %q before one is negotiated", v)
	}
}

// waitForState polls a call's state. The cap fires on its own goroutine, so
// the transition is observable only after that goroutine runs — polling the
// state itself (rather than sleeping a fixed interval) is what keeps this from
// being a timing assertion.
func waitForState(t *testing.T, c *Call, want CallState) {
	t.Helper()
	deadline := time.Now().Add(ciScaled(3 * time.Second))
	for time.Now().Before(deadline) {
		if c.State() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state = %q after 3s, want %q: the duration cap never terminated the call",
		c.State(), want)
}
