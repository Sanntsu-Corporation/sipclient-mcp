package session

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// TestConcurrentToolCallInvariant is §6.3's acceptance criterion. For each
// conflicting pair, both operations are issued from separate goroutines
// released by a common barrier, 1000 times: EXACTLY ONE returns ok and the
// other returns precondition_failed, in every iteration. Run under -race.
//
// ALL FIVE OF §6.3's CONFLICTING PAIRS ARE COVERED, and the count is part of
// the acceptance: §6.3 enumerates two call_answers, call_answer vs call_reject,
// two call_hangups, call_hangup vs the policy duration cap, and CALL_HANGUP VS
// A FAR-END BYE. The last was missing from an earlier draft of this table; a
// pair the table omits is a pair nothing tests.
//
// -race proves there is no DATA race here. It does NOT prove there is no
// lock-order inversion; nothing in this file does. That property is held by
// the §6.3 rule 5 review gate and Task 9's deadlock tests.
func TestConcurrentToolCallInvariant(t *testing.T) {
	const iterations = 1000
	now := time.Unix(1000, 0)

	tests := []struct {
		name              string
		initial           CallState
		a, b              func(*Call) error
		wantFinalState    CallState
		wantReasons       map[string]bool
		wantTerminalCount int // exact count; -1 means "at most one"
	}{
		{
			name:              "two call_answers",
			initial:           StateRinging,
			a:                 func(c *Call) error { return c.TryAnswer(now) },
			b:                 func(c *Call) error { return c.TryAnswer(now) },
			wantFinalState:    StateAnswered,
			wantReasons:       map[string]bool{"": true},
			wantTerminalCount: 0,
		},
		{
			name:              "call_answer vs call_reject",
			initial:           StateRinging,
			a:                 func(c *Call) error { return c.TryAnswer(now) },
			b:                 func(c *Call) error { return c.TryReject(now, 486, "Busy Here") },
			wantFinalState:    "", // either answered or terminated; checked below
			wantReasons:       map[string]bool{"": true, "rejected_locally": true},
			wantTerminalCount: -1,
		},
		{
			name:              "two call_hangups",
			initial:           StateAnswered,
			a:                 func(c *Call) error { return c.TryHangup(now, "local_hangup") },
			b:                 func(c *Call) error { return c.TryHangup(now, "local_hangup") },
			wantFinalState:    StateTerminated,
			wantReasons:       map[string]bool{"local_hangup": true},
			wantTerminalCount: 1,
		},
		{
			name:              "call_hangup vs the duration cap",
			initial:           StateAnswered,
			a:                 func(c *Call) error { return c.TryHangup(now, "local_hangup") },
			b:                 func(c *Call) error { return c.TryTerminate(now, "policy_timeout", EventPolicyTimeout) },
			wantFinalState:    StateTerminated,
			wantReasons:       map[string]bool{"local_hangup": true, "policy_timeout": true},
			wantTerminalCount: 1,
		},
		{
			// §6.3's FIFTH pair. A far-end BYE arriving while call_hangup is in
			// flight is the pair an agent hits in ordinary operation — both
			// sides ending the same call at the same moment — and it is the one
			// an earlier draft of this table omitted. The call terminates ONCE,
			// with ONE termination_reason (whichever side won) and ONE terminal
			// event, exactly as the local-cap pair above.
			name:              "call_hangup vs a far-end BYE",
			initial:           StateAnswered,
			a:                 func(c *Call) error { return c.TryHangup(now, "local_hangup") },
			b:                 func(c *Call) error { return c.TryTerminate(now, "remote_bye", EventBye) },
			wantFinalState:    StateTerminated,
			wantReasons:       map[string]bool{"local_hangup": true, "remote_bye": true},
			wantTerminalCount: 1,
		},
	}

	// §6.3 enumerates exactly five conflicting pairs for P1's tool surface (the
	// sixth, two media_record_starts, is §10.9 and arrives at P2). Assert the
	// count so a future edit cannot quietly drop one.
	if len(tests) != 5 {
		t.Fatalf("%d conflicting pairs, want 5 — §6.3's list is exhaustive at P1", len(tests))
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < iterations; i++ {
				c := newCall(newCallHandle(), newUAHandle(), &sessionRecord{id: "s1"},
					Inbound, tc.initial, 1024, time.Unix(1000, 0))

				var barrier sync.WaitGroup
				barrier.Add(1)
				var wg sync.WaitGroup
				errs := make([]error, 2)
				for j, op := range []func(*Call) error{tc.a, tc.b} {
					wg.Add(1)
					go func(j int, op func(*Call) error) {
						defer wg.Done()
						barrier.Wait()
						errs[j] = op(c)
					}(j, op)
				}
				barrier.Done()
				wg.Wait()

				oks, losers := 0, 0
				for _, err := range errs {
					if err == nil {
						oks++
						continue
					}
					var ae *apierr.Error
					if !errors.As(err, &ae) {
						t.Fatalf("iteration %d: err = %v, want *apierr.Error", i, err)
					}
					if ae.Code != apierr.CodePreconditionFailed {
						t.Fatalf("iteration %d: loser code = %q, want precondition_failed", i, ae.Code)
					}
					losers++
				}
				if oks != 1 || losers != 1 {
					t.Fatalf("iteration %d: %d winners, %d losers; want exactly 1 and 1", i, oks, losers)
				}

				if tc.wantFinalState != "" && c.State() != tc.wantFinalState {
					t.Fatalf("iteration %d: state = %q, want %q", i, c.State(), tc.wantFinalState)
				}
				if !tc.wantReasons[c.TerminationReason()] {
					t.Fatalf("iteration %d: termination_reason = %q, not in the permitted set",
						i, c.TerminationReason())
				}

				evs, _, _ := c.Events(0)
				terminal := 0
				for _, e := range evs {
					if e.Type == EventBye || e.Type == EventPolicyTimeout {
						terminal++
					}
				}
				if tc.wantTerminalCount >= 0 && terminal != tc.wantTerminalCount {
					t.Fatalf("iteration %d: %d terminal events, want %d", i, terminal, tc.wantTerminalCount)
				}
				if tc.wantTerminalCount < 0 && terminal > 1 {
					t.Fatalf("iteration %d: %d terminal events, want at most 1", i, terminal)
				}
				for k := 1; k < len(evs); k++ {
					if evs[k].Seq != evs[k-1].Seq+1 {
						t.Fatalf("iteration %d: seq not monotonic: %d then %d", i, evs[k-1].Seq, evs[k].Seq)
					}
				}
			}
		})
	}
}
