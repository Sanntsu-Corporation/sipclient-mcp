package loopback_test

import (
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// waitForFinalResponseCount polls Peer().FinalResponseCount(), bounded by d,
// before asserting it. The winning call_answer/call_reject's HTTP response
// returns as soon as the SERVER'S state transition commits; the 200 OK/486
// it triggers still has to cross the loopback socket and be processed by the
// peer's own receive goroutine, so reading FinalResponseCount() synchronously
// right after the tool call races that delivery — exactly the pattern
// peer.WaitForBye and harness_test.go's own FinalResponseCount poll already
// use for the same reason.
func waitForFinalResponseCount(t *testing.T, h *loopback.Harness, want int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if got := h.Peer().FinalResponseCount(); got == want {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("far end recorded %d final responses after %s, want exactly %d", got, d, want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// §6.3's concurrent-tool-call invariant: two concurrent TOOL CALLS that
// conflict on the same handle resolve to EXACTLY ONE winner; the loser sees
// precondition_failed. There is no interleaving in which both succeed, both
// fail, or the handle is left in a state neither requested.
//
// THREE ROWS, NOT FIVE (D376, user decision). The plan's original table
// also raced call_hangup against PeerSendBye and against TripDurationCap.
// Both are STRUCTURALLY IMPOSSIBLE as "exactly one winner" cases: neither
// PeerSendBye (a far-end SIP message) nor TripDurationCap (a server-side
// timer) is a tool call an agent can be told it "lost" — both racers return
// nil and the harness genuinely reports 2 winners, observed at iteration 32
// (and <nil> | <nil> at 33/400) when this table still carried them. §6.3's
// acceptance sentence was amended to match: it now splits (a) tool-call
// pairs, asserted here as "exactly one winner", from (b) a tool call racing
// a non-tool-call actor, whose correct acceptance is "terminates exactly
// once, one termination_reason, one BYE on the wire" — already covered
// elsewhere in this suite (e.g. TestAdminDeleteDoesNotHoldTheRegistryLockAcrossTheByeWait
// and the scale/lockorder suites' hangup-vs-eviction races). Re-adding a
// "2 winners" assertion for PeerSendBye or TripDurationCap here would be
// REINTRODUCING A KNOWN DEFECT — do not.
func TestConflictingToolCallPairsResolveToExactlyOneWinner(t *testing.T) {
	const iterations = 1000
	tests := []struct {
		name  string
		setup func(*testing.T, *loopback.Harness, string) string // returns the call handle
		a, b  func(*loopback.Harness, string) error
		check func(*testing.T, *loopback.Harness, string)
	}{
		{
			name:  "two call_answer on one ringing call",
			setup: setupInboundRinging,
			a:     func(h *loopback.Harness, c string) error { return h.Answer(c) },
			b:     func(h *loopback.Harness, c string) error { return h.Answer(c) },
			check: func(t *testing.T, h *loopback.Harness, _ string) {
				waitForFinalResponseCount(t, h, 1, 500*time.Millisecond)
			},
		},
		{
			name:  "call_answer racing call_reject",
			setup: setupInboundRinging,
			a:     func(h *loopback.Harness, c string) error { return h.Answer(c) },
			b:     func(h *loopback.Harness, c string) error { return h.Reject(c, 486) },
			check: func(t *testing.T, h *loopback.Harness, _ string) {
				waitForFinalResponseCount(t, h, 1, 500*time.Millisecond)
			},
		},
		{
			name:  "two call_hangup",
			setup: setupOutboundAnswered,
			a:     func(h *loopback.Harness, c string) error { return h.Hangup(c) },
			b:     func(h *loopback.Harness, c string) error { return h.Hangup(c) },
			check: func(t *testing.T, h *loopback.Harness, _ string) {
				if n := h.Peer().ByeCount(); n != 1 {
					t.Fatalf("far end recorded %d BYE, want exactly 1", n)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < iterations; i++ {
				// A FRESH HARNESS PER ITERATION (not a fresh session on a shared
				// harness): each iteration's session.Manager is its own instance,
				// so its max_uas_total cap never accumulates across iterations —
				// unlike Task 24a's TestMassCancellationConcurrentWithEviction,
				// which reuses ONE harness across 1000 sessions and therefore
				// needs an explicit per-iteration ua_destroy. h.Close() tears the
				// whole harness down (registrar, peer, httptest server, daemon
				// context) at the end of each iteration instead.
				h := loopback.New(t)
				call := tt.setup(t, h, h.MustCreateUA(t, "direct"))

				var start sync.WaitGroup
				start.Add(1)
				results := make(chan error, 2)
				for _, op := range []func(*loopback.Harness, string) error{tt.a, tt.b} {
					go func(op func(*loopback.Harness, string) error) {
						start.Wait()
						results <- op(h, call)
					}(op)
				}
				start.Done()
				e1, e2 := <-results, <-results

				winners := 0
				for _, err := range []error{e1, e2} {
					switch {
					case err == nil:
						winners++
					case loopback.ErrorCode(err) == "precondition_failed":
					default:
						t.Fatalf("iteration %d: unexpected error %v (code %q); the loser "+
							"must see precondition_failed", i, err, loopback.ErrorCode(err))
					}
				}
				if winners != 1 {
					t.Fatalf("iteration %d: %d winners, want exactly 1 (errors: %v, %v)",
						i, winners, e1, e2)
				}
				tt.check(t, h, call)
				h.Close()
			}
		})
	}
}
