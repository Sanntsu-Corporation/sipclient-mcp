package loopback_test

import (
	"sync"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// TestDTMFSendCrossModeSingleFlightAtTheToolBoundary is Phase 4 M6's D7/P4-P07
// loopback-layer coverage for F1. F1's fix lives entirely inside
// sipua.UA.SendDTMF (a dialog-level single-flight claim over the mode
// dispatch), and the corruption bug it closes was only reachable because
// nothing ABOVE sipua excluded two DIFFERENT dtmf_send modes from running
// concurrently on the same call — dtmf_send's own tool handler
// (ToolService.DTMFSend) adds no serialisation of its own. A regression that
// only reappears at the session<->sipua boundary (e.g. a future change to
// ToolService that bypasses SendDTMF, or resolves the call/UA differently per
// concurrent request) would be invisible to any test living entirely inside
// internal/sipua. Modeled on conflicting_pairs_test.go's proven concurrent
// harness pattern (TestConflictingToolCallPairsResolveToExactlyOneWinner).
func TestDTMFSendCrossModeSingleFlightAtTheToolBoundary(t *testing.T) {
	h := loopback.New(t)
	defer h.Close()
	call := h.MustDialAnswered(t)

	type result struct {
		mode string
		err  error
	}
	var start sync.WaitGroup
	start.Add(1)
	results := make(chan result, 2)
	for _, mode := range []string{"inband", "rfc2833"} {
		go func(mode string) {
			start.Wait()
			_, err := h.CallTool("dtmf_send", map[string]any{
				"call": call, "digits": "1", "mode": mode, "duration_ms": 200, "gap_ms": 0,
			})
			results <- result{mode, err}
		}(mode)
	}
	start.Done()
	r1, r2 := <-results, <-results

	winners := 0
	for _, r := range []result{r1, r2} {
		switch {
		case r.err == nil:
			winners++
		case loopback.ErrorCode(r.err) == "precondition_failed":
		default:
			t.Fatalf("mode %s: unexpected error %v (code %q); the loser must see precondition_failed",
				r.mode, r.err, loopback.ErrorCode(r.err))
		}
	}
	if winners != 1 {
		t.Fatalf("%d winners, want exactly 1 (errors: %v, %v)", winners, r1.err, r2.err)
	}
}
