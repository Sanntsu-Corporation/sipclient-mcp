package session

import "testing"

// TestCheckDTMFSendBoundsRenderCeiling is P4-N01's Rule 9 mutation proof
// (Phase 4 W1 M2, item 2). checkDTMFSendBounds had NO ceiling test at all
// before this file: toolservice_media_test.go's cross-surface parity tests
// exercise it only through payloads far past any ceiling, never at the exact
// boundary.
//
// The proof is DELIBERATELY on checkDTMFSendBounds, not on the media-plan
// surface (validateMediaPlan/decodeDTMF): once Inputs §4 (RN-1, item 3)
// lands, its 180,000ms default per-step ceiling binds FIRST on the
// media-plan `dtmf` step, making dtmfRenderCeilingMs's own value
// unobservable through that path — a test there would pass for the wrong
// reason. dtmf_send is explicitly UNTOUCHED by item 3 (it is not a
// media-plan step), so its bound stays min(dtmfRenderCeilingMs, configured
// cap) only, which is exactly what this test isolates.
//
// max_call_duration_s is set to 7200 (well above the 300,000ms ceiling) so
// the configured cap never binds instead — the ceiling itself is what is
// under test.
func TestCheckDTMFSendBoundsRenderCeiling(t *testing.T) {
	const maxCallDurationS = 7200

	t.Run("exactly at the 300000ms ceiling is accepted", func(t *testing.T) {
		gap := 0
		in := DTMFSendInput{Call: "call_1", Digits: "1", DurationMs: 300_000, GapMs: &gap}
		if err := checkDTMFSendBounds(in, maxCallDurationS); err != nil {
			t.Fatalf("checkDTMFSendBounds at the ceiling (300000ms) = %v, want nil", err)
		}
	})

	t.Run("one millisecond over the ceiling is rejected", func(t *testing.T) {
		gap := 0
		in := DTMFSendInput{Call: "call_1", Digits: "1", DurationMs: 300_001, GapMs: &gap}
		err := checkDTMFSendBounds(in, maxCallDurationS)
		if err == nil {
			t.Fatal("checkDTMFSendBounds accepted 300001ms, one over the DTMF render ceiling")
		}
	})
}
