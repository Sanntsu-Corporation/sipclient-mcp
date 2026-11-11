// goertzel_dtmf_silence_test.go — D17's real coverage (P4-W2-02, Phase 4 W2).
//
// D17 ASKED FOR A GATE SCENARIO THAT CANNOT BE WRITTEN, and this file is the
// bounded thing that discharges it instead. The asked-for scenario "sends DTMF
// during a silence-suppressed span and asserts it survives"; the assertion would
// be FALSE, and the span is unreachable:
//
//   - Feed reports a digit only on the frame where classification CHANGES
//     (goertzel.go:345-373). A tone with no post-tone frame after it is HELD, not
//     reported. That is the accepted design, stated at Feed's own doc comment.
//   - Nothing in e2e/loop can create the span: no MCP tool stops a call's RTP
//     mid-stream, and the Asterisk rig applies no VAD.
//
// So the honest statement of the risk is a DETECTOR-LEVEL one, and it belongs
// here, deterministically, rather than as a live scenario asserting something
// untrue: a digit's report is owed to the frame AFTER the tone, so anything that
// truncates the stream at the end of a tone loses that digit. This pins exactly
// that, in both directions, so the behaviour is a recorded contract instead of an
// unexamined hazard.
package codec

import "testing"

// TestFeedHoldsTheLastToneUntilAFrameFollowsIt is D17's pin: a tone alone
// reports NOTHING, and one following silence frame flushes it. Both halves
// matter — the first is the hazard, the second is the reason it is acceptable
// (any real stream has a following frame).
func TestFeedHoldsTheLastToneUntilAFrameFollowsIt(t *testing.T) {
	var d DTMFDetector

	// Six 20 ms frames of '5' = 120 ms, comfortably past Q.24's 40 ms floor, so
	// the run is REPORTABLE and only the missing terminator holds it. Reuses
	// NewDTMFSource (dtmf.go), the package's own tone generator — the same one
	// TestDetectorReportsALongToneExactlyOnce uses right above detectAll's
	// neighbourhood in goertzel_test.go — rather than inventing a second one.
	const frames = 6
	src, err := NewDTMFSource("5", frames*20, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < frames; i++ {
		digit, ms, ok := d.Feed(src.Frame())
		if ok {
			t.Fatalf("frame %d of a continuous tone reported digit %q (%d ms); Feed must report "+
				"only when classification CHANGES, so a tone still in progress reports nothing",
				i, digit, ms)
		}
	}

	// THE HAZARD, PINNED: after the whole tone, still nothing. A stream that ends
	// (or is suppressed) here loses this digit entirely — that is D17's real
	// mechanism, and it is a consequence of the reporting rule, not a bug.
	// Nothing above this line reported anything, which is the assertion.

	// THE MITIGATION, PINNED: exactly ONE frame of silence flushes it.
	digit, ms, ok := d.Feed(make([]int16, SamplesPerFrame))
	if !ok {
		t.Fatal("one silence frame after a 120 ms tone reported nothing; the tone's run ended at " +
			"this frame and met Q.24's minimum, so Feed must flush its report here")
	}
	if digit != '5' {
		t.Fatalf("flushed digit = %q, want '5'", digit)
	}
	if ms != frames*20 {
		t.Fatalf("flushed duration = %d ms, want %d — Feed reports the TRUE elapsed length, "+
			"not merely that the floor was crossed", ms, frames*20)
	}
}
