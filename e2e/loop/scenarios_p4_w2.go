package main

// scenarios_p4_w2.go — Phase 4 W2's gate scenarios.
//
// A SEPARATE FILE from scenarios_p4.go on purpose (design 4 leaves the choice
// to plan time): W1's single addition and W2's land in different waves with
// different deferral rows, and keeping them visually separable means a bisect
// over "which wave added this scenario" is a file listing rather than a git
// blame. Nothing here is structurally different from scenarios_p3.go's
// scenarios — same signature, same registration idiom, same helpers
// (including dtmfRigScenario, the shared body both of these wrap).
//
//   scenarioDTMFInfoRig    — D7  (P4-W2-04)
//   scenarioDTMFInbandRig  — D17 (P4-W2-02)
//
// A third scenario, scenarioDTMFRacingSessionRefresh (D9 combination 2,
// P4-W2-03), was scoped by this wave's plan but never written: Task 7's own
// Step 1 found combination 2 already covered elsewhere and recorded the skip
// as an in-plan disposition, not an emergency.

import "context"

// scenarioDTMFInfoRig is D7: the INFO sibling scenarioDTMFRFC2833Rig never had.
//
// WHY IT IS NOT REDUNDANT WITH scenarioDTMFInfo (scenarios_p3.go:224). That one
// drives our own second UA and asserts on the LADDER — it counts eight INFO
// requests leaving us, which proves we emit the method, not that anybody
// understands it. Reception of DTMF-over-INFO is deliberately out of production
// scope (dtmf.go's onInfo ACKs the INFO and never parses the body), so our own
// receiver structurally cannot confirm the digits. Asterisk CAN: it decodes
// application/dtmf-relay into the same dialplan Read() the rfc2833 sibling
// exercises, which is the whole reason 14.5 exists — an INDEPENDENT
// implementation agreeing with our encoding.
//
// ASSERTION: Asterisk's own `User entered '<digits>'` console line over ssh,
// exactly as the rfc2833 sibling asserts, with wall-clock-derived digits so a
// line left by an EARLIER run can never satisfy this one.
func scenarioDTMFInfoRig(ctx context.Context, r *rig) (bool, string) {
	return dtmfRigScenario(ctx, r, "info", "SIP INFO")
}

// scenarioDTMFInbandRig is D17's live half (P4-W2-02) and the gate's first
// rig-side INBAND scenario — rfc2833 had one, INFO got one in D7, inband had
// none, so nothing ever proved an independent implementation decodes the Q.23
// tones our encoder synthesizes.
//
// LIMITATION, STATED HERE RATHER THAN IMPLIED. This is NOT the
// VAD-swallows-a-keypress scenario D17 asked for, and it cannot be: no MCP tool
// stops a call's RTP mid-stream, so e2e/loop cannot produce a suppressed span,
// and the rig applies no VAD to create one either. What D17 was really worried
// about — that a digit's report is owed to the frame AFTER its tone, so a
// truncated stream loses it — is pinned deterministically at the detector in
// internal/media/codec/goertzel_dtmf_silence_test.go. This scenario covers the
// other, genuinely missing half: that the tones themselves are correct on the
// wire by a third party's reckoning.
func scenarioDTMFInbandRig(ctx context.Context, r *rig) (bool, string) {
	return dtmfRigScenario(ctx, r, "inband", "inband")
}
