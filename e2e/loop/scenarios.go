package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// scenarioCallerID (#3): dial 720, assert the callee's surfaced from_uri user
// part is the caller (Asterisk rewrites the host), then answer and clear.
func scenarioCallerID(ctx context.Context, r *rig) (bool, string) {
	before := r.registerCallHandles(ctx, r.registerUA)
	caller, err := r.dial(ctx, r.directUA, "720")
	if err != nil {
		return false, "dial 720: " + err.Error()
	}
	inbound, err := r.waitNewInbound(ctx, r.registerUA, before, 8*time.Second)
	if err != nil {
		return false, err.Error()
	}
	ist, err := r.callStatus(ctx, inbound)
	if err != nil {
		return false, "callee call_status: " + err.Error()
	}
	from := str(ist["from_uri"])
	if u := userPart(from); u != r.cfg.directP {
		return false, fmt.Sprintf("caller-id user=%q want %q (from_uri=%q)", u, r.cfg.directP, from)
	}
	if _, err := r.cl.callOK(ctx, "call_answer", map[string]any{"call": inbound}); err != nil {
		return false, "call_answer: " + err.Error()
	}
	cst, err := r.waitState(ctx, caller, "answered", 8*time.Second)
	if err != nil {
		return false, "caller answer: " + err.Error()
	}
	if callState(cst) != "answered" {
		return false, fmt.Sprintf("caller state=%q, expected answered", callState(cst))
	}
	return true, fmt.Sprintf("callee from_uri user=%q; both legs answered", r.cfg.directP)
}

// scenarioRemoteReject (#7): dial 720, callee rejects 486, assert the caller
// leg observes 486.
func scenarioRemoteReject(ctx context.Context, r *rig) (bool, string) {
	before := r.registerCallHandles(ctx, r.registerUA)
	caller, err := r.dial(ctx, r.directUA, "720")
	if err != nil {
		return false, "dial 720: " + err.Error()
	}
	inbound, err := r.waitNewInbound(ctx, r.registerUA, before, 8*time.Second)
	if err != nil {
		return false, err.Error()
	}
	if _, err := r.cl.callOK(ctx, "call_reject", map[string]any{"call": inbound, "status": 486}); err != nil {
		return false, "call_reject 486: " + err.Error()
	}
	cst, err := r.waitTerminal(ctx, caller, 10*time.Second)
	if err != nil {
		return false, "caller terminate: " + err.Error()
	}
	if code := lastCode(cst); code != 486 {
		return false, fmt.Sprintf("caller last_response.code=%d want 486", code)
	}
	return true, "caller observed 486 Busy Here"
}

// scenarioRemoteOffline (#6): destroy the callee (drops its AOR contact), dial
// 720 into a rig with nothing registered, assert 404. Re-registers the callee
// afterwards for the remaining scenarios.
func scenarioRemoteOffline(ctx context.Context, r *rig) (bool, string) {
	if _, err := r.cl.callOK(ctx, "ua_destroy", map[string]any{"ua": r.registerUA}); err != nil {
		return false, "ua_destroy callee: " + err.Error()
	}
	r.registerUA = ""
	// Let Asterisk drop the contact before we dial.
	sleepCtx(ctx, 1500*time.Millisecond)

	caller, derr := r.dial(ctx, r.directUA, "720")
	var cst map[string]any
	var werr error
	if derr == nil {
		cst, werr = r.waitTerminal(ctx, caller, 12*time.Second)
	}

	// Recreate the callee no matter what happened above — later scenarios need it.
	newUA, rerr := r.createRegisterUA(ctx)
	if rerr != nil {
		return false, "re-register callee after offline test failed: " + rerr.Error()
	}
	r.registerUA = newUA

	if derr != nil {
		return false, "dial 720: " + derr.Error()
	}
	if werr != nil {
		return false, "caller terminate: " + werr.Error()
	}
	if code := lastCode(cst); code != 404 {
		return false, fmt.Sprintf("caller last_response.code=%d want 404 (unregistered callee)", code)
	}
	return true, "caller observed 404 Not Found (callee unregistered)"
}

// scenarioRemoteDisconnect (#1, D1): dial 720, answer, then the PEER side (the
// caller leg / Asterisk) disconnects; assert the callee observes a clean remote
// BYE (remote_bye, terminated — no 481).
func scenarioRemoteDisconnect(ctx context.Context, r *rig) (bool, string) {
	before := r.registerCallHandles(ctx, r.registerUA)
	caller, err := r.dial(ctx, r.directUA, "720")
	if err != nil {
		return false, "dial 720: " + err.Error()
	}
	inbound, err := r.waitNewInbound(ctx, r.registerUA, before, 8*time.Second)
	if err != nil {
		return false, err.Error()
	}
	if _, err := r.cl.callOK(ctx, "call_answer", map[string]any{"call": inbound}); err != nil {
		return false, "call_answer: " + err.Error()
	}
	if _, err := r.waitState(ctx, caller, "answered", 8*time.Second); err != nil {
		return false, "caller answer: " + err.Error()
	}
	// Peer-side disconnect: the caller hangs up -> Asterisk BYEs the callee.
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": caller}); err != nil {
		return false, "caller call_hangup: " + err.Error()
	}
	ist, err := r.waitTerminal(ctx, inbound, 8*time.Second)
	if err != nil {
		return false, "callee terminate: " + err.Error()
	}
	if reason := termReason(ist); reason != "remote_bye" {
		return false, fmt.Sprintf("callee termination_reason=%q want remote_bye (D1)", reason)
	}
	if st := callState(ist); st != "terminated" {
		return false, fmt.Sprintf("callee state=%q, not clean terminated (possible 481)", st)
	}
	return true, "callee saw clean remote BYE (remote_bye, D1)"
}

// scenarioLocalDisconnect (#2, D1): dial 720, answer, then the CALLEE hangs up
// (a UAS BYE); assert the caller sees that BYE (remote_bye) — i.e. the callee's
// UAS BYE was accepted, not 481'd.
func scenarioLocalDisconnect(ctx context.Context, r *rig) (bool, string) {
	before := r.registerCallHandles(ctx, r.registerUA)
	caller, err := r.dial(ctx, r.directUA, "720")
	if err != nil {
		return false, "dial 720: " + err.Error()
	}
	inbound, err := r.waitNewInbound(ctx, r.registerUA, before, 8*time.Second)
	if err != nil {
		return false, err.Error()
	}
	if _, err := r.cl.callOK(ctx, "call_answer", map[string]any{"call": inbound}); err != nil {
		return false, "call_answer: " + err.Error()
	}
	if _, err := r.waitState(ctx, caller, "answered", 8*time.Second); err != nil {
		return false, "caller answer: " + err.Error()
	}
	// Local disconnect: the callee (UAS) hangs up.
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": inbound}); err != nil {
		return false, "callee call_hangup: " + err.Error()
	}
	cst, err := r.waitTerminal(ctx, caller, 8*time.Second)
	if err != nil {
		return false, "caller terminate: " + err.Error()
	}
	if reason := termReason(cst); reason != "remote_bye" {
		return false, fmt.Sprintf("caller termination_reason=%q want remote_bye — callee UAS BYE may have been 481'd (D1)", reason)
	}
	return true, "caller saw callee's UAS BYE accepted (remote_bye, D1)"
}

// scenarioRemoteNoAnswer (#5, D3): dial 721 (8s ring) and do NOT answer;
// Asterisk cancels the callee leg at ring expiry. Assert the callee terminates
// with a cancel reason, not its own inbound_ring_timeout.
//
// NOTE: the caller-initiated CANCEL variant is NOT driven here — see
// scenarioCallerCancel (#5b). The D3 assertion (callee sees "cancelled", not
// "inbound_ring_timeout") is exercised via Asterisk's own ring-expiry CANCEL.
func scenarioRemoteNoAnswer(ctx context.Context, r *rig) (bool, string) {
	before := r.registerCallHandles(ctx, r.registerUA)
	if _, err := r.dial(ctx, r.directUA, "721"); err != nil {
		return false, "dial 721: " + err.Error()
	}
	inbound, err := r.waitNewInbound(ctx, r.registerUA, before, 8*time.Second)
	if err != nil {
		return false, err.Error()
	}
	// Do not answer. Asterisk cancels at the 8s ring budget; allow margin.
	ist, err := r.waitTerminal(ctx, inbound, 20*time.Second)
	if err != nil {
		return false, "callee terminate: " + err.Error()
	}
	switch reason := termReason(ist); reason {
	// The daemon derives this wire value from apierr.CodeCancelled
	// (terminationReasonFor), and internal/apierr's §11.2 guard forbids a bare
	// "cancelled" literal outside apierr — so reference the constant, keeping
	// the harness's expected value single-sourced with the daemon's.
	case string(apierr.CodeCancelled):
		return true, "callee saw CANCEL as 'cancelled' (not ring-timeout, D3)"
	case "inbound_ring_timeout":
		return false, "callee hit its own inbound_ring_timeout instead of CANCEL (D3 regression)"
	default:
		return false, fmt.Sprintf("callee termination_reason=%q want cancelled (D3)", reason)
	}
}

// scenarioCallerCancel (#5b, CF-043): dial 721 (rings the callee, nobody
// answers) and, once the callee is ringing, call_hangup the CALLER's call about
// a second in. The caller's own CANCEL must reach Asterisk and make it CANCEL
// the callee leg: the callee terminates "cancelled" within 3 s of the hangup,
// well inside Asterisk's 8 s ring budget (which is what separates this from
// scenario #5, where Asterisk's own ring expiry does the cancelling). The
// caller's ladder must show one CANCEL and the 487 that answers the INVITE.
func scenarioCallerCancel(ctx context.Context, r *rig) (bool, string) {
	before := r.registerCallHandles(ctx, r.registerUA)
	caller, err := r.dial(ctx, r.directUA, "721")
	if err != nil {
		return false, "dial 721: " + err.Error()
	}
	inbound, err := r.waitNewInbound(ctx, r.registerUA, before, 8*time.Second)
	if err != nil {
		return false, err.Error()
	}
	if ist, err := r.waitState(ctx, inbound, "ringing", 3*time.Second); err != nil || callState(ist) != "ringing" {
		return false, fmt.Sprintf("callee did not reach ringing (err=%v state=%q)", err, callState(ist))
	}
	sleepCtx(ctx, time.Second)

	hungUp := time.Now()
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": caller}); err != nil {
		return false, "caller call_hangup: " + err.Error()
	}
	cst, err := r.waitTerminal(ctx, caller, 3*time.Second)
	if err != nil {
		return false, "caller terminate: " + err.Error()
	}
	if reason := termReason(cst); reason != "local_hangup" {
		return false, fmt.Sprintf("caller termination_reason=%q want local_hangup", reason)
	}
	ist, err := r.waitTerminal(ctx, inbound, 3*time.Second)
	if err != nil {
		return false, "callee terminate after the caller's CANCEL (Asterisk's own ring budget is 8 s): " + err.Error()
	}
	took := time.Since(hungUp)
	if reason := termReason(ist); reason != string(apierr.CodeCancelled) {
		return false, fmt.Sprintf("callee termination_reason=%q want %q", reason, apierr.CodeCancelled)
	}
	if took > 3*time.Second {
		return false, fmt.Sprintf("callee ended %s after the hangup, want within 3s", took)
	}

	// The 487 is written by Asterisk in answer to the CANCEL; the caller has
	// already recorded local_hangup, so poll briefly for it to be logged.
	var cancels int
	saw487 := false
	for deadline := time.Now().Add(3 * time.Second); ; {
		msgs, err := r.ladderMessages(ctx, caller)
		if err != nil {
			return false, "call_ladder: " + err.Error()
		}
		cancels, saw487 = 0, false
		for _, m := range msgs {
			if m.Method == "CANCEL" {
				cancels++
			}
			if strings.HasPrefix(m.Serialized, "SIP/2.0 487") {
				saw487 = true
			}
		}
		if saw487 || time.Now().After(deadline) || !sleepCtx(ctx, 200*time.Millisecond) {
			break
		}
	}
	if cancels != 1 || !saw487 {
		return false, fmt.Sprintf("caller ladder has %d CANCEL and 487 seen=%v, want 1 CANCEL and a 487", cancels, saw487)
	}
	return true, fmt.Sprintf("caller CANCEL propagated: callee cancelled %s after the hangup; ladder 1 CANCEL + 487", took.Round(10*time.Millisecond))
}

// scenarioNegotiatePCMUPCMA (P2 W3, §14.5/§6.5.3): creates a UA offering BOTH
// PCMU and PCMA, dials the Asterisk echo extension (600, Echo() —
// extensions.conf), and asserts the daemon negotiated one of the two G.711
// codecs it offered and reported a routable local_media_addr. Signalling-only
// this wave: no audio is exchanged.
func scenarioNegotiatePCMUPCMA(ctx context.Context, r *rig) (bool, string) {
	ua, err := r.createDirectUAWithCodecs(ctx, []string{"PCMU", "PCMA"})
	if err != nil {
		return false, "createDirectUAWithCodecs: " + err.Error()
	}
	defer func() { _, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": ua}) }()

	handle, err := r.dial(ctx, ua, "600")
	if err != nil {
		return false, "dial 600: " + err.Error()
	}
	st, err := r.waitState(ctx, handle, "answered", 8*time.Second)
	if err != nil {
		return false, "waitState answered: " + err.Error()
	}
	if callState(st) != "answered" {
		return false, fmt.Sprintf("state=%q, want answered", callState(st))
	}
	codec := str(st["codec"])
	if codec != "PCMU" && codec != "PCMA" {
		return false, "unexpected negotiated codec: " + codec
	}
	if lma := str(st["local_media_addr"]); lma == "" {
		return false, "local_media_addr empty"
	}
	r.teardownLive(ctx)
	return true, "negotiated " + codec
}

// scenario488AckThenBye (P2 W3, §11.2.1): points the daemon at a local
// non-compliant UAS stub (noncompliant_uas.go) that answers every INVITE
// with an SDP offering a codec the daemon never offered (opus, payload type 111) — Asterisk
// itself will never misbehave this way on demand, so the stub is the oracle.
// Asserts the daemon reacts entirely locally: it ACKs the stub's 200 OK,
// terminates with media_negotiation_failed while still reporting the peer's
// genuine 200 last_response.code (the peer's own response was never itself a
// SIP error), then internally BYEs the stub — and that the stub observed
// that ACK strictly before the BYE, with exactly one INVITE (no retransmit).
func scenario488AckThenBye(ctx context.Context, r *rig) (bool, string) {
	stub, err := startNonCompliantUAS(r.cfg.localAddr)
	if err != nil {
		return false, "startNonCompliantUAS: " + err.Error()
	}
	defer stub.Close()

	ua, err := r.createDirectUA(ctx)
	if err != nil {
		return false, "createDirectUA: " + err.Error()
	}
	defer func() { _, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": ua}) }()

	handle, err := r.dialURI(ctx, ua, stub.SIPTarget())
	if err != nil {
		return false, "dialURI: " + err.Error()
	}
	st, err := r.waitTerminal(ctx, handle, 8*time.Second)
	if err != nil {
		return false, "waitTerminal: " + err.Error()
	}
	if callState(st) != "terminated" || termReason(st) != "media_negotiation_failed" {
		return false, fmt.Sprintf("state/reason: %s/%s", callState(st), termReason(st))
	}
	if code := lastCode(st); code != 200 {
		return false, fmt.Sprintf("last_response.code=%d, want 200", code)
	}
	if !stub.SawAckBeforeBye() || stub.InviteCount() != 1 {
		return false, fmt.Sprintf("stub ordering/count violated: ackBeforeBye=%v inviteCount=%d",
			stub.SawAckBeforeBye(), stub.InviteCount())
	}
	return true, "ack-then-bye confirmed (media_negotiation_failed, last_response.code 200)"
}

// scenarioEchoQuality (P2 W4, §14.5/§6.5, R4/R7/R10): dial the Asterisk echo
// extension (600, Echo()) with a dedicated, short-lived daemon's hidden tone
// source feeding TX (SIPCLIENT_MCP_TX_TONE_HZ). Asserts the call answers, RTP
// flows both ways (packets_received climbs), and quality_get is a clean
// tier-1 readout: tier 1, mos_lqo null, near-zero loss, plausible MOS, zero
// srtp_auth_failures on a plain-RTP call.
//
// CF-026: this used to run against the ONE shared gate daemon, which had the
// tone knob on for its ENTIRE lifetime (daemon.go's old unconditional env
// var) — so every OTHER scenario's "silence" was actually a continuous
// near-full-scale 1 kHz tone too, including the DTMF-vs-Asterisk-ext-602
// scenarios that depend on a real independent detector reading real audio
// content over the wire. Only this scenario and scenarioPlayRecordRoundTrip
// actually need the tone (they assert on the echoed signal), so each now
// spawns its own daemon with the knob on via startToneRig (daemon.go),
// self-contained and torn down before returning; the shared gate daemon
// (r.cl) stays real-silence like production.
//
// D26 (W2): and packets_sent is asserted against a derived floor, the first
// behavioral assertion on the TX counter anywhere in the tree.
func scenarioEchoQuality(ctx context.Context, r *rig) (bool, string) {
	tr, cleanup, err := startToneRig(ctx, r)
	if err != nil {
		return false, err.Error()
	}
	defer cleanup()

	ua, err := tr.createDirectUAWithCodecs(ctx, []string{"PCMU", "PCMA"})
	if err != nil {
		return false, "createDirectUAWithCodecs: " + err.Error()
	}
	defer func() { _, _ = tr.cl.call(ctx, "ua_destroy", map[string]any{"ua": ua}) }()

	handle, err := tr.dial(ctx, ua, "600")
	if err != nil {
		return false, "dial 600: " + err.Error()
	}
	if _, err := tr.waitState(ctx, handle, "answered", 8*time.Second); err != nil {
		return false, "waitState answered: " + err.Error()
	}
	// Let real RTP flow both ways through the echo for a couple of seconds.
	sleepCtx(ctx, 2500*time.Millisecond)

	q, err := tr.cl.callOK(ctx, "quality_get", map[string]any{"call": handle})
	if err != nil {
		return false, "quality_get: " + err.Error()
	}
	if tier := num(q["tier"]); tier != 1 {
		return false, fmt.Sprintf("tier=%d want 1", tier)
	}
	if v, ok := q["mos_lqo"]; !ok || v != nil {
		return false, "mos_lqo must be present and null on a tier-1 readout"
	}
	if rx := num(q["packets_received"]); rx <= 0 {
		return false, fmt.Sprintf("packets_received=%d, echo returned no RTP", rx)
	}
	// D26 (P4-W2-06): the TX direction, asserted for the first time. The RX check
	// above proves the echo returned RTP; it says nothing about what we SENT, so a
	// TX path that stalled after a handful of packets — or a packets_sent counter
	// wired to the wrong accumulator field — passed this scenario unnoticed.
	//
	// THE FLOOR IS DERIVED, NOT GUESSED. PCMU at the 20 ms ptime this UA
	// negotiates is 50 packets/second, and the sleep above is 2500 ms, so a
	// healthy TX stream is ~125 packets. 50 is a deliberately generous floor
	// (40% of nominal) that still cannot be met by a stream that stopped early,
	// which is the failure being excluded.
	tx := num(q["packets_sent"])
	if tx <= 0 {
		return false, fmt.Sprintf("packets_sent=%d — we transmitted no RTP at all on an answered call", tx)
	}
	if tx < 50 {
		return false, fmt.Sprintf("packets_sent=%d after %s of media; PCMU at 20ms ptime is 50 pkt/s, "+
			"so a healthy TX stream is ~125 — this one stalled", tx, 2500*time.Millisecond)
	}
	if under := num(q["tx_underruns"]); under != 0 {
		return false, fmt.Sprintf("tx_underruns=%d on a clean echo path; the TX pump starved", under)
	}
	if loss := numf(q["loss_pct"]); loss > 5.0 {
		return false, fmt.Sprintf("loss_pct=%.2f too high for a clean echo path", loss)
	}
	if mos := numf(q["mos_estimate"]); mos < 3.5 {
		return false, fmt.Sprintf("mos_estimate=%.2f implausibly low for a clean echo", mos)
	}
	if af := num(q["srtp_auth_failures"]); af != 0 {
		return false, fmt.Sprintf("srtp_auth_failures=%d on a plain-RTP call", af)
	}
	// No r.teardownLive(ctx) here: this scenario's call lives on the tone
	// daemon (tr), not the shared gate daemon (r) — defer toneD.stop() above
	// tears the whole thing down, call included, when this function returns.
	return true, fmt.Sprintf("echo tier-1 clean: tx=%d rx=%d loss=%.2f mos=%.2f",
		tx, num(q["packets_received"]), numf(q["loss_pct"]), numf(q["mos_estimate"]))
}

// scenarioPlayRecordRoundTrip (P2 W5, §14.5/§6, R3): dial the Asterisk echo
// extension (600, Echo()), play a registered prompt into TX (wait_complete),
// THEN start/stop a recording. play and record cannot overlap — they share
// the same call's single play-or-record slot (§4 decision 6) — so this proves
// play works end-to-end against a real peer with a real negotiated codec, and
// separately proves the RX->WAV->artifact->HTTP-fetch chain carries real
// peer audio (the tone daemon's TX tone, reflected back by Echo() — CF-026,
// see scenarioEchoQuality's doc comment: this runs on its own startToneRig
// daemon, not the shared gate daemon, for the same reason that one does).
// It does NOT prove the specific played prompt's bytes are what comes back
// in the recording, since play completes and releases the slot before
// recording starts.
func scenarioPlayRecordRoundTrip(ctx context.Context, r *rig) (bool, string) {
	tr, cleanup, err := startToneRig(ctx, r)
	if err != nil {
		return false, err.Error()
	}
	defer cleanup()

	ua, err := tr.createDirectUAWithCodecs(ctx, []string{"PCMU", "PCMA"})
	if err != nil {
		return false, "createDirectUAWithCodecs: " + err.Error()
	}
	defer func() { _, _ = tr.cl.call(ctx, "ua_destroy", map[string]any{"ua": ua}) }()

	handle, err := tr.dial(ctx, ua, "600")
	if err != nil {
		return false, "dial 600: " + err.Error()
	}
	if _, err := tr.waitState(ctx, handle, "answered", 8*time.Second); err != nil {
		return false, "waitState answered: " + err.Error()
	}

	// Play first, blocking until it completes and releases the play-or-record
	// slot -- Play and RecordStart cannot overlap (§4 decision 6).
	playOut, err := tr.cl.callOK(ctx, "media_play", map[string]any{
		"call": handle, "prompt": "prompt-1", "wait_complete": true,
	})
	if err != nil {
		return false, "media_play: " + err.Error()
	}
	if num(playOut["duration_ms"]) <= 0 {
		return false, "media_play duration_ms not positive"
	}

	// Now record RX for a bit; Echo() keeps reflecting the tone daemon's TX
	// tone back, so the recording will contain real (non-silent) audio.
	if _, err := tr.cl.callOK(ctx, "media_record_start", map[string]any{"call": handle}); err != nil {
		return false, "media_record_start: " + err.Error()
	}
	sleepCtx(ctx, 500*time.Millisecond)
	stop, err := tr.cl.callOK(ctx, "media_record_stop", map[string]any{"call": handle})
	if err != nil {
		return false, "media_record_stop: " + err.Error()
	}

	// Header assertions from the tool payload.
	format, _ := stop["format"].(map[string]any)
	if num(format["sample_rate"]) != 8000 || num(format["channels"]) != 1 || num(format["bits"]) != 16 {
		return false, fmt.Sprintf("format=%v want 8000/1/16", format)
	}
	if num(stop["bytes"]) <= 44 {
		return false, fmt.Sprintf("recorded bytes=%d, no audio captured", num(stop["bytes"]))
	}
	if num(stop["duration_ms"]) <= 0 {
		return false, "duration_ms not positive"
	}

	// Fetch the artifact bytes and confirm the RIFF/WAVE magic and non-silent
	// content (the echo returned real energy, not all zeros).
	uri, _ := stop["uri"].(string)
	body, err := tr.cl.fetchArtifact(ctx, uri)
	if err != nil {
		return false, "fetch artifact: " + err.Error()
	}
	if len(body) < 44 || string(body[0:4]) != "RIFF" || string(body[8:12]) != "WAVE" {
		return false, "artifact is not a RIFF/WAVE file"
	}
	var nonzero int
	for i := 44; i+1 < len(body); i += 2 {
		if body[i] != 0 || body[i+1] != 0 {
			nonzero++
		}
	}
	if nonzero == 0 {
		return false, "recorded WAV is entirely silent; echo round-trip produced no audio"
	}
	// No r.teardownLive(ctx) here: this scenario's call lives on the tone
	// daemon (tr), not the shared gate daemon (r) — defer cleanup() above
	// tears the whole thing down, call included, when this function returns.
	return true, fmt.Sprintf("play/record round-trip: play_duration=%dms, %d bytes, %d ms, %d non-zero samples",
		num(playOut["duration_ms"]), num(stop["bytes"]), num(stop["duration_ms"]), nonzero)
}
