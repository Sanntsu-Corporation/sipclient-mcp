package main

// scenarios_cf5a.go — round 5 Lane A (cf5-a-sdp-media) live scenarios against
// the lab Asterisk. The wire claims (PT, source, SDP shape) are confirmed from
// a packet capture taken around the run; each scenario asserts what the MCP
// tool results can show. UA ports 5361-5364 are Lane A's base.
//
// The inbound answer shape (CF-137, CF-141, CF-143) is read from the capture of
// the standing "#3 caller-id" scenario, which already runs the 720 loop.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// cf5aUA creates a direct-mode UA on a Lane A port.
func cf5aUA(ctx context.Context, r *rig, account, transport string, port int, codecs []string) (string, error) {
	args, err := uaCreateArgs("direct", account, r.cfg.asteriskIP, transport, fmt.Sprintf("%s:%d", r.cfg.localAddr, port), codecs)
	if err != nil {
		return "", err
	}
	env, err := r.cl.callOK(ctx, "ua_create", args)
	if err != nil {
		return "", err
	}
	return str(env["ua_handle"]), nil
}

func cf5aDestroy(ctx context.Context, r *rig, ua string) {
	_, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": ua})
}

// cf5aEchoCall dials ext 600 on the given port from ua, and returns the answered
// call's handle, or a failure reason.
func cf5aEchoCall(ctx context.Context, r *rig, ua string, port int, extra map[string]any) (string, map[string]any, string) {
	args := map[string]any{"ua": ua, "to_uri": fmt.Sprintf("sip:600@%s:%d", r.cfg.asteriskIP, port)}
	for k, v := range extra {
		args[k] = v
	}
	env, err := r.cl.call(ctx, "call_dial", args)
	if err != nil {
		return "", nil, "call_dial: " + err.Error()
	}
	if ok, _ := env["ok"].(bool); !ok {
		return "", env, fmt.Sprintf("call_dial refused: %s (%s)", str(env["code"]), str(env["message"]))
	}
	call := str(env["call_handle"])
	st, err := r.waitState(ctx, call, "answered", 8*time.Second)
	if err != nil || callState(st) != "answered" {
		return call, st, fmt.Sprintf("not answered (err=%v state=%q reason=%q code=%d)", err, callState(st), termReason(st), lastCode(st))
	}
	return call, st, ""
}

func cf5aQuality(ctx context.Context, r *rig, call string) (map[string]any, error) {
	return r.cl.callOK(ctx, "quality_get", map[string]any{"call": call})
}

// scenarioCF5aPTAndStrictSource: our audio goes at the PT Asterisk answered and
// RX takes only Asterisk's signalled source.
func scenarioCF5aPTAndStrictSource(ctx context.Context, r *rig) (bool, string) {
	ua, err := cf5aUA(ctx, r, r.cfg.directP, "udp", 5361, []string{"PCMA", "PCMU"})
	if err != nil {
		return false, "ua_create: " + err.Error()
	}
	defer cf5aDestroy(ctx, r, ua)
	call, st, why := cf5aEchoCall(ctx, r, ua, r.cfg.dialPort, nil)
	if why != "" {
		return false, why
	}
	sleepCtx(ctx, 2500*time.Millisecond)
	q, err := cf5aQuality(ctx, r, call)
	if err != nil {
		return false, "quality_get: " + err.Error()
	}
	if rx := num(q["packets_received"]); rx <= 0 {
		return false, fmt.Sprintf("packets_received=%d: nothing accepted from the signalled source", rx)
	}
	if rg := num(q["rogue_source_packets"]); rg != 0 {
		return false, fmt.Sprintf("rogue_source_packets=%d: Asterisk sent from an address other than its SDP's", rg)
	}
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": call}); err != nil {
		return false, "call_hangup: " + err.Error()
	}
	return true, fmt.Sprintf("codec %s, rx=%d rogue=0", str(st["codec"]), num(q["packets_received"]))
}

// scenarioCF5aDTMFEventsList: Asterisk lists 0-16, so 1 and A (events 1, 12) go.
func scenarioCF5aDTMFEventsList(ctx context.Context, r *rig) (bool, string) {
	ua, err := cf5aUA(ctx, r, r.cfg.directP, "udp", 5362, []string{"PCMU"})
	if err != nil {
		return false, "ua_create: " + err.Error()
	}
	defer cf5aDestroy(ctx, r, ua)
	call, err := r.dial(ctx, ua, "602")
	if err != nil {
		return false, "dial 602: " + err.Error()
	}
	if st, err := r.waitState(ctx, call, "answered", 10*time.Second); err != nil || callState(st) != "answered" {
		return false, fmt.Sprintf("602 not answered (err=%v state=%q)", err, callState(st))
	}
	sleepCtx(ctx, 1500*time.Millisecond)
	out, err := r.cl.callOK(ctx, "dtmf_send", map[string]any{"call": call, "digits": "1A", "mode": "rfc2833"})
	if err != nil {
		return false, "dtmf_send 1A: " + err.Error()
	}
	if n := num(out["digits_sent"]); n != 2 {
		return false, fmt.Sprintf("digits_sent=%d want 2", n)
	}
	return true, "dtmf_send 1A rfc2833 accepted (events 1 and 12 within Asterisk's list)"
}

// scenarioCF5aSRTPRequiredTLS: SRTP required over TLS against the SDES endpoint.
func scenarioCF5aSRTPRequiredTLS(ctx context.Context, r *rig) (bool, string) {
	ua, err := cf5aUA(ctx, r, "e2e-uac-srtp-required", "tls", 5363, []string{"PCMU"})
	if err != nil {
		return false, "ua_create: " + err.Error()
	}
	defer cf5aDestroy(ctx, r, ua)
	call, st, why := cf5aEchoCall(ctx, r, ua, 5071, nil)
	if why != "" {
		return false, why
	}
	if st["srtp"] != true {
		return false, fmt.Sprintf("call_status srtp=%v, want true", st["srtp"])
	}
	sleepCtx(ctx, 2500*time.Millisecond)
	q, err := cf5aQuality(ctx, r, call)
	if err != nil {
		return false, "quality_get: " + err.Error()
	}
	if num(q["packets_received"]) <= 0 || num(q["srtp_auth_failures"]) != 0 {
		return false, fmt.Sprintf("rx=%d srtp_auth_failures=%d", num(q["packets_received"]), num(q["srtp_auth_failures"]))
	}
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": call}); err != nil {
		return false, "call_hangup: " + err.Error()
	}
	return true, fmt.Sprintf("SRTP over TLS: rx=%d auth_failures=0", num(q["packets_received"]))
}

// scenarioCF5aSRTPOptionalFallback: an optional UA over UDP offers a key to a
// plain endpoint, which answers without one; the call runs plain.
func scenarioCF5aSRTPOptionalFallback(ctx context.Context, r *rig) (bool, string) {
	ua, err := cf5aUA(ctx, r, "e2e-uac-direct-srtp-optional", "udp", 5364, []string{"PCMU"})
	if err != nil {
		return false, "ua_create: " + err.Error()
	}
	defer cf5aDestroy(ctx, r, ua)
	call, st, why := cf5aEchoCall(ctx, r, ua, r.cfg.dialPort, nil)
	if why != "" {
		return false, why
	}
	if st["srtp"] != false {
		return false, fmt.Sprintf("call_status srtp=%v, want false (plain fallback)", st["srtp"])
	}
	sleepCtx(ctx, 2000*time.Millisecond)
	q, err := cf5aQuality(ctx, r, call)
	if err != nil {
		return false, "quality_get: " + err.Error()
	}
	if num(q["packets_received"]) <= 0 {
		return false, "no media after the plain fallback"
	}
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": call}); err != nil {
		return false, "call_hangup: " + err.Error()
	}
	return true, fmt.Sprintf("optional offer answered plain: srtp=false rx=%d", num(q["packets_received"]))
}

// scenarioCF5aSRTPOptionalTLSProbe: optional over TLS against the SDES endpoint.
// Probed live: Asterisk accepts the
// RTP/AVP offer with a=crypto and answers a key, so the call runs SRTP.
func scenarioCF5aSRTPOptionalTLSProbe(ctx context.Context, r *rig) (bool, string) {
	ua, err := cf5aUA(ctx, r, "e2e-uac-srtp-optional", "tls", 5363, []string{"PCMU"})
	if err != nil {
		return false, "ua_create: " + err.Error()
	}
	defer cf5aDestroy(ctx, r, ua)
	call, st, why := cf5aEchoCall(ctx, r, ua, 5071, nil)
	if why != "" {
		return false, "optional offer to the SDES endpoint: " + why
	}
	defer func() { _, _ = r.cl.call(ctx, "call_hangup", map[string]any{"call": call}) }()
	if st["srtp"] != true {
		return false, fmt.Sprintf("call_status srtp=%v, want true (Asterisk answered a key)", st["srtp"])
	}
	return true, "optional offer accepted by the SDES endpoint, srtp=true"
}

// scenarioCF5aPerCallSRTP: a per-call srtp only tightens.
func scenarioCF5aPerCallSRTP(ctx context.Context, r *rig) (bool, string) {
	ua, err := cf5aUA(ctx, r, "e2e-uac-direct-srtp-optional", "udp", 5364, []string{"PCMU"})
	if err != nil {
		return false, "ua_create: " + err.Error()
	}
	defer cf5aDestroy(ctx, r, ua)
	// Loosening is refused before any INVITE.
	env, err := r.cl.call(ctx, "call_dial", map[string]any{
		"ua": ua, "to_uri": fmt.Sprintf("sip:600@%s:%d", r.cfg.asteriskIP, r.cfg.dialPort), "srtp": "disabled"})
	if err != nil {
		return false, "call_dial(disabled): " + err.Error()
	}
	if ok, _ := env["ok"].(bool); ok || str(env["code"]) != string(apierr.CodeInvalidArgument) || !strings.Contains(str(env["message"]), "loosen") {
		return false, fmt.Sprintf("srtp=disabled on an optional UA was not refused invalid_argument: %v", env)
	}
	// Tightening is offered as RTP/SAVP; the plain endpoint refuses it (probed
	// live: 488), so the call fails with last response 488.
	_, st, why := cf5aEchoCall(ctx, r, ua, r.cfg.dialPort, map[string]any{"srtp": "required"})
	if why == "" {
		return false, "a required (RTP/SAVP) offer to the plain endpoint was answered"
	}
	if callState(st) != "failed" || lastCode(st) != 488 {
		return false, fmt.Sprintf("required offer outcome state=%q code=%d, want failed/488 (%s)", callState(st), lastCode(st), why)
	}
	return true, "loosening refused invalid_argument; per-call required offered RTP/SAVP and drew 488"
}
