package main

// scenarios_cf6a.go — CF clearing round 6, Lane A (cf6-a-sdp) live scenarios.
// Scenario 1 runs against the lab Asterisk; 2-4 drive a local SIPp against a
// throwaway direct UA (the cf5-d ports, scenarios run one at a time). Wire
// verdicts (keys, the 488 timing, no DNS query, the answer's crypto tag) are
// read from a packet capture of the run (Rule 21); PASS/FAIL here covers what
// the MCP surface shows. UA port 5371 is Lane A's.

import (
	"context"
	"fmt"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// scenarioCF198Redirect302SRTP: an SRTP-required dial follows Asterisk's 302
// and the second offer carries a fresh key (checked on the capture).
func scenarioCF198Redirect302SRTP(ctx context.Context, r *rig) (bool, string) {
	ua, err := cf5aUA(ctx, r, "e2e-uac-srtp-required-udp", "udp", 5371, []string{"PCMU"})
	if err != nil {
		return false, "ua_create: " + err.Error()
	}
	defer cf5aDestroy(ctx, r, ua)
	target := fmt.Sprintf("PJSIP/sip:600@%s:%d", r.cfg.asteriskIP, r.cfg.dialPort)
	return withRigExtension(ctx, r, "cf6a302", []string{"Transfer," + target}, func() (bool, string) {
		call, err := r.dialURI(ctx, ua, fmt.Sprintf("sip:cf6a302@%s:%d", r.cfg.asteriskIP, r.cfg.dialPort))
		if err != nil {
			return false, "dial: " + err.Error()
		}
		st, err := r.waitState(ctx, call, "answered", 10*time.Second)
		if err != nil || callState(st) != "answered" {
			return false, fmt.Sprintf("not answered (err=%v state=%q reason=%q code=%d)", err, callState(st), termReason(st), lastCode(st))
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
		return true, fmt.Sprintf("SRTP dial followed the 302: rx=%d auth_failures=0", num(q["packets_received"]))
	})
}

// cf6aRefuse runs a SIPp UAC scenario whose offer the UA must refuse: the gate
// answers the ringing call and requires media_negotiation / no_common_codec.
func cf6aRefuse(ctx context.Context, r *rig, ua, scenario string) error {
	before := r.registerCallHandles(ctx, ua)
	s, err := startSIPp(ctx, scenario, 30*time.Second, cf5dUAAddr)
	if err != nil {
		return err
	}
	call, err := r.waitNewInbound(ctx, ua, before, 8*time.Second)
	if err != nil {
		return err
	}
	env, err := r.cl.call(ctx, "call_answer", map[string]any{"call": call})
	if err != nil {
		return fmt.Errorf("call_answer: %w", err)
	}
	det, _ := env["detail"].(map[string]any)
	if ok, _ := env["ok"].(bool); ok || str(env["code"]) != string(apierr.CodeMediaNegotiation) || str(det["kind"]) != "no_common_codec" {
		return fmt.Errorf("%s: call_answer = ok:%v code:%q kind:%q, want ok:false media_negotiation no_common_codec", scenario, env["ok"], str(env["code"]), str(det["kind"]))
	}
	return s.wait(ctx)
}

// scenarioCF201OfferRefusals: a hostname in c= and an out-of-range m= port each
// draw 488 (the SIPp scenario requires it); no DNS query is made (capture).
func scenarioCF201OfferRefusals(ctx context.Context, r *rig) (bool, string) {
	ua, done, err := r.cf5dUA(ctx, nil)
	if err != nil {
		return false, err.Error()
	}
	defer done()
	for _, sc := range []string{"cf6a-uac-c-hostname", "cf6a-uac-port-range"} {
		if err := cf6aRefuse(ctx, r, ua, sc); err != nil {
			return false, err.Error()
		}
	}
	return true, "c=IN IP4 media.invalid and m=audio 99999 each drew 488; call_answer media_negotiation/no_common_codec"
}

// scenarioCF210ReofferHostname: a re-INVITE naming a hostname draws 488, the
// call goes on, and the next valid re-INVITE draws 200.
func scenarioCF210ReofferHostname(ctx context.Context, r *rig) (bool, string) {
	ua, done, err := r.cf5dUA(ctx, nil)
	if err != nil {
		return false, err.Error()
	}
	defer done()
	before := r.registerCallHandles(ctx, ua)
	s, err := startSIPp(ctx, "cf6a-uac-reoffer-hostname", 30*time.Second, cf5dUAAddr)
	if err != nil {
		return false, err.Error()
	}
	call, err := r.waitNewInbound(ctx, ua, before, 8*time.Second)
	if err != nil {
		return false, err.Error()
	}
	if _, err := r.cl.callOK(ctx, "call_answer", map[string]any{"call": call}); err != nil {
		return false, "call_answer: " + err.Error()
	}
	if err := s.wait(ctx); err != nil {
		return false, err.Error()
	}
	st, err := r.waitTerminal(ctx, call, 5*time.Second)
	if err != nil || termReason(st) != "remote_bye" {
		return false, fmt.Sprintf("call ended err=%v reason=%q, want remote_bye", err, termReason(st))
	}
	return true, "hostname re-offer drew 488, the following valid re-offer 200, call ended remote_bye"
}

// scenarioCF187SDESOrder: an RTP/SAVP offer listing an unsupported suite first
// is answered with the supported line, tag 2 (the SIPp scenario checks it).
func scenarioCF187SDESOrder(ctx context.Context, r *rig) (bool, string) {
	ua, done, err := r.cf5dUA(ctx, map[string]any{"srtp": "required", "allow_cleartext_sdes": true})
	if err != nil {
		return false, err.Error()
	}
	defer done()
	before := r.registerCallHandles(ctx, ua)
	s, err := startSIPp(ctx, "cf6a-uac-sdes-order", 30*time.Second, cf5dUAAddr)
	if err != nil {
		return false, err.Error()
	}
	call, err := r.waitNewInbound(ctx, ua, before, 8*time.Second)
	if err != nil {
		return false, err.Error()
	}
	if _, err := r.cl.callOK(ctx, "call_answer", map[string]any{"call": call}); err != nil {
		return false, "call_answer: " + err.Error()
	}
	if err := s.wait(ctx); err != nil {
		return false, err.Error()
	}
	return true, "the 200 answered the SDES offer with a=crypto:2 AES_CM_128_HMAC_SHA1_80"
}
