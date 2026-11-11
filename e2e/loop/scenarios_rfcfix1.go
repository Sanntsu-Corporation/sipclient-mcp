package main

// scenarios_rfcfix1.go — the rfc-fix-1 wave's standing UDP-gate scenarios. They
// run against the daemon the gate builds from the checked-out branch.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// scenarioOversizeDialGoesOverTCP (CF-106, RFC 3261 18.1.1): an INVITE larger
// than 1300 bytes from a UDP UA is sent over TCP instead of failing. The pad
// header takes the request over the limit (validateHeaders sets no length
// limit); the call must still reach answered on the echo extension.
func scenarioOversizeDialGoesOverTCP(ctx context.Context, r *rig) (bool, string) {
	toURI := fmt.Sprintf("sip:600@%s:%d", r.cfg.asteriskIP, r.cfg.dialPort)
	env, err := r.cl.callOK(ctx, "call_dial", map[string]any{
		"ua": r.directUA, "to_uri": toURI,
		"headers": map[string]string{"X-Rfcfix1-Pad": strings.Repeat("x", 1400)},
	})
	if err != nil {
		return false, "oversize dial: " + err.Error()
	}
	call := str(env["call_handle"])
	st, err := r.waitState(ctx, call, "answered", 8*time.Second)
	if err != nil || callState(st) != "answered" {
		return false, fmt.Sprintf("oversize dial did not answer (err=%v state=%q reason=%q)", err, callState(st), termReason(st))
	}
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": call}); err != nil {
		return false, "call_hangup: " + err.Error()
	}
	return true, "a 1400-byte header INVITE from a UDP UA reached answered (sent over TCP)"
}

// scenarioDurationCapSendsBye (CF-092): max_duration_s ends the dialog on the
// wire. The call ends within 10 s with policy_timeout, and the rig's best-effort
// channel list shows nothing left for it.
func scenarioDurationCapSendsBye(ctx context.Context, r *rig) (bool, string) {
	toURI := fmt.Sprintf("sip:600@%s:%d", r.cfg.asteriskIP, r.cfg.dialPort)
	env, err := r.cl.callOK(ctx, "call_dial", map[string]any{
		"ua": r.directUA, "to_uri": toURI, "max_duration_s": 5,
	})
	if err != nil {
		return false, "capped dial: " + err.Error()
	}
	call := str(env["call_handle"])
	st, err := r.waitTerminal(ctx, call, 10*time.Second)
	if err != nil {
		return false, "capped call did not end: " + err.Error()
	}
	if termReason(st) != "policy_timeout" {
		return false, fmt.Sprintf("termination_reason=%q, want policy_timeout", termReason(st))
	}
	sleepCtx(ctx, time.Second)
	if out, ok := r.asteriskRX(ctx, "core show channels concise"); ok && strings.TrimSpace(out) != "" {
		return false, "the rig still has a channel after the cap ended the call: " + strings.TrimSpace(out)
	}
	return true, "call ended with policy_timeout and the rig has no channel left"
}
