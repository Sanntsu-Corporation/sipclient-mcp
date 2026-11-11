package main

// scenarios_cf6c.go — round 6 lane C (cf6-c-transport) standing-gate scenarios.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// scenarioCF190OversizeUDPInviteInLadder (CF-190, CF-106): the oversize INVITE a
// UDP UA sends over TCP is now tapped, so call_ladder holds it, framed as TCP.
func scenarioCF190OversizeUDPInviteInLadder(ctx context.Context, r *rig) (bool, string) {
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
	msgs, err := r.ladderMessages(ctx, call)
	if err != nil {
		return false, "call_ladder: " + err.Error()
	}
	found := false
	for _, m := range msgs {
		if m.Method == "INVITE" && strings.Contains(m.Serialized, "SIP/2.0/TCP") && strings.Contains(m.Serialized, "X-Rfcfix1-Pad") {
			found = true
		}
	}
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": call}); err != nil {
		return false, "call_hangup: " + err.Error()
	}
	if !found {
		return false, fmt.Sprintf("call_ladder (%d messages) has no INVITE over SIP/2.0/TCP carrying X-Rfcfix1-Pad", len(msgs))
	}
	return true, "the oversize INVITE sent over TCP is in call_ladder, labelled SIP/2.0/TCP"
}

// scenarioCF185SipsRegistrarRefusedOnUDP (CF-185): ua_create refuses a sips:
// registrar on a udp UA before any UA exists, so no SIP is sent.
func scenarioCF185SipsRegistrarRefusedOnUDP(ctx context.Context, r *rig) (bool, string) {
	env, err := r.cl.call(ctx, "ua_create", map[string]any{
		"mode": "register", "transport": "udp",
		"aor":       fmt.Sprintf("sip:cf6c@%s", r.cfg.asteriskIP),
		"registrar": fmt.Sprintf("sips:%s:5071", r.cfg.asteriskIP),
	})
	if err != nil {
		return false, "ua_create: " + err.Error()
	}
	if h := str(env["ua_handle"]); h != "" {
		_, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": h})
		return false, "ua_create returned a UA handle for a sips: registrar on udp"
	}
	if ok, _ := env["ok"].(bool); ok || str(env["code"]) != string(apierr.CodeInvalidArgument) || !strings.Contains(str(env["message"]), "sips:") {
		return false, fmt.Sprintf("ua_create envelope = %v, want ok:false invalid_argument naming sips:", env)
	}
	return true, "refused: " + str(env["message"])
}
