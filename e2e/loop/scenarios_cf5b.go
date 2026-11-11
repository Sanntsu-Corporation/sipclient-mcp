package main

// scenarios_cf5b.go -- the cf5-b wave's standing UDP-gate scenario: the
// x-in-udp loop shape, where Asterisk
// bridges our direct UA to our register UA and both legs run session timers.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// scenarioSessionTimerAsteriskLoopOrientation: the gate's direct UA dials ext 720,
// Asterisk bridges to a 90/90 register UA, which answers. After ~100 s (two of
// our refreshes on leg 2) leg 2 must still be answered, report itself as the
// refresher (dialog orientation "uas", we answered), carry session_refresh events,
// and our UPDATEs must say refresher=uac with Min-SE 90 (RFC 4028 7.4). The wire
// verdicts V1-V4 are read from the capture. It runs LAST: its REGISTER displaces
// the gate's contact (max_contacts = 1), which it restores.
func scenarioSessionTimerAsteriskLoopOrientation(ctx context.Context, r *rig) (bool, string) {
	// Free the AOR's single contact for this scenario's 90/90 register UA.
	if r.registerUA != "" {
		_, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": r.registerUA})
		r.registerUA = ""
	}
	restore := func() {
		if ua, err := r.createRegisterUA(ctx); err == nil {
			r.registerUA = ua
		}
	}
	reg, err := r.createUA(ctx, "register", "e2e-uac-register-st90", r.cfg.localAddr)
	if err != nil {
		restore()
		return false, "ua_create(e2e-uac-register-st90): " + err.Error()
	}
	defer func() {
		_, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": reg})
		restore()
	}()

	before := r.registerCallHandles(ctx, reg)
	leg1, err := r.dial(ctx, r.directUA, "720")
	if err != nil {
		return false, "dial 720: " + err.Error()
	}
	leg2, err := r.waitNewInbound(ctx, reg, before, 10*time.Second)
	if err != nil {
		return false, "waitNewInbound: " + err.Error()
	}
	if _, err := r.cl.callOK(ctx, "call_answer", map[string]any{"call": leg2}); err != nil {
		return false, "call_answer: " + err.Error()
	}
	if _, err := r.waitState(ctx, leg1, "answered", 10*time.Second); err != nil {
		return false, "waitState leg1 answered: " + err.Error()
	}
	fmt.Printf("cf5-b leg1=%s leg2=%s\n", leg1, leg2)

	sleepCtx(ctx, 100*time.Second)

	st, err := r.callStatus(ctx, leg2)
	if err != nil {
		return false, "call_status leg2: " + err.Error()
	}
	if callState(st) != "answered" {
		return false, fmt.Sprintf("leg 2 state=%q ~100 s in, want answered", callState(st))
	}
	tim, ok := st["session_timer"].(map[string]any)
	if !ok {
		return false, "leg 2 call_status.session_timer absent"
	}
	if str(tim["refresher"]) != "uas" || tim["armed"] != true || num(tim["interval_s"]) != 90 {
		return false, fmt.Sprintf("leg 2 session_timer=%v, want refresher=uas armed interval_s=90", tim)
	}

	evs, err := r.cl.callOK(ctx, "call_events", map[string]any{"call": leg2})
	if err != nil {
		return false, "call_events: " + err.Error()
	}
	refreshes := 0
	if list, ok := evs["events"].([]any); ok {
		for _, e := range list {
			m, _ := e.(map[string]any)
			if str(m["type"]) != "session_refresh" {
				continue
			}
			refreshes++
			if d, _ := m["detail"].(map[string]any); str(d["refresher"]) != "uas" {
				return false, fmt.Sprintf("session_refresh refresher=%q, want uas", str(d["refresher"]))
			}
		}
	}
	if refreshes < 2 {
		return false, fmt.Sprintf("%d session_refresh events on leg 2, want at least 2", refreshes)
	}

	msgs, err := r.ladderMessages(ctx, leg2)
	if err != nil {
		return false, "ladder leg2: " + err.Error()
	}
	ours := 0
	for _, m := range msgs {
		if m.Method == "UPDATE" && strings.HasPrefix(m.Serialized, "UPDATE ") &&
			strings.Contains(m.Serialized, "refresher=uac") && hasHeaderLine(m.Serialized, "Min-SE") {
			ours++
		}
	}
	if ours < 2 {
		return false, fmt.Sprintf("%d UPDATE requests with refresher=uac and Min-SE on leg 2's ladder, want at least 2", ours)
	}
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": leg1}); err != nil {
		return false, "call_hangup leg1: " + err.Error()
	}
	if _, err := r.waitTerminal(ctx, leg2, 15*time.Second); err != nil {
		return false, "leg 2 did not end: " + err.Error()
	}
	return true, fmt.Sprintf("leg 2 answered at ~100 s, refresher=uas armed, %d session_refresh events", refreshes)
}
