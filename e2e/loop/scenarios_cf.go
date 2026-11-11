package main

// scenarios_cf.go — the carry-forward clearing sub-wave's gate scenarios.

import (
	"context"
	"fmt"
	"time"
)

// blackHoleTarget is in TEST-NET-1 (RFC 5737, documentation range): nothing
// answers there, so a dial to it never gets a provisional and ends only at the
// UA's own dial timeout (default 32 s).
const blackHoleTarget = "sip:x@192.0.2.1"

// scenarioDialTimeoutSiblingSurvives (CF-037): a dial that times out ends only
// its own dialog. An answered call on the same UA (echo, 600) must still be
// answered, and hang up cleanly, after a black-hole dial has timed out. The same
// holds for a second black-hole dial hung up at once (no provisional yet), whose
// own timeout fires after the caller has already let go of it.
//
// If 192.0.2.1 is not a silent black hole from this workstation (an ICMP error
// ends the dial early) the dial still ends its own dialog; the result line says
// how long the first dial took so the report can tell which happened.
func scenarioDialTimeoutSiblingSurvives(ctx context.Context, r *rig) (bool, string) {
	sibling, err := r.dial(ctx, r.directUA, "600")
	if err != nil {
		return false, "dial 600: " + err.Error()
	}
	if st, err := r.waitState(ctx, sibling, "answered", 8*time.Second); err != nil || callState(st) != "answered" {
		return false, fmt.Sprintf("600 did not answer (err=%v state=%q)", err, callState(st))
	}

	start := time.Now()
	timedOut, err := r.dialURI(ctx, r.directUA, blackHoleTarget)
	if err != nil {
		return false, "dial black hole: " + err.Error()
	}
	hungUp, err := r.dialURI(ctx, r.directUA, blackHoleTarget)
	if err != nil {
		return false, "dial black hole (hung up at once): " + err.Error()
	}
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": hungUp}); err != nil {
		return false, "call_hangup on the no-provisional dial: " + err.Error()
	}

	// UA default dial timeout 32 s, plus margin.
	if _, err := r.waitTerminal(ctx, timedOut, 42*time.Second); err != nil {
		return false, "black-hole dial did not end: " + err.Error()
	}
	took := time.Since(start)
	// The hung-up dial's own timeout fires about when the first one's does.
	sleepCtx(ctx, 2*time.Second)

	st, err := r.callStatus(ctx, sibling)
	if err != nil {
		return false, "sibling call_status: " + err.Error()
	}
	if callState(st) != "answered" {
		return false, fmt.Sprintf("the answered 600 call is %q (reason %q) after the black-hole dials ended, want answered",
			callState(st), termReason(st))
	}
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": sibling}); err != nil {
		return false, "call_hangup on the surviving 600 call: " + err.Error()
	}
	return true, fmt.Sprintf("600 call stayed answered and hung up cleanly; black-hole dial ended after %s", took.Round(time.Second))
}
