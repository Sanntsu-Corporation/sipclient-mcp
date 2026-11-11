package main

// scenarios_cf6b.go — cf6-b-indialog live scenarios. Local SIPp is the callee
// of a throwaway direct UA on Lane D's port base (cf5dUAAddr, cf5dSIPpPort).

import (
	"context"
	"fmt"
	"time"
)

const cf6bTarget = "sip:cf6b@127.0.0.1:15470"

// cf6bDial starts the named cf6-b SIPp callee and dials it from a throwaway UA.
func (r *rig) cf6bDial(ctx context.Context, scenario string, bound time.Duration) (string, string, *sippRun, func(), error) {
	ua, done, err := r.cf5dUA(ctx, nil)
	if err != nil {
		return "", "", nil, nil, err
	}
	s, err := startSIPp(ctx, "cf6-b/"+scenario, bound, "")
	if err != nil {
		done()
		return "", "", nil, nil, err
	}
	sleepCtx(ctx, time.Second) // SIPp binds its UDP socket
	call, err := r.dialURI(ctx, ua, cf6bTarget)
	if err != nil {
		done()
		return "", "", nil, nil, fmt.Errorf("dial %s: %w", scenario, err)
	}
	return ua, call, s, done, nil
}

// scenarioCF6bInDialogRefresh (CF-193, CF-207, CF-165, CF-186, CF-184): the
// SIPp callee checks the ACK's request line and Route, our offer in the 200 to
// an offerless re-INVITE, the live answer to an unchanged re-offer and the
// BYE's Request-URI (the refreshed Contact).
func scenarioCF6bInDialogRefresh(ctx context.Context, r *rig) (bool, string) {
	_, call, s, done, err := r.cf6bDial(ctx, "reoffer-uas", 60*time.Second)
	if err != nil {
		return false, err.Error()
	}
	defer done()
	if st, err := r.waitState(ctx, call, "answered", 10*time.Second); err != nil || callState(st) != "answered" {
		return false, fmt.Sprintf("not answered (err=%v state=%q reason=%q)", err, callState(st), termReason(st))
	}
	sleepCtx(ctx, 8*time.Second) // both re-INVITEs done; SIPp waits for our BYE
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": call}); err != nil {
		return false, "call_hangup: " + err.Error()
	}
	if err := s.wait(ctx); err != nil {
		return false, err.Error()
	}
	st, err := r.waitTerminal(ctx, call, 5*time.Second)
	if err != nil {
		return false, err.Error()
	}
	if termReason(st) != "local_hangup" {
		return false, fmt.Sprintf("termination_reason=%q, want local_hangup", termReason(st))
	}
	return true, "ACK to the Contact via the Route; offerless re-INVITE got 0 8 101 and the ACK answer; unchanged re-offer answered with the live codec; BYE to the refreshed Contact"
}

// scenarioCF6bReInviteNoAck (CF-208): the 200 to the peer's re-INVITE is
// retransmitted and, with no ACK, our BYE ends the dialog.
func scenarioCF6bReInviteNoAck(ctx context.Context, r *rig) (bool, string) {
	_, call, s, done, err := r.cf6bDial(ctx, "reinvite-noack-uas", 75*time.Second)
	if err != nil {
		return false, err.Error()
	}
	defer done()
	if err := s.wait(ctx); err != nil {
		return false, err.Error()
	}
	st, err := r.waitTerminal(ctx, call, 5*time.Second)
	if err != nil {
		return false, "call not terminated after the no-ACK BYE: " + err.Error()
	}
	if termReason(st) != "transport_failure" {
		return false, fmt.Sprintf("termination_reason=%q, want transport_failure", termReason(st))
	}
	return true, "re-INVITE 2xx re-sent, no ACK, our BYE sent, call terminated transport_failure"
}
