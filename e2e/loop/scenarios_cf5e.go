package main

// scenarios_cf5e.go — CF clearing round 5, Lane E (outbound dial) live
// scenarios against the lab rig. Wire verdicts (ACK credentials, the 302's ACK
// Request-URI, the first-SDP answer) come from a packet capture of the run
// (Rule 21); PASS/FAIL here covers what the MCP surface shows.

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// withRigExtension adds a runtime dialplan extension (context e2e) made of
// steps (each "App" or "App,data"), runs fn, and always removes the extension.
// A failed add fails the scenario; a failed remove is a loud CLEANUP FAILED
// that also fails it, so a leftover extension is never silent (Rule 25).
func withRigExtension(ctx context.Context, r *rig, ext string, steps []string, fn func() (bool, string)) (bool, string) {
	if strings.TrimSpace(r.cfg.sshTarget) == "" {
		return false, "this scenario needs the rig ssh target (-ssh); it adds a runtime extension"
	}
	for i, s := range steps {
		if _, ok := r.asteriskRX(ctx, fmt.Sprintf("dialplan add extension %s,%d,%s into e2e", ext, i+1, s)); !ok {
			_, _ = r.asteriskRX(ctx, "dialplan remove extension "+ext+"@e2e")
			return false, fmt.Sprintf("dialplan add extension %s step %d (%s) failed", ext, i+1, s)
		}
	}
	ok, reason := fn()
	if _, rok := r.asteriskRX(ctx, "dialplan remove extension "+ext+"@e2e"); !rok {
		fmt.Printf("  CLEANUP FAILED: extension %s@e2e may still exist on the rig; remove it by name\n", ext)
		return false, reason + " [CLEANUP FAILED: " + ext + "]"
	}
	return ok, reason
}

// cf5eAnswerThenHangup dials toURI, waits for answered, optionally checks
// received RTP on quality_get, hangs up and requires a local_hangup end.
func cf5eAnswerThenHangup(ctx context.Context, r *rig, toURI string, wantRX bool) (bool, string) {
	call, err := r.dialURI(ctx, r.directUA, toURI)
	if err != nil {
		return false, "dial " + toURI + ": " + err.Error()
	}
	st, err := r.waitState(ctx, call, "answered", 10*time.Second)
	if err != nil || callState(st) != "answered" {
		return false, fmt.Sprintf("did not answer (err=%v state=%q reason=%q code=%d)", err, callState(st), termReason(st), lastCode(st))
	}
	detail := "answered"
	if wantRX {
		sleepCtx(ctx, 3*time.Second)
		q, err := r.cl.callOK(ctx, "quality_get", map[string]any{"call": call})
		if err != nil {
			return false, "quality_get: " + err.Error()
		}
		rx := num(q["packets_received"])
		if rx <= 0 {
			return false, "answered but no RTP received (packets_received=0)"
		}
		detail += fmt.Sprintf(", packets_received=%d", rx)
	}
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": call}); err != nil {
		return false, "call_hangup: " + err.Error()
	}
	if end, err := r.waitTerminal(ctx, call, 8*time.Second); err != nil || termReason(end) != "local_hangup" {
		return false, fmt.Sprintf("did not end local_hangup (err=%v reason=%q)", err, termReason(end))
	}
	return true, detail + ", ended local_hangup"
}

// scenarioCF087AckCredentials: the digest-challenged INVITE to 600 is answered,
// so the ACK for the 200 must carry the retried INVITE's credentials (checked
// on the capture).
func scenarioCF087AckCredentials(ctx context.Context, r *rig) (bool, string) {
	return cf5eAnswerThenHangup(ctx, r, fmt.Sprintf("sip:600@%s:%d", r.cfg.asteriskIP, r.cfg.dialPort), false)
}

// scenarioCF161EarlySDP: Asterisk answers with early media (183 then 200).
func scenarioCF161EarlySDP(ctx context.Context, r *rig) (bool, string) {
	return withRigExtension(ctx, r, "cf5e183", []string{"Progress", "Playback,beep,noanswer", "Answer", "Echo"},
		func() (bool, string) {
			return cf5eAnswerThenHangup(ctx, r, fmt.Sprintf("sip:cf5e183@%s:%d", r.cfg.asteriskIP, r.cfg.dialPort), true)
		})
}

// scenarioCF161EarlyThenBridge: early media, then a bridged answer by the
// gate's registered callee.
func scenarioCF161EarlyThenBridge(ctx context.Context, r *rig) (bool, string) {
	return withRigExtension(ctx, r, "cf5e183b",
		[]string{"Progress", "Playback,beep,noanswer", "Dial,PJSIP/e2e-uac-register,20"},
		func() (bool, string) {
			before := r.registerCallHandles(ctx, r.registerUA)
			caller, err := r.dial(ctx, r.directUA, "cf5e183b")
			if err != nil {
				return false, "dial: " + err.Error()
			}
			inbound, err := r.waitNewInbound(ctx, r.registerUA, before, 12*time.Second)
			if err != nil {
				return false, err.Error()
			}
			if _, err := r.cl.callOK(ctx, "call_answer", map[string]any{"call": inbound}); err != nil {
				return false, "call_answer: " + err.Error()
			}
			st, err := r.waitState(ctx, caller, "answered", 10*time.Second)
			if err != nil || callState(st) != "answered" {
				return false, fmt.Sprintf("caller did not answer (err=%v state=%q)", err, callState(st))
			}
			sleepCtx(ctx, 3*time.Second)
			var rx [2]int
			for i, h := range []string{caller, inbound} {
				q, err := r.cl.callOK(ctx, "quality_get", map[string]any{"call": h})
				if err != nil {
					return false, "quality_get: " + err.Error()
				}
				rx[i] = num(q["packets_received"])
			}
			if rx[0] <= 0 || rx[1] <= 0 {
				return false, fmt.Sprintf("packets_received caller=%d callee=%d, want both > 0", rx[0], rx[1])
			}
			return true, fmt.Sprintf("both legs answered; packets_received caller=%d callee=%d", rx[0], rx[1])
		})
}

// scenarioCF090Redirect302: an unanswered channel is transferred, which
// chan_pjsip answers with a 302; the dial must follow it to 600.
func scenarioCF090Redirect302(ctx context.Context, r *rig) (bool, string) {
	target := fmt.Sprintf("PJSIP/sip:600@%s:%d", r.cfg.asteriskIP, r.cfg.dialPort)
	return withRigExtension(ctx, r, "cf5e302", []string{"Transfer," + target}, func() (bool, string) {
		return cf5eAnswerThenHangup(ctx, r, fmt.Sprintf("sip:cf5e302@%s:%d", r.cfg.asteriskIP, r.cfg.dialPort), false)
	})
}

// scenarioCF161DifferingSDPOverNetwork: a SIPp UAS on the rig host sends a 183
// (SDP port 15592) then a 200 (SDP port 15594); our RTP must go to 15592 only
// (checked on the capture).
func scenarioCF161DifferingSDPOverNetwork(ctx context.Context, r *rig) (bool, string) {
	if strings.TrimSpace(r.cfg.sshTarget) == "" {
		return false, "this scenario needs the rig ssh target (-ssh)"
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sipp := exec.CommandContext(sctx, "ssh", "-o", "BatchMode=yes", r.cfg.sshTarget,
		"cd ~/e2e-asterisk && timeout 90 docker compose run --rm -T sipp -sf /scenarios/cf5-e-183-200.xml -p 15590 -i "+r.cfg.asteriskIP+" -m 1 -timeout 60s")
	var out strings.Builder
	sipp.Stdout, sipp.Stderr = &out, &out
	if err := sipp.Start(); err != nil {
		return false, "start sipp over ssh: " + err.Error()
	}
	done := make(chan error, 1)
	go func() { done <- sipp.Wait() }()
	bound := false
	for i := 0; i < 40 && !bound; i++ {
		chk := exec.CommandContext(ctx, "ssh", "-o", "BatchMode=yes", r.cfg.sshTarget, "ss -lun | grep -c ':15590 '")
		if b, _ := chk.Output(); strings.TrimSpace(string(b)) == "1" {
			bound = true
			break
		}
		sleepCtx(ctx, 500*time.Millisecond)
	}
	if !bound {
		return false, "sipp never bound UDP 15590 on the rig host: " + out.String()
	}
	ok, reason := cf5eAnswerThenHangup(ctx, r, fmt.Sprintf("sip:cf5e@%s:15590", r.cfg.asteriskIP), false)
	select {
	case err := <-done:
		if ok && err != nil {
			return false, "sipp UAS did not complete cleanly: " + err.Error() + " " + out.String()
		}
	case <-time.After(15 * time.Second):
		cancel()
		if ok {
			return false, "sipp UAS did not finish within 15s of the hangup"
		}
	}
	return ok, reason
}
