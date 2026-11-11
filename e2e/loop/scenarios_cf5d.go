package main

// scenarios_cf5d.go — cf5-d (inbound UAS) live scenarios. Two run against the
// lab Asterisk (the registered-UA callee path); the rest drive a local SIPp
// against a throwaway direct UA on Lane D's port base (UA 127.0.0.1:15460,
// SIPp 15470, media literals 15482/15484/15486, SIPp control 15490). SIPp runs
// only through startSIPp/runSIPp.

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

const (
	cf5dUAAddr   = "127.0.0.1:15460"
	cf5dSIPpPort = 15470
	cf5dSIPpCtl  = 15490
	cf5dAORUser  = "cf5d-uas"
)

// sippRun is one SIPp process started by startSIPp.
type sippRun struct {
	scenario string
	out      *bytes.Buffer
	done     chan error
}

func cf5dSIPpDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "sipp", "cf5-d")
}

// startSIPp starts the named scenario (e2e/loop/sipp/cf5-d/<scenario>.xml) in
// the background under `timeout --signal=INT <bound>`, one call only, on Lane
// D's SIPp port. target is the remote host:port a UAC scenario sends to ("" for
// a UAS scenario).
func startSIPp(ctx context.Context, scenario string, bound time.Duration, target string) (*sippRun, error) {
	dir := cf5dSIPpDir()
	if strings.Contains(scenario, "/") { // "cf6-b/x" is relative to e2e/loop/sipp/
		dir = filepath.Dir(dir)
	}
	args := []string{"--signal=INT", strconv.Itoa(int(bound.Seconds())), "sipp",
		"-sf", filepath.Join(dir, scenario+".xml"),
		"-i", "127.0.0.1", "-p", strconv.Itoa(cf5dSIPpPort), "-cp", strconv.Itoa(cf5dSIPpCtl),
		"-m", "1", "-nostdin"}
	if target != "" {
		args = append(args, target)
	}
	cmd := exec.CommandContext(ctx, "timeout", args...)
	s := &sippRun{scenario: scenario, out: &bytes.Buffer{}, done: make(chan error, 1)}
	cmd.Stdout, cmd.Stderr = s.out, s.out
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start sipp %s: %w", scenario, err)
	}
	go func() { s.done <- cmd.Wait() }()
	return s, nil
}

// wait blocks until SIPp exits and reports a failed call (a missing or wrong
// response, a failed header check) as an error.
func (s *sippRun) wait(ctx context.Context) error {
	select {
	case err := <-s.done:
		if err != nil {
			return fmt.Errorf("sipp %s: %v: %s", s.scenario, err, sippDiag(s.out.String()))
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runSIPp runs a scenario that needs no control while it runs.
func runSIPp(ctx context.Context, scenario string, bound time.Duration, target string) error {
	s, err := startSIPp(ctx, scenario, bound, target)
	if err != nil {
		return err
	}
	return s.wait(ctx)
}

// sippDiag keeps SIPp's failure explanation (its stats table is noise).
func sippDiag(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		low := strings.ToLower(l)
		if strings.Contains(low, "unexpected") || strings.Contains(low, "abort") || strings.Contains(low, "timeout") ||
			strings.Contains(low, "variable") || strings.Contains(low, "error") || strings.Contains(low, "expected") ||
			strings.Contains(low, "regexp") || strings.Contains(low, "check") {
			keep = append(keep, strings.TrimSpace(l))
		}
	}
	if len(keep) == 0 {
		return lastLines(s, 8)
	}
	if len(keep) > 8 {
		keep = keep[:8]
	}
	return strings.Join(keep, " | ")
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// cf5dUA creates the throwaway direct UA the SIPp scenarios talk to and returns
// it with a destroy func. extra adds ua_create fields (session timers).
func (r *rig) cf5dUA(ctx context.Context, extra map[string]any) (string, func(), error) {
	args := map[string]any{"mode": "direct", "transport": "udp", "local_addr": cf5dUAAddr,
		"aor": "sip:" + cf5dAORUser + "@127.0.0.1"}
	for k, v := range extra {
		args[k] = v
	}
	env, err := r.cl.callOK(ctx, "ua_create", args)
	if err != nil {
		return "", nil, fmt.Errorf("ua_create: %w", err)
	}
	ua := str(env["ua_handle"])
	return ua, func() { _, _ = r.cl.call(context.WithoutCancel(ctx), "ua_destroy", map[string]any{"ua": ua}) }, nil
}

func (r *rig) cf5dCallsOn(ctx context.Context, ua string) []map[string]any {
	var out []map[string]any
	env, err := r.cl.call(ctx, "call_list", map[string]any{})
	if err != nil {
		return out
	}
	calls, _ := env["calls"].([]any)
	for _, c := range calls {
		if m, ok := c.(map[string]any); ok && str(m["ua_handle"]) == ua {
			out = append(out, m)
		}
	}
	return out
}

// cf5dHeader returns the value of the first header line `name:` in a
// serialized SIP message ("" when absent).
func cf5dHeader(serialized, name string) string {
	for _, line := range strings.Split(serialized, "\n") {
		line = strings.TrimSpace(line)
		if len(line) > len(name)+1 && strings.EqualFold(line[:len(name)+1], name+":") {
			return strings.TrimSpace(line[len(name)+1:])
		}
	}
	return ""
}

var cf5dToTag = regexp.MustCompile(`(?i);\s*tag=([^;>\s]+)`)

// scenarioCF5dInboundShapeVsAsterisk (CF-072, CF-075, CF-103): Asterisk calls
// our registered UA. Every response the inbound leg sent carries one To tag,
// and the 200 lists NOTIFY in Allow. The no-copy-after-ACK half is read from
// the capture.
func scenarioCF5dInboundShapeVsAsterisk(ctx context.Context, r *rig) (bool, string) {
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
	if st, err := r.waitState(ctx, caller, "answered", 8*time.Second); err != nil || callState(st) != "answered" {
		return false, fmt.Sprintf("caller did not answer (err=%v state=%q)", err, callState(st))
	}
	sleepCtx(ctx, 1500*time.Millisecond) // past Timer-G range: a copy after the ACK would be on the wire
	msgs, err := r.ladderMessages(ctx, inbound)
	if err != nil {
		return false, "ladder: " + err.Error()
	}
	tags := map[string]bool{}
	allow := ""
	for _, m := range msgs {
		if !strings.HasPrefix(m.Serialized, "SIP/2.0 ") || !strings.Contains(cf5dHeader(m.Serialized, "CSeq"), "INVITE") ||
			strings.HasPrefix(m.Serialized, "SIP/2.0 100") {
			continue
		}
		if sub := cf5dToTag.FindStringSubmatch(cf5dHeader(m.Serialized, "To")); sub != nil {
			tags[sub[1]] = true
		}
		if strings.HasPrefix(m.Serialized, "SIP/2.0 200") {
			allow = cf5dHeader(m.Serialized, "Allow")
		}
	}
	_, _ = r.cl.callOK(ctx, "call_hangup", map[string]any{"call": caller})
	if len(tags) != 1 {
		return false, fmt.Sprintf("the inbound leg's INVITE responses carry %d distinct To tags, want 1", len(tags))
	}
	if !strings.Contains(allow, "NOTIFY") {
		return false, fmt.Sprintf("200 Allow=%q lacks NOTIFY", allow)
	}
	return true, fmt.Sprintf("one To tag on every response; 200 Allow=%q", allow)
}

// scenarioCF5dOptionsFromAsterisk (CF-094): Asterisk qualifies our registered
// UA with an OPTIONS, which the UA answers 200 (the capture shows the headers;
// the contact stays NonQual because the endpoint has qualify_frequency 0, so
// the CLI's own "Qualifying AOR" line is the only in-band confirmation that the
// request was sent).
func scenarioCF5dOptionsFromAsterisk(ctx context.Context, r *rig) (bool, string) {
	out, ok := r.asteriskRX(ctx, "pjsip qualify e2e-uac-register")
	if !ok {
		return false, "pjsip qualify could not run (ssh)"
	}
	if !strings.Contains(out, "Qualifying AOR 'e2e-uac-register'") {
		return false, "pjsip qualify did not qualify the AOR: " + strings.TrimSpace(out)
	}
	sleepCtx(ctx, time.Second)
	return true, "Asterisk sent a qualify OPTIONS to the registered UA (answer read from the capture)"
}

// scenarioCF5dScreening (CF-095, CF-098, CF-146, CF-147): each refused INVITE
// draws its status (checked by the SIPp scenario) and creates no call.
func scenarioCF5dScreening(ctx context.Context, r *rig) (bool, string) {
	ua, done, err := r.cf5dUA(ctx, nil)
	if err != nil {
		return false, err.Error()
	}
	defer done()
	for _, sc := range []string{"uas-tel-uri", "uas-require", "s-ctype", "s-cenc"} {
		if err := runSIPp(ctx, sc, 30*time.Second, cf5dUAAddr); err != nil {
			return false, err.Error()
		}
	}
	if n := len(r.cf5dCallsOn(ctx, ua)); n != 0 {
		return false, fmt.Sprintf("%d daemon call(s) exist after four refused INVITEs, want 0", n)
	}
	return true, "416 (tel:), 420 + Unsupported, 415 + Accept, 415 + Accept-Encoding; no call created"
}

// scenarioCF5dMerged (CF-097): the second INVITE with the same Call-ID, From
// tag and CSeq but a new branch draws 482; the daemon holds one call.
func scenarioCF5dMerged(ctx context.Context, r *rig) (bool, string) {
	ua, done, err := r.cf5dUA(ctx, nil)
	if err != nil {
		return false, err.Error()
	}
	defer done()
	before := r.registerCallHandles(ctx, ua)
	sp, err := startSIPp(ctx, "uas-merged", 30*time.Second, cf5dUAAddr)
	if err != nil {
		return false, err.Error()
	}
	if _, err := r.waitNewInbound(ctx, ua, before, 8*time.Second); err != nil {
		return false, err.Error()
	}
	sleepCtx(ctx, 2*time.Second) // the merged INVITE is sent 1 s after the 180
	if n := len(r.cf5dCallsOn(ctx, ua)); n != 1 {
		return false, fmt.Sprintf("%d daemon calls after the merged INVITE, want 1", n)
	}
	if err := sp.wait(ctx); err != nil {
		return false, err.Error()
	}
	return true, "second INVITE drew 482; exactly one daemon call (the first, then cancelled)"
}

// scenarioCF5dOptionsAnd405 (CF-093, CF-094): OPTIONS draws 200 with the five
// capability headers; SUBSCRIBE, MESSAGE and an unknown method draw 405 with
// Allow (all header checks are in the SIPp scenarios).
func scenarioCF5dOptionsAnd405(ctx context.Context, r *rig) (bool, string) {
	ua, done, err := r.cf5dUA(ctx, nil)
	if err != nil {
		return false, err.Error()
	}
	defer done()
	for _, sc := range []string{"uas-options", "uas-subscribe", "uas-unknown-method"} {
		if err := runSIPp(ctx, sc, 30*time.Second, cf5dUAAddr); err != nil {
			return false, err.Error()
		}
	}
	if n := len(r.cf5dCallsOn(ctx, ua)); n != 0 {
		return false, fmt.Sprintf("%d daemon call(s) after OPTIONS/405 traffic, want 0", n)
	}
	return true, "OPTIONS 200 with Allow/Accept/Accept-Encoding/Accept-Language/Supported; SUBSCRIBE, MESSAGE, unknown method 405 + Allow; no call created"
}

// scenarioCF5dNoAck (CF-103): the 200 is retransmitted and, with no ACK, the
// dialog ends with our BYE (SIPp requires the BYE). The timing is read from
// the capture.
func scenarioCF5dNoAck(ctx context.Context, r *rig) (bool, string) {
	ua, done, err := r.cf5dUA(ctx, nil)
	if err != nil {
		return false, err.Error()
	}
	defer done()
	before := r.registerCallHandles(ctx, ua)
	s, err := startSIPp(ctx, "uas-no-ack", 75*time.Second, cf5dUAAddr)
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
	if err != nil {
		return false, "call not terminated after the no-ACK BYE: " + err.Error()
	}
	if termReason(st) != "transport_failure" {
		return false, fmt.Sprintf("termination_reason=%q, want transport_failure", termReason(st))
	}
	return true, "no ACK: 200 re-sent, our BYE sent, call terminated transport_failure"
}

// cf5dDialSIPp starts a UAS scenario, dials it from ua and waits for SIPp to
// finish (every UAS scenario here ends the dialog with its own BYE). It returns
// the call's terminal status.
func (r *rig) cf5dDialSIPp(ctx context.Context, ua, scenario string, bound time.Duration) (map[string]any, error) {
	s, err := startSIPp(ctx, scenario, bound, "")
	if err != nil {
		return nil, err
	}
	sleepCtx(ctx, time.Second) // SIPp binds its UDP socket
	call, err := r.dialURI(ctx, ua, fmt.Sprintf("sip:cf5d@127.0.0.1:%d", cf5dSIPpPort))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", scenario, err)
	}
	if err := s.wait(ctx); err != nil {
		return nil, err
	}
	st, err := r.waitTerminal(ctx, call, 5*time.Second)
	if err != nil {
		return st, fmt.Errorf("%s: %w", scenario, err)
	}
	return st, nil
}

// scenarioCF5dGlare (CF-124, CF-166): our session-refresh re-INVITE is pending
// while the peer sends a re-INVITE (rfr-glare) and then an UPDATE offer
// (m-uglare); each draws 491 (the SIPp scenario requires it).
func scenarioCF5dGlare(ctx context.Context, r *rig) (bool, string) {
	ua, done, err := r.cf5dUA(ctx, map[string]any{"session_expires_s": 90, "min_se_s": 90, "session_refresh_method": "invite"})
	if err != nil {
		return false, err.Error()
	}
	defer done()
	for _, sc := range []string{"rfr-glare", "m-uglare"} {
		st, err := r.cf5dDialSIPp(ctx, ua, sc, 85*time.Second)
		if err != nil {
			return false, err.Error()
		}
		if termReason(st) != "remote_bye" {
			return false, fmt.Sprintf("%s: termination_reason=%q, want remote_bye", sc, termReason(st))
		}
	}
	return true, "re-INVITE during our re-INVITE and UPDATE offer during our re-INVITE each drew 491"
}

// scenarioCF5dRefusedAnswer (CF-131): the peer's Session-Expires is below our
// Min-SE, so Answer refuses with 422. call_answer fails with
// precondition_failed, the call ends rejected_locally with no answered event,
// and call_hangup on it is precondition_failed, not not_found.
func scenarioCF5dRefusedAnswer(ctx context.Context, r *rig) (bool, string) {
	ua, done, err := r.cf5dUA(ctx, map[string]any{"session_expires_s": 120, "min_se_s": 120})
	if err != nil {
		return false, err.Error()
	}
	defer done()
	before := r.registerCallHandles(ctx, ua)
	s, err := startSIPp(ctx, "uas-422", 45*time.Second, cf5dUAAddr)
	if err != nil {
		return false, err.Error()
	}
	call, err := r.waitNewInbound(ctx, ua, before, 8*time.Second)
	if err != nil {
		return false, err.Error()
	}
	env, err := r.cl.call(ctx, "call_answer", map[string]any{"call": call})
	if err != nil {
		return false, "call_answer: " + err.Error()
	}
	if ok, _ := env["ok"].(bool); ok || str(env["code"]) != string(apierr.CodePreconditionFailed) {
		return false, fmt.Sprintf("call_answer = ok:%v code:%q, want ok:false precondition_failed", env["ok"], str(env["code"]))
	}
	if err := s.wait(ctx); err != nil {
		return false, err.Error()
	}
	st, err := r.callStatus(ctx, call)
	if err != nil {
		return false, "call_status: " + err.Error()
	}
	if callState(st) != "terminated" || termReason(st) != "rejected_locally" {
		return false, fmt.Sprintf("call_status state=%q reason=%q, want terminated/rejected_locally", callState(st), termReason(st))
	}
	evs, err := r.cl.callOK(ctx, "call_events", map[string]any{"call": call})
	if err != nil {
		return false, "call_events: " + err.Error()
	}
	list, _ := evs["events"].([]any)
	for _, e := range list {
		if m, _ := e.(map[string]any); str(m["type"]) == "answered" {
			return false, "call_events has an answered event for a refused answer"
		}
	}
	hang, err := r.cl.call(ctx, "call_hangup", map[string]any{"call": call})
	if err != nil {
		return false, "call_hangup: " + err.Error()
	}
	if str(hang["code"]) != string(apierr.CodePreconditionFailed) {
		return false, fmt.Sprintf("call_hangup code=%q, want precondition_failed", str(hang["code"]))
	}
	return true, "422 sent; call_answer precondition_failed; terminated/rejected_locally; no answered event; hangup precondition_failed"
}

// scenarioCF5dInDialogOffers (CF-163, CF-164): re-INVITE and UPDATE offers are
// applied and answered. m-out (six re-INVITEs we answer), m-upd (an UPDATE
// offer) and m-in (SIPp calls us, two changed re-INVITEs) check the answer
// bodies; the media effect (RTP port, PT, hold, o= version) is read from the
// capture.
func scenarioCF5dInDialogOffers(ctx context.Context, r *rig) (bool, string) {
	ua, done, err := r.cf5dUA(ctx, nil)
	if err != nil {
		return false, err.Error()
	}
	defer done()
	for _, sc := range []string{"m-out", "m-upd"} {
		st, err := r.cf5dDialSIPp(ctx, ua, sc, 60*time.Second)
		if err != nil {
			return false, err.Error()
		}
		if termReason(st) != "remote_bye" {
			return false, fmt.Sprintf("%s: termination_reason=%q, want remote_bye", sc, termReason(st))
		}
	}
	before := r.registerCallHandles(ctx, ua)
	s, err := startSIPp(ctx, "m-in", 60*time.Second, cf5dUAAddr)
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
	return true, "m-out (6 re-INVITEs), m-upd (UPDATE offer) and m-in (2 re-INVITEs) answered with the expected bodies"
}
