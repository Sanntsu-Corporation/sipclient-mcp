package main

// scenarios_p3.go — Task 33's e2e scenarios: DTMF (rfc2833 against the rig's
// ext 602, plus rfc2833/inband/info against a local second real UA — see the
// DTMF sections below), the session-timer both-roles pair, keepalive, and §11.3.1 case 2
// (in-dialog timeout at the real Timer F). RULING 2 retargets the
// session-timer peer-refresher half and the in-dialog-timeout scenario to
// local stubs (sessiontimer_peer_stub.go, sessiontimer_silent_stub.go)
// instead of the shared lab rig; keepalive similarly targets a local stub
// (keepalive_stub.go, C8) since OPTIONS traffic is out-of-dialog and the tool
// surface has no UA-scoped ladder or capture to observe it through Asterisk.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// createUA is a generic ua_create wrapper parameterized on mode/account/
// local_addr (Rule 16/18): createDirectUA, createDirectUAWithCodecs and
// createRegisterUA each hardcode one specific combination of these three, and
// Task 33's five new scenarios each need a DIFFERENT combination (a
// session-timer account reused three ways, a register-mode account against a
// local stub, and one UA pinned to a fixed local_addr a local stub dials
// INTO) — enough call sites to justify one parameterized helper rather than
// five more near-duplicates of createDirectUA's shape.
//
// accountName names an accounts.go entry, which is resolved HERE into the
// inline ua_create fields it used to name a policy.yaml profile for (Phase 1,
// D1/D6).
func (r *rig) createUA(ctx context.Context, mode, accountName, localAddr string) (string, error) {
	args, err := uaCreateArgs(mode, accountName, r.cfg.asteriskIP, "udp", localAddr, []string{"PCMU"})
	if err != nil {
		return "", err
	}
	env, err := r.cl.callOK(ctx, "ua_create", args)
	if err != nil {
		return "", err
	}
	if mode == "register" {
		if registered, _ := env["registered"].(bool); !registered {
			return "", fmt.Errorf("%s did not register (register_code=%v)", accountName, env["register_code"])
		}
	}
	return str(env["ua_handle"]), nil
}

// ---- ladder helpers (C7, C9) ------------------------------------------------

// ladderMsg mirrors internal/trace's JSON ladder rendering (session/
// toolservice.go's call_ladder, format:"json") just enough for Task 33's two
// assertions: a BYE's Reason header, and a per-method count.
type ladderMsg struct {
	Method     string `json:"method"`
	Serialized string `json:"serialized"`
}

func (r *rig) ladderMessages(ctx context.Context, handle string) ([]ladderMsg, error) {
	env, err := r.cl.callOK(ctx, "call_ladder", map[string]any{"call": handle, "format": "json"})
	if err != nil {
		return nil, err
	}
	raw, _ := env["ladder"].(string)
	var msgs []ladderMsg
	if err := json.Unmarshal([]byte(raw), &msgs); err != nil {
		return nil, fmt.Errorf("decode ladder json: %w", err)
	}
	return msgs, nil
}

// ladderHasPlainBYE reports whether the ladder contains AT LEAST ONE BYE and
// NONE of them carry a Reason header — the plain-hangup shape a DTMF
// scenario's own teardown must have, as opposed to a session-timer-expiry
// BYE (Reason: SIP;cause=408). Fix round 1 (I3): an earlier version of this
// check (named ladderHasNoReasonBYE) returned true when the ladder had NO
// BYE AT ALL, which let a claim like "plain BYE (no Reason)" pass without
// ever observing a BYE — reachable in practice, since dtmfRoundTrip's
// deferred receiver teardown runs before the scenario's own call_hangup.
// scenarioSessionTimerInDialogTimeout wants that looser "no BYE at all is
// fine too" shape (§11.3.1 case 2 sends none) and checks it directly against
// ladderMessages instead of through this stricter helper.
func (r *rig) ladderHasPlainBYE(ctx context.Context, handle string) (bool, error) {
	msgs, err := r.ladderMessages(ctx, handle)
	if err != nil {
		return false, err
	}
	sawBYE := false
	for _, m := range msgs {
		if m.Method != "BYE" {
			continue
		}
		sawBYE = true
		if hasHeaderLine(m.Serialized, "Reason") {
			return false, nil
		}
	}
	return sawBYE, nil
}

// F-M7 (D20, W2): LINE-ANCHORED, not a bare substring. The old
// strings.Contains(m.Serialized, "Reason:") would also match the text "Reason:"
// appearing INSIDE another header's value — e.g. a Warning or a display name that
// quoted it — so "this BYE carries no Reason header" could be wrong in the one
// direction that matters (a false "has Reason", turning a plain BYE into a
// failure). RFC 3261 §7.3.1 puts a header name at the start of a line, so that is
// what we match.
func hasHeaderLine(serialized, name string) bool {
	for _, line := range strings.Split(serialized, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), name+":") {
			return true
		}
	}
	return false
}

func (r *rig) ladderCountMethod(ctx context.Context, handle, method string) (int, error) {
	msgs, err := r.ladderMessages(ctx, handle)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range msgs {
		if m.Method == method {
			n++
		}
	}
	return n, nil
}

// terminationReasonCount parses one calls_by_termination_reason{reason="X"} N
// line out of /metrics' Prometheus text (C12).
func terminationReasonCount(metricsText, reason string) (int, error) {
	re := regexp.MustCompile(`calls_by_termination_reason\{reason="` + regexp.QuoteMeta(reason) + `"\}\s+(\d+)`)
	m := re.FindStringSubmatch(metricsText)
	if m == nil {
		return 0, fmt.Errorf("no calls_by_termination_reason line for reason=%q", reason)
	}
	return strconv.Atoi(m[1])
}

// ---- DTMF against a local second real UA, one scenario per mode ------------
//
// These three prove our RX decode path digit by digit — a finer-grained check
// than Asterisk's dialplan can make. They are the counterpart to
// scenarioDTMFRFC2833Rig (below), which proves the TX direction against an
// independent implementation; see dtmf_receiver.go's doc comment.

const dtmfTestDigits = "12345678"

// dtmfRoundTrip dials the local receiver directly from ua, sends digits in
// mode via the real dtmf_send tool, asserts the send side (digits_sent) and
// — for checkReceived — the receiver's own DECODED digits, then hangs the
// call up ITSELF (via callOK, so a tool-level failure is never silently
// swallowed) before the receiver is torn down.
//
// Fix round 1 (I3): an earlier version left call_hangup to each scenario
// AFTER this function's deferred receiver Close() had already run, so the
// BYE had no peer left to reach — reachable, not theoretical, and masked
// because that call_hangup went through the swallowing r.cl.call. Owning the
// hangup here, before defer recv.Close() fires, removes the ordering bug
// instead of just papering over the swallowed error.
//
// checkReceived is skipped for "info": DTMF-over-INFO RECEPTION is
// explicitly out of scope in production (dtmf.go's onInfo doc comment,
// "decision 3: detect covers the two RTP-path modes only" — it ACKs the
// INFO but never parses/reports a digit), a real production scope boundary
// this task found empirically by running the redesigned receiver against
// all three modes, not a defect to route around. scenarioDTMFInfo instead
// checks the ladder (C9's original observable for that mode) using the
// returned, now-terminated call handle.
func (r *rig) dtmfRoundTrip(ctx context.Context, ua, mode, digits string, checkReceived bool) (string, error) {
	recv, err := startDTMFReceiverUA(ctx, mode, r.cfg.localAddr)
	if err != nil {
		return "", fmt.Errorf("startDTMFReceiverUA(%s): %w", mode, err)
	}
	defer recv.Close()

	handle, err := r.dialURI(ctx, ua, recv.SIPTarget())
	if err != nil {
		return "", fmt.Errorf("dialURI: %w", err)
	}
	if err := recv.AnswerWhenRinging(ctx, 5*time.Second); err != nil {
		return "", fmt.Errorf("receiver AnswerWhenRinging: %w", err)
	}
	if _, err := r.waitState(ctx, handle, "answered", 8*time.Second); err != nil {
		return "", fmt.Errorf("waitState answered: %w", err)
	}

	out, err := r.cl.callOK(ctx, "dtmf_send", map[string]any{
		"call": handle, "digits": digits, "mode": mode,
	})
	if err != nil {
		return "", fmt.Errorf("dtmf_send(%s): %w", mode, err)
	}
	if n := num(out["digits_sent"]); n != len(digits) {
		return "", fmt.Errorf("digits_sent=%d want %d", n, len(digits))
	}

	if checkReceived {
		deadline := time.Now().Add(5 * time.Second)
		for recv.Digits() != digits && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if got := recv.Digits(); got != digits {
			return "", fmt.Errorf("receiver decoded %q, want %q", got, digits)
		}
	}

	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": handle}); err != nil {
		return "", fmt.Errorf("call_hangup: %w", err)
	}
	return handle, nil
}

func scenarioDTMFRFC2833(ctx context.Context, r *rig) (bool, string) {
	// dtmfRoundTrip hangs the call up itself before returning (see its doc
	// comment), so handle is already terminated here — the ladder read is
	// safe against it either way.
	handle, err := r.dtmfRoundTrip(ctx, r.directUA, "rfc2833", dtmfTestDigits, true)
	if err != nil {
		return false, err.Error()
	}
	plainBYE, lerr := r.ladderHasPlainBYE(ctx, handle)
	if lerr != nil {
		return false, "call_ladder: " + lerr.Error()
	}
	if !plainBYE {
		return false, "no plain BYE (no Reason) found in the ladder after call_hangup"
	}
	return true, fmt.Sprintf("%d rfc2833 digits round-tripped to a second real UA; plain BYE (no Reason)", len(dtmfTestDigits))
}

func scenarioDTMFInband(ctx context.Context, r *rig) (bool, string) {
	if _, err := r.dtmfRoundTrip(ctx, r.directUA, "inband", dtmfTestDigits, true); err != nil {
		return false, err.Error()
	}
	return true, fmt.Sprintf("%d inband digits round-tripped to a second real UA", len(dtmfTestDigits))
}

func scenarioDTMFInfo(ctx context.Context, r *rig) (bool, string) {
	handle, err := r.dtmfRoundTrip(ctx, r.directUA, "info", dtmfTestDigits, false)
	if err != nil {
		return false, err.Error()
	}
	n, lerr := r.ladderCountMethod(ctx, handle, "INFO")
	if lerr != nil {
		return false, "call_ladder: " + lerr.Error()
	}
	if n != len(dtmfTestDigits) {
		return false, fmt.Sprintf("ladder shows %d INFO requests, want %d", n, len(dtmfTestDigits))
	}
	return true, fmt.Sprintf("%d SIP INFO DTMF requests confirmed in the ladder", n)
}

// ---- DTMF rfc2833 against the rig (third-party interop, §14.5) --------------
//
// The scenario above proves our RX decode path against a second UA of our own.
// This one proves the other direction and the thing §14.5 actually exists for:
// that an INDEPENDENT implementation understands the RFC 4733 events we send.
// Both are needed; neither replaces the other.
//
// Ext 602 works as of 2026-07-28 (see e2e/asterisk/conf/extensions.conf's
// comment on the `silence/1` prompt for the Asterisk bug that made it look
// broken and how it was diagnosed).
//
// ASSERTION: Asterisk's own `User entered '<digits>'` console line, read back
// over ssh — see rigAsteriskLog for why that is the only place the PBX exposes
// what it decoded. The digits are derived from the wall clock rather than
// fixed, so a line left in the container log by an EARLIER run can never
// satisfy a later one; the assertion cannot pass on stale evidence.
func dtmfRigDigits() string {
	return fmt.Sprintf("%08d", time.Now().UnixNano()%100000000)
}

// dtmfRigScenario is the shared body every rig-side DTMF-vs-Asterisk scenario
// drives: dial ext 602, settle past Asterisk's Answer()-to-Read() window, send
// digits in mode via dtmf_send, then poll the Asterisk console log for its own
// "User entered" readback. mode is the dtmf_send mode ("rfc2833"/"inband"/
// "info"); label is the human-readable name used in this scenario's own
// success/failure text ("rfc2833"/"inband"/"SIP INFO").
//
// Extracted (Rule 13 Cycle 3, code-quality finding #1) from three near-verbatim
// ~50-line copies — scenarioDTMFRFC2833Rig here plus scenarios_p4_w2.go's
// scenarioDTMFInfoRig and scenarioDTMFInbandRig — that differed only in mode,
// label and the exact wording of two message literals. All three keep their
// own thin wrapper so gate.go's registration by name is unaffected.
func dtmfRigScenario(ctx context.Context, r *rig, mode, label string) (bool, string) {
	if strings.TrimSpace(r.cfg.sshTarget) == "" {
		return false, "-ssh is required: this scenario asserts on Asterisk's own record of the digits it decoded"
	}

	// CF-026: Asterisk pins dtmf_mode PER ACCOUNT (conf/pjsip.conf), not per
	// call. r.directUA authenticates as e2e-uac-direct, dtmf_mode=rfc4733 —
	// fine for the rfc2833 arm (that IS its configured mode) and for info
	// (chan_pjsip honours SIP INFO DTMF regardless of dtmf_mode), but the
	// inband arm needs e2e-uac-inband, the one endpoint Asterisk actually
	// runs its Goertzel detector against; e2e-uac-direct's audio is never
	// even looked at for DTMF, so "User entered nothing" was guaranteed
	// regardless of tone quality.
	callerUA := r.directUA
	if mode == "inband" {
		ua, err := r.createInbandUA(ctx)
		if err != nil {
			return false, "createInbandUA: " + err.Error()
		}
		defer func() { _, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": ua}) }()
		callerUA = ua
	}

	digits := dtmfRigDigits()
	start := time.Now()

	handle, err := r.dial(ctx, callerUA, "602")
	if err != nil {
		return false, "dial 602: " + err.Error()
	}
	st, err := r.waitState(ctx, handle, "answered", 10*time.Second)
	if err != nil {
		return false, "waitState answered: " + err.Error()
	}
	if callState(st) != "answered" {
		return false, "ext 602 leg did not answer (state=" + callState(st) + ")"
	}

	// Asterisk's Answer() waits up to 500ms for media before the dialplan
	// advances, so Read() is not armed at the instant we see the 200 OK.
	// Settle first rather than racing the app with the first digits.
	if !sleepCtx(ctx, 1500*time.Millisecond) {
		return false, "cancelled before dtmf_send"
	}

	out, err := r.cl.callOK(ctx, "dtmf_send", map[string]any{
		"call": handle, "digits": digits, "mode": mode,
	})
	if err != nil {
		return false, "dtmf_send(" + mode + "): " + err.Error()
	}
	if n := num(out["digits_sent"]); n != len(digits) {
		return false, fmt.Sprintf("digits_sent=%d want %d", n, len(digits))
	}

	// Read() returns as soon as the 8th digit lands (maxdigits=8), so the
	// verbose line appears within a second of the last event on the wire.
	want := "User entered '" + digits + "'"
	deadline := time.Now().Add(15 * time.Second)
	var lastLog string
	for {
		if logText, ok := r.rigAsteriskLog(ctx, time.Since(start)+5*time.Second); ok {
			lastLog = logText
			if strings.Contains(logText, want) {
				return true, fmt.Sprintf("Asterisk read back all %d %s digits (%s) on ext 602", len(digits), label, digits)
			}
		}
		if time.Now().After(deadline) {
			break
		}
		if !sleepCtx(ctx, time.Second) {
			return false, "cancelled while waiting for Asterisk to report the digits"
		}
	}
	return false, fmt.Sprintf("Asterisk never reported %q from %s on ext 602; its own log said: %s",
		digits, label, summariseUserEntered(lastLog))
}

func scenarioDTMFRFC2833Rig(ctx context.Context, r *rig) (bool, string) {
	return dtmfRigScenario(ctx, r, "rfc2833", "rfc2833")
}

// summariseUserEntered pulls Asterisk's "User entered ..." verbose lines out of
// a console log so a failure names what the PBX DID collect instead of only
// what it did not.
func summariseUserEntered(logText string) string {
	var found []string
	for _, line := range strings.Split(logText, "\n") {
		if i := strings.Index(line, "User entered"); i >= 0 {
			found = append(found, strings.TrimSpace(line[i:]))
		}
	}
	if len(found) == 0 {
		return "(no \"User entered\" line at all — Read() may not have run)"
	}
	return strings.Join(found, " | ")
}

// ---- session-timer, "we refresh" half (scenario 4, RULING 2) --------------

// scenarioSessionTimerWeRefresh needs no stub and no rig change (RULING 2):
// e2e-uac-sessiontimer proposes Session-Expires: 90;refresher=uac, and
// Asterisk's e2e-uac-direct-style endpoints advertise timers_min_se=90
// (live-verified), so it's accepted without a 422 retry, giving an
// interval/2 ~45s refresh (Task 29). Two next_refresh_ms samples a few
// seconds apart prove the countdown is live, and the call still being
// answered past the original 90s interval proves a refresh actually landed
// on the wire — Asterisk's own RFC 4028 enforcement would otherwise have
// ended the dialog at ~90s.
func scenarioSessionTimerWeRefresh(ctx context.Context, r *rig) (bool, string) {
	ua, err := r.createUA(ctx, "direct", "e2e-uac-sessiontimer", r.cfg.localAddr)
	if err != nil {
		return false, "ua_create(e2e-uac-sessiontimer): " + err.Error()
	}
	// F-M6 (D20, W2): the deferred ua_destroy DELIBERATELY keeps the swallowing
	// r.cl.call. A defer cannot return a scenario verdict, and a cleanup error on
	// a path that has already decided PASS or FAIL must not overwrite that
	// verdict — the in-body call_hangup sites, which CAN report, now use callOK.
	defer func() { _, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": ua}) }()

	handle, err := r.dial(ctx, ua, "605")
	if err != nil {
		return false, "dial 605: " + err.Error()
	}
	if _, err := r.waitState(ctx, handle, "answered", 8*time.Second); err != nil {
		return false, "waitState answered: " + err.Error()
	}

	st1, err := r.callStatus(ctx, handle)
	if err != nil {
		return false, "call_status: " + err.Error()
	}
	tim1, ok := st1["session_timer"].(map[string]any)
	if !ok {
		return false, "call_status.session_timer absent; RFC 4028 was not negotiated"
	}
	// D12/D14 (P4-W2-08, W2): THIS ASSERTION IS A SHAPE CHECK, NOT A ROLE CHECK,
	// and is documented as such rather than left looking stronger than it is.
	// Mutating outboundRefresherRole to return "uac" unconditionally leaves it
	// PASSING (the sibling unit test correctly fails), because this scenario is
	// constructed so that "uac" is the right answer — we proposed it. It still
	// earns its place: it proves session_timer.refresher is POPULATED and
	// well-formed on a live rig-negotiated call, which nothing else here does.
	// The role LOGIC is pinned at the unit level; do not read this line as
	// covering it.
	if got := str(tim1["refresher"]); got != "uac" {
		return false, fmt.Sprintf("refresher=%q want uac (we proposed it)", got)
	}
	next1 := num(tim1["next_refresh_ms"])

	sleepCtx(ctx, 5*time.Second)
	st2, err := r.callStatus(ctx, handle)
	if err != nil {
		return false, "call_status (2): " + err.Error()
	}
	// Fix round 1 (M2): the discarded `ok` here let session_timer vanishing
	// between samples pass silently — tim2 nil, num(nil) 0, and 0 >= next1
	// is false, so "next_refresh_ms decreased" was satisfied by the timer
	// disappearing, not by it counting down.
	tim2, ok := st2["session_timer"].(map[string]any)
	if !ok {
		return false, "call_status.session_timer absent on the second sample; RFC 4028 must stay negotiated"
	}
	next2 := num(tim2["next_refresh_ms"])
	if next2 >= next1 {
		return false, fmt.Sprintf("next_refresh_ms did not decrease: %d then %d", next1, next2)
	}

	sleepCtx(ctx, 92*time.Second) // total ~97s: past the original 90s interval
	st3, err := r.callStatus(ctx, handle)
	if err != nil {
		return false, "call_status (3): " + err.Error()
	}
	if callState(st3) != "answered" {
		return false, fmt.Sprintf("state=%q ~97s in; want still answered (a refresh must have landed)", callState(st3))
	}
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": handle}); err != nil {
		return false, "call_hangup: " + err.Error()
	}
	return true, fmt.Sprintf("we-refresh session timer live: next_refresh_ms %d -> %d, still answered past 90s", next1, next2)
}

// ---- session-timer, "peer refreshes" half (scenario 4, RULING 2) ----------

// sessionTimerPeerFixedAddr is the daemon UA's local_addr, fixed rather than
// ephemeral: sessiontimer_peer_stub.go's UAC dials INTO it, so the address
// must be known before the UA exists.
const sessionTimerPeerFixedAddr = "127.0.0.1:39320"

// scenarioSessionTimerPeerRefresher: a local stub DIALS the daemon's UA,
// proposing itself as refresher (Session-Expires: 90;refresher=uac in the
// stub's own INVITE). Per Task 28's rule ("claim uas unless the peer asked
// uac"), the daemon — UAS here — honours the peer's claim and arms its
// watchdog instead of refreshing itself: "peer refreshes, our watchdog is
// armed", retargeted off the shared rig per RULING 2. The stub's one
// mid-dialog UPDATE refresh, sent before the original 90s watchdog deadline,
// must rearm that watchdog — proven by the call still being answered well
// past it.
func scenarioSessionTimerPeerRefresher(ctx context.Context, r *rig) (bool, string) {
	ua, err := r.createUA(ctx, "direct", r.cfg.directP, sessionTimerPeerFixedAddr)
	if err != nil {
		return false, "ua_create (fixed local_addr): " + err.Error()
	}
	defer func() { _, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": ua}) }()

	stub, err := newSessionTimerPeerUAC("127.0.0.1")
	if err != nil {
		return false, "newSessionTimerPeerUAC: " + err.Error()
	}
	defer stub.Close()

	// The stub's Dial blocks on WaitAnswer until OUR 200 OK arrives, and we
	// only send that from call_answer below — so the dial must run
	// concurrently with waitNewInbound/call_answer, not before them.
	before := r.registerCallHandles(ctx, ua)
	dialErrCh := make(chan error, 1)
	go func() {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		dialErrCh <- stub.Dial(dctx, "sip:"+r.cfg.directP+"@"+sessionTimerPeerFixedAddr)
	}()
	inbound, err := r.waitNewInbound(ctx, ua, before, 5*time.Second)
	if err != nil {
		return false, "waitNewInbound: " + err.Error()
	}
	if _, err := r.cl.callOK(ctx, "call_answer", map[string]any{"call": inbound}); err != nil {
		return false, "call_answer: " + err.Error()
	}
	if derr := <-dialErrCh; derr != nil {
		return false, "stub Dial: " + derr.Error()
	}

	ist, err := r.callStatus(ctx, inbound)
	if err != nil {
		return false, "call_status: " + err.Error()
	}
	tim, ok := ist["session_timer"].(map[string]any)
	if !ok {
		return false, "call_status.session_timer absent; RFC 4028 was not negotiated"
	}
	// SessionTimerView.Refresher is the SIP ROLE that refreshes, not "us" vs
	// "peer": we answered (we are UAS), and the peer, who dialled, is UAC and
	// claimed the refresher role — so the correct value here is "uac".
	//
	// D12/D14 (P4-W2-08, W2): shape check, not role check — see the sibling
	// comment in scenarioSessionTimerWeRefresh. Here "uac" is right because the
	// PEER dialled and claimed the refresher role, so an unconditional "uac"
	// would satisfy this line too. The role logic's discriminating test is at the
	// unit level.
	if got := str(tim["refresher"]); got != "uac" {
		return false, fmt.Sprintf("refresher=%q want uac (the peer, who dialled, claimed it)", got)
	}

	sleepCtx(ctx, 50*time.Second) // before the original 90s watchdog deadline
	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	rerr := stub.Refresh(rctx)
	rcancel()
	if rerr != nil {
		return false, "stub Refresh (UPDATE): " + rerr.Error()
	}

	sleepCtx(ctx, 45*time.Second) // ~95s from answer: past the ORIGINAL 90s deadline
	fst, err := r.callStatus(ctx, inbound)
	if err != nil {
		return false, "call_status (final): " + err.Error()
	}
	if callState(fst) != "answered" {
		return false, fmt.Sprintf("state=%q ~95s in; want still answered (the watchdog must have rearmed)", callState(fst))
	}
	return true, "peer-refresher session timer: watchdog rearmed by the peer's mid-dialog UPDATE, still answered past 90s"
}

// ---- keepalive (scenario 5, C8) --------------------------------------------

// scenarioKeepaliveObservable: keepalive OPTIONS are out-of-dialog and the
// tool surface has no UA-scoped ladder or capture (C8), so the only
// observable is a registrar WE control counting what arrives.
func scenarioKeepaliveObservable(ctx context.Context, r *rig) (bool, string) {
	stub, err := startKeepaliveStub()
	if err != nil {
		return false, "startKeepaliveStub: " + err.Error()
	}
	defer stub.Close()

	ua, err := r.createUA(ctx, "register", "e2e-uac-keepalive", r.cfg.localAddr)
	if err != nil {
		return false, "ua_create(e2e-uac-keepalive): " + err.Error()
	}
	defer func() { _, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": ua}) }()

	// keepalive_interval_s: 5 in policy.yaml; two full intervals plus margin.
	sleepCtx(ctx, 12*time.Second)
	n := stub.OptionsCount()
	if n < 2 {
		return false, fmt.Sprintf("stub observed %d OPTIONS in 12s, want >= 2 (interval=5s)", n)
	}
	return true, fmt.Sprintf("keepalive stub observed %d OPTIONS pings in 12s", n)
}

// ---- §11.3.1 case 2: in-dialog timeout at the real Timer F (RULING 2) -----

// scenarioSessionTimerInDialogTimeout: our own refresh (interval/2 ~45s,
// e2e-uac-sessiontimer) draws no response from the stub, which goes silent
// on it deliberately; the daemon's client transaction runs out the real
// ~32s Timer F (ua.go's 32s default) with nothing ever arriving, reaching
// transport_failure/in_dialog_timeout with no BYE ever built (Task 29's
// mechanism, exercised live). A second, ordinary call on the SAME UA (ext
// 605 via Asterisk, same profile) proves the fault is dialog-scoped, not
// UA-wide.
func scenarioSessionTimerInDialogTimeout(ctx context.Context, r *rig) (bool, string) {
	stub, err := startSessionTimerSilentStub(r.cfg.localAddr)
	if err != nil {
		return false, "startSessionTimerSilentStub: " + err.Error()
	}
	defer stub.Close()

	before, berr := r.cl.fetchMetrics(ctx)
	if berr != nil {
		return false, "fetchMetrics (before): " + berr.Error()
	}
	beforeCount, cerr := terminationReasonCount(before, "transport_failure")
	if cerr != nil {
		return false, "parse metrics (before): " + cerr.Error()
	}

	ua, err := r.createUA(ctx, "direct", "e2e-uac-sessiontimer", r.cfg.localAddr)
	if err != nil {
		return false, "ua_create(e2e-uac-sessiontimer): " + err.Error()
	}
	defer func() { _, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": ua}) }()

	faulty, err := r.dialURI(ctx, ua, stub.SIPTarget())
	if err != nil {
		return false, "dialURI (faulty): " + err.Error()
	}
	if _, err := r.waitState(ctx, faulty, "answered", 8*time.Second); err != nil {
		return false, "waitState answered (faulty): " + err.Error()
	}
	control, err := r.dial(ctx, ua, "605")
	if err != nil {
		return false, "dial 605 (control): " + err.Error()
	}
	if _, err := r.waitState(ctx, control, "answered", 8*time.Second); err != nil {
		return false, "waitState answered (control): " + err.Error()
	}

	// interval/2 ~45s refresh + the real ~32s Timer F + margin.
	fst, err := r.waitTerminal(ctx, faulty, 90*time.Second)
	if err != nil {
		return false, "waitTerminal (faulty): " + err.Error()
	}
	if callState(fst) != "terminated" || termReason(fst) != "transport_failure" {
		return false, fmt.Sprintf("faulty leg state/reason=%s/%s want terminated/transport_failure", callState(fst), termReason(fst))
	}

	// The fault under test must actually have been INJECTED: the daemon's own
	// refresh has to have reached the stub and been dropped there. Without this
	// the terminal state above is reached identically by a daemon that never
	// refreshed at all and died of something else, and the scenario passes for
	// the wrong reason (fix round 2, F/I3 — the stub carried this observable
	// with zero callers).
	if n := stub.RefreshesSeen(); n < 1 {
		return false, fmt.Sprintf("the stub dropped %d in-dialog refreshes; the daemon never sent one, "+
			"so the transport_failure above is NOT the §11.3.1 case 2 fault this scenario injects", n)
	}

	// §11.3.1 case 2 sends NO BYE at all (the peer never answered, so there is
	// nothing to retry against) — checked directly against the raw messages
	// rather than through ladderHasPlainBYE, whose "at least one BYE" contract
	// is the opposite of what this scenario wants to see (fix round 1, I3).
	msgs, lerr := r.ladderMessages(ctx, faulty)
	if lerr != nil {
		return false, "call_ladder (faulty messages): " + lerr.Error()
	}
	for _, m := range msgs {
		if m.Method == "BYE" {
			return false, "the faulty leg's ladder contains a BYE at all; §11.3.1 case 2 sends none"
		}
	}

	evs, err := r.cl.callOK(ctx, "call_events", map[string]any{"call": faulty})
	if err != nil {
		return false, "call_events: " + err.Error()
	}
	var sawInDialogTimeout bool
	if list, ok := evs["events"].([]any); ok {
		for _, e := range list {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if str(m["type"]) != "error" {
				continue
			}
			detail, _ := m["detail"].(map[string]any)
			if str(detail["kind"]) == "transport_failure" && str(detail["cause"]) == "in_dialog_timeout" {
				sawInDialogTimeout = true
			}
		}
	}
	if !sawInDialogTimeout {
		return false, "no error event with detail.kind=transport_failure, detail.cause=in_dialog_timeout"
	}

	cst, err := r.callStatus(ctx, control)
	if err != nil {
		return false, "call_status (control): " + err.Error()
	}
	if callState(cst) != "answered" {
		return false, fmt.Sprintf("control leg on the same UA state=%q, want answered (the fault must be dialog-scoped)", callState(cst))
	}
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": control}); err != nil {
		return false, "call_hangup (control): " + err.Error()
	}

	after, aerr := r.cl.fetchMetrics(ctx)
	if aerr != nil {
		return false, "fetchMetrics (after): " + aerr.Error()
	}
	afterCount, aerr2 := terminationReasonCount(after, "transport_failure")
	if aerr2 != nil {
		return false, "parse metrics (after): " + aerr2.Error()
	}
	if afterCount != beforeCount+1 {
		return false, fmt.Sprintf("calls_by_termination_reason{reason=\"transport_failure\"} went %d -> %d, want exactly +1", beforeCount, afterCount)
	}

	return true, "§11.3.1 case 2 confirmed live: in_dialog_timeout, no BYE, control leg unaffected, metrics +1"
}
