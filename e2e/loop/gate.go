package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// rig holds the live MCP client and the two UA handles the scenarios drive.
// registerUA is mutable: scenario #6 destroys and recreates it.
type rig struct {
	cl         *mcpClient
	cfg        gateConfig
	directUA   string // caller (direct mode)
	registerUA string // callee (register mode)
	// registerContact is registerUA's own Contact URI, as ua_create returned
	// it (M8/D5). Its ephemeral source port makes it unique per run, which is
	// what lets scenarioRegistrationRefresh (scenarios_p4.go) bind its
	// wire-level REGISTER-block match to THIS run's own traffic rather than
	// (in principle) another REGISTER in the same logger-armed window.
	registerContact string
}

// scenario is one loop-call check. run returns PASS/FAIL and a one-line reason.
type scenario struct {
	name string
	run  func(ctx context.Context, r *rig) (bool, string)
}

// runGate creates the two UAs and runs the eight scenarios, printing one
// PASS/FAIL line each. It returns a non-nil error unless all eight pass (so
// main exits 1).
func runGate(ctx context.Context, cl *mcpClient, cfg gateConfig) (err error) {
	r := &rig{cl: cl, cfg: cfg}

	r.rigHealthPing(ctx)

	fmt.Println("\n== creating UAs ==")
	if r.directUA, err = r.createDirectUA(ctx); err != nil {
		return fmt.Errorf("create direct (caller) UA: %w", err)
	}
	fmt.Printf("caller  (direct)   ua=%s\n", r.directUA)
	if r.registerUA, err = r.createRegisterUA(ctx); err != nil {
		return fmt.Errorf("create register (callee) UA: %w", err)
	}
	fmt.Printf("callee  (register) ua=%s (registered)\n", r.registerUA)

	// Always destroy both UAs at the end (unregisters the callee, BYEs any leg).
	defer func() {
		fmt.Println("\n== teardown UAs ==")
		if r.registerUA != "" {
			_, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": r.registerUA})
		}
		if r.directUA != "" {
			_, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": r.directUA})
		}
		// M8/D5 safety net: scenarioRegistrationRefresh arms `pjsip set logger
		// on` around its wire-level assertion and disarms it itself via defer,
		// but this is a shared rig — an unconditional second `off` here means a
		// panic mid-scenario still can't leave the logger armed for whatever
		// runs on the rig next.
		if strings.TrimSpace(r.cfg.sshTarget) != "" {
			_, _ = r.asteriskRX(ctx, "pjsip set logger off")
		}
	}()

	scenarios := []scenario{
		{"#3 caller-id (normal answer)", scenarioCallerID},
		{"#7 remote-reject (486)", scenarioRemoteReject},
		{"#6 remote-offline (404)", scenarioRemoteOffline},
		{"#1 remote-disconnect (peer BYE, D1)", scenarioRemoteDisconnect},
		{"#2 local-disconnect (callee BYE, D1)", scenarioLocalDisconnect},
		{"#5 remote-no-answer (CANCEL, D3)", scenarioRemoteNoAnswer},
		{"#5b caller-CANCEL (call_hangup while ringing, CF-043)", scenarioCallerCancel},
		{"negotiate PCMU/PCMA (P2 W3, §14.5)", scenarioNegotiatePCMUPCMA},
		{"488/ACK-then-BYE (P2 W3, §11.2.1)", scenario488AckThenBye},
		{"echo quality (P2 W4, §14.5, R4/R7)", scenarioEchoQuality},
		{"play/record round-trip (P2 W5, §14.5, R3)", scenarioPlayRecordRoundTrip},
		{"DTMF rfc2833 (P3 Task 33, R2/§8)", scenarioDTMFRFC2833},
		{"DTMF rfc2833 vs Asterisk ext 602 (§14.5)", scenarioDTMFRFC2833Rig},
		{"DTMF inband (P3 Task 33, R2/§8)", scenarioDTMFInband},
		{"DTMF inband vs Asterisk ext 602 (D17, W2)", scenarioDTMFInbandRig},
		{"DTMF SIP INFO (P3 Task 33, §8)", scenarioDTMFInfo},
		{"DTMF SIP INFO vs Asterisk ext 602 (D7, W2)", scenarioDTMFInfoRig},
		{"session-timer: we refresh (P3 Task 33, §5/§8)", scenarioSessionTimerWeRefresh},
		{"session-timer: peer refreshes (P3 Task 33, §5/§8, RULING 2)", scenarioSessionTimerPeerRefresher},
		{"session-timer: in-dialog timeout (P3 Task 33, §11.3.1 case 2, RULING 2)", scenarioSessionTimerInDialogTimeout},
		{"keepalive observable (P3 Task 33, §2.4/§8)", scenarioKeepaliveObservable},
		{"CF-037 sibling survives a dial timeout", scenarioDialTimeoutSiblingSurvives},
		{"registration refresh, sustained (M8 D5, Phase 4 W1)", scenarioRegistrationRefresh},
		{"CF-106 oversize INVITE goes over TCP (rfc-fix-1)", scenarioOversizeDialGoesOverTCP},
		{"CF-092 duration cap sends BYE (rfc-fix-1)", scenarioDurationCapSendsBye},
		{"cf5-a PT and strict source vs ext 600 (CF-150, CF-155, CF-179)", scenarioCF5aPTAndStrictSource},
		{"cf5-a DTMF events list vs ext 602 (CF-156)", scenarioCF5aDTMFEventsList},
		{"cf5-a SRTP required over TLS vs e2e-uac-srtp (CF-170)", scenarioCF5aSRTPRequiredTLS},
		{"cf5-a SRTP optional falls back to plain vs e2e-uac-direct (CF-170)", scenarioCF5aSRTPOptionalFallback},
		{"cf5-a SRTP optional over TLS vs e2e-uac-srtp (CF-170 probe)", scenarioCF5aSRTPOptionalTLSProbe},
		{"cf5-a per-call srtp tightening (CF-170)", scenarioCF5aPerCallSRTP},
		{"session-timer: Asterisk loop refresher orientation (cf5-b)", scenarioSessionTimerAsteriskLoopOrientation},
		{"CF-087 ACK of an authenticated 200 carries credentials (cf5-e)", scenarioCF087AckCredentials},
		{"CF-161 early SDP is the answer, Asterisk early media (cf5-e)", scenarioCF161EarlySDP},
		{"CF-161 early media then a bridged answer (cf5-e)", scenarioCF161EarlyThenBridge},
		{"CF-090/CF-089 a 302 is followed (cf5-e)", scenarioCF090Redirect302},
		{"CF-161 a 200 SDP that differs from the 183's, over the network (cf5-e)", scenarioCF161DifferingSDPOverNetwork},
		{"cf5-d inbound shape vs Asterisk (CF-072, CF-075, CF-103)", scenarioCF5dInboundShapeVsAsterisk},
		{"cf5-d OPTIONS from Asterisk (CF-094)", scenarioCF5dOptionsFromAsterisk},
		{"cf5-d local SIPp: screening (CF-095, CF-098, CF-146, CF-147)", scenarioCF5dScreening},
		{"cf5-d local SIPp: merged INVITE (CF-097)", scenarioCF5dMerged},
		{"cf5-d local SIPp: OPTIONS and 405 (CF-093, CF-094)", scenarioCF5dOptionsAnd405},
		{"cf5-d local SIPp: 2xx without ACK (CF-103)", scenarioCF5dNoAck},
		{"cf5-d local SIPp: glare (CF-124, CF-166)", scenarioCF5dGlare},
		{"cf5-d local SIPp: refused answer (CF-131)", scenarioCF5dRefusedAnswer},
		{"cf5-d local SIPp: in-dialog offers (CF-163, CF-164)", scenarioCF5dInDialogOffers},
		{"cf6-b local SIPp: ACK route, re-offer, ACK answer, live answer, refreshed target (CF-193, CF-207, CF-165, CF-186, CF-184)", scenarioCF6bInDialogRefresh},
		{"cf6-b local SIPp: re-INVITE 2xx without ACK (CF-208)", scenarioCF6bReInviteNoAck},
		{"CF-190 oversize UDP-UA INVITE is in call_ladder over TCP (cf6-c)", scenarioCF190OversizeUDPInviteInLadder},
		{"CF-185 ua_create refuses a sips: registrar on a udp UA (cf6-c)", scenarioCF185SipsRegistrarRefusedOnUDP},
		{"CF-198 an SRTP dial follows a 302 with a fresh key (cf6-a)", scenarioCF198Redirect302SRTP},
		{"CF-201 an offer naming a hostname or a bad port draws 488 (cf6-a)", scenarioCF201OfferRefusals},
		{"CF-210 a re-offer naming a hostname draws 488 and the call goes on (cf6-a)", scenarioCF210ReofferHostname},
		{"CF-187 an SDES offer in FreeSWITCH order is answered with tag 2 (cf6-a)", scenarioCF187SDESOrder},
	}

	fmt.Println("\n== scenarios ==")
	passed := 0
	for _, s := range scenarios {
		ok, reason := s.run(ctx, r)
		r.teardownLive(ctx)
		r.channelCrossCheck(ctx, s.name)
		verdict := "FAIL"
		if ok {
			verdict = "PASS"
			passed++
		}
		fmt.Printf("%-4s %-38s %s\n", verdict, s.name, reason)
		if ctx.Err() != nil {
			break
		}
	}

	fmt.Printf("\n=== %d/%d passed ===\n", passed, len(scenarios))
	if passed != len(scenarios) {
		return fmt.Errorf("loop-call gate FAILED: %d/%d", passed, len(scenarios))
	}
	return nil
}

// ---- UA lifecycle -----------------------------------------------------------

// createDirectUA is createDirectUAWithCodecs' ["PCMU"] case. The two used to
// be near-identical copies differing only in that literal; the Phase 1 inline-
// account migration had to touch both anyway, and leaving two copies of the
// argument assembly was the more expensive option.
func (r *rig) createDirectUA(ctx context.Context) (string, error) {
	return r.createDirectUAWithCodecs(ctx, []string{"PCMU"})
}

// createInbandUA (CF-026) creates a direct-mode UA against e2e-uac-inband,
// the rig's dedicated dtmf_mode=inband endpoint (accounts.go) — the one
// Asterisk actually runs its Goertzel detector against, unlike
// e2e-uac-direct (dtmf_mode=rfc4733).
func (r *rig) createInbandUA(ctx context.Context) (string, error) {
	args, err := uaCreateArgs("direct", "e2e-uac-inband", r.cfg.asteriskIP, "udp", r.cfg.localAddr, []string{"PCMU"})
	if err != nil {
		return "", err
	}
	env, err := r.cl.callOK(ctx, "ua_create", args)
	if err != nil {
		return "", err
	}
	return str(env["ua_handle"]), nil
}

// createDirectUAWithCodecs creates a direct-mode UA with an explicit
// codec_pref — used by scenarioNegotiatePCMUPCMA (P2 W3) to genuinely
// exercise codec selection by offering more than one codec to Asterisk.
func (r *rig) createDirectUAWithCodecs(ctx context.Context, codecs []string) (string, error) {
	args, err := uaCreateArgs("direct", r.cfg.directP, r.cfg.asteriskIP, "udp", r.cfg.localAddr, codecs)
	if err != nil {
		return "", err
	}
	env, err := r.cl.callOK(ctx, "ua_create", args)
	if err != nil {
		return "", err
	}
	return str(env["ua_handle"]), nil
}

// createRegisterUA creates the callee UA and REQUIRES a successful REGISTER —
// without a contact the rig cannot bridge 720/721 to it.
func (r *rig) createRegisterUA(ctx context.Context) (string, error) {
	args, err := uaCreateArgs("register", r.cfg.registerP, r.cfg.asteriskIP, "udp", r.cfg.localAddr, []string{"PCMU"})
	if err != nil {
		return "", err
	}
	env, err := r.cl.callOK(ctx, "ua_create", args)
	if err != nil {
		return "", err
	}
	if registered, _ := env["registered"].(bool); !registered {
		return "", fmt.Errorf("callee did not register (register_code=%v)", env["register_code"])
	}
	if code := num(env["register_code"]); code != 200 {
		return "", fmt.Errorf("callee register_code=%d, want 200", code)
	}
	// M8/D5: stash the granted Contact URI so scenarioRegistrationRefresh can
	// bind its registrar-side log match to this run specifically.
	r.registerContact = str(env["contact"])
	return str(env["ua_handle"]), nil
}

// ---- dialing + inbound discovery -------------------------------------------

// dial places an outbound call to an Asterisk extension and returns the caller
// call handle (state dialing).
func (r *rig) dial(ctx context.Context, ua, ext string) (string, error) {
	toURI := fmt.Sprintf("sip:%s@%s:%d", ext, r.cfg.asteriskIP, r.cfg.dialPort)
	return r.dialURI(ctx, ua, toURI)
}

// dialURI places an outbound call to an explicit SIP URI — unlike dial, which
// always addresses the Asterisk rig, this lets a scenario dial an arbitrary
// destination (P2 W3's local non-compliant UAS stub, not the rig).
func (r *rig) dialURI(ctx context.Context, ua, toURI string) (string, error) {
	env, err := r.cl.callOK(ctx, "call_dial", map[string]any{"ua": ua, "to_uri": toURI})
	if err != nil {
		return "", err
	}
	return str(env["call_handle"]), nil
}

// registerCallHandles snapshots ua's current call handles, so a new inbound
// leg can be told apart from earlier scenarios' terminated calls. ua defaults
// to the gate's standing callee (r.registerUA) at every pre-Task-33 call
// site; Task 33's scenarios pass a different UA handle (a fixed-local_addr
// direct-mode UA a local stub dials into, bypassing Asterisk — RULING 2),
// which is the reason this takes ua explicitly rather than closing over
// r.registerUA (Rule 16: widening the existing helper instead of a parallel
// duplicate).
func (r *rig) registerCallHandles(ctx context.Context, ua string) map[string]bool {
	out := map[string]bool{}
	env, err := r.cl.call(ctx, "call_list", map[string]any{})
	if err != nil {
		return out
	}
	calls, _ := env["calls"].([]any)
	for _, c := range calls {
		if m, ok := c.(map[string]any); ok && str(m["ua_handle"]) == ua {
			out[str(m["call_handle"])] = true
		}
	}
	return out
}

// waitNewInbound polls call_list until a call handle on ua that was not in
// `before` appears — the inbound INVITE that reached it. See
// registerCallHandles's doc comment for why ua is a parameter.
func (r *rig) waitNewInbound(ctx context.Context, ua string, before map[string]bool, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		env, err := r.cl.call(ctx, "call_list", map[string]any{})
		if err == nil {
			calls, _ := env["calls"].([]any)
			for _, c := range calls {
				m, ok := c.(map[string]any)
				if !ok {
					continue
				}
				h := str(m["call_handle"])
				if str(m["ua_handle"]) == ua && !before[h] {
					return h, nil
				}
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no inbound leg reached the callee within %s", timeout)
		}
		if !sleepCtx(ctx, 150*time.Millisecond) {
			return "", ctx.Err()
		}
	}
}

// ---- status helpers ---------------------------------------------------------

func (r *rig) callStatus(ctx context.Context, handle string) (map[string]any, error) {
	return r.cl.call(ctx, "call_status", map[string]any{"call": handle})
}

// waitTerminal polls call_status until the call is terminated or failed.
func (r *rig) waitTerminal(ctx context.Context, handle string, timeout time.Duration) (map[string]any, error) {
	deadline := time.Now().Add(timeout)
	var last map[string]any
	for {
		st, err := r.callStatus(ctx, handle)
		if err != nil {
			return last, err
		}
		last = st
		switch str(st["state"]) {
		case "terminated", "failed":
			return st, nil
		}
		if time.Now().After(deadline) {
			return last, fmt.Errorf("call %s did not terminate within %s (state=%s)", handle, timeout, str(st["state"]))
		}
		if !sleepCtx(ctx, 200*time.Millisecond) {
			return last, ctx.Err()
		}
	}
}

// waitState polls call_status until the call reaches `want` (or any terminal
// state, which it returns too so the caller can detect an unexpected failure).
func (r *rig) waitState(ctx context.Context, handle, want string, timeout time.Duration) (map[string]any, error) {
	deadline := time.Now().Add(timeout)
	var last map[string]any
	for {
		st, err := r.callStatus(ctx, handle)
		if err != nil {
			return last, err
		}
		last = st
		state := str(st["state"])
		if state == want || state == "terminated" || state == "failed" {
			return st, nil
		}
		if time.Now().After(deadline) {
			return last, fmt.Errorf("call %s did not reach %q within %s (state=%s)", handle, want, timeout, state)
		}
		if !sleepCtx(ctx, 200*time.Millisecond) {
			return last, ctx.Err()
		}
	}
}

func lastCode(st map[string]any) int {
	if lr, ok := st["last_response"].(map[string]any); ok {
		return num(lr["code"])
	}
	return 0
}

func termReason(st map[string]any) string { return str(st["termination_reason"]) }
func callState(st map[string]any) string  { return str(st["state"]) }

// userPart returns the user portion of a SIP URI, accepting the name-addr form
// (`"display" <sip:user@host>;params`) that Asterisk surfaces in from_uri as well
// as the bare addr-spec (sip:user@host / user@host).
func userPart(uri string) string {
	s := uri
	// Unwrap a name-addr: take what's inside the first <...>.
	if i := strings.Index(s, "<"); i >= 0 {
		s = s[i+1:]
		if j := strings.Index(s, ">"); j >= 0 {
			s = s[:j]
		}
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "sips:"), "sip:")
	if i := strings.Index(s, "@"); i >= 0 {
		return s[:i]
	}
	return ""
}

// ---- teardown + cross-checks ------------------------------------------------

// teardownLive hangs up any leg still live after a scenario, so the next one
// starts from a clean slate regardless of how the previous ended.
func (r *rig) teardownLive(ctx context.Context) {
	env, err := r.cl.call(ctx, "call_list", map[string]any{})
	if err != nil {
		return
	}
	calls, _ := env["calls"].([]any)
	for _, c := range calls {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		switch str(m["state"]) {
		case "dialing", "ringing", "answered":
			_, _ = r.cl.call(ctx, "call_hangup", map[string]any{"call": str(m["call_handle"])})
		}
	}
	// brief settle so BYE/CANCEL exchanges complete before the channel check
	sleepCtx(ctx, 400*time.Millisecond)
}
