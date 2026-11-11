package main

// tcptls.go — T7 (P2 W2c): real-peer TCP/TLS interop driver (spec §14.5).
//
// Reuses rig's UA-lifecycle/call-polling machinery from gate.go/scenarios.go
// (Rule 16 DRY) rather than a standalone module: dial/waitNewInbound/
// waitState/waitTerminal/teardownLive are all transport-agnostic already
// (they only read r.cfg.asteriskIP/dialPort and the UA handles this file
// sets). Only UA CREATION hardcodes "transport":"udp" in gate.go's
// createDirectUA/createRegisterUA, so this file supplies its own transport-
// parameterized creators instead of touching those.
//
// Ground truth this driver depends on (Rule 6b, locked, not re-derived
// here): ua_create's `transport` argument selects tcp/tls independently of
// the account, while the registrar is an account field (accounts.go, inline
// on the request since Phase 1 — it was a policy.yaml profile field before
// D1/D6 deleted profiles), so TLS needs its own account entry
// (e2e-uac-register-tls, registrar :5061) while TCP reuses e2e-uac-register
// unmodified (Asterisk's TCP listener is also :5060);
// call_dial's to_uri rejects ";" and "sips:", so the dial target is a bare
// "sip:<ext>@<host>:<port>" with no ;transport= param — outbound transport
// selection is Via-driven from the UA's own transport, not the R-URI.
import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// runTransportGate drives the interop check against the lab Asterisk over the
// given transport ("tcp" or "tls") as two calls. The first: REGISTER
// (outbound), a caller-initiated outbound INVITE (outbound), the
// Asterisk-initiated inbound INVITE to the registered contact (inbound — the
// leg sipp cannot drive for TLS), a capture armed on the inbound leg spanning
// both directions, and a caller-side hangup; it prints its capture's on-disk
// path. The second (reverse direction, CF-117): the callee hangs up, so
// Asterisk's BYE must reach the caller's dialog Contact. It returns the second
// call's inbound handle (the caller locates that pcap under artifact.dir) and a
// non-nil error unless every step above succeeded.
func runTransportGate(ctx context.Context, cl *mcpClient, cfg gateConfig, transport string) (callHandle string, err error) {
	var (
		dialPort  int
		registerP string
	)
	switch transport {
	case "tcp":
		// Asterisk's TCP transport binds the SAME port as UDP (conf/pjsip.conf's
		// [transport-tcp] bind = <rig>:5070), so the existing register
		// account is reused unmodified — only ua_create's transport differs.
		dialPort, registerP = 5070, cfg.registerP
	case "tls":
		// Asterisk's TLS transport binds a DIFFERENT port (:5071); the account's
		// registrar must point there, hence the dedicated accounts.go entry.
		dialPort, registerP = 5071, "e2e-uac-register-tls"
	default:
		return "", fmt.Errorf("unsupported -transport %q (want tcp or tls)", transport)
	}

	trCfg := cfg
	trCfg.dialPort = dialPort
	r := &rig{cl: cl, cfg: trCfg}
	tag := strings.ToUpper(transport)

	fmt.Printf("\n== %s: creating UAs ==\n", tag)
	if r.directUA, err = r.createTransportUA(ctx, "direct", cfg.directP, transport); err != nil {
		return "", fmt.Errorf("%s: create direct (caller) UA: %w", transport, err)
	}
	fmt.Printf("caller  (direct)   ua=%s transport=%s\n", r.directUA, transport)

	regEnv, err := r.createRegisterUATransport(ctx, registerP, transport)
	if err != nil {
		return "", fmt.Errorf("%s: create register (callee) UA: %w", transport, err)
	}
	r.registerUA = regEnv
	fmt.Printf("callee  (register) ua=%s (registered over %s, registrar port %d)\n", r.registerUA, transport, dialPort)

	defer func() {
		fmt.Printf("\n== %s: teardown UAs ==\n", tag)
		if r.registerUA != "" {
			_, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": r.registerUA})
		}
		if r.directUA != "" {
			_, _ = r.cl.call(ctx, "ua_destroy", map[string]any{"ua": r.directUA})
		}
	}()

	// ---- outbound: caller dials the extension over the given transport ----
	before := r.registerCallHandles(ctx, r.registerUA)
	caller, err := r.dial(ctx, r.directUA, "720")
	if err != nil {
		return "", fmt.Errorf("%s: outbound dial 720: %w", transport, err)
	}
	fmt.Printf("outbound INVITE (caller -> Asterisk over %s): call=%s\n", transport, caller)

	// ---- inbound: Asterisk dials back into the registered contact ----
	inbound, err := r.waitNewInbound(ctx, r.registerUA, before, 8*time.Second)
	if err != nil {
		return "", fmt.Errorf("%s: inbound leg never reached the callee: %w", transport, err)
	}
	fmt.Printf("inbound INVITE (Asterisk -> callee over %s): call=%s\n", transport, inbound)

	// Arm the capture on the inbound leg BEFORE answering, so the pcap spans
	// the whole exchange (INVITE -> 200 -> ACK -> BYE) in both directions.
	// This is the both-direction, protocol-6 proof the gate evidence needs —
	// for TLS the daemon's own post-handshake tap is the only place plaintext
	// SIP is observable at all (on the wire it is ciphertext).
	if _, err := r.cl.callOK(ctx, "capture_start", map[string]any{"call": inbound}); err != nil {
		return "", fmt.Errorf("%s: capture_start: %w", transport, err)
	}
	fmt.Printf("capture armed on inbound leg %s\n", inbound)

	if _, err := r.cl.callOK(ctx, "call_answer", map[string]any{"call": inbound}); err != nil {
		return "", fmt.Errorf("%s: call_answer: %w", transport, err)
	}
	cst, err := r.waitState(ctx, caller, "answered", 8*time.Second)
	if err != nil {
		return "", fmt.Errorf("%s: caller answer: %w", transport, err)
	}
	if callState(cst) != "answered" {
		return "", fmt.Errorf("%s: caller state=%q, want answered", transport, callState(cst))
	}
	fmt.Printf("both legs answered over %s (inbound+outbound interop proven)\n", transport)

	// Clean peer-side disconnect (mirrors scenarioRemoteDisconnect), so the
	// pcap captures a full clean call including the closing BYE.
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": caller}); err != nil {
		return "", fmt.Errorf("%s: caller call_hangup: %w", transport, err)
	}
	ist, err := r.waitTerminal(ctx, inbound, 8*time.Second)
	if err != nil {
		return "", fmt.Errorf("%s: callee terminate: %w", transport, err)
	}
	if reason := termReason(ist); reason != "remote_bye" {
		return "", fmt.Errorf("%s: callee termination_reason=%q want remote_bye", transport, reason)
	}

	stopEnv, err := r.cl.callOK(ctx, "capture_stop", map[string]any{"call": inbound})
	if err != nil {
		return "", fmt.Errorf("%s: capture_stop: %w", transport, err)
	}
	fmt.Printf("capture stopped: name=%v bytes=%v packets=%v truncated=%v uri=%v\n",
		stopEnv["name"], stopEnv["bytes"], stopEnv["packets"], stopEnv["truncated"], stopEnv["uri"])
	if path, perr := artifactPath(inbound, "capture.pcap"); perr == nil {
		fmt.Printf("first call's capture artifact (on disk): %s\n", path)
	}

	// Reverse direction (CF-117): a second call whose CALLEE hangs up, so
	// Asterisk's BYE must reach the caller's own dialog Contact (a sips: URI on
	// TLS, sip:;transport=tcp on TCP). The caller ends remote_bye only if that
	// BYE arrived. The capture on this inbound leg is the gate's evidence.
	before = r.registerCallHandles(ctx, r.registerUA)
	caller2, err := r.dial(ctx, r.directUA, "720")
	if err != nil {
		return "", fmt.Errorf("%s: reverse-call dial 720: %w", transport, err)
	}
	inbound2, err := r.waitNewInbound(ctx, r.registerUA, before, 8*time.Second)
	if err != nil {
		return "", fmt.Errorf("%s: reverse-call inbound leg never reached the callee: %w", transport, err)
	}
	if _, err := r.cl.callOK(ctx, "capture_start", map[string]any{"call": inbound2}); err != nil {
		return "", fmt.Errorf("%s: reverse-call capture_start: %w", transport, err)
	}
	if _, err := r.cl.callOK(ctx, "call_answer", map[string]any{"call": inbound2}); err != nil {
		return "", fmt.Errorf("%s: reverse-call call_answer: %w", transport, err)
	}
	if _, err := r.waitState(ctx, caller2, "answered", 8*time.Second); err != nil {
		return "", fmt.Errorf("%s: reverse-call caller answer: %w", transport, err)
	}
	if _, err := r.cl.callOK(ctx, "call_hangup", map[string]any{"call": inbound2}); err != nil {
		return "", fmt.Errorf("%s: reverse-call callee call_hangup: %w", transport, err)
	}
	cst2, err := r.waitTerminal(ctx, caller2, 8*time.Second)
	if err != nil {
		return "", fmt.Errorf("%s: reverse-call caller terminate: %w", transport, err)
	}
	if reason := termReason(cst2); reason != "remote_bye" {
		return "", fmt.Errorf("%s: reverse-call caller termination_reason=%q want remote_bye", transport, reason)
	}
	if _, err := r.cl.callOK(ctx, "capture_stop", map[string]any{"call": inbound2}); err != nil {
		return "", fmt.Errorf("%s: reverse-call capture_stop: %w", transport, err)
	}
	fmt.Printf("reverse call: callee hung up, caller ended remote_bye over %s\n", transport)

	r.teardownLive(ctx)
	fmt.Printf("\n=== %s gate PASSED (inbound+outbound interop, reverse-direction BYE, capture recorded) ===\n", tag)
	return inbound2, nil
}

// createTransportUA creates a UA over the given transport. It mirrors
// gate.go's rig.createDirectUA but takes mode/account/transport as parameters
// — createDirectUA hardcodes "udp" and the direct account, which is exactly
// what this file cannot reuse.
func (r *rig) createTransportUA(ctx context.Context, mode, accountName, transport string) (string, error) {
	args, err := uaCreateArgs(mode, accountName, r.cfg.asteriskIP, transport, r.cfg.localAddr, []string{"PCMU"})
	if err != nil {
		return "", err
	}
	env, err := r.cl.callOK(ctx, "ua_create", args)
	if err != nil {
		return "", err
	}
	return str(env["ua_handle"]), nil
}

// createRegisterUATransport creates the callee UA over the given transport
// and account, requiring a successful REGISTER — mirrors gate.go's
// rig.createRegisterUA, parameterized the same way as createTransportUA.
func (r *rig) createRegisterUATransport(ctx context.Context, accountName, transport string) (string, error) {
	args, err := uaCreateArgs("register", accountName, r.cfg.asteriskIP, transport, r.cfg.localAddr, []string{"PCMU"})
	if err != nil {
		return "", err
	}
	env, err := r.cl.callOK(ctx, "ua_create", args)
	if err != nil {
		return "", err
	}
	if registered, _ := env["registered"].(bool); !registered {
		return "", fmt.Errorf("callee did not register over %s (register_code=%v)", transport, env["register_code"])
	}
	if code := num(env["register_code"]); code != 200 {
		return "", fmt.Errorf("callee register_code=%d, want 200", code)
	}
	return str(env["ua_handle"]), nil
}

// artifactPath resolves a capture_stop'd artifact's on-disk path. It hardcodes
// "e2e/loop/artifacts", matching policy.yaml's artifact.dir literally (both
// are this task's own files; parsing the YAML back out here would be
// speculative generality for a single-purpose harness — Rule 15).
func artifactPath(callHandle, name string) (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "e2e", "loop", "artifacts", callHandle, name), nil
}
