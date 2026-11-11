package main

// gate_test.go — D4's fix (P4-W2-05, Phase 4 W2).
//
// `find e2e -name '*_test.go'` was EMPTY: e2e/loop is package main, driven only
// by run.sh (`exec go run ./e2e/loop`), so nothing under e2e/ was reachable from
// `go test ./...`. This file adds that entry point and NOTHING else — it calls
// run(ctx, cfg), the same function main() calls, with the same
// defaultGateConfig(). No runner logic changed; gate.go and scenarios*.go are
// untouched by this task.
//
// A RIG OUTAGE MUST NEVER REDDEN THIS TEST (design 10, a hard requirement).
// The gate drives a live Asterisk on the lab LAN, which is absent from CI and
// from any developer machine off that network, so an unconditional test here
// would turn a normal `go test ./...` into a guaranteed red. Two gates,
// belt and braces:
//
//  1. OPT-IN. Without SIPCLIENT_E2E_GATE=1 the test skips immediately, before
//     any network call. This is the gate that protects CI and every casual
//     `go test ./...`.
//  2. REACHABILITY PREFLIGHT. Even with the opt-in set, an ssh probe of the rig
//     that fails means SKIP, not FAIL — the rig being down is an environment
//     fact, not a regression in this repository.
//
// Only a rig that is opted into AND reachable can produce a failure, and then
// the failure is a real scenario failure. Per the standing gotcha,
// e2e/asterisk/smoke-test.sh gates trust in any live result: run it before
// believing a PASS here.

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// e2eGateEnv opts into the live gate. Any value other than "1" skips.
const e2eGateEnv = "SIPCLIENT_E2E_GATE"

// e2eGateTimeout bounds the whole run. The scenario count is whatever gate.go's
// slice holds (run.sh's comment: do not restate it here — it drifts); three of
// them are session-timer scenarios that each sleep past a 90 s RFC 4028
// interval, so the real floor is several minutes; 20 is generous without being
// unbounded.
const e2eGateTimeout = 20 * time.Minute

// rigReachable probes the rig over ssh with a batch-mode no-op. ssh is the right
// probe rather than a TCP dial to 5060: the gate's rig-side assertions
// (scenarioDTMFRFC2833Rig and Task 5's INFO sibling) read Asterisk's console log
// over exactly this channel, so ssh working is the actual precondition. A TCP
// probe could pass while the assertions still could not run.
func rigReachable(target string) error {
	if strings.TrimSpace(target) == "" {
		return errNoSSHTarget
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh",
		"-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=accept-new",
		target, "true")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &rigUnreachableError{target: target, err: err, output: strings.TrimSpace(string(out))}
	}
	return nil
}

var errNoSSHTarget = &rigUnreachableError{target: "", output: "no ssh target configured"}

type rigUnreachableError struct {
	target string
	err    error
	output string
}

func (e *rigUnreachableError) Error() string {
	if e.err == nil {
		return e.output
	}
	return e.target + ": " + e.err.Error() + " (" + e.output + ")"
}

// TestE2EGate runs the full 14.5 loop-call gate. See this file's header for the
// two skip gates and why neither may become a failure.
func TestE2EGate(t *testing.T) {
	if os.Getenv(e2eGateEnv) != "1" {
		t.Skipf("live gate not opted in: set %s=1 to run the 14.5 loop-call gate "+
			"against the Asterisk rig (see e2e/loop/README.md). This skip is DELIBERATE — "+
			"the gate needs a live PBX on the lab LAN, so it must never run unasked.", e2eGateEnv)
	}

	cfg := defaultGateConfig()
	// Env overrides for a rig at a different address, mirroring run.sh's flags.
	if v := os.Getenv("SIPCLIENT_E2E_ASTERISK"); v != "" {
		cfg.asteriskIP = v
	}
	if v := os.Getenv("SIPCLIENT_E2E_LOCAL"); v != "" {
		cfg.localAddr = v
	}
	if v := os.Getenv("SIPCLIENT_E2E_SSH"); v != "" {
		cfg.sshTarget = v
	}

	if err := rigReachable(cfg.sshTarget); err != nil {
		t.Skipf("Asterisk rig unreachable (%v) — SKIPPING, not failing: a rig outage is an "+
			"environment fact, not a regression in this repository (design 10). Bring the rig up "+
			"and re-run, or check e2e/asterisk/USAGE.md.", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), e2eGateTimeout)
	defer cancel()

	if err := run(ctx, cfg); err != nil {
		t.Fatalf("loop-call gate failed: %v\n\nThis is a REAL failure: the rig answered the ssh "+
			"preflight, so the gate reached it. Before treating it as a code regression, run "+
			"e2e/asterisk/smoke-test.sh to confirm the rig itself is healthy (standing gotcha).", err)
	}
}
