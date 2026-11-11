package main

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// sleepCtx sleeps for d unless ctx is cancelled first. It returns false if the
// context was cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// asteriskRX runs one Asterisk CLI command inside the rig container over ssh.
// Returns "", false when ssh is disabled or the command fails — every caller
// treats the cross-check as best-effort, never as a gate verdict.
func (r *rig) asteriskRX(ctx context.Context, clicmd string) (string, bool) {
	if strings.TrimSpace(r.cfg.sshTarget) == "" {
		return "", false
	}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "ssh",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		r.cfg.sshTarget,
		"docker exec e2e-asterisk asterisk -rx "+strconv.Quote(clicmd))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", false
	}
	return string(out), true
}

// rigAsteriskLog returns the rig container's Asterisk console output for the
// last `window`, over ssh. Returns "", false when ssh is disabled or the
// command fails.
//
// Unlike asteriskRX's cross-checks this one IS a gate verdict input
// (scenarioDTMFRFC2833Rig): Asterisk's own `User entered '<digits>'` verbose
// line is the only place the PBX reports the digits it decoded on ext 602.
// They live in a channel variable that dies with the channel, so no post-call
// `asterisk -rx` query can reach them, and PJSIP_HEADER(add,...) is not
// applied to the BYE that Hangup() generates (verified on the rig), so there
// is no in-band SIP carrier for them either.
func (r *rig) rigAsteriskLog(ctx context.Context, window time.Duration) (string, bool) {
	if strings.TrimSpace(r.cfg.sshTarget) == "" {
		return "", false
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "ssh",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		r.cfg.sshTarget,
		fmt.Sprintf("docker logs --since %ds e2e-asterisk 2>&1", int(window.Seconds())+1))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", false
	}
	return string(out), true
}

// rigHealthPing is a lightweight, best-effort pre-flight: confirm the 720/721
// dialplan is loaded. A warning (not a failure) if ssh is unavailable — the
// scenarios themselves are the real signal.
func (r *rig) rigHealthPing(ctx context.Context) {
	out, ok := r.asteriskRX(ctx, "dialplan show e2e")
	if !ok {
		fmt.Println("note: skipping rig health ping (ssh cross-check disabled or unreachable)")
		return
	}
	if strings.Contains(out, "720") && strings.Contains(out, "721") {
		fmt.Println("rig health: [e2e] dialplan loaded (720/721 present)")
	} else {
		fmt.Println("WARNING: [e2e] dialplan does not show 720/721 — rig may be misconfigured")
	}
}

// channelCrossCheck warns if Asterisk still holds active channels after a
// scenario's teardown — a wedged channel the MCP-side assertions cannot see.
// Best-effort: silent when ssh is disabled.
func (r *rig) channelCrossCheck(ctx context.Context, scenario string) {
	out, ok := r.asteriskRX(ctx, "core show channels")
	if !ok {
		return
	}
	// The summary line reads e.g. "0 active channels".
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, "active channels") {
			n, _ := strconv.Atoi(strings.Fields(line)[0])
			if n != 0 {
				fmt.Printf("  WARNING [%s]: rig still has %d active channel(s) after teardown\n", scenario, n)
			}
			return
		}
	}
}
