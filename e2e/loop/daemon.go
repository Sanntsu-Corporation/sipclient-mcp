package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// daemonSeq disambiguates bin/state paths across multiple startDaemon calls
// within the SAME process (e.g. scenarioEchoQuality's dedicated tone daemon,
// spawned while the main gate daemon is still running): both would otherwise
// derive from the same os.Getpid() and collide on the same bin file and, far
// worse, the same --state directory, which startDaemon removes before
// spawning — clobbering a sibling daemon's live state out from under it.
var daemonSeq int64

// daemon is a locally spawned sipclient-mcpd process plus the facts a client
// needs to talk to it.
type daemon struct {
	cmd      *exec.Cmd
	endpoint string // http://127.0.0.1:<port>/mcp
	baseURL  string // http://127.0.0.1:<port>
	bearer   string // the token the daemon MINTED at bootstrap, read back from stateDir
	stateDir string // this run's private --state directory, removed by stop()
	stopped  bool
}

// startDaemon locates the repo, builds the daemon, picks a free port, spawns it
// with the committed policy and a run-private state directory, waits for
// /healthz, and reads back the bearer token the daemon minted for itself.
// cmd.Dir is the repo root so the policy's repo-root-relative file paths
// resolve.
//
// txToneHz, when true, sets SIPCLIENT_MCP_TX_TONE_HZ=1000 on this daemon
// alone (the hidden e2e-gate TX tone knob, internal/sipua/medialoop.go's
// txAudioSource) — CF-026: this used to be set unconditionally on the ONE
// shared gate daemon, so every scenario's "silence" was actually a
// continuous near-full-scale 1 kHz tone, including the DTMF-vs-Asterisk-ext-602
// scenarios that depend on a real independent detector reading real audio
// content. Only scenarioEchoQuality needs the tone (it asserts on the
// echoed signal), and it now spawns its own short-lived tone daemon via this
// flag instead.
func startDaemon(ctx context.Context, cfg gateConfig, txToneHz bool) (*daemon, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	policyPath := filepath.Join(root, "e2e", "loop", "policy.yaml")
	if _, err := os.Stat(policyPath); err != nil {
		return nil, fmt.Errorf("policy not found at %s: %w", policyPath, err)
	}

	seq := atomic.AddInt64(&daemonSeq, 1)
	bin := filepath.Join(os.TempDir(), fmt.Sprintf("sipclient-mcpd-loopgate-%d-%d", os.Getpid(), seq))
	fmt.Printf("building daemon -> %s\n", bin)
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/sipclient-mcpd")
	build.Dir = root
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		return nil, fmt.Errorf("go build ./cmd/sipclient-mcpd: %w", err)
	}

	port := cfg.listenPort
	if port == 0 {
		if port, err = freePort(); err != nil {
			return nil, fmt.Errorf("pick free port: %w", err)
		}
	}
	listen := fmt.Sprintf("127.0.0.1:%d", port)

	// --state MUST BE GIVEN EXPLICITLY (Phase 2 §2.2). Its default resolves
	// to $XDG_STATE_HOME (or ~/.local/state) under the REAL user's home, so
	// an unflagged harness run writes a state directory, a state file and two
	// minted token files outside the repo — and on the SECOND run finds that
	// state file already there, at which point --policy is vestigial and
	// IGNORED, leaving the gate authenticating against a token from a
	// previous run's mint. A per-PID-and-seq temp directory (same convention
	// as `bin` above) makes every run a genuine first run: fresh mint,
	// --policy honoured, nothing written outside the repo or TMPDIR.
	stateDir := filepath.Join(os.TempDir(), fmt.Sprintf("sipclient-mcpd-loopgate-state-%d-%d", os.Getpid(), seq))
	if err := os.RemoveAll(stateDir); err != nil {
		return nil, fmt.Errorf("clear stale state dir %s: %w", stateDir, err)
	}
	statePath := filepath.Join(stateDir, "state.yaml")

	// The daemon runs on its OWN process group and is signalled on stop, so it
	// never outlives this harness.
	cmd := exec.Command(bin, "--listen", listen, "--policy", policyPath, "--state", statePath)
	cmd.Dir = root
	cmd.Env = os.Environ()
	if txToneHz {
		cmd.Env = append(cmd.Env, "SIPCLIENT_MCP_TX_TONE_HZ=1000")
	}
	if cfg.verbose {
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	}
	fmt.Printf("spawning: %s --listen %s --policy %s --state %s\n", bin, listen, policyPath, statePath)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn daemon: %w", err)
	}

	d := &daemon{
		cmd:      cmd,
		endpoint: "http://" + listen + "/mcp",
		baseURL:  "http://" + listen,
		stateDir: stateDir,
	}

	if err := d.waitReady(ctx, cfg.readyWait); err != nil {
		d.stop()
		return nil, err
	}

	// THE COMMITTED e2e/loop/bearer_token.txt IS NOT WHAT THE DAEMON
	// AUTHENTICATES AGAINST (Phase 2 §2.5). Because --policy is given on this
	// necessarily-first run, bootstrap seeds the state file from it and
	// OVERRIDES auth.bearer_token_file with a token it mints itself. The file
	// in the repo still has to exist and be readable — policy.Load requires
	// it of the seed — but its value is dead the moment bootstrap finishes.
	// Read what the daemon actually minted, exactly as
	// internal/testutil/loopback/daemon.go does.
	bearer, err := readTrimmed(filepath.Join(stateDir, "bearer.token"))
	if err != nil {
		d.stop()
		return nil, fmt.Errorf("read the daemon-minted bearer token: %w", err)
	}
	d.bearer = bearer

	fmt.Printf("daemon ready at %s\n", d.baseURL)
	return d, nil
}

// startToneRig spawns a dedicated, short-lived daemon with the hidden TX
// tone knob on (SIPCLIENT_MCP_TX_TONE_HZ) and wraps it in a throwaway *rig
// sharing r's account/dial config, for the two scenarios (echo quality,
// play/record round-trip) that assert on real non-silent audio coming back
// from Asterisk's Echo().
//
// CF-026: this must NOT be the shared gate daemon (r), whose "silence" needs
// to be real silence — the DTMF-vs-Asterisk-ext-602 scenarios depend on a
// real independent detector reading real audio content, and a continuous
// near-full-scale test tone in every "silent" moment of the call broke that.
// Before this existed, both callers set the knob on the ONE shared daemon
// for its entire lifetime, which is what broke DTMF inband detection.
//
// The returned cleanup stops the tone daemon and its client, in that order;
// call it via defer immediately.
func startToneRig(ctx context.Context, r *rig) (*rig, func(), error) {
	toneCfg := r.cfg
	toneCfg.listenPort = 0 // always auto-pick: r.cfg's port, if explicit, is already bound by the main daemon
	toneD, err := startDaemon(ctx, toneCfg, true)
	if err != nil {
		return nil, nil, fmt.Errorf("start tone daemon: %w", err)
	}
	toneCl, err := connectClient(ctx, toneD.endpoint, toneD.bearer)
	if err != nil {
		toneD.stop()
		return nil, nil, fmt.Errorf("connect tone daemon client: %w", err)
	}
	cleanup := func() {
		toneCl.close()
		toneD.stop()
	}
	return &rig{cl: toneCl, cfg: r.cfg}, cleanup, nil
}

// waitReady polls the unauthenticated /healthz until the HTTP server answers.
func (d *daemon) waitReady(ctx context.Context, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	client := &http.Client{Timeout: 2 * time.Second}
	for {
		if d.cmd.ProcessState != nil {
			return fmt.Errorf("daemon exited before becoming ready")
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, d.baseURL+"/healthz", nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("daemon not ready within %s", budget)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
}

// stop signals the daemon and reaps it, escalating to SIGKILL if it lingers.
func (d *daemon) stop() {
	if d == nil || d.cmd == nil || d.cmd.Process == nil || d.stopped {
		return
	}
	d.stopped = true
	_ = d.cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { _, _ = d.cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = d.cmd.Process.Kill()
	}
	// The state directory holds this run's minted tokens; it is per-PID and
	// of no use to anything once the daemon is down.
	if d.stateDir != "" {
		_ = os.RemoveAll(d.stateDir)
	}
	fmt.Println("daemon stopped")
}

// repoRoot walks up from the working directory to the go.mod that owns this
// module, so `go run ./e2e/loop` works from anywhere under the repo.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			if strings.Contains(string(b), "module github.com/sanntsu-corporation/sipclient-mcp") {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate repo root (go.mod) above %s", dir)
		}
		dir = parent
	}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func readTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
