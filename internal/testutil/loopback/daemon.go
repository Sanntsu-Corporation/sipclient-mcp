package loopback

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// DaemonProcess drives the REAL sipclient-mcpd BINARY as a child process,
// over its real HTTP listener — for P1d Task 20's §11.4/§11.5 crash and
// shutdown acceptance, which must exercise the actual process lifecycle
// (SIGTERM/SIGKILL, exit codes) rather than the in-process Harness.
type DaemonProcess struct {
	t          *testing.T
	cmd        *exec.Cmd
	addr       string
	policyPath string
	bearer     string
	peer       *peer.Peer
	rpc        *rpcClient
	sessionID  string

	stdout *bytes.Buffer
	stderr *bytes.Buffer
	mu     sync.Mutex

	waitErr  error
	waitDone chan struct{}
}

// StartDaemonProcess launches bin as a child process against a freshly
// allocated, kernel-assigned port (D310): a fixed port collides across
// packages and breaks -count=2. It writes a real policy file (with a real
// far-end peer UAS as its only profile-less consumer — Peer() below), starts
// the process, and polls GET /healthz to a BOUNDED deadline — N4's
// documented unauthenticated exemption, whose body is pinned byte-exactly to
// "ok", so readiness is unambiguous.
func StartDaemonProcess(t *testing.T, bin string) *DaemonProcess {
	t.Helper()

	// D310: allocate our own port, then release it immediately before the
	// child binds it — the window between Close and the child's own Listen
	// is the same one every "pick a free TCP port" helper accepts.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("loopback: allocate daemon port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("loopback: release daemon port: %v", err)
	}

	dir := t.TempDir()
	bearer := "daemonprocess-bearer-token"
	bearerFile := filepath.Join(dir, "bearer_token")
	if err := os.WriteFile(bearerFile, []byte(bearer), 0o600); err != nil {
		t.Fatalf("loopback: write bearer_token file: %v", err)
	}
	// D294: artifact.dir must be a real writable directory, or /readyz never
	// reports ready.
	artifactDir := t.TempDir()

	doc := map[string]any{
		"auth":     map[string]any{"bearer_token_file": bearerFile},
		"artifact": map[string]any{"dir": artifactDir},
	}
	b, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("loopback: marshal daemon policy: %v", err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, b, 0o600); err != nil {
		t.Fatalf("loopback: write daemon policy: %v", err)
	}

	// The far-end peer UAS this DaemonProcess's tests dial against — the same
	// canonical internal/testutil/peer as the in-process Harness (Rule 18).
	p := peer.Start(t, peer.Config{Addr: localIP + ":0", Realm: "sipclient-test"})

	// Phase 2 §2.2: --state defaults to a path under the real user's
	// $XDG_STATE_HOME/~/.local/state, which a test process must never
	// touch. Pointing it into this test's own TempDir keeps every
	// DaemonProcess's bootstrap (minted tokens, the seeded state file)
	// isolated to this one process and this one t.TempDir(), exactly like
	// policyPath and artifactDir above.
	statePath := filepath.Join(dir, "state.yaml")
	cmd := exec.Command(bin, "--policy", policyPath, "--state", statePath, "--listen", addr)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("loopback: start daemon process %s: %v", bin, err)
	}

	d := &DaemonProcess{
		t: t, cmd: cmd, addr: addr, policyPath: policyPath, bearer: bearer,
		peer: p, stdout: &stdout, stderr: &stderr,
		rpc: newRPCClient("http://" + addr), waitDone: make(chan struct{}),
	}
	go func() {
		err := cmd.Wait()
		d.mu.Lock()
		d.waitErr = err
		d.mu.Unlock()
		close(d.waitDone)
	}()
	t.Cleanup(func() {
		_ = d.cmd.Process.Kill()
		<-d.waitDone
	})

	d.waitForReady(t, 5*time.Second)

	// Phase 2 §2.5: because --policy is given on this (necessarily first,
	// t.TempDir()-fresh) run, the daemon's bootstrap seed OVERRIDES
	// auth.bearer_token_file with its own freshly minted token -- the
	// fixture value written into bearerFile above is NOT what the running
	// daemon actually authenticates against once it has started. Read the
	// token the daemon itself minted (into the same directory as statePath)
	// rather than assume the fixture's value still works.
	mintedBearer, err := os.ReadFile(filepath.Join(dir, "bearer.token"))
	if err != nil {
		t.Fatalf("loopback: read daemon-minted bearer token: %v", err)
	}
	bearer = string(mintedBearer)
	d.bearer = bearer

	status, sessionID, _, err := d.rpc.rawPost(context.Background(), bearer, "", "initialize",
		map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "loopback-daemonprocess", "version": "0"},
		})
	if err != nil || status != 200 || sessionID == "" {
		t.Fatalf("loopback: daemon process initialize: status=%d id=%q err=%v", status, sessionID, err)
	}
	d.sessionID = sessionID
	return d
}

// waitForReady polls GET /healthz to a bounded deadline. The body is pinned
// byte-exactly to "ok" (N4), so readiness is unambiguous.
func (d *DaemonProcess) waitForReady(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := d.rpc.hc
	for {
		resp, err := client.Get("http://" + d.addr + "/healthz")
		if err == nil {
			body := make([]byte, 2)
			n, _ := resp.Body.Read(body)
			_ = resp.Body.Close()
			if resp.StatusCode == 200 && string(body[:n]) == "ok" {
				return
			}
		}
		if time.Now().After(deadline) {
			d.mu.Lock()
			out, errOut := d.stdout.String(), d.stderr.String()
			d.mu.Unlock()
			t.Fatalf("loopback: daemon process did not become ready within %s; stdout=%q stderr=%q",
				timeout, out, errOut)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Addr is the daemon's real HTTP listen address.
func (d *DaemonProcess) Addr() string { return d.addr }

// Peer is the far-end canonical peer UAS this DaemonProcess's tests dial
// against.
func (d *DaemonProcess) Peer() *peer.Peer { return d.peer }

// PeerURI is the SIP URI at which Peer() is reachable.
func (d *DaemonProcess) PeerURI() string { return "sip:peer@" + d.peer.Addr() }

// CallTool calls a tool on the daemon process's own session.
func (d *DaemonProcess) CallTool(name string, args map[string]any) (map[string]any, error) {
	env, _, err := d.rpc.callTool(context.Background(), d.bearer, d.sessionID, name, args)
	return env, err
}

// MustCallTool fails the test on any error.
func (d *DaemonProcess) MustCallTool(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	env, err := d.CallTool(name, args)
	if err != nil {
		t.Fatalf("loopback: daemon process: %s: %v", name, err)
	}
	return env
}

// MustCreateUA creates a "direct" mode UA on the daemon process's own
// session.
func (d *DaemonProcess) MustCreateUA(t *testing.T, mode string) string {
	t.Helper()
	env := d.MustCallTool(t, "ua_create", map[string]any{"mode": mode, "transport": "udp"})
	handle, _ := env["ua_handle"].(string)
	if handle == "" {
		t.Fatalf("loopback: daemon process: ua_create returned no ua_handle: %+v", env)
	}
	return handle
}

// MustDial dials toURI from ua on the daemon process's own session.
func (d *DaemonProcess) MustDial(t *testing.T, ua, toURI string) string {
	t.Helper()
	env := d.MustCallTool(t, "call_dial", map[string]any{"ua": ua, "to_uri": toURI})
	handle, _ := env["call_handle"].(string)
	if handle == "" {
		t.Fatalf("loopback: daemon process: call_dial returned no call_handle: %+v", env)
	}
	return handle
}

// MustWait calls call_wait once and fails the test unless the matching event
// arrived.
func (d *DaemonProcess) MustWait(t *testing.T, callHandle, until string, timeoutMs int) WaitResult {
	t.Helper()
	callCtx, cancel := context.WithTimeout(context.Background(),
		time.Duration(timeoutMs)*time.Millisecond+5*time.Second)
	defer cancel()
	env, _, err := d.rpc.callTool(callCtx, d.bearer, d.sessionID, "call_wait",
		map[string]any{"call": callHandle, "until": until, "timeout_ms": timeoutMs})
	res := decodeWaitResult(env, err)
	if res.Err != nil {
		t.Fatalf("loopback: daemon process: call_wait(%s, %s): %v", callHandle, until, res.Err)
	}
	if res.TimedOut {
		t.Fatalf("loopback: daemon process: call_wait(%s, %s) timed out after %dms", callHandle, until, timeoutMs)
	}
	return res
}

// Signal sends sig to the daemon process.
func (d *DaemonProcess) Signal(t *testing.T, sig syscall.Signal) {
	t.Helper()
	if err := d.cmd.Process.Signal(sig); err != nil {
		t.Fatalf("loopback: signal daemon process: %v", err)
	}
}

// Stop sends SIGTERM and waits up to d's grace budget for exit.
func (d *DaemonProcess) Stop(t *testing.T, grace time.Duration) {
	t.Helper()
	d.Signal(t, syscall.SIGTERM)
	if _, err := d.WaitForExit(t, grace); err != nil {
		t.Fatalf("loopback: daemon process did not exit cleanly: %v", err)
	}
}

// WaitForExit blocks, bounded by d, until the process has exited, returning
// its exit error (nil on a clean exit(0)).
func (d *DaemonProcess) WaitForExit(t *testing.T, d2 time.Duration) (bool, error) {
	t.Helper()
	select {
	case <-d.waitDone:
		d.mu.Lock()
		err := d.waitErr
		d.mu.Unlock()
		return true, err
	case <-time.After(d2):
		return false, fmt.Errorf("loopback: daemon process did not exit within %s", d2)
	}
}

// Stdout and Stderr return the process's captured output so far.
func (d *DaemonProcess) Stdout() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stdout.String()
}

// Stderr returns the process's captured stderr output so far.
func (d *DaemonProcess) Stderr() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stderr.String()
}
