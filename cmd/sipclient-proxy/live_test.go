//go:build live

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/proxy"
)

// The Asterisk rig's PUBLISHED lab credential (e2e/asterisk/conf/pjsip.conf:
// "e2e-test-only-not-a-secret"). It is what the transcript must never contain.
const (
	rigPassword = "e2e-test-only-not-a-secret"
	rigUser     = "e2e-uac-register"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// startDaemon builds and starts a THROWAWAY sipclient-mcpd on a free loopback
// port with a scratch state directory, and returns its MCP URL and bearer token.
// The process is killed by t.Cleanup; nothing about the owner's own daemon
// (127.0.0.1:8100) or home directory is touched. The daemon's stderr carries a
// first-run banner with its tokens, so it is discarded, never captured.
func startDaemon(t *testing.T) (upstream, token string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "sipclient-mcpd")
	build := exec.Command("go", "build", "-o", bin, "../sipclient-mcpd")
	build.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build sipclient-mcpd: %v\n%s", err, out)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	d := exec.Command(bin, "--listen", addr, "--state", filepath.Join(dir, "state.yaml"))
	d.Stdout, d.Stderr = io.Discard, io.Discard
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Process.Kill(); _ = d.Wait() })
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("throwaway daemon did not come up on %s", addr)
		}
		time.Sleep(100 * time.Millisecond)
	}
	tok, err := os.ReadFile(filepath.Join(dir, "bearer.token")) // minted next to --state on first run
	if err != nil {
		t.Fatalf("the daemon did not write bearer.token next to its state file: %v", err)
	}
	return "http://" + addr + "/mcp", strings.TrimSpace(string(tok))
}

// TestLiveRigRegistersByAccountName drives the REAL proxy binary against a REAL
// (throwaway) sipclient-mcpd and the Asterisk rig, using only an account label.
// Gated twice: the `live` build tag and SIPPROXY_LIVE=1, so `make test` never
// touches the rig.
//
//	SIPPROXY_LIVE=1 go test -tags live -run TestLiveRig -count=1 -v ./cmd/sipclient-proxy/
func TestLiveRigRegistersByAccountName(t *testing.T) {
	if os.Getenv("SIPPROXY_LIVE") != "1" {
		t.Skip("set SIPPROXY_LIVE=1 to run against the Asterisk rig")
	}
	rigServer := os.Getenv("SIPPROXY_LIVE_RIG_HOST")
	if rigServer == "" {
		t.Skip("set SIPPROXY_LIVE_RIG_HOST to the Asterisk rig address: see e2e/asterisk/README.md")
	}
	if c, err := net.DialTimeout("tcp", net.JoinHostPort(rigServer, "5070"), 5*time.Second); err != nil {
		t.Fatalf("the rig %s:5070 is unreachable (%v): stop and report it rather than working around it", rigServer, err)
	} else {
		_ = c.Close()
	}
	upstream, token := startDaemon(t)

	cfgPath := filepath.Join(t.TempDir(), "sipclient-proxy.json")
	err := proxy.Save(cfgPath, &proxy.Config{Upstream: upstream, Token: token, Accounts: map[string]proxy.Account{
		"rig-register": {Mode: "register", SIPServer: rigServer, Port: 5070, Transport: "udp", Username: rigUser, Password: rigPassword},
		"rig-tcp":      {Mode: "register", SIPServer: rigServer, Port: 5070, Transport: "tcp", Username: rigUser, Password: rigPassword},
	}})
	if err != nil {
		t.Fatal(err)
	}

	bin := buildBinary(t)
	var stderr syncBuffer
	cmd := exec.Command(bin, "--config", cfgPath)
	cmd.Stderr = &stderr
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "live", Version: "0"}, nil).
		Connect(ctx, &sdk.CommandTransport{Command: cmd}, nil)
	if err != nil {
		// No error text and no stderr: either may carry a secret (P5).
		t.Fatalf("connect to the proxy binary failed (%d bytes of proxy stderr, not shown)", len(stderr.String()))
	}
	defer func() { _ = cs.Close() }()

	var transcript strings.Builder // everything the model would have seen
	call := func(name, args string) *sdk.CallToolResult {
		t.Helper()
		var a any
		if args != "" {
			a = json.RawMessage(args)
		}
		res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: a})
		if err != nil {
			t.Fatalf("%s: the call failed (a %d-byte error, not shown: it may hold a secret)", name, len(err.Error()))
		}
		b, _ := json.Marshal(res)
		transcript.WriteString(name + " " + args + " -> " + string(b) + "\n")
		return res
	}
	body := func(res *sdk.CallToolResult) map[string]any {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal([]byte(text0(res)), &m); err != nil {
			t.Fatalf("result is not the daemon's JSON envelope (%s)", describeResult("ua_create", res))
		}
		return m
	}

	if res := call("account_list", ""); !strings.Contains(text0(res), `"name":"rig-register"`) {
		t.Fatal(describeResult("account_list (expected the rig-register account)", res))
	}

	for _, acct := range []string{"rig-register", "rig-tcp"} {
		res := call("ua_create", `{"account":"`+acct+`"}`)
		if res.IsError {
			t.Fatal(acct + ": " + describeResult("ua_create", res))
		}
		m := body(res)
		if m["registered"] != true || m["register_code"] != float64(200) {
			t.Fatalf("%s: want registered:true register_code:200, got %s", acct, registrationSummary(m))
		}
		ua, _ := m["ua_handle"].(string)
		if ua == "" {
			t.Fatalf("%s: the reply carries no ua_handle (%s)", acct, registrationSummary(m))
		}
		// ua_status is the fallback proof of registration when the rig's own
		// `pjsip show contacts` (Task 9 Step 6, L4) cannot be run.
		if st := call("ua_status", `{"ua":"`+ua+`"}`); !strings.Contains(text0(st), `"registered":true`) {
			t.Fatal(acct + ": " + describeResult("ua_status (expected registered:true)", st))
		}
		if h, _ := strconv.Atoi(os.Getenv("SIPPROXY_LIVE_HOLD_S")); h > 0 && acct == "rig-register" {
			t.Logf("holding the registration for %ds: run `pjsip show contacts` on the rig now (optional)", h)
			time.Sleep(time.Duration(h) * time.Second)
		}
		call("ua_destroy", `{"ua":"`+ua+`"}`)
	}

	// Local refusals: an account combined with an owned field, and an unknown account.
	if res := call("ua_create", `{"account":"rig-register","auth_pass":"x"}`); !res.IsError || !strings.Contains(text0(res), `combined with "auth_pass"`) {
		t.Fatal(describeResult("ua_create conflict (expected a local refusal naming auth_pass)", res))
	}
	if res := call("ua_create", `{"account":"nope"}`); !res.IsError || !strings.Contains(text0(res), "rig-register, rig-tcp") {
		t.Fatal(describeResult("ua_create unknown account (expected the valid names)", res))
	}

	// Which secret check failed, by label only: never the transcript or stderr text (P5).
	if msg := leakReport(
		[]namedSecret{{"the rig password", rigPassword}, {"the daemon token", token}},
		[]namedText{{"tool-call transcript", transcript.String()}, {"proxy stderr", stderr.String()}},
	); msg != "" {
		t.Fatal(msg)
	}
}

func text0(res *sdk.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}
