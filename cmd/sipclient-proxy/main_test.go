package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/proxy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/mcpdaemon"
)

func TestRealMainVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := realMain([]string{"--version"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr=%q", code, errb.String())
	}
	if !strings.HasPrefix(out.String(), "sipclient-proxy ") || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestRealMainUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"--bogus"}, {"whatever"}} {
		var out, errb bytes.Buffer
		if code := realMain(args, strings.NewReader(""), &out, &errb); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
		if out.Len() != 0 {
			t.Errorf("%v: stdout must stay empty, got %q", args, out.String())
		}
	}
}

func TestServeMissingConfig(t *testing.T) {
	var out, errb bytes.Buffer
	code := realMain([]string{"--config", filepath.Join(t.TempDir(), "absent.json")}, strings.NewReader(""), &out, &errb)
	if code != 1 || out.Len() != 0 || !strings.Contains(errb.String(), "configure") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errb.String())
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping binary build in -short mode")
	}
	bin := filepath.Join(t.TempDir(), "sipclient-proxy")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func writeProxyConfig(t *testing.T, upstream, token string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sipclient-proxy.json")
	err := proxy.Save(p, &proxy.Config{Upstream: upstream, Token: token, Accounts: map[string]proxy.Account{
		"lab": {Mode: "direct", Username: "u", Password: "BINARY-PW-SECRET"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBinaryServesAccountList(t *testing.T) {
	bin := buildBinary(t)
	d := mcpdaemon.Start(t)
	cfg := writeProxyConfig(t, d.URL, d.Token)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "t", Version: "0"}, nil).
		Connect(ctx, &sdk.CommandTransport{Command: exec.Command(bin, "--config", cfg)}, nil)
	if err != nil {
		t.Fatalf("connect to proxy binary (stdout must carry only MCP frames): %v", err)
	}
	defer func() { _ = cs.Close() }()

	names := map[string]bool{}
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		names[tool.Name] = true
	}
	if !names["account_list"] || !names["ua_create"] {
		t.Fatalf("tools = %v", names)
	}
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "account_list"})
	if err != nil || res.IsError {
		t.Fatalf("account_list: %v %+v", err, res)
	}
	b, _ := (res.Content[0]).(*sdk.TextContent)
	if !strings.Contains(b.Text, `"name":"lab"`) || strings.Contains(b.Text, "BINARY-PW-SECRET") {
		t.Fatalf("account_list = %s", b.Text)
	}
}

func TestBinaryFailsFastWithoutPollutingStdout(t *testing.T) {
	bin := buildBinary(t)
	d := mcpdaemon.Start(t)
	cfg := writeProxyConfig(t, d.URL, "wrong-token-SECRET")

	cmd := exec.Command(bin, "--config", cfg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Stdin = io.NopCloser(strings.NewReader("")) // EOF immediately
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a non-zero exit with a bad token")
		}
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("proxy did not fail fast")
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty on failure, got %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "wrong-token-SECRET") {
		t.Errorf("stderr leaks the token: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "upstream") {
		t.Errorf("stderr should explain the failure: %s", stderr.String())
	}
}

// N7: a client that simply disconnects (stdin EOF) is a normal end, exit 0.
func TestRealMainCleanDisconnectExitsZero(t *testing.T) {
	d := mcpdaemon.Start(t)
	cfg := writeProxyConfig(t, d.URL, d.Token)
	inR, inW := io.Pipe()   // client -> proxy stdin
	outR, outW := io.Pipe() // proxy stdout -> client
	var errb bytes.Buffer
	code := make(chan int, 1)
	go func() { code <- realMain([]string{"--config", cfg}, inR, outW, &errb) }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "t", Version: "0"}, nil).
		Connect(ctx, &sdk.IOTransport{Reader: outR, Writer: inW}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "account_list"}); err != nil || res.IsError {
		t.Fatalf("account_list: %v %v", err, res)
	}
	_ = cs.Close() // closes the pipe the proxy reads: EOF on its stdin
	select {
	case c := <-code:
		if c != 0 {
			t.Fatalf("clean disconnect exited %d, stderr=%q", c, errb.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("proxy did not exit after its client disconnected")
	}
}

func TestServeWarnsAboutWorldReadableConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits")
	}
	// An unreachable upstream makes serve return quickly; the warning is printed first.
	p := filepath.Join(t.TempDir(), "sipclient-proxy.json")
	if err := proxy.Save(p, &proxy.Config{Upstream: "http://127.0.0.1:1/mcp", Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = serve(ctx, serveConfig{ConfigPath: p}, io.NopCloser(strings.NewReader("")), nopWriteCloser{io.Discard}, &errb)
	if !strings.Contains(errb.String(), "chmod 600") {
		t.Fatalf("stderr should warn about the file mode, got %q", errb.String())
	}
	// And a 0600 file draws no warning.
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	_ = serve(ctx, serveConfig{ConfigPath: p}, io.NopCloser(strings.NewReader("")), nopWriteCloser{io.Discard}, &errb)
	if strings.Contains(errb.String(), "chmod") {
		t.Fatalf("no warning expected for mode 0600, got %q", errb.String())
	}
}

func TestServeSignalCancelExitsCleanly(t *testing.T) {
	d := mcpdaemon.Start(t)
	cfg := writeProxyConfig(t, d.URL, d.Token)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	var errb bytes.Buffer
	go func() { done <- serve(ctx, serveConfig{ConfigPath: cfg}, inR, outW, &errb) }()
	cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer ccancel()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "t", Version: "0"}, nil).
		Connect(cctx, &sdk.IOTransport{Reader: outR, Writer: inW}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	cancel() // what SIGTERM does through signal.NotifyContext
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a signal-driven stop must be a clean exit, got %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not stop after its context was cancelled")
	}
}

func TestServeWarnsAtEveryStartAboutCleartextUpstream(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sipclient-proxy.json")
	if err := proxy.Save(p, &proxy.Config{Upstream: "http://192.0.2.7:8100/mcp", Token: "t", AllowInsecureHTTP: true}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 1; i <= 2; i++ {
		var errb bytes.Buffer
		_ = serve(ctx, serveConfig{ConfigPath: p}, io.NopCloser(strings.NewReader("")), nopWriteCloser{io.Discard}, &errb)
		if !strings.Contains(errb.String(), "travels in cleartext to 192.0.2.7:8100") {
			t.Fatalf("start %d: stderr lacks the cleartext warning: %q", i, errb.String())
		}
		if !strings.Contains(errb.String(), "level=WARN") || !strings.Contains(errb.String(), "allow_insecure_http is set") {
			t.Fatalf("start %d: the logger lacks the host-free warning line: %q", i, errb.String())
		}
	}
}
