package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

// TestMintTokensIfAbsent (P2-T1): the two files exist at 0600, the dir is
// 0700, the tokens are 64 hex chars and distinct, and a second call does
// NOT re-mint or re-print.
func TestMintTokensIfAbsent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode assertions")
	}
	dir := filepath.Join(t.TempDir(), "state")
	var out bytes.Buffer

	bearerPath, adminPath, err := mintTokensIfAbsent(dir, &out, discardLogger())
	if err != nil {
		t.Fatalf("mintTokensIfAbsent: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat state dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("state dir mode = %o, want 0700", perm)
	}

	bearerInfo, err := os.Stat(bearerPath)
	if err != nil {
		t.Fatalf("stat bearer token file: %v", err)
	}
	if perm := bearerInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("bearer token file mode = %o, want 0600", perm)
	}
	adminInfo, err := os.Stat(adminPath)
	if err != nil {
		t.Fatalf("stat admin token file: %v", err)
	}
	if perm := adminInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("admin token file mode = %o, want 0600", perm)
	}

	bearerBytes, err := os.ReadFile(bearerPath)
	if err != nil {
		t.Fatalf("read bearer token file: %v", err)
	}
	adminBytes, err := os.ReadFile(adminPath)
	if err != nil {
		t.Fatalf("read admin token file: %v", err)
	}
	if len(bearerBytes) != 64 {
		t.Errorf("bearer token is %d chars, want 64 (256 bits hex)", len(bearerBytes))
	}
	if _, err := hex.DecodeString(string(bearerBytes)); err != nil {
		t.Errorf("bearer token is not valid hex: %v", err)
	}
	if len(adminBytes) != 64 {
		t.Errorf("admin token is %d chars, want 64", len(adminBytes))
	}
	if string(bearerBytes) == string(adminBytes) {
		t.Error("bearer and admin tokens are identical, want distinct")
	}

	banner := out.String()
	if banner == "" {
		t.Error("first mint printed nothing on stdout, want a banner")
	}

	// Second call: must NOT re-mint (files unchanged) and must NOT print
	// anything.
	out.Reset()
	bearerAgain, adminAgain, err := mintTokensIfAbsent(dir, &out, discardLogger())
	if err != nil {
		t.Fatalf("mintTokensIfAbsent (second call): %v", err)
	}
	if bearerAgain != bearerPath || adminAgain != adminPath {
		t.Errorf("second call returned different paths: (%q,%q) want (%q,%q)", bearerAgain, adminAgain, bearerPath, adminPath)
	}
	if out.Len() != 0 {
		t.Errorf("second call printed %q, want nothing (no re-print)", out.String())
	}
	bearerBytes2, _ := os.ReadFile(bearerPath)
	if string(bearerBytes2) != string(bearerBytes) {
		t.Error("bearer token file changed after a second mintTokensIfAbsent call (re-minted)")
	}
}

func TestPrintTokens(t *testing.T) {
	dir := t.TempDir()
	var mintOut bytes.Buffer
	if _, _, err := mintTokensIfAbsent(dir, &mintOut, discardLogger()); err != nil {
		t.Fatalf("mintTokensIfAbsent: %v", err)
	}
	wantBearer, err := os.ReadFile(filepath.Join(dir, bearerTokenFileName))
	if err != nil {
		t.Fatalf("read bearer file: %v", err)
	}
	wantAdmin, err := os.ReadFile(filepath.Join(dir, adminTokenFileName))
	if err != nil {
		t.Fatalf("read admin file: %v", err)
	}

	var out bytes.Buffer
	if err := printTokens(dir, &out); err != nil {
		t.Fatalf("printTokens: %v", err)
	}
	got := out.String()
	if got != string(wantBearer)+"\n"+string(wantAdmin)+"\n" {
		t.Errorf("printTokens output = %q, want the two file contents", got)
	}
}

func TestPrintTokensFailsClearlyWhenStateDirMissing(t *testing.T) {
	var out bytes.Buffer
	err := printTokens(filepath.Join(t.TempDir(), "does-not-exist"), &out)
	if err == nil {
		t.Fatal("want printTokens to fail when the state dir does not exist, got nil")
	}
}

func TestBootstrapDefaultState(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.yaml")
	var mintOut bytes.Buffer
	bearerPath, adminPath, err := mintTokensIfAbsent(dir, &mintOut, discardLogger())
	if err != nil {
		t.Fatalf("mintTokensIfAbsent: %v", err)
	}

	if err := bootstrapDefaultState(statePath, bearerPath, adminPath); err != nil {
		t.Fatalf("bootstrapDefaultState: %v", err)
	}

	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("state file mode = %o, want 0600", perm)
	}

	p, err := policy.Load(statePath)
	if err != nil {
		t.Fatalf("Load the bootstrapped state file: %v", err)
	}
	if p.Auth.BearerTokenFile != bearerPath {
		t.Errorf("Auth.BearerTokenFile = %q, want %q", p.Auth.BearerTokenFile, bearerPath)
	}
	if p.Auth.AdminTokenFile != adminPath {
		t.Errorf("Auth.AdminTokenFile = %q, want %q", p.Auth.AdminTokenFile, adminPath)
	}
	if p.Artifact.Dir == "" {
		t.Fatal("Artifact.Dir is empty -- D294: a daemon with no artifact dir never reports ready")
	}
	if di, err := os.Stat(p.Artifact.Dir); err != nil || !di.IsDir() {
		t.Errorf("Artifact.Dir %q is not a writable directory: %v", p.Artifact.Dir, err)
	}

	// A second call (as run.go would perform on a second start, guarded by
	// its own os.Stat check -- this test exercises bootstrapDefaultState in
	// isolation) still produces a loadable file; idempotency of the OUTER
	// "only call this when absent" gate is run.go's, asserted by the
	// end-to-end test below.
	before, _ := os.ReadFile(statePath)
	if err := bootstrapDefaultState(statePath, bearerPath, adminPath); err != nil {
		t.Fatalf("bootstrapDefaultState (second call): %v", err)
	}
	after, _ := os.ReadFile(statePath)
	if string(before) != string(after) {
		t.Error("calling bootstrapDefaultState twice with the same inputs produced a different file")
	}
}

func TestBootstrapSeedFromPolicy(t *testing.T) {
	dir := t.TempDir()
	fixtureBearer := filepath.Join(dir, "fixture-bearer.token")
	if err := os.WriteFile(fixtureBearer, []byte("fixture-bearer-value"), 0o600); err != nil {
		t.Fatalf("write fixture bearer token: %v", err)
	}
	fixtureAdmin := filepath.Join(dir, "fixture-admin.token")
	if err := os.WriteFile(fixtureAdmin, []byte("fixture-admin-value"), 0o600); err != nil {
		t.Fatalf("write fixture admin token: %v", err)
	}
	promptFile := filepath.Join(dir, "welcome.wav")
	if err := os.WriteFile(promptFile, []byte("not-really-audio"), 0o600); err != nil {
		t.Fatalf("write fixture prompt: %v", err)
	}
	artifactDir := filepath.Join(dir, "artifacts")
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		t.Fatalf("mkdir artifact dir: %v", err)
	}

	fixture := map[string]any{
		"auth": map[string]any{
			"bearer_token_file": fixtureBearer,
			"admin_token_file":  fixtureAdmin,
		},
		"limits": map[string]any{"max_uas_total": 77},
		"prompts": []map[string]any{
			{"name": "welcome", "path": promptFile},
		},
		"artifact": map[string]any{"dir": artifactDir},
	}
	b, err := yaml.Marshal(fixture)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, b, 0o600); err != nil {
		t.Fatalf("write fixture policy: %v", err)
	}

	stateDir := filepath.Join(dir, "state")
	statePath := filepath.Join(stateDir, "state.yaml")
	var mintOut bytes.Buffer
	bearerPath, adminPath, err := mintTokensIfAbsent(stateDir, &mintOut, discardLogger())
	if err != nil {
		t.Fatalf("mintTokensIfAbsent: %v", err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	if err := bootstrapSeedFromPolicy(statePath, policyPath, bearerPath, adminPath, logger); err != nil {
		t.Fatalf("bootstrapSeedFromPolicy: %v", err)
	}

	p, err := policy.Load(statePath)
	if err != nil {
		t.Fatalf("Load the seeded state file: %v", err)
	}

	// (a) limits/prompts/artifact round-trip identically.
	if p.Limits.MaxUAsTotal != 77 {
		t.Errorf("Limits.MaxUAsTotal = %d, want 77 (from the fixture)", p.Limits.MaxUAsTotal)
	}
	if len(p.Prompts) != 1 || p.Prompts[0].Name != "welcome" || p.Prompts[0].Path != promptFile {
		t.Errorf("Prompts = %+v, want [{welcome %s}]", p.Prompts, promptFile)
	}
	if p.Artifact.Dir != artifactDir {
		t.Errorf("Artifact.Dir = %q, want %q", p.Artifact.Dir, artifactDir)
	}

	// (b) auth.*_token_file are the MINTED paths, not the fixture's.
	if p.Auth.BearerTokenFile != bearerPath {
		t.Errorf("Auth.BearerTokenFile = %q, want the minted path %q, not the fixture's", p.Auth.BearerTokenFile, bearerPath)
	}
	if p.Auth.AdminTokenFile != adminPath {
		t.Errorf("Auth.AdminTokenFile = %q, want the minted path %q, not the fixture's", p.Auth.AdminTokenFile, adminPath)
	}

	// (c) the minted bearer token authenticates; the fixture's does not.
	mintedBearer, err := os.ReadFile(bearerPath)
	if err != nil {
		t.Fatalf("read minted bearer token: %v", err)
	}
	if !p.MatchesBearerToken(mintedBearer) {
		t.Error("the MINTED bearer token does not authenticate against the seeded state file")
	}
	if p.MatchesBearerToken([]byte("fixture-bearer-value")) {
		t.Error("the FIXTURE's bearer token still authenticates -- it must have been overridden")
	}

	// (d) the WARN names both overridden keys.
	logText := logBuf.String()
	for _, want := range []string{"bearer_token_file", "admin_token_file", policyPath} {
		if !strings.Contains(logText, want) {
			t.Errorf("seed WARN log missing %q: %s", want, logText)
		}
	}

	// A second start does not re-seed: calling again with different fixture
	// values must not be exercised here (run.go's os.Stat gate is what
	// prevents the second call in practice); bootstrapSeedFromPolicy itself
	// is idempotent given the SAME inputs.
	before, _ := os.ReadFile(statePath)
	if err := bootstrapSeedFromPolicy(statePath, policyPath, bearerPath, adminPath, logger); err != nil {
		t.Fatalf("bootstrapSeedFromPolicy (second call): %v", err)
	}
	after, _ := os.ReadFile(statePath)
	if string(before) != string(after) {
		t.Error("calling bootstrapSeedFromPolicy twice with the same inputs produced a different file")
	}
}

func TestDefaultStatePath(t *testing.T) {
	t.Run("XDG_STATE_HOME set", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", "/xdg/state")
		got, err := defaultStatePath()
		if err != nil {
			t.Fatalf("defaultStatePath: %v", err)
		}
		want := filepath.Join("/xdg/state", "sipclient-mcp", "state.yaml")
		if got != want {
			t.Errorf("defaultStatePath() = %q, want %q", got, want)
		}
	})
	t.Run("XDG_STATE_HOME unset falls back to ~/.local/state", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", "")
		t.Setenv("HOME", "/home/fixture-user")
		got, err := defaultStatePath()
		if err != nil {
			t.Fatalf("defaultStatePath: %v", err)
		}
		want := filepath.Join("/home/fixture-user", ".local", "state", "sipclient-mcp", "state.yaml")
		if got != want {
			t.Errorf("defaultStatePath() = %q, want %q", got, want)
		}
	})
}

// TestTrueFirstRunBootstrapEndToEnd (P2-T3a/P2-T10): the daemon binary,
// started with NEITHER --state NOR --policy against a completely fresh
// $HOME, must bootstrap a complete state file on its own and become ready
// -- the run this whole bootstrap sequence exists for, and the one that
// would have failed outright before it (an empty PolicyPath used to be a
// hard startup error).
func TestTrueFirstRunBootstrapEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and forks the daemon binary")
	}
	bin := filepath.Join(t.TempDir(), "sipclient-mcpd")
	build := exec.Command("go", "build", "-o", bin,
		"github.com/sanntsu-corporation/sipclient-mcp/cmd/sipclient-mcpd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build daemon: %v\n%s", err, out)
	}

	home := t.TempDir()
	// D310-style: allocate our own port, release it immediately, then hand
	// it to the child -- see internal/testutil/loopback/daemon.go's own
	// comment on why a fixed port collides across packages.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate port: %v", err)
	}
	ln := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}

	cmd := exec.Command(bin, "--listen", ln)
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_STATE_HOME=")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	healthzURL := "http://" + ln + "/healthz"
	deadline := time.Now().Add(5 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if httpGetOK(healthzURL) {
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("daemon never answered /healthz\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}

	statePath := filepath.Join(home, ".local", "state", "sipclient-mcp", "state.yaml")
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("bootstrapped state file not found at %s: %v", statePath, err)
	}
	p, err := policy.Load(statePath)
	if err != nil {
		t.Fatalf("Load the bootstrapped state file: %v", err)
	}
	if p.Artifact.Dir == "" {
		t.Fatal("bootstrapped state file has no artifact.dir")
	}

	bearerFile := filepath.Join(home, ".local", "state", "sipclient-mcp", bearerTokenFileName)
	bearer, err := os.ReadFile(bearerFile)
	if err != nil {
		t.Fatalf("read minted bearer token: %v", err)
	}

	if !httpGetReadyz("http://"+ln+"/readyz", string(bearer)) {
		t.Fatalf("GET /readyz with the minted bearer token did not report ready\nstdout: %s\nstderr: %s",
			stdout.String(), stderr.String())
	}

	// A second start must NOT re-mint or re-seed.
	before, _ := os.ReadFile(statePath)
	cmd2 := exec.Command(bin, "--listen", ln)
	cmd2.Env = cmd.Env
	// The port is still held by cmd; cmd2 is expected to fail to bind, which
	// is fine -- this only checks that bootstrap itself (which runs before
	// the listener starts) does not touch the existing state file. Give it
	// a moment then kill it.
	_ = cmd2.Start()
	time.Sleep(200 * time.Millisecond)
	if cmd2.Process != nil {
		_ = cmd2.Process.Kill()
		_ = cmd2.Wait()
	}
	after, _ := os.ReadFile(statePath)
	if string(before) != string(after) {
		t.Error("a second start rewrote the state file (re-bootstrapped)")
	}
}

// TestExistingStateFileWithForeignTokenPathsNeitherMintsNorPrints is the
// regression pin for the first-run gate.
//
// THE BUG IT PINS — run() called mintTokensIfAbsent BEFORE it stat'd the state
// file, and mintTokensIfAbsent's own idempotency check keys on the two token
// files under the state DIRECTORY. A daemon started against an existing
// state.yaml whose auth.bearer_token_file / auth.admin_token_file point
// somewhere else therefore found neither file where it looked, minted two
// fresh 256-bit tokens, and printed "FIRST RUN — generated credentials (shown
// ONCE)" over two values that authenticate nothing — on a daemon that was
// already running fine on the credentials its own state file names.
// --print-tokens, which reads those same two stateDir paths, then reported the
// same wrong pair.
//
// Mutation check: move the mintTokensIfAbsent call back out of run()'s
// ErrNotExist branch, ahead of the stat, and this test reddens on both
// assertions (the banner appears and the two token files are created).
func TestExistingStateFileWithForeignTokenPathsNeitherMintsNorPrints(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and forks the daemon binary")
	}
	bin := filepath.Join(t.TempDir(), "sipclient-mcpd")
	build := exec.Command("go", "build", "-o", bin,
		"github.com/sanntsu-corporation/sipclient-mcp/cmd/sipclient-mcpd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build daemon: %v\n%s", err, out)
	}

	// The token files live in a DIFFERENT directory from the state file --
	// that separation is the whole point: it is what makes the stateDir paths
	// mintTokensIfAbsent checks absent while the daemon's real credentials are
	// perfectly present.
	stateDir, tokenDir := t.TempDir(), t.TempDir()
	bearerFile := filepath.Join(tokenDir, "bearer.token")
	adminFile := filepath.Join(tokenDir, "admin.token")
	if err := os.WriteFile(bearerFile, []byte("the-real-bearer-token"), 0o600); err != nil {
		t.Fatalf("write bearer token file: %v", err)
	}
	if err := os.WriteFile(adminFile, []byte("the-real-admin-token"), 0o600); err != nil {
		t.Fatalf("write admin token file: %v", err)
	}
	artifactDir := filepath.Join(stateDir, "artifacts")
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		t.Fatalf("create artifact directory: %v", err)
	}
	statePath := filepath.Join(stateDir, "state.yaml")
	p := policy.Defaults()
	p.Auth.BearerTokenFile = bearerFile
	p.Auth.AdminTokenFile = adminFile
	p.Artifact.Dir = artifactDir
	if err := policy.WriteFile(statePath, p); err != nil {
		t.Fatalf("write the pre-existing state file: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate port: %v", err)
	}
	ln := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}

	cmd := exec.Command(bin, "--listen", ln, "--state", statePath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	// exec copies the child's pipes into the two buffers on ITS OWN goroutine
	// until Wait returns, so the buffers may only be read after the daemon has
	// been stopped -- reading them while it runs is a data race, not merely a
	// torn read.
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	defer stop()

	deadline := time.Now().Add(5 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if httpGetOK("http://" + ln + "/healthz") {
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The daemon really is running on the credentials its state file names --
	// asserted while it is still up, before the buffers can be read.
	readyzOK := ready && httpGetReadyz("http://"+ln+"/readyz", "the-real-bearer-token")
	stop()

	if !ready {
		t.Fatalf("daemon never answered /healthz\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}
	if !readyzOK {
		t.Errorf("GET /readyz with the state file's OWN bearer token did not report ready\nstdout: %s\nstderr: %s",
			stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "FIRST RUN") {
		t.Errorf("the daemon printed the FIRST RUN credentials banner although its state file already "+
			"exists; the two values it shows authenticate nothing:\n%s", stdout.String())
	}
	for _, name := range []string{bearerTokenFileName, adminTokenFileName} {
		if _, err := os.Stat(filepath.Join(stateDir, name)); err == nil {
			t.Errorf("the daemon minted %s beside an EXISTING state file that points its auth.* "+
				"elsewhere; nothing reads that file", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("stat %s: %v", name, err)
		}
	}
}

func httpGetOK(url string) bool {
	resp, err := http.Get(url) //nolint:gosec,noctx // test helper, fixed loopback URL
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK
}

func httpGetReadyz(url, bearer string) bool {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK
}

// TestBootstrapSeedFromPolicyWithNoArtifactSectionStillGetsAWritableDir is
// B5's regression pin.
//
// THE BUG IT PINS — bootstrapDefaultState creates an artifacts directory and
// sets Artifact.Dir, with a comment explaining exactly why: an empty
// artifact.dir is a daemon that starts, authenticates and then answers
// /readyz 503 for the rest of its life (the loopback harness's own D294). Its
// sibling bootstrapSeedFromPolicy persisted the --policy seed verbatim and
// overrode only the Auth paths, so a seed with no `artifact:` section — which
// policy.Load accepts without complaint — produced precisely that
// permanently-unready daemon, silently, on the operator's very first start.
//
// The assertion is deliberately on the RELOADED state file, not on an
// in-memory struct: the state file is what the next start reads, so that is
// where a non-empty dir has to survive. The directory must also actually
// exist and be writable — a path recorded but never created fails /readyz the
// same way an empty one does.
//
// Mutation check: delete the `if seed.Artifact.Dir == ""` block from
// bootstrapSeedFromPolicy and this test reddens.
func TestBootstrapSeedFromPolicyWithNoArtifactSectionStillGetsAWritableDir(t *testing.T) {
	dir := t.TempDir()
	fixtureBearer := filepath.Join(dir, "fixture-bearer.token")
	if err := os.WriteFile(fixtureBearer, []byte("fixture-bearer-value"), 0o600); err != nil {
		t.Fatalf("write fixture bearer token: %v", err)
	}

	// The whole point of the fixture: NO `artifact:` section at all.
	b, err := yaml.Marshal(map[string]any{
		"auth":   map[string]any{"bearer_token_file": fixtureBearer},
		"limits": map[string]any{"max_uas_total": 42},
	})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, b, 0o600); err != nil {
		t.Fatalf("write fixture policy: %v", err)
	}

	stateDir := filepath.Join(dir, "state")
	statePath := filepath.Join(stateDir, "state.yaml")
	var mintOut bytes.Buffer
	bearerPath, adminPath, err := mintTokensIfAbsent(stateDir, &mintOut, discardLogger())
	if err != nil {
		t.Fatalf("mintTokensIfAbsent: %v", err)
	}
	if err := bootstrapSeedFromPolicy(statePath, policyPath, bearerPath, adminPath, discardLogger()); err != nil {
		t.Fatalf("bootstrapSeedFromPolicy: %v", err)
	}

	p, err := policy.Load(statePath)
	if err != nil {
		t.Fatalf("Load the seeded state file: %v", err)
	}
	if p.Artifact.Dir == "" {
		t.Fatal("seeded state file has an EMPTY artifact.dir: this daemon would answer /readyz 503 " +
			"forever, with nothing in its log naming the cause (D294)")
	}
	// The rest of the seed must still have survived — the default must be
	// additive, not a reset to policy.Defaults().
	if p.Limits.MaxUAsTotal != 42 {
		t.Errorf("Limits.MaxUAsTotal = %d, want 42 (from the fixture): defaulting artifact.dir must not "+
			"discard the rest of the seed", p.Limits.MaxUAsTotal)
	}

	info, err := os.Stat(p.Artifact.Dir)
	if err != nil {
		t.Fatalf("artifact.dir %q was recorded but not created: %v", p.Artifact.Dir, err)
	}
	if !info.IsDir() {
		t.Fatalf("artifact.dir %q is not a directory", p.Artifact.Dir)
	}
	// Writable in the only way that matters: an actual write.
	probe := filepath.Join(p.Artifact.Dir, "writability-probe")
	if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
		t.Fatalf("artifact.dir %q is not writable: %v", p.Artifact.Dir, err)
	}
	_ = os.Remove(probe)
}
