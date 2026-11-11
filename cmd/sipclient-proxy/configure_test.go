package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/proxy"
)

// fakeRunner records every command. LookPath returns a RESOLVED path and the
// tests require Run to be given exactly that path (never the bare CLI name).
type fakeRunner struct {
	have    map[string]string // CLI name -> resolved path ("" or absent: not on PATH)
	calls   []string
	failing map[string]error // full command line -> error
}

func bothCLIs() *fakeRunner {
	return &fakeRunner{have: map[string]string{"claude": "/fake/bin/claude", "codex": "/fake/bin/codex"}}
}

func (f *fakeRunner) LookPath(file string) (string, error) {
	if p := f.have[file]; p != "" {
		return p, nil
	}
	return "", errors.New("not found")
}

func (f *fakeRunner) Run(path string, args ...string) ([]byte, error) {
	line := path + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	if err := f.failing[line]; err != nil {
		return []byte(err.Error()), err
	}
	return nil, nil
}

func newOpts(t *testing.T, r *fakeRunner) (configureOptions, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	home := t.TempDir()
	var out, errb bytes.Buffer
	return configureOptions{
		ConfigPath: filepath.Join(home, ".config", "sipclient-proxy", "sipclient-proxy.json"),
		Upstream:   "https://host:8100/mcp",
		Token:      "CONFIGURE-TOKEN-SECRET",
		Exe:        "/opt/sipclient-proxy/sipclient-proxy",
		Home:       home,
		GOOS:       "linux",
		Now:        func() time.Time { return time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC) },
		Pause:      func() {}, // no real wait between the two snapshot reads
		Runner:     r,
		Stdin:      strings.NewReader(""),
		Stdout:     &out,
		Stderr:     &errb,
	}, &out, &errb
}

const (
	claudeRm  = "/fake/bin/claude mcp remove --scope user sipclient-proxy"
	claudeAdd = "/fake/bin/claude mcp add --scope user sipclient-proxy -- /opt/sipclient-proxy/sipclient-proxy"
	codexRm   = "/fake/bin/codex mcp remove sipclient-proxy"
	codexAdd  = "/fake/bin/codex mcp add sipclient-proxy -- /opt/sipclient-proxy/sipclient-proxy"
)

func TestConfigureFirstRun(t *testing.T) {
	r := bothCLIs()
	o, out, errb := newOpts(t, r)
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.calls, "|"); got != strings.Join([]string{claudeRm, claudeAdd, codexRm, codexAdd}, "|") {
		t.Fatalf("calls:\n%s", strings.Join(r.calls, "\n"))
	}
	c, err := proxy.LoadConfig(o.ConfigPath)
	if err != nil || c.Upstream != o.Upstream || c.Token != o.Token || len(c.Accounts) != 0 {
		t.Fatalf("config not created correctly: %v %v", c, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(o.ConfigPath); fi.Mode().Perm() != 0o600 {
			t.Errorf("config mode %o", fi.Mode().Perm())
		}
	}
	if strings.Contains(out.String()+errb.String(), o.Token) {
		t.Error("the token must never be printed")
	}
	if !strings.Contains(out.String(), "mcpServers") {
		t.Error("Claude Desktop snippet not printed")
	}
}

func TestConfigureIdempotent(t *testing.T) {
	r := bothCLIs()
	o, out, _ := newOpts(t, r)
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	// User adds an account by hand between runs.
	c, _ := proxy.LoadConfig(o.ConfigPath)
	c.Accounts = map[string]proxy.Account{"lab": {Mode: "direct", Username: "u", Password: "keep-me"}}
	if err := proxy.Save(o.ConfigPath, c); err != nil {
		t.Fatal(err)
	}
	first := append([]string(nil), r.calls...)
	r.calls = nil
	out.Reset()
	o.Upstream, o.Token = "https://other/mcp", "OTHER" // must NOT overwrite an existing file
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.calls, "|") != strings.Join(first, "|") {
		t.Fatalf("second run differs:\n%v\nvs\n%v", r.calls, first)
	}
	after, _ := proxy.LoadConfig(o.ConfigPath)
	if after.Accounts["lab"].Password != "keep-me" || after.Token != c.Token || after.Upstream != c.Upstream {
		t.Fatalf("existing config was modified: %+v", after)
	}
	if !strings.Contains(out.String(), "existing config kept") || !strings.Contains(out.String(), o.ConfigPath) {
		t.Errorf("--upstream/--token against an existing file must be reported, not silently ignored: %q", out.String())
	}
	// Without those flags there is nothing to report.
	out.Reset()
	o.Upstream, o.Token = "", ""
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "existing config kept") {
		t.Errorf("no notice expected when no flags were given: %q", out.String())
	}
}

func TestConfigureExplicitConfigPassedToClients(t *testing.T) {
	r := bothCLIs()
	o, _, _ := newOpts(t, r)
	o.ExplicitConfig = true
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	want := claudeAdd + " --config " + o.ConfigPath
	found := false
	for _, c := range r.calls {
		found = found || c == want
	}
	if !found {
		t.Fatalf("missing %q in %v", want, r.calls)
	}
}

// Rule 13 F4: a relative --config is registered as an absolute path, so a client
// started from any other directory still finds the file.
func TestConfigureRegistersAnAbsoluteExplicitConfig(t *testing.T) {
	r := bothCLIs()
	o, out, _ := newOpts(t, r)
	t.Chdir(o.Home)
	o.ExplicitConfig = true
	o.ConfigPath = filepath.Join("rel", "sipclient-proxy.json")
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(o.Home, "rel", "sipclient-proxy.json")
	for _, want := range []string{claudeAdd + " --config " + abs, codexAdd + " --config " + abs} {
		found := false
		for _, c := range r.calls {
			found = found || c == want
		}
		if !found {
			t.Errorf("missing %q in %v", want, r.calls)
		}
	}
	if _, err := os.Stat(abs); err != nil {
		t.Errorf("config file not created at %s: %v", abs, err)
	}
	if !strings.Contains(out.String(), `"`+abs+`"`) {
		t.Errorf("the desktop snippet must carry the absolute path: %s", out.String())
	}
}

func TestConfigureSkipsMissingCLI(t *testing.T) {
	r := &fakeRunner{have: map[string]string{"claude": "/fake/bin/claude"}}
	o, out, errb := newOpts(t, r)
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	// Exactly claude's two commands: codex is never run (not even via an empty
	// resolved path) and claude still proceeds.
	if got := strings.Join(r.calls, "|"); got != claudeRm+"|"+claudeAdd {
		t.Fatalf("only claude may be invoked when codex is absent: %v", r.calls)
	}
	if !strings.Contains(out.String()+errb.String(), "skipped codex") {
		t.Error("should say codex was skipped")
	}
}

func backups(t *testing.T, dir, prefix string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix+".sipclient-proxy.bak-") {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestConfigureBacksUpClientConfigs(t *testing.T) {
	r := bothCLIs()
	o, out, _ := newOpts(t, r)
	claudeCfg := filepath.Join(o.Home, ".claude.json")
	if err := os.WriteFile(claudeCfg, []byte(`{"other":"keep"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	bak := claudeCfg + ".sipclient-proxy.bak-20260930T120000Z"
	b, err := os.ReadFile(bak)
	if err != nil || string(b) != `{"other":"keep"}` {
		t.Fatalf("backup missing or wrong: %v %q", err, b)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(bak); fi.Mode().Perm() != 0o600 {
			t.Errorf("backup mode %o, want 600", fi.Mode().Perm())
		}
	}
	if !strings.Contains(out.String(), bak) || !strings.Contains(out.String(), "delete it when it is no longer needed") {
		t.Errorf("the backup path and the delete-when-done note must be printed: %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(o.Home, ".codex", "config.toml.sipclient-proxy.bak-20260930T120000Z")); err == nil {
		t.Error("no codex backup expected when config.toml does not exist")
	}
}

func TestConfigureDoesNotRepeatAnIdenticalBackup(t *testing.T) {
	r := bothCLIs()
	o, out, _ := newOpts(t, r)
	claudeCfg := filepath.Join(o.Home, ".claude.json")
	if err := os.WriteFile(claudeCfg, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	o.Now = func() time.Time { return time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC) }
	out.Reset()
	if err := configure(o); err != nil { // the fake runner does not change the file: same bytes
		t.Fatal(err)
	}
	if n := len(backups(t, o.Home, ".claude.json")); n != 1 {
		t.Fatalf("an unchanged client config must not be backed up again, found %d backups", n)
	}
	if !strings.Contains(out.String(), "already up to date") || !strings.Contains(out.String(), "delete it when it is no longer needed") {
		t.Errorf("the existing backup path should still be shown: %q", out.String())
	}
	// A changed client config does get a new backup.
	if err := os.WriteFile(claudeCfg, []byte(`{"a":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	names := backups(t, o.Home, ".claude.json")
	if len(names) != 1 {
		t.Fatalf("a changed client config gets a new backup and the old one is removed (OD28), found %v", names)
	}
	if b, err := os.ReadFile(filepath.Join(o.Home, names[0])); err != nil || string(b) != `{"a":2}` {
		t.Fatalf("the remaining backup must hold the NEW bytes: %v %q", err, b)
	}
}

// Rule 13 F7: when the current snapshot equals an existing backup (no new one is
// written), the other, older backups are still pruned after a successful run.
func TestConfigureReusedBackupStillPrunesOlderOnes(t *testing.T) {
	r := bothCLIs()
	o, _, _ := newOpts(t, r)
	claudeCfg := filepath.Join(o.Home, ".claude.json")
	stale := claudeCfg + ".sipclient-proxy.bak-20260101T000000Z"
	current := claudeCfg + ".sipclient-proxy.bak-20260201T000000Z"
	for path, body := range map[string]string{claudeCfg: `{"v":2}`, stale: `{"v":1}`, current: `{"v":2}`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	if names := backups(t, o.Home, ".claude.json"); len(names) != 1 || names[0] != filepath.Base(current) {
		t.Fatalf("only the reused (newest) backup may remain, found %v", names)
	}
}

// OD28: only the newest backup is kept; only this tool's own regular files are removed.
func TestConfigureKeepsOnlyTheNewestBackup(t *testing.T) {
	r := bothCLIs()
	o, out, _ := newOpts(t, r)
	claudeCfg := filepath.Join(o.Home, ".claude.json")
	if err := os.WriteFile(claudeCfg, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	first := claudeCfg + ".sipclient-proxy.bak-20260930T120000Z"
	if _, err := os.Stat(first); err != nil {
		t.Fatalf("premise: first backup missing: %v", err)
	}
	// Things that must survive: an unrelated sibling, a directory and a symlink named like a backup.
	keep := []string{claudeCfg + ".other", claudeCfg + ".sipclient-proxy.bak-dir"}
	if err := os.WriteFile(keep[0], []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keep[1], 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keep[0], claudeCfg+".sipclient-proxy.bak-link"); err == nil {
		keep = append(keep, claudeCfg+".sipclient-proxy.bak-link")
	}
	if err := os.WriteFile(claudeCfg, []byte(`{"v":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	o.Now = func() time.Time { return time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC) }
	out.Reset()
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	second := claudeCfg + ".sipclient-proxy.bak-20261002T090000Z"
	if b, err := os.ReadFile(second); err != nil || string(b) != `{"v":2}` {
		t.Fatalf("new backup missing or wrong: %v %q", err, b)
	}
	if _, err := os.Stat(first); err == nil {
		t.Error("the previous backup must be removed")
	}
	for _, k := range keep {
		if _, err := os.Lstat(k); err != nil {
			t.Errorf("%s must survive: %v", k, err)
		}
	}
	if !strings.Contains(out.String(), "removed the previous backup") || !strings.Contains(out.String(), first) {
		t.Errorf("the removal must be reported: %q", out.String())
	}
}

// F6 / Cycle C: the previous good backup is deleted only after the client command
// has succeeded, so a failing CLI never leaves the user without one.
func TestConfigureKeepsThePreviousBackupWhenTheClientCommandFails(t *testing.T) {
	for _, mode := range []string{"add fails", "remove fails"} {
		t.Run(mode, func(t *testing.T) {
			r := bothCLIs()
			o, out, _ := newOpts(t, r)
			claudeCfg := filepath.Join(o.Home, ".claude.json")
			if err := os.WriteFile(claudeCfg, []byte(`{"v":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := configure(o); err != nil { // leaves the first backup
				t.Fatal(err)
			}
			first := claudeCfg + ".sipclient-proxy.bak-20260930T120000Z"
			if err := os.WriteFile(claudeCfg, []byte(`{"v":2}`), 0o600); err != nil {
				t.Fatal(err)
			}
			o.Now = func() time.Time { return time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC) }
			if mode == "add fails" {
				r.failing = map[string]error{claudeAdd: errors.New("boom")}
			} else {
				r.failing = map[string]error{claudeRm: errors.New("not registered")}
				o.Remove = true
			}
			out.Reset()
			err := configure(o)
			if mode == "add fails" && err == nil {
				t.Fatal("a failed add must be fatal")
			}
			if mode == "remove fails" && err != nil {
				t.Fatalf("--remove of an absent entry must not fail: %v", err)
			}
			if _, err := os.Stat(first); err != nil {
				t.Fatalf("the previous backup must survive a failed client command: %v", err)
			}
			if !strings.Contains(out.String(), first) {
				t.Errorf("the kept backup's path must be printed: %q", out.String())
			}
			if strings.Contains(out.String(), "removed the previous backup") {
				t.Errorf("nothing may be pruned after a failure: %q", out.String())
			}
		})
	}
}

// F6: a half-written client config must never become the backup, and never
// costs the user the previous one.
func TestConfigureDoesNotTreatAnInvalidOrUnstableSnapshotAsABackup(t *testing.T) {
	t.Run("invalid JSON", func(t *testing.T) {
		r := bothCLIs()
		o, _, _ := newOpts(t, r)
		claudeCfg := filepath.Join(o.Home, ".claude.json")
		if err := os.WriteFile(claudeCfg, []byte(`{"v":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := configure(o); err != nil {
			t.Fatal(err)
		}
		first := claudeCfg + ".sipclient-proxy.bak-20260930T120000Z"
		if err := os.WriteFile(claudeCfg, []byte(`{"v":2,"half":`), 0o600); err != nil { // torn write
			t.Fatal(err)
		}
		o.Now = func() time.Time { return time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC) }
		r.calls = nil
		err := configure(o)
		if err == nil || !strings.Contains(err.Error(), "backup failed") || !strings.Contains(err.Error(), first) {
			t.Fatalf("want a backup error naming the kept backup, got %v", err)
		}
		if strings.Contains(err.Error(), `"half"`) {
			t.Errorf("the error must not carry file content: %v", err)
		}
		if b, err := os.ReadFile(first); err != nil || string(b) != `{"v":1}` {
			t.Fatalf("the previous backup must be intact: %v %q", err, b)
		}
		if n := len(backups(t, o.Home, ".claude.json")); n != 1 {
			t.Errorf("no new backup may be written from a bad snapshot, found %d", n)
		}
		for _, c := range r.calls {
			if strings.Contains(c, "claude") {
				t.Errorf("the client must not be touched when no good backup exists: %v", r.calls)
			}
		}
	})
	t.Run("changing under our feet", func(t *testing.T) {
		r := bothCLIs()
		o, _, _ := newOpts(t, r)
		codexCfg := filepath.Join(o.Home, ".codex", "config.toml")
		if err := os.MkdirAll(filepath.Dir(codexCfg), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(codexCfg, []byte("a = 0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		n := 0
		o.Pause = func() { n++; _ = os.WriteFile(codexCfg, []byte(fmt.Sprintf("a = %d\n", n)), 0o600) }
		err := configure(o)
		if err == nil || !strings.Contains(err.Error(), "changed while it was being read") {
			t.Fatalf("an unstable snapshot must be refused, got %v", err)
		}
		if len(backups(t, filepath.Dir(codexCfg), "config.toml")) != 0 {
			t.Error("no backup may be written from an unstable snapshot")
		}
	})
}

// F6 / Cycle C: the backup name is created exclusively, so a symlink planted at
// the expected name is never followed (the victim would be overwritten).
func TestConfigureBackupNeverFollowsAPlantedSymlink(t *testing.T) {
	r := bothCLIs()
	o, _, _ := newOpts(t, r)
	claudeCfg := filepath.Join(o.Home, ".claude.json")
	if err := os.WriteFile(claudeCfg, []byte(`{"secret":"tokens"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(o.Home, "victim.txt")
	if err := os.WriteFile(victim, []byte("VICTIM"), 0o600); err != nil {
		t.Fatal(err)
	}
	planted := claudeCfg + ".sipclient-proxy.bak-20260930T120000Z"
	if err := os.Symlink(victim, planted); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "VICTIM" {
		t.Fatalf("the backup followed the symlink and overwrote its target: %q", b)
	}
	if fi, err := os.Lstat(planted); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the planted symlink must be left alone: %v", err)
	}
	b, err := os.ReadFile(planted + "-1")
	if err != nil || string(b) != `{"secret":"tokens"}` {
		t.Fatalf("the backup must go to the next free name: %v %q", err, b)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(planted + "-1"); fi.Mode().Perm() != 0o600 {
			t.Errorf("backup mode %o, want 600", fi.Mode().Perm())
		}
	}
}

func TestConfigureAddFailureIsFatalAndPrintsTheManualCommand(t *testing.T) {
	r := bothCLIs()
	r.failing = map[string]error{claudeAdd: errors.New("boom")}
	o, _, errb := newOpts(t, r)
	err := configure(o)
	if err == nil || !strings.Contains(err.Error(), "claude") {
		t.Fatalf("want an error naming claude, got %v", err)
	}
	want := "claude mcp add --scope user sipclient-proxy -- /opt/sipclient-proxy/sipclient-proxy"
	if !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr should carry the exact manual command %q, got %q", want, errb.String())
	}
}

func TestConfigureRemove(t *testing.T) {
	r := bothCLIs()
	o, out, _ := newOpts(t, r)
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	o.Remove = true
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.calls, "|"); got != claudeRm+"|"+codexRm {
		t.Fatalf("remove must only run the remove commands: %v", r.calls)
	}
	if _, err := os.Stat(o.ConfigPath); err != nil {
		t.Error("credentials file must be left in place on --remove (OD8)")
	}
	if !strings.Contains(out.String(), o.ConfigPath) {
		t.Error("should tell the user the credentials file was left in place")
	}
}

func TestConfigureRemoveWhenAbsent(t *testing.T) {
	r := bothCLIs()
	r.failing = map[string]error{claudeRm: errors.New("No MCP server found"), codexRm: errors.New("not found")}
	o, out, _ := newOpts(t, r)
	o.Remove = true
	if err := configure(o); err != nil {
		t.Fatalf("--remove on a clean machine must not fail: %v", err)
	}
	if !strings.Contains(out.String(), "claude mcp remove --scope user sipclient-proxy") {
		t.Errorf("a failed remove should show the manual command: %q", out.String())
	}
}

func TestConfigureNeedsUpstreamAndTokenWhenFileAbsent(t *testing.T) {
	tests := []struct{ upstream, token, wantSub string }{
		{"", "tok", "upstream"},
		{"https://h/mcp", "", "--token-file"},
	}
	for _, tc := range tests {
		r := &fakeRunner{have: map[string]string{"claude": "/fake/bin/claude"}}
		o, _, _ := newOpts(t, r)
		o.Upstream, o.Token = tc.upstream, tc.token
		err := configure(o)
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Fatalf("upstream=%q token=%q: want an error mentioning %q, got %v", tc.upstream, tc.token, tc.wantSub, err)
		}
		if _, err := os.Stat(o.ConfigPath); err == nil {
			t.Error("no config file may be created on failure")
		}
		if len(r.calls) != 0 {
			t.Errorf("no client may be touched on failure: %v", r.calls)
		}
	}
}

func TestConfigureRefusesCleartextRemoteUpstream(t *testing.T) {
	r := bothCLIs()
	o, _, _ := newOpts(t, r)
	o.Upstream = "http://daemon.example:8100/mcp"
	err := configure(o)
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("want the https requirement, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Dir(o.ConfigPath)); statErr == nil {
		t.Error("nothing may be written before the config is validated: not even the directory")
	}
	if len(r.calls) != 0 {
		t.Errorf("no client may be touched: %v", r.calls)
	}
}

func TestConfigureRejectsInvalidExistingConfig(t *testing.T) {
	r := &fakeRunner{have: map[string]string{"claude": "/fake/bin/claude"}}
	o, _, _ := newOpts(t, r)
	if err := os.MkdirAll(filepath.Dir(o.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.ConfigPath, []byte(`{"upstream":"x"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configure(o); err == nil || len(r.calls) != 0 {
		t.Fatalf("invalid existing config must abort before touching clients (err=%v calls=%v)", err, r.calls)
	}
}

func TestConfigureWarnsAboutUnusableAccountsButProceeds(t *testing.T) {
	r := bothCLIs()
	o, _, errb := newOpts(t, r)
	if err := os.MkdirAll(filepath.Dir(o.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"upstream":"https://h/mcp","token":"t","accounts":{"broken":{"mode":"direct","password":"pw"}}}`
	if err := os.WriteFile(o.ConfigPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configure(o); err != nil {
		t.Fatalf("a bad account must not block configure: %v", err)
	}
	if !strings.Contains(errb.String(), `account "broken"`) || strings.Contains(errb.String(), "pw") {
		t.Fatalf("stderr should name the account and the problem, without values: %q", errb.String())
	}
	if len(r.calls) == 0 {
		t.Fatal("clients should still be configured")
	}
}

// ---- Windows .cmd/.bat shims (UNVERIFIED on a real Windows machine) --------

func TestConfigureRunsTheResolvedPathIncludingShims(t *testing.T) {
	const shim = `C:\Users\u\AppData\Roaming\npm\codex.cmd`
	const exe = `C:\Program Files\sipclient-proxy\sipclient-proxy.exe`
	r := &fakeRunner{have: map[string]string{"claude": `C:\Users\u\.local\bin\claude.exe`, "codex": shim}}
	o, _, _ := newOpts(t, r)
	o.GOOS, o.Exe = "windows", exe
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.calls {
		if strings.HasPrefix(c, "claude ") || strings.HasPrefix(c, "codex ") {
			t.Fatalf("the bare CLI name was executed: %q", c)
		}
	}
	want := shim + " mcp add sipclient-proxy -- " + exe
	found := false
	for _, c := range r.calls {
		found = found || c == want
	}
	if !found {
		t.Fatalf("the shim's resolved path was not used; calls: %v", r.calls)
	}
}

func TestConfigureRefusesUnsafeArgumentsForBatchShims(t *testing.T) {
	const shim = `C:\Users\u\AppData\Roaming\npm\codex.cmd`
	r := &fakeRunner{have: map[string]string{"codex": shim}}
	o, _, errb := newOpts(t, r)
	o.GOOS = "windows"
	o.Exe = `C:\tools\sipclient-proxy.exe`
	o.ExplicitConfig = true
	// A directory literally named "100%": cmd.exe would expand %...% inside the argument.
	o.ConfigPath = filepath.Join(o.Home, "100%", "sipclient-proxy.json")
	err := configure(o)
	if err == nil || !strings.Contains(err.Error(), "batch shim") {
		t.Fatalf("want a refusal naming the batch shim, got %v", err)
	}
	for _, c := range r.calls {
		if strings.Contains(c, " add ") {
			t.Fatalf("the unsafe add must not run: %v", r.calls)
		}
	}
	if !strings.Contains(errb.String(), "codex mcp add sipclient-proxy") {
		t.Fatalf("the manual command must be printed: %q", errb.String())
	}
}

func TestBatchCmdLine(t *testing.T) {
	line, err := batchCmdLine(`C:\Users\a b\npm\codex.cmd`, []string{"mcp", "add", "x", "--", `C:\Program Files\p\p.exe`, "--config", `C:\Users\a b\c.json`})
	if err != nil {
		t.Fatal(err)
	}
	want := `"C:\Users\a b\npm\codex.cmd" "mcp" "add" "x" "--" "C:\Program Files\p\p.exe" "--config" "C:\Users\a b\c.json"`
	if line != want {
		t.Fatalf("got  %s\nwant %s", line, want)
	}
	for _, bad := range []string{`a"b`, `50%`, `a^b`, `a!b`, "a\nb", "a\rb", "a\x00b", `C:\dir\`, ``} {
		if _, err := batchCmdLine("x.cmd", []string{bad}); err == nil {
			t.Errorf("argument %q must be refused", bad)
		}
	}
	for _, ok := range []string{`a&b`, `a|b`, `a<b>c`, `(x)`, `a b`, `C:\R&D\x.json`} {
		if _, err := batchCmdLine("x.cmd", []string{ok}); err != nil {
			t.Errorf("argument %q is literal inside quotes and must be accepted: %v", ok, err)
		}
	}
}

func TestIsBatchShim(t *testing.T) {
	tests := []struct {
		goos, path string
		want       bool
	}{
		{"windows", `C:\npm\codex.cmd`, true},
		{"windows", `C:\npm\CODEX.CMD`, true},
		{"windows", `C:\x\tool.bat`, true},
		{"windows", `C:\x\claude.exe`, false},
		{"windows", `C:\x\claude`, false},
		{"linux", "/usr/bin/tool.cmd", false},
		{"darwin", "/usr/bin/tool.bat", false},
	}
	for _, tc := range tests {
		if got := isBatchShim(tc.goos, tc.path); got != tc.want {
			t.Errorf("isBatchShim(%q, %q) = %v, want %v", tc.goos, tc.path, got, tc.want)
		}
	}
}

func TestManualCommandQuoting(t *testing.T) {
	args := []string{"mcp", "add", "sipclient-proxy", "--", `C:\Program Files\p\p.exe`}
	if got, want := manualCommand("windows", "claude", args), `claude mcp add sipclient-proxy -- "C:\Program Files\p\p.exe"`; got != want {
		t.Errorf("windows: got %s want %s", got, want)
	}
	args[4] = "/Users/o'brien/my dir/p"
	if got, want := manualCommand("darwin", "claude", args), `claude mcp add sipclient-proxy -- '/Users/o'\''brien/my dir/p'`; got != want {
		t.Errorf("posix: got %s want %s", got, want)
	}
}

// N11: cmd.exe comes from the system directory, never from PATH or the current directory.
func TestSystemCmdExe(t *testing.T) {
	env := func(kv ...string) func(string) string {
		return func(k string) string {
			for i := 0; i+1 < len(kv); i += 2 {
				if kv[i] == k {
					return kv[i+1]
				}
			}
			return ""
		}
	}
	tests := []struct {
		name string
		env  func(string) string
		want string // "" = error
	}{
		{"SystemRoot", env("SystemRoot", `C:\Windows`), `C:\Windows\System32\cmd.exe`},
		{"trailing separator", env("SystemRoot", `D:\WIN\`), `D:\WIN\System32\cmd.exe`},
		{"forward slashes", env("SystemRoot", `C:/Windows`), `C:/Windows\System32\cmd.exe`},
		{"windir fallback", env("windir", `C:\Windows`), `C:\Windows\System32\cmd.exe`},
		{"SystemRoot wins", env("SystemRoot", `C:\Windows`, "windir", `E:\Other`), `C:\Windows\System32\cmd.exe`},
		{"unset", env(), ""},
		{"relative", env("SystemRoot", `Windows`), ""},
		{"bare program name", env("SystemRoot", `cmd.exe`), ""},
		{"drive-relative", env("SystemRoot", `C:Windows`), ""},
	}
	for _, tc := range tests {
		got, err := systemCmdExe(tc.env)
		if (tc.want == "") != (err != nil) || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
}

// ---- token input --------------------------------------------------------

func TestParseConfigureFlagsAndTokenSources(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "tok")
	if err := os.WriteFile(tf, []byte("  FILE-TOKEN \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := parseConfigureFlags([]string{"--token-file", tf, "--upstream", "https://h/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := resolveToken(f, strings.NewReader("")); err != nil || tok != "FILE-TOKEN" {
		t.Fatalf("token-file: %q %v", tok, err)
	}
	f, _ = parseConfigureFlags([]string{"--token-stdin"})
	if tok, err := resolveToken(f, strings.NewReader("STDIN-TOKEN\nsecond line\n")); err != nil || tok != "STDIN-TOKEN" {
		t.Fatalf("token-stdin: %q %v", tok, err)
	}
	f, _ = parseConfigureFlags([]string{"--token", "FLAG-TOKEN"})
	if tok, _ := resolveToken(f, strings.NewReader("")); tok != "FLAG-TOKEN" {
		t.Fatalf("token flag: %q", tok)
	}
	f, _ = parseConfigureFlags([]string{"--token-stdin"})
	if _, err := resolveToken(f, strings.NewReader("")); err == nil {
		t.Fatal("empty stdin must be an error")
	}
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	f, _ = parseConfigureFlags([]string{"--token-file", empty})
	if _, err := resolveToken(f, strings.NewReader("")); err == nil {
		t.Fatal("an empty token file must be an error")
	}
	f, _ = parseConfigureFlags([]string{"--token-file", filepath.Join(dir, "absent")})
	if _, err := resolveToken(f, strings.NewReader("")); err == nil {
		t.Fatal("a missing token file must be an error")
	}
	for _, bad := range [][]string{
		{"--token", "a", "--token-file", tf},
		{"--token-stdin", "--token", "a"},
		{"--nope"},
		{"stray"},
	} {
		if _, err := parseConfigureFlags(bad); err == nil {
			t.Errorf("%v must be a usage error", bad)
		}
	}
}

func TestSnippetEscapesWindowsPath(t *testing.T) {
	exe := `C:\Program Files\sipclient-proxy\sipclient-proxy.exe`
	s := desktopSnippet(exe, `C:\Users\u\AppData\Roaming\sipclient-proxy\sipclient-proxy.json`, true)
	var v struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if err := json.Unmarshal([]byte(s[start:end+1]), &v); err != nil {
		t.Fatalf("snippet is not valid JSON: %v\n%s", err, s)
	}
	e := v.MCPServers["sipclient-proxy"]
	if e.Command != exe || len(e.Args) != 2 || e.Args[0] != "--config" {
		t.Fatalf("snippet entry = %+v", e)
	}
}

// CF-047 (a): the batch-shim refusal of the add is decided before the remove runs.
func TestConfigureChecksTheBatchShimBeforeRemoving(t *testing.T) {
	r := &fakeRunner{have: map[string]string{"claude": `C:\npm\claude.cmd`}}
	o, out, errb := newOpts(t, r)
	o.GOOS = "windows"
	o.Exe = `C:\100%\sipclient-proxy.exe` // % cannot be passed to cmd.exe safely
	if err := configure(o); err == nil {
		t.Fatal("configure must fail for a shim that cannot be given the add arguments")
	}
	if len(r.calls) != 0 {
		t.Fatalf("the runner must not see the remove (or anything else) when the add would be refused, got %v", r.calls)
	}
	if !strings.Contains(out.String()+errb.String(), "claude mcp add --scope user sipclient-proxy") {
		t.Errorf("the manual add command must be printed: %q %q", out.String(), errb.String())
	}
}

// CF-047 (b): an empty (zero-byte) client config is nothing to back up, not a failure.
func TestConfigureAcceptsAnEmptyClaudeJSON(t *testing.T) {
	r := bothCLIs()
	o, _, _ := newOpts(t, r)
	claudeCfg := filepath.Join(o.Home, ".claude.json")
	if err := os.WriteFile(claudeCfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configure(o); err != nil {
		t.Fatalf("an empty .claude.json must not fail the backup: %v", err)
	}
	if n := len(backups(t, o.Home, ".claude.json")); n != 0 {
		t.Errorf("an empty file needs no backup, found %d", n)
	}
	if !containsCall(r.calls, claudeAdd) {
		t.Errorf("the add must run, calls: %v", r.calls)
	}
}

func TestConfigureStillRefusesAnInvalidNonEmptyClaudeJSON(t *testing.T) {
	r := bothCLIs()
	o, _, _ := newOpts(t, r)
	if err := os.WriteFile(filepath.Join(o.Home, ".claude.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := configure(o)
	if err == nil || !strings.Contains(err.Error(), "backup failed, nothing was changed") {
		t.Fatalf("a non-empty invalid file must still fail the backup, got %v", err)
	}
	if len(r.calls) != 0 {
		t.Errorf("nothing may run, got %v", r.calls)
	}
}

// CF-047 (c): only a client that has a scope names one.
func TestConfigureRegistrationMessagesNameScopeOnlyForClaude(t *testing.T) {
	r := bothCLIs()
	o, out, _ := newOpts(t, r)
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "claude: registered sipclient-proxy (user scope)\n") {
		t.Errorf("claude line missing: %q", out.String())
	}
	if !strings.Contains(out.String(), "codex: registered sipclient-proxy\n") {
		t.Errorf("codex line must carry no scope text: %q", out.String())
	}
}

// CF-047 (d): a reused backup that is not the newest is not described as "the newest".
func TestConfigurePruneMessageWhenTheReusedBackupIsNotTheNewest(t *testing.T) {
	r := bothCLIs()
	o, out, _ := newOpts(t, r)
	claudeCfg := filepath.Join(o.Home, ".claude.json")
	b1 := claudeCfg + ".sipclient-proxy.bak-20260101T000000Z"
	b2 := claudeCfg + ".sipclient-proxy.bak-20260201T000000Z"
	for path, body := range map[string]string{claudeCfg: `{"v":1}`, b1: `{"v":1}`, b2: `{"v":2}`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	if names := backups(t, o.Home, ".claude.json"); len(names) != 1 || names[0] != filepath.Base(b1) {
		t.Fatalf("B1 (matches the current config) must be the one kept, found %v", names)
	}
	if strings.Contains(out.String(), "only the newest is kept") {
		t.Errorf("wrong wording, B1 is not the newest: %q", out.String())
	}
	if !strings.Contains(out.String(), "kept the one matching the current config") {
		t.Errorf("the message must say which backup was kept: %q", out.String())
	}
}

func containsCall(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}

func TestConfigureWritesTheInsecureKeyAndItRoundTrips(t *testing.T) {
	o, out, _ := newOpts(t, bothCLIs())
	o.Upstream = "http://daemon.example:8100/mcp"
	o.AllowInsecureHTTP = true
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(o.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"allow_insecure_http": true`) {
		t.Fatalf("the key was not written: %s", b)
	}
	cfg, err := proxy.LoadConfig(o.ConfigPath)
	if err != nil || !cfg.AllowInsecureHTTP {
		t.Fatalf("round trip: %v, %+v", err, cfg)
	}
	if !strings.Contains(out.String(), "travels in cleartext to daemon.example:8100") {
		t.Fatalf("stdout lacks the warning: %q", out.String())
	}
}

// Pin: no flag, no key.
func TestConfigureWithoutTheFlagWritesNoInsecureKey(t *testing.T) {
	o, _, _ := newOpts(t, bothCLIs())
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(o.ConfigPath)
	if strings.Contains(string(b), "allow_insecure_http") {
		t.Fatalf("the file carries the key: %s", b)
	}
}

func TestConfigureReportsTheIgnoredInsecureFlagForAnExistingFile(t *testing.T) {
	o, out, _ := newOpts(t, bothCLIs())
	if err := os.MkdirAll(filepath.Dir(o.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"upstream":"https://host:8100/mcp","token":"t","accounts":{}}`)
	if err := os.WriteFile(o.ConfigPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	o.Upstream, o.Token = "", ""
	o.AllowInsecureHTTP = true
	if err := configure(o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `set "allow_insecure_http": true in `+o.ConfigPath+` yourself (--allow-insecure-http ignored)`) {
		t.Fatalf("stdout lacks the ignored-flag line: %q", out.String())
	}
	if got, _ := os.ReadFile(o.ConfigPath); !bytes.Equal(got, body) {
		t.Fatalf("the existing file was modified: %s", got)
	}
}

func TestParseConfigureFlagsAcceptsAllowInsecureHTTP(t *testing.T) {
	f, err := parseConfigureFlags([]string{"--allow-insecure-http"})
	if err != nil || !f.AllowInsecureHTTP {
		t.Fatalf("with the flag: %v, %v", err, f.AllowInsecureHTTP)
	}
	f, err = parseConfigureFlags(nil)
	if err != nil || f.AllowInsecureHTTP {
		t.Fatalf("without the flag: %v, %v", err, f.AllowInsecureHTTP)
	}
}

func TestConfigureIgnoresTheInsecureFlagForAnHTTPSOrLoopbackUpstream(t *testing.T) {
	for _, up := range []string{"https://h/mcp", "http://127.0.0.1:8100/mcp"} {
		o, out, _ := newOpts(t, bothCLIs())
		o.Upstream = up
		o.AllowInsecureHTTP = true
		if err := configure(o); err != nil {
			t.Fatalf("%s: %v", up, err)
		}
		b, _ := os.ReadFile(o.ConfigPath)
		if strings.Contains(string(b), "allow_insecure_http") {
			t.Errorf("%s: the key was written: %s", up, b)
		}
		if !strings.Contains(out.String(), "--allow-insecure-http ignored: the upstream is https:// or loopback") {
			t.Errorf("%s: stdout lacks the ignored line: %q", up, out.String())
		}
	}
}
