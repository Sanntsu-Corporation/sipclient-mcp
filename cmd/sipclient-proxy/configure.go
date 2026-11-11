package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/proxy"
)

const serverName = "sipclient-proxy"

// runner is the seam through which configure touches other programs. LookPath
// returns the RESOLVED path and Run must be given that path, never the bare name.
type runner interface {
	LookPath(file string) (string, error)
	Run(path string, args ...string) ([]byte, error) // combined output
}

type execRunner struct{}

func (execRunner) LookPath(f string) (string, error) { return exec.LookPath(f) }

func (execRunner) Run(path string, args ...string) ([]byte, error) {
	if isBatchShim(runtime.GOOS, path) {
		cmd, err := batchCommand(path, args) // windows only; see runner_windows.go
		if err != nil {
			return nil, err
		}
		return cmd.CombinedOutput()
	}
	return exec.Command(path, args...).CombinedOutput()
}

type configureOptions struct {
	Remove          bool
	ConfigPath      string
	ExplicitConfig  bool
	Upstream, Token string
	Exe             string
	Home            string
	GOOS            string // decides shim handling and manual-command quoting; runtime.GOOS in production
	Now             func() time.Time
	// Pause separates the two reads that make a backup snapshot; nil means 50 ms.
	// Tests replace it (often to change the file between the reads).
	Pause          func()
	Runner         runner
	Stdin          io.Reader
	Stdout, Stderr io.Writer

	// AllowInsecureHTTP writes allow_insecure_http when the new file's upstream
	// is a non-loopback http:// URL (--allow-insecure-http).
	AllowInsecureHTTP bool
}

// client describes how to wire and unwire one MCP client through its own CLI.
type client struct {
	cli        string
	scope      string // shown after "registered"; "" when the client has none
	configFile func(home string) string
	validate   func(content []byte) error // nil: any stable content is accepted (no TOML parser in the standard library)
	removeArgs []string
	addArgs    func(exe string, extra []string) []string
}

var clients = []client{
	{
		cli:        "claude",
		scope:      " (user scope)",
		configFile: func(h string) string { return filepath.Join(h, ".claude.json") },
		validate: func(b []byte) error {
			if !json.Valid(b) {
				return errors.New("it is not valid JSON (Claude Code may be writing it right now)")
			}
			return nil
		},
		removeArgs: []string{"mcp", "remove", "--scope", "user", serverName},
		addArgs: func(exe string, extra []string) []string {
			return append([]string{"mcp", "add", "--scope", "user", serverName, "--", exe}, extra...)
		},
	},
	{
		cli:        "codex",
		configFile: func(h string) string { return filepath.Join(h, ".codex", "config.toml") },
		removeArgs: []string{"mcp", "remove", serverName},
		addArgs: func(exe string, extra []string) []string {
			return append([]string{"mcp", "add", serverName, "--", exe}, extra...)
		},
	},
}

// configureFlags is what the command line asked for; the token may still have to
// be read from a file or stdin (resolveToken).
type configureFlags struct {
	configureOptions
	tokenFile  string
	tokenStdin bool
}

func parseConfigureFlags(args []string) (configureFlags, error) {
	fs := flag.NewFlagSet("sipclient-proxy configure", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var f configureFlags
	fs.BoolVar(&f.Remove, "remove", false, "remove the client registrations (keeps the credentials file)")
	fs.StringVar(&f.ConfigPath, "config", "", "path to sipclient-proxy.json")
	fs.StringVar(&f.Upstream, "upstream", "", "daemon MCP URL, e.g. https://host:8100/mcp")
	fs.BoolVar(&f.AllowInsecureHTTP, "allow-insecure-http", false, "allow a non-loopback http:// upstream (the daemon token travels in cleartext)")
	fs.StringVar(&f.Token, "token", "", "daemon bearer token (visible in the process list and shell history; prefer --token-file)")
	fs.StringVar(&f.tokenFile, "token-file", "", "read the daemon bearer token from this file")
	fs.BoolVar(&f.tokenStdin, "token-stdin", false, "read the daemon bearer token from the first line of stdin")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	if fs.NArg() > 0 {
		return f, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	n := 0
	for _, given := range []bool{f.Token != "", f.tokenFile != "", f.tokenStdin} {
		if given {
			n++
		}
	}
	if n > 1 {
		return f, errors.New("use only one of --token, --token-file, --token-stdin")
	}
	return f, nil
}

// resolveToken returns the token from whichever source the flags named ("" if none).
func resolveToken(f configureFlags, stdin io.Reader) (string, error) {
	switch {
	case f.tokenFile != "":
		b, err := os.ReadFile(f.tokenFile)
		if err != nil {
			return "", fmt.Errorf("cannot read --token-file: %w", err)
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", errors.New("--token-file is empty")
		}
		return tok, nil
	case f.tokenStdin:
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", errors.New("--token-stdin: no token on stdin")
		}
		return strings.TrimSpace(line), nil
	}
	return f.Token, nil
}

func runConfigure(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		_, _ = fmt.Fprintln(stderr, "sipclient-proxy configure:", err)
		return 2
	}
	f, err := parseConfigureFlags(args)
	if err != nil {
		return fail(err)
	}
	o := f.configureOptions
	if o.Token, err = resolveToken(f, stdin); err != nil {
		return fail(err)
	}
	if f.tokenStdin {
		stdin = strings.NewReader("") // consumed; never prompt for anything else
	}
	o.ExplicitConfig = o.ConfigPath != ""
	if o.ConfigPath == "" {
		p, err := proxy.DefaultConfigPathFromEnv()
		if err != nil {
			return fail(err)
		}
		o.ConfigPath = p
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "sipclient-proxy configure: cannot locate own executable:", err)
		return 1
	}
	home, _ := os.UserHomeDir()
	o.Exe, o.Home, o.GOOS, o.Now, o.Runner = exe, home, runtime.GOOS, time.Now, execRunner{}
	o.Stdin, o.Stdout, o.Stderr = stdin, stdout, stderr
	if err := configure(o); err != nil {
		_, _ = fmt.Fprintln(stderr, "sipclient-proxy configure:", err)
		return 1
	}
	return 0
}

func configure(o configureOptions) error {
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	if o.ExplicitConfig { // registered as --config: a client starts the proxy from another directory
		abs, err := filepath.Abs(o.ConfigPath)
		if err != nil {
			return err
		}
		o.ConfigPath = abs
	}
	if !o.Remove {
		if err := ensureConfigFile(&o); err != nil {
			return err
		}
	}
	var extra []string
	if o.ExplicitConfig {
		extra = []string{"--config", o.ConfigPath}
	}
	for _, c := range clients {
		path, err := o.Runner.LookPath(c.cli)
		if err != nil {
			_, _ = fmt.Fprintf(o.Stdout, "skipped %s: '%s' not found on PATH\n", c.cli, c.cli)
			continue
		}
		var addArgs []string
		if !o.Remove {
			// Every local precondition of the add runs BEFORE the remove, so a refusal removes nothing.
			addArgs = c.addArgs(o.Exe, extra)
			if err := checkShim(o, c.cli, path, addArgs); err != nil {
				_, _ = fmt.Fprintf(o.Stderr, "could not register with %s. Run this yourself:\n  %s\n", c.cli, manualCommand(o.GOOS, c.cli, addArgs))
				return fmt.Errorf("%s: nothing was changed: %w", c.cli, err)
			}
		}
		bk, err := takeBackup(o, c)
		if err != nil {
			return fmt.Errorf("%s: backup failed, nothing was changed: %w", c.cli, err)
		}
		rmOut, rmErr := runClient(o, c.cli, path, c.removeArgs)
		if o.Remove {
			if rmErr != nil {
				_, _ = fmt.Fprintf(o.Stdout, "%s: not registered, already removed, or the command failed: %s\n  to remove it yourself: %s\n",
					c.cli, strings.TrimSpace(string(rmOut)+errText(rmErr)), manualCommand(o.GOOS, c.cli, c.removeArgs))
			} else {
				_, _ = fmt.Fprintf(o.Stdout, "%s: removed %s\n", c.cli, serverName)
			}
			bk.finish(o, rmErr == nil)
			continue
		}
		if out, err := runClient(o, c.cli, path, addArgs); err != nil {
			_, _ = fmt.Fprintf(o.Stderr, "could not register with %s. Run this yourself:\n  %s\n", c.cli, manualCommand(o.GOOS, c.cli, addArgs))
			bk.finish(o, false)
			return fmt.Errorf("%s mcp add failed (the previous %s entry, if any, was removed first): %w: %s", c.cli, serverName, err, strings.TrimSpace(string(out)))
		}
		_, _ = fmt.Fprintf(o.Stdout, "%s: registered %s%s\n", c.cli, serverName, c.scope)
		bk.finish(o, true)
	}
	if o.Remove {
		_, _ = fmt.Fprintf(o.Stdout, "credentials file left in place: %s (delete it yourself if you no longer need it)\n", o.ConfigPath)
		return nil
	}
	_, _ = fmt.Fprintf(o.Stdout, "\nClaude Desktop is not edited automatically. Add this to its config file\n"+
		"(macOS: ~/Library/Application Support/Claude/claude_desktop_config.json, Windows: %%APPDATA%%\\Claude\\claude_desktop_config.json), then restart Claude Desktop:\n\n%s\n",
		desktopSnippet(o.Exe, o.ConfigPath, o.ExplicitConfig))
	return nil
}

// runClient runs one client CLI through its RESOLVED path. A Windows .cmd/.bat
// shim is checked here for arguments cmd.exe cannot be given safely (the same
// check the real runner applies), so the refusal is testable on any OS.
func runClient(o configureOptions, cli, path string, args []string) ([]byte, error) {
	if err := checkShim(o, cli, path, args); err != nil {
		return nil, err
	}
	return o.Runner.Run(path, args...)
}

func checkShim(o configureOptions, cli, path string, args []string) error {
	if isBatchShim(o.GOOS, path) {
		if _, err := batchCmdLine(path, args); err != nil {
			return fmt.Errorf("%s is a batch shim and an argument cannot be passed to it safely: %w", cli, err)
		}
	}
	return nil
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return " (" + err.Error() + ")"
}

// isBatchShim reports whether path is a Windows batch file (npm-installed CLIs
// such as codex are .cmd shims). exec.Command cannot run those safely: cmd.exe
// re-parses the command line with its own quoting rules.
func isBatchShim(goos, path string) bool {
	if goos != "windows" {
		return false
	}
	ext := strings.ToLower(filepath.Ext(strings.ReplaceAll(path, `\`, "/")))
	return ext == ".cmd" || ext == ".bat"
}

// batchCmdLine builds the command line for cmd.exe /d /s /c "<line>": every
// element double-quoted. Inside double quotes cmd treats & | < > ( ) literally,
// but it still expands %VAR%, honours ^ and ! on some configurations, and has no
// way to escape a double quote, so any element containing one of those, a line
// break, NUL or a trailing backslash is REFUSED rather than escaped. Shim
// handling is UNVERIFIED on a real Windows machine (none is available here);
// the pure function is fully tested on every OS.
func batchCmdLine(path string, args []string) (string, error) {
	parts := append([]string{path}, args...)
	quoted := make([]string, len(parts))
	for i, p := range parts {
		if p == "" || strings.ContainsAny(p, "\"%^!\r\n\x00") || strings.HasSuffix(p, `\`) {
			return "", fmt.Errorf("argument %d contains a character cmd.exe cannot be given safely (one of \" %% ^ ! line break, or a trailing backslash)", i)
		}
		quoted[i] = `"` + p + `"`
	}
	return strings.Join(quoted, " "), nil
}

// systemCmdExe returns the absolute path of cmd.exe inside the Windows system
// directory, taken from %SystemRoot% (or %windir%). It never consults PATH or the
// current directory (N11): with LookPath an attacker-writable directory ahead of
// System32 could substitute another executable. The value must be an absolute
// Windows path; anything else is refused. UNVERIFIED on a real Windows machine.
func systemCmdExe(getenv func(string) string) (string, error) {
	root := strings.TrimSpace(getenv("SystemRoot"))
	if root == "" {
		root = strings.TrimSpace(getenv("windir"))
	}
	absolute := len(root) >= 3 && root[1] == ':' && (root[2] == '\\' || root[2] == '/') &&
		(root[0]|0x20 >= 'a' && root[0]|0x20 <= 'z')
	if !absolute {
		return "", errors.New("cannot locate the Windows system directory (%SystemRoot% is unset or not an absolute path)")
	}
	return strings.TrimRight(root, `\/`) + `\System32\cmd.exe`, nil
}

// manualCommand renders the command a person can paste into their own shell.
func manualCommand(goos, cli string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, cli)
	for _, a := range args {
		parts = append(parts, quoteArg(goos, a))
	}
	return strings.Join(parts, " ")
}

func quoteArg(goos, s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-") == "" {
		return s
	}
	if goos == "windows" {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return `'` + strings.ReplaceAll(s, `'`, `'\''`) + `'`
}

// ensureConfigFile creates the credentials file when absent. An existing file is
// validated and NEVER modified; if the caller also passed --upstream/--token it
// says so instead of silently ignoring them.
func ensureConfigFile(o *configureOptions) error {
	if _, err := os.Stat(o.ConfigPath); err == nil {
		c, err := proxy.LoadConfig(o.ConfigPath)
		if err != nil {
			return fmt.Errorf("existing config %s is invalid: %w", o.ConfigPath, err)
		}
		if o.Upstream != "" || o.Token != "" {
			_, _ = fmt.Fprintf(o.Stdout, "existing config kept; edit %s to change upstream/token (--upstream/--token ignored)\n", o.ConfigPath)
		}
		if o.AllowInsecureHTTP {
			_, _ = fmt.Fprintf(o.Stdout, "existing config kept; set \"allow_insecure_http\": true in %s yourself (--allow-insecure-http ignored)\n", o.ConfigPath)
		}
		for _, p := range c.Invalid() {
			_, _ = fmt.Fprintf(o.Stderr, "warning: account %q is unusable: %s\n", p.Name, p.Problem)
		}
		return nil
	}
	if o.Upstream == "" {
		up, err := promptLine(o, "Upstream URL (e.g. https://host:8100/mcp): ")
		if err != nil {
			return errors.New("upstream is required to create the config file (pass --upstream)")
		}
		o.Upstream = up
	}
	if o.Token == "" {
		return errors.New("the daemon token is required to create the config file: pass --token-file <path> (recommended), " +
			"--token-stdin, or --token (visible in the process list and shell history)")
	}
	c := &proxy.Config{Upstream: o.Upstream, Token: o.Token, Accounts: map[string]proxy.Account{}, AllowInsecureHTTP: o.AllowInsecureHTTP}
	ignored := false
	if c.AllowInsecureHTTP && c.CleartextWarning() == "" { // https:// or loopback: the key would only widen a later hand edit
		c.AllowInsecureHTTP, ignored = false, true
	}
	if err := c.Validate(); err != nil { // refuse a bad config BEFORE anything is written (no file, no directory)
		return err
	}
	if err := proxy.Save(o.ConfigPath, c); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(o.Stdout, "created %s (add accounts under \"accounts\", see docs/sipclient-proxy.md)\n", o.ConfigPath)
	if ignored {
		_, _ = fmt.Fprintln(o.Stdout, "--allow-insecure-http ignored: the upstream is https:// or loopback; allow_insecure_http not written")
	}
	if w := c.CleartextWarning(); w != "" {
		_, _ = fmt.Fprintln(o.Stdout, w)
	}
	return nil
}

// promptLine asks for one non-secret line, only when stdin is a terminal.
func promptLine(o *configureOptions, label string) (string, error) {
	f, ok := o.Stdin.(*os.File)
	if !ok {
		return "", errors.New("not a terminal")
	}
	if fi, err := f.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return "", errors.New("not a terminal")
	}
	_, _ = fmt.Fprint(o.Stderr, label)
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

const backupMarker = ".sipclient-proxy.bak-"

// readStable returns the content of path once two reads a moment apart agree and
// the content is valid for the client (validate, when set). It returns (nil, nil)
// when the file does not exist or is empty (nothing to lose; an empty file is
// never validated). Clients rewrite their config while running, so a single read can catch a
// half-written file; after three unstable or invalid attempts it gives up with an
// error that never contains file content.
func readStable(o configureOptions, path string, validate func([]byte) error) ([]byte, error) {
	pause := o.Pause
	if pause == nil {
		pause = func() { time.Sleep(50 * time.Millisecond) }
	}
	var problem error
	for attempt := 0; attempt < 3; attempt++ {
		first, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		pause()
		second, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			problem = errors.New("the file disappeared while it was being read")
			continue
		}
		if err != nil {
			return nil, err
		}
		switch {
		case !bytes.Equal(first, second):
			problem = errors.New("the file changed while it was being read")
		case len(first) == 0: // nothing to lose, whatever the client's validator would say
			return nil, nil
		case validate != nil && validate(first) != nil:
			problem = fmt.Errorf("%s cannot be used as a backup source: %w", filepath.Base(path), validate(first))
		default:
			return first, nil
		}
	}
	return nil, problem
}

// ownBackups lists this tool's backups of path: regular files only (never
// symlinks or directories), oldest name first.
func ownBackups(path string) []string {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	var out []string
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), base+backupMarker) && e.Type().IsRegular() {
				out = append(out, filepath.Join(dir, e.Name()))
			}
		}
	}
	return out
}

// writeExclusive creates a new file, mode 0600, that must not exist yet
// (O_EXCL: an existing name, including a symlink planted there, is never opened
// or followed). On a name clash it tries "<path>-1", "<path>-2", ...
func writeExclusive(path string, content []byte) (string, error) {
	for i := 0; i < 20; i++ {
		name := path
		if i > 0 {
			name = fmt.Sprintf("%s-%d", path, i)
		}
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		_, werr := f.Write(content)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			_ = os.Remove(name)
			return "", werr
		}
		return name, nil
	}
	return "", errors.New("could not find an unused backup name")
}

// backupSet is one client config's backup for this run. The older backups of the
// same file are removed only by finish(ok=true), i.e. after the client command
// has succeeded (OD28): if it fails, or the snapshot was bad, the previous good
// backup is still there.
type backupSet struct {
	older []string
	kept  string // set only when a reused backup is not the newest one
}

// takeBackup copies a client's config file next to it before configure edits it
// through that client's CLI. A copy identical to an existing backup is not
// repeated. The snapshot must be stable and valid (readStable) or nothing is
// written and an error names the previous backup(s), which stay. The path is
// always printed. A nil *backupSet (no file to back up) is valid.
func takeBackup(o configureOptions, c client) (*backupSet, error) {
	path := c.configFile(o.Home)
	content, err := readStable(o, path, c.validate)
	if err != nil {
		if kept := ownBackups(path); len(kept) > 0 {
			err = fmt.Errorf("%w (the previous backup was kept: %s)", err, strings.Join(kept, ", "))
		}
		return nil, err
	}
	if content == nil {
		return nil, nil
	}
	older := ownBackups(path)
	for i, prev := range older {
		if have, err := os.ReadFile(prev); err == nil && bytes.Equal(have, content) {
			printBackup(o, prev, true)
			b := &backupSet{older: append(older[:i:i], older[i+1:]...)} // the others are still pruned
			if i < len(older)-1 {
				b.kept = prev
			}
			return b, nil
		}
	}
	dst, err := writeExclusive(path+backupMarker+o.Now().UTC().Format("20060102T150405Z"), content)
	if err != nil {
		return nil, err
	}
	printBackup(o, dst, false)
	return &backupSet{older: older}, nil
}

// finish ends the run for one client: on success the older backups are removed
// (only the newest is kept); on failure they are kept and named.
func (b *backupSet) finish(o configureOptions, ok bool) {
	if b == nil || len(b.older) == 0 {
		return
	}
	if !ok {
		_, _ = fmt.Fprintf(o.Stdout, "the client command did not succeed, so the previous backup was kept: %s\n", strings.Join(b.older, ", "))
		return
	}
	for _, prev := range b.older {
		if err := os.Remove(prev); err != nil {
			_, _ = fmt.Fprintf(o.Stderr, "warning: could not remove the previous backup %s: %v\n", prev, err)
			continue
		}
		if b.kept != "" {
			_, _ = fmt.Fprintf(o.Stdout, "removed the other backup %s (kept the one matching the current config: %s)\n", prev, b.kept)
			continue
		}
		_, _ = fmt.Fprintf(o.Stdout, "removed the previous backup %s (only the newest is kept)\n", prev)
	}
}

func printBackup(o configureOptions, path string, reused bool) {
	state := "backup"
	if reused {
		state = "backup (already up to date)"
	}
	_, _ = fmt.Fprintf(o.Stdout, "%s: %s\n  it is a full copy of that client's config, including any other tokens it holds; delete it when it is no longer needed\n", state, path)
}

// desktopSnippet returns the Claude Desktop config fragment. Built with
// encoding/json so backslashes in Windows paths are escaped. It contains no secrets.
func desktopSnippet(exe, configPath string, explicit bool) string {
	entry := map[string]any{"command": exe}
	if explicit {
		entry["args"] = []string{"--config", configPath}
	}
	b, _ := json.MarshalIndent(map[string]any{"mcpServers": map[string]any{serverName: entry}}, "", "  ")
	return string(b)
}
