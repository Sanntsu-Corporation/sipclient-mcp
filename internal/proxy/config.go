// Package proxy implements sipclient-proxy: a local stdio MCP proxy that
// resolves SIP account NAMES to credentials from a local JSON file so the
// password never enters the model's context (spec 2026-09-30).
package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Account modes accepted in the config file.
const (
	ModeRegister = "register"
	ModeDirect   = "direct"

	configDirName  = "sipclient-proxy"
	configFileName = "sipclient-proxy.json"
)

// Account is one named SIP account. Password is never printed by any method of
// this package; see String and LogValue.
type Account struct {
	Mode      string `json:"mode"`
	SIPServer string `json:"sipserver,omitempty"`
	Port      int    `json:"port,omitempty"`
	Transport string `json:"transport,omitempty"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	// AuthAnyHost lifts the daemon's CF-046 destination guard for this account:
	// its UA answers a digest challenge from any host. A direct account has no
	// registrar/AOR anchor, so it needs this to authenticate at all.
	AuthAnyHost bool `json:"auth_any_host,omitempty"`
}

// Config is the whole sipclient-proxy.json file.
type Config struct {
	Upstream string             `json:"upstream"`
	Token    string             `json:"token"`
	Accounts map[string]Account `json:"accounts"`
	// AllowInsecureHTTP accepts a non-loopback http:// upstream. The daemon
	// token and every tool call then cross the network in cleartext; the
	// proxy warns at every start. The owner opted in to that risk (L-HTTP).
	AllowInsecureHTTP bool `json:"allow_insecure_http,omitempty"`
	// Problems maps the name of every account entry that failed validation to a
	// value-free description of the problem. Such an account is NOT in Accounts:
	// one bad entry must not stop the others from working (OD15).
	Problems map[string]string `json:"-"`
	// invalidPasswords holds the password of every entry in Problems (best
	// effort) so account_list can scrub them; never printed or put in a message.
	invalidPasswords []string
}

// AccountInfo is what account_list may reveal. It has no password field.
type AccountInfo struct {
	Name      string `json:"name"`
	Mode      string `json:"mode"`
	SIPServer string `json:"sipserver,omitempty"`
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Username  string `json:"username"`
}

// AccountProblem names an account entry that is present in the file but unusable.
type AccountProblem struct {
	Name    string `json:"name"`
	Problem string `json:"problem"`
}

// String returns a form that omits the password. Value receivers on purpose: a
// Config or Account passed BY VALUE to fmt or slog must be redacted too.
func (a Account) String() string {
	return fmt.Sprintf("account{mode=%s server=%s user=%s password=[redacted]}", a.Mode, a.SIPServer, a.Username)
}

// GoString makes %#v as safe as %v.
func (a Account) GoString() string { return a.String() }

// LogValue keeps the password out of slog output.
func (a Account) LogValue() slog.Value { return slog.StringValue(a.String()) }

// String returns a form that omits the token and every password.
func (c Config) String() string {
	return fmt.Sprintf("config{upstream=%s accounts=%d token=[redacted]}", c.Upstream, len(c.Accounts))
}

// GoString makes %#v as safe as %v.
func (c Config) GoString() string { return c.String() }

// LogValue keeps the token and passwords out of slog output.
func (c Config) LogValue() slog.Value { return slog.StringValue(c.String()) }

func defaultPort(transport string) int {
	if transport == "tls" {
		return 5061
	}
	return 5060
}

// rawConfig is the file as written: accounts stay raw so that one bad entry is
// reported per account instead of failing the whole file.
type rawConfig struct {
	Upstream          string                     `json:"upstream"`
	Token             string                     `json:"token"`
	Accounts          map[string]json.RawMessage `json:"accounts"`
	AllowInsecureHTTP bool                       `json:"allow_insecure_http"`
}

// LoadConfig reads and validates path. It fails as a whole only when the file is
// unreadable, is not one JSON object with the known top-level keys, or has an
// unusable upstream or token. An invalid account ENTRY does not fail the load:
// it is recorded in Config.Problems and left out of Config.Accounts (OD15).
// Errors name accounts and fields, never values. The path is trusted: symlinks
// are followed and ownership is not checked, so the file and its directory must
// be controlled by the current user (OD29).
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config file: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var raw rawConfig
	if err := dec.Decode(&raw); err != nil {
		return nil, sanitizeDecodeError(err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("config file has trailing data after the JSON object")
	}
	c := &Config{
		Upstream: strings.TrimSpace(raw.Upstream),
		Token:    strings.TrimSpace(raw.Token),
		Accounts: map[string]Account{},
		Problems: map[string]string{},

		AllowInsecureHTTP: raw.AllowInsecureHTTP,
	}
	if err := c.validateTop(); err != nil {
		return nil, err
	}
	for name, rm := range raw.Accounts {
		a, err := decodeAccount(rm)
		if err == nil {
			err = a.validate()
		}
		if err != nil {
			c.Problems[name] = err.Error()
			if pw := retainedPassword(rm); pw != "" {
				c.invalidPasswords = append(c.invalidPasswords, pw)
			}
			continue
		}
		c.Accounts[name] = a
	}
	return c, nil
}

// retainedPassword is the password of an invalid entry as text, so it can still
// be scrubbed: a JSON string as is, a JSON number as its literal text (a numeric
// password is a plausible typo). bool, null, object and array are not a password
// shape and are not retained. Best effort: a type error elsewhere in the entry
// does not matter.
func retainedPassword(rm json.RawMessage) string {
	var pw struct {
		Password json.RawMessage `json:"password"`
	}
	_ = json.Unmarshal(rm, &pw)
	raw := bytes.TrimSpace(pw.Password)
	switch {
	case len(raw) == 0:
		return ""
	case raw[0] == '"':
		var s string
		_ = json.Unmarshal(raw, &s)
		return s
	case raw[0] == '-' || (raw[0] >= '0' && raw[0] <= '9'):
		return string(raw)
	}
	return ""
}

func sanitizeDecodeError(err error) error {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Errorf("config file is not valid JSON (syntax error at byte %d)", syn.Offset)
	case errors.As(err, &typ):
		return fmt.Errorf("config field %q has the wrong type", typ.Field)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return errors.New("config file is empty or truncated")
	default:
		return fmt.Errorf("config file rejected: %w", err) // e.g. json: unknown field "x"
	}
}

// decodeAccount decodes one account entry strictly (unknown keys rejected).
func decodeAccount(rm json.RawMessage) (Account, error) {
	var a Account
	if t := bytes.TrimSpace(rm); len(t) == 0 || t[0] != '{' {
		return a, errors.New("entry must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(rm))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		var typ *json.UnmarshalTypeError
		if errors.As(err, &typ) {
			return Account{}, fmt.Errorf("field %q has the wrong type", typ.Field)
		}
		return Account{}, err // json: unknown field "x" (a key name, never a value)
	}
	return a, nil
}

// Validate applies the whole-file rules LoadConfig applies (a usable upstream
// URL and a non-blank token, after trimming) to a Config that was never read
// from disk, so a caller can refuse a bad one before saving it. It does not
// modify c and does not look at the accounts.
func (c *Config) Validate() error {
	t := *c
	t.Upstream, t.Token = strings.TrimSpace(c.Upstream), strings.TrimSpace(c.Token)
	return t.validateTop()
}

func (c *Config) validateTop() error {
	if c.Upstream == "" {
		return errors.New("config: upstream is required")
	}
	if err := validateUpstream(c.Upstream, c.AllowInsecureHTTP); err != nil {
		return err
	}
	if c.Token == "" {
		return errors.New("config: token is required")
	}
	return nil
}

// validateUpstream requires https, except for a loopback host (OD18): the
// bearer token must not cross a network in cleartext. Loopback means exactly
// "localhost", an IPv4 address in 127.0.0.0/8, or ::1 - a host name that merely
// starts with "localhost" or "127." is remote. allowInsecureHTTP (the
// allow_insecure_http config key) lifts only that cleartext refusal; the scheme,
// host and credentials rules still apply.
func validateUpstream(raw string, allowInsecureHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("config: upstream must be an http:// or https:// URL")
	}
	if u.User != nil {
		return errors.New("config: upstream must not contain credentials; put the token in \"token\"")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) && !allowInsecureHTTP {
		return errors.New(`config: upstream must use https:// unless the host is loopback (localhost, 127.0.0.0/8, ::1); the bearer token must not travel in cleartext; to accept that risk set "allow_insecure_http": true (configure: --allow-insecure-http)`)
	}
	return nil
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func (a Account) validate() error {
	switch a.Mode {
	case ModeRegister, ModeDirect:
	default:
		return errors.New(`mode must be "register" or "direct"`)
	}
	if a.Username == "" {
		return errors.New("username is required")
	}
	if a.Password == "" {
		return errors.New("password is required")
	}
	if a.Mode == ModeRegister && a.SIPServer == "" {
		return errors.New("sipserver is required for mode register")
	}
	if a.SIPServer != "" && !validSIPHost(a.SIPServer) {
		return errors.New(`sipserver must be a host name or IP address only (put the port in "port")`)
	}
	switch a.Transport {
	case "", "udp", "tcp", "tls":
	default:
		return errors.New(`transport must be "udp", "tcp" or "tls"`)
	}
	if a.Port < 0 || a.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

// validSIPHost accepts an IP literal (IPv6 with or without brackets; zone
// identifiers are not supported) or a plain host name. It rejects "host:port",
// paths, URI parameters and whitespace so the registrar and AOR URIs built from
// it (OD21) cannot be malformed by a config typo.
func validSIPHost(h string) bool {
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return true
	}
	if h == "" {
		return false
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// uriHost is the host as it appears in a SIP URI: an IPv6 literal is bracketed.
func (a Account) uriHost() string {
	h := strings.Trim(a.SIPServer, "[]")
	if ip := net.ParseIP(h); ip != nil && strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return h
}

// addSecretsTo adds to s the token, every valid account's password and
// credential pair, and every retained invalid-entry password: the file's whole
// secret set, used or not. It is the only enumeration of the file's secrets.
func (c *Config) addSecretsTo(s *secretSet) {
	s.add(c.Token)
	for _, a := range c.Accounts {
		s.addCredential(a.Username, a.Password)
	}
	for _, pw := range c.invalidPasswords {
		s.add(pw)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (a Account) withDefaults() Account {
	if a.Transport == "" {
		a.Transport = "udp"
	}
	if a.Port == 0 {
		a.Port = defaultPort(a.Transport)
	}
	return a
}

// Resolve returns the named account with defaults applied.
func (c *Config) Resolve(name string) (Account, error) {
	if p, bad := c.Problems[name]; bad {
		return Account{}, fmt.Errorf("account %q: %s", name, p)
	}
	a, ok := c.Accounts[name]
	if !ok {
		if len(c.Accounts) == 0 && len(c.Problems) == 0 {
			return Account{}, errors.New("unknown account (the requested name is not shown): no accounts are configured")
		}
		// The name is not echoed: a redaction marker at its position would tell a
		// model that its guess equals a password.
		msg := "unknown account (the requested name is not shown); valid accounts: " + strings.Join(sortedKeys(c.Accounts), ", ")
		if len(c.Problems) > 0 {
			// Parenthesised, not ";"-joined: a short secret is scrubbed only as a standalone token.
			msg += " (accounts with configuration problems (see account_list): " + strings.Join(sortedKeys(c.Problems), ", ") + ")"
		}
		return Account{}, errors.New(msg)
	}
	return a.withDefaults(), nil
}

// Invalid lists the account entries that failed validation, sorted by name.
func (c *Config) Invalid() []AccountProblem {
	out := make([]AccountProblem, 0, len(c.Problems))
	for _, n := range sortedKeys(c.Problems) {
		out = append(out, AccountProblem{Name: n, Problem: c.Problems[n]})
	}
	return out
}

// List returns every account without its password, sorted by name.
func (c *Config) List() []AccountInfo {
	out := make([]AccountInfo, 0, len(c.Accounts))
	for _, n := range sortedKeys(c.Accounts) {
		a := c.Accounts[n].withDefaults()
		out = append(out, AccountInfo{Name: n, Mode: a.Mode, SIPServer: a.SIPServer, Port: a.Port, Transport: a.Transport, Username: a.Username})
	}
	return out
}

// Save writes c to path atomically with mode 0600 (directory 0700).
func Save(path string, c *Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sipclient-proxy-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// DefaultConfigPath is spec section 4's default location.
func DefaultConfigPath(goos, home, appdata string) (string, error) {
	if goos == "windows" {
		if appdata == "" {
			return "", errors.New("%APPDATA% is not set; pass --config")
		}
		return filepath.Join(appdata, configDirName, configFileName), nil
	}
	if home == "" {
		return "", errors.New("home directory unknown; pass --config")
	}
	return filepath.Join(home, ".config", configDirName, configFileName), nil
}

// DefaultConfigPathFromEnv resolves DefaultConfigPath for this process.
func DefaultConfigPathFromEnv() (string, error) {
	home, _ := os.UserHomeDir()
	return DefaultConfigPath(runtime.GOOS, home, os.Getenv("APPDATA"))
}

// PermissionWarning returns a stderr warning, or "" when the file looks safe.
func PermissionWarning(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return permissionWarning(runtime.GOOS, path, fi.Mode())
}

// CleartextWarning returns a stderr warning when the opt-in is on and the
// upstream is a non-loopback http:// URL, else "".
func (c *Config) CleartextWarning() string {
	if !c.AllowInsecureHTTP {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(c.Upstream))
	if err != nil || u.Scheme != "http" || u.Host == "" || isLoopbackHost(u.Hostname()) {
		return ""
	}
	return "sipclient-proxy: warning: allow_insecure_http is set: the daemon bearer token travels in cleartext to " + u.Host
}

// InsecureUpstreamWarning loads the config at path and returns its
// CleartextWarning, or "" when the file cannot be loaded (Relay.Run reports that).
func InsecureUpstreamWarning(path string) string {
	c, err := LoadConfig(path)
	if err != nil {
		return ""
	}
	return c.CleartextWarning()
}

func permissionWarning(goos, path string, mode fs.FileMode) string {
	if goos == "windows" {
		return "sipclient-proxy: warning: cannot verify the access control list (ACL) of " + path + "; make sure only your user can read it"
	}
	if mode.Perm()&0o077 != 0 {
		return fmt.Sprintf("sipclient-proxy: warning: %s is accessible to other users (mode %04o); run: chmod 600 %s", path, mode.Perm(), path)
	}
	return ""
}
