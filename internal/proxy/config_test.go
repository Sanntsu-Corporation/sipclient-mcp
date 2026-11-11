package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testPassword = `p@ss"w\ord<&>é`

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sipclient-proxy.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func goodConfigJSON() string {
	pw, _ := json.Marshal(testPassword)
	return `{
  "upstream": "https://host:8100/mcp",
  "token": "tok-123",
  "accounts": {
    "sbc-lab":   {"mode":"register","sipserver":"10.1.2.3","port":5070,"transport":"tcp","username":"1001","password":` + string(pw) + `},
    "carrier-x": {"mode":"direct","transport":"tls","username":"acme","password":` + string(pw) + `},
    "plain":     {"mode":"register","sipserver":"pbx.example","username":"u","password":"pw"}
  }
}`
}

func TestLoadConfigOK(t *testing.T) {
	c, err := LoadConfig(writeFile(t, goodConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Upstream != "https://host:8100/mcp" || c.Token != "tok-123" || len(c.Accounts) != 3 {
		t.Fatalf("unexpected config: %+v", c.List())
	}
	if c.Accounts["carrier-x"].SIPServer != "" {
		t.Fatal("direct account must allow an empty sipserver")
	}
}

func TestLoadConfigTrimsToken(t *testing.T) {
	c, err := LoadConfig(writeFile(t, `{"upstream":" https://h/mcp ","token":"  tok-1\n"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "tok-1" || c.Upstream != "https://h/mcp" {
		t.Fatalf("token/upstream not trimmed: %q %q", c.Token, c.Upstream)
	}
}

// Whole-file failures (OD15): the proxy cannot start, or cannot trust the file.
func TestLoadConfigRejectsWholeFile(t *testing.T) {
	tests := []struct {
		name, body, wantSub string
	}{
		{"no upstream", `{"token":"t","accounts":{}}`, "upstream"},
		{"bad upstream scheme", `{"upstream":"ftp://h","token":"t"}`, "upstream"},
		{"upstream with credentials", `{"upstream":"https://u:SECRETPW@h/mcp","token":"t"}`, "credentials"},
		{"no token", `{"upstream":"https://h/mcp","accounts":{}}`, "token"},
		{"blank token", `{"upstream":"https://h/mcp","token":"  \n","accounts":{}}`, "token"},
		{"token wrong type", `{"upstream":"https://h/mcp","token":5}`, "token"},
		{"unknown top-level key", `{"upstream":"https://h/mcp","token":"t","acounts":{}}`, "acounts"},
		{"trailing object", goodConfigJSON() + `{}`, "trailing"},
		{"trailing garbage", goodConfigJSON() + ` xyz`, "trailing"},
		{"trailing closing brace", goodConfigJSON() + `}`, "trailing"},
		{"trailing closing bracket", goodConfigJSON() + `]`, "trailing"},
		{"syntax error near a secret", `{"upstream":"https://h/mcp","token":"t","accounts":{"a":{"mode":"direct","password":SECRETPW}}}`, "not valid JSON"},
		{"empty file", ``, "empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadConfig(writeFile(t, tc.body))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not mention %q", err, tc.wantSub)
			}
			// This check cannot fail today (encoding/json errors never carry
			// values) and pins nothing by itself. What pins the sanitising is the
			// wantSub column: "not valid JSON" only appears if sanitizeDecodeError
			// replaced the decoder's own message (Step 6, mutation 1).
			if strings.Contains(err.Error(), "SECRETPW") {
				t.Fatalf("error leaks the password: %q", err)
			}
		})
	}
}

// Per-account failures (OD15): the file still loads; the entry is reported
// under Problems, absent from Accounts, and the other accounts keep working.
func TestLoadConfigDefersAccountProblems(t *testing.T) {
	tests := []struct {
		name, body, wantSub string
	}{
		{"missing mode", `{"username":"u","password":"SECRETPW"}`, "mode"},
		{"bad mode", `{"mode":"proxy","username":"u","password":"SECRETPW"}`, "mode"},
		{"missing username", `{"mode":"direct","password":"SECRETPW"}`, "username"},
		{"missing password", `{"mode":"direct","username":"u"}`, "password"},
		{"register without sipserver", `{"mode":"register","username":"u","password":"SECRETPW"}`, "sipserver"},
		{"sipserver with port", `{"mode":"register","sipserver":"10.1.2.3:5060","username":"u","password":"SECRETPW"}`, "sipserver"},
		{"sipserver with path", `{"mode":"register","sipserver":"h/x","username":"u","password":"SECRETPW"}`, "sipserver"},
		{"bad transport", `{"mode":"direct","transport":"sctp","username":"u","password":"SECRETPW"}`, "transport"},
		{"port too big", `{"mode":"direct","port":65536,"username":"u","password":"SECRETPW"}`, "port"},
		{"port negative", `{"mode":"direct","port":-1,"username":"u","password":"SECRETPW"}`, "port"},
		{"unknown account key", `{"mode":"direct","usernme":"u","username":"u","password":"SECRETPW"}`, "usernme"},
		{"wrong type", `{"mode":"direct","username":5,"password":"SECRETPW"}`, "username"},
		{"not an object", `"SECRETPW"`, "JSON object"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"upstream":"https://h/mcp","token":"t","accounts":{"bad":` + tc.body +
				`,"good":{"mode":"direct","username":"u","password":"pw"}}}`
			c, err := LoadConfig(writeFile(t, body))
			if err != nil {
				t.Fatalf("one bad account must not fail the load: %v", err)
			}
			if _, ok := c.Accounts["bad"]; ok {
				t.Fatal("invalid account must not be usable")
			}
			if _, ok := c.Accounts["good"]; !ok {
				t.Fatal("valid account must survive its neighbour's problem")
			}
			_, rerr := c.Resolve("bad")
			if rerr == nil || !strings.Contains(rerr.Error(), `account "bad": `) || !strings.Contains(rerr.Error(), tc.wantSub) {
				t.Fatalf("Resolve error %v does not name account and %q", rerr, tc.wantSub)
			}
			inv := c.Invalid()
			if len(inv) != 1 || inv[0].Name != "bad" || !strings.Contains(inv[0].Problem, tc.wantSub) {
				t.Fatalf("Invalid() = %+v", inv)
			}
			if strings.Contains(rerr.Error(), "SECRETPW") || strings.Contains(inv[0].Problem, "SECRETPW") {
				t.Fatalf("problem text leaks the password: %v / %+v", rerr, inv)
			}
		})
	}
}

// CF-046: auth_any_host is an optional bool in an account entry; a wrong type
// makes that entry invalid by name and leaves the others working.
func TestLoadConfigAuthAnyHostType(t *testing.T) {
	load := func(v string) *Config {
		body := `{"upstream":"https://h/mcp","token":"t","accounts":{"x":{"mode":"direct","username":"u","password":"pw","auth_any_host":` + v +
			`},"good":{"mode":"direct","username":"u","password":"pw"}}}`
		c, err := LoadConfig(writeFile(t, body))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		return c
	}
	if c := load("true"); !c.Accounts["x"].AuthAnyHost || c.Accounts["good"].AuthAnyHost {
		t.Errorf("true: x=%v good=%v, want true/false", c.Accounts["x"].AuthAnyHost, c.Accounts["good"].AuthAnyHost)
	}
	if c := load("false"); c.Accounts["x"].AuthAnyHost {
		t.Error("false: AuthAnyHost = true")
	}
	for _, v := range []string{`"true"`, `1`, `{}`} {
		body := `{"upstream":"https://h/mcp","token":"t","accounts":{"x":{"mode":"direct","username":"u","password":"pw","auth_any_host":` + v +
			`},"good":{"mode":"direct","username":"u","password":"pw"}}}`
		c, err := LoadConfig(writeFile(t, body))
		if err != nil {
			t.Fatalf("%s: one bad entry must not fail the load: %v", v, err)
		}
		if _, ok := c.Accounts["x"]; ok {
			t.Errorf("%s: entry must be invalid", v)
		}
		if _, ok := c.Accounts["good"]; !ok {
			t.Errorf("%s: the other entry must survive", v)
		}
		inv := c.Invalid()
		if len(inv) != 1 || inv[0].Name != "x" || !strings.Contains(inv[0].Problem, "auth_any_host") {
			t.Errorf("%s: Invalid() = %+v, want x naming auth_any_host", v, inv)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name          string
		upstream, tok string
		wantSub       string // "" = valid
	}{
		{"https", "https://host:8100/mcp", "t", ""},
		{"loopback http", "http://127.0.0.1:8100/mcp", "t", ""},
		{"trimmed", " https://h/mcp\n", "  t\n", ""},
		{"remote http", "http://host:8100/mcp", "t", "https://"},
		{"blank token", "https://h/mcp", " \n", "token"},
		{"no upstream", "", "t", "upstream"},
		{"credentials in the URL", "https://u:SECRETPW@h/mcp", "t", "credentials"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{Upstream: tc.upstream, Token: tc.tok}
			err := c.Validate()
			switch {
			case tc.wantSub == "" && err != nil:
				t.Fatalf("want valid, got %v", err)
			case tc.wantSub != "" && (err == nil || !strings.Contains(err.Error(), tc.wantSub)):
				t.Fatalf("want an error mentioning %q, got %v", tc.wantSub, err)
			}
			if c.Upstream != tc.upstream || c.Token != tc.tok {
				t.Fatal("Validate must not modify the Config")
			}
		})
	}
}

func TestLoadConfigUpstreamScheme(t *testing.T) {
	tests := []struct {
		upstream string
		ok       bool
	}{
		{"https://host:8100/mcp", true},
		{"https://127.0.0.1:8100/mcp", true},
		{"http://localhost:8100/mcp", true},
		{"http://LOCALHOST/mcp", true},
		{"http://127.0.0.1:8100/mcp", true},
		{"http://127.5.5.5/mcp", true},
		{"http://[::1]:8100/mcp", true},
		{"http://host:8100/mcp", false},
		{"http://10.0.0.5:8100/mcp", false},
		{"http://localhost.evil.example/mcp", false},
		{"http://localhostx/mcp", false},
		{"http://127.0.0.1.evil.example/mcp", false},
		{"http://[::2]:8100/mcp", false},
		{"http://0.0.0.0:8100/mcp", false},
		{"ws://localhost/mcp", false},
	}
	for _, tc := range tests {
		t.Run(tc.upstream, func(t *testing.T) {
			_, err := LoadConfig(writeFile(t, `{"upstream":"`+tc.upstream+`","token":"t"}`))
			if (err == nil) != tc.ok {
				t.Fatalf("upstream %q: ok=%v err=%v", tc.upstream, tc.ok, err)
			}
		})
	}
	_, err := LoadConfig(writeFile(t, `{"upstream":"http://host:8100/mcp","token":"t"}`))
	if err == nil || !strings.Contains(err.Error(), "https://") || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("cleartext error should tell the user what to do: %v", err)
	}
}

func TestSIPHostHandling(t *testing.T) {
	tests := []struct {
		in      string
		valid   bool
		uriHost string
	}{
		{"10.1.2.3", true, "10.1.2.3"},
		{"pbx.example-1.com", true, "pbx.example-1.com"},
		{"::1", true, "[::1]"},
		{"[::1]", true, "[::1]"},
		{"2001:db8::5", true, "[2001:db8::5]"},
		{"fe80::1%eth0", false, ""},
		{"10.1.2.3:5060", false, ""},
		{"a b", false, ""},
		{"h;transport=tcp", false, ""},
		{"h/x", false, ""},
		{"bücher.example", false, ""},
	}
	for _, tc := range tests {
		if got := validSIPHost(tc.in); got != tc.valid {
			t.Errorf("validSIPHost(%q) = %v, want %v", tc.in, got, tc.valid)
		}
		if tc.valid {
			if got := (Account{SIPServer: tc.in}).uriHost(); got != tc.uriHost {
				t.Errorf("uriHost(%q) = %q, want %q", tc.in, got, tc.uriHost)
			}
		}
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestResolveDefaults(t *testing.T) {
	c, _ := LoadConfig(writeFile(t, goodConfigJSON()))
	tests := []struct {
		name, wantTransport string
		wantPort            int
	}{
		{"plain", "udp", 5060},     // no transport, no port
		{"sbc-lab", "tcp", 5070},   // explicit port wins
		{"carrier-x", "tls", 5061}, // tls default port
	}
	for _, tc := range tests {
		a, err := c.Resolve(tc.name)
		if err != nil {
			t.Fatal(err)
		}
		if a.Transport != tc.wantTransport || a.Port != tc.wantPort {
			t.Errorf("%s: got %s/%d want %s/%d", tc.name, a.Transport, a.Port, tc.wantTransport, tc.wantPort)
		}
	}
	// tcp without an explicit port must also default to 5060.
	c.Accounts["tcpdef"] = Account{Mode: "direct", Transport: "tcp", Username: "u", Password: "p"}
	if a, _ := c.Resolve("tcpdef"); a.Port != 5060 {
		t.Errorf("tcp default port = %d, want 5060", a.Port)
	}
}

func TestResolveUnknownListsValidNames(t *testing.T) {
	c, _ := LoadConfig(writeFile(t, goodConfigJSON()))
	_, err := c.Resolve("nope")
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"the requested name is not shown", "carrier-x, plain, sbc-lab"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "nope") {
		t.Errorf("error %q echoes the requested name", err)
	}
	if strings.Contains(err.Error(), testPassword) {
		t.Error("error leaks a password")
	}
	empty := &Config{Upstream: "https://h/mcp", Token: "t"}
	if _, err := empty.Resolve("x"); err == nil || !strings.Contains(err.Error(), "no accounts") {
		t.Errorf("empty config error = %v", err)
	}
}

func TestResolveUnknownMentionsProblemAccounts(t *testing.T) {
	c, err := LoadConfig(writeFile(t, `{"upstream":"https://h/mcp","token":"t","accounts":{`+
		`"good":{"mode":"direct","username":"u","password":"pw"},"broken":{"mode":"direct"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Resolve("nope")
	if err == nil || !strings.Contains(err.Error(), "valid accounts: good") || !strings.Contains(err.Error(), "problems (see account_list): broken") {
		t.Fatalf("got %v", err)
	}
}

func TestListHasNoPassword(t *testing.T) {
	c, _ := LoadConfig(writeFile(t, goodConfigJSON()))
	l := c.List()
	if len(l) != 3 || l[0].Name != "carrier-x" || l[2].Name != "sbc-lab" {
		t.Fatalf("List not sorted by name: %+v", l)
	}
	b, _ := json.Marshal(l)
	if bytes.Contains(b, []byte("password")) || bytes.Contains(b, []byte("pw")) {
		t.Fatalf("List JSON exposes a password: %s", b)
	}
	if !strings.Contains(string(b), `"port":5061`) {
		t.Fatalf("List must show resolved default port: %s", b)
	}
}

func TestRedaction(t *testing.T) {
	c, _ := LoadConfig(writeFile(t, goodConfigJSON()))
	a := c.Accounts["sbc-lab"]
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "cfg", c, "acct", a)
	// BY VALUE as well as by pointer: value receivers make both safe.
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("y", "cfgv", *c, "acctp", &a)
	outs := []string{
		fmt.Sprintf("%v %+v %#v %s", c, c, c, c),
		fmt.Sprintf("%v %+v %#v %s", *c, *c, *c, *c),
		fmt.Sprintf("%v %+v %#v %s", a, a, a, a),
		fmt.Sprintf("%v %+v %#v %s", &a, &a, &a, &a),
		buf.String(),
	}
	for i, o := range outs {
		if strings.Contains(o, testPassword) || strings.Contains(o, "tok-123") {
			t.Errorf("output %d leaks a secret: %s", i, o)
		}
	}
}

func TestSaveRoundTripAndMode(t *testing.T) {
	c, _ := LoadConfig(writeFile(t, goodConfigJSON()))
	p := filepath.Join(t.TempDir(), "sub", "dir", "sipclient-proxy.json")
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("file mode = %o, want 600", fi.Mode().Perm())
		}
		di, _ := os.Stat(filepath.Dir(p))
		if di.Mode().Perm() != 0o700 {
			t.Errorf("dir mode = %o, want 700", di.Mode().Perm())
		}
	}
	back, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if back.Accounts["sbc-lab"] != c.Accounts["sbc-lab"] {
		t.Fatal("round trip changed an account")
	}
}

func TestPermissionWarning(t *testing.T) {
	tests := []struct {
		goos string
		mode os.FileMode
		want string // substring; "" means no warning
	}{
		{"linux", 0o600, ""},
		{"darwin", 0o600, ""},
		{"darwin", 0o644, "chmod 600"},
		{"linux", 0o640, "chmod 600"},
		{"linux", 0o660, "chmod 600"},
		{"windows", 0o666, "ACL"},
	}
	for _, tc := range tests {
		got := permissionWarning(tc.goos, "/p/x.json", tc.mode)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s %o: got %q want substring %q", tc.goos, tc.mode, got, tc.want)
		}
	}
}

func TestDefaultConfigPath(t *testing.T) {
	tests := []struct {
		goos, home, appdata, want string
		wantErr                   bool
	}{
		{"darwin", "/Users/u", "", filepath.Join("/Users/u", ".config", "sipclient-proxy", "sipclient-proxy.json"), false},
		{"linux", "/home/u", "", filepath.Join("/home/u", ".config", "sipclient-proxy", "sipclient-proxy.json"), false},
		{"windows", "C:/Users/u", "C:/Users/u/AppData/Roaming", filepath.Join("C:/Users/u/AppData/Roaming", "sipclient-proxy", "sipclient-proxy.json"), false},
		{"windows", "C:/Users/u", "", "", true},
	}
	for _, tc := range tests {
		got, err := DefaultConfigPath(tc.goos, tc.home, tc.appdata)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q (err=%v)", tc.goos, got, err, tc.want, tc.wantErr)
		}
	}
}

const refusalWithRemedy = `config: upstream must use https:// unless the host is loopback (localhost, 127.0.0.0/8, ::1); the bearer token must not travel in cleartext; to accept that risk set "allow_insecure_http": true (configure: --allow-insecure-http)`

func TestInsecureHTTPOptInOffStillRefusesWithTheRemedy(t *testing.T) {
	_, err := LoadConfig(writeFile(t, `{"upstream":"http://192.0.2.7:8100/mcp","token":"t"}`))
	if err == nil || err.Error() != refusalWithRemedy {
		t.Fatalf("got %v, want %q", err, refusalWithRemedy)
	}
	_, err = LoadConfig(writeFile(t, `{"upstream":"http://192.0.2.7:8100/mcp","token":"t","allow_insecure_http":false}`))
	if err == nil || err.Error() != refusalWithRemedy {
		t.Fatalf("explicit false: got %v, want %q", err, refusalWithRemedy)
	}
}

func TestInsecureHTTPOptInAcceptsANonLoopbackHTTPUpstream(t *testing.T) {
	cfg, err := LoadConfig(writeFile(t, `{"upstream":"http://192.0.2.7:8100/mcp","token":"t","allow_insecure_http":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowInsecureHTTP {
		t.Fatal("AllowInsecureHTTP not copied into the Config")
	}
	if err := (&Config{Upstream: "http://192.0.2.7:8100/mcp", Token: "t", AllowInsecureHTTP: true}).Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestInsecureHTTPOptInKeepsTheOtherUpstreamRules(t *testing.T) {
	for _, tc := range []struct{ upstream, want string }{
		{"https://u:pw@h/mcp", "credentials"},
		{"ws://h/mcp", "http:// or https://"},
		{"http:///mcp", "http:// or https://"},
	} {
		_, err := LoadConfig(writeFile(t, `{"upstream":"`+tc.upstream+`","token":"t","allow_insecure_http":true}`))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error naming %q", tc.upstream, err, tc.want)
		}
	}
}

func TestInsecureHTTPOptInHTTPSAndLoopbackUnchanged(t *testing.T) {
	for _, up := range []string{"https://h/mcp", "http://127.0.0.1:8100/mcp"} {
		for _, opt := range []string{"false", "true"} {
			cfg, err := LoadConfig(writeFile(t, `{"upstream":"`+up+`","token":"t","allow_insecure_http":`+opt+`}`))
			if err != nil {
				t.Fatalf("%s opt=%s: %v", up, opt, err)
			}
			if w := cfg.CleartextWarning(); w != "" {
				t.Errorf("%s opt=%s: warning %q, want none", up, opt, w)
			}
		}
	}
}

func TestInsecureUpstreamWarning(t *testing.T) {
	const prefix = "sipclient-proxy: warning: allow_insecure_http is set: the daemon bearer token travels in cleartext to "
	for _, tc := range []struct{ upstream, want string }{
		{"http://192.0.2.7:8100/mcp", prefix + "192.0.2.7:8100"},
		{"http://[fd00::1]:8100/mcp", prefix + "[fd00::1]:8100"},
		{"http://[::1]:8100/mcp", ""},
	} {
		got := InsecureUpstreamWarning(writeFile(t, `{"upstream":"`+tc.upstream+`","token":"t","allow_insecure_http":true}`))
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.upstream, got, tc.want)
		}
	}
	if got := InsecureUpstreamWarning(writeFile(t, `{"upstream":"http://192.0.2.7:8100/mcp","token":"t"}`)); got != "" {
		t.Errorf("opt-in off: got %q, want none", got)
	}
	if got := InsecureUpstreamWarning(filepath.Join(t.TempDir(), "missing.json")); got != "" {
		t.Errorf("missing file: got %q, want none", got)
	}
}

// Pin: a config saved without the opt-in carries no new key.
func TestConfigWithoutTheInsecureKeyStillLoadsAndSavesWithoutIt(t *testing.T) {
	cfg, err := LoadConfig(writeFile(t, goodConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AllowInsecureHTTP {
		t.Fatal("AllowInsecureHTTP true without the key")
	}
	p := filepath.Join(t.TempDir(), "out.json")
	if err := Save(p, cfg); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "allow_insecure_http") {
		t.Fatalf("saved file carries the key: %s", b)
	}
}
