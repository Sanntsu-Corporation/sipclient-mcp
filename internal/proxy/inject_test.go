package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func lookup(accts map[string]Account) func(string) (Account, error) {
	c := &Config{Upstream: "http://h/mcp", Token: "t", Accounts: accts}
	return c.Resolve
}

var registerAcct = Account{Mode: "register", SIPServer: "10.1.2.3", Port: 5070, Transport: "tcp", Username: "1001", Password: "pw1"}
var directAcct = Account{Mode: "direct", Transport: "tls", Username: "acme", Password: "pw2"}

func decode(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	if !json.Valid(raw) {
		t.Fatalf("output is not valid JSON: %s", raw)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInjectRegister(t *testing.T) {
	out, acct, err := Inject(json.RawMessage(`{"account":"sbc-lab","dtmf_mode":"rfc2833"}`),
		lookup(map[string]Account{"sbc-lab": registerAcct}))
	if err != nil || acct == nil {
		t.Fatalf("err=%v acct=%v", err, acct)
	}
	m := decode(t, out)
	want := map[string]any{
		"mode": "register", "transport": "tcp", "auth_user": "1001", "auth_pass": "pw1",
		"registrar": "sip:10.1.2.3:5070", "aor": "sip:1001@10.1.2.3", "dtmf_mode": "rfc2833",
	}
	if len(m) != len(want) {
		t.Fatalf("got %v", m)
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %v, want %v", k, m[k], v)
		}
	}
	if _, ok := m["account"]; ok {
		t.Fatal("account must be stripped before forwarding")
	}
}

func TestInjectDirect(t *testing.T) {
	out, _, err := Inject(json.RawMessage(`{"account":"carrier-x"}`), lookup(map[string]Account{"carrier-x": directAcct}))
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, out)
	if m["mode"] != "direct" || m["transport"] != "tls" || m["auth_user"] != "acme" || m["auth_pass"] != "pw2" {
		t.Fatalf("got %v", m)
	}
	for _, k := range []string{"registrar", "aor", "account", "auth_any_host"} {
		if _, ok := m[k]; ok {
			t.Errorf("direct account must not set %q", k)
		}
	}
}

// CF-046 (D-C3): auth_any_host is forwarded only when the account entry says
// true; otherwise the key is absent (an older daemon never sees it).
func TestInjectCarriesAuthAnyHostFromTheAccount(t *testing.T) {
	for _, base := range []Account{directAcct, registerAcct} {
		on, off := base, base
		on.AuthAnyHost = true
		out, _, err := Inject(json.RawMessage(`{"account":"a"}`), lookup(map[string]Account{"a": on}))
		if err != nil {
			t.Fatal(err)
		}
		if got := decode(t, out)["auth_any_host"]; got != true {
			t.Errorf("%s account with auth_any_host: forwarded %v, want true", base.Mode, got)
		}
		out, _, err = Inject(json.RawMessage(`{"account":"a"}`), lookup(map[string]Account{"a": off}))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := decode(t, out)["auth_any_host"]; ok {
			t.Errorf("%s account without auth_any_host must not forward the key", base.Mode)
		}
	}
}

// CF-046 (D-C3): a model-supplied auth_any_host next to account is rejected like
// every owned field (any value, any letter case), never silently stripped.
func TestInjectConflictOnAuthAnyHost(t *testing.T) {
	for _, key := range []string{"auth_any_host", "Auth_Any_Host", "AUTH_ANY_HOST"} {
		for _, val := range []string{`true`, `false`, `null`, `"yes"`} {
			called := false
			args := json.RawMessage(`{"account":"a","` + key + `":` + val + `}`)
			out, acct, err := Inject(args, func(string) (Account, error) { called = true; return directAcct, nil })
			var ce *ConflictError
			if !errors.As(err, &ce) || ce.Field != "auth_any_host" {
				t.Errorf("%s=%s: want ConflictError for auth_any_host, got %v", key, val, err)
				continue
			}
			if out != nil || acct != nil || called {
				t.Errorf("%s=%s: nothing may be produced or resolved on conflict", key, val)
			}
			if !strings.Contains(err.Error(), "auth_any_host") {
				t.Errorf("conflict text does not name auth_any_host: %v", err)
			}
		}
	}
}

func TestInjectConflict(t *testing.T) {
	for _, f := range []string{"mode", "registrar", "aor", "auth_user", "auth_pass", "transport"} {
		t.Run(f, func(t *testing.T) {
			called := false
			args := json.RawMessage(`{"account":"a","` + f + `":"x"}`)
			out, acct, err := Inject(args, func(string) (Account, error) { called = true; return registerAcct, nil })
			var ce *ConflictError
			if !errors.As(err, &ce) || ce.Field != f {
				t.Fatalf("want ConflictError for %q, got %v", f, err)
			}
			// The message lists all six fields in its explanation, so a bare Contains(f)
			// would pass for every field; pin the two spots that carry the offender.
			for _, frag := range []string{`combined with "` + f + `"`, `remove "` + f + `"`} {
				if !strings.Contains(err.Error(), frag) {
					t.Errorf("error %q must contain %s", err, frag)
				}
			}
			if out != nil || acct != nil {
				t.Errorf("nothing may be produced on conflict (out=%s)", out)
			}
			if called {
				t.Error("resolve must not be called on conflict")
			}
		})
	}
}

// Documented rule: the error names the FIRST offender in the fixed order
// mode, transport, registrar, aor, auth_user, auth_pass, whatever the JSON key order.
func TestInjectConflictNamesFirstOffenderInFixedOrder(t *testing.T) {
	tests := []struct{ args, want string }{
		{`{"account":"a","auth_pass":"x","mode":"m"}`, "mode"},
		{`{"account":"a","mode":"m","auth_pass":"x"}`, "mode"},
		{`{"account":"a","aor":"x","transport":"y"}`, "transport"},
		{`{"account":"a","auth_pass":"x","auth_user":"u"}`, "auth_user"},
		{`{"account":"a","aor":"x","registrar":"sip:h"}`, "registrar"},
	}
	for _, tc := range tests {
		_, _, err := Inject(json.RawMessage(tc.args), lookup(map[string]Account{"a": registerAcct}))
		var ce *ConflictError
		if !errors.As(err, &ce) || ce.Field != tc.want {
			t.Errorf("%s: want first offender %q, got %v", tc.args, tc.want, err)
		}
	}
}

// Presence, not value: an empty string is still an attempt to set the field.
func TestInjectConflictOnEmptyStringField(t *testing.T) {
	for _, f := range []string{"mode", "registrar", "aor", "auth_user", "auth_pass", "transport"} {
		_, _, err := Inject(json.RawMessage(`{"account":"a","`+f+`":""}`), lookup(map[string]Account{"a": registerAcct}))
		var ce *ConflictError
		if !errors.As(err, &ce) || ce.Field != f {
			t.Errorf("empty %s must conflict, got %v", f, err)
		}
	}
}

// N2: Go's decoder matches keys case-insensitively (and folds U+017F to "s"), so a
// case variant of an owned field must conflict too; the error names the owned
// field in its canonical spelling, never the caller's.
func TestInjectConflictOnCaseVariantsOfOwnedFields(t *testing.T) {
	tests := []struct{ key, want string }{
		{"Registrar", "registrar"},
		{"REGISTRAR", "registrar"},
		{"Auth_Pass", "auth_pass"},
		{"MODE", "mode"},
		{"Aor", "aor"},
		{"tran\u017Fport", "transport"}, // U+017F LATIN SMALL LETTER LONG S folds to "s"
		{"regi\u017Ftrar", "registrar"},
	}
	for _, tc := range tests {
		called := false
		args := json.RawMessage(`{"account":"a","` + tc.key + `":"sip:evil.example:5060"}`)
		out, acct, err := Inject(args, func(string) (Account, error) { called = true; return registerAcct, nil })
		var ce *ConflictError
		if !errors.As(err, &ce) || ce.Field != tc.want {
			t.Errorf("key %q: want ConflictError for %q, got %v", tc.key, tc.want, err)
			continue
		}
		if out != nil || acct != nil || called {
			t.Errorf("key %q: nothing may be produced or resolved on conflict", tc.key)
		}
	}
	// A near miss is not a conflict: a different field that merely contains an owned name.
	_, acct, err := Inject(json.RawMessage(`{"account":"a","mode_x":"1","registrar2":"2"}`), lookup(map[string]Account{"a": registerAcct}))
	if err != nil || acct == nil {
		t.Errorf("fields that only contain an owned name must pass through: %v", err)
	}
}

func TestInjectConflictOnNullField(t *testing.T) {
	_, _, err := Inject(json.RawMessage(`{"account":"a","auth_pass":null}`), lookup(map[string]Account{"a": registerAcct}))
	var ce *ConflictError
	if !errors.As(err, &ce) || ce.Field != "auth_pass" {
		t.Fatalf("null owned field must still conflict, got %v", err)
	}
}

func TestInjectUnknownAccount(t *testing.T) {
	_, _, err := Inject(json.RawMessage(`{"account":"zzz"}`), lookup(map[string]Account{"a": registerAcct, "b": directAcct}))
	if err == nil || !strings.Contains(err.Error(), "a, b") {
		t.Fatalf("want error listing valid names, got %v", err)
	}
}

func TestInjectBadAccountValue(t *testing.T) {
	for _, v := range []string{`5`, `null`, `""`, `[]`, `{"n":1}`, `true`} {
		t.Run(v, func(t *testing.T) {
			out, _, err := Inject(json.RawMessage(`{"account":`+v+`}`), lookup(map[string]Account{"a": registerAcct}))
			if err == nil || out != nil {
				t.Fatalf("account=%s must be a local error, got out=%s err=%v", v, out, err)
			}
			if !strings.Contains(err.Error(), "account") {
				t.Errorf("error %q must mention account", err)
			}
		})
	}
}

func TestInjectPreservesUnknownFieldsByteForByte(t *testing.T) {
	in := `{"account":"sbc-lab","codec_pref": [ "PCMU" ,"PCMA" ],"future_field":{"x" : 1.0e+2 , "big":12345678901234567890123},` +
		`"srtp":"disabled","expires_s":  300,"local_addr":"0.0.0.0:0","keepalive":"options","dtmf_mode":"info",` +
		`"session_expires_s":1800,"min_se_s":90,"keepalive_interval_s":30,"session_refresh_method":"update",` +
		`"e\u0061cute":"caf\u00e9","a&b":"<tag>"}`
	out, _, err := Inject(json.RawMessage(in), lookup(map[string]Account{"sbc-lab": registerAcct}))
	if err != nil {
		t.Fatal(err)
	}
	decode(t, out)
	for _, frag := range []string{
		`"codec_pref":[ "PCMU" ,"PCMA" ]`,
		`"future_field":{"x" : 1.0e+2 , "big":12345678901234567890123}`,
		`"srtp":"disabled"`, `"expires_s":300`, `"local_addr":"0.0.0.0:0"`, `"keepalive":"options"`,
		`"dtmf_mode":"info"`, `"session_expires_s":1800`, `"min_se_s":90`, `"keepalive_interval_s":30`,
		`"session_refresh_method":"update"`, `"a&b":"<tag>"`,
	} {
		if !bytes.Contains(out, []byte(frag)) {
			t.Errorf("output lost %s\nout=%s", frag, out)
		}
	}
	// "expires_s":  300 has extra input whitespace BEFORE the value; the value bytes themselves are what is preserved.
}

func TestInjectNoAccountIsUntouched(t *testing.T) {
	never := func(string) (Account, error) { t.Fatal("resolve must not be called"); return Account{}, nil }
	for _, in := range []string{
		`{"mode":"direct","auth_pass":"explicit-pw","transport":"udp"}`,
		`{ "mode" : "direct" }`,
		``, `null`, `[1,2]`, `"str"`,
	} {
		out, acct, err := Inject(json.RawMessage(in), never)
		if err != nil || acct != nil || string(out) != in {
			t.Errorf("in=%q out=%q acct=%v err=%v; want untouched", in, out, acct, err)
		}
	}
}

func TestInjectRegistrarAndAORURIs(t *testing.T) {
	tests := []struct {
		name          string
		acct          Account
		wantRegistrar string
		wantAOR       string
	}{
		{"ipv4", Account{Mode: "register", SIPServer: "10.1.2.3", Port: 5070, Transport: "udp", Username: "1001", Password: "p"},
			"sip:10.1.2.3:5070", "sip:1001@10.1.2.3"},
		{"ipv6 literal", Account{Mode: "register", SIPServer: "::1", Port: 5070, Transport: "udp", Username: "1001", Password: "p"},
			"sip:[::1]:5070", "sip:1001@[::1]"},
		{"ipv6 already bracketed", Account{Mode: "register", SIPServer: "[2001:db8::5]", Port: 5061, Transport: "tls", Username: "1001", Password: "p"},
			"sip:[2001:db8::5]:5061", "sip:1001@[2001:db8::5]"},
		{"hostname", Account{Mode: "register", SIPServer: "pbx.example.com", Port: 5060, Transport: "udp", Username: "u", Password: "p"},
			"sip:pbx.example.com:5060", "sip:u@pbx.example.com"},
		{"username with reserved characters", Account{Mode: "register", SIPServer: "h", Port: 5060, Transport: "udp", Username: "a b@c:d%e", Password: "p"},
			"sip:h:5060", "sip:a%20b%40c%3Ad%25e@h"},
		{"username with user-unreserved and plus", Account{Mode: "register", SIPServer: "h", Port: 5060, Transport: "udp", Username: "+1555-01;x=y", Password: "p"},
			"sip:h:5060", "sip:+1555-01;x=y@h"},
		{"non-ASCII username", Account{Mode: "register", SIPServer: "h", Port: 5060, Transport: "udp", Username: "é", Password: "p"},
			"sip:h:5060", "sip:%C3%A9@h"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := Inject(json.RawMessage(`{"account":"x"}`), lookup(map[string]Account{"x": tc.acct}))
			if err != nil {
				t.Fatal(err)
			}
			m := decode(t, out)
			if m["registrar"] != tc.wantRegistrar || m["aor"] != tc.wantAOR {
				t.Fatalf("registrar=%v aor=%v, want %s / %s", m["registrar"], m["aor"], tc.wantRegistrar, tc.wantAOR)
			}
			if m["auth_user"] != tc.acct.Username {
				t.Fatalf("auth_user must stay the raw username, got %v", m["auth_user"])
			}
		})
	}
}

func TestInjectOversizedArgumentsSurviveIntact(t *testing.T) {
	big := strings.Repeat("A", 1<<20)
	in := `{"account":"sbc-lab","codec_pref":["` + big + `"],"future":"` + big + `"}`
	out, _, err := Inject(json.RawMessage(in), lookup(map[string]Account{"sbc-lab": registerAcct}))
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, out)
	if cp := m["codec_pref"].([]any); len(cp) != 1 || cp[0] != big || m["future"] != big {
		t.Fatal("1 MiB values were altered")
	}
}

func TestInjectPasswordSpecialChars(t *testing.T) {
	a := registerAcct
	a.Password = `p@ss"w\ord<&>é` + "\u2028"
	out, _, err := Inject(json.RawMessage(`{"account":"a"}`), lookup(map[string]Account{"a": a}))
	if err != nil {
		t.Fatal(err)
	}
	if got := decode(t, out)["auth_pass"]; got != a.Password {
		t.Fatalf("auth_pass = %q, want %q", got, a.Password)
	}
	if !bytes.Contains(out, []byte(`<&>`)) {
		t.Errorf("HTML escaping must be off so the daemon sees the same bytes: %s", out)
	}
}

// jsonString must stay byte-identical when it is expressed through jsonInner:
// no HTML escaping, U+2028/U+2029 and control characters escaped, invalid UTF-8
// replaced by U+FFFD (one per invalid byte, written as the raw rune). The
// replacement spelling must not depend on the Go toolchain: encoding/json
// writes `\ufffd` without GOEXPERIMENT=jsonv2 and a raw U+FFFD with it (the
// default from Go 1.27), so run this test under both settings.
func TestJSONStringMatchesJSONInnerGolden(t *testing.T) {
	bs := "\\" // one backslash
	for _, tc := range []struct{ in, want string }{
		{"plain", `"plain"`},
		{"<>&", `"<>&"`},
		{`say "hi"`, `"say \"hi\""`},
		{`back\slash`, `"back\\slash"`},
		{"a\xe2\x80\xa8b", `"a` + bs + `u2028b"`},
		{"a\xe2\x80\xa9b", `"a` + bs + `u2029b"`},
		{"a\x01b", `"a` + bs + `u0001b"`},
		{"a\xffb", "\"a\ufffdb\""},
		{"a\xff\xfeb", "\"a\ufffd\ufffdb\""},
		{"a\xe2\x80b", "\"a\ufffd\ufffdb\""},
		{"\n\t", `"\n\t"`},
		{"", `""`},
	} {
		if got := string(jsonString(tc.in)); got != tc.want {
			t.Errorf("jsonString(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}
