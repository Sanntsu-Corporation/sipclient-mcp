package proxy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const redactPW = `Rp@ss"w\ord<&>é` + " " + `-UNIQUE` // U+2028 LINE SEPARATOR: encoding/json always escapes it

// every textual form a daemon could plausibly echo the password in.
func echoForms(t *testing.T, pw string) map[string]string {
	t.Helper()
	esc := func(v string, html bool) string { return jsonInner(v, html) }
	return map[string]string{
		"raw":                pw,
		"json (html on)":     esc(pw, true),
		"json (html off)":    esc(pw, false),
		"json twice (on)":    esc(esc(pw, true), true),
		"json twice (off)":   esc(esc(pw, false), false),
		"json twice (mixed)": esc(esc(pw, false), true),
	}
}

func TestSecretSetScrubsEveryForm(t *testing.T) {
	s := newSecretSet("tok-TOKEN")
	s.add(redactPW)
	for name, form := range echoForms(t, redactPW) {
		got := s.scrub("before " + form + " after")
		if strings.Contains(got, "Rp@ss") || strings.Contains(got, "UNIQUE") || !strings.Contains(got, redacted) {
			t.Errorf("%s not redacted: %q", name, got)
		}
	}
	if got := s.scrub("Authorization: Bearer tok-TOKEN"); strings.Contains(got, "tok-TOKEN") {
		t.Errorf("token not redacted: %q", got)
	}
	if got := s.scrub("nothing secret here"); got != "nothing secret here" {
		t.Errorf("clean text altered: %q", got)
	}
}

func TestSecretSetIgnoresEmptySecretAndDuplicates(t *testing.T) {
	s := newSecretSet("", "dup-secret-value", "dup-secret-value")
	s.add("")
	s.addCredential("", "")
	if got := s.scrub("abc"); got != "abc" {
		t.Fatalf("empty secret must not match everywhere: %q", got)
	}
	if got := s.scrub("a dup-secret-value b"); got != "a "+redacted+" b" {
		t.Fatalf("got %q", got)
	}
	if n := len(s.forms); n != len(secretForms("dup-secret-value")) {
		t.Fatalf("duplicate secrets must not duplicate forms: %d forms", n)
	}
}

func TestSecretSetLongestFormFirst(t *testing.T) {
	// The raw form of this secret (one trailing backslash) is a PREFIX of its
	// JSON-escaped form (the backslash doubles): scrubbing the short form first
	// would leave a stray backslash behind.
	s := newSecretSet(`password1\`)
	if got, want := s.scrub(`x password1\\ y`), "x "+redacted+" y"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestScrubValueWholeStringNestedAndKeys(t *testing.T) {
	s := newSecretSet(redactPW)
	in := map[string]any{
		"whole":  redactPW,
		"nested": map[string]any{"list": []any{"ok", redactPW, map[string]any{"deep": "x" + redactPW + "y"}}},
		"num":    float64(7),
		"flag":   true,
		"nil":    nil,
		redactPW: "value-under-a-secret-key",
	}
	outAny, err := s.scrubValue(in)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(outAny)
	if strings.Contains(string(b), "Rp@ss") || strings.Contains(string(b), "UNIQUE") {
		t.Fatalf("secret survived: %s", b)
	}
	out := outAny.(map[string]any)
	if out["whole"] != redacted || out["num"] != float64(7) || out["flag"] != true || out["nil"] != nil {
		t.Fatalf("scrubValue altered non-secret data: %v", out)
	}
	if in["whole"] != redactPW {
		t.Fatal("input was mutated")
	}
}

func TestScrubValueNormalisesTypedValuesAndFailsOnUnmarshalable(t *testing.T) {
	s := newSecretSet(redactPW)
	type payload struct {
		Echo string `json:"echo"`
		N    int    `json:"n"`
	}
	out, err := s.scrubValue(payload{Echo: redactPW, N: 3})
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["echo"] != redacted || m["n"] != json.Number("3") {
		t.Fatalf("got %v", m)
	}
	if _, err := s.scrubValue(make(chan int)); err == nil {
		t.Fatal("an uninspectable value must be an error, not a pass-through")
	}
}

func textRes(text string) *sdk.CallToolResult {
	return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: text}}}
}

func resultJSON(t *testing.T, r *sdk.CallToolResult) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRedactResultWhereThePasswordCanHide(t *testing.T) {
	s := newSecretSet("tok-TOKEN", redactPW)
	tests := []struct {
		name string
		res  *sdk.CallToolResult
	}{
		{"text", textRes("echo " + redactPW)},
		{"structured whole string value", &sdk.CallToolResult{Content: []sdk.Content{}, StructuredContent: map[string]any{"pw": redactPW}}},
		{"structured nested", &sdk.CallToolResult{StructuredContent: map[string]any{"a": []any{map[string]any{"b": "x" + redactPW}}}}},
		{"structured JSON-in-a-string (twice escaped)", &sdk.CallToolResult{StructuredContent: map[string]any{"raw": jsonInner(jsonInner(redactPW, true), true)}}},
		{"result _meta", &sdk.CallToolResult{Meta: sdk.Meta{"k": redactPW}}},
		{"text block _meta", &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "ok", Meta: sdk.Meta{"k": redactPW}}}}},
		{"token in text", textRes("Bearer tok-TOKEN")},
		{"typed structured content", &sdk.CallToolResult{StructuredContent: struct {
			P string `json:"p"`
		}{redactPW}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := resultJSON(t, tc.res)
			got, err := s.redactResult(tc.res, false)
			if err != nil {
				t.Fatal(err)
			}
			out := resultJSON(t, got)
			for _, leak := range []string{"Rp@ss", "UNIQUE", "tok-TOKEN"} {
				if strings.Contains(out, leak) {
					t.Fatalf("%q survived: %s", leak, out)
				}
			}
			if !strings.Contains(out, redacted) {
				t.Fatalf("expected the marker: %s", out)
			}
			if resultJSON(t, tc.res) != before {
				t.Fatal("redactResult must not modify its input")
			}
		})
	}
}

func TestRedactResultFailsClosedOnUninspectableContent(t *testing.T) {
	s := newSecretSet(redactPW)
	img := &sdk.CallToolResult{Content: []sdk.Content{
		&sdk.TextContent{Text: "created"},
		&sdk.ImageContent{Data: []byte(redactPW), MIMEType: "image/png"},
	}}
	got, err := s.redactResult(img, true)
	if err != errUninspectable || got != nil {
		t.Fatalf("failClosed must reject non-text content with no data, got %v / %v", got, err)
	}
	// Without failClosed (an unrelated tool) a clean non-text block passes through.
	clean := &sdk.CallToolResult{Content: []sdk.Content{
		&sdk.TextContent{Text: "created"},
		&sdk.ImageContent{Data: []byte("\x89PNG-fake"), MIMEType: "image/png"},
	}}
	got, err = s.redactResult(clean, false)
	if err != nil || len(got.Content) != 2 {
		t.Fatalf("got %v %v", got, err)
	}
	// Structured content that cannot be inspected is rejected whatever failClosed says.
	bad := &sdk.CallToolResult{StructuredContent: make(chan int)}
	if _, err := s.redactResult(bad, false); err == nil {
		t.Fatal("uninspectable structured content must be an error")
	}
}

func TestRedactResultKeepsCleanResultIntact(t *testing.T) {
	s := newSecretSet(redactPW)
	in := &sdk.CallToolResult{
		Meta:              sdk.Meta{"m": "v"},
		Content:           []sdk.Content{&sdk.TextContent{Text: `{"ok":true}`}},
		StructuredContent: map[string]any{"ok": true, "n": float64(2)},
		IsError:           true,
	}
	got, err := s.redactResult(in, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsError || !reflect.DeepEqual(got.StructuredContent, in.StructuredContent) || got.Content[0].(*sdk.TextContent).Text != `{"ok":true}` || got.Meta["m"] != "v" {
		t.Fatalf("clean result altered: %s", resultJSON(t, got))
	}
	if r, err := s.redactResult(nil, true); r != nil || err != nil {
		t.Fatalf("nil result: %v %v", r, err)
	}
}

// ---- encodings (OD24) -------------------------------------------------------

func TestSecretSetScrubsURLEncodedForms(t *testing.T) {
	s := newSecretSet(redactPW)
	for name, form := range map[string]string{
		"QueryEscape": url.QueryEscape(redactPW),
		"PathEscape":  url.PathEscape(redactPW),
	} {
		if form == redactPW {
			t.Fatalf("%s: premise broken, the form equals the raw secret", name)
		}
		got := s.scrub("GET /x?pw=" + form + "&y=1")
		if strings.Contains(got, "UNIQUE") || strings.Contains(got, "%40") || !strings.Contains(got, "?pw="+redacted+"&y=1") {
			t.Errorf("%s not redacted: %q", name, got)
		}
		// Inside a JSON text the & of a path-escaped password is written &.
		if in := `{"echo":"` + jsonInner(form, true) + `"}`; s.scrub(in) != `{"echo":"`+redacted+`"}` {
			t.Errorf("%s not redacted inside JSON: %s", name, s.scrub(in))
		}
	}
}

func TestSecretSetScrubsBase64Forms(t *testing.T) {
	s := newSecretSet(redactPW)
	b := []byte(redactPW)
	for name, form := range map[string]string{
		"std padded": base64.StdEncoding.EncodeToString(b),
		"std raw":    base64.RawStdEncoding.EncodeToString(b),
		"url padded": base64.URLEncoding.EncodeToString(b),
		"url raw":    base64.RawURLEncoding.EncodeToString(b),
	} {
		got := s.scrub("blob=" + form + ";")
		if strings.Contains(got, form) || got != "blob="+redacted+";" {
			t.Errorf("%s not redacted: %q", name, got)
		}
	}
	// Only the whole-secret spellings are recognised (OD24): base64 of a longer
	// text that merely contains the secret is not, and unrelated base64 is left alone.
	if in := base64.StdEncoding.EncodeToString([]byte("prefix:" + redactPW + ":suffix")); s.scrub(in) != in {
		t.Errorf("embedded base64 is a documented limit, but was altered: %q", s.scrub(in))
	}
	if got := s.scrub("dGhpcyBpcyBmaW5l"); got != "dGhpcyBpcyBmaW5l" {
		t.Errorf("unrelated base64 altered: %q", got)
	}
}

func TestSecretSetScrubsBasicAuthCredentialPair(t *testing.T) {
	s := newSecretSet()
	s.addCredential("1001", redactPW)
	pair := []byte("1001:" + redactPW)
	for name, form := range map[string]string{
		"std padded": base64.StdEncoding.EncodeToString(pair),
		"std raw":    base64.RawStdEncoding.EncodeToString(pair),
		"url padded": base64.URLEncoding.EncodeToString(pair),
		"url raw":    base64.RawURLEncoding.EncodeToString(pair),
	} {
		got := s.scrub("Authorization: Basic " + form)
		if strings.Contains(got, form) || got != "Authorization: Basic "+redacted {
			t.Errorf("%s: %q", name, got)
		}
	}
	// The pair form only exists for credentials that were registered as a pair.
	only := newSecretSet(redactPW)
	form := base64.StdEncoding.EncodeToString(pair)
	if got := only.scrub(form); got != form {
		t.Errorf("a plain password must not register a user:password form, got %q", got)
	}
}

func TestSecretSetScrubsEveryBase64Alphabet(t *testing.T) {
	// "pw>>>???xy" encodes to cHc+Pj4/Pz94eQ== (standard) and cHc-Pj4_Pz94eQ== (URL),
	// so all four spellings differ; redactPW's four spellings are identical strings
	// and could not tell the alphabets apart.
	const pw = "pw>>>???xy"
	b := []byte(pw)
	forms := map[string]string{
		"std padded": base64.StdEncoding.EncodeToString(b),
		"std raw":    base64.RawStdEncoding.EncodeToString(b),
		"url padded": base64.URLEncoding.EncodeToString(b),
		"url raw":    base64.RawURLEncoding.EncodeToString(b),
	}
	distinct := map[string]bool{}
	for _, f := range forms {
		distinct[f] = true
	}
	if len(distinct) != 4 {
		t.Fatalf("premise broken: want 4 distinct spellings, got %d", len(distinct))
	}
	s := newSecretSet(pw)
	for name, f := range forms {
		if got := s.scrub("blob=" + f + ";"); got != "blob="+redacted+";" {
			t.Errorf("%s: %q", name, got)
		}
	}
}

func TestSecretSetScrubsEveryBase64AlphabetOfThePair(t *testing.T) {
	// "1001:pw>>>???x" (14 bytes) has four distinct spellings, as above.
	const user, pw = "1001", "pw>>>???x"
	b := []byte(user + ":" + pw)
	forms := map[string]string{
		"std padded": base64.StdEncoding.EncodeToString(b),
		"std raw":    base64.RawStdEncoding.EncodeToString(b),
		"url padded": base64.URLEncoding.EncodeToString(b),
		"url raw":    base64.RawURLEncoding.EncodeToString(b),
	}
	distinct := map[string]bool{}
	for _, f := range forms {
		distinct[f] = true
	}
	if len(distinct) != 4 {
		t.Fatalf("premise broken: want 4 distinct spellings, got %d", len(distinct))
	}
	s := newSecretSet()
	s.addCredential(user, pw)
	for name, f := range forms {
		if got := s.scrub("Authorization: Basic " + f); got != "Authorization: Basic "+redacted {
			t.Errorf("%s: %q", name, got)
		}
	}
}

// ---- short secrets (OD23) ---------------------------------------------------

// legitimate is a daemon-shaped ua_create reply: URIs, a handle, timestamps, numbers.
const legitimate = `{"ok":true,"ua_handle":"ua_1001","mode":"register","transport":"udp","registered":true,` +
	`"register_code":200,"expires_s":1001,"contact":"<sip:1001@10.0.0.5:5070>","session_cookie":"c1001x",` +
	`"expires_at":"2026-09-30T10:01:00.100Z","ids":[1001,2],"1001":"key"}`

func TestShortSecretDoesNotCorruptLegitimateOutput(t *testing.T) {
	s := newSecretSet("1001")
	for _, in := range []string{
		"sip:1001@10.0.0.5", "<sip:1001@h>;tag=x1001y", "ua_1001", "10:01:00 2026-09-30T10:01:00.100Z", "ports 51001 and 10011",
		"a=1001;b", "http://h/x?u=1001", legitimate,
	} {
		if got := s.scrub(in); got != in {
			t.Errorf("short secret altered legitimate text:\n in: %s\nout: %s", in, got)
		}
	}
	// The same holds for decoded structured content: keys, numbers and
	// non-standalone strings are untouched.
	var v any
	dec := json.NewDecoder(strings.NewReader(legitimate))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	out, err := s.scrubValue(v)
	if err != nil || !reflect.DeepEqual(v, out) {
		t.Fatalf("structured content altered: %v %v", out, err)
	}
}

// A password equal to the username (as on the lab rig) or to a status code, a
// boolean or a transport name must not make the reply unusable: it still parses,
// keeps its keys, and only STRING values that equal the password change.
func TestShortSecretKeepsTheReplyParseable(t *testing.T) {
	var want map[string]any
	if err := json.Unmarshal([]byte(legitimate), &want); err != nil {
		t.Fatal(err)
	}
	for _, pw := range []string{"1001", "1234", "200", "true", "udp", "ok", "3600", "a", "1"} {
		s := newSecretSet(pw)
		s.addCredential("1001", pw)
		got := s.scrub(legitimate)
		var m map[string]any
		if err := json.Unmarshal([]byte(got), &m); err != nil {
			t.Errorf("password %q: reply no longer parses: %v\n%s", pw, err, got)
			continue
		}
		if len(m) != len(want) {
			t.Errorf("password %q: keys changed: %s", pw, got)
		}
		for k, wv := range want {
			exp := wv
			if str, ok := wv.(string); ok && str == pw {
				exp = redacted // the one legitimate effect: a whole string value equal to the password
			}
			if !reflect.DeepEqual(m[k], exp) {
				t.Errorf("password %q: %q is %v, want %v", pw, k, m[k], exp)
			}
		}
	}
}

// A short secret that stands alone IS redacted: as a bare word in text, quoted,
// as a whole string value, and inside JSON carried in a string.
func TestShortSecretStandingAloneIsRedacted(t *testing.T) {
	s := newSecretSet("1001")
	for in, want := range map[string]string{
		"bad credentials 1001 for ua":  "bad credentials [redacted] for ua",
		"1001":                         "[redacted]",
		`password="1001" was rejected`: `password="[redacted]" was rejected`,
		"(1001)":                       "([redacted])",
		`{"echo":"1001","n":1001}`:     `{"echo":"[redacted]","n":1001}`,
		`["a","1001",1001]`:            `["a","[redacted]",1001]`,
		`{"m":"{\"pw\":\"1001\"}"}`:    `{"m":"{\"pw\":\"[redacted]\"}"}`,
	} {
		if got := s.scrub(in); got != want {
			t.Errorf("scrub(%s)\n got %s\nwant %s", in, got, want)
		}
	}
	out, err := s.scrubValue(map[string]any{"pw": "1001", "1001": "key", "n": json.Number("1001")})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, map[string]any{"pw": redacted, "1001": "key", "n": json.Number("1001")}) {
		t.Errorf("structured value: %v", out)
	}
	// A short secret with JSON-special characters is still found inside a JSON string.
	q := newSecretSet(`a"b`)
	if got := q.scrub(`{"m":"x a\"b y"}`); got != `{"m":"x [redacted] y"}` {
		t.Errorf("escaped short secret in JSON text: %s", got)
	}
}

// One and two character passwords: only standalone occurrences are redacted
// (which can blank an unrelated word, documented); nothing structural changes.
func TestVeryShortSecretsBehaveSanely(t *testing.T) {
	one := newSecretSet("1")
	if got := one.scrub("retry 1 time, sip:1001@h, ua_1, 2026-09-30, 51"); got != "retry [redacted] time, sip:1001@h, ua_1, 2026-09-30, 51" {
		t.Errorf("one character: %q", got)
	}
	if got := one.scrub(legitimate); got != legitimate {
		t.Errorf("one character altered a legitimate reply: %s", got)
	}
	two := newSecretSet("ab")
	if got := two.scrub("ab abc cab (ab) sip:ab@h"); got != "[redacted] abc cab ([redacted]) sip:ab@h" {
		t.Errorf("two characters: %q", got)
	}
}

// The 7/8-character edge of shortSecretLen: 8 or more characters are removed
// everywhere, fewer only when standing alone; the split is by rune count, not bytes.
func TestShortSecretLengthEdge(t *testing.T) {
	tests := []struct {
		name, secret, in, want string
	}{
		{"8 chars glued is redacted", "abcd1234", "pw=abcd1234&x", "pw=" + redacted + "&x"},
		{"7 chars glued is not redacted", "abcd123", "pw=abcd123&x", "pw=abcd123&x"},
		{"8 chars alone is redacted", "abcd1234", "abcd1234", redacted},
		{"7 chars alone is redacted", "abcd123", "abcd123", redacted},
		{"8 runes glued is redacted", "pässwörd", "pw=pässwörd&x", "pw=" + redacted + "&x"},
		{"7 runes glued is not redacted", "pässwör", "pw=pässwör&x", "pw=pässwör&x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := newSecretSet(tc.secret).scrub(tc.in); got != tc.want {
				t.Errorf("scrub(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Nil stays nil (a result with no content array must not gain an empty one) and
// an empty array stays an array.
func TestRedactResultPreservesNilContent(t *testing.T) {
	s := newSecretSet(redactPW)
	got, err := s.redactResult(&sdk.CallToolResult{StructuredContent: map[string]any{"n": float64(1)}}, true)
	if err != nil || got.Content != nil {
		t.Fatalf("nil Content must stay nil: %#v %v", got.Content, err)
	}
	got, err = s.redactResult(&sdk.CallToolResult{Content: []sdk.Content{}}, true)
	if err != nil || got.Content == nil || len(got.Content) != 0 {
		t.Fatalf("empty Content must stay an empty, non-nil slice: %#v %v", got.Content, err)
	}
}

func TestContainsSecret(t *testing.T) {
	if !ContainsSecret(redactPW, "x "+jsonInner(redactPW, true)+" y") || !ContainsSecret(redactPW, url.QueryEscape(redactPW)) {
		t.Fatal("ContainsSecret must recognise every spelling the proxy scrubs")
	}
	if ContainsSecret(redactPW, "nothing to see") || ContainsSecret("", "anything") {
		t.Fatal("ContainsSecret false positive")
	}
}

// escapeCase rewrites the hex digits of every percent-escape in v: pick(i) says
// whether the i-th escape gets upper (true) or lower (false) case.
func escapeCase(v string, pick func(i int) bool) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] == '%' && i+2 < len(v) && isHex(v[i+1]) && isHex(v[i+2]) {
			esc := v[i+1 : i+3]
			if pick(n) {
				esc = strings.ToUpper(esc)
			} else {
				esc = strings.ToLower(esc)
			}
			b.WriteString("%" + esc)
			n++
			i += 2
			continue
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// F5 / Cycle C: url.QueryEscape and url.PathEscape only produce UPPER-case hex, but
// RFC 3986 treats %3e and %3E as the same escape, so an echo in lower or mixed
// case (also different cases within one string) must not slip past.
func TestSecretSetScrubsPercentEscapesInAnyCase(t *testing.T) {
	const pw = "Pw>1?2/3 four" // '>', '?', '/' and a space: every one of them is percent-escaped
	q, p := url.QueryEscape(pw), url.PathEscape(pw)
	if q != "Pw%3E1%3F2%2F3+four" || p != "Pw%3E1%3F2%2F3%20four" {
		t.Fatalf("premise: unexpected escapes %q %q", q, p)
	}
	s := newSecretSet(pw)
	for name, base := range map[string]string{"query": q, "path": p} {
		upper := escapeCase(base, func(int) bool { return true })
		lower := escapeCase(base, func(int) bool { return false })
		mixed := escapeCase(base, func(i int) bool { return i%2 == 1 })
		if lower == upper || mixed == upper || mixed == lower {
			t.Fatalf("premise: %s spellings are not pairwise distinct: %q %q %q", name, upper, lower, mixed)
		}
		for kind, form := range map[string]string{"upper": upper, "lower": lower, "mixed": mixed} {
			got := s.scrub("GET /x?p=" + form + "&y=1")
			if got != "GET /x?p="+redacted+"&y=1" {
				t.Errorf("%s %s escape %q not scrubbed exactly: %q", name, kind, form, got)
			}
		}
	}
}

// The same holds for a short password, whose boundary rules must stay intact.
func TestShortSecretPercentEscapesInAnyCaseKeepTheirBoundaries(t *testing.T) {
	const pw = "a>?b" // 4 characters: short, so bounded
	s := newSecretSet(pw)
	q := url.QueryEscape(pw) // a%3E%3Fb
	for kind, form := range map[string]string{
		"upper": q,
		"lower": escapeCase(q, func(int) bool { return false }),
		"mixed": escapeCase(q, func(i int) bool { return i == 1 }),
	} {
		if got := s.scrub("x " + form + " y"); got != "x "+redacted+" y" {
			t.Errorf("%s: standalone short escape not scrubbed: %q", kind, got)
		}
		glued := "pw=" + form + "&z=1"
		if got := s.scrub(glued); got != glued {
			t.Errorf("%s: a short escape glued to other text must stay (OD23): %q", kind, got)
		}
	}
}

// F4 / Cycle C: a long secret split across two fields of one result is not found
// by the per-field scrub; the concatenation check withholds the result.
func TestRedactResultWithholdsASecretSplitAcrossFields(t *testing.T) {
	const pw = "secret-prefixsecret-suffix"
	s := newSecretSet(pw)
	quoted := `ab"cdefghijkl` // its JSON-escaped spelling is ab\"cdefghijkl
	s.add(quoted)
	cases := map[string]*sdk.CallToolResult{
		"two text blocks":                     {Content: []sdk.Content{&sdk.TextContent{Text: "id secret-prefix"}, &sdk.TextContent{Text: "secret-suffix ok"}}},
		"three text blocks":                   {Content: []sdk.Content{&sdk.TextContent{Text: "a secret-"}, &sdk.TextContent{Text: "prefixsecret"}, &sdk.TextContent{Text: "-suffix"}}},
		"json-escaped spelling across blocks": {Content: []sdk.Content{&sdk.TextContent{Text: `x ab\`}, &sdk.TextContent{Text: `"cdefghijkl y`}}},
		"two structured strings":              {Content: []sdk.Content{}, StructuredContent: map[string]any{"a": "secret-prefix", "b": "secret-suffix"}},
		"structured list":                     {StructuredContent: []any{"secret-prefix", "secret-suffix"}},
		"structured nested":                   {StructuredContent: map[string]any{"x": []any{"secret-pre", map[string]any{"y": "fixsecret-suffix"}}}},
	}
	for name, res := range cases {
		for _, closed := range []bool{true, false} {
			got, err := s.redactResult(res, closed)
			if !errors.Is(err, errSplitSecret) || got != nil {
				t.Errorf("%s (failClosed=%v): want errSplitSecret and no result, got %v %v", name, closed, got, err)
			}
		}
	}
}

func TestRedactResultLeavesAdjacentFieldsAloneWhenTheyDoNotFormASecret(t *testing.T) {
	s := newSecretSet("secret-prefixsecret-suffix", "1001")
	cases := map[string]*sdk.CallToolResult{
		"long secret, halves of different things": {
			Content:           []sdk.Content{&sdk.TextContent{Text: "secret-prefix"}, &sdk.TextContent{Text: "other-suffix"}},
			StructuredContent: map[string]any{"a": "secret-prefix", "b": "other-suffix"},
		},
		// "10" then "01" read one after the other are the short secret 1001, which is
		// deliberately NOT checked across fields (OD23): it would match everywhere.
		"short secret, text blocks":        {Content: []sdk.Content{&sdk.TextContent{Text: "10"}, &sdk.TextContent{Text: "01"}}},
		"short secret, structured strings": {StructuredContent: []any{"10", "01"}},
	}
	for name, res := range cases {
		before, _ := json.Marshal(res)
		got, err := s.redactResult(res, true)
		if err != nil {
			t.Errorf("%s: adjacent fields that do not concatenate to a long secret must pass: %v", name, err)
			continue
		}
		if after, _ := json.Marshal(got); string(before) != string(after) {
			t.Errorf("%s: result altered:\n%s\n%s", name, before, after)
		}
	}
}

// Rule 13 F1: without failClosed, every non-text block is inspected in full: each
// string field, _meta, annotations and the raw bytes of binary data. A result in
// which one of them carries a secret is withheld, and so is a block of a type the
// redactor does not know, whatever it carries.
func TestRedactResultInspectsEveryNonTextBlock(t *testing.T) {
	const tok = "tok-TOKEN-0123"
	s := newSecretSet(tok, redactPW)
	ann := &sdk.Annotations{LastModified: tok}
	// The token sits at an offset the base64 of the whole blob does not align with,
	// so it is found only in the raw bytes, not in their JSON (base64) spelling.
	unaligned := []byte("\x89PNG" + tok + "\x00")
	file := &sdk.ResourceContents{URI: "file:///x", Text: "t"}
	tests := map[string]sdk.Content{
		"image data":                &sdk.ImageContent{Data: unaligned, MIMEType: "image/png"},
		"image mime type":           &sdk.ImageContent{Data: []byte("x"), MIMEType: "image/" + tok},
		"image _meta":               &sdk.ImageContent{Data: []byte("x"), MIMEType: "image/png", Meta: sdk.Meta{"k": tok}},
		"image annotations":         &sdk.ImageContent{Data: []byte("x"), MIMEType: "image/png", Annotations: ann},
		"audio data":                &sdk.AudioContent{Data: unaligned, MIMEType: "audio/wav"},
		"audio _meta":               &sdk.AudioContent{Data: []byte("x"), MIMEType: "audio/wav", Meta: sdk.Meta{"k": tok}},
		"resource link name":        &sdk.ResourceLink{URI: "file:///x", Name: tok},
		"resource link uri":         &sdk.ResourceLink{URI: "https://h/?t=" + url.QueryEscape(tok), Name: "n"},
		"resource link title":       &sdk.ResourceLink{URI: "file:///x", Name: "n", Title: tok},
		"resource link description": &sdk.ResourceLink{URI: "file:///x", Name: "n", Description: "d " + redactPW},
		"resource link annotations": &sdk.ResourceLink{URI: "file:///x", Name: "n", Annotations: ann},
		"embedded text":             &sdk.EmbeddedResource{Resource: &sdk.ResourceContents{URI: "file:///x", Text: "pw " + redactPW}},
		"embedded uri":              &sdk.EmbeddedResource{Resource: &sdk.ResourceContents{URI: "file:///" + tok, Text: "t"}},
		"embedded blob":             &sdk.EmbeddedResource{Resource: &sdk.ResourceContents{URI: "file:///x", Blob: unaligned}},
		"embedded resource _meta":   &sdk.EmbeddedResource{Resource: &sdk.ResourceContents{URI: "file:///x", Text: "t", Meta: sdk.Meta{"k": tok}}},
		"embedded block _meta":      &sdk.EmbeddedResource{Resource: file, Meta: sdk.Meta{"k": tok}},
		"embedded annotations":      &sdk.EmbeddedResource{Resource: file, Annotations: ann},
		"text annotations":          &sdk.TextContent{Text: "ok", Annotations: ann},
		"unknown block type":        &sdk.ToolUseContent{ID: "1", Name: "x"},
	}
	for name, c := range tests {
		t.Run(name, func(t *testing.T) {
			res := &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "created"}, c}}
			if got, err := s.redactResult(res, false); err == nil || got != nil {
				t.Fatalf("the result must be withheld, got %v / %v", got, err)
			}
		})
	}
	// Clean blocks of every supported type still pass through untouched.
	clean := []sdk.Content{
		&sdk.TextContent{Text: "ok", Annotations: &sdk.Annotations{LastModified: "2026-09-30T12:00:00Z"}},
		&sdk.ImageContent{Data: []byte("\x89PNG"), MIMEType: "image/png", Meta: sdk.Meta{"k": "v"}},
		&sdk.AudioContent{Data: []byte("RIFF"), MIMEType: "audio/wav"},
		&sdk.ResourceLink{URI: "file:///x", Name: "n", Title: "t", Description: "d"},
		&sdk.EmbeddedResource{Resource: &sdk.ResourceContents{URI: "file:///x", Text: "t", Blob: []byte("b")}},
	}
	got, err := s.redactResult(&sdk.CallToolResult{Content: clean}, false)
	if err != nil || !reflect.DeepEqual(got.Content, clean) {
		t.Fatalf("clean blocks must pass through unchanged: %v / %v", got, err)
	}
}

// Rule 13 F6: JSON text is decoded (so non-canonical escapes such as a \uXXXX ASCII
// escape or \/ are undone) even when no short secret is registered.
func TestScrubDecodesNonCanonicalJSONEscapesWithoutAShortSecret(t *testing.T) {
	const tok = "TOKEN/abc-123456"
	s := newSecretSet(tok) // long secrets only
	out := s.scrub(`{"t":"\u0054OKEN/abc-123456","u":"TOKEN\/abc-123456"}`)
	if strings.Contains(out, "OKEN") || strings.Count(out, redacted) != 2 {
		t.Fatalf("an escaped spelling of the token survived: %s", out)
	}
}
