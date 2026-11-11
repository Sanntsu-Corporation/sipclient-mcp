package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	redacted = "[redacted]"

	// shortSecretLen is the length (in characters) below which a secret is
	// matched only as a standalone token (OD23): a short secret such as "1001" or
	// "200" is a substring of legitimate output (sip:1001@h, ua handles,
	// timestamps, status codes) and replacing it everywhere would corrupt the
	// very results the model needs.
	shortSecretLen = 8

	// maxJSONDepth bounds how deep JSON carried inside a string is inspected.
	maxJSONDepth = 4
)

// errUninspectable is returned when a result carries content the redactor
// cannot read. The caller must withhold the result (fail closed).
var errUninspectable = errors.New("result contains content that cannot be checked for credentials")

// errSecretInBlock is returned when a content block that is not text carries a
// secret. Such a block is not rewritten (its fields are typed, some binary), so
// the caller must withhold the whole result.
var errSecretInBlock = errors.New("result carries a credential in a non-text content block")

// errSplitSecret is returned when a long secret is not present in any single
// field of a result but appears once the fields are read one after the other:
// it was split across text blocks or across structured string values.
var errSplitSecret = errors.New("result carries a credential split across fields")

// percentEscape is one URL percent-escape. RFC 3986 section 2.1 says the hex
// digits of an escape are case-insensitive, and section 6.2.2.1 says "%3a" and
// "%3A" are equivalent, but url.QueryEscape and url.PathEscape only produce
// upper case.
var percentEscape = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)

// secretForm is one textual spelling of a secret. bounded forms (spellings of a
// short secret) are replaced only where they stand alone as a token. A form that
// contains percent-escapes carries a matcher that accepts either case for the hex
// digits of every escape, independently (so "%3e%3E" and "%3E%3e" both match).
type secretForm struct {
	text    string
	bounded bool
	re      *regexp.Regexp // nil unless text contains a percent-escape
}

func newSecretForm(text string, bounded bool) secretForm {
	f := secretForm{text: text, bounded: bounded}
	locs := percentEscape.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return f
	}
	var b strings.Builder
	last := 0
	for _, l := range locs {
		b.WriteString(regexp.QuoteMeta(text[last:l[0]]))
		b.WriteString("%(?i:" + text[l[0]+1:l[1]] + ")")
		last = l[1]
	}
	b.WriteString(regexp.QuoteMeta(text[last:]))
	f.re = regexp.MustCompile(b.String())
	return f
}

// find returns the first match of the form in s ([-1, -1] when absent).
func (f secretForm) find(s string) (start, end int) {
	if f.re != nil {
		if loc := f.re.FindStringIndex(s); loc != nil {
			return loc[0], loc[1]
		}
		return -1, -1
	}
	if i := strings.Index(s, f.text); i >= 0 {
		return i, i + len(f.text)
	}
	return -1, -1
}

// secretSet is the per-process set of values that must never reach the model:
// the upstream bearer token plus every account password the proxy has injected.
// It is safe for concurrent use.
type secretSet struct {
	mu         sync.Mutex
	seen       map[string]bool
	forms      []secretForm // every textual form of every secret, longest first
	hasBounded bool
}

func newSecretSet(initial ...string) *secretSet {
	s := &secretSet{seen: map[string]bool{}}
	for _, v := range initial {
		s.add(v)
	}
	return s
}

// add registers secret. An empty secret is ignored (it would match everywhere).
func (s *secretSet) add(secret string) {
	s.addForms("s\x00"+secret, secret, secretForms(secret))
}

// addCredential registers an account's password and, in addition, the
// base64 spellings of "username:password" (the HTTP Basic credential form).
func (s *secretSet) addCredential(user, pass string) {
	if pass == "" {
		return
	}
	s.add(pass)
	if user != "" {
		pair := user + ":" + pass
		s.addForms("c\x00"+pair, pair, base64Forms(pair))
	}
}

func (s *secretSet) addForms(key, source string, texts []string) {
	if source == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[key] {
		return
	}
	s.seen[key] = true
	bounded := utf8.RuneCountInString(source) < shortSecretLen
	type formKey struct {
		text    string
		bounded bool
	}
	have := map[formKey]bool{}
	for _, f := range s.forms {
		have[formKey{f.text, f.bounded}] = true
	}
	for _, t := range texts {
		k := formKey{t, bounded}
		if t != "" && !have[k] {
			have[k] = true
			s.forms = append(s.forms, newSecretForm(t, bounded))
		}
	}
	s.hasBounded = s.hasBounded || bounded
	// Longest first, so a shorter form never leaves a fragment of a longer one.
	sort.SliceStable(s.forms, func(i, j int) bool { return len(s.forms[i].text) > len(s.forms[j].text) })
}

// secretForms returns the raw secret and its other textual spellings: URL-encoded
// (QueryEscape and PathEscape) and base64 (standard and URL alphabets, padded and
// unpadded), and each of those JSON-escaped once (the spelling inside a JSON
// text) and twice (a JSON text carried as a string inside another JSON text, as
// a daemon payload that embeds one would produce), with and without HTML
// escaping (encoding/json escapes <, > and & by default, so a path-escaped
// password containing & arrives as &; a daemon using SetEscapeHTML(false)
// does not). Non-reversible transforms (digests, hashes) are out of scope.
func secretForms(secret string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(v string) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	bases := append([]string{secret, url.QueryEscape(secret), url.PathEscape(secret)}, base64Forms(secret)...)
	for _, base := range bases {
		add(base)
		for _, once := range []string{jsonInner(base, true), jsonInner(base, false)} {
			add(once)
			add(jsonInner(once, true))
			add(jsonInner(once, false))
		}
	}
	return out
}

func base64Forms(v string) []string {
	b := []byte(v)
	return []string{
		base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
	}
}

// jsonInner returns v JSON-encoded without the surrounding quotes. Invalid
// UTF-8 is replaced by U+FFFD (one per invalid byte) before encoding, so the
// output does not depend on the toolchain: encoding/json writes `\ufffd` for an
// invalid byte without GOEXPERIMENT=jsonv2 and a raw U+FFFD with it (the
// default from Go 1.27), while a valid U+FFFD is written raw by both.
func jsonInner(v string, escapeHTML bool) string {
	if !utf8.ValidString(v) {
		v = strings.Map(func(r rune) rune { return r }, v) // range semantics: U+FFFD per invalid byte
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(escapeHTML)
	_ = enc.Encode(v) // cannot fail for a string
	b := bytes.TrimRight(buf.Bytes(), "\n")
	return string(b[1 : len(b)-1])
}

// ContainsSecret reports whether s carries secret in any spelling the proxy
// scrubs. Tests and the live gate use it so that spelling knowledge stays in
// this file.
func ContainsSecret(secret, s string) bool { return newSecretSet(secret).scrub(s) != s }

func (s *secretSet) snapshot() ([]secretForm, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]secretForm(nil), s.forms...), s.hasBounded
}

// isSeparator reports whether r may stand next to a short secret that is still
// to count as standalone: white space, quotes, brackets and commas. Letters,
// digits and joiners such as @ : . - _ / = % are NOT separators, so a short
// password never matches inside sip:1001@host, ua_1001, 10:01:00 or a URL.
func isSeparator(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune("\"'`()[]{}<>,", r)
}

// replaceStandalone replaces every occurrence of form in str that stands alone
// (both neighbours are a separator or the edge of str).
func replaceStandalone(str string, form secretForm) string {
	if form.text == "" {
		return str
	}
	if start, _ := form.find(str); start < 0 {
		return str
	}
	var b strings.Builder
	i := 0
	for i < len(str) {
		j, e := form.find(str[i:])
		if j < 0 {
			break
		}
		start, end := i+j, i+e
		before, sb := utf8.DecodeLastRuneInString(str[:start])
		after, sa := utf8.DecodeRuneInString(str[end:])
		if (sb == 0 || isSeparator(before)) && (sa == 0 || isSeparator(after)) {
			b.WriteString(str[i:start])
			b.WriteString(redacted)
			i = end
			continue
		}
		_, w := utf8.DecodeRuneInString(str[start:])
		b.WriteString(str[i : start+w])
		i = start + w
	}
	b.WriteString(str[i:])
	return b.String()
}

func replaceForms(str string, forms []secretForm, bounded bool) string {
	for _, f := range forms {
		switch {
		case f.bounded != bounded:
		case bounded:
			str = replaceStandalone(str, f)
		case f.re != nil:
			str = f.re.ReplaceAllLiteralString(str, redacted)
		default:
			str = strings.ReplaceAll(str, f.text, redacted)
		}
	}
	return str
}

// scrub replaces every form of every secret in str with [redacted]. Long
// secrets are replaced wherever they occur. Short secrets are replaced only as
// standalone tokens, and never inside JSON structure: if str is a JSON object or
// array its string VALUES are inspected and its keys and non-string literals are
// left alone (OD23). A result of scrub that changed JSON text is re-encoded, so
// key order may change; unchanged JSON text is returned byte for byte.
func (s *secretSet) scrub(str string) string { return s.scrubDepth(str, 0) }

func (s *secretSet) scrubDepth(str string, depth int) string {
	forms, _ := s.snapshot()
	str = replaceForms(str, forms, false)
	// JSON text is decoded even without a short secret: a value spelled with
	// non-canonical escapes (\u0054, \/) matches no form until it is decoded.
	if depth < maxJSONDepth {
		if out, ok := s.scrubJSONText(str, depth); ok {
			return out
		}
	}
	return replaceForms(str, forms, true)
}

// scrubJSONText handles str when it is one JSON object or array.
func (s *secretSet) scrubJSONText(str string, depth int) (string, bool) {
	t := strings.TrimSpace(str)
	if t == "" || (t[0] != '{' && t[0] != '[') {
		return "", false
	}
	dec := json.NewDecoder(strings.NewReader(t))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return "", false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", false // trailing data: not one JSON value
	}
	out, err := s.scrubValueDepth(v, depth+1)
	if err != nil {
		return "", false
	}
	if reflect.DeepEqual(v, out) {
		return str, true
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(out) != nil {
		return "", false
	}
	return strings.TrimRight(buf.String(), "\n"), true
}

// scrubKey scrubs an object key: long secrets only. A short secret is never
// applied to keys (a key equal to a short password would otherwise be rewritten).
func (s *secretSet) scrubKey(k string) string {
	forms, _ := s.snapshot()
	return replaceForms(k, forms, false)
}

// scrubValue returns a copy of v (decoded JSON) with every string VALUE and
// object KEY scrubbed, recursively (short secrets: values only, see scrub).
// Values of other Go types are normalised through JSON first; if that fails the
// error is returned and the caller must withhold the data.
func (s *secretSet) scrubValue(v any) (any, error) { return s.scrubValueDepth(v, 0) }

func (s *secretSet) scrubValueDepth(v any, depth int) (any, error) {
	switch x := v.(type) {
	case nil, bool, float64, json.Number:
		return v, nil
	case string:
		return s.scrubDepth(x, depth), nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			r, err := s.scrubValueDepth(e, depth)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			r, err := s.scrubValueDepth(e, depth)
			if err != nil {
				return nil, err
			}
			out[s.scrubKey(k)] = r
		}
		return out, nil
	case sdk.Meta:
		return s.scrubValueDepth(map[string]any(x), depth)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		var n any
		if err := dec.Decode(&n); err != nil {
			return nil, err
		}
		return s.scrubValueDepth(n, depth)
	}
}

func (s *secretSet) scrubMeta(m sdk.Meta) (sdk.Meta, error) {
	if m == nil {
		return nil, nil
	}
	r, err := s.scrubValue(map[string]any(m))
	if err != nil {
		return nil, err
	}
	return sdk.Meta(r.(map[string]any)), nil
}

// splitAcross reports whether a LONG secret (any spelling) appears once parts are
// read one after the other. It is meant for parts that were already scrubbed one
// by one, so any remaining occurrence spans a boundary between two fields. Short
// secrets are excluded on purpose (OD23): concatenating unrelated fields would
// make them match everywhere.
func (s *secretSet) splitAcross(parts []string) bool {
	if len(parts) < 2 {
		return false
	}
	forms, _ := s.snapshot()
	joined := strings.Join(parts, "")
	return replaceForms(joined, forms, false) != joined
}

// structuredStrings appends every string VALUE of a decoded JSON value in
// document order: array order, and sorted key order for objects (a decoded
// object no longer knows the order it had on the wire).
func structuredStrings(v any, out *[]string) {
	switch x := v.(type) {
	case string:
		*out = append(*out, x)
	case []any:
		for _, e := range x {
			structuredStrings(e, out)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			structuredStrings(x[k], out)
		}
	}
}

// carriesSecret reports whether s contains any spelling of any secret.
func (s *secretSet) carriesSecret(v string) bool { return s.scrub(v) != v }

// blockCarriesSecret inspects a content block that is not text, or a text
// block's annotations: every field as the JSON the block is sent as (strings,
// _meta, annotations), plus the raw bytes of binary data, where a secret at any
// offset would not be found in the base64 spelling. It returns errUninspectable
// for a block type it does not know and errSecretInBlock when a secret is found.
func (s *secretSet) blockCarriesSecret(c any) error {
	var raw []byte
	switch b := c.(type) {
	case *sdk.ImageContent:
		raw = b.Data
	case *sdk.AudioContent:
		raw = b.Data
	case *sdk.EmbeddedResource:
		if b.Resource != nil {
			raw = b.Resource.Blob
		}
	case *sdk.ResourceLink, *sdk.Annotations:
	default:
		return errUninspectable
	}
	j, err := json.Marshal(c)
	if err != nil {
		return errUninspectable
	}
	if s.carriesSecret(string(j)) || s.carriesSecret(string(raw)) {
		return errSecretInBlock
	}
	return nil
}

// redactResult returns a scrubbed copy of res; res itself is never modified.
// Text blocks, structured content and _meta (result and text-block level) are
// scrubbed. A block of any other type is not rewritten: with failClosed the
// result is rejected with errUninspectable (used for account-based ua_create,
// where the password is known to have been sent); otherwise the block is
// inspected (blockCarriesSecret, which also covers a text block's annotations)
// and passes through unchanged only when it carries no secret.
// After the per-field scrub, the text blocks read one after the other, and
// separately the structured string values read one after the other, are checked
// again for a long secret that was split across fields; if one is found the
// result is rejected with errSplitSecret. A nil Content stays nil. Any error
// means the caller must withhold the result entirely.
func (s *secretSet) redactResult(res *sdk.CallToolResult, failClosed bool) (*sdk.CallToolResult, error) {
	if res == nil {
		return nil, nil
	}
	out := *res
	var err error
	if out.Meta, err = s.scrubMeta(res.Meta); err != nil {
		return nil, err
	}
	if res.Content != nil {
		out.Content = make([]sdk.Content, len(res.Content))
	}
	var texts []string
	for i, c := range res.Content {
		tc, ok := c.(*sdk.TextContent)
		if !ok {
			if failClosed {
				return nil, errUninspectable
			}
			if err := s.blockCarriesSecret(c); err != nil {
				return nil, err
			}
			out.Content[i] = c
			continue
		}
		if tc.Annotations != nil {
			if err := s.blockCarriesSecret(tc.Annotations); err != nil {
				return nil, err
			}
		}
		cp := *tc
		cp.Text = s.scrub(tc.Text)
		texts = append(texts, cp.Text)
		if cp.Meta, err = s.scrubMeta(tc.Meta); err != nil {
			return nil, err
		}
		out.Content[i] = &cp
	}
	if s.splitAcross(texts) {
		return nil, errSplitSecret
	}
	if res.StructuredContent != nil {
		if out.StructuredContent, err = s.scrubValue(res.StructuredContent); err != nil {
			return nil, err
		}
		var strs []string
		structuredStrings(out.StructuredContent, &strs)
		if s.splitAcross(strs) {
			return nil, errSplitSecret
		}
	}
	return &out, nil
}
