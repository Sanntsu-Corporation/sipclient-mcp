package session

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// TestInputStructsMatchSection10 asserts each input struct's JSON field set
// equals §10's parameter table for that tool, transcribed by hand.
//
// It is a TRANSCRIPTION CHECK, and that is the point: the failure it catches is
// a field named `to` where §10 says `to_uri`, which compiles, passes every
// behavioural test, and silently drops the parameter on the wire.
func TestInputStructsMatchSection10(t *testing.T) {
	tests := []struct {
		name   string
		in     any
		fields []string
	}{
		{"ua_create", UACreateInput{}, []string{
			"mode", "transport", "local_addr", "srtp", "codec_pref", "keepalive",
			"aor", "auth_user", "auth_pass", "registrar", "expires_s",
			"dtmf_mode", "session_expires_s", "min_se_s", "keepalive_interval_s",
			"session_refresh_method", "auth_any_host", "allow_cleartext_sdes"}},
		{"session_keepalive", SessionKeepaliveInput{}, nil},
		{"ua_status", UAStatusInput{}, []string{"ua"}},
		{"ua_destroy", UADestroyInput{}, []string{"ua"}},
		{"call_dial", CallDialInput{}, []string{
			"ua", "to_uri", "from_user", "codec_pref", "srtp", "media_plan", "capture",
			"max_duration_s", "headers"}},
		{"call_answer", CallAnswerInput{}, []string{
			"call", "codec_pref", "srtp", "media_plan", "capture", "max_duration_s"}},
		{"call_reject", CallRejectInput{}, []string{"call", "status", "reason"}},
		{"call_hangup", CallHangupInput{}, []string{"call", "reason"}},
		{"call_status", CallStatusInput{}, []string{"call"}},
		{"call_list", CallListInput{}, nil},
		{"call_wait", CallWaitInput{}, []string{"call", "until", "timeout_ms", "since"}},
		{"call_events", CallEventsInput{}, []string{"call", "since"}},
		{"call_ladder", CallLadderInput{}, []string{"call", "format"}},
	}
	if len(tests) != 13 {
		t.Fatalf("%d input structs, want 13 — one per P1 tool (§14.6)", len(tests))
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt := reflect.TypeOf(tc.in)
			var got []string
			for i := 0; i < rt.NumField(); i++ {
				tag := rt.Field(i).Tag.Get("json")
				if tag == "" || tag == "-" {
					t.Fatalf("field %s has no json tag; §10's names are the wire contract",
						rt.Field(i).Name)
				}
				name := tag
				if idx := len(name); idx > 0 {
					if c := indexByte(name, ','); c >= 0 {
						name = name[:c]
					}
				}
				got = append(got, name)
			}
			want := append([]string(nil), tc.fields...)
			sort.Strings(got)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("json fields = %v, want %v (§10's parameter table)", got, want)
			}
		})
	}
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// TestRequiredInputsAreNotOmitempty guards the one asymmetry that matters: a
// REQUIRED parameter tagged omitempty vanishes from a round-trip when it holds
// its zero value, which for call_wait's timeout_ms turns an invalid_argument
// into a silently-defaulted wait.
func TestRequiredInputsAreNotOmitempty(t *testing.T) {
	raw, err := json.Marshal(CallWaitInput{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"call"`, `"until"`, `"timeout_ms"`} {
		if !containsSub(string(raw), want) {
			t.Errorf("zero CallWaitInput marshalled to %s, missing required field %s", raw, want)
		}
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestValidateToURI is D72: to_uri accepts ONLY §10.3's enumerated forms and
// rejects everything the six PERMITTED-but-shouldn't-be samples proved live —
// a whole-scheme "sips:" bypass (in any case-fold), a CRLF header-injection
// attempt, host percent-encoding and more than one "@". These are pure string
// checks and need no policy fixture at all; TestCallDialClosesTheSipsSchemeBypass
// in toolservice_test.go is the integration proof against a DENY-ONLY policy —
// policy.Defaults() ships neither an allow nor a deny list and therefore
// permits everything, so it cannot observe any of this (D72).
func TestValidateToURI(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"plain sip", "sip:19005550123@example.net", false},
		{"sip with port", "sip:bob@example.net:5061", false},
		{"bare host port", "example.net:5060", false},
		{"bare host, no port", "lab.internal", false},
		{"sips lowercase", "sips:19005550123@example.net", true},
		{"sips uppercase", "SIPS:19005550123@example.net", true},
		{"sips mixed case", "SiPs:19005550123@example.net", true},
		{"crlf header injection", "sip:x@lab.internal\r\nINVITE sip:evil@a.b SIP/2.0", true},
		{"host percent-encoding", "sip:x@lab%2Einternal", true},
		{"multiple at", "sip:x@lab.internal@evil.example", true},
		{"internal whitespace", "sip:x@lab internal", true},
		{"bare form with an at sign", "x@lab.internal:5060", true},
		// The name-addr bracket bypass: policy.Normalise trims a leading "<"
		// and trailing ">" BEFORE detecting the scheme, so "<sips:host>"
		// normalises to a sips: URI even though its raw bytes do not start
		// with "sips:". These are BARE-HOST forms (no "@") deliberately: with
		// a user part present, the pre-existing "no sip: scheme but contains
		// @" default-branch check would reject them for an unrelated reason
		// and the case would prove nothing about the bracket-trim fix
		// specifically — exactly the over-determination the CRLF case had.
		// Without the trim, these fell into the bare-host default branch
		// (which permits ANY string with no "@"), letting the disallowed
		// scheme reach CheckDestination whole — proved live via CallDial in
		// TestCallDialClosesTheSipsSchemeBypass.
		{"sips bracketed name-addr, bare host", "<sips:lab.internal>", true},
		{"sips bracketed uppercase, bare host", "<SIPS:lab.internal>", true},
		{"sips bracketed no closing bracket, bare host", "<sips:lab.internal", true},
		{"sips bracketed with port, bare host", "<sips:lab.internal:5060>", true},
		{"sips bracketed name-addr, with user part", "<sips:19005550123@example.net>", true},
		{"sip bracketed name-addr is still accepted", "<sip:19005550123@example.net>", false},
		{"empty to_uri is rejected", "", true},
		{"bare scheme with no host is rejected", "sip:", true},
		{"empty brackets are rejected", "<>", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateToURI(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateToURI(%q) = nil, want an error", tc.in)
				}
				assertCode(t, err, apierr.CodeInvalidArgument)
				return
			}
			if err != nil {
				t.Fatalf("validateToURI(%q) = %v, want nil", tc.in, err)
			}
		})
	}
}

// TestValidateToURIRejectsControlCharactersWithNoOtherViolation is a test the
// control-character check ALONE can fail. TestValidateToURI's own CRLF case
// ("sip:x@lab.internal\r\nINVITE sip:evil@a.b SIP/2.0") also contains a space
// and a second "@", so it is over-determined: it is rejected by the
// whitespace or multiple-"@" rule even if the control-character check is
// deleted entirely, and the whole ./internal/session suite stays green with
// that check gone. This input has no space and exactly one "@" — it can be
// rejected ONLY by the control-character check — so deleting that check must
// make this specific assertion fail.
func TestValidateToURIRejectsControlCharactersWithNoOtherViolation(t *testing.T) {
	const in = "sip:x@lab.internal\r\nFoo:bar"
	if strings.ContainsAny(in, " \t") {
		t.Fatalf("test input %q contains whitespace; it would no longer isolate "+
			"the control-character check", in)
	}
	if strings.Count(in, "@") > 1 {
		t.Fatalf("test input %q contains more than one \"@\"; it would no longer "+
			"isolate the control-character check", in)
	}
	err := validateToURI(in)
	if err == nil {
		t.Fatalf("validateToURI(%q) = nil, want an error (CRLF header injection)", in)
	}
	assertCode(t, err, apierr.CodeInvalidArgument)
	if !strings.Contains(err.Error(), "control character") {
		t.Fatalf("validateToURI(%q) = %v, want the control-character message; "+
			"this input must be caught by NO OTHER rule", in, err)
	}
}

// canonicalFormProblems reports every way norm — the output of
// policy.Normalise — fails to be the canonical sip: form
// TestValidateToURIAgreesWithNormalise requires whenever validateToURI has
// accepted the raw string norm was built from: it must start with "sip:", it
// must carry no residual angle bracket, its (lowercased) scheme must not be
// "sips:", and it must carry no Unicode whitespace anywhere — a strict
// superset of the "no leading/trailing" wording this test was specified
// against: none of the eight §10.3-permitted forms carry embedded whitespace
// either, so checking the whole string costs nothing, and it is what makes
// this property test — not just the pre-existing hand-enumerated
// "internal whitespace" case in TestValidateToURI — independently sensitive
// to a regression in validateToURI's whole-string unicode.IsSpace scan.
func canonicalFormProblems(norm string) []string {
	var problems []string
	if !strings.HasPrefix(norm, "sip:") {
		problems = append(problems, `does not start with "sip:"`)
	}
	if strings.ContainsAny(norm, "<>") {
		problems = append(problems, "contains a residual angle bracket")
	}
	if strings.HasPrefix(strings.ToLower(norm), "sips:") {
		problems = append(problems, `scheme is "sips:"`)
	}
	if strings.IndexFunc(norm, unicode.IsSpace) >= 0 {
		problems = append(problems, "contains Unicode whitespace")
	}
	// D72 ROUND 3: a host must survive. HasPrefix(norm, "sip:") alone was the
	// gap this whole round exploited — "sip:" itself satisfies that prefix
	// check, which is exactly why an 11,512-case corpus never tripped on
	// Normalise erasing the host down to nothing (destination.go's ';'/'?'
	// truncation, unchanged this round, does this whenever the separator
	// sits before any '@'). This clause does not enumerate that one axis: it
	// fires on ANY norm whose scheme carries no host at all, or carries a
	// user part with nothing after the '@', whatever future divergence
	// produces that shape.
	if len(norm) <= len("sip:") {
		problems = append(problems, `carries no host: normalised form is "sip:" or shorter`)
	} else {
		host := norm[len("sip:"):]
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
		if host == "" {
			problems = append(problems, "host is empty after the scheme (user part present but no host)")
		}
	}
	// D72 ROUND 4 (axis 5): a doubled scheme — Normalise prepending its own
	// "sip:" in front of a remainder that is ITSELF a "sip:"/"sips:" scheme
	// literal, which is exactly what it does with a to_uri whose scheme
	// token contains a rune (like 'İ', U+0130) that folds into "sip:" under
	// strings.ToLower but not under strings.EqualFold — satisfies every
	// clause above: it starts with "sip:", carries no bracket, its OWN outer
	// fold is not "sips:", it has no whitespace, and the "host" (whatever
	// follows the first '@', if any) is non-empty. None of the clauses above
	// can see a scheme token hiding one level in, so it is checked for
	// explicitly here.
	if strings.HasPrefix(norm, "sip:") {
		remainder := norm[len("sip:"):]
		hasSip := len(remainder) >= len("sip:") && strings.EqualFold(remainder[:len("sip:")], "sip:")
		hasSips := len(remainder) >= len("sips:") && strings.EqualFold(remainder[:len("sips:")], "sips:")
		if hasSip || hasSips {
			problems = append(problems,
				`remainder after "sip:" itself begins with a "sip:"/"sips:" scheme (doubled scheme)`)
		}
	}
	return problems
}

// TestValidateToURIAgreesWithNormalise is D72 ROUND 2's THIRD attempt at this
// class of bug, and it is deliberately shaped differently from the first two:
// TestValidateToURI and TestCallDialClosesTheSipsSchemeBypass each enumerate
// known-bad INSTANCES (a hand list of "sips:" spellings, bracket forms and
// now Unicode whitespace runes), and enumeration has already missed a whole
// bypass twice in this wave (Task 6, then Task 11b round 1). This test pins
// the AGREEMENT itself instead:
//
//	validateToURI(raw) == nil  =>  policy.Normalise(raw) is canonical.
//
// That invariant fails for EVERY past divergence of this shape — the round-1
// bracket bug, the round-2 Unicode-whitespace bug — and for any FUTURE
// divergence nobody has enumerated yet, because it does not depend on
// knowing what the divergence looks like. It is driven over a corpus
// generated from schemes x hosts x bracket-nesting depths x Unicode
// whitespace runes x position, rather than a hand list, specifically so a
// future change to either function is checked against combinations this
// review never thought of.
func TestValidateToURIAgreesWithNormalise(t *testing.T) {
	// Every Unicode code point strings.TrimSpace (unicode.IsSpace) trims,
	// beyond plain ASCII ' ' and '\t' — the exact set the round-2 bypass
	// report proved live via Normalise, plus the ASCII control whitespace
	// runes for completeness.
	whitespaceRunes := []rune{
		' ', '\t', '\n', '\r', '\v', '\f',
		0x0085, // NEL
		0x00A0, // NBSP
		0x1680, // Ogham space mark
		0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
		0x2028, 0x2029, // line/paragraph separator
		0x202F, // narrow no-break space
		0x205F, // medium mathematical space
		0x3000, // ideographic space
	}
	schemes := []string{"", "sip:", "sips:", "SIP:", "SIPS:", "SiPs:"}
	hosts := []string{"lab.internal", "19005550123.example.net", "x@lab.internal", "[2001:db8::1]:5060"}
	bracketDepths := []int{0, 1, 2, 3}

	var corpus []string

	// The seven live evasions from the round-2 bypass report, verbatim.
	corpus = append(corpus,
		"<<sips:19005550123.example.net>>",
		" sips:19005550123.example.net",
		"< sips:19005550123.example.net>",
		"\u0085sips:19005550123.example.net",
		" sips:19005550123.example.net",
		"　sips:19005550123.example.net",
		" sips:19005550123.example.net",
		" <sips:19005550123.example.net>",
	)

	// The eight §10.3-permitted forms that must NOT be over-rejected.
	corpus = append(corpus,
		"sip:lab.internal",
		"<sip:lab.internal>",
		"sip:alice@lab.internal:5060",
		"192.0.2.10:5060",
		"sip:sips@h",
		"sip:x@sips.example",
		"sip:[2001:db8::1]:5060",
		"SIP:lab.internal",
	)

	// D72 ROUND 3's four live evasions (the ';'/'?' axis: with the
	// separator at index 0, policy.Normalise's truncation guard sees no
	// surviving '@' either way and truncates to "", so the default branch
	// prepends "sip:" and the host is gone), plus two minimal constructed
	// forms — "sip:;" and "sip:?" — that isolate the SAME failure behind an
	// explicit scheme instead of relying on the no-scheme default branch.
	// validateToURI's Fix 1 (the ';'/'?' rejection) makes every one of these
	// return a non-nil error, so the loop below skips them entirely with
	// Fix 1 in place — they exist here so that reverting Fix 1 ALONE (per
	// the round-3 MANDATORY PROOF) makes this test fail on this corpus,
	// proving canonicalFormProblems' "a host must survive" clause below
	// catches the axis on its own, independent of the exclusion rule that
	// actually closes it in production.
	corpus = append(corpus,
		";evil.example",
		"?evil.example",
		";sips:evil.example",
		";sip:evil.example",
		"sip:;",
		"sip:?",
	)

	// Generated adversarial corpus: every scheme x host x bracket-nesting
	// depth, each optionally padded with each Unicode whitespace rune at
	// every position a name-addr could plausibly carry one.
	for _, scheme := range schemes {
		for _, host := range hosts {
			base := scheme + host
			for _, depth := range bracketDepths {
				bracketed := base
				for i := 0; i < depth; i++ {
					bracketed = "<" + bracketed + ">"
				}
				corpus = append(corpus, bracketed)
				for _, ws := range whitespaceRunes {
					w := string(ws)
					corpus = append(corpus,
						w+bracketed,   // leading
						bracketed+w,   // trailing
						w+bracketed+w, // both
					)
					if depth > 0 {
						// whitespace just inside the outermost bracket pair:
						// "< sip:host >"
						inner := bracketed[1 : len(bracketed)-1]
						corpus = append(corpus, "<"+w+inner+w+">")
					}
					// INTERIOR whitespace, away from either edge: the case
					// policy.TrimBrackets' TrimSpace does NOT remove (TrimSpace
					// only touches the string's ends), so it exercises a
					// genuinely different code path than the edge cases above —
					// the whole-string unicode.IsSpace scan, not the shared
					// trim helper. Splitting the UNBRACKETED base keeps the
					// inserted rune away from the brackets entirely, isolating
					// this case from the bracket-residue check too.
					if mid := len(base) / 2; mid > 0 && mid < len(base) {
						corpus = append(corpus, base[:mid]+w+base[mid:])
					}
				}
			}
		}
	}

	// D72 ROUND 4 (axis 5): the 25 runes whose lowercase form has a
	// different UTF-8 byte length than the rune itself (computed by
	// iterating every code point and comparing len(string(r)) against
	// len(string(unicode.ToLower(r)))). 'İ' (U+0130, folds to "i") is the
	// only one whose lowercase form is itself a character "sip:"/"sips:"
	// contains — the round's live bypass — but the other 24 are swept too
	// per the round's mandatory instruction, so a FUTURE change widening
	// validateToURI's or Normalise's scheme match no longer depends on this
	// one rune to trip the invariant. Substituted at every rune position of
	// both scheme tokens, combined with every host: neither the hand-picked
	// schemes list (which has no length-changing runes) nor the Unicode
	// whitespace sweep (padding, not substitution) could ever reach this.
	lengthChangingLowerRunes := []rune{
		0x0130, 0x023A, 0x023E, 0x1E9E, 0x2126, 0x212A, 0x212B, 0x2C62, 0x2C64,
		0x2C6D, 0x2C6E, 0x2C6F, 0x2C70, 0x2C7E, 0x2C7F, 0xA78D, 0xA7AA, 0xA7AB,
		0xA7AC, 0xA7AD, 0xA7AE, 0xA7B0, 0xA7B1, 0xA7B2, 0xA7C5,
	}
	for _, tok := range []string{"sip:", "sips:"} {
		for _, host := range hosts {
			for pos := 0; pos < len(tok); pos++ {
				for _, r := range lengthChangingLowerRunes {
					mangled := tok[:pos] + string(r) + tok[pos+1:]
					corpus = append(corpus, mangled+host)
				}
			}
		}
	}

	failures := 0
	for _, raw := range corpus {
		err := validateToURI(raw)
		if err != nil {
			continue // rejected: the invariant has nothing to check
		}
		norm := policy.Normalise(raw)
		if problems := canonicalFormProblems(norm); len(problems) > 0 {
			failures++
			if failures <= 20 { // cap output; the corpus can be large
				t.Errorf("validateToURI(%q) = nil (ACCEPTED), but policy.Normalise(%q) = %q "+
					"is not canonical: %s", raw, raw, norm, strings.Join(problems, "; "))
			}
		}
	}
	if failures > 20 {
		t.Errorf("... and %d more corpus entries failed the same invariant", failures-20)
	}
	t.Logf("corpus size: %d", len(corpus))
}

// TestValidateToURIProbeTable is the MANDATORY end-to-end-style proof table:
// every one of the seven live evasions from the round-2 bypass report is
// REJECTED, and every one of the eight §10.3-permitted forms is still
// ACCEPTED, at the validateToURI layer. TestCallDialClosesTheSipsSchemeBypass
// in toolservice_test.go carries the deny-only-policy, real-CallDial version
// of this same table (D72).
func TestValidateToURIProbeTable(t *testing.T) {
	evasions := []string{
		"<<sips:19005550123.example.net>>",
		" sips:19005550123.example.net",
		"< sips:19005550123.example.net>",
		"\u0085sips:19005550123.example.net",
		" sips:19005550123.example.net",
		"　sips:19005550123.example.net",
		" sips:19005550123.example.net",
		" <sips:19005550123.example.net>",
	}
	for _, raw := range evasions {
		t.Run(fmt.Sprintf("evasion %q", raw), func(t *testing.T) {
			if err := validateToURI(raw); err == nil {
				t.Fatalf("validateToURI(%q) = nil, want an error (round-2 evasion)", raw)
			}
		})
	}

	permitted := []string{
		"sip:lab.internal",
		"<sip:lab.internal>",
		"sip:alice@lab.internal:5060",
		"192.0.2.10:5060",
		"sip:sips@h",
		"sip:x@sips.example",
		"sip:[2001:db8::1]:5060",
		"SIP:lab.internal",
	}
	for _, raw := range permitted {
		t.Run(fmt.Sprintf("permitted %q", raw), func(t *testing.T) {
			if err := validateToURI(raw); err != nil {
				t.Fatalf("validateToURI(%q) = %v, want nil (must not over-reject)", raw, err)
			}
		})
	}
}

// ---- HIGH-1: validateHeaders, validateFromUser, validateRejectReason ------
//
// CallDialInput.Headers and CallDialInput.FromUser flow VERBATIM to the wire
// (session/toolservice.go -> sipua/call.go:249-250's
// `inv.AppendHeader(sip.NewHeader(k, v))`), and CallRejectInput.Reason lands
// straight in the SIP status line (sipua/call.go:669's
// sip.NewResponseFromRequest). sipgo v0.24.1's Request.Destination() prefers
// a Route header over the Request-URI (sip/request.go:191-200), matched by
// getHeader's LOWERCASED name (sip/headers.go:236-244), so an unvalidated
// "Route" or "rOuTe" header redirects an INVITE to a host neither to_uri nor
// policy.CheckDestination ever saw. These three functions are validateToURI's
// sibling checks at the SAME boundary (session, not sipua — Rule 18) and in
// its style: apierr.InvalidArgument, one rule closing a whole class rather
// than a deny-list of code points.

// TestValidateHeaders exercises the three LOCKED rules in order: name is a
// non-empty RFC 3261 token, value carries no control character, and the
// case-folded name is not on the fixed deny list or "proxy-"-prefixed.
func TestValidateHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		wantErr bool
	}{
		{"route header", map[string]string{"Route": "sip:evil@attacker.test"}, true},
		// Case-fold proof: sipgo's getHeader matches by LOWERCASED name, so a
		// case-sensitive deny list would let this straight through.
		{"route header case-folded", map[string]string{"rOuTe": "sip:evil@attacker.test"}, true},
		{"record-route", map[string]string{"Record-Route": "sip:evil@attacker.test"}, true},
		{"via", map[string]string{"Via": "SIP/2.0/UDP evil.example"}, true},
		{"from", map[string]string{"From": "sip:evil@attacker.test"}, true},
		{"to", map[string]string{"To": "sip:evil@attacker.test"}, true},
		{"contact", map[string]string{"Contact": "sip:evil@attacker.test"}, true},
		{"call-id", map[string]string{"Call-ID": "forged@evil"}, true},
		{"cseq", map[string]string{"CSeq": "1 INVITE"}, true},
		{"max-forwards", map[string]string{"Max-Forwards": "0"}, true},
		{"authorization", map[string]string{"Authorization": "Digest x"}, true},
		{"www-authenticate", map[string]string{"WWW-Authenticate": "Digest x"}, true},
		{"proxy-authorization prefix", map[string]string{"Proxy-Authorization": "Digest x"}, true},
		{"proxy-authenticate prefix", map[string]string{"Proxy-Authenticate": "Digest x"}, true},
		{"proxy-require prefix", map[string]string{"Proxy-Require": "sec-agree"}, true},
		{"proxy-route prefix, lowercase", map[string]string{"proxy-route": "sip:evil@attacker.test"}, true},
		{"crlf header injection in a value", map[string]string{
			"P-Asserted-Identity": "sip:a@b\r\nP-Asserted-Identity: sip:victim@bank",
		}, true},
		// Deny-list evasion by a name sipgo's own getHeader would never
		// match, closed by the token-shape rule regardless of the deny list.
		{"trailing space evades the literal deny list", map[string]string{"Route ": "x"}, true},
		{"colon evades the literal deny list", map[string]string{"Route:": "x"}, true},
		{"embedded space is not a token", map[string]string{"X Bad": "value"}, true},
		{"empty name", map[string]string{"": "value"}, true},
		// negative control (required): a legitimate header must not be
		// over-rejected.
		{"legitimate header", map[string]string{"X-Trace-Id": "abc-123"}, false},
		{"nil map", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHeaders(tc.headers)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateHeaders(%v) = nil, want an error", tc.headers)
				}
				assertCode(t, err, apierr.CodeInvalidArgument)
				return
			}
			if err != nil {
				t.Fatalf("validateHeaders(%v) = %v, want nil", tc.headers, err)
			}
		})
	}
}

// TestValidateHeadersNamesTheOffendingHeader pins rule 4: the error names
// the offending header.
func TestValidateHeadersNamesTheOffendingHeader(t *testing.T) {
	err := validateHeaders(map[string]string{"Route": "sip:evil@attacker.test"})
	if err == nil {
		t.Fatal("validateHeaders(Route) = nil, want an error")
	}
	if !strings.Contains(err.Error(), "Route") {
		t.Errorf("error = %q, want it to name the offending header (Route)", err.Error())
	}
}

// TestValidateFromUser: from_user renders verbatim at sipgo sip/uri.go:74.
func TestValidateFromUser(t *testing.T) {
	tests := []struct {
		name     string
		fromUser string
		wantErr  bool
	}{
		{"crlf", "alice\r\nX-Injected: yes", true},
		{"bare cr", "alice\r", true},
		{"bare lf", "alice\n", true},
		{"nul", "alice\x00", true},
		{"legitimate", "alice", false},
		{"empty (omitempty field)", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateFromUser(tc.fromUser)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateFromUser(%q) = nil, want an error", tc.fromUser)
				}
				assertCode(t, err, apierr.CodeInvalidArgument)
				return
			}
			if err != nil {
				t.Fatalf("validateFromUser(%q) = %v, want nil", tc.fromUser, err)
			}
		})
	}
}

// TestValidateRejectReason: call_reject's reason reaches
// sip.NewResponseFromRequest(inv, status, reason, nil), the SIP status line
// itself (sipua/call.go:669). call_hangup's reason is DELIBERATELY excluded
// (rule 5) and has no equivalent check — input.go's own comment on
// CallHangupInput already says "free text; NO value is rejected (§10.3)",
// and sipua.(*UA).Hangup's reason parameter is `_ string`, discarded.
func TestValidateRejectReason(t *testing.T) {
	tests := []struct {
		name    string
		reason  string
		wantErr bool
	}{
		{"crlf", "Busy\r\nX-Injected: yes", true},
		{"bare cr", "Busy\r", true},
		{"bare lf", "Busy\n", true},
		{"legitimate", "Busy Here", false},
		{"empty (omitempty field)", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRejectReason(tc.reason)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateRejectReason(%q) = nil, want an error", tc.reason)
				}
				assertCode(t, err, apierr.CodeInvalidArgument)
				return
			}
			if err != nil {
				t.Fatalf("validateRejectReason(%q) = %v, want nil", tc.reason, err)
			}
		})
	}
}
