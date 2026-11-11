package session

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// ---- §10 tool inputs. ONE definition, used by both packages -----------------
// They live HERE, not in transport/mcp, so `mcp` registers tools against the
// same structs `session` validates and no import cycle arises (contract Part 3).

// UACreateInput is §10.2's parameter table.
//
// Phase 1 (session-scoped UA lifecycle, owner-locked decision): a UA's
// account is carried INLINE on the request, not looked up by a policy.yaml
// "profile" name. policy.Profile and its name-based lookup are deleted
// outright in this same wave (D1/D6) — there is no shared account registry
// left to name into. Credentials appearing here, and in the ua_create
// response's echo of this input where the transport logs it, is DELIBERATELY
// ACCEPTED for this local, single-dev-user tool (owner-locked decision); see
// ToolService.UACreate for the one place the plaintext is wrapped in
// policy.Secret before it goes any further.
type UACreateInput struct {
	Mode      string   `json:"mode"`
	Transport string   `json:"transport,omitempty"`
	LocalAddr string   `json:"local_addr,omitempty"`
	SRTP      string   `json:"srtp,omitempty"`
	CodecPref []string `json:"codec_pref,omitempty"`
	Keepalive string   `json:"keepalive,omitempty"`

	AOR       string `json:"aor,omitempty"`
	AuthUser  string `json:"auth_user,omitempty"`
	AuthPass  string `json:"auth_pass,omitempty"`
	Registrar string `json:"registrar,omitempty"`
	ExpiresS  int    `json:"expires_s,omitempty"`

	DTMFMode             string `json:"dtmf_mode,omitempty"`
	SessionExpiresS      int    `json:"session_expires_s,omitempty"`
	MinSES               int    `json:"min_se_s,omitempty"`
	KeepaliveIntervalS   int    `json:"keepalive_interval_s,omitempty"`
	SessionRefreshMethod string `json:"session_refresh_method,omitempty"`

	// AuthAnyHost lifts CF-046's destination guard: the UA answers an INVITE
	// digest challenge from any host, not only its registrar/AOR host.
	AuthAnyHost bool `json:"auth_any_host,omitempty"`

	// AllowCleartextSDES permits srtp other than "disabled" on a transport
	// that does not protect the SDP body (CF-134, RFC 4566 section 7): SDES
	// keys then travel in cleartext. Same per-UA trade-off model as
	// AuthAnyHost.
	AllowCleartextSDES bool `json:"allow_cleartext_sdes,omitempty"`
}

// SessionKeepaliveInput is session_keepalive's parameter table (Phase 1,
// D2/D7): no parameters — the session id itself comes from the transport's
// `sess` argument, exactly like every other tool. Named 1:1 after the
// session_keepalive tool, matching every other <Tool>Input in this file
// (UACreateInput for ua_create, CallDialInput for call_dial, ...); the
// revive "stutter" warning below is inherent to this tool's own name.
//
//nolint:revive // see comment above
type SessionKeepaliveInput struct{}

// ConfigGetInput is config_get's parameter table (Phase 2, admin-scoped): no
// parameters — it always returns the whole current policy.
//
//nolint:revive // see SessionKeepaliveInput's comment above
type ConfigGetInput struct{}

// ConfigSetInput is config_set's parameter table (Phase 2, admin-scoped): a
// single dotted policy key and its new value, applied through
// policy.Store.Mutate (§2.3a). Key is one of the names applyConfigKey
// (config.go) recognises; Value's Go type after JSON decode (float64,
// string, bool, or []any of string) must match what that key expects. An
// unrecognised key, a wrong-typed value, or a value validate() rejects all
// return invalid_argument and leave the state file untouched.
type ConfigSetInput struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

// AdminTokenRotateInput is admin_token_rotate's parameter table (Phase 2,
// admin-scoped, §2.2 item 5): no parameters — it always mints and installs
// a fresh admin token and returns it once.
type AdminTokenRotateInput struct{}

// UAStatusInput is §10.2's parameter table.
type UAStatusInput struct {
	UA string `json:"ua,omitempty"` // omitted = every UA in the session
}

// UADestroyInput is §10.2's parameter table.
type UADestroyInput struct {
	UA string `json:"ua"`
}

// CallDialInput is §10.3's parameter table.
type CallDialInput struct {
	UA           string            `json:"ua"`
	ToURI        string            `json:"to_uri"`
	FromUser     string            `json:"from_user,omitempty"`
	CodecPref    []string          `json:"codec_pref,omitempty"`
	SRTP         string            `json:"srtp,omitempty"`
	MediaPlan    []map[string]any  `json:"media_plan,omitempty"` // [P2] §10.7
	Capture      *CaptureInput     `json:"capture,omitempty"`    // [P2] D9b
	MaxDurationS int               `json:"max_duration_s,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
}

// CaptureInput is §10.3's [P2] capture sub-object (D9b).
type CaptureInput struct {
	Scope       string `json:"scope,omitempty"`
	PayloadMode string `json:"payload_mode,omitempty"`
}

// CallAnswerInput is §10.3's parameter table.
type CallAnswerInput struct {
	Call         string           `json:"call"`
	CodecPref    []string         `json:"codec_pref,omitempty"`
	SRTP         string           `json:"srtp,omitempty"`
	MediaPlan    []map[string]any `json:"media_plan,omitempty"` // [P2]
	Capture      *CaptureInput    `json:"capture,omitempty"`    // [P2]
	MaxDurationS int              `json:"max_duration_s,omitempty"`
}

// CallRejectInput is §10.3's parameter table.
type CallRejectInput struct {
	Call   string `json:"call"`
	Status int    `json:"status,omitempty"` // default 486; permitted 300-699 (U13)
	Reason string `json:"reason,omitempty"`
}

// CallHangupInput is §10.3's parameter table.
type CallHangupInput struct {
	Call   string `json:"call"`
	Reason string `json:"reason,omitempty"` // free text; NO value is rejected (§10.3)
}

// CallTransferInput is §10.14's parameter table (spec 2026-09-26 §4.1). The
// spec's (ua_id, dialog_id) pair is `call`, and consult_dialog_id is
// `consult_call`, matching every other per-call tool's handle convention.
type CallTransferInput struct {
	Call        string `json:"call" jsonschema:"The answered call to transfer (the transferee's dialog)."`
	Mode        string `json:"mode" jsonschema:"blind or attended."`
	Target      string `json:"target,omitempty" jsonschema:"Blind only: the sip: or sips: URI to transfer the call to."`
	ConsultCall string `json:"consult_call,omitempty" jsonschema:"Attended only: an answered call on the SAME UA whose dialog the transferee should replace."`
}

// CallStatusInput is §10.3's parameter table.
type CallStatusInput struct {
	Call string `json:"call"`
}

// CallListInput is §10.3's parameter table: no parameters.
type CallListInput struct{}

// CallWaitInput is §10.5's parameter table.
type CallWaitInput struct {
	Call      string `json:"call"`
	Until     string `json:"until"`
	TimeoutMs int    `json:"timeout_ms"`
	// Since is the last seq the caller already saw (from a prior call_wait or
	// call_events response); omitted or 0 preserves today's behavior of
	// matching from the start of the log. Mirrors CallEventsInput.Since (CF-015).
	Since int64 `json:"since,omitempty"`
}

// CallEventsInput is §10.5's parameter table.
type CallEventsInput struct {
	Call  string `json:"call"`
	Since int64  `json:"since,omitempty"`
}

// CallLadderInput is §10.11's parameter table.
type CallLadderInput struct {
	Call   string `json:"call"`
	Format string `json:"format,omitempty"` // text (default) | mermaid | json
}

// CaptureStartInput is §10.11's capture_start parameter table.
type CaptureStartInput struct {
	Call        string `json:"call"`
	Scope       string `json:"scope,omitempty"`        // signaling (default) | media | both
	PayloadMode string `json:"payload_mode,omitempty"` // plaintext (default) | ciphertext
}

// CaptureStopInput is §10.11's capture_stop parameter table.
type CaptureStopInput struct {
	Call string `json:"call"`
}

// MediaPlayInput is §10.9 media_play's request.
type MediaPlayInput struct {
	Call         string `json:"call"`
	Prompt       string `json:"prompt"`
	Repeat       int    `json:"repeat,omitempty"`
	WaitComplete *bool  `json:"wait_complete,omitempty"`
}

// MediaRecordStartInput is §10.9 media_record_start's request.
type MediaRecordStartInput struct {
	Call string `json:"call"`
	Name string `json:"name,omitempty"`
}

// MediaRecordStopInput is §10.9 media_record_stop's request.
type MediaRecordStopInput struct {
	Call string `json:"call"`
	Name string `json:"name,omitempty"`
}

// DTMFSendInput is §10.8 dtmf_send's request. mode omitted means the UA's
// profile default; duration_ms and gap_ms omitted mean DefaultDTMFDurationMs and
// DefaultDTMFGapMs (collaborators.go).
//
// GapMs IS A POINTER, AND THAT IS THE ONLY WAY THIS FIELD CAN BE CORRECT.
// `gap_ms: 0` is a legal request — send the digits back to back — so it must be
// distinguishable from an omitted gap_ms, which is what asks for the default. A
// plain int collapses the two into 0 and forces the handler to guess; guessing the
// default silently overrides an agent that explicitly asked for none. nil means
// absent, and DTMFSend forwards that to sipua as DTMFGapUnset, the negative
// sentinel ResolveDTMFTiming understands.
//
// DurationMs stays a plain int because 0 is NOT a legal tone length (sipua
// rejects it), so 0 unambiguously means "unset" there.
//
// THE THREE `jsonschema` TAGS ARE THE PUBLISHED SCHEMA'S ONLY RECORD OF
// checkDTMFSendBounds (toolservice.go). This struct IS dtmf_send's input schema —
// registerTool infers it by reflection — and the SDK's tag support carries a
// description and nothing else (no minimum/maximum), so the bounds are ADVERTISED
// here and ENFORCED there. They now name the OUTER bound directly: a fixed
// 300,000ms DTMF render ceiling (dtmfRenderCeilingMs, mediaplan_validate.go —
// P4-N01, Phase 4 W1 M2, decoupled it from max_call_duration_s so raising
// that key's default could not silently widen this OOM-prevention ceiling
// with it), which never changes at runtime. max_call_duration_s is still the
// TIGHTER bound whenever an operator configures it below the ceiling, and
// that one is deliberately NOT given a literal number here: SIGHUP can
// change it under a running daemon, and a literal baked into the schema
// would be a second, silently-drifting copy of it (Rule 18).
type DTMFSendInput struct {
	Call       string `json:"call"`
	Digits     string `json:"digits" jsonschema:"DTMF digits to send, from 0-9 A-D * #. Rejected with invalid_argument when len(digits) x (duration_ms + gap_ms) exceeds the 300000ms DTMF render ceiling, or the policy's max_call_duration_s when configured below it."`
	Mode       string `json:"mode,omitempty"`
	DurationMs int    `json:"duration_ms,omitempty" jsonschema:"Per-digit tone length in ms; omit for the default of 100. A negative value is rejected with invalid_argument, never defaulted, and the value is bounded by the RFC 4733 wire-safe maximum, the 300000ms DTMF render ceiling, and the policy's max_call_duration_s when configured below it."`
	GapMs      *int   `json:"gap_ms,omitempty" jsonschema:"Inter-digit gap in ms; omit for the default of 50, or pass 0 for no gap. A negative value is rejected with invalid_argument, never defaulted, and the value is bounded by the 300000ms DTMF render ceiling, and the policy's max_call_duration_s when configured below it."`
}

// DTMFReceivedInput is §10.8 dtmf_received's request. since is the seq cursor
// from a previous call's next_since; 0 (the default) means "everything".
type DTMFReceivedInput struct {
	Call  string `json:"call"`
	Since int64  `json:"since,omitempty"`
}

// validateToURI is D72's user-approved decision: to_uri accepts ONLY §10.3's
// enumerated forms — sip:user@host, sip:user@host:port, or a bare host:port —
// and REJECTS "sips:" in any case-fold: §10.3 enumerates only sip: forms and
// destination deny patterns are written against "sip:", so a sips: URI would
// slip past one anchored on it (D-E2). A TLS UA dials a sip: target over TLS
// (transport=tls); sipua.Dial itself honours a sips: target over TLS for its
// other callers. Called from CallDial BEFORE CheckDestination, which is the
// wave's only call site.
//
// THE ORDER MATTERS FOR THE FIRST CHECK. Control characters and CRLF are
// checked FIRST: an unvalidated to_uri carrying a bare CRLF is a SIP
// header-injection vector — proved live against
// "sip:x@lab.internal\r\nINVITE sip:evil@a.b SIP/2.0" — and is the
// highest-value check this function makes.
//
// THE SCHEME BYPASS THIS CLOSES IS OBSERVABLE ONLY UNDER A DENY-ONLY POLICY.
// policy.CheckDestination permits every destination whenever no allow list is
// configured (len(p.allowRE) == 0), so policy.Defaults() — which ships
// neither list — cannot exercise this function's reason for existing at all;
// it is tested against a deny-only fixture (input_test.go,
// toolservice_test.go).
//
// WHITESPACE IS CHECKED RUNE-WISE WITH unicode.IsSpace, NOT byte-wise against
// " \t": strings.TrimSpace — what policy.Normalise (destination.go) uses to
// peel the envelope off a to_uri before CheckDestination ever sees it — also
// trims by unicode.IsSpace, which accepts NBSP (U+00A0), NEL (U+0085), the
// various Unicode space separators (U+2000-U+200A, U+2028/29, U+3000) and
// ogham space mark (U+1680). Every one of those encodes to UTF-8 bytes ALL
// >= 0x20, so a byte-oriented check (or an ASCII-only " \t" check) misses
// them entirely: a leading NBSP before "sips:" is invisible to a prefix
// check here, Normalise then trims it away by the same unicode.IsSpace rule
// and reveals the scheme, and a "^sip:"-anchored deny pattern never sees it.
// Matching Normalise's rune-wise definition of whitespace, instead of trying
// to enumerate which of the ~25 Unicode space code points to also reject, is
// what closes the WHOLE CLASS rather than one code point at a time.
func validateToURI(raw string) error {
	if hasControlByte(raw) {
		return apierr.InvalidArgument(
			"to_uri contains a control character; CRLF and other control " +
				"bytes are not accepted in a dial destination")
	}
	for _, r := range raw {
		if unicode.IsSpace(r) {
			return apierr.InvalidArgument(
				"to_uri contains whitespace (including non-ASCII Unicode space " +
					"characters, which policy.Normalise's TrimSpace would silently " +
					"strip before scheme detection)")
		}
	}
	if strings.Count(raw, "@") > 1 {
		return apierr.InvalidArgument(`to_uri contains more than one "@"`)
	}

	// D72 ROUND 3: reject ';' or '?' ANYWHERE in raw. This closes the axis by
	// EXCLUSION, not by re-modelling policy.Normalise's own ';'/'?'
	// truncation (destination.go) — re-modelling that truncation has now
	// failed three times this wave and is not attempted a fourth time here.
	// None of §10.3's three enumerated forms — sip:user@host,
	// sip:user@host:port, or a bare host:port — carries a ';' or '?' in any
	// of its parts, so rejecting both characters outright costs no
	// legitimate destination. This does NOT mean validateToURI and
	// Normalise now agree on ';'/'?' handling in general — they do not, and
	// no claim to that effect should be inferred from this check. It means
	// only that a to_uri containing either character never reaches
	// Normalise at all, so whatever Normalise does with it is moot here.
	// policy.Normalise and policy.TrimBrackets are UNCHANGED this round:
	// Normalise is Task 6's, mutation-proven, and shared by
	// CheckDestination; TrimBrackets was proven behaviour-preserving over
	// 1,599,360 inputs last round.
	if strings.ContainsAny(raw, ";?") {
		return apierr.InvalidArgument(
			`to_uri contains ";" or "?", which §10.3 permits in none of its ` +
				`enumerated forms (sip:user@host, sip:user@host:port, or a bare ` +
				`host:port)`)
	}

	// Peel the envelope with policy.TrimBrackets — the EXACT trim
	// policy.Normalise applies to the same raw string before detecting its
	// scheme (destination.go). Sharing the function instead of duplicating
	// its two operations is what stops this check and Normalise's own
	// envelope trim from ever diverging again (this is the third divergence
	// of this shape in the wave). raw is already known whitespace-free by
	// the check above, so here TrimBrackets only strips at most one leading
	// '<' and one trailing '>'.
	s := policy.TrimBrackets(raw)
	if s == "" {
		return apierr.InvalidArgument("to_uri is empty")
	}
	// A '<' or '>' surviving a SINGLE bracket strip means the input was
	// nested ("<<sips:host>>") or otherwise not itself well-formed name-addr
	// syntax. Normalise's own single TrimPrefix/TrimSuffix would leave the
	// inner brackets in the string it returns, and CheckDestination would
	// then match against "sip:<sips:host>" — which starts with "sip:" and so
	// slips past a "^sip:"-anchored deny pattern while a literal "sips:"
	// scheme sits right behind the visible one. Rather than guess how many
	// layers to peel (there is no bound), reject outright.
	if strings.ContainsAny(s, "<>") {
		return apierr.InvalidArgument(
			"to_uri contains unbalanced or nested angle brackets")
	}

	// D72 ROUND 4 (axis 5): reject any rune whose lowercase form has a
	// DIFFERENT UTF-8 byte length than the rune itself — e.g. 'İ' (U+0130)
	// ToLower's to 'i', collapsing 2 bytes to 1. 'İ' is the only one of the
	// 25 such runes whose lowercase form is itself a character "sip:"
	// contains, so "sİp:host" makes `lower := strings.ToLower(s)` below
	// equal "sip:host" and HasPrefix(lower, "sip:") match — but slicing s
	// (not lower) at byte offset len("sip:") then lands ONE BYTE SHORT of
	// where the scheme actually ends in s, landing on the ':' instead of
	// past it. Proved live for "sİp:19005550123@example.net": accepted here,
	// then policy.Normalise — which detects the scheme with
	// strings.EqualFold and a rune count that "sİp:" fails — takes the
	// no-scheme branch and PREPENDS its own "sip:", producing the doubled
	// scheme "sip:sİp:19005550123@example.net".
	//
	// This is a PER-RUNE check, not a check of the whole string's aggregate
	// ToLower length: two of the 25 runes (U+023A, U+023E) GROW under
	// ToLower rather than shrink, so pairing one of those with 'İ' anywhere
	// else in the same string can leave the WHOLE STRING's post-ToLower
	// byte length unchanged even though 'İ' still misaligns wherever IT
	// sits. Checking each rune's own length individually has no such
	// cancellation.
	for _, r := range s {
		if len(string(r)) != len(string(unicode.ToLower(r))) {
			return apierr.InvalidArgument(
				`to_uri contains a character whose lowercase form has a ` +
					`different UTF-8 byte length (for example "İ", U+0130), ` +
					`which can misalign a case-insensitive scheme check ` +
					`against a byte-offset slice of the same string`)
		}
	}

	lower := strings.ToLower(s)
	rest := s
	switch {
	case strings.HasPrefix(lower, "sips:"):
		return apierr.InvalidArgument(
			`to_uri scheme "sips:" is not accepted; §10.3 permits sip:user@host, ` +
				`sip:user@host:port or a bare host:port; a TLS ua dials a sip: target over TLS`)
	case strings.HasPrefix(lower, "sip:"):
		rest = s[len("sip:"):]
		if rest == "" {
			return apierr.InvalidArgument(`to_uri has a "sip:" scheme but no host`)
		}
	default:
		// The bare host:port form (§10.3) has no scheme and no user part.
		if strings.Contains(rest, "@") {
			return apierr.InvalidArgument(
				`to_uri has no "sip:" scheme but contains "@"; §10.3 accepts ` +
					`sip:user@host[:port] or a bare host:port, not a mix of the two`)
		}
	}

	host := rest
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		host = rest[at+1:]
	}
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if strings.Contains(host, "%") {
		return apierr.InvalidArgument("to_uri's host contains percent-encoding, which is not accepted")
	}
	return nil
}

// hasControlByte is validateToURI's own first check (above), EXTRACTED so
// validateHeaders, validateFromUser and validateRejectReason below can share
// its byte-wise definition of "control character" instead of three more
// inline copies of the same loop (Rule 16). It returns only a bool:
// validateToURI still builds its own error message from the result, so this
// extraction changes NEITHER that message NOR its behaviour — it moves the
// loop, nothing else.
func hasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// isHeaderToken reports whether name is a non-empty RFC 3261 `token`: ALPHA /
// DIGIT / one of "-.!%*_+`'~". This is the CLASS-CLOSING form for a header
// NAME and it subsumes the control-character check for names on its own —
// every byte < 0x20 or == 0x7f fails every one of the switches below. It also
// closes deny-list evasion by a name sipgo's own getHeader would never match
// but a downstream parser might: "Route " (trailing space) or "Route:" are
// not tokens and are rejected here regardless of validateHeaders' deny list.
func isHeaderToken(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
			continue
		}
		switch b {
		case '-', '.', '!', '%', '*', '_', '+', '`', '\'', '~':
			continue
		}
		return false
	}
	return true
}

// deniedHeaderNames is CallDialInput.Headers' fixed deny list (LOCKED),
// keyed lowercase — see validateHeaders for why the fold is load-bearing.
// There is no SIP header that sets the Request-URI (it is a request-line
// field, not a header); "route" is the header that OVERRIDES it as sipgo's
// resolved next hop and is the one that matters on that axis. The rest close
// the same class of forgery one level down: dialog identity (from, to,
// call-id, cseq), routing (record-route, via, max-forwards) and challenge
// headers (authorization, www-authenticate) an agent has no business
// setting by hand. Proxy-* is denied separately, by PREFIX, in
// validateHeaders — a prefix rule closes that whole class instead of
// enumerating Proxy-Authorization / Proxy-Authenticate / Proxy-Require /
// Proxy-Route one at a time.
var deniedHeaderNames = map[string]bool{
	"route":            true,
	"record-route":     true,
	"via":              true,
	"from":             true,
	"to":               true,
	"contact":          true,
	"call-id":          true,
	"cseq":             true,
	"max-forwards":     true,
	"authorization":    true,
	"www-authenticate": true,
}

// validateHeaders is CallDialInput.Headers' half of this file's "close the
// whole class, not one code point at a time" doctrine (see validateToURI
// above). Headers flows VERBATIM onto the wire — sipua/call.go's Dial does
// `inv.AppendHeader(sip.NewHeader(k, v))` for every entry, with no validation
// of its own (Rule 18: sipua is not this boundary; session is, same as
// validateToURI) — so an agent-supplied header name or value is otherwise
// indistinguishable from one this process minted itself.
//
// sipgo v0.24.1's Request.Destination() prefers a Route header over the
// Request-URI (sip/request.go:191-200), and getHeader matches by
// LOWERCASED name across any header type (sip/headers.go:236-244) — so a
// generic header appended with the name "Route" or "rOuTe" is honoured as
// the real next hop either way, redirecting the INVITE to a host neither
// to_uri nor policy.CheckDestination ever evaluated. CRLF in a header VALUE
// additionally serialises into two headers (P-Asserted-Identity forgery,
// caller-ID spoofing).
//
// THREE RULES, IN THIS ORDER, EACH CLOSING A WHOLE CLASS:
//  1. The name is a non-empty RFC 3261 token (isHeaderToken).
//  2. The value carries no control character — byte-wise, sharing
//     validateToURI's own definition via hasControlByte. This is the CRLF
//     check.
//  3. The name, CASE-FOLDED, is not in deniedHeaderNames and does not start
//     with "proxy-". Case-folding is LOAD-BEARING for the reason above: a
//     case-sensitive deny list does not close the "rOuTe" bypass at all.
func validateHeaders(headers map[string]string) error {
	for name, value := range headers {
		if !isHeaderToken(name) {
			return apierr.InvalidArgument(fmt.Sprintf(
				"header %q is not a valid header name; a name may contain only "+
					"letters, digits and \"-.!%%*_+`'~\"", name))
		}
		if hasControlByte(value) {
			return apierr.InvalidArgument(fmt.Sprintf(
				"header %q value contains a control character; CRLF and other "+
					"control bytes are not accepted in a header value", name))
		}
		lower := strings.ToLower(name)
		if deniedHeaderNames[lower] || strings.HasPrefix(lower, "proxy-") {
			return apierr.InvalidArgument(fmt.Sprintf(
				"header %q is a routing or identity header and is not accepted "+
					"from an agent-supplied headers map", name))
		}
	}
	return nil
}

// validateFromUser is CallDialInput.FromUser's half of the same doctrine:
// FromUser flows into sipua's engine config and renders verbatim at sipgo
// sip/uri.go:74, so a bare CRLF here is the SAME header-injection vector
// validateToURI's own first check exists to close, reached through a
// different field. Only a control-character check — from_user carries no
// scheme, no host and no other structure to validate.
func validateFromUser(fromUser string) error {
	if hasControlByte(fromUser) {
		return apierr.InvalidArgument(
			"from_user contains a control character; CRLF and other control " +
				"bytes are not accepted")
	}
	return nil
}

// validateRejectReason is CallRejectInput.Reason's half: sipua.(*UA).Reject
// (call.go) passes reason straight into
// sip.NewResponseFromRequest(inv, status, reason, nil) — the SIP STATUS LINE
// itself — so a CRLF here forges response lines wholesale. This is
// call_reject's reason ONLY. call_hangup's reason is DELIBERATELY
// UNVALIDATED (see CallHangupInput above: "free text; NO value is rejected
// (§10.3)") — sipua.(*UA).Hangup's reason parameter is `_ string`, discarded,
// and never reaches the wire, so there is no injection surface there to
// close.
func validateRejectReason(reason string) error {
	if hasControlByte(reason) {
		return apierr.InvalidArgument(
			"reason contains a control character; CRLF and other control " +
				"bytes are not accepted in a reject status line")
	}
	return nil
}
