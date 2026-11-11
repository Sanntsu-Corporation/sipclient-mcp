package sipua

// Pure REFER/NOTIFY wire helpers for call transfer (spec 2026-09-26 §4.2-§4.3).
// Everything here is side-effect free; the *Locked readers take a *dialog whose
// invite/ok the caller has read under u.calls.mu (both are set once and never
// replaced after answer — D147/F1).

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// referTargetUnreserved is RFC 3261 §25.1's "unreserved" set (ALPHA / DIGIT /
// mark, where mark = "-_.!~*'()") — legal, un-escaped, in every SIP-URI
// component below.
const referTargetUnreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"

// referTargetUserExtra is (most of) RFC 3261 §25.1's user-unreserved:
// characters legal, un-escaped, in a URI's user part beyond
// referTargetUnreserved. '?' is DELIBERATELY OMITTED even though the RFC
// grammar allows it there (Rule 13 wave review, Cycle 6 Fix A, CF-004/005): the
// vendored parser's uriStateUser (third_party/sipgo/sip/parse_uri.go) scans
// forward to the first '@' before ever looking for '?', so
// "sip:x?Replaces=evil@host.example" is parsed with the ENTIRE
// "x?Replaces=evil" captured as User and Uri.Headers left empty — which
// defeats validReferTarget's own len(u.Headers)!=0 check below, CF-004's
// actual defense. A legitimate literal '?' can still be expressed
// percent-escaped ("%3F"; componentCharsValid already accepts a well-formed
// escape). ';' and '/' are left in this set: uri-parameters (introduced by
// ';') are already openly allowed (referTargetParamExtra, checked below), and
// only '?' can open a URI-headers part — validReferTarget's own
// len(u.Headers)!=0 check above already rejects that — so neither carries the
// same smuggling risk that motivated omitting '?'.
const referTargetUserExtra = "&=+$,;/"

// referTargetPasswordExtra is RFC 3261 §25.1's password production's own
// extra set (Cycle C round 4 fix) — narrower than user-unreserved: password
// omits ";", "?", "/", which only the user production allows.
const referTargetPasswordExtra = "&=+$,"

// referTargetParamExtra is RFC 3261 §25.1's param-unreserved: characters
// legal, un-escaped, in a uri-parameter's pname/pvalue beyond
// referTargetUnreserved.
const referTargetParamExtra = "[]/:&+$"

// referTargetHostChars restricts a host to RFC 3261's hostname/IPv4address
// grammar (ASCII letters, digits, '-', '.'). A bracketed IPv6 reference host
// never reaches this check: parseValidSIPURI (register.go) already rejects
// any Host starting with "[" outright, so this never has to admit
// '['/']'/':'.
const referTargetHostChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-."

// componentCharsValid reports whether every byte of s is in
// referTargetUnreserved, in extra, or part of a well-formed "%" HEXHEX escape
// (RFC 3261's "escaped" production). It is applied to a raw, UN-DECODED field
// already split out of a parsed sip.Uri — register.go/parse_uri.go's FSM
// parser never percent-decodes User/Password/Host or a UriParams key/value
// (parse_params.go's UnmarshalParams stores the raw substrings verbatim) — so
// a legitimate "%XX" escape is recognized here exactly as it appeared on the
// wire, and a malformed one ("%" not followed by two hex digits) is rejected
// here rather than silently passed through.
func componentCharsValid(s, extra string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' {
			if i+2 >= len(s) || !isHexDigit(s[i+1]) || !isHexDigit(s[i+2]) {
				return false
			}
			i += 2
			continue
		}
		if !strings.ContainsRune(referTargetUnreserved, rune(c)) && !strings.ContainsRune(extra, rune(c)) {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// hostCharsValid validates host against RFC 3261's hostname/IPv4address
// grammar (Cycle C round 4 fix — a character-set-only check let through
// hosts no hostname or IPv4 grammar actually admits): a hostname is a
// dot-separated sequence of labels, each non-empty, built only from
// referTargetHostChars, and not starting or ending with '-' (RFC 1035
// §2.3.1, referenced by RFC 3261 §25.1's hostname production). A host whose
// labels are ALL digits is instead validated as an IPv4 address via the
// standard library's net.ParseIP (Rule 16 reuse — its IPv4 parser already
// enforces exactly 4 octets, each 0-255, with no leading zeros; hand-rolling
// that grammar would duplicate a maintained stdlib parser). A bracketed IPv6
// reference host never reaches this check: parseValidSIPURI (register.go)
// already rejects any Host starting with "[" outright.
//
// CF-022: RFC 3261 §25.1's hostname production is `toplabel ["."]` — a
// single trailing dot on an FQDN is technically legal (it denotes an
// absolute name), so one is stripped before label-splitting below. A bare
// "." or a host ending in ".." (two or more trailing dots) still produces an
// empty label after stripping at most one, and is rejected by the same
// per-label emptiness check every other empty label hits below — no special
// case needed for either.
func hostCharsValid(host string) bool {
	if host == "" {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	labels := strings.Split(host, ".")
	allNumeric := true
	for _, label := range labels {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !strings.ContainsRune(referTargetHostChars, r) {
				return false
			}
			if r < '0' || r > '9' {
				allNumeric = false
			}
		}
	}
	if allNumeric {
		return net.ParseIP(host) != nil
	}
	return true
}

// validReferTarget accepts a blind-transfer target only if it is a sip:/sips:
// URI (Refer-To carries a URI, never a bare user@host) that parseValidSIPURI
// (register.go — Rule 16 reuse) accepts, whose User, Password, Host, and each
// uri-parameter name/value are each built entirely from THAT component's own
// RFC 3261 §25.1 character grammar — not one generic allowlist applied to the
// whole raw string, which the vendored parser's loose field-splitting would
// let slip past, and Host
// additionally passes hostname-label/IPv4 structural validation (Cycle C
// round 4 fix) — and that carries no URI headers of its own (a target with
// its own '?name=value' could otherwise smuggle header parameters into the
// REFER — CF-004). User and Password are checked against their OWN distinct
// grammars (Cycle C round 4 fix): RFC 3261 §25.1's password production is
// narrower than user-unreserved (it omits ";", "?", "/").
func validReferTarget(target string) bool {
	lt := strings.ToLower(target)
	if !strings.HasPrefix(lt, "sip:") && !strings.HasPrefix(lt, "sips:") {
		return false
	}
	u, ok := parseValidSIPURI(target)
	if !ok {
		return false
	}
	if len(u.Headers) != 0 {
		return false
	}
	if !componentCharsValid(u.User, referTargetUserExtra) || !componentCharsValid(u.Password, referTargetPasswordExtra) {
		return false
	}
	if !hostCharsValid(u.Host) {
		return false
	}
	for k, v := range u.UriParams {
		if !componentCharsValid(k, referTargetParamExtra) || !componentCharsValid(v, referTargetParamExtra) {
			return false
		}
	}
	return true
}

// buildReplacesReferTo renders an attended transfer's Refer-To header VALUE:
// targetURI with a Replaces URI header naming the dialog to replace, escaped
// exactly as RFC 3891 §7.1's worked example (url.QueryEscape turns '@', ';' and
// '=' into %40, %3B and %3D, uppercase hex). toTag is the replace-target UA's
// local tag, fromTag ours (RFC 3891 §3). The join is UNCONDITIONALLY '?'
// (Rule 13 wave review, Cycle 6 Fix A): validReferTarget rejects any target
// whose user part carries a raw '?' before targetURI ever reaches here (both
// callers — the blind-transfer target and consultReferToLocked's own
// peerTargetLocked — validate first), so targetURI can never already carry a
// URI header of its own by this point; the old '&'-choosing branch was dead
// for any input that actually passed validation, and wrong (a second '?' — or
// worse, a smuggled one — ahead of "Replaces=") for any input that had not.
func buildReplacesReferTo(targetURI, callID, toTag, fromTag string) string {
	replaces := url.QueryEscape(callID + ";to-tag=" + toTag + ";from-tag=" + fromTag)
	return "<" + targetURI + "?Replaces=" + replaces + ">"
}

// peerTagLocked is the PEER's local tag on d — the mirror of
// ourReInviteTagLocked. Outbound (we are UAC): the To-tag of the 200 we
// received. Inbound (we are UAS): the From-tag of the INVITE we received.
func peerTagLocked(d *dialog) string {
	switch d.direction {
	case session.Inbound:
		if d.invite == nil || d.invite.From() == nil {
			return ""
		}
		tag, _ := d.invite.From().Params.Get("tag")
		return tag
	default: // session.Outbound
		if d.ok == nil || d.ok.To() == nil {
			return ""
		}
		tag, _ := d.ok.To().Params.Get("tag")
		return tag
	}
}

// peerTargetLocked is the URI that reaches the PEER on d. Outbound: the 200's
// Contact, falling back to the INVITE's Request-URI — the same fallback sipgo's
// newByeRequestUAC uses (dialog_client.go), mirrored natively rather than
// called (locked decision 6). Inbound: the INVITE's Contact, falling back to its
// From address. The caller has already checked d.invite (and, outbound, d.ok)
// non-nil.
func peerTargetLocked(d *dialog) string {
	if d.remoteTarget != nil { // CF-184: where the peer now is
		return d.remoteTarget.String()
	}
	if d.direction == session.Inbound {
		if c := d.invite.Contact(); c != nil {
			u := c.Address
			return u.String()
		}
		u := d.invite.From().Address
		return u.String()
	}
	if c := d.ok.Contact(); c != nil {
		u := c.Address
		return u.String()
	}
	u := d.invite.Recipient
	return u.String()
}

// consultReferToLocked builds the attended transfer's Refer-To from the
// CONSULTATION dialog cd: its peer's URI plus Replaces naming cd itself. It only
// READS cd (spec §4.6). ok is false when cd has no confirmed dialog to replace
// (no 200 yet, or a missing tag), OR when the consult peer's own URI fails the
// same sanitization a directly-supplied blind-transfer target must pass
// (CF-005) — sipgo's Uri.String() re-serialization could in principle produce
// a URI carrying headers or characters validReferTarget would otherwise
// reject. Caller MUST hold u.calls.mu.
func consultReferToLocked(cd *dialog) (string, bool) {
	if cd.invite == nil || cd.ok == nil || cd.invite.From() == nil {
		return "", false
	}
	local, remote := ourReInviteTagLocked(cd), peerTagLocked(cd)
	if local == "" || remote == "" {
		return "", false
	}
	target := peerTargetLocked(cd)
	if !validReferTarget(target) {
		return "", false
	}
	return buildReplacesReferTo(target, cd.callID, remote, local), true
}

// parseReferEvent reads an Event header value. isRefer reports the "refer"
// package (RFC 3515 §2.4.4); id is its id parameter — the REFER's CSeq number —
// and hasID whether one was present. A MALFORMED id reports hasID=true with
// id=0, which can never equal a real REFER CSeq, so that NOTIFY is answered and
// ignored rather than mis-attributed (D6).
func parseReferEvent(v string) (isRefer bool, id uint32, hasID bool) {
	parts := strings.Split(v, ";")
	if !strings.EqualFold(strings.TrimSpace(parts[0]), "refer") {
		return false, 0, false
	}
	for _, p := range parts[1:] {
		k, val, found := strings.Cut(strings.TrimSpace(p), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(k), "id") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(val), 10, 32)
		if err != nil {
			return true, 0, true
		}
		return true, uint32(n), true
	}
	return true, 0, false
}

// parseSipfrag reads the status line of a message/sipfrag body (RFC 3420) —
// "SIP/2.0 200 OK" — which is all RFC 3515 §2.4.5 requires a refer NOTIFY to
// carry. ok is false for anything that is not a SIP/2.0 status line with a
// 100-699 code.
func parseSipfrag(body []byte) (code int, reason string, ok bool) {
	line, _, _ := strings.Cut(string(body), "\n")
	fields := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "SIP/2.0") {
		return 0, "", false
	}
	n, err := strconv.Atoi(fields[1])
	if err != nil || n < 100 || n > 699 {
		return 0, "", false
	}
	if len(fields) == 3 {
		reason = strings.TrimSpace(fields[2])
	}
	return n, reason, true
}
