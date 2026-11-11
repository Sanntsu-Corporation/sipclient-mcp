package policy

import (
	"fmt"
	"strings"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// RuleAllowListDefault names the rule reported when an allow list is
// configured and a destination matched none of its patterns. The deny-by-
// default posture is not attributable to any single pattern, so the policy
// KEY is named instead.
const RuleAllowListDefault = "destinations.allow"

// TrimBrackets performs the exact leading/trailing envelope trim Normalise
// applies before scheme detection: Unicode-whitespace trim (TrimSpace uses
// unicode.IsSpace, not just ASCII " \t"), one leading '<', one trailing '>',
// then Unicode-whitespace trim again (a name-addr's brackets can themselves
// be padded: "< sip:x@lab.internal >").
//
// Exported so a caller that must validate raw to_uri input BEFORE Normalise
// ever runs (internal/session's validateToURI, D72) can match Normalise's
// notion of "canonical envelope" exactly rather than reimplementing it with
// its own — inevitably diverging — whitespace or bracket rule. This is the
// ONLY piece of Normalise pulled out; the scheme/case-folding logic below is
// unchanged and still lives here alone.
func TrimBrackets(rawURI string) string {
	s := strings.TrimSpace(rawURI)
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return strings.TrimSpace(s)
}

// Normalise reduces a dial destination to the single form the destinations
// patterns are evaluated against.
//
// Every transformation here closes a bypass rather than tidying input:
//   - a missing scheme is filled in, so a bare "host:port" (which §10.3
//     permits for IP-to-IP) cannot skip a '^sip:'-anchored pattern;
//   - scheme and host are case-folded, so 'SIP:x@LAB.internal' cannot skip a
//     lowercase pattern (the user part is NOT folded: SIP user parts are
//     case-sensitive and folding one would make two distinct AORs match one
//     rule);
//   - URI parameters and headers are stripped at the first ';' or '?': RFC
//     3261 puts the host before any parameter or header, so a well-formed
//     user part escapes a literal ';' or '?', and one appearing unescaped
//     before the '@' means the input is malformed. Truncating there would
//     discard the host and let it evade a '$'-anchored deny pattern, so in
//     that one case — and only that case — the string is left whole
//     instead, failing closed;
//   - a trailing dot on the host is stripped (CF-211), so 'denied.example.'
//     cannot skip a '$'-anchored deny pattern for 'denied.example'.
func Normalise(rawURI string) string {
	s := TrimBrackets(rawURI)
	if s == "" {
		return ""
	}

	// Strip at the first ';' or '?', unless doing so would discard an '@'
	// that the untruncated string has but the truncated part doesn't — that
	// means the ';'/'?' fell inside the user part, which is malformed input.
	if i := strings.IndexAny(s, ";?"); i >= 0 {
		if strings.Contains(s[:i], "@") || !strings.Contains(s, "@") {
			s = s[:i]
		}
	}

	scheme, rest := "", s
	switch {
	case len(s) >= 5 && strings.EqualFold(s[:5], "sips:"):
		scheme, rest = "sips:", s[5:]
	case len(s) >= 4 && strings.EqualFold(s[:4], "sip:"):
		scheme, rest = "sip:", s[4:]
	default:
		scheme = "sip:"
	}

	// Fold the host, preserve the user part.
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[:at+1] + trimHostDot(strings.ToLower(rest[at+1:]))
	} else {
		rest = trimHostDot(strings.ToLower(rest))
	}
	return scheme + rest
}

// trimHostDot strips the trailing dot(s) of a host name, before any port: DNS
// resolves "denied.example." to the same host as "denied.example", so leaving
// the dot would let it evade a '$'-anchored deny pattern (CF-211). An IPv6
// literal ("[...]") has no host name to trim.
func trimHostDot(hostport string) string {
	if strings.HasPrefix(hostport, "[") {
		return hostport
	}
	host, port := hostport, ""
	if i := strings.LastIndex(hostport, ":"); i >= 0 {
		host, port = hostport[:i], hostport[i:]
	}
	return strings.TrimRight(host, ".") + port
}

// CheckDestination evaluates a dial destination against the ordered
// allow/deny lists of §12.2, on the NORMALISED URI, and RETURNS that
// normalised URI as dialURI.
//
// dialURI IS THE STRING THE CALLER MUST DIAL (Task 11d, D85, spec:1330's
// ValidateWebhook shape): policy.Normalise's output is what CheckDestination
// evaluated, so a caller that dials anything else — in particular the raw
// input this function received — reopens the divergence class Task 11b
// closed five separate times, one evasion axis at a time. Returning the
// evaluated string makes it structurally impossible for the evaluated and
// dialled strings to differ, the same way spec:1340 describes for the
// sibling webhook control: "the resolution and the class check that
// produced the verdict also produce the address the connection uses, so
// there is no window between deciding and connecting."
//
// The order is: deny first, then allow. Deny wins — a destination matching
// both lists is refused — and when an allow list is non-empty the posture is
// DENY BY DEFAULT: a destination matching no allow pattern is refused, and
// the refusal names destinations.allow.
//
// rule is returned on BOTH paths so a caller can log which pattern decided a
// permitted dial as well as a refused one, and so the §11.2 denied shape's
// "rule" field is built from a value this function produced rather than one
// the caller reconstructed.
//
// apierr.Denied (not DeniedLimit) is correct here: a destination refusal has
// no numeric bound. DeniedLimit is for the §12.2.2 concurrency caps, where
// rule, limit and current must travel together.
func (p *Policy) CheckDestination(rawURI string) (dialURI string, rule string, err error) {
	uri := Normalise(rawURI)

	for i, re := range p.denyRE {
		if re.MatchString(uri) {
			pat := p.Destinations.Deny[i]
			return uri, pat, apierr.Denied(pat, fmt.Sprintf(
				"destination %s matched policy deny rule %s", uri, pat))
		}
	}

	if len(p.allowRE) == 0 {
		return uri, "", nil
	}

	for i, re := range p.allowRE {
		if re.MatchString(uri) {
			return uri, p.Destinations.Allow[i], nil
		}
	}

	return uri, RuleAllowListDefault, apierr.Denied(RuleAllowListDefault, fmt.Sprintf(
		"destination %s matched no pattern in destinations.allow (deny-by-default)", uri))
}
