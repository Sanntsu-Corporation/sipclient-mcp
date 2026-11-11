package sipua

import (
	"net/url"
	"testing"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// TestBuildReplacesReferToMatchesRFC3891Section7_1 asserts the RFC's own worked
// example byte for byte (spec §4.2 requires this exact string, not an
// eyeballed approximation):
//
//	Refer-To: <sip:dave@denver.example.org?Replaces=12345%40192.168118.3%3Bto-tag%3D12345%3Bfrom-tag%3D5FFE-3994>
func TestBuildReplacesReferToMatchesRFC3891Section7_1(t *testing.T) {
	got := buildReplacesReferTo("sip:dave@denver.example.org", "12345@192.168118.3", "12345", "5FFE-3994")
	want := "<sip:dave@denver.example.org?Replaces=12345%40192.168118.3%3Bto-tag%3D12345%3Bfrom-tag%3D5FFE-3994>"
	if got != want {
		t.Fatalf("Refer-To value\n got %s\nwant %s", got, want)
	}
}

// TestBuildReplacesReferToAlwaysJoinsWithAQuestionMark is Rule 13 wave review,
// Cycle 6 Fix A: buildReplacesReferTo's old '&'-vs-'?' branch is gone, because
// validReferTarget (refer.go) now guarantees a targetURI reaching here never
// already carries a URI header of its own (CF-004/005) — so the join is
// unconditional. This supersedes the old
// TestBuildReplacesReferToJoinsExistingURIHeadersWithAmpersand, which pinned
// the removed branch's behavior for an input shape validReferTarget rejects.
func TestBuildReplacesReferToAlwaysJoinsWithAQuestionMark(t *testing.T) {
	got := buildReplacesReferTo("sip:dave@example.org", "c", "a", "b")
	want := "<sip:dave@example.org?Replaces=c%3Bto-tag%3Da%3Bfrom-tag%3Db>"
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func testURI(user, host string) sip.Uri {
	return sip.Uri{Scheme: "sip", User: user, Host: host, Port: 5060}
}

// newTestInvite builds a minimal INVITE From fromURI (tagged fromTag) To toURI
// (untagged), with an optional Contact.
func newTestInvite(fromURI, toURI sip.Uri, fromTag, callID string, contact *sip.Uri) *sip.Request {
	inv := sip.NewRequest(sip.INVITE, toURI)
	from := &sip.FromHeader{Address: fromURI, Params: sip.NewParams()}
	from.Params.Add("tag", fromTag)
	inv.AppendHeader(from)
	inv.AppendHeader(&sip.ToHeader{Address: toURI, Params: sip.NewParams()})
	cid := sip.CallIDHeader(callID)
	inv.AppendHeader(&cid)
	inv.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})
	if contact != nil {
		inv.AppendHeader(&sip.ContactHeader{Address: *contact})
	}
	return inv
}

// TestConsultReferToIsDirectionAware pins D5. RFC 3891 §3: to-tag is the
// replace-target UA's local tag (the PEER's, from our side) and from-tag is
// ours — which live on DIFFERENT messages depending on who dialed.
func TestConsultReferToIsDirectionAware(t *testing.T) {
	alice, carol := testURI("alice", "10.0.0.1"), testURI("carol", "10.0.0.2")

	// OUTBOUND: we dialed carol. Our tag is on our INVITE's From; hers is on the
	// 200's To; her target is the 200's Contact.
	outInv := newTestInvite(alice, carol, "ourtag", "cid-out@10.0.0.1", nil)
	outOK := sip.NewResponseFromRequest(outInv, 200, "OK", nil)
	outOK.To().Params.Add("tag", "peertag")
	carolContact := testURI("carol", "10.0.0.9")
	outOK.AppendHeader(&sip.ContactHeader{Address: carolContact})
	out := &dialog{direction: session.Outbound, invite: outInv, ok: outOK, callID: "cid-out@10.0.0.1"}
	got, ok := consultReferToLocked(out)
	want := "<sip:carol@10.0.0.9:5060?Replaces=" +
		url.QueryEscape("cid-out@10.0.0.1;to-tag=peertag;from-tag=ourtag") + ">"
	if !ok || got != want {
		t.Fatalf("outbound: got (%q, %v) want %q", got, ok, want)
	}

	// OUTBOUND, no Contact on the 200: fall back to the INVITE's Request-URI
	// (newByeRequestUAC's fallback, mirrored natively — locked decision 6).
	outOK2 := sip.NewResponseFromRequest(outInv, 200, "OK", nil)
	outOK2.To().Params.Add("tag", "peertag")
	out2 := &dialog{direction: session.Outbound, invite: outInv, ok: outOK2, callID: "cid-out@10.0.0.1"}
	if got, _ := consultReferToLocked(out2); got != "<sip:carol@10.0.0.2:5060?Replaces="+
		url.QueryEscape("cid-out@10.0.0.1;to-tag=peertag;from-tag=ourtag")+">" {
		t.Fatalf("outbound fallback: got %q", got)
	}

	// INBOUND: dave dialed us. His tag is on his INVITE's From; ours is on the
	// 200 WE sent; his target is his INVITE's Contact.
	dave, daveContact := testURI("dave", "10.0.0.3"), testURI("dave", "10.0.0.33")
	inInv := newTestInvite(dave, alice, "peertag", "cid-in@10.0.0.3", &daveContact)
	inOK := sip.NewResponseFromRequest(inInv, 200, "OK", nil)
	inOK.To().Params.Add("tag", "ourtag")
	in := &dialog{direction: session.Inbound, invite: inInv, ok: inOK, callID: "cid-in@10.0.0.3"}
	got, ok = consultReferToLocked(in)
	want = "<sip:dave@10.0.0.33:5060?Replaces=" +
		url.QueryEscape("cid-in@10.0.0.3;to-tag=peertag;from-tag=ourtag") + ">"
	if !ok || got != want {
		t.Fatalf("inbound: got (%q, %v) want %q", got, ok, want)
	}

	// No confirmed dialog (no 200): nothing to replace.
	if _, ok := consultReferToLocked(&dialog{direction: session.Outbound, invite: outInv}); ok {
		t.Fatal("a dialog with no 200 OK produced a Replaces target")
	}
}

func TestValidReferTarget(t *testing.T) {
	for target, want := range map[string]bool{
		"sip:carol@example.com":           true,
		"sips:carol@example.com:5061":     true,
		"SIP:carol@example.com":           true,
		"carol@example.com":               false, // no scheme: Refer-To must be a URI
		"tel:+15551234":                   false,
		"sip:carol@example.com>;evil=1":   false, // breaks out of <...>
		"sip:<carol@example.com":          false,
		"sip:carol@example.com x":         false,
		"sip:carol@example.com\r\nX-Evil": false,
		"sip:\"carol\"@example.com":       false,
		"":                                false,
		// CF-003: an allowlist, not a blocklist, catches non-ASCII/control
		// characters the old blocklist never named.
		"sip:carol\x07@example.com": false,
		"sip:cárol@example.com":     false,
		// CF-004: a target carrying URI headers is rejected outright, not
		// just string-scanned for '?'/'&'.
		"sip:carol@example.com?Replaces=xyz":      false,
		"sip:carol@example.com?X-Evil=1&Y-Evil=2": false,
		// Regression: a URI PARAMETER (before any '?') is not a header and
		// must still be accepted.
		"sip:carol@example.com;transport=tcp": true,
		// CF-003 Cycle C fix: unusual-but-valid RFC 3986 characters, each in a
		// position RFC 3261 §25.1's grammar actually allows it — "+" and ","
		// are user-unreserved (valid in the user part), "'" is unreserved/mark
		// (valid in any component, here a uri-parameter value), and a
		// well-formed "%" HEXHEX escape is valid anywhere.
		"sip:+15551234@example.com":          true,
		"sip:carol,jr@example.com":           true,
		"sip:carol@example.com;isub=o'brien": true,
		"sip:john%20doe@example.com":         true,
		// CF-003 Cycle C fix: strings built solely from generic RFC 3986
		// delimiter/percent characters that the old single flat allowlist (and
		// the vendored parser's loose field-splitting) would have let through,
		// but that no SIP-URI component grammar actually admits.
		"sip:carol[oops@example.com": false, // "[" is not user-unreserved or unreserved
		"sip:carol@example.com#frag": false, // "#" is not part of any SIP-URI component grammar
		"sip:carol%2@example.com":    false, // malformed "%" escape (only one hex digit follows)
		"sip:carol%zz@example.com":   false, // malformed "%" escape ("zz" is not hex)
		// Cycle C round 4 fix (host structure): a character-set-only host check
		// let through hosts no hostname/IPv4 grammar actually admits.
		"sip:carol@-example.com":      false, // label starts with '-'
		"sip:carol@example-.com":      false, // label ends with '-'
		"sip:carol@example..com":      false, // empty label
		"sip:carol@.example.com":      false, // empty leading label
		"sip:carol@example.com.":      true,  // CF-022: a single trailing dot is a legal FQDN (RFC 3261 §25.1 toplabel ["."])
		"sip:carol@.":                 false, // bare "." strips to an empty host, still an empty label
		"sip:carol@example.com..":     false, // two trailing dots: still an empty label after stripping one
		"sip:carol@10.0.0.1":          true,  // valid IPv4, all-numeric labels
		"sip:carol@999.0.0.1":         false, // octet out of range — not a valid IPv4 address, and not a valid hostname either (all labels numeric)
		"sip:carol@1.2.3.4.5":         false, // 5 numeric labels: not a valid IPv4 address
		"sip:carol@a1-b2.example.com": true,  // hyphen in the MIDDLE of a label is fine
		// Cycle C round 4 fix (password's narrower grammar): ";" is legal,
		// un-escaped, in a user part (user-unreserved) but NOT in a password
		// part (RFC 3261 §25.1's password production omits ";", "?", "/").
		"sip:carol;ext=1@example.com": true,  // ";" in the USER part: fine
		"sip:carol:pw;x@example.com":  false, // ";" in the PASSWORD part: not fine
		// Rule 13 wave review, Cycle 6 Fix A (CF-004/005 bypass): the vendored
		// parser's uriStateUser scans forward to the first '@' before ever
		// looking for '?', so a raw '?' before '@' used to be captured whole
		// into User with Uri.Headers left empty — never tripping the
		// len(u.Headers)!=0 check just above. referTargetUserExtra no longer
		// allows a raw '?' in the user part, so this is rejected now.
		"sip:x?Replaces=evil@host.example": false,
		// The same literal, percent-escaped, is still a safe, well-formed user
		// part (componentCharsValid's existing "%" HEXHEX handling) — proving
		// the fix above rejects the raw byte, not the character's meaning.
		"sip:x%3FReplaces=evil@host.example": true,
	} {
		if got := validReferTarget(target); got != want {
			t.Errorf("validReferTarget(%q)=%v want %v", target, got, want)
		}
	}
}

// TestConsultReferToRejectsAConsultPeerURICarryingHeaders is CF-005: the
// attended-transfer consult-derived URI goes through the same sanitization as
// a directly-supplied blind-transfer target, even though it originates from a
// live, already-negotiated dialog rather than untrusted input.
func TestConsultReferToRejectsAConsultPeerURICarryingHeaders(t *testing.T) {
	alice := testURI("alice", "10.0.0.1")
	carolWithHeaders := sip.Uri{
		Scheme: "sip", User: "carol", Host: "10.0.0.9", Port: 5060,
		Headers: sip.HeaderParams{"X-Evil": "1"},
	}

	outInv := newTestInvite(alice, testURI("carol", "10.0.0.2"), "ourtag", "cid-hdr@10.0.0.1", nil)
	outOK := sip.NewResponseFromRequest(outInv, 200, "OK", nil)
	outOK.To().Params.Add("tag", "peertag")
	outOK.AppendHeader(&sip.ContactHeader{Address: carolWithHeaders})
	d := &dialog{direction: session.Outbound, invite: outInv, ok: outOK, callID: "cid-hdr@10.0.0.1"}

	if _, ok := consultReferToLocked(d); ok {
		t.Fatal("consultReferToLocked accepted a consult peer URI carrying URI headers (CF-005)")
	}
}

// TestConsultReferToRejectsAConsultPeerURIWithARawQuestionMarkInTheUser is
// Rule 13 wave review, Cycle 6 Fix A's CF-005 regression: a consult peer's own
// URI whose User carries a raw '?' (rather than a populated Uri.Headers) is
// the SAME bypass validReferTarget's user-part fix closes for a directly
// supplied blind-transfer target, reached here through the sip.Uri struct
// directly rather than through parseValidSIPURI's parse, since that is how a
// real sipgo.Uri.String()-then-reparse round trip could in principle produce
// one.
func TestConsultReferToRejectsAConsultPeerURIWithARawQuestionMarkInTheUser(t *testing.T) {
	alice := testURI("alice", "10.0.0.1")
	carolWithRawQuestionMark := sip.Uri{
		Scheme: "sip", User: "carol?Replaces=evil", Host: "10.0.0.9", Port: 5060,
	}

	outInv := newTestInvite(alice, testURI("carol", "10.0.0.2"), "ourtag", "cid-qmark@10.0.0.1", nil)
	outOK := sip.NewResponseFromRequest(outInv, 200, "OK", nil)
	outOK.To().Params.Add("tag", "peertag")
	outOK.AppendHeader(&sip.ContactHeader{Address: carolWithRawQuestionMark})
	d := &dialog{direction: session.Outbound, invite: outInv, ok: outOK, callID: "cid-qmark@10.0.0.1"}

	if _, ok := consultReferToLocked(d); ok {
		t.Fatal("consultReferToLocked accepted a consult peer URI whose user part carried a raw '?' (CF-005)")
	}
}

func TestParseReferEvent(t *testing.T) {
	for _, tc := range []struct {
		in             string
		isRefer, hasID bool
		id             uint32
	}{
		{"refer;id=93809824", true, true, 93809824},
		{"refer", true, false, 0},
		{" Refer ; ID = 7 ", true, true, 7},
		{"refer;id=abc", true, true, 0}, // malformed id never equals a real CSeq
		{"presence", false, false, 0},
		{"", false, false, 0},
	} {
		isRefer, id, hasID := parseReferEvent(tc.in)
		if isRefer != tc.isRefer || id != tc.id || hasID != tc.hasID {
			t.Errorf("parseReferEvent(%q)=(%v,%d,%v) want (%v,%d,%v)",
				tc.in, isRefer, id, hasID, tc.isRefer, tc.id, tc.hasID)
		}
	}
}

func TestParseSipfrag(t *testing.T) {
	for _, tc := range []struct {
		body   string
		code   int
		reason string
		ok     bool
	}{
		{"SIP/2.0 200 OK\r\n", 200, "OK", true},
		{"SIP/2.0 100 Trying", 100, "Trying", true},
		{"SIP/2.0 503 Service Unavailable\r\nContent-Length: 0\r\n", 503, "Service Unavailable", true},
		{"SIP/2.0 180", 180, "", true},
		{"garbage", 0, "", false},
		{"SIP/2.0 abc OK", 0, "", false},
		{"SIP/2.0 99 Low", 0, "", false},
		{"", 0, "", false},
	} {
		code, reason, ok := parseSipfrag([]byte(tc.body))
		if code != tc.code || reason != tc.reason || ok != tc.ok {
			t.Errorf("parseSipfrag(%q)=(%d,%q,%v) want (%d,%q,%v)",
				tc.body, code, reason, ok, tc.code, tc.reason, tc.ok)
		}
	}
}
