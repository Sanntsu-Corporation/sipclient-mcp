package sip

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseUriIPv6Literal pins the B7 fork divergence in uriStateHost
// (Phase 4 M1). uriStateHost had no '['/']' awareness, so an IPv6 reference
// host (RFC 3261 19.1.1, e.g. sip:[::1]:5060) hit its first ':' at the
// literal's OWN colon rather than the host/port separator, mis-splitting
// Host="[" and handing uriStatePort the remainder ":1]:5060", which fails
// strconv.Atoi. Because ParseUri has no external seam (it runs inside the
// start-line parser before any header hook, see VENDOR.md), one malformed
// Contact/Request-URI/To/From with an IPv6 host previously killed the ENTIRE
// message parse, not just that one URI.
//
// Brackets are RETAINED in Uri.Host ("[::1]", not "::1"): StringWrite writes
// Host verbatim, so stripping them would make String() emit the invalid
// "sip:::1:5060", and HostPort() (Host + ":" + port) is consumed by
// net.SplitHostPort, which requires brackets around an IPv6 literal.
func TestParseUriIPv6Literal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		uriStr   string
		wantUser string
		wantHost string
		wantPort int
	}{
		{
			name:     "bracketed host with port",
			uriStr:   "sip:[::1]:5060",
			wantHost: "[::1]",
			wantPort: 5060,
		},
		{
			name:     "longer IPv6 literal with port",
			uriStr:   "sip:[2001:db8::1]:5060",
			wantHost: "[2001:db8::1]",
			wantPort: 5060,
		},
		{
			name:     "bracketed host, no port",
			uriStr:   "sip:[::1]",
			wantHost: "[::1]",
			wantPort: 0,
		},
		{
			name:     "bracketed host followed by uri-params",
			uriStr:   "sip:[::1];transport=tcp",
			wantHost: "[::1]",
			wantPort: 0,
		},
		{
			name:     "bracketed host followed by headers",
			uriStr:   "sip:[::1]?h=v",
			wantHost: "[::1]",
			wantPort: 0,
		},
		{
			name:     "userinfo plus bracketed host with port",
			uriStr:   "sip:alice@[::1]:5060",
			wantUser: "alice",
			wantHost: "[::1]",
			wantPort: 5060,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var uri Uri
			err := ParseUri(tc.uriStr, &uri)
			require.NoError(t, err, "ParseUri(%q)", tc.uriStr)

			assert.Equal(t, tc.wantUser, uri.User, "User")
			assert.Equal(t, tc.wantHost, uri.Host, "Host")
			assert.Equal(t, tc.wantPort, uri.Port, "Port")

			// Round-trip: String() must reproduce the exact input, which is
			// only possible if the brackets survived in Host.
			assert.Equal(t, tc.uriStr, uri.String(), "String() round-trip")
		})
	}
}

// TestParseUriIPv6LiteralFullMessage is the B7 full-message proof: the
// defect's actual blast radius is whole-message loss (a Contact with an
// IPv6 host aborted parsing of the entire response), not just a bad URI
// value, so this drives the real sip.NewParser().ParseSIP over a response
// whose Contact carries a bracketed IPv6 host.
func TestParseUriIPv6LiteralFullMessage(t *testing.T) {
	msg, err := NewParser().ParseSIP([]byte(strings.Join([]string{
		"SIP/2.0 200 OK",
		"Via: SIP/2.0/UDP 192.0.2.7:5060;branch=z9hG4bK.ipv6contact",
		"From: <sip:alice@example.com>;tag=1928301774",
		"To: <sip:alice@example.com>;tag=registrar",
		"Call-ID: ipv6-contact-test",
		"CSeq: 1 REGISTER",
		"Contact: <sip:[::1]:5060>",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")))
	require.NoError(t, err)

	headers := msg.GetHeaders("Contact")
	require.Len(t, headers, 1)

	contact, ok := headers[0].(*ContactHeader)
	require.True(t, ok)
	assert.Equal(t, "[::1]", contact.Address.Host)
	assert.Equal(t, 5060, contact.Address.Port)
}
