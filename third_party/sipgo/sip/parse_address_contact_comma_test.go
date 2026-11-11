package sip

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseContactHeaderCommaCombinedKeepsPerContactParams pins the P3 fork
// divergence in parseContactHeader.
//
// RFC 3261 §7.3.1 lets a registrar fold several same-name header rows into one
// comma-separated line, and Kamailio/OpenSIPS-class registrars build their
// REGISTER 200 OK that way. parseContactHeader split such a line into one
// ContactHeader per section with the correct ADDRESSES, but parsed the header
// PARAMS from the whole line, so every split header ended up carrying the LAST
// section's params. Downstream that is undetectable: once parsed, a
// comma-combined list and separate rows are indistinguishable.
//
// The two multi-contact cases are ordered mirror images on purpose: the
// ours-first case fails against a last-wins bug (the original defect), the
// ours-last case fails against a first-wins bug, so neither can be satisfied by
// a parser that just picks a fixed section's params.
func TestParseContactHeaderCommaCombinedKeepsPerContactParams(t *testing.T) {
	type contact struct {
		hostport string
		expires  string
	}

	for _, tc := range []struct {
		name  string
		value string
		want  []contact
	}{
		{
			name:  "ours first",
			value: "<sip:alice@192.0.2.7:5060>;expires=60, <sip:alice@10.0.0.9:5060>;expires=3600",
			want: []contact{
				{"192.0.2.7:5060", "60"},
				{"10.0.0.9:5060", "3600"},
			},
		},
		{
			name:  "ours last",
			value: "<sip:alice@10.0.0.9:5060>;expires=3600, <sip:alice@192.0.2.7:5060>;expires=60",
			want: []contact{
				{"10.0.0.9:5060", "3600"},
				{"192.0.2.7:5060", "60"},
			},
		},
		{
			// Control: the overwhelmingly common single-contact path, which
			// takes no comma branch at all and must be unchanged.
			name:  "single contact",
			value: "<sip:alice@192.0.2.7:5060>;expires=60",
			want: []contact{
				{"192.0.2.7:5060", "60"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := NewParser().ParseSIP([]byte(strings.Join([]string{
				"SIP/2.0 200 OK",
				"Via: SIP/2.0/UDP 192.0.2.7:5060;branch=z9hG4bK.commacombined",
				"From: <sip:alice@example.com>;tag=1928301774",
				"To: <sip:alice@example.com>;tag=registrar",
				"Call-ID: comma-combined-contacts",
				"CSeq: 1 REGISTER",
				"Contact: " + tc.value,
				"Content-Length: 0",
				"",
				"",
			}, "\r\n")))
			require.NoError(t, err)

			headers := msg.GetHeaders("Contact")
			require.Len(t, headers, len(tc.want))

			for i, want := range tc.want {
				c, ok := headers[i].(*ContactHeader)
				require.True(t, ok)

				assert.Equal(t, want.hostport, c.Address.Host+":"+strconv.Itoa(c.Address.Port))

				got, ok := c.Params.Get("expires")
				require.True(t, ok, "contact %d has no expires parameter", i)
				assert.Equal(t, want.expires, got, "contact %d carries another contact's expires", i)
			}
		})
	}
}

// TestParseContactHeaderCommaCombinedDoesNotLeakForeignParams covers the wider
// blast radius of the same defect: it is not only `expires` that leaked. A
// section must carry ONLY its own params, so a param present on one contact and
// absent from the other must not appear on both.
func TestParseContactHeaderCommaCombinedDoesNotLeakForeignParams(t *testing.T) {
	msg, err := NewParser().ParseSIP([]byte(strings.Join([]string{
		"SIP/2.0 200 OK",
		"Via: SIP/2.0/UDP 192.0.2.7:5060;branch=z9hG4bK.commacombined",
		"From: <sip:alice@example.com>;tag=1928301774",
		"To: <sip:alice@example.com>;tag=registrar",
		"Call-ID: comma-combined-contacts",
		"CSeq: 1 REGISTER",
		`Contact: "A,B" <sip:alice@192.0.2.7:5060>;expires=60, <sip:alice@10.0.0.9:5060>;q=0.5;expires=3600`,
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")))
	require.NoError(t, err)

	headers := msg.GetHeaders("Contact")
	require.Len(t, headers, 2)

	first, ok := headers[0].(*ContactHeader)
	require.True(t, ok)
	// The quoted display name holds a comma - it must not split the line.
	assert.Equal(t, "A,B", first.DisplayName)
	assert.Equal(t, "192.0.2.7", first.Address.Host)
	if _, leaked := first.Params.Get("q"); leaked {
		t.Errorf("first contact carries the second contact's q parameter: %v", first.Params)
	}
	// The SWALLOW shape, which is the one VENDOR.md actually writes out and
	// which nothing pinned before (Cycle 4 / C4-A, item A7): a section's own
	// param corrupted with the rest of the line, `expires="60, <sip:...>"` on
	// parsed[0]. Every other assertion here and in the sibling test puts the
	// discriminating param on the LAST section, where a parser that simply runs
	// to end-of-line still lands on the right answer. This one reads a param on
	// a NON-LAST section, so it is the only assertion in the pair that can tell
	// "stopped at the comma" from "ran to the end of the line".
	expires, ok := first.Params.Get("expires")
	require.True(t, ok, "first contact lost its own expires parameter")
	assert.Equal(t, "60", expires,
		"first contact's own expires swallowed the rest of the line (VENDOR.md's documented failure shape)")

	second, ok := headers[1].(*ContactHeader)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.9", second.Address.Host)
	q, ok := second.Params.Get("q")
	require.True(t, ok)
	assert.Equal(t, "0.5", q)
}
