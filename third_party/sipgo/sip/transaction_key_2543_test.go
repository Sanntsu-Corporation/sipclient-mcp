package sip

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// CF-077 (Cycle C B1): the RFC 2543 server-transaction key must not vary with
// HeaderParams map order, nor with the transport layer's own received/rport
// annotations.
func TestServerTxKeyFor2543ViaIsStableAfterTheStamp(t *testing.T) {
	const via2543 = "SIP/2.0/UDP 127.0.0.2:5099;rport;ttl=16;maddr=224.0.1.1"
	keyFor := func(via, source string) string {
		req := parseInviteWithVia(t, via, "")
		req.SetSource(source)
		stampReceived(req)
		key, err := MakeServerTxKey(req)
		require.NoError(t, err)
		return key
	}
	first := keyFor(via2543, "127.0.0.1:40000")
	for i := 0; i < 200; i++ {
		require.Equal(t, first, keyFor(via2543, "127.0.0.1:40000"), "run %d", i)
	}
	require.Equal(t, first, keyFor(via2543, "127.0.0.1:40001"), "the annotations are not part of the key")

	// An RFC 3261 key is byte-identical with and without the stamp.
	const via3261 = "SIP/2.0/UDP localhost:5099;rport;branch=z9hG4bKabc"
	plain := parseInviteWithVia(t, via3261, "")
	want, err := MakeServerTxKey(plain)
	require.NoError(t, err)
	require.Equal(t, want, keyFor(via3261, "127.0.0.1:40000"))
}
