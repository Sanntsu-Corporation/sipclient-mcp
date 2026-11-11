package sip

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// resolveAddrIP prefers an IPv4 address. Go's resolver can hand an IPv4
// address back in the 16-byte form (an IPv4-mapped AAAA answer, as here, or a
// line from the hosts file), which a length test does not recognise, so the
// first address, ::1, used to be picked and the send from an IPv4 socket
// failed. The zone has no A record, so every address arrives 16 bytes long.
func TestResolveAddrIPPrefersASixteenByteIPv4(t *testing.T) {
	r, _ := startFakeDNS(t, map[string][]string{
		"dual.example.test/AAAA": {"::1", "::ffff:127.0.0.9"},
	})
	ips, err := r.LookupIPAddr(context.Background(), "dual.example.test")
	require.NoError(t, err)
	require.Len(t, ips, 2)
	require.Equal(t, "::1", ips[0].IP.String(), "fixture premise: ::1 sorts first")
	require.Len(t, ips[1].IP, net.IPv6len, "fixture premise: the IPv4 address is 16 bytes")

	l := dnsTestLayer(t, r)
	var a Addr
	require.NoError(t, l.resolveAddrIP(context.Background(), "dual.example.test", &a))
	require.NotNil(t, a.IP.To4(), "picked %s, want the IPv4 address", a.IP)
	require.True(t, a.IP.Equal(net.ParseIP("127.0.0.9")), "picked %s, want 127.0.0.9", a.IP)
}
