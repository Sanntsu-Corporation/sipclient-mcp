package sip

import (
	"net"
	"testing"
)

// TestB2LocalPortIsEphemeral asserts the B2 divergence: an outbound dial's
// local address keeps the Via-derived IP but uses port 0 (ephemeral), so a UA
// listening on BoundIP:5060 can still dial out without EADDRINUSE.
func TestB2LocalPortIsEphemeral(t *testing.T) {
	// laddr as the transport layer builds it from the Via: BoundIP + the
	// listening port (non-zero). After the B2 patch, the dialer must NOT bind
	// that port; it must bind port 0.
	via := Addr{IP: net.ParseIP("127.0.0.1"), Port: 5060}
	got := dialLocalAddr(via) // helper extracted by the patch (see Step 3)
	if got == nil {
		t.Fatal("dialLocalAddr returned nil for a non-nil IP")
	}
	if !got.IP.Equal(via.IP) {
		t.Fatalf("dial local IP = %v, want Via IP %v (B2 controls the IP)", got.IP, via.IP)
	}
	if got.Port != 0 {
		t.Fatalf("dial local port = %d, want 0 (B2 leaves the port ephemeral)", got.Port)
	}
}

// TestB2DialLocalPortGatedByOption asserts the option-gated behavior: default
// (upstream) preserves the Via port; opted-in uses the ephemeral port. This
// proves other fork consumers (internal/sipengine/calltester, siptest.NewClient,
// sipgo's own tests) that do not set WithDialEphemeralLocalPort keep upstream
// behavior unchanged.
func TestB2DialLocalPortGatedByOption(t *testing.T) {
	via := Addr{IP: net.ParseIP("127.0.0.1"), Port: 5060}

	// Default (upstream): the dial keeps the Via port.
	def := newTCPTransport(NewParser())
	if a := def.dialLocalFor(via); a == nil || a.Port != 5060 {
		t.Fatalf("default must preserve upstream port 5060, got %v", a)
	}

	// Opted-in: ephemeral local port, IP preserved.
	opt := newTCPTransport(NewParser())
	opt.dialEphemeralLocalPort = true
	if a := opt.dialLocalFor(via); a == nil || !a.IP.Equal(via.IP) || a.Port != 0 {
		t.Fatalf("opted-in must be IP:0, got %v", a)
	}
}
