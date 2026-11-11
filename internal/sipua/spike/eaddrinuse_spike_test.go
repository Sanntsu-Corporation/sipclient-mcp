package spike

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

// TestOutboundDialFromListeningPort_CurrentPinClashes reproduces sipgo's
// current behavior: a UA listening on IP:5060/tcp that dials outbound with
// LocalAddr pinned to the SAME IP:5060 (as sipgo derives from the Via) is
// expected to EADDRINUSE on Linux.
func TestOutboundDialFromListeningPort_CurrentPinClashes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	laddr := ln.Addr().(*net.TCPAddr) // the listener's bound IP:port

	// A second listener to dial toward (any reachable TCP acceptor).
	peer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	defer func() { _ = peer.Close() }()

	// CURRENT PIN: LocalAddr = listener's own IP:port (BoundIP:5060 analog).
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: laddr.IP, Port: laddr.Port}}
	conn, err := d.Dial("tcp", peer.Addr().String())
	if err == nil {
		_ = conn.Close()
		t.Fatalf("expected EADDRINUSE dialing from the listening port, got nil (record this — B2 fork touch may be unnecessary)")
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Logf("dial failed with a non-EADDRINUSE error (record the exact errno): %v", err)
	}
	t.Logf("EVIDENCE current-pin: dial err = %v", err)
}

// TestOutboundDialFromListeningPort_B2DialsClean proves B2: LocalAddr pinned to
// BoundIP with port 0 dials cleanly and the resulting source IP == BoundIP.
func TestOutboundDialFromListeningPort_B2DialsClean(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	laddr := ln.Addr().(*net.TCPAddr)

	peer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	defer func() { _ = peer.Close() }()

	// B2: same IP, ephemeral port.
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: laddr.IP, Port: 0}}
	conn, err := d.Dial("tcp", peer.Addr().String())
	if err != nil {
		t.Fatalf("B2 dial (BoundIP:0) must succeed, got: %v", err)
	}
	defer func() { _ = conn.Close() }()
	src := conn.LocalAddr().(*net.TCPAddr)
	if !src.IP.Equal(laddr.IP) {
		t.Fatalf("B2 source IP = %v, want BoundIP %v", src.IP, laddr.IP)
	}
	if src.Port == laddr.Port {
		t.Fatalf("B2 source port must be ephemeral, got the listener port %d", src.Port)
	}
	t.Logf("EVIDENCE B2: dialed clean, src = %v (IP == BoundIP, ephemeral port)", src)
}
