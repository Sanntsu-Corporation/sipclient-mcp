package sipua

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"testing"
)

// L3: with the UDP half bindable but the TCP twin taken, an unpinned bind
// retries a fresh pair on one equal port.
func TestBindUDPAndTCPFallsBackToAFreshPairWhenTheTCPTwinIsTaken(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = held.Close() }()
	heldAddr := held.Addr().String()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	conn, ln, err := bindUDPAndTCP(heldAddr, false, logger)
	if err != nil {
		t.Fatalf("bindUDPAndTCP: %v", err)
	}
	defer func() { _ = conn.Close(); _ = ln.Close() }()

	if conn.LocalAddr().String() == heldAddr {
		t.Fatalf("pair bound on the held TCP port %s", heldAddr)
	}
	if got, want := ln.Addr().String(), conn.LocalAddr().String(); got != want {
		t.Fatalf("TCP listener %s is not on the UDP address %s", got, want)
	}
	if n := strings.Count(logs.String(), "L4-port-fallback"); n != 1 {
		t.Fatalf("want one L4-port-fallback warning, got %d:\n%s", n, logs.String())
	}
}
