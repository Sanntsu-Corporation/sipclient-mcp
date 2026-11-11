package sipua

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

func isAddrInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }

func withPortZero(addr string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, "0"), nil
}

// bindPacket binds a UDP PacketConn at addr. On EADDRINUSE it falls back to a
// kernel-ephemeral port (L4, non-explicit default) or returns invalid_argument
// (L5, explicit pin).
func bindPacket(network, addr string, portExplicit bool, logger *slog.Logger) (net.PacketConn, error) {
	conn, err := net.ListenPacket(network, addr)
	if err == nil {
		return conn, nil
	}
	if !isAddrInUse(err) {
		return nil, apierr.InvalidArgument(fmt.Sprintf("cannot bind %s %s: %v", network, addr, err))
	}
	if portExplicit {
		return nil, apierr.InvalidArgument(fmt.Sprintf(
			"cannot bind %s %s: address in use and an explicit port was requested", network, addr))
	}
	ephemeral, zerr := withPortZero(addr)
	if zerr != nil {
		return nil, apierr.InvalidArgument(fmt.Sprintf("cannot bind %s %s: %v", network, addr, zerr))
	}
	conn, err = net.ListenPacket(network, ephemeral)
	if err != nil {
		return nil, apierr.InvalidArgument(fmt.Sprintf("cannot bind %s %s (fallback): %v", network, ephemeral, err))
	}
	logger.Warn("preferred signalling port unavailable; bound an ephemeral port instead",
		"requested", addr, "bound", conn.LocalAddr().String(), "rule", "L4-port-fallback")
	return conn, nil
}

// maxPairBinds bounds the UDP+TCP pair attempts when the TCP twin of an
// unpinned port is taken (L3/L4).
const maxPairBinds = 3

// bindUDPAndTCP binds a UDP socket and a TCP listener on the same IP and port
// (RFC 3261 18.2.1 MUST: a server listening on UDP listens on TCP there too).
// The TCP listener is bound on the UDP socket's own address, so it is never
// wider than the UDP bind. If the TCP twin is taken, a pinned port (the caller
// wrote a non-zero port) fails with invalid_argument; an unpinned one retries
// a fresh pair on a kernel-chosen port, at most maxPairBinds attempts.
func bindUDPAndTCP(addr string, portExplicit bool, logger *slog.Logger) (net.PacketConn, net.Listener, error) {
	if logger == nil {
		logger = slog.Default() // tests construct a UA without a logger
	}
	pinned := portExplicit
	if _, port, err := net.SplitHostPort(addr); err == nil && port == "0" {
		pinned = false
	}
	requested := addr
	for attempt := 1; ; attempt++ {
		conn, err := bindPacket("udp", addr, pinned, logger)
		if err != nil {
			return nil, nil, err
		}
		ln, err := net.Listen("tcp", conn.LocalAddr().String())
		if err == nil {
			if attempt > 1 {
				logger.Warn("preferred signalling port unavailable; bound an ephemeral port instead",
					"requested", requested, "bound", conn.LocalAddr().String(), "rule", "L4-port-fallback")
			}
			return conn, ln, nil
		}
		bound := conn.LocalAddr().String()
		_ = conn.Close()
		if !isAddrInUse(err) {
			return nil, nil, apierr.InvalidArgument(fmt.Sprintf("cannot bind tcp %s: %v", bound, err))
		}
		if pinned || attempt >= maxPairBinds {
			return nil, nil, apierr.InvalidArgument(fmt.Sprintf(
				"cannot bind tcp %s: address in use; RFC 3261 18.2.1 requires a UDP UA to listen on the same port for TCP", bound))
		}
		if addr, err = withPortZero(addr); err != nil {
			return nil, nil, apierr.InvalidArgument(fmt.Sprintf("cannot bind %s: %v", requested, err))
		}
	}
}
