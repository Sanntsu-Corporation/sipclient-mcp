package sipua

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// bindListener binds a stream (tcp) listener at addr. On EADDRINUSE it falls
// back to a kernel-ephemeral port (L4, non-explicit default) or returns
// invalid_argument (L5, explicit pin) — the same policy as bindPacket.
func bindListener(network, addr string, portExplicit bool, logger *slog.Logger) (net.Listener, error) {
	ln, err := net.Listen(network, addr)
	if err == nil {
		return ln, nil
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
		return nil, apierr.InvalidArgument(fmt.Sprintf("cannot bind %s %s: %v", network, ephemeral, err))
	}
	ln, err = net.Listen(network, ephemeral)
	if err != nil {
		return nil, apierr.InvalidArgument(fmt.Sprintf("cannot bind %s %s (fallback): %v", network, ephemeral, err))
	}
	logger.Warn("preferred signalling port unavailable; bound an ephemeral port instead",
		"requested", addr, "bound", ln.Addr().String(), "rule", "L4-port-fallback")
	return ln, nil
}
