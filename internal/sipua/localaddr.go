// Package sipua owns the UDP signalling user agent and the D9d concrete-bind
// constraint its capture tap depends on.
package sipua

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// interfaceAddrs is the seam rule 4 enumerates through. Production always uses
// net.InterfaceAddrs; tests substitute a fixture so the "no usable address"
// case, unreachable on a host that has one, can be asserted (§15 P1 row).
var interfaceAddrs = net.InterfaceAddrs

// dialUDP is the seam rule 3 connects through. Production always uses
// net.Dial; tests substitute a fixture so a zoned, link-local, multicast or
// unspecified kernel-selected local address — unreachable by dialling a real
// interface — can be asserted against routeLookup's rejection.
var dialUDP = net.Dial

// errNoLocalAddr is the rule-4 exhaustion case. Callers at the tool boundary
// map it to invalid_argument; see ResolveBindAddr.
var errNoLocalAddr = errors.New(
	"no non-loopback, non-link-local unicast address is available on this host")

// ResolveLocalIP applies §6.5.3 rule 3 then rule 4. See the package doc for the
// contract; P2's media-address selection consumes this function unchanged.
func ResolveLocalIP(remote string, logger *slog.Logger) (net.IP, error) {
	// Rule 3: route lookup toward the remote signalling peer.
	if ip := routeLookup(remote); ip != nil {
		return ip, nil
	}

	// Rule 4: first non-loopback, non-link-local unicast address, with a WARN.
	addrs, err := interfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("enumerate interface addresses: %w", err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if !usableUnicast(n.IP) {
			continue
		}
		logger.Warn("local signalling address derived by fallback, not by route lookup",
			"local_ip", n.IP.String(),
			"rule", "6.5.3-rule-4",
			"remote_peer", remote)
		return n.IP, nil
	}
	return nil, errNoLocalAddr
}

// routeLookup opens an unconnected UDP socket, connect()s it to remote so the
// kernel selects the route, reads back the chosen local address, and closes it.
// NO PACKETS ARE SENT: connect(2) on a UDP socket only installs a destination
// and triggers a route lookup. Returns nil when no peer is known, when the
// lookup fails, or when the kernel selected an address that could not legally
// reach a Via (unspecified, link-local or zoned) — in every case resolution
// falls through to rule 4.
func routeLookup(remote string) net.IP {
	if remote == "" {
		return nil
	}
	c, err := dialUDP("udp", remote)
	if err != nil {
		return nil
	}
	defer func() { _ = c.Close() }()

	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || ua.Zone != "" || !usableRouteResult(ua.IP) {
		return nil
	}
	return ua.IP
}

// usableRouteResult accepts a loopback address — a loopback registrar is a
// legitimate destination and 127.0.0.1 is a concrete, Via-safe host. Only rule
// 4's blind fallback excludes loopback, because there it would be a guess.
func usableRouteResult(ip net.IP) bool {
	return ip != nil &&
		!ip.IsUnspecified() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast()
}

func usableUnicast(ip net.IP) bool {
	return usableRouteResult(ip) && !ip.IsLoopback()
}

// preferredPort is the standard local signalling port for a transport (L3).
// W2b binds only UDP; the tcp/tls arms are the W2c seam.
func preferredPort(transport string) string {
	if transport == "tls" {
		return "5061"
	}
	return "5060"
}

// ResolveBindAddr turns the caller-supplied local_addr into a concrete
// "ip:port" safe to bind and to pin a Via to (§8 D9d, §6.5.3). See the package
// contract above. Every failure is invalid_argument and yields no address, so
// the caller creates no UA. portExplicit reports whether the caller pinned a
// numeric port (true) or left it to be defaulted/kernel-chosen (false); the
// caller uses it to decide whether a bind conflict may fall back to an
// ephemeral port or must be reported as invalid_argument.
func ResolveBindAddr(localAddr, remote, transport string, logger *slog.Logger) (string, bool, error) {
	host, port, explicit, err := splitLocalAddr(localAddr)
	if err != nil {
		return "", false, apierr.InvalidArgument(err.Error())
	}
	if port == "" {
		port = preferredPort(transport)
	}

	if host != "" {
		ip := net.ParseIP(host)
		if ip == nil {
			return "", false, apierr.InvalidArgument(fmt.Sprintf(
				"local_addr host %q is not an IP literal", host))
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return "", false, apierr.InvalidArgument(fmt.Sprintf(
				"local_addr host %q is link-local; a link-local address cannot appear "+
					"in a SIP Via and would defeat the D9d capture tap", host))
		}
		if !ip.IsUnspecified() {
			return net.JoinHostPort(ip.String(), port), explicit, nil
		}
		// Wildcard host: fall through to resolution, keeping the supplied port.
	}

	ip, err := ResolveLocalIP(remote, logger)
	if err != nil {
		return "", false, apierr.InvalidArgument(fmt.Sprintf(
			"cannot resolve local_addr %q to a concrete address: %v", localAddr, err))
	}
	return net.JoinHostPort(ip.String(), port), explicit, nil
}

// splitLocalAddr accepts "", "host:port", a bare port ("5060" or ":5060") and a
// bare IP literal. An empty host means "resolve it"; an empty port means
// "unspecified" — the caller substitutes preferredPort. explicit is true only
// when the caller supplied a concrete numeric port. An IPv6 zone is rejected
// here, before any parse, because a zone can never legally reach a Via (§8 D9d).
func splitLocalAddr(s string) (host, port string, explicit bool, err error) {
	if s == "" {
		return "", "", false, nil
	}
	if strings.Contains(s, "%") {
		return "", "", false, fmt.Errorf(
			"local_addr %q carries an IPv6 zone; a zone is not valid in a SIP Via host", s)
	}
	if h, p, e := net.SplitHostPort(s); e == nil {
		if p == "" {
			return h, "", false, nil
		}
		if _, e2 := strconv.Atoi(p); e2 != nil {
			return "", "", false, fmt.Errorf("local_addr %q has a non-numeric port %q", s, p)
		}
		return h, p, true, nil
	}
	if _, e := strconv.Atoi(s); e == nil {
		return "", s, true, nil // bare port, e.g. "5060"
	}
	if net.ParseIP(s) != nil {
		return s, "", false, nil // bare IP literal
	}
	return "", "", false, fmt.Errorf(
		"local_addr %q is not host:port, a bare port or an IP literal", s)
}
