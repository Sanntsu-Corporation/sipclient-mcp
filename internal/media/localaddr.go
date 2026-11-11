package media

import (
	"errors"
	"log/slog"
	"net"
	"strings"
)

// RouteResolver applies §6.5.3 rules 3 and 4 (route lookup then unicast
// fallback). internal/sipua wires SetRouteResolver(sipua.ResolveLocalIP) at
// init — media NEVER imports sipua, which is what keeps the sipua->media
// negotiation edge free of a cycle.
type RouteResolver func(remote string, logger *slog.Logger) (net.IP, error)

var routeResolver RouteResolver = func(string, *slog.Logger) (net.IP, error) {
	return nil, errors.New("media: no RouteResolver installed (sipua must call SetRouteResolver)")
}

// SetRouteResolver installs the rules 3/4 fallback. Called once from sipua init
// and, in media's own tests, from each test that exercises the fallthrough.
func SetRouteResolver(fn RouteResolver) { routeResolver = fn }

// ResolveMediaAddr applies §6.5.3 in order: (1) the caller-supplied local_addr's
// explicit IP, (2) policy media.local_ip, then (3/4) the injected resolver. It
// returns an IP only; the even media PORT is allocated by sipua from
// media.port_range and joined to this address before the SDP is built.
func ResolveMediaAddr(explicitLocalAddr, policyMediaIP, remote string, logger *slog.Logger) (net.IP, error) {
	// Rule 1: an explicit IP supplied in local_addr (not wildcard, not a bare
	// port). Co-locates media with signalling (§6.5.3 r1).
	if ip := explicitIPOf(explicitLocalAddr); ip != nil {
		return ip, nil
	}
	// Rule 2: policy media.local_ip override.
	if policyMediaIP != "" {
		if ip := net.ParseIP(policyMediaIP); ip != nil {
			return ip, nil
		}
	}
	// Rules 3/4: route lookup toward the remote peer, then unicast fallback.
	return routeResolver(remote, logger)
}

// explicitIPOf returns the concrete IP a caller pinned in local_addr, or nil for
// "", a wildcard (0.0.0.0/::), or a bare port. It mirrors sipua.splitLocalAddr's
// classification but needs no error channel: an unparseable value simply means
// "rule 1 does not apply" and resolution continues.
func explicitIPOf(localAddr string) net.IP {
	if localAddr == "" {
		return nil
	}
	host := localAddr
	if h, _, err := net.SplitHostPort(localAddr); err == nil {
		host = h
	} else if strings.ContainsRune(localAddr, ':') && net.ParseIP(localAddr) == nil {
		// Something with a colon that is neither host:port nor a bare IPv6 IP.
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return nil
	}
	return ip
}
