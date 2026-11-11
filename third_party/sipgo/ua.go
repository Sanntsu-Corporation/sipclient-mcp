package sipgo

import (
	"crypto/tls"
	"net"

	"github.com/emiago/sipgo/sip"
)

type UserAgent struct {
	name                   string
	hostname               string
	dnsResolver            *net.Resolver
	tlsConfig              *tls.Config
	dialEphemeralLocalPort bool
	dialConnWrap           func(net.Conn) net.Conn
	parser                 *sip.Parser
	tp                     *sip.TransportLayer
	tx                     *sip.TransactionLayer
}

type UserAgentOption func(s *UserAgent) error

// WithUserAgent changes user agent name
// Default: sipgo
func WithUserAgent(ua string) UserAgentOption {
	return func(s *UserAgent) error {
		s.name = ua
		return nil
	}
}

// WithUserAgentHostname represents FQDN of user that can be presented in From header
func WithUserAgentHostname(hostname string) UserAgentOption {
	return func(s *UserAgent) error {
		s.hostname = hostname
		return nil
	}
}

// WithUserAgentDNSResolver allows customizing default DNS resolver for transport layer
func WithUserAgentDNSResolver(r *net.Resolver) UserAgentOption {
	return func(s *UserAgent) error {
		s.dnsResolver = r
		return nil
	}
}

// WithUserAgenTLSConfig allows customizing default tls config.
func WithUserAgenTLSConfig(c *tls.Config) UserAgentOption {
	return func(s *UserAgent) error {
		s.tlsConfig = c
		return nil
	}
}

// WithDialEphemeralLocalPort is a W2c B2 divergence (opt-in, default off):
// when set, outbound TCP/TLS dials bind the Via-derived local IP but leave
// the local port ephemeral (0) instead of upstream's IP:Port, so a UA
// listening on that port can still dial out without EADDRINUSE. Consumers
// that do not set this option keep upstream behavior unchanged. See
// third_party/sipgo/VENDOR.md.
func WithDialEphemeralLocalPort() UserAgentOption {
	return func(s *UserAgent) error {
		s.dialEphemeralLocalPort = true
		return nil
	}
}

// WithDialConnWrap is a W2c capture divergence (opt-in, default nil/no-op):
// when set, every outbound TCP/TLS dial's conn (post-handshake for TLS) is
// passed through wrap before the transport takes ownership of it, so a
// caller can observe/tap outbound plaintext. Instance-scoped on this
// UserAgent's own TransportLayer -- never a package-level global -- so
// concurrently-running UAs each carry their own wrap without
// cross-contaminating each other's captures. See third_party/sipgo/VENDOR.md.
func WithDialConnWrap(wrap func(net.Conn) net.Conn) UserAgentOption {
	return func(s *UserAgent) error {
		s.dialConnWrap = wrap
		return nil
	}
}

// WithUserAgentParser allows removing default behavior of parser
// You can define and remove default headers parser map and pass here.
// Only use if your benchmarks are better than default
func WithUserAgentParser(p *sip.Parser) UserAgentOption {
	return func(s *UserAgent) error {
		s.parser = p
		return nil
	}
}

// NewUA creates User Agent
// User Agent will create transport and transaction layer
// Check options for customizing user agent
func NewUA(options ...UserAgentOption) (*UserAgent, error) {
	ua := &UserAgent{
		name:        "sipgo",
		hostname:    "localhost",
		dnsResolver: net.DefaultResolver,
		parser:      sip.NewParser(),
	}

	for _, o := range options {
		if err := o(ua); err != nil {
			return nil, err
		}
	}

	ua.tp = sip.NewTransportLayer(ua.dnsResolver, ua.parser, ua.tlsConfig, ua.dialEphemeralLocalPort, ua.dialConnWrap)
	ua.tx = sip.NewTransactionLayer(ua.tp)
	return ua, nil
}

func (ua *UserAgent) Close() error {
	// stop transaction layer
	ua.tx.Close()

	// stop transport layer
	return ua.tp.Close()
}

func (ua *UserAgent) Name() string {
	return ua.name
}

func (ua *UserAgent) TransportLayer() *sip.TransportLayer {
	return ua.tp
}

func (ua *UserAgent) TransactionLayer() *sip.TransactionLayer {
	return ua.tx
}
