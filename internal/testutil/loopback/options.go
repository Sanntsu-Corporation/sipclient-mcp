// Package loopback is §14.1's centrepiece: two UAs inside one test process
// exchanging real SIP over loopback, with no external SIP server. It is what
// makes the whole product testable in CI with no infrastructure, and every
// acceptance test in P1b/P1d/P1e's later tasks runs on it.
package loopback

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// PeerBehaviour is a TYPE ALIAS for peer.Behaviour, not a second struct
// (contract §2.10, Rule 18). An alias — `=`, not a defined type — so
// loopback.PeerBehaviour{...} and peer.Behaviour{...} are the SAME type and
// h.Peer().SetBehaviour(loopback.PeerBehaviour{...}) compiles with no
// conversion. internal/testutil/peer is the canonical far-end UAS
// (P1c Task 14); this package never declares its own.
type PeerBehaviour = peer.Behaviour

// Account is a register-mode SIP account fixture for the harness's tests —
// the Phase 1 (session-scoped UA lifecycle, owner-locked decision)
// replacement for the pre-Phase-1 policy.Profile fixture. Where TestProfile
// built a []Profile the harness's policy.yaml carried, an Account is sent
// INLINE on ua_create, exactly as the real tool surface now requires: there
// is no shared profile registry left to write into policy.yaml (D1/D6 in
// internal/session deleted it). Registrar is left blank by TestAccount and
// filled in by MustCreateUAWithAccount at call time, because TestAccount
// runs before New() starts the harness's own in-process registrar and
// cannot know its ephemeral port.
type Account struct {
	Name      string // fixture lookup key only; never sent on the wire
	AOR       string
	AuthUser  string
	AuthPass  string
	Transport string
	ExpiresS  int
}

type options struct {
	transport   string
	accounts    []Account
	policy      *policy.Policy
	overrides   map[string]any
	wrapConn    func(net.PacketConn) net.PacketConn
	peer        PeerBehaviour
	adminToken  string
	fakeClock   bool
	peerTLSCert *tls.Certificate
	uaTimeout   time.Duration
}

func newOptions() options {
	return options{
		transport: "udp",
		overrides: map[string]any{},
		// The identity wrapper, not nil. P2 substitutes netfault here; keeping
		// the seam on the P1 path means it is exercised rather than dead code.
		wrapConn: func(c net.PacketConn) net.PacketConn { return c },
	}
}

// Option configures a Harness (decision 13: functional options).
type Option func(*options)

// WithTransport sets the transport every UA the harness creates uses.
func WithTransport(transport string) Option { return func(o *options) { o.transport = transport } }

// WithAccounts adds inline SIP account fixtures MustCreateUAWithAccount can
// create UAs against (Phase 1 replacement for WithProfiles/policy.yaml
// profiles — see Account's doc comment).
func WithAccounts(accounts ...Account) Option {
	return func(o *options) { o.accounts = append(o.accounts, accounts...) }
}

// WithPolicy supplies a whole base *policy.Policy for the harness to marshal
// into its own policy file.
func WithPolicy(p *policy.Policy) Option { return func(o *options) { o.policy = p } }

// WithPolicyOverride sets one dotted policy key (e.g.
// "limits.shutdown_grace_period") in the harness's policy file.
func WithPolicyOverride(dottedKey string, value any) Option {
	return func(o *options) { o.overrides[dottedKey] = value }
}

// WithPolicyOverrides sets several dotted policy keys at once.
func WithPolicyOverrides(m map[string]any) Option {
	return func(o *options) {
		for k, v := range m {
			o.overrides[k] = v
		}
	}
}

// WithConn substitutes the UA's signalling net.PacketConn. THIS IS P2's
// netfault substitution seam and it is DESIGNED AT P1 deliberately: adding it
// at P2 would reshape the Harness constructor and every call site, which is
// the forward dependency §15 exists to prevent.
func WithConn(wrap func(net.PacketConn) net.PacketConn) Option {
	return func(o *options) { o.wrapConn = wrap }
}

// WithUATimeout sets the per-transaction timeout of every UA the harness
// creates (sipua.Config.Timeout), so a dial to a silent far end fails in
// milliseconds instead of the default 32 s. Test-only; zero keeps the default.
func WithUATimeout(d time.Duration) Option { return func(o *options) { o.uaTimeout = d } }

// WithPeerBehaviour installs the far-end peer UAS's call-side behaviour.
func WithPeerBehaviour(b PeerBehaviour) Option { return func(o *options) { o.peer = b } }

// WithAdminToken enables the §12.7 admin plane with the given token.
func WithAdminToken(token string) Option { return func(o *options) { o.adminToken = token } }

// WithFakeClock builds the harness on a deterministic fakeclock.Clock instead
// of clock.System().
func WithFakeClock() Option { return func(o *options) { o.fakeClock = true } }

// WithPeerTLSCert arms the harness's canonical peer (internal/testutil/peer)
// with a TLS listener serving cert (M7a §2's Config.TLSCert), and points a
// tls-transport profile's registrar at that TLS listener instead of the
// UDP sipproxy/registrar address (Phase 4 W1 M7c, §6). This is the narrow,
// pre-approved harness expansion §12.5's tls acceptance cases need: without
// it the harness has no TLS-capable far end for a tls UA to register
// against at all.
func WithPeerTLSCert(cert *tls.Certificate) Option {
	return func(o *options) { o.peerTLSCert = cert }
}
