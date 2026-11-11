package sipua

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/siptest"
)

// init wires media's rules 3/4 fallback to this package's own ResolveLocalIP
// (§6.5.3), unchanged. media never imports sipua — this is the one edge that
// avoids the cycle (M5 / design spec §3.1).
func init() {
	media.SetRouteResolver(ResolveLocalIP)
}

// serveReadyTimeout bounds the wait for sipgo's transport pool to register the
// listener (see readyConn) before New returns. It exists only as a safety net
// against a hang; the ordinary path closes the channel in well under a
// millisecond.
const serveReadyTimeout = 2 * time.Second

// dnsResolverOverride is a TEST-ONLY seam (nil in production, so the agent keeps
// net.DefaultResolver); see the C-M5 comment in call.go.
var dnsResolverOverride *net.Resolver

func dnsResolver() *net.Resolver {
	if dnsResolverOverride != nil {
		return dnsResolverOverride
	}
	return net.DefaultResolver
}

// Config carries everything a UA needs to bind and to run. Transport is an
// explicit parameter, never a literal (O1, §15.1); WrapConn is the
// caller-supplied socket seam D9d/U1 requires — P1 installs the trace observer
// there, P2 composes netfault on top, and nothing else changes.
//
// WrapConn is a DECORATOR, not a listener factory: sipua binds the concrete
// address itself (§3d) and only then hands the conn over, so no caller can bind
// a wildcard and silently defeat the tap.
type Config struct {
	Mode      string // "register" | "direct"
	Transport string // "udp" | "tcp" | "tls" — O1: explicit, NEVER a literal
	LocalAddr string
	AOR       string
	AuthUser  string

	// AuthPass is PLAINTEXT, BY NECESSITY — and it is the one field here that
	// is NOT shaped like the adjacent layer's.
	//
	// session.UAConfig.AuthPass is a redacting policy.Secret whose String,
	// GoString, MarshalJSON and LogValue all render "[REDACTED]". This one
	// cannot be: Part 1.1 forbids the direct edge sipua -> policy, so `sipua`
	// cannot name policy.Secret at all, and DoRequestWithDigest needs the real
	// value to compute the response hash. The redaction guarantee is upheld ONE
	// LAYER UP in session.UAConfig, and §2.9's wiring closure performs the one
	// production de-redaction call as it copies the fields across.
	//
	// CONSEQUENCE: sipua.Config MUST NEVER BE LOGGED WHOLE. `%+v`, `%#v`,
	// slog.Any("cfg", cfg) or any struct-wide dump leaks the password here,
	// even though doing exactly the same thing to a session.UAConfig is safe —
	// which is precisely what makes it easy to get wrong. Log NAMED SCALAR
	// FIELDS ONLY (Mode, Transport, AOR, Registrar, BoundAddr); never the
	// struct. §14.2's "no credential appears in any log line" test asserts the
	// outcome, but this comment is what stops the line being written.
	AuthPass string

	Registrar string // "sip:host:port"; required when Mode == "register"

	// AuthAnyHost lifts CF-046's destination guard for this UA: an INVITE digest
	// challenge is answered whatever host it came from. Default false: it is
	// answered only when the INVITE target host is the registrar's or the AOR's
	// (digestHostAllowed).
	AuthAnyHost bool

	// CodecPref, SRTP, MediaLocalIP and MediaPortRange are P2 W3's media
	// negotiation policy (M5). CodecPref is ordered; empty defaults to
	// ["PCMU","PCMA"] (codecPrefs). SRTP is "disabled" | "optional" |
	// "required" (srtpPolicy; an empty value is "disabled"). MediaLocalIP
	// is policy media.local_ip (§6.5.3 rule 2). MediaPortRange is policy
	// media.port_range; bindMediaPort allocates an even port within it.
	CodecPref      []string
	SRTP           string
	MediaLocalIP   string
	MediaPortRange [2]int

	// JitterBufferMS is policy media.jitter_buffer_ms (§6.5.1), default 60,
	// clamped 20-200 by the media loop. TXToneHz is the hidden e2e-gate TX tone
	// knob (locked decision 3): 0 => silence; never exposed via any MCP tool.
	JitterBufferMS int
	TXToneHz       float64

	// Prompts is the policy prompts: name->path map, injected by the composition
	// root (cmd/sipclient-mcpd). media_play resolves prompt NAMES through this;
	// arbitrary paths are never accepted (§10.9, §12.3).
	Prompts map[string]string

	// Artifacts is the canonical artifact store, injected by the composition root.
	// media_record_* streams the WAV through it. nil in unit harnesses that never
	// record.
	Artifacts session.ArtifactStore

	// ArtifactMaxBytes is the policy artifact.max_bytes high-watermark (§13.3),
	// injected by the composition root. RecordStart refuses a new recording when
	// the store's UsageBytes is at/over this and the value is >0; 0 disables the
	// guard.
	ArtifactMaxBytes int64

	// ExpiresS is the REQUESTED registration expiry in seconds, read through
	// registerExpiresS (never directly — see that accessor for the default).
	// It reaches the wire from P3 onward: siptest.BuildRegister (the vendored
	// builder) hardcodes Expires: 300, so Register and Unregister override the
	// header AFTER building, through setExpires (register.go). A post-build
	// override rather than a builder edit because G4 — an owner-ruled standing
	// gate, not a technical constraint (VENDOR.md calls the copy "owned and
	// modifiable") — freezes internal/sipengine. The GRANTED
	// expiry is a different value entirely:
	// responseExpires reads it off the registrar's response — the Contact
	// `expires` parameter first (RFC 3261 §10.2.4's authoritative form), then
	// the optional Expires header — and falls back to its requestedExpiresS
	// parameter (the clamped value actually sent, per requestedExpires) only
	// when the registrar granted through neither.
	ExpiresS int

	Keepalive string

	// DTMFMode/SessionExpiresS/MinSES/KeepaliveIntervalS/SessionRefreshMethod
	// mirror session.UAConfig's fields of the same names (spec §3). Read
	// through the defaulting accessors in dtmf.go / sessiontimer.go /
	// keepalive.go, never directly, so the documented defaults live in one
	// place per key.
	DTMFMode             string
	SessionExpiresS      int
	MinSES               int
	KeepaliveIntervalS   int
	SessionRefreshMethod string

	InboundRingTimeout time.Duration
	Timeout            time.Duration

	Logger *slog.Logger
	Clock  clock.Clock

	// WrapConn is the caller-supplied socket seam D9d/U1 requires. sipua binds a
	// CONCRETE address, then hands the conn to WrapConn, then hands the result
	// to Server.ServeUDP. nil means the identity wrapper. P1 installs the trace
	// observer here; P2 composes netfault on top. NOTHING ELSE CHANGES.
	WrapConn func(net.PacketConn) net.PacketConn

	// WrapListener is the P2 W2c T5 INBOUND stream-capture seam, mirroring
	// WrapConn one level up (net.Listener, not net.PacketConn): sipua binds a
	// CONCRETE tcp/tls listener, applies any TLS wrap, THEN hands the result
	// to WrapListener, and only then to Server.ServeTCP/ServeTLS — so the tap
	// always observes post-handshake plaintext, never raw TLS bytes. nil
	// means the identity wrapper (no observation). A UDP UA applies it to its
	// TCP listener too (CF-190, after the connection cap).
	WrapListener func(net.Listener) net.Listener

	// WrapDialConn is the P2 W2c T5 OUTBOUND stream-capture seam. Unlike
	// WrapConn/WrapListener, sipua does not apply this itself: it is threaded
	// into sipgo via sipgo.WithDialConnWrap (D4), because outbound tcp/tls
	// dials are sipgo-owned. sipgo calls it on the dialed conn (post-handshake
	// for TLS) before the transport takes ownership. nil means no wrap. A UDP
	// UA threads it in too, for its TCP dials (CF-190: CF-106 oversize
	// requests, tcp in-dialog requests to a transport=tcp Contact).
	WrapDialConn func(net.Conn) net.Conn

	// TLSRootCAs and TLSInsecureSkipVerify are the RESOLVED trust material for
	// the "tls" transport's outbound dialer (Phase 4 M7b, §7.1). They carry
	// only *x509.CertPool/bool — internal/sipua must never learn policy.TLS's
	// shape (Part 1.1 forbids the sipua -> policy edge). TLSRootCAs nil means
	// "use the host roots"; a non-nil pool (resolved from policy tls.ca_bundle
	// by the composition root) REPLACES the host roots, it does not add to
	// them. TLSInsecureSkipVerify mirrors policy tls.insecure_skip_verify.
	// Both are read only by newTLSConfigs and are no-ops for udp/tcp.
	TLSRootCAs            *x509.CertPool
	TLSInsecureSkipVerify bool

	// CallLimit is the live concurrent-call limit of this UA's session,
	// min(max_concurrent_calls_per_session, max_concurrent_calls_total), read
	// once per initial INVITE to bound the INVITE handlers onInvite holds
	// (CF-177). Nil means no bound, which is what tests and UAs that do not
	// set it get.
	CallLimit func() int
}

// UA is a signalling user agent bound to one concrete transport address.
type UA struct {
	// resolver is the DNS resolver the sipgo agent and the digest pins share
	// (dnsResolver, fixed at construction).
	resolver *net.Resolver

	// digestPins holds the resolved anchor addresses an INVITE digest challenge
	// must come from (CF-054); see anchorPins.
	digestPins anchorPins

	conn   net.PacketConn // udp only (its TCP twin listener, CF-076, closes with it); the tcp/tls path tears down via agent+listener instead
	srv    *sipgo.Server
	client *siptest.Client // the VENDORED wrapper: DoRequestWithDigest,
	//                        RawTransaction and Raw() exist only here

	// agent is the sipgo UserAgent this UA was built on. Retained for BOTH
	// transports (P2 W2c T2, Cycle B item 4/5): the tcp/tls closer needs it to
	// drain the pool (agent.Close()) as the last teardown step; udp's closer
	// does the same after conn.Close(), because an oversize request is sent
	// over a dialed TCP connection (CF-106) that must not outlive the UA.
	agent *sipgo.UserAgent

	// boundIP/boundPort are the SOLE source of truth for the post-bind
	// address (W6): the Via and the sipgo pool key are built from these.
	// BoundAddr() synthesizes a fresh *net.UDPAddr from them on every call
	// (signature unchanged); LocalAddr() synthesizes the transport-correct
	// net.Addr (*net.TCPAddr for tcp/tls, *net.UDPAddr for udp).
	boundIP   net.IP
	boundPort int

	// cfg and daemonCtx are PERSISTED and UNEXPORTED. Every call site in Tasks
	// 14 and 15 is inside package sipua, so unexported fields serve them all;
	// exported Cfg()/DaemonContext() accessors would leak internals across a
	// package boundary for zero external callers (Rule 15).
	cfg       Config
	daemonCtx context.Context

	// uaCtx is this UA's own lifetime context, derived from daemonCtx via
	// context.WithCancel in New and cancelled by cancel below. Per-UA
	// background goroutines (the ctx watcher, emit's fallback, runDial, and
	// armRingTimeout's timeout goroutine) select on uaCtx.Done(), NOT
	// daemonCtx.Done() (I7): daemonCtx is the long-lived DAEMON context
	// (locked decision 17) shared by every UA, so waiting on it alone means
	// closing ONE UA never unblocks its own goroutines — they leak until the
	// whole daemon shuts down (D114/I7).
	uaCtx context.Context

	// cancel stops the ctx watcher goroutine started in newUA. It is derived
	// from daemonCtx via context.WithCancel rather than reusing daemonCtx
	// directly, because daemonCtx is the long-lived DAEMON context (locked
	// decision 17) — waiting on IT alone means Close never unblocks the
	// watcher, leaking one goroutine per UA until daemon shutdown (D114).
	cancel context.CancelFunc

	// closeConn closes conn EXACTLY ONCE, however teardown is triggered: by
	// Close() or by the ctx watcher goroutine racing it after u.cancel() (D115).
	// Without this guard both call conn.Close() independently, the loser sees
	// net.ErrClosed, and Close() reports failure on a fully successful
	// teardown. It is built in New (over a sync.Once shared with the watcher
	// goroutine, which is started before the UA struct exists) rather than
	// added here as separate Once/error fields, so both closers share the same
	// underlying sync.Once no matter which one is asked to close conn first.
	closeConn func() error

	// closeGate runs Close's body once (CF-061); every other Close blocks
	// until it has returned and then returns its closeResult.
	closeGate   sync.Once
	closeResult error

	// reg is Task 14's registration state.
	reg regState

	// nonceCounter is P4-D06's ONE RFC 7616 §3.4.3 nonce-count tracker, shared
	// by BOTH digest legs — REGISTER (register.go's four doRequestWithDigest
	// sites) and the challenged outbound INVITE (call.go's runDial, via
	// digestAuthTransaction). It lives on the UA and not on regState precisely
	// because it must span both: nc counts the requests sent WITH A GIVEN
	// NONCE, not with a given method, and every peer that issues one nonce for
	// both methods enforces monotonicity across them. Two per-leg counters
	// would each emit 1, 2, 3… on that one nonce and the peer would reject the
	// collisions as replays — the exact defect this counter exists to remove,
	// reintroduced by the topology instead of by the counter.
	//
	// It holds one slot PER (realm, nonce) rather than a single slot, because
	// an outbound INVITE can face a different realm than the registrar (this UA
	// has no outbound proxy); and the REGISTRAR's slot is PINNED, so no amount
	// of INVITE traffic can evict the one identity whose continuity this feature
	// exists to protect. See digestauth.go's type comment and design §13
	// Amendments 1 and 2.
	//
	// A VALUE FIELD, always taken as &u.nonceCounter. It carries its own mutex
	// (digestauth.go) and nothing outside digestauth.go reads its fields.
	nonceCounter nonceCounter

	// digestRetryMu SERIALIZES NONCE-COUNT RESERVATION across the two digest
	// legs, which nonceCounter's own mutex cannot: that one is released the
	// instant next() returns, while stamping the reserved nc onto the request's
	// Authorization header happens afterwards. The register refresher's
	// goroutine and runDial's goroutine are otherwise unserialized — regState's
	// doc comment forbids holding reg.mu across a network write and register.go
	// honours it — so without this lock the two legs could interleave between
	// reserving and stamping and put the WRONG nc on a request.
	//
	// HELD ACROSS applyDigest ONLY — NOT across the TransactionRequest that
	// carries the nc, and not across a response wait (which is why
	// doTxWithAddVia was split into digestAuthTransaction + pumpFinal).
	// Narrowing it to the reservation is the Rule 13 Cycle 5 (architecture
	// review) fix: this mutex is UA-GLOBAL, it does not distinguish
	// (realm, nonce) identities, and TransactionRequest synchronously DIALS when
	// the destination has no live connection (TCP connect; for tls the whole
	// handshake). Held across dispatch, one unreachable callee on the INVITE leg
	// would block a healthy registrar's refresh on a completely unrelated
	// identity — and since Mutex.Lock takes no context, the blocked leg could
	// not honour its own deadline while waiting, turning unrelated call-path
	// network trouble into registration failure.
	//
	// WIRE ORDERING IS THEREFORE BEST-EFFORT, CONSISTENTLY SO. Reservation order
	// is guaranteed (nc=1 is reserved before nc=2); which of the two reaches the
	// wire first is not, because the lock is gone by then. That is the same
	// guarantee the network already gave us — two datagrams in flight can
	// reorder no matter what this process locks — so the trade only widens an
	// already-documented window, and it buys back the far more serious cross-leg
	// blocking hazard above.
	digestRetryMu sync.Mutex

	// calls is Task 15's dialog registry and event-callback holder.
	calls callRegistry

	// learnedPublic is Task 3's RFC 3581 rport LEARN state: the
	// server-observed public address read off the REGISTER response's top
	// Via (received/rport), consulted by Answer to build the 200 OK Contact.
	// Constructed in the initial struct literal below, BEFORE
	// installHandlers — an inbound INVITE can race in the instant ServeUDP's
	// read loop starts, and Answer dereferences this field, so it must be
	// non-nil first (mirrors uaCtx's ordering requirement above).
	learnedPublic *publicAddr
}

// New binds the UA's signalling listener to a CONCRETE IP:port and pins its Via
// to that same post-bind address (§8 D9d). Both halves are load-bearing: with
// either missing, sipgo silently opens a new, untapped socket on the first
// outbound REGISTER or INVITE (v0.24.1 sip/transport_udp.go:99-127), producing a
// silently incomplete capture rather than a failure. ctx is the long-lived
// DAEMON context (locked decision 17), never an HTTP request context.
func New(ctx context.Context, cfg Config) (*UA, error) {
	// DEFENSIVE DEFAULT — a defect this task's loopback harness discovered,
	// out of Task 22's declared scope (reported per Rule 6c), fixed here as
	// the minimal, self-contained point that protects every caller.
	//
	// internal/session's ToolService.UACreate builds a UAConfig and never
	// sets Timeout, so session.UAConfig.Timeout — and therefore cfg.Timeout
	// here, forwarded verbatim through every wiring closure including this
	// package's own production one (cmd/run.go) — is ALWAYS the zero value
	// on every real request path. transactionWithProvisional (call.go) and
	// RawTransaction (register.go, BYE) both derive their per-transaction
	// deadline via `context.WithTimeout(ctx, cfg.Timeout)`; a zero duration
	// is an ALREADY-EXPIRED deadline, so the client transaction is destroyed
	// before ANY response — including the immediate 100 Trying — can be
	// matched to it. Proved live: the loopback harness's very first real
	// register-mode `ua_create` and outbound `call_dial` both hung at
	// "dialing"/failed with sipgo logging "Unhandled sip response ...
	// handler not added" for every 100/180/200/401 the far end sent, because
	// the transaction was already torn down by the time they arrived.
	//
	// This mirrors D131/bf5ef16's already-shipped fix for the SAME failure
	// mode one layer down (siptest.NewClient never received AuthUser/
	// AuthPass/Timeout for Register/Unregister) — that fix passes cfg.Timeout
	// through correctly; the remaining gap is that the CALLER never sets it
	// to anything but zero. 32s is RFC 3261's Timer B/F (64*T1, T1=500ms),
	// the standard maximum time to await a SIP transaction's final response;
	// it is applied ONLY when the caller left Timeout unset, so any caller
	// that already supplies a real value (sipua's own test suite sets one
	// explicitly throughout) is completely unaffected.
	if cfg.Timeout <= 0 {
		cfg.Timeout = 32 * time.Second
	}

	network, err := networkFor(cfg.Transport)
	if err != nil {
		return nil, err
	}

	// Resolve BEFORE binding: the listener is never wildcard-bound, because the
	// pool key is conn.LocalAddr().String() (sip/transport_udp.go:65) and no
	// routable Via can ever match a key of "0.0.0.0:5060".
	//
	// §6.5.3 rule 3 routes toward the REGISTRAR in register mode; in direct mode
	// no remote peer is known at ua_create at all, so remote is "" and
	// resolution falls straight to rule 4 (§3d).
	bind, portExplicit, err := ResolveBindAddr(cfg.LocalAddr, registrarHostPort(cfg), cfg.Transport, cfg.Logger)
	if err != nil {
		return nil, err
	}

	if network == "tcp" {
		ln, err := bindListener(network, bind, portExplicit, cfg.Logger)
		if err != nil {
			return nil, err
		}
		ua, err := newUAStream(ctx, cfg, ln, ln.Addr().String())
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
		return ua, nil
	}

	// RFC 3261 18.2.1 (CF-076): the UDP socket's TCP twin on the same
	// address and port, bound together.
	conn, ln, err := bindUDPAndTCP(bind, portExplicit, cfg.Logger)
	if err != nil {
		return nil, err
	}

	// The D9d/U1 seam: wrap the ALREADY-CONCRETELY-BOUND conn, then hand the
	// WRAPPED conn to ServeUDP. Identity when nil.
	wrapped := conn
	if cfg.WrapConn != nil {
		wrapped = cfg.WrapConn(conn)
	}

	// Pin to the address read back POST-BIND from the INNER conn, not to the
	// configured string: a 0 port only becomes concrete here, and
	// conn.LocalAddr() is precisely the value sip/transport_udp.go:65 uses as
	// the pool key, so the Via and the key agree by construction.
	ua, err := newUA(ctx, cfg, wrapped, ln, conn.LocalAddr().String())
	if err != nil {
		_ = conn.Close()
		_ = ln.Close()
		return nil, err
	}
	return ua, nil
}

// registrarHostPort strips the sip:/sips: scheme from Config.Registrar so
// ResolveBindAddr receives the bare "host:port" its contract names. Direct mode
// has no registrar, so it yields "" and rule 3 is skipped.
func registrarHostPort(cfg Config) string {
	if cfg.Mode != "register" {
		return ""
	}
	return strings.TrimPrefix(strings.TrimPrefix(cfg.Registrar, "sips:"), "sip:")
}

// networkFor maps the transport parameter to a listener network. tcp and tls
// both bind a tcp listener (P2 W2c T2/T3); tls additionally wraps it in TLS
// inside newUAStream.
func networkFor(transport string) (string, error) {
	switch transport {
	case "udp":
		return "udp", nil
	case "tcp":
		return "tcp", nil
	case "tls":
		return "tcp", nil
	default:
		return "", apierr.InvalidArgument(fmt.Sprintf("unknown transport %q", transport))
	}
}

// readyConn signals readiness on its FIRST ReadFrom call. sipgo's
// transportUDP.Serve (v0.24.1 sip/transport_udp.go:57-70) calls t.pool.Add
// (:69) BEFORE it enters the read loop that calls ReadFrom (:70 ->
// readListenerConnection -> ReadFrom at :189), so closing ready there is
// reached only after the pool entry exists.
//
// New waits on this channel before returning. Without it, newUA returns as
// soon as the ServeUDP goroutine is merely SCHEDULED, racing the first
// outbound request's ClientRequestConnection pool lookup
// (sip/transport_layer.go:341-346) against pool.Add: losing that race sends
// control to CreateConnection, which tries to rebind the address this
// listener already holds and fails with EADDRINUSE. A time.Sleep would only
// narrow the race, not close it — this barrier closes it.
type readyConn struct {
	net.PacketConn
	once  sync.Once
	ready chan struct{}
}

func newReadyConn(pc net.PacketConn) *readyConn {
	return &readyConn{PacketConn: pc, ready: make(chan struct{})}
}

func (r *readyConn) ReadFrom(p []byte) (int, net.Addr, error) {
	r.once.Do(func() { close(r.ready) })
	n, addr, err := r.PacketConn.ReadFrom(p)
	// D22 / RFC 5626 §3.5.1: answer an inbound double-CRLF ping with a
	// single-CRLF pong. This is the ONE non-vendored seam every inbound UDP
	// datagram passes through before sipgo's own transport layer
	// (transport_udp.go's parseAndHandle, G4-frozen) sees it — that code
	// already treats a bare CRLF-only datagram as a no-op keep-alive
	// ("Keep alive CRLF received") and never answers it, so the pong half
	// has nowhere else to live without editing the frozen tree. Best-effort:
	// a failed write here must not surface as a ReadFrom error to sipgo's
	// own read loop, and the datagram is still handed up unchanged so
	// sipgo's existing no-op handling of it is untouched.
	if err == nil && n == 4 && string(p[:4]) == "\r\n\r\n" {
		_, _ = r.WriteTo([]byte("\r\n"), addr)
	}
	return n, addr, err
}

// newUACore is the construction core SHARED by newUA (udp) and newUAStream
// (tcp/tls) — P2 W2c T2, Cycle A item 6. The two paths differ only in: the
// agent's construction options (the stream path opts into T1's B2 ephemeral
// dial port), how boundIP/boundPort are derived, how the server actually
// serves (startServe — ServeUDP behind the readyConn barrier vs ServeTCP/
// ServeTLS with none, B2 makes the barrier unnecessary for streams), and how
// teardown closes the listener/conn (closeConn). Everything else — the
// sipgo server/client construction, the UA struct, the ctx-watcher wiring —
// is identical, so it lives here once rather than being duplicated in both
// callers (Rule 15/16). viaAddr is the address the client pins its Via to.
func newUACore(ctx context.Context, cfg Config, agent *sipgo.UserAgent,
	boundIP net.IP, boundPort int, viaAddr string,
	startServe func(srv *sipgo.Server) error,
	closeConn func() error,
) (*UA, error) {
	srv, err := sipgo.NewServer(agent)
	if err != nil {
		return nil, fmt.Errorf("sipgo.NewServer: %w", err)
	}

	// Construct through the VENDORED wrapper, never sipgo.NewClient directly.
	// Two reasons, both load-bearing:
	//   1. Tasks 14-16 need DoRequestWithDigest, RawTransaction and Raw(), which
	//      exist ONLY on *siptest.Client (verified in source).
	//   2. siptest/client.go:20 already applies sipgo.WithClientAddr(
	//      cfg.LocalAddr), so setting engineCfg.LocalAddr to the POST-BIND
	//      address delivers §3d's pinned-Via half FOR FREE. Do NOT hand-roll the
	//      option: one fewer place the invariant can be dropped.
	//
	// AuthUser, AuthPass and Timeout are passed through here, not just onto the
	// request config Task 14's builders use: DoRequestWithDigest reads its
	// challenge-response credentials and its per-request deadline from the
	// CLIENT's own c.cfg, a different object from the one BuildRegister builds
	// the request from. Without this, Timeout is 0 (an instantly expiring
	// context) and AuthUser/AuthPass are empty (a 401 with no way to answer
	// it) — proven for Task 14's Register/Unregister.
	client, err := siptest.NewClient(config.Config{
		LocalAddr: viaAddr,
		AuthUser:  cfg.AuthUser,
		AuthPass:  cfg.AuthPass,
		Timeout:   cfg.Timeout,
	}, agent)
	if err != nil {
		return nil, fmt.Errorf("siptest.NewClient: %w", err)
	}

	// The UA struct is built here, BEFORE Serve* starts, so installHandlers
	// (below) has a receiver to register srv.OnInvite/OnBye/OnCancel against.
	// cancel and closeConn are filled in once they exist, further down.
	u := &UA{
		srv:           srv,
		client:        client,
		agent:         agent,
		boundIP:       boundIP,
		boundPort:     boundPort,
		cfg:           cfg,
		daemonCtx:     ctx,
		learnedPublic: &publicAddr{},
		resolver:      dnsResolver(),
	}

	// uaCtx is derived and stored HERE, before installHandlers/Serve* start
	// (not further down, where the D114 ctx watcher goroutine and u.cancel are
	// set up): armRingTimeout, emit and runDial (I7) read u.uaCtx from
	// goroutines an inbound INVITE can trigger the instant the Serve* read
	// loop starts. daemonCtx is race-free only because it is set in this same
	// initial struct literal, before any handler exists to race it; uaCtx
	// needs the identical ordering guarantee, or a peer whose INVITE lands
	// during construction races this field's write against armRingTimeout's
	// read of it.
	uaCtx, uaCancel := context.WithCancel(ctx)
	u.uaCtx = uaCtx

	// Task 15 (locked decision D129/C3): install the inbound SIP handlers
	// UNCONDITIONALLY here, before the Serve* goroutine starts, so a UA that
	// has never dialled or registered still answers an inbound INVITE.
	// Gating this behind a sync.Once in Dial/Register (as originally drafted)
	// left srv.OnInvite unregistered for every UA driven purely as a UAS —
	// every inbound test constructs a UA and has the peer dial it without
	// calling either. This is additive to construction: it does not touch
	// the constructor signature, the WrapConn seam, or the concrete bind.
	u.installHandlers()

	if err := startServe(srv); err != nil {
		uaCancel() // release uaCtx: this path returns before u.cancel = uaCancel below
		return nil, err
	}

	// The ctx watcher closes the transport when the UA's own lifetime ends.
	// uaCtx (derived above, before installHandlers) is NOT ctx itself: ctx is
	// the long-lived DAEMON context (locked decision 17), so waiting on
	// ctx.Done() directly would mean Close never unblocks this goroutine,
	// leaking one goroutine per UA until daemon shutdown (D114). Close cancels
	// uaCancel.
	//
	// stopAllMediaLoops runs FIRST, before the transport itself closes: it is
	// the UA-lifetime-end teardown for any dialog's mediaLoop that outlived
	// every other call site (teardownDialog/Hangup/onBye) — see its own doc
	// comment (dialog_teardown.go) for the leak this closes.
	//
	// stopRefreshers runs even before that: a timer that fires during teardown
	// would put a REGISTER or an OPTIONS on a transport that is about to close.
	//
	// stopAllMediaLoops(false): this path sends no BYE and does not mark the
	// UA closed. Close runs its own sweep first (CF-061), so after a Close this
	// one finds only a dialog established since.
	go func() {
		<-uaCtx.Done()
		u.stopRefreshers()
		u.stopAllMediaLoops(false)
		_ = closeConn()
	}()

	u.cancel = uaCancel
	u.closeConn = closeConn
	return u, nil
}

// newUA is the udp construction path, built on newUACore. viaAddr is the
// address the client pins its Via to; New always passes conn.LocalAddr().
// String(). It is a parameter rather than a derived value so the D9d
// acceptance cases can be constructed by a test without adding a production
// option nobody uses (Rule 15). ln (never nil) is the TCP listener on the same
// address and port as conn (RFC 3261 18.2.1, CF-076); newUA caps it
// (caplistener.go), applies the capture tap (cfg.WrapListener) on top, and owns
// closing it.
func newUA(ctx context.Context, cfg Config, conn net.PacketConn, ln net.Listener, viaAddr string) (*UA, error) {
	bound, err := net.ResolveUDPAddr("udp", conn.LocalAddr().String())
	if err != nil {
		return nil, fmt.Errorf("bound address %q is not a UDP address: %w",
			conn.LocalAddr().String(), err)
	}

	agentOpts := []sipgo.UserAgentOption{
		sipgo.WithUserAgentHostname(bound.IP.String()),
		// CF-106: an oversize request is sent over a TCP connection this UA
		// dials (RFC 3261 18.1.1); without this option the dial binds the UDP
		// listen port's address and a second one fails EADDRINUSE.
		sipgo.WithDialEphemeralLocalPort(),
		// B1 (Phase 4 M1): bounded Content-Length parser, see
		// newHardenedSIPParser's doc comment (parserhardening.go).
		sipgo.WithUserAgentParser(newHardenedSIPParser()),
		sipgo.WithUserAgentDNSResolver(dnsResolver()),
	}
	// CF-190: the TCP dials of this UA (CF-106) get the same capture seam the
	// stream path threads in, guarded like it.
	if cfg.WrapDialConn != nil {
		agentOpts = append(agentOpts, sipgo.WithDialConnWrap(cfg.WrapDialConn))
	}
	agent, err := sipgo.NewUA(agentOpts...)
	if err != nil {
		return nil, fmt.Errorf("sipgo.NewUA: %w", err)
	}

	ln = newCapListener(ln, maxInboundTCPConns, inboundTCPIdle(cfg.InboundRingTimeout),
		inboundTCPEvictIdle(cfg.InboundRingTimeout))
	// CF-190: raw -> cap -> tap, the stream path's order: a connection closed
	// over the cap never reaches the tap.
	if cfg.WrapListener != nil {
		ln = cfg.WrapListener(ln)
	}

	// closeConn is shared by the watcher goroutine and Close() (D115): a
	// sync.Once ensures conn.Close() runs exactly once no matter which side
	// gets there first, so the loser never observes (and Close() never
	// returns) a spurious net.ErrClosed from closing an already-closed conn.
	// conn.Close() runs first, then agent.Close() closes any TCP connection
	// the UA dialed for an oversize request (CF-106). The pool may already
	// have closed the listener, so a net.ErrClosed from agent.Close() is not
	// an error.
	//
	// CF-076: the TCP listener closes right after conn and its serve goroutine
	// is awaited before agent.Close(), the stream path's order (newUAStream,
	// L8): an in-flight accept/init must not race pool.Clear(). closeConn is
	// reachable only after startServe returned nil, i.e. after the TCP serve
	// goroutine started, so the wait cannot hang.
	tcpServeDone := make(chan struct{})
	var closeOnce sync.Once
	var closeErr error
	closeConn := func() error {
		closeOnce.Do(func() {
			closeErr = conn.Close()
			if lerr := ln.Close(); closeErr == nil {
				closeErr = lerr
			}
			<-tcpServeDone
			if cerr := agent.Close(); closeErr == nil && !errors.Is(cerr, net.ErrClosed) {
				closeErr = cerr
			}
		})
		return closeErr
	}

	// ServeUDP over the CALLER-SUPPLIED PacketConn (server.go:234-236), never
	// ListenAndServe, which is only a wrapper that makes its own socket
	// (server.go:110-125). This is the seam the trace observer wraps (U1).
	//
	// The conn is wrapped in readyConn here, not passed to ServeUDP directly:
	// ServeUDP has no readiness signal of its own (ListenReadyCtxKey/Value
	// exist only on ListenAndServe), so without this barrier New would return
	// before sipgo's transport pool holds the listener, racing the first
	// outbound request against pool.Add (see readyConn's doc comment). KEPT
	// UNCHANGED for udp (P2 W2c T2, Rule 6b locked fact 3): only the stream
	// path drops this barrier.
	startServe := func(srv *sipgo.Server) error {
		rc := newReadyConn(conn)
		go func() { _ = srv.ServeUDP(rc) }()
		select {
		case <-rc.ready:
			go func() {
				defer close(tcpServeDone)
				_ = srv.ServeTCP(ln)
			}()
			return nil
		case <-time.After(serveReadyTimeout):
			return fmt.Errorf("sipua: ServeUDP did not register %s in the "+
				"transport pool within %s", conn.LocalAddr(), serveReadyTimeout)
		}
	}

	u, err := newUACore(ctx, cfg, agent, bound.IP, bound.Port, viaAddr, startServe, closeConn)
	if err != nil {
		return nil, err
	}
	u.conn = conn
	// The NAT keepalive is armed at CONSTRUCTION, not at Register: a
	// direct-mode UA has no registrar and arms nothing (keepaliveTarget is
	// ""), and a register-mode UA's binding needs keeping open from the
	// moment it binds, including across a REGISTER that has not succeeded
	// yet. Started here, after u.conn is set (not inside newUACore), because
	// sendCRLFKeepalive reads u.conn from the refresher's own goroutine and
	// newUACore returns before newUA assigns it (Correction 14: no
	// happens-before edge otherwise).
	u.startKeepalive()
	return u, nil
}

// newUAStream is the tcp/tls construction path, built on newUACore (P2 W2c
// T2). It differs from newUA in exactly the ways Cycle A/B named: the agent
// opts into T1's B2 ephemeral dial port (a UA that is also listening can
// still dial out without EADDRINUSE — BoundIP:0, never BoundIP:<listen-port>);
// boundIP/boundPort come from the listener's own Addr(), not
// net.ResolveUDPAddr; it serves via ServeTCP with NO readiness barrier (see
// startServe below); and its close order is listener.Close() -> wait for the
// serve goroutine to return -> agent.Close() (L8) — NEVER agent.Close()
// before the listener close, or an in-flight accept/init could race
// pool.Clear(). T3 (P2 W2c) adds the tls branch below: when cfg.Transport ==
// "tls", listener is wrapped in a tls.NewListener using a SERVER *tls.Config,
// while a SEPARATE CLIENT *tls.Config is threaded into the agent's outbound
// dialer via sipgo.WithUserAgenTLSConfig (third_party/sipgo/ua.go:49 —
// sipgo's own spelling — NO fork touch); the two-config split is Phase 4
// M7b, §7 scope item 5. startServe calls ServeTLS instead of ServeTCP.
// closeConn's listener.Close() below still works unchanged: tls.Listener.
// Close() delegates to the wrapped inner Listener. Every listener is capped
// (caplistener.go, CF-189), wrapped below tls so the order is raw -> cap -> tls
// -> tap (D6C-1).
func newUAStream(ctx context.Context, cfg Config, listener net.Listener, viaAddr string) (*UA, error) {
	host, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return nil, fmt.Errorf("bound address %q is not host:port: %w", listener.Addr().String(), err)
	}
	boundIP := net.ParseIP(host)
	if boundIP == nil {
		return nil, fmt.Errorf("bound address %q has no parseable IP", listener.Addr().String())
	}
	boundPort, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("bound address %q has no parseable port: %w", listener.Addr().String(), err)
	}

	agentOpts := []sipgo.UserAgentOption{
		sipgo.WithUserAgentHostname(boundIP.String()),
		// T1's B2 opt-in: this UA both listens AND dials, so an unmodified
		// outbound dial pinned to BoundIP:<listen-port> would EADDRINUSE.
		sipgo.WithDialEphemeralLocalPort(),
		// B1 (Phase 4 M1): bounded Content-Length parser, see
		// newHardenedSIPParser's doc comment (parserhardening.go).
		sipgo.WithUserAgentParser(newHardenedSIPParser()),
		sipgo.WithUserAgentDNSResolver(dnsResolver()),
	}

	// CF-189: cap the RAW tcp listener (raw -> cap -> tls -> tap), so the cap
	// counts TCP connections and the idle deadline also bounds a stalled
	// handshake; the tap still sees post-handshake plaintext (D6C-1).
	listener = newCapListener(listener, maxInboundTCPConns, inboundTCPIdle(cfg.InboundRingTimeout),
		inboundTCPEvictIdle(cfg.InboundRingTimeout))

	if cfg.Transport == "tls" {
		serverTLSCfg, clientTLSCfg, err := newTLSConfigs(boundIP, cfg.TLSRootCAs, cfg.TLSInsecureSkipVerify, cfg.Logger)
		if err != nil {
			return nil, fmt.Errorf("newTLSConfigs: %w", err)
		}
		// Two configs, not one (M7b): the SERVER config wraps the inbound
		// listener; the SEPARATE CLIENT config is threaded into the outbound
		// dialer via the existing sanctioned option — no fork touch.
		agentOpts = append(agentOpts, sipgo.WithUserAgenTLSConfig(clientTLSCfg))
		listener = tls.NewListener(listener, serverTLSCfg)
	}

	// T5 D3: the inbound capture seam is applied to the FINAL listener —
	// after any TLS wrap above — so the tap always observes post-handshake
	// plaintext (tcp: the raw listener; tls: the tls.Listener). nil is the
	// identity wrapper.
	if cfg.WrapListener != nil {
		listener = cfg.WrapListener(listener)
	}

	// T5 D3/D4: the outbound capture seam threads into sipgo's per-instance
	// dial-wrap hook (WithDialConnWrap), never applied by sipua itself —
	// outbound tcp/tls dials are sipgo-owned. Guarded like the tls branch
	// above: only append the option when a wrap is actually configured.
	if cfg.WrapDialConn != nil {
		agentOpts = append(agentOpts, sipgo.WithDialConnWrap(cfg.WrapDialConn))
	}

	agent, err := sipgo.NewUA(agentOpts...)
	if err != nil {
		return nil, fmt.Errorf("sipgo.NewUA: %w", err)
	}

	// serveDone is closed unconditionally by the serve goroutine once
	// ServeTCP returns, so closeConn's wait below can never block forever
	// even if ServeTCP returns an error rather than because of the listener
	// close.
	serveDone := make(chan struct{})

	// closeConn's ORDER is load-bearing (L8): (1) listener.Close() stops new
	// Accepts, (2) <-serveDone waits for the serve goroutine to observe the
	// closed listener and return, (3) agent.Close() drains the sipgo pool.
	// Reversing (1) and (3) lets an in-flight accept/init race pool.Clear().
	// sync.Once makes this idempotent and shared with the ctx watcher, same
	// pattern as the udp closer.
	var closeOnce sync.Once
	var closeErr error
	closeConn := func() error {
		closeOnce.Do(func() {
			closeErr = listener.Close()
			<-serveDone
			if cerr := agent.Close(); closeErr == nil {
				closeErr = cerr
			}
		})
		return closeErr
	}

	// No readiness barrier here (Rule 6b locked fact 3): B2 pins the outbound
	// dial's local port to 0, never the listen port, so the EADDRINUSE race
	// the udp readyConn barrier exists to close cannot happen on this path —
	// a pool-lookup racing pool.Add merely creates one extra, benign
	// connection. Add one only if a -race test ever proves an actual problem
	// (YAGNI, Rule 15).
	startServe := func(srv *sipgo.Server) error {
		go func() {
			defer close(serveDone)
			if cfg.Transport == "tls" {
				_ = srv.ServeTLS(listener)
			} else {
				_ = srv.ServeTCP(listener)
			}
		}()
		return nil
	}

	u, err := newUACore(ctx, cfg, agent, boundIP, boundPort, viaAddr, startServe, closeConn)
	if err != nil {
		return nil, err
	}
	// See newUA's identical call for why this lives here rather than in
	// newUACore (Correction 14).
	u.startKeepalive()
	return u, nil
}

// BoundAddr is the concrete IP:port the listener bound. It is the value the Via
// is pinned to and the key sipgo pools the tapped socket under; every builder
// call site MUST take its Via host and port from here, not from the configured
// local_addr string. Synthesized fresh from boundIP/boundPort on every call
// (W6): boundIP/boundPort, not a stored *net.UDPAddr, are the sole source of
// truth, so this is always an IP/port convenience, never a shared pointer.
func (u *UA) BoundAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: u.boundIP, Port: u.boundPort}
}

// LocalAddr is BoundAddr's session.UserAgent-facing alias, transport-correct
// (P2 W2c T2/W6): *net.TCPAddr for tcp/tls, *net.UDPAddr for udp. It exists
// because session.UserAgent names it (contract §2.5.3) and sipua's own call
// sites read better as BoundAddr.
//
// THE RETURN TYPE IS net.Addr, NOT *net.UDPAddr (U17), and narrowing it back is
// a defect: Go requires an EXACT signature match, so *net.UDPAddr does not
// satisfy `LocalAddr() net.Addr` and assert_test.go would stop compiling.
// In-package code that needs .IP or .Port calls BoundAddr(); it must not type-
// assert this value.
func (u *UA) LocalAddr() net.Addr {
	if u.cfg.Transport == "tcp" || u.cfg.Transport == "tls" {
		return &net.TCPAddr{IP: u.boundIP, Port: u.boundPort}
	}
	return &net.UDPAddr{IP: u.boundIP, Port: u.boundPort}
}

// TLSVerified implements session.UserAgent.TLSVerified (Phase 4 W1 M7c,
// §7.2). ok is false on any transport other than tls; verified reflects
// this UA's CONSTRUCTION-TIME TLSInsecureSkipVerify snapshot, never a live
// policy read.
func (u *UA) TLSVerified() (verified bool, ok bool) {
	if u.cfg.Transport != "tls" {
		return false, false
	}
	return !u.cfg.TLSInsecureSkipVerify, true
}

// Transport reports the transport this UA was constructed with.
func (u *UA) Transport() string { return u.cfg.Transport }

// codecPrefs is the ordered codec list Answer/Dial negotiate with (M5),
// defaulting to ["PCMU","PCMA"] when Config.CodecPref is unset.
func (u *UA) codecPrefs() media.CodecPrefs {
	if len(u.cfg.CodecPref) == 0 {
		return media.CodecPrefs{"PCMU", "PCMA"}
	}
	return media.CodecPrefs(u.cfg.CodecPref)
}

// srtpPolicy is the negotiation policy (M5): a non-empty per-call override
// (already validated by session to only tighten the UA's policy) else
// Config.SRTP. An empty or unrecognised value is SRTPDisabled.
func (u *UA) srtpPolicy(override string) media.SRTPPolicy {
	if override == "" {
		override = u.cfg.SRTP
	}
	switch p := media.SRTPPolicy(override); p {
	case media.SRTPOptional, media.SRTPRequired:
		return p
	}
	return media.SRTPDisabled
}

// Client returns the vendored wrapper: DoRequestWithDigest, RawTransaction and
// Raw() exist only here, not on *sipgo.Client.
func (u *UA) Client() *siptest.Client { return u.client }

// Server returns the underlying sipgo server this UA runs its transport on.
func (u *UA) Server() *sipgo.Server { return u.srv }

// closeByeWait bounds, in REAL time, how long Close waits for the BYEs of the
// established dialogs it took over and for a Hangup's BYE claimed before its
// sweep (CF-061). A BYE still unsent when it elapses is lost.
const closeByeWait = time.Second

// Close tears the UA down (CF-061). Its sweep (stopAllMediaLoops(true)) runs
// synchronously while the transport is still open: it marks the UA closed and
// takes over every ESTABLISHED dialog (phaseAnswered, phaseControlOp), ending
// it locally as the watcher's sweep does, media and session timer stopped
// here, and Close sends that dialog's one BYE through sendInDialog. Close then
// waits, at most closeByeWait and detached from ctx's cancellation, for those
// BYEs and for any BYE a Hangup counted before the sweep, and only then
// cancels uaCtx and closes the client and the transport. Every other phase is
// left as before (no 603, no CANCEL). The body runs once: a concurrent or later
// Close blocks until it has returned, then returns the same result.
//
// INVARIANT: no UAEvent callback may call Close. The sweep's media stop joins
// the media loop's goroutines, which deliver events synchronously, so a
// callback calling Close would block in closeGate while Close waits for it.
// A callback that needs to tear a UA down must do so from its own goroutine.
func (u *UA) Close(ctx context.Context) error {
	u.closeGate.Do(func() {
		u.stopRefreshers()
		owed := u.stopAllMediaLoops(true)
		bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeByeWait)
		for _, d := range owed {
			go func() {
				defer u.calls.byes.Done()
				if _, _, err := u.sendInDialog(bctx, d, sip.BYE, nil); err != nil {
					if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
						// No response within closeByeWait; the BYE may still have been
						// queued behind the send-order token and never written.
						u.log().Warn("BYE from UA close: no response observed within closeByeWait (the BYE may not have been written)", "dialog_id", d.id, "call_id", d.callID, "err", err)
						return
					}
					u.log().Warn("BYE from UA close failed", "dialog_id", d.id, "call_id", d.callID, "err", err)
				}
			}()
		}
		done := make(chan struct{})
		go func() {
			u.calls.byes.Wait()
			close(done)
		}()
		timer := time.NewTimer(closeByeWait)
		select {
		case <-done:
		case <-timer.C:
		}
		timer.Stop()
		cancel()
		u.cancel()
		_ = u.client.Close()
		u.closeResult = u.closeConn()
	})
	return u.closeResult
}

// dtmfModeDefault is the profile's DTMF mode, defaulting to rfc2833 (spec §3).
func (u *UA) dtmfModeDefault() string {
	if u.cfg.DTMFMode == "" {
		return "rfc2833"
	}
	return u.cfg.DTMFMode
}

// registerExpiresS is the REQUESTED registration expiry, defaulting to 300 —
// the same value siptest.BuildRegister has always hardcoded, so an unset
// profile keeps byte-identical wire behavior to before this task's fix.
func (u *UA) registerExpiresS() int {
	if u.cfg.ExpiresS <= 0 {
		return 300
	}
	return u.cfg.ExpiresS
}

// sessionExpiresS is the REQUESTED RFC 4028 interval, defaulting to 1800.
func (u *UA) sessionExpiresS() int {
	if u.cfg.SessionExpiresS <= 0 {
		return 1800
	}
	return u.cfg.SessionExpiresS
}

// minSES is the Min-SE floor we advertise and enforce, defaulting to RFC
// 4028's own 90.
func (u *UA) minSES() int {
	if u.cfg.MinSES <= 0 {
		return 90
	}
	return u.cfg.MinSES
}

// keepaliveIntervalS is the NAT keepalive period, defaulting to 30.
func (u *UA) keepaliveIntervalS() int {
	if u.cfg.KeepaliveIntervalS <= 0 {
		return 30
	}
	return u.cfg.KeepaliveIntervalS
}

// refreshMethodPref is decision 11's per-profile override, defaulting to auto.
func (u *UA) refreshMethodPref() string {
	if u.cfg.SessionRefreshMethod == "" {
		return "auto"
	}
	return u.cfg.SessionRefreshMethod
}
