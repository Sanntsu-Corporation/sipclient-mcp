package loopback

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/artifact"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/metrics"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/sipproxy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/trace"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/transport/mcp"
)

const (
	testBearer  = "test-bearer-token"
	otherBearer = "other-bearer-token"
	localIP     = "127.0.0.1"
)

// TestBearer is the harness's own MCP bearer token — every Harness built by
// New authenticates against exactly this value.
func TestBearer() string { return testBearer }

// OtherBearer is a syntactically valid but WRONG bearer token — a different
// string from TestBearer, never configured against any harness — for the
// negative "wrong token" cases §12.2/§12.7 require.
func OtherBearer() string { return otherBearer }

// Harness is an in-process daemon, an in-process registrar/forwarding proxy
// (the relocated siptest/proxy.go — P1a Task 2) and a far-end peer UAS, all
// over loopback UDP. No external SIP server is involved (§14.1).
type Harness struct {
	t          *testing.T
	opts       options
	srv        *httptest.Server
	mcpSrv     *mcp.Server
	registrar  *sipproxy.Proxy
	peer       *peer.Peer
	mgr        *session.Manager
	store      *policy.Store
	sink       *trace.Sink
	metrics    *metrics.Registry
	logBuf     *syncBuffer
	logger     *slog.Logger
	clk        clock.Clock
	fake       *fakeclock.Clock
	policyPath string
	stopDaemon context.CancelFunc
	sessionID  string
	rpc        *rpcClient
	closeOnce  sync.Once // Close is the single teardown path and must be idempotent

	// shutdownFn is D309's ShutdownWith seam: Task 20b passes the REAL
	// gracefulShutdown in from package main, where it is visible (this
	// package cannot import cmd/sipclient-mcpd — it is package main and is
	// unimportable). ShutdownWith runs it asynchronously and WaitForExit
	// joins it, so the daemon-lifecycle test exercises the SAME shutdown
	// body the shipped binary runs, not a harness-local copy that could
	// silently diverge from it (D309).
	shutdownMu   sync.Mutex
	shutdownDone chan error

	// handleOwner maps every call OR UA handle this harness's sessions have
	// minted to its owning session id (Harness.MustDial, Session.MustDial,
	// MustCreateUA and MustWaitForInboundCall all register it). EvictNow and
	// PeerSendBye/PeerSendFinal resolve through it rather than assuming
	// h.sessionID, because Task 24's lock-order test evicts calls minted by
	// a Harness.NewSession(t) SUB-session.
	handleMu    sync.Mutex
	handleOwner map[string]string
}

// New starts an in-process daemon, an in-process registrar/forwarding proxy
// and a far-end peer UAS, all over loopback UDP. No external SIP server is
// involved (§14.1).
func New(t *testing.T, opts ...Option) *Harness {
	t.Helper()
	o := newOptions()
	for _, opt := range opts {
		opt(&o)
	}

	h := &Harness{t: t, opts: o, logBuf: newSyncBuffer(), handleOwner: map[string]string{}}
	logger := slog.New(slog.NewJSONHandler(h.logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.logger = logger

	if o.fakeClock {
		h.fake = fakeclock.New(time.Date(2026, 7, 18, 9, 0, 0, 0, time.UTC))
		h.clk = h.fake
	} else {
		h.clk = clock.System()
	}

	// ONE cleanup, registered ONCE, calling the SAME Close every test already
	// defers. Per-component t.Cleanup registrations do not run until the TEST
	// ends, which would leak every component a per-iteration loop creates.
	t.Cleanup(h.Close)

	h.registrar = sipproxy.StartProxy(t, localIP)

	// The CANONICAL peer UAS (contract §2.10, Rule 18) — P1c Task 14's
	// package, not a loopback-local duplicate. WithPeerTLSCert (Phase 4 W1
	// M7c, §6) additionally arms a TLS listener on this same peer when set.
	h.peer = peer.Start(t, peer.Config{
		Addr:      localIP + ":0", // concrete, never a wildcard
		Realm:     "sipclient-test",
		Behaviour: o.peer,
		TLSCert:   o.peerTLSCert,
	})

	h.policyPath, h.store = writeAndLoadPolicy(t, o, h.clk, logger)
	if len(o.accounts) > 0 {
		// THE SECRET IS PASSED ACROSS THIS CALL STILL REDACTED (B2). SetDigest
		// takes a policy.Secret and reveals INSIDE its digest computation at
		// the point of use (sipproxy.digestOK) — see the notes there and on
		// SetDigest itself. Phase 1: the plaintext comes straight from the
		// Account fixture (owner-accepted for ua_create's own inline
		// auth_pass), wrapped here rather than read back through a policy
		// file — there is no policy-file credential to read any more.
		acct := o.accounts[0]
		h.registrar.SetDigest("sipclient-test", acct.AuthUser, policy.NewSecret(acct.AuthPass))
	}

	daemonCtx, stopDaemon := context.WithCancel(context.Background())
	h.stopDaemon = stopDaemon

	h.metrics = metrics.New(session.TerminationReasons)

	// U15: trace.New takes TWO bounds — depth per ring, and the NUMBER of
	// rings. Read from the policy STORE, not a literal, so a harness built
	// with WithPolicyOverride("limits.max_ladders", N) genuinely exercises
	// the bound.
	h.sink = trace.New(0, h.store.Current().Limits.MaxLadders)

	// The canonical [P2] artifact store (D9b), rooted at the SAME
	// artifact.dir writeAndLoadPolicy already wrote into the harness's
	// policy document.
	artifacts := artifact.New(h.store.Current().Artifact.Dir, h.clk)

	mgr, err := session.NewManager(session.ManagerConfig{
		Ctx:       daemonCtx, // the DAEMON context, per decision 17
		Clock:     h.clk,
		Policy:    h.store,
		Logger:    logger,
		Metrics:   h.metrics,
		Tap:       h.sink,
		Artifacts: artifacts,
		// PARAMETER IS session.UAConfig, NEVER sipua.Config — this closure IS
		// the wiring layer (§2.9), and it is the only place in the harness
		// where a session.UAConfig becomes a sipua.Config.
		NewUA: func(uaCtx context.Context, uc session.UAConfig) (session.UserAgent, error) {
			// Harness UAs ALWAYS bind a concrete 127.0.0.1:<port>. A wildcard
			// would defeat the D9d tap (§3d), so the harness cannot produce
			// one.
			uc.LocalAddr = localIP + ":0"
			if o.uaTimeout > 0 {
				uc.Timeout = o.uaTimeout
			}
			return sipua.New(uaCtx, sipua.Config{
				Mode: uc.Mode, Transport: string(uc.Transport), LocalAddr: uc.LocalAddr,
				AOR: uc.AOR, AuthUser: uc.AuthUser,
				// The single production-shaped de-redaction site in this
				// closure, mirroring cmd/'s own (§2.9); see UAConfig.AuthPass's
				// doc for why the two sides of this boundary differ in type.
				AuthPass:           uc.AuthPass.Reveal(),
				Registrar:          uc.Registrar,
				ExpiresS:           uc.ExpiresS,
				Keepalive:          uc.Keepalive,
				InboundRingTimeout: uc.InboundRingTimeout,
				Timeout:            uc.Timeout,

				SRTP:                 uc.SRTP,
				DTMFMode:             uc.DTMFMode,
				SessionExpiresS:      uc.SessionExpiresS,
				MinSES:               uc.MinSES,
				KeepaliveIntervalS:   uc.KeepaliveIntervalS,
				SessionRefreshMethod: uc.SessionRefreshMethod,
				AuthAnyHost:          uc.AuthAnyHost,

				// B10 (P4-W2-09, W2): sipua.Config.Tap is gone (see
				// cmd/sipclient-mcpd/run.go's wiring closure for why removing it
				// changes no behavior) -- h.sink still reaches sipua via
				// ObservingConn below, not via this field.
				Logger: logger, Clock: h.clk,
				// Phase 4 M7b, §7.1(c): field-threading only — the harness's
				// far ends (sipproxy, peer) are UDP-only, so this is not a
				// loopback TLS test path (that is out of scope for M7b
				// entirely).
				TLSRootCAs:            h.store.Current().TLSRootCAs(),
				TLSInsecureSkipVerify: h.store.Current().TLS.InsecureSkipVerify,
				WrapConn: func(c net.PacketConn) net.PacketConn {
					// HIGH-3: stamp the owning UA handle so the sink keys by
					// (ua_handle, call_id).
					return sipua.ObservingConn(o.wrapConn(c), h.sink, uc.Transport, h.clk.Now, string(uc.Handle))
				},
			})
		},
	})
	if err != nil {
		t.Fatalf("loopback: build session manager: %v", err)
	}
	h.mgr = mgr

	srv, err := mcp.NewServer(mcp.Config{
		Sessions: mgr,
		Tools:    session.NewToolService(mgr),
		Admin:    mgr,
		Policy:   h.store,
		Metrics:  h.metrics,
		Ready: func() mcp.ReadyStatus {
			return mcp.BuildReadyStatus(h.store, h.clk, h.clk.Now())
		},
		Artifacts: artifacts,
		Log:       logger,
		Clock:     h.clk,
	})
	if err != nil {
		t.Fatalf("loopback: build mcp server: %v", err)
	}
	h.mcpSrv = srv
	h.srv = httptest.NewServer(srv.Handler())
	h.rpc = newRPCClient(h.srv.URL)

	res := h.Initialize(t, "", testBearer)
	if res.Status != 200 || res.SessionID == "" {
		t.Fatalf("loopback: initialize failed: status=%d session=%q", res.Status, res.SessionID)
	}
	h.sessionID = res.SessionID
	return h
}

// Peer is the canonical far-end UAS this harness built (contract §2.10).
func (h *Harness) Peer() *peer.Peer { return h.peer }

// Registrar is the in-process registrar/forwarding proxy this harness built.
func (h *Harness) Registrar() *sipproxy.Proxy { return h.registrar }

// PeerURI is the SIP URI at which Peer() is reachable.
func (h *Harness) PeerURI() string { return "sip:peer@" + h.peer.Addr() }

// Clock fails the test if the harness was not built WithFakeClock().
func (h *Harness) Clock() *fakeclock.Clock {
	if h.fake == nil {
		h.t.Fatal("harness was not built WithFakeClock()")
	}
	return h.fake
}

// HasFakeClock reports instead of failing, for setup preconditions.
func (h *Harness) HasFakeClock() bool { return h.fake != nil }

// Close RELEASES THE WHOLE HARNESS, idempotently: the srv, the peer, the
// registrar, then the daemon context, in that order — stop accepting new
// work, then the far end, then the daemon, so closing the daemon first
// cannot strand in-flight requests against a live listener.
func (h *Harness) Close() {
	h.closeOnce.Do(func() {
		if h.srv != nil {
			h.srv.Close()
		}
		if h.peer != nil {
			h.peer.Close()
		}
		if h.registrar != nil {
			h.registrar.Close()
		}
		h.stopDaemon()
	})
}

// SendSIGHUP reproduces the BODY of cmd/'s SIGHUP branch against this
// harness's own store, metrics registry and logger. It does NOT deliver a
// real signal and does NOT call a shared function: cmd/sipclient-mcpd is
// package main and unimportable, and internal/importguard forbids cmd/ from
// reaching internal/testutil in the other direction. The three observable
// effects (Reload() on the real *policy.Store, one metrics counter on
// failure, one ERROR log line) are what this exists to exercise; P1d Task
// 20's own acceptance drives the REAL signal against the REAL binary through
// StartDaemonProcess.
func (h *Harness) SendSIGHUP(t *testing.T) {
	t.Helper()
	if err := h.store.Reload(); err != nil {
		h.metrics.IncPolicyReloadFailures()
		h.logger.Error("policy reload failed; previous policy remains in force",
			slog.String("path", h.policyPath), slog.String("error", err.Error()))
		return
	}
	h.logger.Info("policy reloaded", slog.String("path", h.policyPath))
}

// ---- D309: real shutdown-body accessors, zero production surface ----------

// MCPServer is the concrete *mcp.Server this harness built.
func (h *Harness) MCPServer() *mcp.Server { return h.mcpSrv }

// HTTPServer is the *httptest.Server fronting the daemon; its ".Config" is
// the *http.Server the real shutdownDeps.HTTP wants.
func (h *Harness) HTTPServer() *httptest.Server { return h.srv }

// Manager is the *session.Manager this harness built.
func (h *Harness) Manager() *session.Manager { return h.mgr }

// Logger is the *slog.Logger this harness built, the same one RawLog reads.
func (h *Harness) Logger() *slog.Logger { return h.logger }

// HarnessClock is the clock.Clock this harness built (the fake if
// WithFakeClock(), else clock.System()).
func (h *Harness) HarnessClock() clock.Clock { return h.clk }

// ShutdownWith runs fn asynchronously and makes WaitForExit join it. Task 20b
// passes the REAL gracefulShutdown in from package main, built against
// MCPServer/HTTPServer/Manager/Logger/HarnessClock above, so the test
// exercises the shipped shutdown body rather than a harness-local copy of it
// (D309).
func (h *Harness) ShutdownWith(fn func() error) {
	h.shutdownMu.Lock()
	defer h.shutdownMu.Unlock()
	done := make(chan error, 1)
	h.shutdownDone = done
	go func() { done <- fn() }()
}

// WaitForExit blocks until the function passed to ShutdownWith returns, or
// fails the test after d. It fails the test if ShutdownWith was never
// called, rather than blocking forever.
func (h *Harness) WaitForExit(t *testing.T, d time.Duration) error {
	t.Helper()
	h.shutdownMu.Lock()
	done := h.shutdownDone
	h.shutdownMu.Unlock()
	if done == nil {
		t.Fatal("loopback: WaitForExit called with no prior ShutdownWith")
	}
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("loopback: WaitForExit: shutdown did not complete within %s", d)
		return nil
	}
}

// ---- policy file construction ----------------------------------------------

// writeAndLoadPolicy builds the harness's policy YAML on disk and loads it
// through policy.NewStore — the SAME path cmd/ takes (policy.Load is
// deliberately not consumed directly by this package), so SendSIGHUP's
// Reload() is meaningful.
//
// PHASE 1: no `profiles:` section is EVER written here. policy.Profile is
// deleted (D1/D6, owner-locked decision); every account this harness's tests
// need is sent inline on ua_create by MustCreateUAWithAccount, which resolves
// the harness's own registrar/peer-TLS address itself at CALL time instead of
// this function resolving it at policy-file-write time.
//
// D294: artifact.dir MUST be a real writable directory — policy.Defaults
// sets none and nothing validates one, so every harness-built daemon would
// otherwise be PERMANENTLY UN-READY and every /readyz assertion in later
// tasks would read 503.
func writeAndLoadPolicy(t *testing.T, o options, clk clock.Clock, logger *slog.Logger) (string, *policy.Store) {
	t.Helper()
	dir := t.TempDir()

	bearerFile := filepath.Join(dir, "bearer_token")
	if err := os.WriteFile(bearerFile, []byte(testBearer), 0o600); err != nil {
		t.Fatalf("loopback: write bearer_token file: %v", err)
	}

	artifactDir := t.TempDir()

	auth := map[string]any{"bearer_token_file": bearerFile}
	if o.adminToken != "" {
		adminFile := filepath.Join(dir, "admin_token")
		if err := os.WriteFile(adminFile, []byte(o.adminToken), 0o600); err != nil {
			t.Fatalf("loopback: write admin_token file: %v", err)
		}
		auth["admin_token_file"] = adminFile
	}

	doc := map[string]any{
		"auth":     auth,
		"artifact": map[string]any{"dir": artifactDir},
	}

	if o.policy != nil {
		// WithPolicy: the caller supplied a whole *policy.Policy. Marshal it
		// as the base document instead of building one field by field, then
		// let overrides still apply on top.
		var base map[string]any
		b, err := yaml.Marshal(o.policy)
		if err != nil {
			t.Fatalf("loopback: marshal WithPolicy value: %v", err)
		}
		if err := yaml.Unmarshal(b, &base); err != nil {
			t.Fatalf("loopback: re-decode WithPolicy value: %v", err)
		}
		for k, v := range doc {
			base[k] = v
		}
		doc = base
	}

	for k, v := range o.overrides {
		setDottedKey(doc, k, v)
	}

	b, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("loopback: marshal policy document: %v", err)
	}
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("loopback: write policy file: %v", err)
	}

	store, err := policy.NewStore(path, clk, logger)
	if err != nil {
		t.Fatalf("loopback: load policy: %v", err)
	}
	return path, store
}

// setDottedKey sets doc's nested map at the dotted path key (e.g.
// "limits.shutdown_grace_period") to value, creating intermediate maps as
// needed. It is what makes WithPolicyOverride generic over every policy key
// with no per-key plumbing: the strict-mode loader's KnownFields(true) is
// the backstop that fails a typo'd key loudly rather than leaving the
// default silently in place.
func setDottedKey(doc map[string]any, dottedKey string, value any) {
	parts := strings.Split(dottedKey, ".")
	m := doc
	for _, p := range parts[:len(parts)-1] {
		next, ok := m[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[p] = next
		}
		m = next
	}
	m[parts[len(parts)-1]] = value
}

// TestAccount builds an Account fixture for the harness's register-mode
// tests (Phase 1 replacement for TestProfile). pass travels as a PLAIN
// STRING, matching ua_create's own inline `auth_pass` field (owner-accepted
// for this local dev tool) — there is no auth_pass_file indirection to
// route it through any more. Registrar is left blank;
// MustCreateUAWithAccount fills it in at call time with the harness's own
// in-process registrar address, because TestAccount runs before New()
// starts that registrar and so cannot know its ephemeral port.
func TestAccount(name, pass string) Account {
	return Account{
		Name:      name,
		AOR:       "sip:testuser@" + name + ".invalid",
		AuthUser:  "testuser",
		AuthPass:  pass,
		Transport: "udp",
		ExpiresS:  300,
	}
}

// WritePolicyFile overwrites the harness's OWN policy file with raw content,
// for tests that need to drive SendSIGHUP against a deliberately malformed
// or hand-written document.
func (h *Harness) WritePolicyFile(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(h.policyPath, []byte(content), 0o600); err != nil {
		t.Fatalf("loopback: WritePolicyFile: %v", err)
	}
}

// PolicyLimits is U9: policy.Limits is the one canonical type; there is no
// session.Limits.
func (h *Harness) PolicyLimits(t *testing.T) policy.Limits {
	t.Helper()
	return h.store.Current().Limits
}

// ---- syncBuffer: the harness's own log capture -----------------------------

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newSyncBuffer() *syncBuffer { return &syncBuffer{} }

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// ---- handle -> owning session id bookkeeping (EvictNow, PeerSendBye/Final) -

func (h *Harness) rememberHandle(handle, sid string) {
	h.handleMu.Lock()
	defer h.handleMu.Unlock()
	h.handleOwner[handle] = sid
}

func (h *Harness) ownerOf(t *testing.T, handle string) string {
	t.Helper()
	h.handleMu.Lock()
	sid, ok := h.handleOwner[handle]
	h.handleMu.Unlock()
	if !ok {
		t.Fatalf("loopback: handle %q was never minted by this harness", handle)
	}
	return sid
}
