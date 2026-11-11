package sipua

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/siptest"
)

// countingConn is the P1 stand-in for P2's tee. P1 wires no pcap writer, so the
// no-untapped-socket assertion is made with a counting net.PacketConn the TEST
// installs through Config.WrapConn — which is itself proof that the D9d seam
// exists and is caller-supplied, and that it is a DECORATOR (it receives the
// already-concretely-bound conn) rather than a listener factory that could
// rebind a wildcard behind sipua's back.
type countingConn struct {
	net.PacketConn
	mu           sync.Mutex
	bytesWritten int
	writes       int
}

func (c *countingConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	c.mu.Lock()
	c.bytesWritten += n
	c.writes++
	c.mu.Unlock()
	return n, err
}

func (c *countingConn) observed() (bytes, writes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesWritten, c.writes
}

// peer is a bare UDP socket standing in for the registrar. It records the
// SOURCE ADDRESS of every datagram it receives; the number of DISTINCT source
// addresses IS the number of sockets the UA's transport opened, which is the
// quantity D9d's acceptance asserts on.
type peer struct {
	conn net.PacketConn
	mu   sync.Mutex
	srcs map[string]int
}

func newPeer(t *testing.T) *peer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	p := &peer{conn: pc, srcs: map[string]int{}}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			_, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			p.mu.Lock()
			p.srcs[addr.String()]++
			p.mu.Unlock()
		}
	}()
	return p
}

func (p *peer) addr() string { return p.conn.LocalAddr().String() }

func (p *peer) sources() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]int, len(p.srcs))
	for k, v := range p.srcs {
		out[k] = v
	}
	return out
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// sendREGISTER fires one outbound REGISTER at the peer and waits for the
// transaction to time out. No response is needed: the untapped-socket defect is
// on the FIRST OUTBOUND request, so the outbound leg alone settles it. The
// transaction error, if any, is returned rather than swallowed (D115): a test
// helper that discards the error it exists to surface is how a deterministic
// EADDRINUSE reads as an innocuous empty source map instead of the actual
// defect. It is also t.Logf'd here so it is visible even where the caller
// (case 1 and case 2) doesn't inspect the return value.
func sendREGISTER(t *testing.T, u *UA, viaAddr, peerAddr string) error {
	t.Helper()
	cfg := config.Config{
		LocalAddr:  viaAddr,
		TargetURI:  "sip:" + peerAddr,
		FromUser:   "alice",
		FromDomain: "example.net",
	}
	req := siptest.BuildRegister(cfg, u.Transport())
	req.SetDestination(peerAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	// Raw() reaches the underlying *sipgo.Client; Client() is the vendored
	// wrapper, which is what Tasks 14-16 need for DoRequestWithDigest,
	// RawTransaction and Raw itself.
	tx, err := u.Client().Raw().TransactionRequest(ctx, req)
	if err != nil {
		// A transport-level failure is itself a result: the assertions below
		// read the sockets (or, in case 3, this returned error), not the
		// transaction outcome.
		t.Logf("sendREGISTER: transaction error (read as a socket-level result, not a failure): %v", err)
		return err
	}
	defer tx.Terminate()
	select {
	case <-tx.Done():
	case <-ctx.Done():
	}
	return nil
}

// Case 1 of D9d's no-untapped-socket acceptance: concrete bind, pinned Via.
func TestNoUntappedSocketConcreteBindPinnedVia(t *testing.T) {
	p := newPeer(t)
	var counted *countingConn

	ua, err := New(context.Background(), Config{
		Transport: "udp",
		Mode:      "register",
		AOR:       "sip:alice@example",
		Registrar: "sip:" + p.addr(),
		LocalAddr: "127.0.0.1:0",
		Logger:    testLogger(),
		Clock:     clock.System(),
		// The D9d seam is a DECORATOR over the conn sipua has already bound to a
		// concrete address, never a listener factory.
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			counted = &countingConn{PacketConn: pc}
			return counted
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = ua.Close(context.Background()) }()

	_ = sendREGISTER(t, ua, ua.BoundAddr().String(), p.addr())

	srcs := p.sources()
	if len(srcs) != 1 {
		t.Fatalf("peer saw %d distinct source addresses %v, want exactly 1 "+
			"(a second address means sipgo opened an untapped socket)", len(srcs), srcs)
	}
	if _, ok := srcs[ua.BoundAddr().String()]; !ok {
		t.Fatalf("peer saw source %v, want the UA's bound address %s", srcs, ua.BoundAddr())
	}
	if b, w := counted.observed(); b == 0 || w == 0 {
		t.Fatalf("the tapped conn observed %d bytes in %d writes; want non-zero "+
			"— zero means the message left through a socket the tap does not wrap", b, w)
	}
}

// Case 2 of D9d's no-untapped-socket acceptance: concrete bind, Via
// deliberately left unpinned. The assertion MUST fire — a second socket is
// attempted (or the send fails outright) and the tapped conn observes zero
// bytes.
//
// The Via host here is "localhost", NOT "" (D112): an empty Config.LocalAddr
// reaches siptest.NewClient -> sipgo.WithClientAddr("") -> sip.ParseAddr(""),
// which errors with "missing port in address" before any UA is even
// constructed — that fails at newUA's own error return, not at the assertion
// this test exists to fire. "localhost" is routable but not an IP literal, so
// it genuinely reaches sipgo's laddr.IP != nil guard
// (sip/transport_layer.go:341-346) and fails it, taking the same
// createConnection fall-through (sip/transport_udp.go:99-127) an unpinned Via
// would in production.
func TestNoUntappedSocketUnpinnedViaFiresTheAssertion(t *testing.T) {
	p := newPeer(t)

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	counted := &countingConn{PacketConn: conn}

	_, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("split bound addr: %v", err)
	}
	unpinnedVia := net.JoinHostPort("localhost", port)

	tcpTwin, err := net.Listen("tcp", conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("tcp twin listen: %v", err)
	}

	ua, err := newUA(context.Background(), Config{
		Transport: "udp",
		Logger:    testLogger(),
		Clock:     clock.System(),
	}, counted, tcpTwin, unpinnedVia) // a non-IP-literal host: the Via is not pinned
	if err != nil {
		t.Fatalf("newUA: %v", err)
	}
	defer func() { _ = ua.Close(context.Background()) }()

	sendErr := sendREGISTER(t, ua, unpinnedVia, p.addr())

	if b, _ := counted.observed(); b != 0 {
		t.Fatalf("expected the tapped conn to observe 0 bytes with an unpinned Via, got %d", b)
	}
	if sendErr == nil || !strings.Contains(sendErr.Error(), "address already in use") {
		t.Fatalf("expected sipgo's second-socket attempt to fail with "+
			"'address already in use' (an unpinned Via falls through to "+
			"createConnection, which tries to rebind the address the concrete "+
			"listen already holds), got %v", sendErr)
	}
}

// Case 3 of D9d's no-untapped-socket acceptance: the listener is bound to
// 0.0.0.0:<port> DIRECTLY BY THE TEST, bypassing ua_create's resolution, with
// the Via pinned to a routable 127.0.0.1:<port>.
//
// D113: the brief's original assertion here read `srcs=map[]` with a swallowed
// EADDRINUSE and called that a pass — but that observation is IDENTICAL
// whether D110's defect is present or absent, so it has zero discriminating
// power. This version asserts on the OBSERVED TRANSPORT ERROR instead: the
// pool is keyed by conn.LocalAddr().String() — literally "0.0.0.0:<port>"
// (sip/transport_udp.go:65) — so the lookup at sip/transport_layer.go:344 for
// "127.0.0.1:<port>" misses even though the Via is perfectly well pinned, and
// sipgo's createConnection fall-through (sip/transport_udp.go:99-127) tries to
// open a SECOND listener on 127.0.0.1:<port> — a port the wildcard bind
// already owns on every interface — which fails with EADDRINUSE. That failure
// IS the untapped-socket attempt made visible: a real (non-wildcard) network
// topology would let the second socket actually open and send, which is
// exactly what case 1 exists to catch when the Via is NOT pinned to the bound
// address.
func TestNoUntappedSocketWildcardBindAttemptsASecondSocket(t *testing.T) {
	p := newPeer(t)

	conn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("wildcard listen: %v", err)
	}
	counted := &countingConn{PacketConn: conn}

	_, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("split bound addr: %v", err)
	}
	routableVia := net.JoinHostPort("127.0.0.1", port)

	tcpTwin, err := net.Listen("tcp", conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("tcp twin listen: %v", err)
	}

	ua, err := newUA(context.Background(), Config{
		Transport: "udp",
		Logger:    testLogger(),
		Clock:     clock.System(),
	}, counted, tcpTwin, routableVia)
	if err != nil {
		t.Fatalf("newUA: %v", err)
	}
	defer func() { _ = ua.Close(context.Background()) }()

	if !ua.BoundAddr().IP.IsUnspecified() {
		t.Fatalf("this case requires a wildcard bind, got %q", ua.BoundAddr())
	}

	sendErr := sendREGISTER(t, ua, routableVia, p.addr())

	if b, _ := counted.observed(); b != 0 {
		t.Fatalf("expected the tapped wildcard conn to observe 0 bytes, got %d", b)
	}
	if sendErr == nil || !strings.Contains(sendErr.Error(), "address already in use") {
		t.Fatalf("expected sipgo's second-socket attempt to fail with "+
			"'address already in use' (pool key %q does not match the pinned Via "+
			"%q), got %v", ua.BoundAddr(), routableVia, sendErr)
	}
}

// §15's P1 row: local_addr="0.0.0.0:<port>" on a host with a route to the peer
// yields a UA whose Via host is the concrete resolved IP and NOT 0.0.0.0. A
// kernel-chosen port is used instead of the literal 5060 so the test cannot
// collide in CI; the ua_create tool task re-asserts the literal "0.0.0.0:5060"
// at the tool surface.
func TestNewResolvesWildcardLocalAddrToAConcreteViaHost(t *testing.T) {
	p := newPeer(t)

	ua, err := New(context.Background(), Config{
		Transport: "udp",
		Mode:      "register",
		AOR:       "sip:alice@example",
		Registrar: "sip:" + p.addr(),
		LocalAddr: "0.0.0.0:0",
		Logger:    testLogger(),
		Clock:     clock.System(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = ua.Close(context.Background()) }()

	host := ua.BoundAddr().IP.String()
	if ua.BoundAddr().IP.IsUnspecified() {
		t.Fatalf("listener bound to a wildcard %q; D9d requires a concrete IP", host)
	}
	if net.ParseIP(host) == nil {
		t.Fatalf("Via host %q is not an IP literal; sipgo's net.ParseIP(viaHop.Host) "+
			"at sip/transport_layer.go:336 would return nil", host)
	}
	if ua.BoundAddr().Zone != "" || strings.Contains(ua.BoundAddr().String(), "%") {
		t.Fatalf("bound address %q carries an IPv6 zone, which cannot appear in a Via",
			ua.BoundAddr())
	}
	// LocalAddr() and BoundAddr() are both freshly synthesized from
	// boundIP/boundPort (W6) and, for tcp/tls, of different concrete types
	// (*net.TCPAddr vs *net.UDPAddr), so pointer identity no longer holds
	// (P2 W2c T2). The invariant that actually matters — advertised addr ==
	// bound addr — is value equality on IP+port.
	la, ba := ua.LocalAddr(), ua.BoundAddr()
	lh, lp, _ := net.SplitHostPort(la.String())
	bh, bp, _ := net.SplitHostPort(ba.String())
	if lh != bh || lp != bp {
		t.Errorf("LocalAddr() %s and BoundAddr() %s must share IP:port", la, ba)
	}

	cfg := config.Config{LocalAddr: ua.BoundAddr().String(), TargetURI: "sip:" + p.addr(),
		FromUser: "alice", FromDomain: "example.net"}
	msg := siptest.BuildRegister(cfg, ua.Transport()).String()
	if strings.Contains(msg, "0.0.0.0") {
		t.Fatalf("REGISTER carries 0.0.0.0:\n%s", msg)
	}
	if !strings.Contains(msg, "SIP/2.0/UDP "+host) {
		t.Fatalf("Via does not pin the bound host %q:\n%s", host, msg)
	}
}

// tcp is wired as of P2 W2c T2 (see TestTCPUABindsAndReportsTCPLocalAddr) and
// tls as of T3 (see TestTLSInboundAndOutboundCallsComplete in
// ua_tls_test.go); both former TestNewRejectsUnwiredTransports cases are now
// wired, so that test is removed rather than left asserting a behavior T3
// intentionally changed.
func TestNewRejectsUnknownTransport(t *testing.T) {
	ua, err := New(context.Background(), Config{
		Transport: "sctp",
		LocalAddr: "127.0.0.1:0",
		Logger:    testLogger(),
		Clock:     clock.System(),
	})
	if ua != nil {
		t.Fatal("a UA was created for an unknown transport")
	}
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != apierr.CodeInvalidArgument {
		t.Fatalf("err = %v (%T), want *apierr.Error with code invalid_argument", err, err)
	}
}

// D114: newUA's ctx watcher goroutine (`<-ctx.Done(); conn.Close()`) blocked on
// the long-lived DAEMON context (locked decision 17), and Close did not cancel
// it — one goroutine leaked per UA until daemon shutdown. The fix derives a
// per-UA context.WithCancel(ctx) that Close cancels. This asserts the fixed
// behavior directly: ten create/close cycles must leave the goroutine count
// unchanged, not +10.
func TestCloseDoesNotLeakTheCtxWatcherGoroutine(t *testing.T) {
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()

	for i := 0; i < 10; i++ {
		ua, err := New(context.Background(), Config{
			Transport: "udp",
			Mode:      "direct",
			LocalAddr: "127.0.0.1:0",
			Logger:    testLogger(),
			Clock:     clock.System(),
		})
		if err != nil {
			t.Fatalf("New (cycle %d): %v", i, err)
		}
		if err := ua.Close(context.Background()); err != nil {
			t.Fatalf("Close (cycle %d): %v", i, err)
		}
	}

	runtime.GC()
	time.Sleep(500 * time.Millisecond)
	after := runtime.NumGoroutine()

	if delta := after - before; delta != 0 {
		t.Fatalf("goroutine delta after 10 create/close cycles = %d (before=%d after=%d), "+
			"want 0 — a per-UA ctx watcher goroutine leaked", delta, before, after)
	}
}

// newTestUAWithDaemonCtx builds a UA whose daemon context is the
// CALLER-SUPPLIED ctx, so a test can hold its own handle on the daemon ctx and
// assert on it independently of the UA's own lifetime (I7).
func newTestUAWithDaemonCtx(daemonCtx context.Context, t *testing.T) *UA {
	t.Helper()
	ua, err := New(daemonCtx, Config{
		Transport: "udp",
		Mode:      "direct",
		LocalAddr: "127.0.0.1:0",
		Logger:    testLogger(),
		Clock:     clock.System(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ua
}

// ringGoroutine is a handle a test passes to waitGoroutineExit to confirm the
// armRingTimeout goroutine startInboundRinging spawned has actually exited.
// It carries no state: the real signal is armRingTimeoutStackMarker's
// presence/absence in a live runtime.Stack dump (see goroutineStackContains).
// A plain total-goroutine-count comparison was tried first and rejected —
// runtime.NumGoroutine() is perturbed by unrelated goroutines (GC workers,
// this package's own already-fixed per-UA ctx-watcher goroutine exiting
// alongside the one under test) enough to make the count cross the baseline
// even with the bug present, which is a false GREEN this test exists to
// avoid. Grepping live stacks for the target function's own name pins down
// that ONE goroutine precisely, independent of anything else running.
type ringGoroutine struct{}

// armRingTimeoutStackMarker is the substring runtime.Stack renders for
// armRingTimeout's goroutine literal (call.go): the method name followed by
// ".func1" per Go's closure-naming convention.
const armRingTimeoutStackMarker = "UA).armRingTimeout.func1"

// goroutineStackContains reports whether any currently running goroutine's
// stack trace contains needle.
func goroutineStackContains(needle string) bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Contains(string(buf[:n]), needle)
}

// startInboundRinging arms a ring-timeout goroutine directly, the same way
// onInvite does via u.armRingTimeout, without needing a full inbound INVITE
// over the wire. It leaves the timeout at DefaultInboundRingTimeout (60s) —
// far longer than any assertion this test makes — so within the test's
// window the goroutine can only exit via ctx.Done(), never the timer firing.
// It blocks until the goroutine has actually started and parked on its
// select (confirmed via its own stack trace), so waitGoroutineExit only ever
// observes an exit, never a race against startup.
func (u *UA) startInboundRinging(t *testing.T) *ringGoroutine {
	t.Helper()
	d := &dialog{id: newDialogID(), phase: phaseRinging}
	u.armRingTimeout(d)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if goroutineStackContains(armRingTimeoutStackMarker) {
			return &ringGoroutine{}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("armRingTimeout goroutine did not start within 2s")
	return nil
}

// waitGoroutineExit polls until no goroutine's stack contains
// armRingTimeoutStackMarker — i.e. the ring-timeout goroutine
// startInboundRinging spawned has actually exited — or fails the test if it
// never does within the deadline: a timeout, not a hang, when the goroutine
// is still parked on the wrong context.
func waitGoroutineExit(t *testing.T, _ *ringGoroutine) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !goroutineStackContains(armRingTimeoutStackMarker) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("ring-timeout goroutine did not exit within 2s")
}

// TestUA_GoroutinesKeyOffUACtxNotDaemon is I7: closing one UA must stop its
// per-UA background goroutines promptly, without touching the daemon context
// other UAs (and the daemon itself) still depend on. Before the fix,
// armRingTimeout's goroutine selects on u.daemonCtx.Done(), so u.Close (which
// only cancels the per-UA uaCtx) never unblocks it — it leaks until the
// daemon itself shuts down.
func TestUA_GoroutinesKeyOffUACtxNotDaemon(t *testing.T) {
	daemonCtx, daemonCancel := context.WithCancel(context.Background())
	defer daemonCancel()
	u := newTestUAWithDaemonCtx(daemonCtx, t)
	// Arm a ring timeout (spawns the per-UA goroutine that today selects on
	// daemonCtx).
	d := u.startInboundRinging(t)
	if err := u.Close(context.Background()); err != nil { // cancels uaCtx, NOT daemonCtx
		t.Fatalf("Close: %v", err)
	}
	// The ring-timeout goroutine must exit promptly on uaCtx.Done().
	waitGoroutineExit(t, d)
	if daemonCtx.Err() != nil {
		t.Fatal("daemon ctx must remain live")
	}
}
