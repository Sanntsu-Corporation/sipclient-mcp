//go:build linux

package siptest_test

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/siptest"
)

// mockRegistrar captures every REGISTER received and applies a 407-then-200
// response pattern. First REGISTER -> 407 Proxy Authentication Required with
// a Digest challenge. Subsequent REGISTERs -> 200 if Proxy-Authorization is
// present, else 407 again.
type mockRegistrar struct {
	mu            sync.Mutex
	received      []*sip.Request
	ua            *sipgo.UserAgent
	srv           *sipgo.Server
	listener      net.PacketConn
	listenAddr    string
	tcpListener   net.Listener
	tcpListenAddr string
	done          atomic.Bool
	counter       atomic.Int32
}

func startMockRegistrar(t *testing.T) *mockRegistrar {
	t.Helper()
	ua, err := sipgo.NewUA(sipgo.WithUserAgentHostname("127.0.0.1"))
	if err != nil {
		t.Fatalf("NewUA: %v", err)
	}
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tcp: %v", err)
	}
	m := &mockRegistrar{
		ua:            ua,
		srv:           srv,
		listener:      listener,
		listenAddr:    listener.LocalAddr().String(),
		tcpListener:   tcpListener,
		tcpListenAddr: tcpListener.Addr().String(),
	}
	srv.OnRegister(func(req *sip.Request, tx sip.ServerTransaction) {
		m.mu.Lock()
		m.received = append(m.received, req.Clone())
		m.mu.Unlock()

		if m.counter.Add(1) == 1 {
			res := sip.NewResponseFromRequest(req, 407, "Proxy Authentication Required", nil)
			res.AppendHeader(sip.NewHeader(
				"Proxy-Authenticate",
				`Digest realm="test", nonce="abc123def456", algorithm=MD5, qop="auth"`,
			))
			if err := tx.Respond(res); err != nil {
				t.Errorf("mockRegistrar: respond 407: %v", err)
			}
			return
		}
		pa := req.GetHeader("Proxy-Authorization")
		if pa == nil {
			res := sip.NewResponseFromRequest(req, 407, "Proxy Authentication Required", nil)
			res.AppendHeader(sip.NewHeader(
				"Proxy-Authenticate",
				`Digest realm="test", nonce="abc123def456", algorithm=MD5, qop="auth"`,
			))
			_ = tx.Respond(res)
			return
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", nil)
		_ = tx.Respond(res)
	})
	go func() {
		_ = srv.ServeUDP(listener)
	}()
	go func() {
		_ = srv.ServeTCP(tcpListener)
	}()
	return m
}

func (m *mockRegistrar) stop() {
	if m.done.CompareAndSwap(false, true) {
		_ = m.listener.Close()
		_ = m.tcpListener.Close()
		_ = m.srv.Close()
		_ = m.ua.Close()
	}
}

func (m *mockRegistrar) snapshot() []*sip.Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*sip.Request, len(m.received))
	copy(out, m.received)
	return out
}

func viaBranchOf(r *sip.Request) string {
	v := r.Via()
	if v == nil || v.Params == nil {
		return ""
	}
	b, _ := v.Params.Get("branch")
	return b
}

func TestDigestRetry_OnProxy407_SecondRegisterCarriesAuthorization(t *testing.T) {
	m := startMockRegistrar(t)
	defer m.stop()

	// Client configured to hit the mock registrar.
	host, _, err := net.SplitHostPort(m.listenAddr)
	if err != nil {
		t.Fatalf("split listener addr %q: %v", m.listenAddr, err)
	}

	// Use LocalAddr with port 0 (ephemeral) so sipgo's ClientRequestAddVia
	// produces a Via with Port=0. The transport layer then takes the
	// ConnectionReuse path (transport_layer.go:348), looking up the existing
	// connection by raddr instead of laddr. This avoids the dual-stack
	// EADDRINUSE that occurred with the old cloneRequestForRetry approach
	// (which needed to pin a specific port, then had to use v.Port=0 as a
	// sentinel). With port=0, sipgo allocates an ephemeral port on the first
	// transaction and reuses that same socket for the retry.
	cfg := config.Config{
		LocalAddr:  "0.0.0.0:0",
		Transport:  "udp",
		AuthUser:   "alice",
		AuthPass:   "secret",
		FromUser:   "alice",
		FromDomain: host,
		Realm:      host,
		Timeout:    3 * time.Second,
		DoRegister: true,
		TargetURI:  m.listenAddr,
	}

	ua, err := sipgo.NewUA(sipgo.WithUserAgentHostname("127.0.0.1"))
	if err != nil {
		t.Fatalf("NewUA (client): %v", err)
	}
	defer ua.Close()

	cl, err := siptest.NewClient(cfg, ua)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer cl.Close()

	req := siptest.BuildRegister(cfg, "udp")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := cl.DoRequestWithDigest(ctx, req)
	if err != nil {
		t.Fatalf("DoRequestWithDigest: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("final status: want 200, got %d %s", res.StatusCode, res.Reason)
	}

	// Wait briefly for server-side recv to settle (best-effort; under CI
	// load consider replacing with require.Eventually polling on
	// len(snapshot()) == 2).
	time.Sleep(100 * time.Millisecond)
	received := m.snapshot()
	if got := len(received); got != 2 {
		t.Fatalf("registrar received %d REGISTERs, want exactly 2", got)
	}

	first, second := received[0], received[1]

	// Second REGISTER must carry Proxy-Authorization.
	pa := second.GetHeader("Proxy-Authorization")
	if pa == nil {
		t.Fatalf("second REGISTER missing Proxy-Authorization header")
	}
	if !strings.Contains(pa.Value(), `realm="test"`) {
		t.Errorf("second REGISTER Proxy-Authorization missing realm: %q", pa.Value())
	}

	// Via branches must differ (new transaction).
	if firstBranch, secondBranch := viaBranchOf(first), viaBranchOf(second); firstBranch == "" || firstBranch == secondBranch {
		t.Errorf("second REGISTER Via branch must differ from first: first=%q second=%q", firstBranch, secondBranch)
	}

	// CSeq must increase monotonically across the retry (RFC 3261 §20.16).
	firstC, secondC := first.CSeq(), second.CSeq()
	if firstC == nil || secondC == nil {
		t.Fatalf("missing CSeq: first=%v second=%v", firstC, secondC)
	}
	if secondC.SeqNo <= firstC.SeqNo {
		t.Errorf("CSeq must increase: first=%d second=%d", firstC.SeqNo, secondC.SeqNo)
	}
}

// TestDigestRetry_PreservesTransportOnRetry_TCP guards against a regression
// where DoRequestWithDigest's digest-retry path strips the original Via
// (to let sipgo.ClientRequestAddVia rebuild it) without first pinning the
// request's cached transport. sip.Request.Transport() falls back to
// sip.DefaultProtocol ("UDP") once the Via is gone, silently misrouting the
// retry to UDP. That's invisible when UDP and TCP listeners share a port
// (as in the E2E lab), but fatal when they don't (e.g. TLS's dedicated
// port): the retry goes nowhere and the mock registrar never sees it.
func TestDigestRetry_PreservesTransportOnRetry_TCP(t *testing.T) {
	m := startMockRegistrar(t)
	defer m.stop()

	host, _, err := net.SplitHostPort(m.tcpListenAddr)
	if err != nil {
		t.Fatalf("split tcp listener addr %q: %v", m.tcpListenAddr, err)
	}

	cfg := config.Config{
		LocalAddr:  "0.0.0.0:0",
		Transport:  "tcp",
		AuthUser:   "alice",
		AuthPass:   "secret",
		FromUser:   "alice",
		FromDomain: host,
		Realm:      host,
		Timeout:    3 * time.Second,
		DoRegister: true,
		TargetURI:  m.tcpListenAddr,
	}

	ua, err := sipgo.NewUA(sipgo.WithUserAgentHostname("127.0.0.1"))
	if err != nil {
		t.Fatalf("NewUA (client): %v", err)
	}
	defer ua.Close()

	cl, err := siptest.NewClient(cfg, ua)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer cl.Close()

	req := siptest.BuildRegister(cfg, "tcp")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := cl.DoRequestWithDigest(ctx, req)
	if err != nil {
		t.Fatalf("DoRequestWithDigest: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("final status: want 200, got %d %s", res.StatusCode, res.Reason)
	}

	time.Sleep(100 * time.Millisecond)
	received := m.snapshot()
	if got := len(received); got != 2 {
		t.Fatalf("registrar received %d REGISTERs, want exactly 2 (second REGISTER never reached the TCP listener — misrouted to UDP?)", got)
	}

	second := received[1]
	via := second.Via()
	if via == nil {
		t.Fatalf("second REGISTER missing Via")
	}
	if via.Transport != "TCP" {
		t.Errorf("second REGISTER Via transport: want TCP, got %q", via.Transport)
	}
}
