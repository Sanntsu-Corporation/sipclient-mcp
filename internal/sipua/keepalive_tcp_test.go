package sipua_test

// keepalive_tcp_test.go — D-M4's coverage (D20, P4-W2-01, Phase 4 W2).
//
// keepalive.go's crlf mode has a documented fallback: on a STREAM transport
// (tcp/tls) there is no u.conn to write a bare double-CRLF to, so it falls back
// to OPTIONS. Every fixture in keepalive_test.go used Transport: "udp", so that
// branch had never executed in a test — a fallback nothing had ever taken.
//
// NAMED OBSTACLE, RECORDED PER STEP 8'S OWN INSTRUCTIONS: internal/testutil/peer
// (the `peer.Peer` double) has NO plain-TCP listener. Its only stream listener
// is TLS-wrapped, opt-in via Config.TLSCert (peer_serve.go's startTLS,
// documented at Config.TLSCert: "additionally binds a TCP listener wrapped in
// TLS" — there is no code path that binds an unwrapped one). None of the three
// TCP fixtures Step 8 names as reuse candidates (ua_tcp_test.go,
// capture_stream_test.go, ua_stream_teardown_test.go) uses the peer double at
// all — each drives two production sipua.UA instances directly against each
// other, or a raw net.Dial, so none of them exposes Count("OPTIONS") or
// CRLFKeepalives() the way this test needs.
//
// Rather than skip the row or build a novel TCP-only harness (forbidden by
// Step 8/Rule 15), this test uses Transport: "tls" against the peer double's
// existing TLS listener (peer.Config.TLSCert + tlsca, the exact fixture
// internal/sipua/tlsclassify_test.go already uses for other TLS coverage).
// This drives the IDENTICAL branch a "tcp" transport would: sendCRLFKeepalive
// (keepalive.go) tests `u.conn == nil`, which is nil for BOTH tcp and tls —
// sipua only ever populates u.conn for the udp case (ua.go) — so "stream
// transport", the test's own name, is faithfully exercised via tls without
// inventing any new test infrastructure.
import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/tlsca"
)

func TestCRLFKeepaliveFallsBackToOPTIONSOnAStreamTransport(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("tlsca.NewCA: %v", err)
	}
	leaf, err := ca.IssueLeaf(tlsca.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", TLSCert: &leaf})

	clk := fakeclock.New(time.Unix(0, 0))
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport:             "tls",
		Mode:                  "register",
		AOR:                   "sip:alice@example",
		Registrar:             "sip:" + p.TLSAddr(),
		AuthUser:              "alice",
		AuthPass:              "s3cr3t",
		Keepalive:             "crlf",
		KeepaliveIntervalS:    30,
		Timeout:               2 * time.Second,
		Clock:                 clk,
		LocalAddr:             "127.0.0.1:0",
		TLSInsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	defer func() { _ = ua.Close(context.Background()) }()

	clk.BlockUntil(1)
	clk.Advance(31 * time.Second)

	// THE ASSERTION: an OPTIONS arrives, and NO bare-CRLF ping does. Both halves
	// are needed — the first proves the fallback fired, the second proves it did
	// not ALSO try the CRLF write that has no connection to write to.
	waitForCond(t, func() bool { return p.Count("OPTIONS") >= 1 })
	if n := p.CRLFKeepalives(); n != 0 {
		t.Fatalf("peer counted %d bare-CRLF pings on a stream transport; the crlf mode must fall "+
			"back to OPTIONS entirely, not attempt both", n)
	}
}
