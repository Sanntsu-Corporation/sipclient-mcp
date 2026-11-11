package sipua_test

// CF-188: the NAT keepalive goes where REGISTER went (RFC 3263 4.2 SRV first;
// RFC 5626 3.5 the keepalive refreshes the REGISTER's flow). No t.Parallel.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakedns"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// newSRVKeepaliveUA builds a register-mode UDP UA whose portless registrar
// reg.test resolves, through the fake DNS, to srvTarget (host:port).
func newSRVKeepaliveUA(t *testing.T, srvTarget, mode string, timeout time.Duration) (*sipua.UA, *fakeclock.Clock) {
	t.Helper()
	host, port, err := net.SplitHostPort(srvTarget)
	if err != nil {
		t.Fatalf("split %q: %v", srvTarget, err)
	}
	r, _ := fakedns.Start(t, map[string][]string{
		"_sip._udp.reg.test/SRV": {fmt.Sprintf("0 0 %s sip1.reg.test.", port)},
		"sip1.reg.test/A":        {host},
	})
	t.Cleanup(sipua.SetDNSResolverForTest(r))
	clk := fakeclock.New(time.Unix(0, 0))
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "register", AOR: "sip:alice@example", Registrar: "sip:reg.test",
		AuthUser: "alice", AuthPass: "s3cr3t", Keepalive: mode, KeepaliveIntervalS: 30,
		Timeout: timeout, Clock: clk, LocalAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua, clk
}

func TestCRLFKeepaliveGoesWhereTheRegisterWent(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	ua, clk := newSRVKeepaliveUA(t, p.Addr(), "crlf", 2*time.Second)
	res, err := ua.Register(context.Background())
	if err != nil || !res.Registered {
		t.Fatalf("Register = %+v, %v", res, err)
	}
	clk.BlockUntil(2) // the keepalive and the register refresher
	clk.Advance(31 * time.Second)
	waitForCond(t, func() bool { return p.CRLFKeepalives() >= 1 })
}

func TestOptionsKeepaliveResolvesTheRegistrarLikeRegister(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	ua, clk := newSRVKeepaliveUA(t, p.Addr(), "options", 2*time.Second)
	res, err := ua.Register(context.Background())
	if err != nil || !res.Registered {
		t.Fatalf("Register = %+v, %v", res, err)
	}
	clk.BlockUntil(2)
	clk.Advance(31 * time.Second)
	waitForCond(t, func() bool { return p.Count("OPTIONS") >= 1 })
	to := p.LastRequestHeader("OPTIONS", "To")
	if !strings.Contains(to, "<sip:reg.test>") || strings.Contains(to, ":5060") {
		t.Fatalf("OPTIONS To = %q, want <sip:reg.test> with no injected port", to)
	}
}

// A REGISTER that drew no response must not move the keepalive.
func TestUnansweredRegisterDoesNotMoveTheKeepalive(t *testing.T) {
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	var crlf atomic.Int32
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := silent.ReadFrom(buf)
			if err != nil {
				return
			}
			if string(buf[:n]) == "\r\n\r\n" {
				crlf.Add(1)
			}
		}
	}()
	ua, clk := newSRVKeepaliveUA(t, silent.LocalAddr().String(), "crlf", time.Second)
	if _, err := ua.Register(context.Background()); err == nil {
		t.Fatal("Register to a silent registrar returned no error")
	}
	clk.BlockUntil(1)
	clk.Advance(31 * time.Second)
	time.Sleep(200 * time.Millisecond)
	if n := crlf.Load(); n != 0 {
		t.Fatalf("%d CRLF keepalives reached the silent registrar, want 0", n)
	}
}
