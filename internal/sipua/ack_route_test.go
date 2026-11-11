package sipua_test

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// CF-193: every 2xx ACK is addressed by the dialog's remote target and route set.

// ackFirst starts stub A, whose 200 to the INVITE names the extra headers, dials
// it and returns A. The dial completes without waiting for an ACK at A.
func ackDial(t *testing.T, ua *sipua.UA, a *uacStub) string {
	t.Helper()
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + a.addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return res.DialogID
}

func answeringWith(extra ...string) func(*uacStub, string, net.Addr) {
	return func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) == "INVITE" {
			s.send(from, stubResponse(raw, 200, "OK", "stubtag", extra, stubSDP))
		}
	}
}

func waitAck(t *testing.T, s *uacStub) string {
	t.Helper()
	if !stubWait(func() bool { return len(s.requests("ACK")) > 0 }, 3*time.Second) {
		t.Fatal("the expected stub received no ACK")
	}
	return s.requests("ACK")[0]
}

func TestRFC3261_CF193_TwoxxAckGoesToTheRemoteTarget(t *testing.T) {
	b := sinkStub(t)
	a := startUACStub(t, answeringWith("Contact: <sip:callee@"+b.addr()+">"))
	ua := newStubUA(t)
	ackDial(t, ua, a)
	ack := waitAck(t, b)
	if got := stubRequestURI(ack); got != "sip:callee@"+b.addr() {
		t.Errorf("ACK Request-URI %q, want the 2xx's Contact", got)
	}
	if h := stubHeaders(ack, "Route"); len(h) != 0 {
		t.Errorf("ACK carries Route %v with no Record-Route", h)
	}
	time.Sleep(500 * time.Millisecond)
	if n := len(a.requests("ACK")); n != 0 {
		t.Errorf("the INVITE's first hop got %d ACK(s)", n)
	}
}

func TestTwoxxAckFollowsTheLooseRouteSet(t *testing.T) {
	b := sinkStub(t)
	r1, r2 := sinkStub(t), sinkStub(t)
	a := startUACStub(t, answeringWith(
		"Record-Route: <sip:"+r2.addr()+";lr>", "Record-Route: <sip:"+r1.addr()+";lr>",
		"Contact: <sip:callee@"+b.addr()+">"))
	ua := newStubUA(t)
	ackDial(t, ua, a)
	ack := waitAck(t, r1)
	if got := stubRequestURI(ack); got != "sip:callee@"+b.addr() {
		t.Errorf("ACK Request-URI %q, want the remote target", got)
	}
	routes := stubHeaders(ack, "Route")
	if len(routes) != 2 || !strings.Contains(routes[0], r1.addr()) || !strings.Contains(routes[1], r2.addr()) {
		t.Errorf("Route headers %v, want r1 then r2", routes)
	}
}

func TestTwoxxAckFollowsAStrictRouteSet(t *testing.T) {
	b := sinkStub(t)
	r1 := sinkStub(t)
	a := startUACStub(t, answeringWith("Record-Route: <sip:"+r1.addr()+">", "Contact: <sip:callee@"+b.addr()+">"))
	ua := newStubUA(t)
	ackDial(t, ua, a)
	ack := waitAck(t, r1)
	if got := stubRequestURI(ack); got != "sip:"+r1.addr() {
		t.Errorf("ACK Request-URI %q, want the strict router", got)
	}
	routes := stubHeaders(ack, "Route")
	if len(routes) == 0 || !strings.Contains(routes[len(routes)-1], "callee@"+b.addr()) {
		t.Errorf("last Route %v, want the remote target (12.2.1.1 strict)", routes)
	}
}

// credentialedAckUA is a UA whose AOR host is 127.0.0.1 with digest credentials.
func credentialedAckUA(t *testing.T, anyHost bool) *sipua.UA {
	t.Helper()
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@127.0.0.1", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		AuthUser: "alice", AuthPass: "s3cr3t", AuthAnyHost: anyHost,
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	_ = collect(t, ua)
	return ua
}

// challengingStub407s an uncredentialed INVITE and answers the credentialed
// retry 200 naming contact.
func challengingStub(t *testing.T, contact string) *uacStub {
	t.Helper()
	return startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		if len(stubHeaders(raw, "Proxy-Authorization")) == 0 {
			s.send(from, stubResponse(raw, 407, "Proxy Authentication Required", "stubtag", []string{
				`Proxy-Authenticate: Digest realm="cf6b",nonce="fedcba9876543210fedcba9876543210",qop="auth",algorithm=MD5`}, ""))
			return
		}
		s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{"Contact: <sip:callee@" + contact + ">"}, stubSDP))
	})
}

func TestTwoxxAckWithholdsCredentialsFromAForeignTarget(t *testing.T) {
	b := startUACStubAt(t, "127.0.0.2:0", func(*uacStub, string, net.Addr) {})
	a := challengingStub(t, b.addr())
	ua := credentialedAckUA(t, false)
	ackDial(t, ua, a)
	ack := waitAck(t, b)
	if h := stubHeaders(ack, "Proxy-Authorization"); len(h) != 0 {
		t.Errorf("the ACK to a foreign remote target carries credentials %v", h)
	}
}

// The hop is checked on its own: the remote target is on the account host but the
// 2xx record-routes through a foreign proxy, so the ACK goes there and carries
// no credentials.
func TestTwoxxAckWithholdsCredentialsFromAForeignRouteHop(t *testing.T) {
	hop := startUACStubAt(t, "127.0.0.2:0", func(*uacStub, string, net.Addr) {})
	a := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		if len(stubHeaders(raw, "Proxy-Authorization")) == 0 {
			s.send(from, stubResponse(raw, 407, "Proxy Authentication Required", "stubtag", []string{
				`Proxy-Authenticate: Digest realm="cf6b",nonce="fedcba9876543210fedcba9876543210",qop="auth",algorithm=MD5`}, ""))
			return
		}
		s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{
			"Contact: <sip:callee@" + s.addr() + ">", "Record-Route: <sip:" + hop.addr() + ";lr>"}, stubSDP))
	})
	ua := credentialedAckUA(t, false)
	ackDial(t, ua, a)
	ack := waitAck(t, hop)
	if got := stubRequestURI(ack); got != "sip:callee@"+a.addr() {
		t.Errorf("ACK Request-URI %q, want the remote target", got)
	}
	if h := stubHeaders(ack, "Proxy-Authorization"); len(h) != 0 {
		t.Errorf("the ACK through a foreign route hop carries credentials %v", h)
	}
}

func TestTwoxxAckCarriesCredentialsUnderAuthAnyHost(t *testing.T) {
	b := startUACStubAt(t, "127.0.0.2:0", func(*uacStub, string, net.Addr) {})
	a := challengingStub(t, b.addr())
	ua := credentialedAckUA(t, true)
	ackDial(t, ua, a)
	ack := waitAck(t, b)
	invs := a.requests("INVITE")
	want := stubHeaders(invs[len(invs)-1], "Proxy-Authorization")
	got := stubHeaders(ack, "Proxy-Authorization")
	if len(want) != 1 || len(got) != 1 || got[0] != want[0] {
		t.Errorf("ACK Proxy-Authorization %v, want the retry's %v", got, want)
	}
}

func TestForkTwoxxAckAndByeGoToTheForksTarget(t *testing.T) {
	b := sinkStub(t)
	var mu sync.Mutex
	var inv string
	a := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		switch stubMethod(raw) {
		case "INVITE":
			mu.Lock()
			inv = raw
			mu.Unlock()
			s.send(from, stubResponse(raw, 200, "OK", "forkA", []string{"Contact: <sip:a@" + s.addr() + ">"}, stubSDP))
		case "ACK":
			if stubToTag(raw) != "forkA" {
				return
			}
			mu.Lock()
			first := inv
			mu.Unlock()
			s.send(from, stubResponse(first, 200, "OK", "forkB", []string{"Contact: <sip:b@" + b.addr() + ">"}, stubSDP))
		}
	})
	ua := newStubUA(t)
	ackDial(t, ua, a)
	ack := waitAck(t, b)
	if got := stubRequestURI(ack); got != "sip:b@"+b.addr() {
		t.Errorf("fork ACK Request-URI %q", got)
	}
	if !stubWait(func() bool { return len(b.requests("BYE")) > 0 }, 3*time.Second) {
		t.Fatal("the fork's BYE did not reach the fork's target")
	}
	if got := stubRequestURI(b.requests("BYE")[0]); got != "sip:b@"+b.addr() {
		t.Errorf("fork BYE Request-URI %q", got)
	}
}

func TestReInviteTwoxxAckGoesToTheRefreshedTarget(t *testing.T) {
	b := sinkStub(t)
	var invites atomic.Int32
	a := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		if invites.Add(1) == 1 {
			s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{
				"Contact: <sip:stub@" + s.addr() + ">", "Supported: timer", "Require: timer",
				"Session-Expires: 90;refresher=uac", "Allow: INVITE, ACK, BYE, CANCEL, UPDATE"}, stubSDP))
			return
		}
		s.send(from, stubResponse(raw, 200, "OK", "", []string{
			"Contact: <sip:moved@" + b.addr() + ">", "Session-Expires: 90;refresher=uac"}, stubSDP))
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second, Clock: clk,
		LocalAddr: "127.0.0.1:0", SessionExpiresS: 1800, MinSES: 60, SessionRefreshMethod: "invite",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	_ = collect(t, ua)
	dialStub(t, ua, a)
	a.mu.Lock()
	a.got = nil // forget the first ACK
	a.mu.Unlock()
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	ack := waitAck(t, b)
	if got := stubRequestURI(ack); got != "sip:moved@"+b.addr() {
		t.Errorf("re-INVITE ACK Request-URI %q, want the refreshed target", got)
	}
}

func TestSipsContactTwoxxOnAUDPUAIsNotAckedAndEndsTheDial(t *testing.T) {
	a := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) == "INVITE" {
			s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{"Contact: <sips:callee@" + s.addr() + ">"}, stubSDP))
		}
	})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	_, _ = ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + a.addr()})
	if !stubWait(func() bool {
		for _, e := range events() {
			if e.Kind == session.UAEventDialogEnded {
				return true
			}
		}
		return false
	}, 3*time.Second) {
		t.Fatal("the dial did not end after the unacknowledgeable 2xx")
	}
	time.Sleep(500 * time.Millisecond)
	if n := len(a.requests("ACK")); n != 0 {
		t.Errorf("%d ACK(s) sent in the clear to a sips: target", n)
	}
}

func TestSipsContactForkTwoxxIsNeitherAckedNorByed(t *testing.T) {
	b := sinkStub(t)
	var mu sync.Mutex
	var inv string
	a := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		switch stubMethod(raw) {
		case "INVITE":
			mu.Lock()
			inv = raw
			mu.Unlock()
			s.send(from, stubResponse(raw, 200, "OK", "forkA", []string{"Contact: <sip:a@" + s.addr() + ">"}, stubSDP))
		case "ACK":
			if stubToTag(raw) != "forkA" {
				return
			}
			mu.Lock()
			first := inv
			mu.Unlock()
			fb := stubResponse(first, 200, "OK", "forkB", []string{"Contact: <sips:b@" + b.addr() + ">"}, stubSDP)
			s.send(from, fb)
			s.send(from, fb)
			s.send(from, fb)
		}
	})
	ua := newStubUA(t)
	dialStub(t, ua, a)
	time.Sleep(700 * time.Millisecond)
	if n := len(b.requests("ACK")) + len(b.requests("BYE")); n != 0 {
		t.Errorf("%d ACK/BYE sent for a fork whose Contact is sips: on a UDP UA", n)
	}
	// nor to the INVITE's first hop, where the pre-CF-193 builder sent them
	if n := tagCounts(a.requests("ACK"))["forkB"] + len(a.requests("BYE")); n != 0 {
		t.Errorf("%d fork ACK/BYE sent to the INVITE's first hop", n)
	}
}
