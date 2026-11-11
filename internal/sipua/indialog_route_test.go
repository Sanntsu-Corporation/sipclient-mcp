package sipua_test

// CF-085/086/105/108/113/171 wire tests for the in-dialog builder: first
// in-dialog CSeq, remote target, route set, Supported: timer and transport. They
// reuse Lane A's raw UDP stub and raw UAC (rfc3261_pin_uac_test.go,
// rfc3261_pin_uas_test.go). No test here calls t.Parallel.

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

func TestFirstInDialogCSeqAfterDigestRetryIsInvitePlusOne(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		if len(stubHeaders(raw, "Authorization")) == 0 {
			s.send(from, stubResponse(raw, 401, "Unauthorized", "stubtag", []string{
				`WWW-Authenticate: Digest realm="cf5c",nonce="fedcba9876543210fedcba9876543210",qop="auth",algorithm=MD5`,
			}, ""))
			return
		}
		s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{"Contact: <sip:stub@" + s.addr() + ">"}, stubSDP))
	})
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		AuthUser: "alice", AuthPass: "s3cr3t", AuthAnyHost: true,
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	_ = collect(t, ua)
	id := dialStub(t, ua, s)
	if !stubWait(func() bool { return len(s.requests("ACK")) >= 2 }, 3*time.Second) {
		t.Fatal("want the 401's ACK and the 200's ACK")
	}
	if err := ua.Hangup(context.Background(), id, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	invites := s.requests("INVITE")
	if len(invites) != 2 {
		t.Fatalf("stub saw %d INVITEs, want 2", len(invites))
	}
	if got, want := stubCSeq(s.requests("BYE")[0]), stubCSeq(invites[1])+1; got != want {
		t.Errorf("BYE CSeq %d, want the retried INVITE's %d + 1", got, want)
	}
}

// byeWithTimeout runs Hangup against a raw UAC and answers the BYE it receives.
func rawUACHangup(t *testing.T, ua *sipua.UA, r *rawUAC, id string) string {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- ua.Hangup(context.Background(), id, "") }()
	var bye string
	if !stubWait(func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, m := range r.got {
			if stubMethod(m) == "BYE" {
				bye = m
				return true
			}
		}
		return false
	}, 3*time.Second) {
		t.Fatal("the raw UAC never received a BYE")
	}
	r.send(stubResponse(bye, 200, "OK", "", nil, ""))
	if err := <-done; err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	return bye
}

func TestInboundInDialogRequestCarriesTheRouteSetInOrder(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	me := "127.0.0.1:" + r.port()
	extra := "Record-Route: <sip:" + me + ";lr;rr=1>\r\nRecord-Route: <sip:" + me + ";lr;rr=2>\r\n"
	r.send(r.invite(ruri, "cf5c-rr@127.0.0.1", "z9hG4bKcf5cRR", 10, extra))
	in := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if !stubWait(func() bool { return r.hasCode("INVITE", 200) }, 3*time.Second) {
		t.Fatal("no 200")
	}
	bye := rawUACHangup(t, ua, r, in.DialogID)
	rt := stubHeaders(bye, "Route")
	if len(rt) != 2 || !strings.Contains(rt[0], "rr=1") || !strings.Contains(rt[1], "rr=2") {
		t.Errorf("BYE Route = %v, want rr=1 then rr=2", rt)
	}
	if got, want := stubRequestURI(bye), "sip:probe@"+me; got != want {
		t.Errorf("BYE Request-URI %q, want the caller's Contact %q", got, want)
	}
}

func TestInboundStrictRouteBecomesTheRequestURI(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	me := "127.0.0.1:" + r.port()
	r.send(r.invite(ruri, "cf5c-strict@127.0.0.1", "z9hG4bKcf5cST", 10, "Record-Route: <sip:strictrouter@"+me+">\r\n"))
	in := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if !stubWait(func() bool { return r.hasCode("INVITE", 200) }, 3*time.Second) {
		t.Fatal("no 200")
	}
	bye := rawUACHangup(t, ua, r, in.DialogID)
	if got, want := stubRequestURI(bye), "sip:strictrouter@"+me; got != want {
		t.Errorf("BYE Request-URI %q, want the strict router %q", got, want)
	}
	if rt := stubHeaders(bye, "Route"); len(rt) != 1 || !strings.Contains(rt[0], "sip:probe@"+me) {
		t.Errorf("BYE Route = %v, want the remote target last", rt)
	}
}

func timerCount(vals []string) int {
	n := 0
	for _, v := range vals {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "timer") {
				n++
			}
		}
	}
	return n
}

func TestInDialogRequestsCarrySupportedTimerOnce(t *testing.T) {
	newStub := func() *uacStub {
		return startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
			switch stubMethod(raw) {
			case "INVITE":
				s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{
					"Contact: <sip:stub@" + s.addr() + ">",
					"Allow: INVITE, ACK, BYE, CANCEL, UPDATE, INFO, REFER",
					"Session-Expires: 90;refresher=uac",
					"Require: timer",
				}, stubSDP))
			case "UPDATE":
				s.send(from, stubResponse(raw, 200, "OK", "", []string{"Session-Expires: 90;refresher=uac"}, ""))
			case "INFO":
				s.send(from, stubResponse(raw, 200, "OK", "", nil, ""))
			case "REFER":
				s.send(from, stubResponse(raw, 202, "Accepted", "", []string{"Contact: <sip:stub@" + s.addr() + ">"}, ""))
			}
		})
	}
	check := func(t *testing.T, s *uacStub, method string) {
		t.Helper()
		if !stubWait(func() bool { return len(s.requests(method)) > 0 }, 3*time.Second) {
			t.Fatalf("no %s", method)
		}
		sup := stubHeaders(s.requests(method)[0], "Supported")
		if n := timerCount(sup); n != 1 {
			t.Errorf("%s lists timer %d times in Supported %v, want exactly once", method, n, sup)
		}
	}
	t.Run("INFO", func(t *testing.T) {
		s := newStub()
		ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1800, 60)
		id := dialStub(t, ua, s)
		if _, _, err := ua.SendDTMF(context.Background(), id, "1", session.DTMFModeInfo, 100, 0); err != nil {
			t.Fatalf("SendDTMF: %v", err)
		}
		check(t, s, "INFO")
	})
	t.Run("REFER", func(t *testing.T) {
		s := newStub()
		ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1800, 60)
		id := dialStub(t, ua, s)
		if out := blindTransfer(t, ua, id); !out.Accepted {
			t.Fatalf("Transfer: %+v", out)
		}
		check(t, s, "REFER")
	})
	t.Run("UPDATE", func(t *testing.T) {
		s := newStub()
		clk := fakeclock.New(time.Unix(0, 0))
		ua, _ := newSessionTimerUA(t, clk, 1800, 60)
		dialStub(t, ua, s)
		clk.BlockUntil(1)
		clk.Advance(46 * time.Second)
		check(t, s, "UPDATE")
	})
}

// tcpContactStub serves one TCP connection and returns the first request line's
// method plus its raw text; it answers 200 on the same connection.
func tcpContactStub(t *testing.T) (addr string, got chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got = make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				rd := bufio.NewReader(c)
				var b strings.Builder
				for {
					line, err := rd.ReadString('\n')
					if err != nil {
						return
					}
					b.WriteString(line)
					if line == "\r\n" {
						break
					}
				}
				raw := b.String()
				got <- raw
				_, _ = c.Write([]byte(stubResponse(raw, 200, "OK", "", nil, "")))
			}()
		}
	}()
	return ln.Addr().String(), got
}

func TestUDPUAFollowsAContactTransportTCP(t *testing.T) {
	tcpAddr, got := tcpContactStub(t)
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{"Contact: <sip:stub@" + tcpAddr + ";transport=TCP>"}, stubSDP))
	})
	ua := newStubUA(t)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + s.addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// CF-193: the 2xx ACK follows the Contact's transport and address too.
	expect := func(method string) {
		t.Helper()
		select {
		case raw := <-got:
			if stubMethod(raw) != method || !strings.Contains(stubHeaders(raw, "Via")[0], "SIP/2.0/TCP") {
				t.Errorf("TCP listener got %q, want a %s with a TCP Via", strings.SplitN(raw, "\r\n", 2)[0], method)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no %s on the Contact's TCP listener", method)
		}
	}
	expect("ACK")
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	expect("BYE")
	if n := len(s.requests("BYE")) + len(s.requests("ACK")); n != 0 {
		t.Errorf("%d ACK/BYE(s) also went over UDP", n)
	}
}

func TestUDPUAIgnoresAContactTransportWSSAndTLS(t *testing.T) {
	for _, tp := range []string{"wss", "tls"} {
		t.Run(tp, func(t *testing.T) {
			s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
				if stubMethod(raw) != "INVITE" {
					return
				}
				s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{"Contact: <sip:stub@" + s.addr() + ";transport=" + tp + ">"}, stubSDP))
			})
			ua := newStubUA(t)
			id := dialStub(t, ua, s)
			if err := ua.Hangup(context.Background(), id, ""); err != nil {
				t.Fatalf("Hangup: %v", err)
			}
			if !stubWait(func() bool { return len(s.requests("BYE")) > 0 }, 3*time.Second) {
				t.Fatal("the BYE did not reach the UDP stub")
			}
		})
	}
}

func TestSipsRemoteTargetOnAUDPUAIsNeverSentOverUDP(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	r.send(strings.Replace(r.invite(ruri, "cf5c-sips@127.0.0.1", "z9hG4bKcf5cSIPS", 10, ""),
		"Contact: <sip:probe@", "Contact: <sips:probe@", 1))
	in := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if !stubWait(func() bool { return r.hasCode("INVITE", 200) }, 3*time.Second) {
		t.Fatal("no 200")
	}
	err := ua.Hangup(context.Background(), in.DialogID, "")
	if err == nil || !strings.Contains(err.Error(), "sips") {
		t.Fatalf("Hangup err = %v, want a sips refusal", err)
	}
	time.Sleep(time.Second)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.got {
		if stubMethod(m) == "BYE" {
			t.Fatal("a BYE reached the raw UAC over UDP")
		}
	}
}
