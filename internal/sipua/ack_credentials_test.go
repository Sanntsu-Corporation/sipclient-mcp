package sipua_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// credUA is a UA with digest credentials that answers any host.
func credUA(t *testing.T) *sipua.UA {
	t.Helper()
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
	return ua
}

// credStubAndUA starts a stub that challenges an uncredentialed INVITE with
// code (407 with challengeHdr Proxy-Authenticate, or 401 with
// WWW-Authenticate) and answers the credentialed retry 200. after, when
// non-nil, runs once the 200 has been sent (to retransmit it or to fork).
func credStubAndUA(t *testing.T, code int, challengeHdr string, after func(s *uacStub, from net.Addr, ok string)) (*uacStub, *sipua.UA) {
	t.Helper()
	credHdr := "Proxy-Authorization"
	reason := "Proxy Authentication Required"
	if code == 401 {
		credHdr, reason = "Authorization", "Unauthorized"
	}
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		if len(stubHeaders(raw, credHdr)) == 0 {
			s.send(from, stubResponse(raw, code, reason, "stubtag", []string{
				challengeHdr + `: Digest realm="cf5e",nonce="fedcba9876543210fedcba9876543210",qop="auth",algorithm=MD5`,
			}, ""))
			return
		}
		ok := stubResponse(raw, 200, "OK", "stubtag", []string{"Contact: <sip:stub@" + s.addr() + ">"}, stubSDP)
		s.send(from, ok)
		if after != nil {
			after(s, from, ok)
		}
	})
	return s, credUA(t)
}

// ackOfCredentialedRetry waits for the 200's ACK and returns it with the
// credentialed retry INVITE (the second INVITE).
func ackOfCredentialedRetry(t *testing.T, s *uacStub) (ack, retry string) {
	t.Helper()
	if !stubWait(func() bool { return len(s.requests("ACK")) >= 2 }, 3*time.Second) {
		t.Fatalf("precondition: want the challenge's ACK and the 200's ACK, got %d", len(s.requests("ACK")))
	}
	invs := s.requests("INVITE")
	if len(invs) != 2 {
		t.Fatalf("precondition: want a challenge round trip and a retry, got %d INVITEs", len(invs))
	}
	for _, a := range s.requests("ACK") {
		if stubCSeq(a) == stubCSeq(invs[1]) {
			return a, invs[1]
		}
	}
	t.Fatalf("no ACK with the retried INVITE's CSeq %d", stubCSeq(invs[1]))
	return "", ""
}

func TestAckFor2xxAfterA401CarriesAuthorization(t *testing.T) {
	s, ua := credStubAndUA(t, 401, "WWW-Authenticate", nil)
	dialStub(t, ua, s)
	ack, retry := ackOfCredentialedRetry(t, s)
	got, want := stubHeaders(ack, "Authorization"), stubHeaders(retry, "Authorization")
	if len(got) != 1 || len(want) != 1 || got[0] != want[0] {
		t.Errorf("ACK Authorization = %q, want the retry's %q", got, want)
	}
	if p := stubHeaders(ack, "Proxy-Authorization"); len(p) != 0 {
		t.Errorf("ACK carries Proxy-Authorization %q after a 401", p)
	}
}

// Guard: an unchallenged 200 has no credentials to copy.
func TestAckFor2xxWithoutChallengeHasNoCredentials(t *testing.T) {
	s := startUACStub(t, answer200())
	ua := credUA(t)
	dialStub(t, ua, s)
	ack := s.requests("ACK")[0]
	if h := append(stubHeaders(ack, "Authorization"), stubHeaders(ack, "Proxy-Authorization")...); len(h) != 0 {
		t.Errorf("an unchallenged call's ACK carries credentials %q", h)
	}
}

func TestRetransmittedTwoxxReAckCarriesCredentials(t *testing.T) {
	var once sync.Once
	s, ua := credStubAndUA(t, 407, "Proxy-Authenticate", func(s *uacStub, from net.Addr, ok string) {
		once.Do(func() {
			go func() {
				time.Sleep(200 * time.Millisecond)
				s.send(from, ok)
			}()
		})
	})
	dialStub(t, ua, s)
	if !stubWait(func() bool { return len(s.requests("ACK")) >= 3 }, 3*time.Second) {
		t.Fatalf("want the challenge ACK plus two ACKs of the 200, got %d ACKs", len(s.requests("ACK")))
	}
	invs := s.requests("INVITE")
	n := 0
	for _, a := range s.requests("ACK") {
		if stubCSeq(a) != stubCSeq(invs[1]) {
			continue
		}
		n++
		if got := stubHeaders(a, "Proxy-Authorization"); len(got) != 1 {
			t.Errorf("ACK #%d of the 200 carries Proxy-Authorization %q, want one", n, got)
		}
	}
	if n != 2 {
		t.Errorf("ACKs of the 200 = %d, want 2", n)
	}
}

func TestForkTwoxxAckCarriesCredentials(t *testing.T) {
	var mu sync.Mutex
	var firstInv string
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		c := "Contact: <sip:stub@" + s.addr() + ">"
		switch stubMethod(raw) {
		case "INVITE":
			if len(stubHeaders(raw, "Proxy-Authorization")) == 0 {
				s.send(from, stubResponse(raw, 407, "Proxy Authentication Required", "stubtag", []string{
					`Proxy-Authenticate: Digest realm="cf5e",nonce="fedcba9876543210fedcba9876543210",qop="auth",algorithm=MD5`,
				}, ""))
				return
			}
			mu.Lock()
			firstInv = raw
			mu.Unlock()
			s.send(from, stubResponse(raw, 200, "OK", "forkA", []string{c}, stubSDP))
		case "ACK":
			if stubToTag(raw) != "forkA" {
				return
			}
			mu.Lock()
			inv := firstInv
			mu.Unlock()
			if inv != "" {
				s.send(from, stubResponse(inv, 200, "OK", "forkB", []string{c}, stubSDP))
			}
		}
	})
	ua := credUA(t)
	dialStub(t, ua, s)
	stubWait(func() bool { return len(s.requests("BYE")) >= 1 }, 3*time.Second)
	time.Sleep(300 * time.Millisecond)
	var forkBAck string
	for _, a := range s.requests("ACK") {
		if stubToTag(a) == "forkB" {
			forkBAck = a
		}
	}
	if forkBAck == "" {
		t.Fatal("no ACK to forkB")
	}
	if got := stubHeaders(forkBAck, "Proxy-Authorization"); len(got) != 1 {
		t.Errorf("forkB ACK carries Proxy-Authorization %q, want one", got)
	}
	byes := s.requests("BYE")
	if len(byes) != 1 || stubToTag(byes[0]) != "forkB" {
		t.Fatalf("want one BYE to forkB, got %v", tagCounts(byes))
	}
	if h := append(stubHeaders(byes[0], "Authorization"), stubHeaders(byes[0], "Proxy-Authorization")...); len(h) != 0 {
		t.Errorf("forkB BYE carries INVITE credentials %q", h)
	}
}
