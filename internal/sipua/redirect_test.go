package sipua_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

func redirectIdentity(s string) (string, error) { return s, nil }

// ruriUser is the user part of a request's Request-URI.
func ruriUser(raw string) string {
	u := stubRequestURI(raw)
	_, rest, _ := strings.Cut(u, ":")
	user, _, ok := strings.Cut(rest, "@")
	if !ok {
		return ""
	}
	return user
}

func fromTag(raw string) string {
	_, tag, _ := strings.Cut(stubHeaders(raw, "From")[0], "tag=")
	tag, _, _ = strings.Cut(tag, ";")
	return tag
}

func viaBranch(raw string) string {
	_, b, _ := strings.Cut(stubHeaders(raw, "Via")[0], "branch=")
	b, _, _ = strings.Cut(b, ";")
	return b
}

func dialRedirect(t *testing.T, ua *sipua.UA, to string, budget int, check func(string) (string, error)) session.DialResult {
	t.Helper()
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: to, MaxRedirects: budget, CheckRedirect: check})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return res
}

func redirectUA(t *testing.T) (*sipua.UA, func() []session.UAEvent) {
	t.Helper()
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	return ua, collect(t, ua)
}

func send302(s *uacStub, raw string, from net.Addr, contacts ...string) {
	hdrs := []string{}
	for _, c := range contacts {
		hdrs = append(hdrs, "Contact: "+c)
	}
	s.send(from, stubResponse(raw, 302, "Moved Temporarily", "stubtag", hdrs, ""))
}

func answerOK(s *uacStub, raw string, from net.Addr) {
	s.send(from, stubResponse(raw, 200, "OK", "stubtag2",
		[]string{"Contact: <sip:stub@" + s.addr() + ">"}, stubSDP))
}

// Guard: no opt-in, no following.
func TestRedirectIsNotFollowedWithoutOptIn(t *testing.T) {
	cases := map[string]struct {
		max   int
		check func(string) (string, error)
	}{
		"NilCheck":   {3, nil},
		"ZeroBudget": {0, redirectIdentity},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
				if stubMethod(raw) == "INVITE" {
					send302(s, raw, from, "<sip:alt@"+s.addr()+">")
				}
			})
			ua, events := redirectUA(t)
			dialRedirect(t, ua, "sip:bob@"+s.addr(), tc.max, tc.check)
			ev := waitFor(t, events, session.UAEventFinal, 302)
			time.Sleep(200 * time.Millisecond)
			if n := len(s.requests("INVITE")); n != 1 {
				t.Errorf("INVITEs = %d, want 1", n)
			}
			if ev.Reason != "Moved Temporarily" {
				t.Errorf("final reason = %q, want the 302's own", ev.Reason)
			}
		})
	}
}

func TestRedirectBudgetBoundsTheDial(t *testing.T) {
	for _, tc := range []struct{ max, invites int }{{3, 4}, {1, 2}} {
		t.Run(strconv.Itoa(tc.max), func(t *testing.T) {
			var mu sync.Mutex
			n := 0
			s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
				if stubMethod(raw) != "INVITE" {
					return
				}
				mu.Lock()
				n++
				k := n
				mu.Unlock()
				send302(s, raw, from, "<sip:alt"+strconv.Itoa(k)+"@"+s.addr()+">")
			})
			ua, events := redirectUA(t)
			dialRedirect(t, ua, "sip:bob@"+s.addr(), tc.max, redirectIdentity)
			waitFor(t, events, session.UAEventFinal, 302)
			time.Sleep(300 * time.Millisecond)
			if got := len(s.requests("INVITE")); got != tc.invites {
				t.Errorf("INVITEs = %d, want %d", got, tc.invites)
			}
		})
	}
}

func TestRedirectToAVisitedURIIsNotRetried(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		if ruriUser(raw) == "bob" {
			send302(s, raw, from, "<sip:alt@"+s.addr()+">")
		} else {
			send302(s, raw, from, "<sip:bob@"+s.addr()+">")
		}
	})
	ua, events := redirectUA(t)
	dialRedirect(t, ua, "sip:bob@"+s.addr(), 3, redirectIdentity)
	waitFor(t, events, session.UAEventFinal, 302)
	time.Sleep(300 * time.Millisecond)
	if got := len(s.requests("INVITE")); got != 2 {
		t.Errorf("INVITEs = %d, want 2", got)
	}
}

func TestRedirectTriesContactsInQOrderAndFailsOver(t *testing.T) {
	run := func(t *testing.T, highCode int) (*uacStub, func() []session.UAEvent) {
		s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
			if stubMethod(raw) != "INVITE" {
				return
			}
			switch ruriUser(raw) {
			case "bob":
				send302(s, raw, from, "<sip:low@"+s.addr()+">;q=0.1", "<sip:high@"+s.addr()+">;q=0.9")
			case "high":
				s.send(from, stubResponse(raw, highCode, "Fail", "stubtag", nil, ""))
			case "low":
				answerOK(s, raw, from)
			}
		})
		ua, events := redirectUA(t)
		dialRedirect(t, ua, "sip:bob@"+s.addr(), 3, redirectIdentity)
		return s, events
	}
	t.Run("FailsOver", func(t *testing.T) {
		s, events := run(t, 486)
		waitFor(t, events, session.UAEventFinal, 200)
		invs := s.requests("INVITE")
		if len(invs) != 3 || ruriUser(invs[1]) != "high" || ruriUser(invs[2]) != "low" {
			t.Errorf("INVITE users = %v, want bob, high, low", users(invs))
		}
	})
	t.Run("SixHundredStops", func(t *testing.T) {
		s, events := run(t, 603)
		waitFor(t, events, session.UAEventFinal, 603)
		time.Sleep(300 * time.Millisecond)
		if got := len(s.requests("INVITE")); got != 2 {
			t.Errorf("INVITEs = %d, want 2 (no failover on a 6xx)", got)
		}
	})
}

func users(reqs []string) []string {
	var out []string
	for _, r := range reqs {
		out = append(out, ruriUser(r))
	}
	return out
}

func TestRedirectSkipsUnacceptableContacts(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		if ruriUser(raw) == "bob" {
			send302(s, raw, from, "<tel:+15550100>", "<http://x>", "<sip:denied@"+s.addr()+">",
				"<sips:s@"+s.addr()+">", "<sip:ok@"+s.addr()+">")
			return
		}
		answerOK(s, raw, from)
	})
	ua, events := redirectUA(t)
	check := func(t string) (string, error) {
		if strings.Contains(t, "denied") {
			return "", errors.New("denied")
		}
		return t, nil
	}
	dialRedirect(t, ua, "sip:bob@"+s.addr(), 3, check)
	waitFor(t, events, session.UAEventFinal, 200)
	invs := s.requests("INVITE")
	if len(invs) != 2 || ruriUser(invs[1]) != "ok" {
		t.Errorf("INVITE users = %v, want bob, ok", users(invs))
	}
}

func TestRedirect305And380AreNotFollowed(t *testing.T) {
	for _, code := range []int{305, 380, 303} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
				if stubMethod(raw) == "INVITE" {
					s.send(from, stubResponse(raw, code, "Other", "stubtag",
						[]string{"Contact: <sip:alt@" + s.addr() + ">"}, ""))
				}
			})
			ua, events := redirectUA(t)
			dialRedirect(t, ua, "sip:bob@"+s.addr(), 3, redirectIdentity)
			waitFor(t, events, session.UAEventFinal, code)
			time.Sleep(200 * time.Millisecond)
			if got := len(s.requests("INVITE")); got != 1 {
				t.Errorf("INVITEs = %d, want 1", got)
			}
		})
	}
}

func TestHangupBetweenRedirectLegsSendsNoInvite(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) == "INVITE" {
			send302(s, raw, from, "<sip:alt@"+s.addr()+">")
		}
	})
	ua, _ := redirectUA(t)
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	check := func(t string) (string, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-gate
		return t, nil
	}
	res := dialRedirect(t, ua, "sip:bob@"+s.addr(), 3, check)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("CheckRedirect never ran")
	}
	hung := make(chan error, 1)
	start := time.Now()
	go func() { hung <- ua.Hangup(context.Background(), res.DialogID, "") }()
	if !stubWait(func() bool { return sipua.HangupPendingForTest(ua, res.DialogID) }, 3*time.Second) {
		t.Fatal("the hangup was never recorded")
	}
	close(gate)
	select {
	case err := <-hung:
		if err != nil {
			t.Errorf("Hangup = %v, want nil", err)
		}
		if time.Since(start) > 2*time.Second {
			t.Error("Hangup waited out cancelWaitCap")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("Hangup never returned")
	}
	time.Sleep(500 * time.Millisecond)
	if got := len(s.requests("INVITE")); got != 1 {
		t.Errorf("INVITEs = %d, want 1 (no INVITE after the hangup)", got)
	}
	if _, ok := ua.MediaView(res.DialogID); ok {
		t.Error("the dialog is still registered")
	}
}

func TestHangupDuringRedirectedLegCancelsThatLeg(t *testing.T) {
	var mu sync.Mutex
	var leg2 string
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		switch stubMethod(raw) {
		case "INVITE":
			s.send(from, stubResponse(raw, 180, "Ringing", "stubtag", []string{"Contact: <sip:stub@" + s.addr() + ">"}, ""))
			if ruriUser(raw) == "bob" {
				time.Sleep(50 * time.Millisecond)
				send302(s, raw, from, "<sip:alt@"+s.addr()+">")
			} else {
				mu.Lock()
				leg2 = raw
				mu.Unlock()
			}
		case "CANCEL":
			s.send(from, stubResponse(raw, 200, "OK", "", nil, ""))
			mu.Lock()
			inv := leg2
			mu.Unlock()
			if inv != "" {
				s.send(from, stubResponse(inv, 487, "Request Terminated", "stubtag", nil, ""))
			}
		}
	})
	ua, events := redirectUA(t)
	res := dialRedirect(t, ua, "sip:bob@"+s.addr(), 3, redirectIdentity)
	if !stubWait(func() bool {
		n := 0
		for _, ev := range events() {
			if ev.Kind == session.UAEventProvisional {
				n++
			}
		}
		return n >= 2
	}, 3*time.Second) {
		t.Fatal("the redirected leg never rang")
	}
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 487)
	time.Sleep(300 * time.Millisecond)
	cancels := s.requests("CANCEL")
	if len(cancels) != 1 {
		t.Fatalf("CANCELs = %d, want 1", len(cancels))
	}
	invs := s.requests("INVITE")
	if len(invs) != 2 {
		t.Fatalf("INVITEs = %d, want 2", len(invs))
	}
	if stubRequestURI(cancels[0]) != stubRequestURI(invs[1]) || viaBranch(cancels[0]) != viaBranch(invs[1]) {
		t.Errorf("the CANCEL (%s, %s) is not for leg 2 (%s, %s)", stubRequestURI(cancels[0]), viaBranch(cancels[0]),
			stubRequestURI(invs[1]), viaBranch(invs[1]))
	}
}

func TestSDESDialFinalReasonIsTheResponseOwn(t *testing.T) {
	t.Run("486", func(t *testing.T) {
		s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
			if stubMethod(raw) == "INVITE" {
				s.send(from, stubResponse(raw, 486, "Busy Here", "stubtag", nil, ""))
			}
		})
		ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "required")
		events := collect(t, ua)
		dialRedirect(t, ua, "sip:bob@"+s.addr(), 3, redirectIdentity)
		if ev := waitFor(t, events, session.UAEventFinal, 486); ev.Reason != "Busy Here" {
			t.Errorf("reason = %q, want Busy Here", ev.Reason)
		}
	})
	t.Run("BudgetZero", func(t *testing.T) {
		s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
			if stubMethod(raw) == "INVITE" {
				send302(s, raw, from, "<sip:alt@"+s.addr()+">")
			}
		})
		ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "required")
		events := collect(t, ua)
		dialRedirect(t, ua, "sip:bob@"+s.addr(), 0, redirectIdentity)
		if ev := waitFor(t, events, session.UAEventFinal, 302); ev.Reason != "Moved Temporarily" {
			t.Errorf("reason = %q, want the 302's own", ev.Reason)
		}
	})
}

func TestRedirectFromAHostnameTargetGoesToTheNewHost(t *testing.T) {
	b := startUACStubAt(t, "127.0.0.2:0", func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) == "INVITE" {
			answerOK(s, raw, from)
		}
	})
	a := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) == "INVITE" {
			send302(s, raw, from, "<sip:alt@"+b.addr()+">")
		}
	})
	_, port, _ := net.SplitHostPort(a.addr())
	ua, events := redirectUA(t)
	dialRedirect(t, ua, "sip:bob@localhost:"+port, 3, redirectIdentity)
	waitFor(t, events, session.UAEventFinal, 200)
	if got := len(b.requests("INVITE")); got != 1 {
		t.Errorf("stub B INVITEs = %d, want 1", got)
	}
	if got := len(a.requests("INVITE")); got != 1 {
		t.Errorf("stub A INVITEs = %d, want 1 (the redirected INVITE must not return to A)", got)
	}
}

func credUAStrict(t *testing.T) (*sipua.UA, func() []session.UAEvent) {
	t.Helper()
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		AuthUser: "alice", AuthPass: "s3cr3t",
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua, collect(t, ua)
}

func TestRedirectTargetIsSubjectToTheDigestHostCheck(t *testing.T) {
	b := startUACStubAt(t, "127.0.0.2:0", func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) == "INVITE" {
			s.send(from, stubResponse(raw, 401, "Unauthorized", "stubtag", []string{
				`WWW-Authenticate: Digest realm="cf5e",nonce="fedcba9876543210fedcba9876543210",qop="auth",algorithm=MD5`}, ""))
		}
	})
	a := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) == "INVITE" {
			send302(s, raw, from, "<sip:x@"+b.addr()+">")
		}
	})
	ua, events := credUAStrict(t)
	dialRedirect(t, ua, "sip:bob@"+a.addr(), 3, redirectIdentity)
	ev := waitFor(t, events, session.UAEventFinal, 401)
	if !strings.Contains(ev.Reason, "credentials withheld") {
		t.Errorf("final reason = %q, want credentials withheld", ev.Reason)
	}
	for _, r := range b.requests("INVITE") {
		if len(stubHeaders(r, "Authorization")) != 0 {
			t.Error("stub B saw an Authorization")
		}
	}
	if got := len(b.requests("INVITE")); got != 1 {
		t.Errorf("stub B INVITEs = %d, want 1", got)
	}
}

func TestRedirectedInviteDropsTheOldCredentials(t *testing.T) {
	b := startUACStubAt(t, "127.0.0.2:0", func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) == "INVITE" {
			answerOK(s, raw, from)
		}
	})
	a := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		if len(stubHeaders(raw, "Proxy-Authorization")) == 0 {
			s.send(from, stubResponse(raw, 407, "Proxy Authentication Required", "stubtag", []string{
				`Proxy-Authenticate: Digest realm="cf5e",nonce="fedcba9876543210fedcba9876543210",qop="auth",algorithm=MD5`}, ""))
			return
		}
		send302(s, raw, from, "<sip:x@"+b.addr()+">")
	})
	ua := credUA(t)
	events := collect(t, ua)
	dialRedirect(t, ua, "sip:bob@"+a.addr(), 3, redirectIdentity)
	waitFor(t, events, session.UAEventFinal, 200)
	invs := b.requests("INVITE")
	if len(invs) != 1 {
		t.Fatalf("stub B INVITEs = %d, want 1", len(invs))
	}
	if h := append(stubHeaders(invs[0], "Proxy-Authorization"), stubHeaders(invs[0], "Authorization")...); len(h) != 0 {
		t.Errorf("the redirected INVITE carries the old credentials %q", h)
	}
}

// A fallback queued from a 3xx is revalidated against the live policy when it
// is dispatched, not only when it was queued.
func TestQueuedRedirectFallbackIsRevalidatedAtDispatch(t *testing.T) {
	var denied atomic.Bool
	var mu sync.Mutex
	var legA string
	var legAFrom net.Addr
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		switch ruriUser(raw) {
		case "bob":
			send302(s, raw, from, "<sip:a@"+s.addr()+">;q=0.9", "<sip:b@"+s.addr()+">;q=0.1")
		case "a":
			mu.Lock()
			legA, legAFrom = raw, from
			mu.Unlock()
			s.send(from, stubResponse(raw, 180, "Ringing", "stubtag", []string{"Contact: <sip:stub@" + s.addr() + ">"}, ""))
		case "b":
			answerOK(s, raw, from)
		}
	})
	ua, events := redirectUA(t)
	check := func(t string) (string, error) {
		if denied.Load() && strings.Contains(t, "b@") {
			return "", errors.New("denied")
		}
		return t, nil
	}
	dialRedirect(t, ua, "sip:bob@"+s.addr(), 3, check)
	waitFor(t, events, session.UAEventProvisional, 180)
	denied.Store(true) // the admin denies B while A is ringing
	mu.Lock()
	inv, from := legA, legAFrom
	mu.Unlock()
	s.send(from, stubResponse(inv, 486, "Busy Here", "stubtag", nil, ""))
	waitFor(t, events, session.UAEventFinal, 486)
	time.Sleep(300 * time.Millisecond)
	for _, r := range s.requests("INVITE") {
		if ruriUser(r) == "b" {
			t.Fatal("an INVITE went to B although the live policy denied it before dispatch")
		}
	}
}

// A 305 from a redirected target while another is queued is not a failure that
// triggers failover (R15).
func TestRedirectedTarget305DoesNotFailOver(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		switch ruriUser(raw) {
		case "bob":
			send302(s, raw, from, "<sip:high@"+s.addr()+">;q=0.9", "<sip:low@"+s.addr()+">;q=0.1")
		case "high":
			s.send(from, stubResponse(raw, 305, "Use Proxy", "stubtag", nil, ""))
		case "low":
			answerOK(s, raw, from)
		}
	})
	ua, events := redirectUA(t)
	dialRedirect(t, ua, "sip:bob@"+s.addr(), 3, redirectIdentity)
	waitFor(t, events, session.UAEventFinal, 305)
	time.Sleep(300 * time.Millisecond)
	if got := len(s.requests("INVITE")); got != 2 {
		t.Errorf("INVITEs = %d, want 2 (no failover on a 305)", got)
	}
}
