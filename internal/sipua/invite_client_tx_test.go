package sipua_test

// CF-107 and CF-088: our outbound INVITE's client transaction stays in sipgo's
// Accepted state after the first 2xx, and runDial's absorber ACKs every further
// 2xx (RFC 3261 13.2.2.4, rfc3261.txt:4571-4572 and 4587-4590): a retransmission
// of a 2xx gets the same ACK again, a 2xx from a second fork gets its own ACK
// and then one BYE (rfc3261.txt:4605-4607). Raw UDP UAS stub: uacStub
// (rfc3261_pin_uac_test.go). No test here calls t.Parallel.

import (
	"context"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// forkStub answers the INVITE 200 with To tag forkA and, when forkA's ACK
// arrives, sends the same INVITE's 200 under each tag in forks, in order (a tag
// listed twice is a retransmission). pre, when non-nil, may answer an INVITE
// itself first (a challenge or a 422) by returning true.
func forkStub(t *testing.T, pre func(s *uacStub, raw string, from net.Addr) bool, forks ...string) *uacStub {
	t.Helper()
	var mu sync.Mutex
	var inv string
	return startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		c := "Contact: <sip:stub@" + s.addr() + ">"
		switch stubMethod(raw) {
		case "INVITE":
			if pre != nil && pre(s, raw, from) {
				return
			}
			mu.Lock()
			inv = raw
			mu.Unlock()
			s.send(from, stubResponse(raw, 200, "OK", "forkA", []string{c}, stubSDP))
		case "ACK":
			if stubToTag(raw) != "forkA" {
				return
			}
			mu.Lock()
			first := inv
			mu.Unlock()
			for _, tag := range forks {
				s.send(from, stubResponse(first, 200, "OK", tag, []string{c}, stubSDP))
			}
		}
	})
}

// stubToTag returns the To tag of a request datagram.
func stubToTag(raw string) string {
	_, tag, _ := strings.Cut(stubHeaders(raw, "To")[0], "tag=")
	tag, _, _ = strings.Cut(tag, ";")
	return tag
}

// tagCounts counts reqs by To tag.
func tagCounts(reqs []string) map[string]int {
	out := map[string]int{}
	for _, r := range reqs {
		out[stubToTag(r)]++
	}
	return out
}

// withCSeq keeps the requests whose CSeq number is cseq.
func withCSeq(reqs []string, cseq int) []string {
	var out []string
	for _, r := range reqs {
		if stubCSeq(r) == cseq {
			out = append(out, r)
		}
	}
	return out
}

// sameAck reports whether two ACK datagrams are the same request: identical
// but for the order of header parameters, which the vendored serializer takes
// from a Go map (sip.HeaderParams) and so varies between two writes of the
// same object.
func sameAck(a, b string) bool {
	norm := func(raw string) string {
		lines := strings.Split(raw, "\r\n")
		for i, l := range lines {
			parts := strings.Split(l, ";")
			sort.Strings(parts[1:])
			lines[i] = strings.Join(parts, ";")
		}
		return strings.Join(lines, "\r\n")
	}
	return norm(a) == norm(b)
}

// settle waits up to 3 s for at least acks ACKs and byes BYEs, then 300 ms
// more so that any extra one is counted too.
func settle(s *uacStub, acks, byes int) {
	stubWait(func() bool {
		return len(s.requests("ACK")) >= acks && len(s.requests("BYE")) >= byes
	}, 3*time.Second)
	time.Sleep(300 * time.Millisecond)
}

// I4 and I5: a retransmitted fork 2xx gets the remembered ACK again and no
// second BYE.
func TestForkTwoxxRetransmissionIsReAckedWithOneBye(t *testing.T) {
	s := forkStub(t, nil, "forkB", "forkB")
	ua := newStubUA(t)
	dialStub(t, ua, s)
	settle(s, 3, 1)
	acks, byes := s.requests("ACK"), s.requests("BYE")
	if got := tagCounts(acks); len(acks) != 3 || got["forkA"] != 1 || got["forkB"] != 2 {
		t.Errorf("ACKs by To tag = %v (%d), want forkA 1, forkB 2", got, len(acks))
	}
	if got := tagCounts(byes); len(byes) != 1 || got["forkB"] != 1 {
		t.Errorf("BYEs by To tag = %v (%d), want exactly one, to forkB", got, len(byes))
	}
	var forkB []string
	for _, a := range acks {
		if stubToTag(a) == "forkB" {
			forkB = append(forkB, a)
		}
	}
	if len(forkB) == 2 && !sameAck(forkB[0], forkB[1]) {
		t.Errorf("the re-sent forkB ACK differs from the first:\n%s\n---\n%s", forkB[0], forkB[1])
	}
}

// The cap: at most 16 distinct extra To tags per INVITE are ACKed and BYEd; a
// 17th draws neither (D-107).
func TestForkTagsBeyondTheCapAreNotByed(t *testing.T) {
	forks := make([]string, 17)
	for i := range forks {
		forks[i] = "fork" + strconv.Itoa(i+1)
	}
	s := forkStub(t, nil, forks...)
	ua := newStubUA(t)
	dialStub(t, ua, s)
	settle(s, 17, 16)
	acked, byed := tagCounts(s.requests("ACK")), tagCounts(s.requests("BYE"))
	if len(s.requests("ACK")) != 17 || acked["forkA"] != 1 {
		t.Errorf("ACKs by To tag = %v, want forkA once and 16 fork tags once each", acked)
	}
	if len(s.requests("BYE")) != 16 || byed["forkA"] != 0 {
		t.Errorf("BYEs by To tag = %v, want 16, none to forkA", byed)
	}
	for _, tag := range forks {
		if acked[tag] != byed[tag] || acked[tag] > 1 {
			t.Errorf("fork %s: %d ACK(s), %d BYE(s); want 1 and 1, or (the capped one) 0 and 0", tag, acked[tag], byed[tag])
		}
	}
}

// A 2xx with no To tag names no dialog: it is ignored (logged at Debug), not
// ACKed and BYEd as another fork's. forkB after it is the control: the absorber
// is still running and handles a real fork.
func TestTaglessTwoxxIsNotTakenForAFork(t *testing.T) {
	s := forkStub(t, nil, "", "forkB")
	ua := newStubUA(t)
	dialStub(t, ua, s)
	settle(s, 2, 1)
	acked, byed := tagCounts(s.requests("ACK")), tagCounts(s.requests("BYE"))
	if len(s.requests("ACK")) != 2 || acked["forkA"] != 1 || acked["forkB"] != 1 {
		t.Errorf("ACKs by To tag = %v, want forkA 1, forkB 1 and none tagless", acked)
	}
	if len(s.requests("BYE")) != 1 || byed["forkB"] != 1 {
		t.Errorf("BYEs by To tag = %v, want exactly one, to forkB", byed)
	}
}

// I1/I4 on the digest-retry leg: the forkB 200 to the authenticated INVITE is
// ACKed and BYEd.
func TestForkTwoxxAfterDigestRetryIsAckedAndByed(t *testing.T) {
	s := forkStub(t, func(s *uacStub, raw string, from net.Addr) bool {
		if len(stubHeaders(raw, "Authorization")) != 0 {
			return false
		}
		s.send(from, stubResponse(raw, 401, "Unauthorized", "chal", []string{
			`WWW-Authenticate: Digest realm="rfcfix1",nonce="0123456789abcdef0123456789abcdef",qop="auth",algorithm=MD5`,
		}, ""))
		return true
	}, "forkB")
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
	dialStub(t, ua, s)
	settle(s, 3, 1) // the 401's ACK, then forkA's and forkB's
	invs := s.requests("INVITE")
	if len(invs) != 2 {
		t.Fatalf("precondition: want a 401 round trip and an authenticated retry, got %d INVITEs", len(invs))
	}
	acks := withCSeq(s.requests("ACK"), stubCSeq(invs[1]))
	if got := tagCounts(acks); len(acks) != 2 || got["forkA"] != 1 || got["forkB"] != 1 {
		t.Errorf("ACKs to the authenticated INVITE's 2xx by To tag = %v, want forkA 1, forkB 1", got)
	}
	if got := tagCounts(s.requests("BYE")); len(s.requests("BYE")) != 1 || got["forkB"] != 1 {
		t.Errorf("BYEs by To tag = %v, want exactly one, to forkB", got)
	}
}

// I3 on the 422-retry leg: a retransmitted 200 to the retried INVITE is
// re-ACKed with the identical ACK.
func TestRetransmittedTwoxxAfterA422RetryIsReAcked(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		if len(s.requests("INVITE")) == 1 {
			s.send(from, stubResponse(raw, 422, "Session Interval Too Small", "st422", []string{"Min-SE: 120"}, ""))
			return
		}
		ok := stubResponse(raw, 200, "OK", "stubtag", []string{"Contact: <sip:stub@" + s.addr() + ">"}, stubSDP)
		s.send(from, ok)
		s.send(from, ok)
	})
	ua := newStubUA(t)
	dialStub(t, ua, s)
	settle(s, 3, 0) // the 422's ACK, then the 200's twice
	invs := s.requests("INVITE")
	if len(invs) != 2 {
		t.Fatalf("precondition: want a 422 and a retry, got %d INVITEs", len(invs))
	}
	acks := withCSeq(s.requests("ACK"), stubCSeq(invs[1]))
	if len(acks) != 2 {
		t.Fatalf("%d ACKs for the retry's 200 and its retransmission, want 2", len(acks))
	}
	if !sameAck(acks[0], acks[1]) {
		t.Errorf("the re-sent ACK differs from the first:\n%s\n---\n%s", acks[0], acks[1])
	}
	if n := len(s.requests("BYE")); n != 0 {
		t.Errorf("%d BYE(s) for a retransmission", n)
	}
}

// absorberRunning reports whether any goroutine is inside absorbInvite2xx.
// Inlined like onInviteHeld (invite_server_tx_test.go): goroutineStackContains
// (ua_test.go) is in package sipua.
func absorberRunning() bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Contains(string(buf[:n]), "absorbInvite2xx")
}

// I8: UA.Close ends the absorber well before Timer M (32 s).
func TestAbsorbInvite2xxExitsOnUAClose(t *testing.T) {
	s := startUACStub(t, answer200())
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	dialStub(t, ua, s)
	waitFor(t, events, session.UAEventFinal, 200)
	if !stubWait(absorberRunning, 2*time.Second) {
		t.Fatal("precondition: no absorbInvite2xx goroutine after the answer")
	}
	if err := ua.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !stubWait(func() bool { return !absorberRunning() }, 2*time.Second) {
		t.Fatal("absorbInvite2xx is still running 2 s after UA.Close")
	}
}
