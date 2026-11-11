package sipua_test

// Lane A (cf6-a-sdp) Task 3 (CF-205): over a stream transport a first early SDP
// larger than a UDP datagram can carry is not kept, and the call fails at the
// 2xx. No test calls t.Parallel.

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
)

// padSDP returns base padded with a=x-pad: lines to exactly n bytes.
func padSDP(base string, n int) string {
	var b strings.Builder
	b.WriteString(base)
	for rem := n - len(base); rem > 0; {
		k := min(rem, 1000)
		if left := rem - k; left > 0 && left < 10 { // never leave a tail shorter than one pad line
			k = rem - 10
		}
		b.WriteString("a=x-pad:" + strings.Repeat("x", k-10) + "\r\n")
		rem -= k
	}
	return b.String()
}

// tcpEarlyStub serves one INVITE with: a 183 (tag t1) carrying first, then,
// after <-second, a 183 (t1) carrying second (if not empty), then after
// <-final a 200 (t1) carrying the 2xx body. acks and byes count what it sees.
type tcpEarlyStub struct {
	addr          string
	second, final chan struct{}
	acks, byes    atomic.Int32
}

func startTCPEarlyStub(t *testing.T, first, second, ok string) *tcpEarlyStub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &tcpEarlyStub{addr: ln.Addr().String(), second: make(chan struct{}), final: make(chan struct{})}
	contact := []string{"Contact: <sip:stub@" + s.addr + ";transport=tcp>"}
	acceptAll(t, ln, func(c net.Conn) {
		r := bufio.NewReader(c)
		for {
			m, err := readStreamMsg(r)
			if err != nil {
				return
			}
			switch stubMethod(m) {
			case "INVITE":
				go func() {
					_, _ = c.Write([]byte(stubResponse(m, 183, "Session Progress", "t1", contact, first)))
					if second != "" {
						<-s.second
						_, _ = c.Write([]byte(stubResponse(m, 183, "Session Progress", "t1", contact, second)))
					}
					<-s.final
					_, _ = c.Write([]byte(stubResponse(m, 200, "OK", "t1", contact, ok)))
				}()
			case "ACK":
				s.acks.Add(1)
			case "BYE":
				s.byes.Add(1)
				_, _ = c.Write([]byte(stubResponse(m, 200, "OK", "", nil, "")))
			}
		}
	})
	return s
}

func waitEarlyCount(t *testing.T, ua *sipua.UA, id string, n int) {
	t.Helper()
	if !stubWait(func() bool { return sipua.EarlyAnswerCount(ua, id) >= n }, 3*time.Second) {
		t.Fatalf("the UA never held %d early answer(s)", n)
	}
}

func TestOversizedEarlySDPIsNotKeptAndFailsTheCallAtThe200(t *testing.T) {
	normal := earlySDP(40000, "0")
	s := startTCPEarlyStub(t, padSDP(normal, 70000), normal, normal)
	ua, events := newTCPStubUA(t)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + s.addr})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitEarlyCount(t, ua, res.DialogID, 1)
	close(s.second) // the second 183 for the same tag follows the oversized one
	// give the UA time to process it; the entry must stay the marker
	time.Sleep(300 * time.Millisecond)
	if n := sipua.EarlyAnswerBytes(ua, res.DialogID); n != 0 {
		t.Errorf("early answer bytes held = %d, want 0", n)
	}
	if n := sipua.EarlyAnswerCount(ua, res.DialogID); n != 1 {
		t.Errorf("early answer entries = %d, want 1 (the marker)", n)
	}
	close(s.final)
	ev := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ev.Cause != session.UACauseMediaNegotiationFailed {
		t.Errorf("dialog_ended cause = %q, want media_negotiation_failed", ev.Cause)
	}
	if ev.Detail["kind"] != "sdp_unparseable" {
		t.Errorf("dialog_ended detail kind = %v, want sdp_unparseable", ev.Detail["kind"])
	}
	if !stubWait(func() bool { return s.acks.Load() >= 1 && s.byes.Load() >= 1 }, 3*time.Second) {
		t.Fatalf("stub saw %d ACK, %d BYE, want 1 and 1", s.acks.Load(), s.byes.Load())
	}
	if s.acks.Load() != 1 || s.byes.Load() != 1 {
		t.Errorf("stub saw %d ACK, %d BYE, want 1 and 1", s.acks.Load(), s.byes.Load())
	}
	if got := sipua.AnswerSDPForTest(ua, res.DialogID); len(got) != 0 {
		t.Errorf("answer SDP of %d bytes kept for a refused early SDP", len(got))
	}
}

func TestEarlySDPAtTheCapIsKept(t *testing.T) {
	atCap := padSDP(earlySDP(40000, "0"), 65507)
	if len(atCap) != 65507 {
		t.Fatalf("padSDP made %d bytes", len(atCap))
	}
	s := startTCPEarlyStub(t, atCap, "", "")
	ua, events := newTCPStubUA(t)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + s.addr})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitEarlyCount(t, ua, res.DialogID, 1)
	close(s.final)
	waitFor(t, events, session.UAEventFinal, 200)
	if got := sipua.AnswerSDPForTest(ua, res.DialogID); string(got) != atCap {
		t.Errorf("answer SDP is %d bytes, want the 183's %d", len(got), len(atCap))
	}
}
