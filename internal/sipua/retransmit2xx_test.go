package sipua_test

// Lane D (cf5-d) Task 5: the 2xx is retransmitted until the ACK on every
// transport, and the call is ended with a BYE after 64*T1 without one (CF-103,
// RFC 3261 13.3.1.4). Tests that need speed set the T1 seam (SetAck2xxT1);
// the rest run on default timers. No test calls t.Parallel.

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
)

// answerBye makes the caller answer every BYE it receives with a 200.
func answerBye(t *testing.T, r *rawUAC) {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		seen := map[string]bool{}
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			r.mu.Lock()
			var byes []string
			for _, m := range r.got {
				if strings.HasPrefix(m, "BYE ") {
					byes = append(byes, m)
				}
			}
			r.mu.Unlock()
			for _, m := range byes {
				if cs := stubHeaders(m, "CSeq")[0]; !seen[cs] {
					seen[cs] = true
					r.send(stubResponse(m, 200, "OK", "", nil, ""))
				}
			}
		}
	}()
}

func countOf(r *rawUAC, method string, code int) int {
	return len(r.arrivals(method, code))
}

// callerAck builds the caller's ACK of the 200 (CSeq 1) with the given To tag and branch.
func callerAck(r *rawUAC, ruri, cid, toTag, branch string) string {
	return r.request("ACK", ruri, cid, branch, 1, toTag, "", "")
}

// startAnswered answers one raw-UAC INVITE and returns the dialog id and our To tag.
func startAnswered(t *testing.T, ua *sipua.UA, events func() []session.UAEvent, r *rawUAC, ruri, cid, branch string) (dlg, toTag string) {
	t.Helper()
	r.send(r.invite(ruri, cid, branch, 1, ""))
	in := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if !stubWait(func() bool { return r.hasCode("INVITE", 200) }, 3*time.Second) {
		t.Fatal("no 200")
	}
	_, msgs := r.responses("INVITE")
	for _, m := range msgs {
		if strings.HasPrefix(m, "SIP/2.0 200") {
			return in.DialogID, tagOf(stubHeaders(m, "To")[0])
		}
	}
	return "", ""
}

func TestRFC3261_NEWA34_TwoxxIsRetransmittedUntilAck(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	answered(t, ua, events, r, ruri, "cf5d-noack@127.0.0.1", 1)
	time.Sleep(1800 * time.Millisecond)
	codes, msgs := r.responses("INVITE")
	n := 0
	var to string
	for i, c := range codes {
		if c != 200 {
			continue
		}
		n++
		h := stubHeaders(msgs[i], "To")[0]
		if to == "" {
			to = h
		} else if h != to {
			t.Errorf("a re-sent 200 has To %q, want %q", h, to)
		}
	}
	if n < 3 {
		t.Errorf("%d 200s in 1.8 s without an ACK, want at least 3 (the 200 and re-sends at 0.5 s and 1.5 s)", n)
	}
}

func TestTwoxxRetransmissionDoublesToT2(t *testing.T) {
	t.Cleanup(sipua.SetAck2xxT1(20 * time.Millisecond))
	ua, events, r, ruri := uasUA(t)
	startAnswered(t, ua, events, r, ruri, "cf5d-dbl@127.0.0.1", "z9hG4bKcf5dDBL")
	time.Sleep(600 * time.Millisecond)
	at := r.arrivals("INVITE", 200)
	if n := len(at) - 1; n < 4 || n > 8 {
		t.Fatalf("%d re-sends in 600 ms, want 4 to 8", n)
	}
	prev := at[1].Sub(at[0])
	if prev < 15*time.Millisecond {
		t.Errorf("first gap %v, want at least 15 ms", prev)
	}
	for i := 2; i < len(at); i++ {
		gap := at[i].Sub(at[i-1])
		if float64(gap) < 0.8*float64(prev) {
			t.Errorf("gap %d is %v, shorter than 0.8 of the previous %v", i, gap, prev)
		}
		if gap > 8*20*time.Millisecond+100*time.Millisecond {
			t.Errorf("gap %d is %v, over the cap plus 100 ms", i, gap)
		}
		prev = gap
	}
}

// stopsAfterAck sends ack after the second re-send and expects silence.
func stopsAfterAck(t *testing.T, name string, ack func(r *rawUAC, ruri, cid, toTag, branch string) string) {
	t.Run(name, func(t *testing.T) {
		t.Cleanup(sipua.SetAck2xxT1(20 * time.Millisecond))
		ua, events, r, ruri := uasUA(t)
		answerBye(t, r)
		const cid, br = "cf5d-ack@127.0.0.1", "z9hG4bKcf5dACK"
		_, tag := startAnswered(t, ua, events, r, ruri, cid, br)
		if !stubWait(func() bool { return countOf(r, "INVITE", 200) >= 3 }, 2*time.Second) {
			t.Fatal("no retransmission before the ACK")
		}
		r.send(ack(r, ruri, cid, tag, br))
		time.Sleep(60 * time.Millisecond) // a copy already in flight
		n := countOf(r, "INVITE", 200)
		time.Sleep(300 * time.Millisecond)
		if got := countOf(r, "INVITE", 200); got != n {
			t.Errorf("%d more 200s after the ACK", got-n)
		}
	})
}

func TestAckStopsRetransmission(t *testing.T) {
	stopsAfterAck(t, "new branch", func(r *rawUAC, ruri, cid, tag, _ string) string {
		return callerAck(r, ruri, cid, tag, "z9hG4bKcf5dACKnew")
	})
	stopsAfterAck(t, "invite branch", func(r *rawUAC, ruri, cid, tag, br string) string {
		return callerAck(r, ruri, cid, tag, br)
	})
}

func TestAckWithForeignTagDoesNotStopRetransmission(t *testing.T) {
	t.Cleanup(sipua.SetAck2xxT1(20 * time.Millisecond))
	ua, events, r, ruri := uasUA(t)
	answerBye(t, r)
	const cid = "cf5d-fack@127.0.0.1"
	startAnswered(t, ua, events, r, ruri, cid, "z9hG4bKcf5dFACK")
	r.send(callerAck(r, ruri, cid, "not-our-tag", "z9hG4bKcf5dFACKn"))
	time.Sleep(100 * time.Millisecond)
	n := countOf(r, "INVITE", 200)
	time.Sleep(300 * time.Millisecond)
	if countOf(r, "INVITE", 200) <= n {
		t.Error("retransmission stopped on an ACK with a foreign To tag")
	}
}

func TestNoAckEndsTheCallAfter64T1(t *testing.T) {
	t.Cleanup(sipua.SetAck2xxT1(10 * time.Millisecond))
	ua, events, r, ruri := uasUA(t)
	answerBye(t, r)
	start := time.Now()
	startAnswered(t, ua, events, r, ruri, "cf5d-noack64@127.0.0.1", "z9hG4bKcf5dNA")
	byeAt := func() time.Time {
		r.mu.Lock()
		defer r.mu.Unlock()
		for i, m := range r.got {
			if strings.HasPrefix(m, "BYE ") {
				return r.at[i]
			}
		}
		return time.Time{}
	}
	if !stubWait(func() bool { return !byeAt().IsZero() }, 3*time.Second) {
		t.Fatal("no BYE for an unacknowledged 200")
	}
	if d := byeAt().Sub(start); d < 550*time.Millisecond || d > 1500*time.Millisecond {
		t.Errorf("BYE after %v, want about 640 ms", d)
	}
	if !stubWait(func() bool {
		for _, e := range events() {
			if e.Kind == session.UAEventDialogEnded {
				return true
			}
		}
		return false
	}, 2*time.Second) {
		t.Fatal("no dialog_ended")
	}
	var ended []session.UAEvent
	for _, e := range events() {
		if e.Kind == session.UAEventDialogEnded {
			ended = append(ended, e)
		}
	}
	if len(ended) != 1 || ended[0].Cause != session.UACauseTransportFailure || ended[0].Detail["cause"] != "no_ack" {
		t.Fatalf("dialog_ended events %+v, want one transport_failure with cause no_ack", ended)
	}
	for _, a := range r.arrivals("INVITE", 200) {
		if a.After(byeAt().Add(50 * time.Millisecond)) {
			t.Error("a 200 was re-sent after the BYE")
		}
	}
}

func TestHangupStopsRetransmission(t *testing.T) {
	t.Cleanup(sipua.SetAck2xxT1(20 * time.Millisecond))
	ua, events, r, ruri := uasUA(t)
	answerBye(t, r)
	dlg, _ := startAnswered(t, ua, events, r, ruri, "cf5d-hup@127.0.0.1", "z9hG4bKcf5dHUP")
	stubWait(func() bool { return countOf(r, "INVITE", 200) >= 2 }, 2*time.Second)
	if err := ua.Hangup(context.Background(), dlg, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	n := countOf(r, "INVITE", 200)
	time.Sleep(900 * time.Millisecond) // past the 64*T1 deadline (1.28 s from the 200)
	if got := countOf(r, "INVITE", 200); got != n {
		t.Errorf("%d more 200s after the hangup", got-n)
	}
	cseqs := map[string]bool{}
	r.mu.Lock()
	for _, m := range r.got {
		if strings.HasPrefix(m, "BYE ") {
			cseqs[stubHeaders(m, "CSeq")[0]] = true
		}
	}
	r.mu.Unlock()
	if len(cseqs) != 1 {
		t.Errorf("%d distinct BYEs, want exactly 1 (the hangup's; none from the deadline)", len(cseqs))
	}
}

func TestCloseStopsRetransmission(t *testing.T) {
	t.Cleanup(sipua.SetAck2xxT1(20 * time.Millisecond))
	ua, events, r, ruri := uasUA(t)
	answerBye(t, r)
	startAnswered(t, ua, events, r, ruri, "cf5d-cls@127.0.0.1", "z9hG4bKcf5dCLS")
	stubWait(func() bool { return countOf(r, "INVITE", 200) >= 2 }, 2*time.Second)
	_ = ua.Close(context.Background())
	time.Sleep(100 * time.Millisecond)
	n := countOf(r, "INVITE", 200)
	time.Sleep(300 * time.Millisecond)
	if got := countOf(r, "INVITE", 200); got != n {
		t.Errorf("%d more 200s after Close", got-n)
	}
}

func TestEndUnacknowledgedAfterAnotherTeardownIsSilent(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	answerBye(t, r)
	dlg, _ := startAnswered(t, ua, events, r, ruri, "cf5d-eu1@127.0.0.1", "z9hG4bKcf5dEU1")
	if err := ua.Hangup(context.Background(), dlg, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	before := len(events())
	ua.EndUnacknowledgedForTest(dlg)
	time.Sleep(100 * time.Millisecond)
	for _, e := range events()[before:] {
		if e.Kind == session.UAEventDialogEnded {
			t.Errorf("a second teardown emitted %+v", e)
		}
	}
}

func TestEndUnacknowledgedOnAClosedUAIsSilent(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	answerBye(t, r)
	dlg, _ := startAnswered(t, ua, events, r, ruri, "cf5d-eu2@127.0.0.1", "z9hG4bKcf5dEU2")
	ua.CloseMarkedForTest()
	before := len(events())
	ua.EndUnacknowledgedForTest(dlg)
	time.Sleep(100 * time.Millisecond)
	for _, e := range events()[before:] {
		if e.Kind == session.UAEventDialogEnded {
			t.Errorf("a closing UA emitted %+v", e)
		}
	}
}

// TestAckDuringControlOpStopsRetransmission: a transfer can claim the answered
// dialog before the ACK (the INVITE carried an offer); an ACK arriving then is
// still recorded, so the 64*T1 deadline does not BYE a call the peer ACKed.
func TestAckDuringControlOpStopsRetransmission(t *testing.T) {
	t.Cleanup(sipua.SetAck2xxT1(20 * time.Millisecond))
	ua, events, r, ruri := uasUA(t)
	answerBye(t, r)
	const cid, br = "cf5d-cop@127.0.0.1", "z9hG4bKcf5dCOP"
	dlg, tag := startAnswered(t, ua, events, r, ruri, cid, br)
	_, release, err := sipua.ClaimControlOpForTest(ua, dlg)
	if err != nil {
		t.Fatalf("claim control op: %v", err)
	}
	defer release()
	r.send(callerAck(r, ruri, cid, tag, "z9hG4bKcf5dCOPa"))
	time.Sleep(100 * time.Millisecond)
	n := countOf(r, "INVITE", 200)
	time.Sleep(1500 * time.Millisecond) // well past 64*T1 = 1.28 s
	if got := countOf(r, "INVITE", 200); got != n {
		t.Errorf("%d more 200s after the ACK", got-n)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.got {
		if strings.HasPrefix(m, "BYE ") {
			t.Error("the deadline sent a BYE for a call the peer ACKed")
		}
	}
}

// Over TCP the 200 is re-sent too (RFC 3261 13.3.1.4: independent of the
// transport; D-1).
func TestTwoxxIsRetransmittedOverTCP(t *testing.T) {
	ua, events := newTCPStubUA(t)
	c, err := net.Dial("tcp", ua.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	local := c.LocalAddr().String()
	inv := "INVITE sip:alice@" + ua.LocalAddr().String() + ";transport=tcp SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP " + local + ";branch=z9hG4bKcf5dTCP\r\n" +
		"From: <sip:probe@127.0.0.1>;tag=rfcsweepa\r\nTo: <sip:alice@example>\r\n" +
		"Call-ID: cf5d-tcp@127.0.0.1\r\nCSeq: 1 INVITE\r\nMax-Forwards: 70\r\n" +
		"Contact: <sip:probe@" + local + ";transport=tcp>\r\n" +
		"Content-Type: application/sdp\r\nContent-Length: " + itoa(len(stubSDP)) + "\r\n\r\n" + stubSDP
	if _, err := c.Write([]byte(inv)); err != nil {
		t.Fatalf("write: %v", err)
	}
	in := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	rd := bufio.NewReader(c)
	n200 := 0
	deadline := time.Now().Add(1800 * time.Millisecond)
	_ = c.SetReadDeadline(deadline)
	for {
		m, err := readStreamMsg(rd)
		if err != nil {
			break
		}
		if strings.HasPrefix(m, "SIP/2.0 200") {
			n200++
		}
	}
	if n200 < 3 {
		t.Errorf("%d 200s over TCP in 1.8 s without an ACK, want at least 3", n200)
	}
}
