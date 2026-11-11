package sipua_test

// Lane A (rfc-sweep-a) pins for the A-UAS area. Each passes today and must be
// inverted when its NEW-A finding is fixed.
// No test here calls t.Parallel (parallel_invariant_test.go). The requests are
// raw UDP datagrams because the peer package cannot send these shapes (unknown
// Require, tel: Request-URI, merged INVITE, lower CSeq, unmatched CANCEL/BYE).
// The stub helpers (stubHeaders, stubMethod) are in rfc3261_pin_uac_test.go.

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// rawUAC is a raw UDP caller that records every datagram it receives.
type rawUAC struct {
	t   *testing.T
	pc  net.PacketConn
	dst *net.UDPAddr
	mu  sync.Mutex
	got []string
	at  []time.Time // arrival time of each got[i]
}

func newRawUAC(t *testing.T, ua *sipua.UA) *rawUAC {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dst, err := net.ResolveUDPAddr("udp", ua.BoundAddr().String())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	r := &rawUAC{t: t, pc: pc, dst: dst}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			r.mu.Lock()
			r.got = append(r.got, string(buf[:n]))
			r.at = append(r.at, time.Now())
			r.mu.Unlock()
		}
	}()
	return r
}

func (r *rawUAC) port() string {
	_, p, _ := net.SplitHostPort(r.pc.LocalAddr().String())
	return p
}

func (r *rawUAC) send(msg string) {
	r.t.Helper()
	if _, err := r.pc.WriteTo([]byte(msg), r.dst); err != nil {
		r.t.Fatalf("write: %v", err)
	}
}

// responses returns the received responses for method (by CSeq method) with their status codes.
func (r *rawUAC) responses(method string) (codes []int, msgs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.got {
		if !strings.HasPrefix(m, "SIP/2.0 ") {
			continue
		}
		cs := stubHeaders(m, "CSeq")
		if len(cs) == 0 || !strings.HasSuffix(cs[0], " "+method) {
			continue
		}
		code, _ := strconv.Atoi(strings.Fields(m)[1])
		codes = append(codes, code)
		msgs = append(msgs, m)
	}
	return
}

// arrivals returns the arrival times of the responses with the given code to method.
func (r *rawUAC) arrivals(method string, code int) []time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []time.Time
	for i, m := range r.got {
		cs := stubHeaders(m, "CSeq")
		if strings.HasPrefix(m, "SIP/2.0 "+strconv.Itoa(code)+" ") && len(cs) > 0 && strings.HasSuffix(cs[0], " "+method) {
			out = append(out, r.at[i])
		}
	}
	return out
}

func (r *rawUAC) hasCode(method string, code int) bool {
	codes, _ := r.responses(method)
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}

// request builds a request datagram from this caller.
func (r *rawUAC) request(method, ruri, callID, branch string, cseq int, toTag, extra, body string) string {
	to := "<sip:alice@example>"
	if toTag != "" {
		to += ";tag=" + toTag
	}
	m := method + " " + ruri + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:" + r.port() + ";branch=" + branch + "\r\n" +
		"From: <sip:probe@127.0.0.1>;tag=rfcsweepa\r\n" +
		"To: " + to + "\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: " + strconv.Itoa(cseq) + " " + method + "\r\n" +
		"Max-Forwards: 70\r\nContact: <sip:probe@127.0.0.1:" + r.port() + ">\r\n" + extra
	if body != "" {
		m += "Content-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	} else {
		m += "Content-Length: 0\r\n\r\n"
	}
	return m
}

func (r *rawUAC) invite(ruri, callID, branch string, cseq int, extra string) string {
	return r.request("INVITE", ruri, callID, branch, cseq, "", extra, stubSDP)
}

// uasUA is a direct UA with an event collector and its raw caller.
func uasUA(t *testing.T) (*sipua.UA, func() []session.UAEvent, *rawUAC, string) {
	t.Helper()
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	return ua, events, newRawUAC(t, ua), "sip:alice@" + ua.BoundAddr().String()
}

func countInbound(evs []session.UAEvent) int {
	n := 0
	for _, e := range evs {
		if e.Kind == session.UAEventInbound {
			n++
		}
	}
	return n
}

// answered brings up one answered inbound dialog and returns the 200 OK text.
func answered(t *testing.T, ua *sipua.UA, events func() []session.UAEvent, r *rawUAC, ruri, callID string, cseq int) string {
	t.Helper()
	r.send(r.invite(ruri, callID, "z9hG4bKrfcsweepaI"+callID, cseq, ""))
	in := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if !stubWait(func() bool { return r.hasCode("INVITE", 200) }, 3*time.Second) {
		t.Fatal("no 200 to the INVITE")
	}
	_, msgs := r.responses("INVITE")
	for _, m := range msgs {
		if strings.HasPrefix(m, "SIP/2.0 200") {
			return m
		}
	}
	return ""
}

// TestRFC3261_NEWA27_RetransmittedInviteIsAbsorbed was the NEW-A-27 pin
// (A-UAS-93, RFC 3261 17.2.1: "If a request retransmission is received while in
// the "Proceeding" state, the most recent provisional response that was received
// from the TU MUST be passed to the transport layer for retransmission."
// rfc3261.txt:7493-7496), flipped by CF-096: the inbound INVITE server
// transaction now lives until it ends, so one INVITE sent three times is one
// call, and each copy draws the same 180 again. Each copy is sent only after
// the 180 for the first arrived (a copy that beats the first provisional finds
// nothing to resend, a pre-existing window named in the CF-096 report).
func TestRFC3261_NEWA27_RetransmittedInviteIsAbsorbed(t *testing.T) {
	_, events, r, ruri := uasUA(t)
	msg := r.invite(ruri, "rfcsweepa-retx@127.0.0.1", "z9hG4bKrfcsweepaRETX", 1, "")
	r.send(msg)
	if !stubWait(func() bool { return r.hasCode("INVITE", 180) }, 3*time.Second) {
		t.Fatal("no 180 to the first INVITE")
	}
	for i := 0; i < 2; i++ {
		r.send(msg)
		time.Sleep(150 * time.Millisecond)
	}
	stubWait(func() bool { return countInbound(events()) > 1 }, 500*time.Millisecond)
	if n := countInbound(events()); n != 1 {
		t.Errorf("%d inbound calls for one INVITE sent three times, want 1 (NEW-A-27, RFC 3261 17.2.1)", n)
	}
	codes, msgs := r.responses("INVITE")
	var to []string
	seen180 := false
	for i, c := range codes {
		switch {
		case c == 180:
			seen180 = true
			to = append(to, stubHeaders(msgs[i], "To")[0])
		case c == 100 && seen180:
			t.Errorf("a 100 after the first 180 (codes %v): the retransmission must draw the latest provisional", codes)
		}
	}
	if len(to) < 2 {
		t.Errorf("%d 180s for three copies (codes %v), want the 180 re-sent", len(to), codes)
	}
	for _, h := range to {
		if h != to[0] {
			t.Errorf("the re-sent 180 has To %q, want the first 180's %q (one dialog)", h, to[0])
		}
	}
}

// TestRFC3261Pin_NEWA30_UnmatchedCancelIsAnswered200 pins NEW-A-30 (A-UAS-31,
// RFC 3261 9.2: "If the UAS did not find a matching transaction for the CANCEL
// ..., it SHOULD respond to the CANCEL with a 481 (Call Leg/Transaction Does Not
// Exist)." rfc3261.txt:3056-3058). Evidence: evidence/uas-cancel-unknown/excerpt.txt frame 2.
//
// PIN OF A DEVIATION: invert this assertion when NEW-A-30 is fixed.
func TestRFC3261Pin_NEWA30_UnmatchedCancelIsAnswered200(t *testing.T) {
	_, _, r, ruri := uasUA(t)
	r.send(r.request("CANCEL", ruri, "rfcsweepa-cnm@127.0.0.1", "z9hG4bKrfcsweepaCNM", 1, "", "", ""))
	if !stubWait(func() bool { codes, _ := r.responses("CANCEL"); return len(codes) > 0 }, 2*time.Second) {
		t.Fatal("no response to the unmatched CANCEL")
	}
	codes, _ := r.responses("CANCEL")
	t.Logf("the unmatched CANCEL was answered %v", codes)
	if r.hasCode("CANCEL", 481) {
		t.Errorf("the unmatched CANCEL now draws 481: NEW-A-30 is fixed, invert this pin")
	}
}

// TestRFC3261_NEWA31_UnmatchedByeIsAnswered481 is NEW-A-31 (A-UAS-83, RFC 3261
// 15.1.2: "If the BYE does not match an existing dialog, the UAS core SHOULD
// generate a 481 (Call/Transaction Does Not Exist) response and pass that to the
// server transaction." rfc3261.txt:5055-5058). Also CF-100.
func TestRFC3261_NEWA31_UnmatchedByeIsAnswered481(t *testing.T) {
	_, _, r, ruri := uasUA(t)
	r.send(r.request("BYE", ruri, "rfcsweepa-bnm@127.0.0.1", "z9hG4bKrfcsweepaBNM", 7, "rfcsweepa-nomatch", "", ""))
	if !stubWait(func() bool { codes, _ := r.responses("BYE"); return len(codes) > 0 }, 2*time.Second) {
		t.Fatal("no response to the unmatched BYE")
	}
	if codes, _ := r.responses("BYE"); !r.hasCode("BYE", 481) {
		t.Fatalf("the unmatched BYE was answered %v, want 481", codes)
	}
}

// TestRFC3261_NEWA32_LowerCSeqInfoDraws500 is NEW-A-32 / CF-101, fixed: RFC 3261
// 12.2.2: "If the remote sequence number was not empty, but the sequence number
// of the request is lower than the remote sequence number, the request is out of
// order and MUST be rejected with a 500 (Server Internal Error) response."
// rfc3261.txt:4269-4272. The INFO with CSeq 5 on a dialog opened with CSeq 10
// draws 500. Was the RFC3261 pin NEWA32_LowerCSeqInDialogIsNotRejected.
func TestRFC3261_NEWA32_LowerCSeqInfoDraws500(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	ok := answered(t, ua, events, r, ruri, "rfcsweepa-cseq@127.0.0.1", 10)
	toTag := ""
	if to := stubHeaders(ok, "To"); len(to) > 0 {
		if _, tag, found := strings.Cut(to[0], "tag="); found {
			toTag = tag
		}
	}
	r.send(r.request("ACK", ruri, "rfcsweepa-cseq@127.0.0.1", "z9hG4bKrfcsweepaCA", 10, toTag, "", ""))
	r.send(r.request("INFO", ruri, "rfcsweepa-cseq@127.0.0.1", "z9hG4bKrfcsweepaCI", 5, toTag, "", ""))
	if !stubWait(func() bool { codes, _ := r.responses("INFO"); return len(codes) > 0 }, 2*time.Second) {
		t.Fatal("no response to the lower-CSeq INFO")
	}
	if !r.hasCode("INFO", 500) {
		codes, _ := r.responses("INFO")
		t.Errorf("the lower-CSeq INFO was answered %v, want 500", codes)
	}
}

// TestRFC3261Pin_NEWA33_TwoxxHasNoSupported pins NEW-A-33 (A-UAS-69, RFC 3261
// 13.3.1.4: "A 2xx response to an INVITE SHOULD contain the Allow header field
// and the Supported header field" rfc3261.txt:4736-4737). Evidence:
// evidence/uas-basic/excerpt.txt frame 4; evidence/corpus-udp/queries.txt H-FIELDS-16.
//
// PIN OF A DEVIATION: invert this assertion when NEW-A-33 is fixed.
func TestRFC3261Pin_NEWA33_TwoxxHasNoSupported(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	ok := answered(t, ua, events, r, ruri, "rfcsweepa-sup@127.0.0.1", 1)
	if len(stubHeaders(ok, "Allow")) == 0 {
		t.Fatal("the 200 carries no Allow (the pin's precondition)")
	}
	if s := stubHeaders(ok, "Supported"); len(s) != 0 {
		t.Errorf("the 200 now carries Supported %q: NEW-A-33 is fixed, invert this pin", s)
	}
}

// TestRFC3261_NEWA35_AckForNon2xxStopsRetransmission was the NEW-A-35 pin
// (A-UAS-99, RFC 3261 17.2.1: "If an ACK is received while the server
// transaction is in the "Completed" state, the server transaction MUST
// transition to the "Confirmed" state." rfc3261.txt:7541-7543; Timer G stops
// there), flipped by CF-104 (folded into CF-096): the INVITE transaction is
// live when the ACK arrives, so no 486 follows it within 2 s.
func TestRFC3261_NEWA35_AckForNon2xxStopsRetransmission(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	callID := "rfcsweepa-rej@127.0.0.1"
	r.send(r.invite(ruri, callID, "z9hG4bKrfcsweepaREJ", 1, ""))
	in := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Reject(context.Background(), in.DialogID, 486, ""); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if !stubWait(func() bool { return r.hasCode("INVITE", 486) }, 2*time.Second) {
		t.Fatal("no 486")
	}
	_, msgs := r.responses("INVITE")
	var first string
	for _, m := range msgs {
		if strings.HasPrefix(m, "SIP/2.0 486") {
			first = m
			break
		}
	}
	to := stubHeaders(first, "To")[0]
	ack := "ACK " + ruri + " SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:" + r.port() + ";branch=z9hG4bKrfcsweepaREJ\r\n" +
		"From: <sip:probe@127.0.0.1>;tag=rfcsweepa\r\nTo: " + to + "\r\nCall-ID: " + callID + "\r\nCSeq: 1 ACK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
	r.send(ack)
	time.Sleep(100 * time.Millisecond) // a copy already in flight when the ACK landed
	_, settled := r.responses("INVITE")
	before := len(settled)
	if stubWait(func() bool { _, after := r.responses("INVITE"); return len(after) > before }, 2*time.Second) {
		t.Errorf("a 486 retransmission after the ACK: the ACK must stop Timer G (NEW-A-35, RFC 3261 17.2.1)")
	}
}
