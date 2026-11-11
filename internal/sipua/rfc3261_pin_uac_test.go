package sipua_test

// Lane A (rfc-sweep-a) pins for the A-UAC area. Each passes today and must be
// inverted when its NEW-A finding is fixed.
// No test here calls t.Parallel (parallel_invariant_test.go). The peer package
// answers every INVITE itself and cannot script Record-Route, forks, 3xx or
// duplicate Via values, so these tests use a small raw-UDP UAS stub.

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
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

const stubSDP = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"

// uacStub is a raw UDP UAS. onMsg runs for every datagram except BYE, which is
// answered 200 so that closing the UA under test never waits on it.
type uacStub struct {
	pc  net.PacketConn
	mu  sync.Mutex
	got []string
}

func startUACStub(t *testing.T, onMsg func(s *uacStub, raw string, from net.Addr)) *uacStub {
	t.Helper()
	return startUACStubAt(t, "127.0.0.1:0", onMsg)
}

// startUACStubAt is startUACStub on a chosen local address (Linux routes all of
// 127/8 to lo, so 127.0.0.2:0 is a second distinct host).
func startUACStubAt(t *testing.T, listen string, onMsg func(s *uacStub, raw string, from net.Addr)) *uacStub {
	t.Helper()
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		t.Fatalf("stub listen: %v", err)
	}
	s := &uacStub{pc: pc}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			raw := string(buf[:n])
			s.mu.Lock()
			s.got = append(s.got, raw)
			s.mu.Unlock()
			if stubMethod(raw) == "BYE" {
				s.send(from, stubResponse(raw, 200, "OK", "", nil, ""))
				continue
			}
			onMsg(s, raw, from)
		}
	}()
	return s
}

func (s *uacStub) addr() string { return s.pc.LocalAddr().String() }

func (s *uacStub) send(to net.Addr, msg string) { _, _ = s.pc.WriteTo([]byte(msg), to) }

// requests returns the received datagrams whose method is method, in order.
func (s *uacStub) requests(method string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.got {
		if stubMethod(r) == method {
			out = append(out, r)
		}
	}
	return out
}

func stubMethod(raw string) string {
	line, _, _ := strings.Cut(raw, "\r\n")
	m, _, _ := strings.Cut(line, " ")
	return m
}

// stubRequestURI returns the Request-URI of a request datagram.
func stubRequestURI(raw string) string {
	line, _, _ := strings.Cut(raw, "\r\n")
	f := strings.Fields(line)
	if len(f) < 2 {
		return ""
	}
	return f[1]
}

// stubHeaders returns every value of header name (case-insensitive) in a message head.
func stubHeaders(raw, name string) []string {
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	var out []string
	for _, l := range strings.Split(head, "\r\n")[1:] {
		k, v, ok := strings.Cut(l, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}

func stubCSeq(raw string) int {
	h := stubHeaders(raw, "CSeq")
	if len(h) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(strings.Fields(h[0])[0])
	return n
}

// stubResponse answers req: every Via, From, Call-ID and CSeq are echoed, To
// gets toTag when the request has none.
func stubResponse(req string, code int, reason, toTag string, extra []string, body string) string {
	var b strings.Builder
	b.WriteString("SIP/2.0 " + strconv.Itoa(code) + " " + reason + "\r\n")
	for _, v := range stubHeaders(req, "Via") {
		b.WriteString("Via: " + v + "\r\n")
	}
	b.WriteString("From: " + stubHeaders(req, "From")[0] + "\r\n")
	to := stubHeaders(req, "To")[0]
	if toTag != "" && !strings.Contains(to, "tag=") {
		to += ";tag=" + toTag
	}
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Call-ID: " + stubHeaders(req, "Call-ID")[0] + "\r\n")
	b.WriteString("CSeq: " + stubHeaders(req, "CSeq")[0] + "\r\n")
	for _, e := range extra {
		b.WriteString(e + "\r\n")
	}
	if body != "" {
		b.WriteString("Content-Type: application/sdp\r\n")
	}
	b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body)
	return b.String()
}

// answer200 is the standard stub behaviour: 200 with SDP and a Contact on the stub.
func answer200(extra ...string) func(*uacStub, string, net.Addr) {
	return func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		hdr := append([]string{"Contact: <sip:stub@" + s.addr() + ">"}, extra...)
		s.send(from, stubResponse(raw, 200, "OK", "stubtag", hdr, stubSDP))
	}
}

// stubWait polls cond for up to d.
func stubWait(cond func() bool, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// dialStub dials the stub and waits until it has seen the ACK. It returns the
// dialog id.
func dialStub(t *testing.T, ua *sipua.UA, s *uacStub) string {
	t.Helper()
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + s.addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if !stubWait(func() bool { return len(s.requests("ACK")) > 0 }, 3*time.Second) {
		t.Fatal("the stub never saw an ACK")
	}
	return res.DialogID
}

func newStubUA(t *testing.T) *sipua.UA {
	t.Helper()
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	_ = collect(t, ua)
	return ua
}

// TestRFC3261Pin_NEWA14_InviteHasNoAllow pins NEW-A-14 (A-UAC-66, RFC 3261
// 13.2.1: "An Allow header field (Section 20.5) SHOULD be present in the
// INVITE." rfc3261.txt:4357-4357). Evidence: evidence/uac-basic/excerpt.txt frame 1.
//
// PIN OF A DEVIATION: invert this assertion when NEW-A-14 is fixed.
func TestRFC3261Pin_NEWA14_InviteHasNoAllow(t *testing.T) {
	s := startUACStub(t, answer200())
	ua := newStubUA(t)
	dialStub(t, ua, s)
	inv := s.requests("INVITE")
	if len(inv) == 0 {
		t.Fatal("no INVITE received")
	}
	if a := stubHeaders(inv[0], "Allow"); len(a) != 0 {
		t.Errorf("the INVITE now carries Allow %q: NEW-A-14 is fixed, invert this pin", a)
	}
}

// TestRFC3261_NEWA15_FirstInDialogCSeqIsInvitePlusOne is NEW-A-15 / CF-085,
// fixed: RFC 3261 12.2.1.1: "Requests within a dialog MUST contain strictly
// monotonically increasing and contiguous CSeq sequence numbers (increasing-by-one)
// in each direction" rfc3261.txt:4075-4078. The first in-dialog request (the BYE)
// carries the answered INVITE's CSeq + 1. Was
// the old RFC3261 pin NEWA15_FirstInDialogCSeqSkipsOne.
func TestRFC3261_NEWA15_FirstInDialogCSeqIsInvitePlusOne(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	p.WaitForBye(t, 3*time.Second)
	inv, bye := p.AnsweredInviteCSeq(), p.LastByeCSeq()
	if bye != inv+1 {
		t.Errorf("BYE CSeq %d, want the INVITE's %d + 1", bye, inv)
	}
}

// TestRFC3261_NEWA16_ByeCarriesTheRouteSet is NEW-A-16 / CF-086, fixed: RFC 3261
// 12.2.1.1 (loose routing): the BYE carries the route set (the 200's
// Record-Route values in reverse order) as Route headers, and its Request-URI
// is the 200's Contact. Was the RFC3261 pin NEWA16_ByeIgnoresRouteSet.
func TestRFC3261_NEWA16_ByeCarriesTheRouteSet(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{
			"Contact: <sip:stub@" + s.addr() + ">",
			"Record-Route: <sip:" + s.addr() + ";lr;rr=1>",
			"Record-Route: <sip:" + s.addr() + ";lr;rr=2>",
		}, stubSDP))
	})
	ua := newStubUA(t)
	id := dialStub(t, ua, s)
	if err := ua.Hangup(context.Background(), id, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	if !stubWait(func() bool { return len(s.requests("BYE")) > 0 }, 3*time.Second) {
		t.Fatal("the stub never saw a BYE")
	}
	bye := s.requests("BYE")[0]
	r := stubHeaders(bye, "Route")
	if len(r) != 2 || !strings.Contains(r[0], "rr=2") || !strings.Contains(r[1], "rr=1") {
		t.Errorf("BYE Route = %v, want rr=2 then rr=1", r)
	}
	if got, want := stubRequestURI(bye), "sip:stub@"+s.addr(); got != want {
		t.Errorf("BYE Request-URI %q, want the Contact %q", got, want)
	}
}

// TestRFC3261_NEWA17_AckFor2xxCarriesCredentials covers NEW-A-17 / CF-087
// (A-UAC-83, RFC 3261 13.2.2.4: "The ACK MUST contain the same credentials as
// the INVITE." rfc3261.txt:4577). Evidence of the old deviation:
// evidence/uac-407/excerpt.txt frame 4, 7.
func TestRFC3261_NEWA17_AckFor2xxCarriesCredentials(t *testing.T) {
	s, ua := credStubAndUA(t, 407, "Proxy-Authenticate", nil)
	dialStub(t, ua, s)

	ack200, retry := ackOfCredentialedRetry(t, s)
	got, want := stubHeaders(ack200, "Proxy-Authorization"), stubHeaders(retry, "Proxy-Authorization")
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("the ACK for the 200 carries Proxy-Authorization %q, want exactly the retry INVITE's %q", got, want)
	}
}

// TestRFC3261_NEWA18_RetransmittedTwoxxIsReAcked: NEW-A-18 fixed (A-UAC-85,
// CF-088, RFC 3261 13.2.2: "The ACK MUST be passed to the client transport every
// time a retransmission of the 2xx final response that triggered the ACK
// arrives." rfc3261.txt:4587-4590). Evidence of the old deviation:
// evidence/uac-2xx-retx/excerpt.txt frame 3-5. Flipped from the NEW-A-18 pin.
func TestRFC3261_NEWA18_RetransmittedTwoxxIsReAcked(t *testing.T) {
	var mu sync.Mutex
	var ok string
	var from net.Addr
	s := startUACStub(t, func(s *uacStub, raw string, f net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		resp := stubResponse(raw, 200, "OK", "stubtag", []string{"Contact: <sip:stub@" + s.addr() + ">"}, stubSDP)
		mu.Lock()
		ok, from = resp, f
		mu.Unlock()
		s.send(f, resp)
	})
	ua := newStubUA(t)
	dialStub(t, ua, s)
	mu.Lock()
	retx, to := ok, from
	mu.Unlock()
	s.send(to, retx)
	settle(s, 2, 0)
	acks := s.requests("ACK")
	if len(acks) != 2 {
		t.Fatalf("%d ACKs for one 200 and its retransmission, want 2", len(acks))
	}
	if !sameAck(acks[0], acks[1]) {
		t.Errorf("the re-sent ACK differs from the first (same Via branch and CSeq expected):\n%s\n---\n%s", acks[0], acks[1])
	}
	if n := len(s.requests("BYE")); n != 0 {
		t.Errorf("%d BYE(s) for a retransmission of the dialog's own 2xx", n)
	}
}

// TestRFC3261_NEWA19_SecondForkTwoxxIsAckedAndByed: NEW-A-19 fixed (A-UAC-80,
// CF-107, RFC 3261 13.2.2.4: "The UAC core MUST generate an ACK request for
// each 2xx received from the transaction layer." rfc3261.txt:4571-4572; "If,
// after acknowledging any 2xx response to an INVITE, the UAC does not want to
// continue with that dialog, then the UAC MUST terminate the dialog by sending
// a BYE request" rfc3261.txt:4605-4607). Evidence of the old deviation:
// evidence/uac-fork/excerpt.txt frame 4-7. The forkB 200 is sent when the
// forkA ACK arrives (sent back to back the UA may ACK either one first).
// Flipped from the NEW-A-19 pin.
func TestRFC3261_NEWA19_SecondForkTwoxxIsAckedAndByed(t *testing.T) {
	s := forkStub(t, nil, "forkB")
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	id := dialStub(t, ua, s)
	waitFor(t, events, session.UAEventFinal, 200)
	settle(s, 2, 1)
	acks, byes := s.requests("ACK"), s.requests("BYE")
	if got := tagCounts(acks); len(acks) != 2 || got["forkA"] != 1 || got["forkB"] != 1 {
		t.Errorf("ACKs by To tag = %v (%d), want forkA 1, forkB 1", got, len(acks))
	}
	if len(byes) != 1 || stubToTag(byes[0]) != "forkB" {
		t.Fatalf("BYEs by To tag = %v (%d), want exactly one, to forkB", tagCounts(byes), len(byes))
	}
	want := strconv.Itoa(stubCSeq(s.requests("INVITE")[0])+1) + " BYE"
	if got := stubHeaders(byes[0], "CSeq")[0]; got != want {
		t.Errorf("fork BYE CSeq %q, want %q", got, want)
	}
	// The call is still answered: our own hangup BYEs dialog A.
	if err := ua.Hangup(context.Background(), id, ""); err != nil {
		t.Fatalf("Hangup of the answered call: %v", err)
	}
	if !stubWait(func() bool { return tagCounts(s.requests("BYE"))["forkA"] == 1 }, 3*time.Second) {
		t.Errorf("no BYE to forkA after our hangup; BYEs by To tag = %v", tagCounts(s.requests("BYE")))
	}
}

// answer302 redirects to a distinct Contact and records nothing else.
func answer302(s *uacStub, raw string, from net.Addr) {
	if stubMethod(raw) != "INVITE" {
		return
	}
	s.send(from, stubResponse(raw, 302, "Moved Temporarily", "stubtag",
		[]string{"Contact: <sip:alt@" + s.addr() + ">"}, ""))
}

// TestRFC3261_NEWA20_NonTwoxxAckKeepsTheInviteRequestURI covers NEW-A-20 / CF-089
// (A-UAC-123, RFC 3261 17.1.1.3: the ACK "MUST contain values for the Call-ID,
// From, and Request-URI that are equal to the values of those header fields in
// the request passed to the transport by the client transaction" rfc3261.txt:
// 7201-7204). The stub UA sets no redirect check, so the 302 stays final.
func TestRFC3261_NEWA20_NonTwoxxAckKeepsTheInviteRequestURI(t *testing.T) {
	s := startUACStub(t, answer302)
	ua := newStubUA(t)
	dialStub(t, ua, s)
	inv, ack := stubRequestURI(s.requests("INVITE")[0]), stubRequestURI(s.requests("ACK")[0])
	if ack != inv {
		t.Errorf("the ACK for the 302 carries Request-URI %q, want the INVITE's %q", ack, inv)
	}
}

// TestRFC3261_NEWA21_RedirectIsFollowed covers NEW-A-21 / CF-090 (A-UAC-07, RFC
// 3261 8.1.3.4: "Upon receipt of a redirection response ..., clients SHOULD use
// the URI(s) in the Contact header field to formulate one or more new requests"
// rfc3261.txt:2370-2373). Evidence of the old deviation:
// evidence/uac-302/excerpt.txt frame 1-3.
func TestRFC3261_NEWA21_RedirectIsFollowed(t *testing.T) {
	for _, code := range []int{300, 301, 302} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
				if stubMethod(raw) != "INVITE" {
					return
				}
				switch ruriUser(raw) {
				case "bob":
					s.send(from, stubResponse(raw, code, "Redirect", "stubtag",
						[]string{"Contact: <sip:alt@" + s.addr() + ">"}, ""))
				case "alt":
					s.send(from, stubResponse(raw, 200, "OK", "stubtag2",
						[]string{"Contact: <sip:stub@" + s.addr() + ">"}, stubSDP))
				}
			})
			ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
			events := collect(t, ua)
			dialRedirect(t, ua, "sip:bob@"+s.addr(), 3, redirectIdentity)
			waitFor(t, events, session.UAEventFinal, 200)
			invs := s.requests("INVITE")
			if len(invs) != 2 {
				t.Fatalf("INVITEs = %d, want 2", len(invs))
			}
			if got, want := stubRequestURI(invs[1]), "sip:alt@"+s.addr(); got != want {
				t.Errorf("second INVITE Request-URI = %q, want %q", got, want)
			}
			if stubHeaders(invs[0], "Call-ID")[0] != stubHeaders(invs[1], "Call-ID")[0] {
				t.Error("the redirected INVITE changed the Call-ID")
			}
			if fromTag(invs[0]) != fromTag(invs[1]) {
				t.Error("the redirected INVITE changed the From tag")
			}
			if stubCSeq(invs[1]) != stubCSeq(invs[0])+1 {
				t.Errorf("CSeq %d then %d, want +1", stubCSeq(invs[0]), stubCSeq(invs[1]))
			}
			if viaBranch(invs[0]) == viaBranch(invs[1]) {
				t.Error("the redirected INVITE reused the Via branch")
			}
			if strings.Contains(stubHeaders(invs[1], "To")[0], "tag=") {
				t.Error("the redirected INVITE's To carries a tag")
			}
			finals := 0
			for _, ev := range events() {
				if ev.Kind == session.UAEventFinal {
					finals++
				}
			}
			if finals != 1 {
				t.Errorf("final events = %d, want 1", finals)
			}
		})
	}
}

// TestRFC3261Pin_NEWA22_ResponseWithTwoViasIsAccepted pins NEW-A-22 (A-UAC-06,
// RFC 3261 8.1.3.3: "If more than one Via header field value is present in a
// response, the UAC SHOULD discard the message." rfc3261.txt:2361-2362).
// Evidence: evidence/uac-multi-via/excerpt.txt frame 3-4.
//
// PIN OF A DEVIATION: invert this assertion when NEW-A-22 is fixed.
func TestRFC3261Pin_NEWA22_ResponseWithTwoViasIsAccepted(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{
			"Via: SIP/2.0/UDP 127.0.0.2:5099;branch=z9hG4bKrfcsweepaextra",
			"Contact: <sip:stub@" + s.addr() + ">",
		}, stubSDP))
	})
	ua := newStubUA(t)
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + s.addr()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if !stubWait(func() bool { return len(s.requests("ACK")) > 0 }, 3*time.Second) {
		t.Errorf("no ACK for a 200 with two Via values: NEW-A-22 is fixed, invert this pin")
	}
}

// TestRFC3261_NEWA36_InDialogRequestUsesTheRemoteTarget is NEW-A-36 / CF-105,
// fixed: RFC 3261 12.2.1.1: "If the route set is empty, the UAC MUST place the
// remote target URI into the Request-URI." rfc3261.txt:4107-4108. The stub's 200
// carries Contact sip:stub@..., unlike the dialled sip:bob@...; the BYE goes to
// the Contact. Was the RFC3261 pin NEWA36_InDialogRequestIgnoresRemoteTarget.
func TestRFC3261_NEWA36_InDialogRequestUsesTheRemoteTarget(t *testing.T) {
	s := startUACStub(t, answer200())
	ua := newStubUA(t)
	id := dialStub(t, ua, s)
	if err := ua.Hangup(context.Background(), id, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	if !stubWait(func() bool { return len(s.requests("BYE")) > 0 }, 3*time.Second) {
		t.Fatal("the stub never saw a BYE")
	}
	if got, want := stubRequestURI(s.requests("BYE")[0]), "sip:stub@"+s.addr(); got != want {
		t.Errorf("BYE Request-URI %q, want the 200's Contact %q", got, want)
	}
}
