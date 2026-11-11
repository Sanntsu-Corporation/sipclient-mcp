package sipua_test

// Lane B (rfc-sweep-b) pins for NEW-B findings that cite an RFC 3261 row of Lane
// A's checklist (6a D8, D11). Each passes today and must be inverted when its
// finding is fixed. No test here calls
// t.Parallel (parallel_invariant_test.go). They reuse Lane A's raw-UDP UAS stub
// (rfc3261_pin_uac_test.go); the UA under test has a 2 s transaction Timeout
// (newDirectUA), so each stays under D11's 5 s rule.

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// referStub answers the INVITE 200 and every REFER with referReply (nil = swallow).
func referStub(t *testing.T, referReply func(s *uacStub, raw string, from net.Addr)) *uacStub {
	t.Helper()
	return startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		switch stubMethod(raw) {
		case "INVITE":
			answer200()(s, raw, from)
		case "REFER":
			if referReply != nil {
				referReply(s, raw, from)
			}
		}
	})
}

func blindTransfer(t *testing.T, ua *sipua.UA, id string) session.TransferResult {
	t.Helper()
	return mustTransfer(t, ua, session.TransferRequest{
		DialogID: id, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
}

// TestRFC3261_NEWB4_ReferRetransmittedInProceeding is NEW-B-4 / CF-111, fixed:
// RFC 3261 17.1.2.2: "If Timer E fires while in the "Proceeding" state, the
// request MUST be passed to the transport layer for retransmission, and Timer E
// MUST be reset with a value of T2 seconds." rfc3261.txt:7321-7323. The stub
// answers every REFER 100 Trying and nothing else; within the UA's 2 s
// transaction Timeout Timer E (0.5 s) fires again and the same request (same
// Via branch, same CSeq) is retransmitted. (Evidence: evidence/ref-100/excerpt.txt
// frame 4-6.) Was the RFC3261 pin NEWB4_ReferNotRetransmittedAfterProvisional.
func TestRFC3261_NEWB4_ReferRetransmittedInProceeding(t *testing.T) {
	s := referStub(t, func(s *uacStub, raw string, from net.Addr) {
		s.send(from, stubResponse(raw, 100, "Trying", "", nil, ""))
	})
	ua := newStubUA(t)
	id := dialStub(t, ua, s)
	blindTransfer(t, ua, id) // returns at the 2 s transaction Timeout; Timer E fires at 0.5 s
	refers := s.requests("REFER")
	if len(refers) < 2 {
		t.Fatalf("the stub saw %d REFERs, want at least 2 (Timer E must keep retransmitting in Proceeding)", len(refers))
	}
	first, second := refers[0], refers[1]
	// sameAck normalises header-parameter order, which the vendored serializer
	// takes from a Go map.
	if !sameAck(first, second) {
		t.Errorf("retransmission differs from the original:\n%s\n---\n%s", first, second)
	}
}

// stubNotify sends one refer NOTIFY from the stub to the UA inside the dialog
// the stub's 200 created: From is the INVITE's To plus the stub's tag, To is the
// INVITE's From, the Request-URI is the INVITE's Contact.
func stubNotify(t *testing.T, s *uacStub, inv string, cseq int, statusLine, subState string) {
	t.Helper()
	stubNotifyEvent(t, s, inv, cseq, "refer", statusLine, subState)
}

// stubNotifyEvent is stubNotify with an explicit Event header value (for
// example "refer;id=7").
func stubNotifyEvent(t *testing.T, s *uacStub, inv string, cseq int, event, statusLine, subState string) {
	t.Helper()
	contact := strings.Trim(stubHeaders(inv, "Contact")[0], "<>")
	hostport := strings.TrimPrefix(strings.SplitN(contact, ";", 2)[0], "sip:")
	if i := strings.Index(hostport, "@"); i >= 0 {
		hostport = hostport[i+1:]
	}
	to, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		t.Fatalf("resolve %q: %v", hostport, err)
	}
	body := statusLine + "\r\n"
	msg := "NOTIFY " + contact + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + s.addr() + ";branch=z9hG4bKpinreobs" + strconv.Itoa(cseq) + "\r\n" +
		"From: " + stubHeaders(inv, "To")[0] + ";tag=stubtag\r\n" +
		"To: " + stubHeaders(inv, "From")[0] + "\r\n" +
		"Call-ID: " + stubHeaders(inv, "Call-ID")[0] + "\r\n" +
		"CSeq: " + strconv.Itoa(cseq) + " NOTIFY\r\nMax-Forwards: 70\r\n" +
		"Contact: <sip:stub@" + s.addr() + ">\r\nEvent: " + event + "\r\nSubscription-State: " + subState + "\r\n" +
		"Content-Type: message/sipfrag;version=2.0\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	s.send(to, msg)
}

// stubResponseCode returns the status code of the stub's first received
// response whose CSeq header is cseq (for example "5 NOTIFY"), or 0.
func stubResponseCode(s *uacStub, cseq string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.got {
		if !strings.HasPrefix(r, "SIP/2.0 ") {
			continue
		}
		if h := stubHeaders(r, "CSeq"); len(h) > 0 && h[0] == cseq {
			n, _ := strconv.Atoi(strings.Fields(r)[1])
			return n
		}
	}
	return 0
}

// TestRFC3261_ReobsCF101_NotifyLowerCSeqDraws500 is CF-101 (A-UAS-56, RFC 3261
// 12.2.2, rfc3261.txt:4269-4272) in onNotify, fixed: NOTIFY 10 (100 Trying,
// active) then NOTIFY 5 (200 OK, terminated): the second draws 500 and does NOT
// settle the transfer; a later NOTIFY 11 does. Was
// the old RFC3261 pin ReobsCF101_NotifyLowerCSeqIsNotRejected.
func TestRFC3261_ReobsCF101_NotifyLowerCSeqDraws500(t *testing.T) {
	s := referStub(t, func(s *uacStub, raw string, from net.Addr) {
		s.send(from, stubResponse(raw, 202, "Accepted", "", []string{"Contact: <sip:stub@" + s.addr() + ">"}, ""))
	})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	id := dialStub(t, ua, s)
	if out := blindTransfer(t, ua, id); !out.Accepted {
		t.Fatalf("result=%+v, want an accepted REFER", out)
	}
	inv := s.requests("INVITE")[0]
	stubNotify(t, s, inv, 10, "SIP/2.0 100 Trying", "active;expires=60")
	if !stubWait(func() bool { return stubResponseCode(s, "10 NOTIFY") != 0 }, 3*time.Second) {
		t.Fatal("the first NOTIFY drew no response")
	}
	stubNotify(t, s, inv, 5, "SIP/2.0 200 OK", "terminated;reason=noresource")
	if !stubWait(func() bool { return stubResponseCode(s, "5 NOTIFY") != 0 }, 3*time.Second) {
		t.Fatal("the lower-CSeq NOTIFY drew no response")
	}
	if got := stubResponseCode(s, "5 NOTIFY"); got != 500 {
		t.Errorf("the NOTIFY with a lower CSeq draws %d, want 500", got)
	}
	time.Sleep(500 * time.Millisecond)
	for _, ev := range events() {
		if ev.Kind == session.UAEventTransfer && ev.DialogID == id && ev.Detail["final"] == true {
			t.Fatalf("the out-of-order NOTIFY settled the transfer: %+v", ev)
		}
	}
	stubNotify(t, s, inv, 11, "SIP/2.0 200 OK", "terminated;reason=noresource")
	if !stubWait(func() bool {
		for _, ev := range events() {
			if ev.Kind == session.UAEventTransfer && ev.Detail["final"] == true && ev.Code == 200 {
				return true
			}
		}
		return false
	}, 3*time.Second) {
		t.Fatal("the in-order NOTIFY 11 did not settle the transfer")
	}
}
