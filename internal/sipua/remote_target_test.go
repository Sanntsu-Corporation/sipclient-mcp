package sipua_test

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// CF-184 wire tests: a target-refresh request, or the 2xx to ours, moves the
// dialog's remote target, and the next in-dialog request (our BYE) follows it.

// sinkStub is a second raw UDP endpoint; its BYE is answered 200 by uacStub.
func sinkStub(t *testing.T) *uacStub {
	t.Helper()
	return startUACStub(t, func(*uacStub, string, net.Addr) {})
}

// withContact swaps the raw caller's Contact for c.
func withContact(r *rawUAC, msg, c string) string {
	return strings.Replace(msg, "Contact: <sip:probe@127.0.0.1:"+r.port()+">", "Contact: "+c, 1)
}

// rawGotRequest reports whether the raw caller received a request of method.
func rawGotRequest(r *rawUAC, method string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.got {
		if stubMethod(m) == method {
			return true
		}
	}
	return false
}

func inboundDialogID(t *testing.T, events func() []session.UAEvent) string {
	t.Helper()
	for _, e := range events() {
		if e.Kind == session.UAEventInbound {
			return e.DialogID
		}
	}
	t.Fatal("no inbound dialog")
	return ""
}

func expectByeAt(t *testing.T, s *uacStub, ruri string) {
	t.Helper()
	if !stubWait(func() bool { return len(s.requests("BYE")) > 0 }, 3*time.Second) {
		t.Fatalf("no BYE reached the refreshed target")
	}
	if got := stubRequestURI(s.requests("BYE")[0]); got != ruri {
		t.Fatalf("BYE Request-URI %q, want %q", got, ruri)
	}
}

func TestReInviteContactRefreshesTheRemoteTarget(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "cf184-reinv@127.0.0.1"
	tag := answeredTag(t, ua, events, r, ruri, cid)
	moved := sinkStub(t)
	c := "<sip:moved@" + moved.addr() + ">"
	r.send(withContact(r, r.request("INVITE", ruri, cid, "z9hG4bKcf184A", 11, tag, "", stubSDP), c))
	if !stubWait(func() bool { return countCode(r, "INVITE", 200) == 2 }, 3*time.Second) {
		t.Fatal("no 200 to the re-INVITE")
	}
	if err := ua.Hangup(context.Background(), inboundDialogID(t, events), ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	expectByeAt(t, moved, "sip:moved@"+moved.addr())
}

func TestUpdateContactRefreshesTheRemoteTarget(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "cf184-upd@127.0.0.1"
	tag := answeredTag(t, ua, events, r, ruri, cid)
	moved := sinkStub(t)
	c := "<sip:moved@" + moved.addr() + ">"
	r.send(withContact(r, r.request("UPDATE", ruri, cid, "z9hG4bKcf184B", 11, tag, "", ""), c))
	if !stubWait(func() bool { return r.hasCode("UPDATE", 200) }, 3*time.Second) {
		t.Fatal("no 200 to the UPDATE")
	}
	if err := ua.Hangup(context.Background(), inboundDialogID(t, events), ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	expectByeAt(t, moved, "sip:moved@"+moved.addr())
}

// TestRefusedRefreshDoesNotRefreshTheTarget: a non-2xx answer to a refresh changes
// nothing (RFC 6141 4.6); the BYE goes to the original Contact (the raw caller).
func TestRefusedRefreshDoesNotRefreshTheTarget(t *testing.T) {
	const badSDP = "v=0\r\no=- 9 9 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\n"
	for _, method := range []string{"INVITE", "UPDATE"} {
		t.Run(method, func(t *testing.T) {
			ua, events, r, ruri := uasUA(t)
			cid := "cf184-refused-" + method + "@127.0.0.1"
			tag := answeredTag(t, ua, events, r, ruri, cid)
			moved := sinkStub(t)
			c := "<sip:moved@" + moved.addr() + ">"
			r.send(withContact(r, r.request(method, ruri, cid, "z9hG4bKcf184R", 11, tag, "", badSDP), c))
			if !stubWait(func() bool { return countCode(r, method, 488) == 1 }, 3*time.Second) {
				codes, _ := r.responses(method)
				t.Fatalf("%s answered %v, want 488", method, codes)
			}
			if err := ua.Hangup(context.Background(), inboundDialogID(t, events), ""); err != nil {
				t.Fatalf("Hangup: %v", err)
			}
			if !stubWait(func() bool { return rawGotRequest(r, "BYE") }, 3*time.Second) {
				t.Fatal("the BYE did not go to the original Contact")
			}
			if n := len(moved.requests("BYE")); n != 0 {
				t.Fatalf("%d BYE(s) went to the target of a refused refresh", n)
			}
		})
	}
}

// TestOutboundDialogRefreshedByAPeerReInvite: the dialog we dialled; the callee
// re-INVITEs from a new Contact.
func TestOutboundDialogRefreshedByAPeerReInvite(t *testing.T) {
	s := startUACStub(t, answer200())
	moved := sinkStub(t)
	ua := newStubUA(t)
	id := dialStub(t, ua, s)
	inv := s.requests("INVITE")[0]
	re := "INVITE sip:alice@" + ua.BoundAddr().String() + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + s.addr() + ";branch=z9hG4bKcf184O\r\n" +
		"From: <sip:bob@" + s.addr() + ">;tag=stubtag\r\n" +
		"To: " + stubHeaders(inv, "From")[0] + "\r\n" +
		"Call-ID: " + stubHeaders(inv, "Call-ID")[0] + "\r\n" +
		"CSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContact: <sip:callee2@" + moved.addr() + ">\r\n" +
		"Content-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(len(stubSDP)) + "\r\n\r\n" + stubSDP
	dst, _ := net.ResolveUDPAddr("udp", ua.BoundAddr().String())
	s.send(dst, re)
	if !stubWait(func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, m := range s.got {
			if strings.HasPrefix(m, "SIP/2.0 200") && strings.Contains(m, "CSeq: 1 INVITE") {
				return true
			}
		}
		return false
	}, 3*time.Second) {
		t.Fatal("no 200 to the callee's re-INVITE")
	}
	if err := ua.Hangup(context.Background(), id, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	expectByeAt(t, moved, "sip:callee2@"+moved.addr())
}

// TestOurRefreshTwoxxRefreshesTheTarget: the 2xx to our session-timer UPDATE
// carries a new Contact; the next in-dialog request goes there.
func TestOurRefreshTwoxxRefreshesTheTarget(t *testing.T) {
	moved := sinkStub(t)
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		switch stubMethod(raw) {
		case "INVITE":
			s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{
				"Contact: <sip:stub@" + s.addr() + ">", "Supported: timer", "Require: timer",
				"Session-Expires: 90;refresher=uac", "Allow: INVITE, ACK, BYE, CANCEL, UPDATE"}, stubSDP))
		case "UPDATE":
			s.send(from, stubResponse(raw, 200, "OK", "", []string{
				"Contact: <sip:stub2@" + moved.addr() + ">", "Session-Expires: 90;refresher=uac"}, ""))
		}
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 60)
	_ = collect(t, ua)
	id := dialStub(t, ua, s)
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	if !stubWait(func() bool { return len(s.requests("UPDATE")) > 0 }, 3*time.Second) {
		t.Fatal("no refresh UPDATE")
	}
	// the refresh 2xx has been processed once the UA is idle again
	time.Sleep(200 * time.Millisecond)
	if err := ua.Hangup(context.Background(), id, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	expectByeAt(t, moved, "sip:stub2@"+moved.addr())
}
