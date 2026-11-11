package sipua_test

// CF-101 wire tests: a lower remote CSeq draws 500. Raw UAC / raw stub from
// rfc3261_pin_uas_test.go and rfc3261_pin_uac_test.go.

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

func toTagOfOK(ok string) string {
	_, tag, _ := strings.Cut(stubHeaders(ok, "To")[0], "tag=")
	return tag
}

func TestLowerCSeqByeDraws500AndKeepsTheCall(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "cf5c-bye-low@127.0.0.1"
	tag := toTagOfOK(answered(t, ua, events, r, ruri, cid, 10))
	r.send(r.request("ACK", ruri, cid, "z9hG4bKcf5cBA", 10, tag, "", ""))
	r.send(r.request("INFO", ruri, cid, "z9hG4bKcf5cBI", 12, tag, "", ""))
	if !stubWait(func() bool { return r.hasCode("INFO", 200) }, 2*time.Second) {
		t.Fatal("INFO 12 was not answered 200")
	}
	r.send(r.request("BYE", ruri, cid, "z9hG4bKcf5cBB", 11, tag, "", ""))
	if !stubWait(func() bool { return r.hasCode("BYE", 500) }, 2*time.Second) {
		codes, _ := r.responses("BYE")
		t.Fatalf("the lower-CSeq BYE was answered %v, want 500", codes)
	}
	time.Sleep(500 * time.Millisecond)
	if n := countKind(events(), session.UAEventDialogEnded); n != 0 {
		t.Fatalf("the out-of-order BYE ended the call (%d dialog-ended events)", n)
	}
	done := make(chan error, 1)
	go func() { done <- ua.Hangup(context.Background(), idOf(events()), "") }()
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
		t.Fatal("our Hangup sent no BYE: the call was torn down")
	}
	r.send(stubResponse(bye, 200, "OK", "", nil, ""))
	if err := <-done; err != nil {
		t.Fatalf("Hangup after the rejected BYE: %v", err)
	}
}

func idOf(evs []session.UAEvent) string {
	for _, e := range evs {
		if e.Kind == session.UAEventInbound {
			return e.DialogID
		}
	}
	return ""
}

func TestEqualCSeqRequestIsNotRejected(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "cf5c-eq@127.0.0.1"
	tag := toTagOfOK(answered(t, ua, events, r, ruri, cid, 10))
	r.send(r.request("ACK", ruri, cid, "z9hG4bKcf5cEA", 10, tag, "", ""))
	r.send(r.request("INFO", ruri, cid, "z9hG4bKcf5cE1", 12, tag, "", ""))
	r.send(r.request("INFO", ruri, cid, "z9hG4bKcf5cE2", 12, tag, "", ""))
	if !stubWait(func() bool { codes, _ := r.responses("INFO"); return len(codes) >= 2 }, 2*time.Second) {
		t.Fatal("want two responses")
	}
	codes, _ := r.responses("INFO")
	for _, c := range codes {
		if c != 200 {
			t.Errorf("INFO responses %v, want all 200", codes)
		}
	}
}

func TestInboundRemoteCSeqIsSeededFromTheInvite(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "cf5c-seed@127.0.0.1"
	tag := toTagOfOK(answered(t, ua, events, r, ruri, cid, 10))
	r.send(r.request("ACK", ruri, cid, "z9hG4bKcf5cSA", 10, tag, "", ""))
	r.send(r.request("INFO", ruri, cid, "z9hG4bKcf5cS9", 9, tag, "", ""))
	if !stubWait(func() bool { return r.hasCode("INFO", 500) }, 2*time.Second) {
		codes, _ := r.responses("INFO")
		t.Fatalf("INFO 9 after INVITE 10 was answered %v, want 500", codes)
	}
	r.send(r.request("INFO", ruri, cid, "z9hG4bKcf5cS11", 11, tag, "", ""))
	if !stubWait(func() bool { return r.hasCode("INFO", 200) }, 2*time.Second) {
		t.Fatal("INFO 11 was not answered 200")
	}
}

// TestOutboundRemoteCSeqStartsAtThePeersFirstRequest: on an outbound dialog the
// remote number is empty until the peer's first in-dialog request.
func TestOutboundRemoteCSeqStartsAtThePeersFirstRequest(t *testing.T) {
	s := startUACStub(t, answer200())
	ua := newStubUA(t)
	dialStub(t, ua, s)
	inv := s.requests("INVITE")[0]
	contact := strings.Trim(stubHeaders(inv, "Contact")[0], "<>")
	hostport := strings.TrimPrefix(strings.SplitN(contact, ";", 2)[0], "sip:")
	if i := strings.Index(hostport, "@"); i >= 0 {
		hostport = hostport[i+1:]
	}
	to, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		t.Fatal(err)
	}
	send := func(cseq string, branch string) {
		s.send(to, "INFO "+contact+" SIP/2.0\r\nVia: SIP/2.0/UDP "+s.addr()+";branch=z9hG4bK"+branch+"\r\n"+
			"From: "+stubHeaders(inv, "To")[0]+";tag=stubtag\r\nTo: "+stubHeaders(inv, "From")[0]+"\r\n"+
			"Call-ID: "+stubHeaders(inv, "Call-ID")[0]+"\r\nCSeq: "+cseq+" INFO\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n")
	}
	send("100", "cf5cO100")
	if !stubWait(func() bool { return stubResponseCode(s, "100 INFO") == 200 }, 2*time.Second) {
		t.Fatalf("INFO 100 answered %d, want 200", stubResponseCode(s, "100 INFO"))
	}
	send("99", "cf5cO99")
	if !stubWait(func() bool { return stubResponseCode(s, "99 INFO") != 0 }, 2*time.Second) {
		t.Fatal("INFO 99 drew no response")
	}
	if got := stubResponseCode(s, "99 INFO"); got != 500 {
		t.Errorf("INFO 99 after INFO 100 drew %d, want 500", got)
	}
}
