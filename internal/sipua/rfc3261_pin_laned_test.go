package sipua_test

// Lane D (rfc-sweep-d) pins for NEW-D findings that cite a Lane A RFC 3261 row
// (6a D8, D11). Each passes today and must be inverted when its finding is
// fixed. Lane A's raw caller
// (rfc3261_pin_uas_test.go) sends the shapes the peer double cannot: request
// fixes Content-Type, so the body labels are rewritten in the hand-built text.

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

// laneDInvite sends an INVITE built by rawUAC.request, optionally rewritten, and
// returns the UA's dialog id once the inbound event arrives.
func laneDInvite(t *testing.T, id, extra, body string, rewrite func(string) string) (*rawUAC, func() []session.UAEvent, string, func(string) error) {
	t.Helper()
	ua, events, r, ruri := uasUA(t)
	msg := r.request("INVITE", ruri, "rfcsweepd-"+id+"@127.0.0.1", "z9hG4bKrfcsweepdI"+id, 1, "", extra, body)
	if rewrite != nil {
		msg = rewrite(msg)
	}
	r.send(msg)
	in := waitFor(t, events, session.UAEventInbound, 0)
	return r, events, in.DialogID, func(dlg string) error {
		return ua.Answer(context.Background(), session.AnswerRequest{DialogID: dlg})
	}
}

func laneDWaitFinal(t *testing.T, r *rawUAC) (int, string) {
	t.Helper()
	var code int
	var msg string
	if !stubWait(func() bool {
		codes, msgs := r.responses("INVITE")
		for i, c := range codes {
			if c >= 200 {
				code, msg = c, msgs[i]
				return true
			}
		}
		return false
	}, 3*time.Second) {
		t.Fatal("no final response to the INVITE")
	}
	return code, msg
}

// TestRFC3261Pin_NEWD13_NoCommonCodecRejectHasNoWarning pins NEW-D-13 (L12,
// A-UAS-68, RFC 3261 13.3.1: "Such a response SHOULD include a Warning header
// field value explaining why the offer was rejected." rfc3261.txt:4727-4728).
// Evidence: evidence/s-nocommon/excerpt.txt (the 488 to an offer of G.722 and
// events only has no Warning). Locus: internal/sipua/call.go:Answer (the 488
// path).
//
// PIN OF A DEVIATION: invert this assertion when NEW-D-13 is fixed.
func TestRFC3261Pin_NEWD13_NoCommonCodecRejectHasNoWarning(t *testing.T) {
	body := "v=0\r\no=probe 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 15282 RTP/AVP 9 101\r\na=rtpmap:101 telephone-event/8000\r\n"
	r, _, dlg, answer := laneDInvite(t, "nc", "", body, nil)
	if err := answer(dlg); err == nil {
		t.Fatal("Answer succeeded for an offer with no common codec (the pin's precondition)")
	}
	code, msg := laneDWaitFinal(t, r)
	if code != 488 {
		t.Fatalf("final response %d, want 488 (the pin's precondition)", code)
	}
	if w := stubHeaders(msg, "Warning"); len(w) != 0 {
		t.Fatalf("488 carries Warning %v: NEW-D-13 is fixed, invert this pin", w)
	}
}

// TestRFC3261_NEWD14_OfferlessInviteGetsOfferIn2xxAnswerFromAck is NEW-D-14
// fixed (L11, A-UAC-75, CF-145; RFC 3261 13.1: "All user agents that support
// INVITE MUST support these two exchanges." rfc3261.txt:4462; 13.3.1: the UAS
// "MUST provide the offer in its first non-failure reliable message",
// rfc3261.txt:4661-4665, and the answer is in the ACK, rfc3261.txt:4441-4444).
// Evidence of the old 488: evidence/s-nobody/excerpt.txt. Locus:
// internal/sipua/call.go:Answer, onAck and applyAckAnswer. The caller helpers
// are in offerless_invite_test.go.
func TestRFC3261_NEWD14_OfferlessInviteGetsOfferIn2xxAnswerFromAck(t *testing.T) {
	c := startOfferless(t, "nb")
	sock, port := laneDMediaSocket(t)
	c.answer(t)
	if ct := stubHeaders(c.ok, "Content-Type"); len(ct) != 1 || ct[0] != "application/sdp" {
		t.Fatalf("200 Content-Type %v, want application/sdp", ct)
	}
	var m []string
	for _, l := range strings.Split(c.ok, "\r\n") {
		if strings.HasPrefix(l, "m=audio ") {
			m = strings.Fields(l)
		}
	}
	if len(m) < 4 || strings.Join(m[3:], " ") != "0 8 101" {
		t.Fatalf("200's m= line %v, want every codec preference plus 101 (0 8 101)", m)
	}
	c.goodAck(port)
	if pt := rtpWithin(sock, 2*time.Second); pt != 8 {
		t.Fatalf("RTP payload type %d at the ACK's port, want 8 (PCMA, the answered codec)", pt)
	}
}

// TestRFC3261_NEWD30_EarlySDPIsTheAnswer covers NEW-D-30 / CF-161 (L24,
// A-UAC-72, RFC 3261 13.2.1: "The UAC MUST treat the first session description
// it receives as the answer, and MUST ignore any session descriptions in
// subsequent responses to the initial INVITE." rfc3261.txt:4436-4439).
// Evidence of the old deviation: evidence/u-early/excerpt.txt frames 2 (183
// with m=audio 15282 RTP/AVP 8 101) and 3 (200 with m=audio 15284 RTP/AVP 0 101).
// The 183's SDP is the answer: our RTP reaches its port and never the 200's.
func TestRFC3261_NEWD30_EarlySDPIsTheAnswer(t *testing.T) {
	a, b := newEarlySink(t), newEarlySink(t)
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		contact := "Contact: <sip:stub@" + s.addr() + ">"
		s.send(from, stubResponse(raw, 183, "Session Progress", "stubtag", []string{contact}, earlySDP(a.port, "8")))
		time.Sleep(100 * time.Millisecond)
		s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{contact}, earlySDP(b.port, "0")))
	})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU", "PCMA"}, "disabled")
	_ = collect(t, ua)
	id := dialStub(t, ua, s)
	a.expectRTP(t, 2*time.Second, "the 183's port")
	b.expectNoRTP(t, "the 200's port")
	if mv, ok := ua.MediaView(id); !ok || mv.Codec != "PCMA" {
		t.Errorf("MediaView = %+v ok=%v, want codec PCMA (the 183's)", mv, ok)
	}
}

// laneDMediaSocket is a test-owned UDP socket used as an SDP media port.
func laneDMediaSocket(t *testing.T) (*net.UDPConn, int) {
	t.Helper()
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("media socket: %v", err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	return sock, sock.LocalAddr().(*net.UDPAddr).Port
}

func laneDSDP(version, port int) string {
	return "v=0\r\no=probe 1 " + strconv.Itoa(version) + " IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
		"m=audio " + strconv.Itoa(port) + " RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n"
}

// NEW-D-34 (an offerless re-INVITE got our last answer as its offer) was fixed by
// CF-165 and CF-207: see TestRFC3261_NEWD34_OfferlessReInviteGetsAFreshOffer in
// reinvite_offerless_test.go.
