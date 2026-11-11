package sipua_test

// CF-145 (NEW-D-14, RFC 3261 13.3.1, rfc3261.txt:4661-4665 and 4441-4444): an
// INVITE without a session description is answered with our offer in the 200,
// and the caller's ACK carries the answer. The caller is the raw UDP caller of
// rfc3261_pin_uas_test.go, so the ACK's tags, branch, CSeq and body are chosen
// by the test.

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
)

// offerlessCall is one inbound call set up by an INVITE without a body.
type offerlessCall struct {
	ua     *sipua.UA
	events func() []session.UAEvent
	r      *rawUAC
	ruri   string
	cid    string
	branch string
	dlg    string
	ok     string // the 200's text, once answered
}

// startOfferless sends an INVITE without a body and waits for the inbound
// event. Every BYE the caller receives is answered 200.
func startOfferless(t *testing.T, id string) *offerlessCall {
	t.Helper()
	ua, events, r, ruri := uasUA(t)
	c := &offerlessCall{ua: ua, events: events, r: r, ruri: ruri,
		cid: "cf145-" + id + "@127.0.0.1", branch: "z9hG4bKcf145I" + id}
	r.send(r.request("INVITE", ruri, c.cid, c.branch, 1, "", "", ""))
	c.dlg = waitFor(t, events, session.UAEventInbound, 0).DialogID
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		answered := map[string]bool{}
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			for _, m := range c.requests("BYE") {
				if cs := stubHeaders(m, "CSeq")[0]; !answered[cs] {
					answered[cs] = true
					r.send(stubResponse(m, 200, "OK", "", nil, ""))
				}
			}
		}
	}()
	return c
}

// requests returns every request of method the caller received.
func (c *offerlessCall) requests(method string) []string {
	c.r.mu.Lock()
	defer c.r.mu.Unlock()
	var out []string
	for _, m := range c.r.got {
		if strings.HasPrefix(m, method+" ") {
			out = append(out, m)
		}
	}
	return out
}

// byeCount is the number of distinct BYEs (by CSeq) the caller received.
func (c *offerlessCall) byeCount() int {
	seen := map[string]bool{}
	for _, m := range c.requests("BYE") {
		seen[stubHeaders(m, "CSeq")[0]] = true
	}
	return len(seen)
}

// answer runs Answer (nil error required) and waits for the 200.
func (c *offerlessCall) answer(t *testing.T) {
	t.Helper()
	if err := c.ua.Answer(context.Background(), session.AnswerRequest{DialogID: c.dlg}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	c.wait200(t)
}

func (c *offerlessCall) wait200(t *testing.T) {
	t.Helper()
	code, msg := laneDWaitFinal(t, c.r)
	if code != 200 {
		t.Fatalf("offerless INVITE drew %d, want 200 carrying our offer", code)
	}
	c.ok = msg
}

// toTag is the To tag of our 200.
func (c *offerlessCall) toTag() string {
	_, tag, _ := strings.Cut(stubHeaders(c.ok, "To")[0], "tag=")
	return tag
}

// ack sends an ACK of the 200 (CSeq 1) with the given tags, branch and body.
func (c *offerlessCall) ack(fromTag, toTag, branch, body string) {
	msg := c.r.request("ACK", c.ruri, c.cid, branch, 1, toTag, "", body)
	c.r.send(strings.Replace(msg, "tag=rfcsweepa", "tag="+fromTag, 1))
}

// goodAck sends the caller's correctly tagged ACK, fresh branch, answering
// PCMA at port.
func (c *offerlessCall) goodAck(port int) {
	c.ack("rfcsweepa", c.toTag(), c.branch+"ack", ackAnswer(port))
}

func (c *offerlessCall) ended() bool {
	for _, ev := range c.events() {
		if ev.Kind == session.UAEventDialogEnded {
			return true
		}
	}
	return false
}

// ackAnswer is an SDP answer choosing PCMA (8) and telephone-event at port.
func ackAnswer(port int) string {
	return "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
		"m=audio " + strconv.Itoa(port) + " RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n"
}

// rtpWithin reads one datagram from sock within d and returns its RTP payload
// type, or -1 when none arrives.
func rtpWithin(sock *net.UDPConn, d time.Duration) int {
	buf := make([]byte, 1500)
	_ = sock.SetReadDeadline(time.Now().Add(d))
	n, _, err := sock.ReadFromUDP(buf)
	if err != nil || n < 12 {
		return -1
	}
	return int(buf[1] & 0x7f)
}

// TestOfferlessInviteAckWithoutAnswerEndsWithBye is invariant I4: an ACK with
// no body leaves the offer unanswered, so the call ends with one BYE and
// dialog_ended media_negotiation_failed (sdp_absent).
func TestOfferlessInviteAckWithoutAnswerEndsWithBye(t *testing.T) {
	c := startOfferless(t, "noans")
	c.answer(t)
	c.ack("rfcsweepa", c.toTag(), c.branch+"ack", "")
	ev := waitFor(t, c.events, session.UAEventDialogEnded, 0)
	if ev.Cause != session.UACauseMediaNegotiationFailed {
		t.Fatalf("dialog_ended cause %q, want %q", ev.Cause, session.UACauseMediaNegotiationFailed)
	}
	if k := ev.Detail["kind"]; k != "sdp_absent" {
		t.Fatalf("detail.kind %v, want sdp_absent", k)
	}
	if !stubWait(func() bool { return c.byeCount() == 1 }, 3*time.Second) {
		t.Fatalf("caller received %d BYEs, want 1", c.byeCount())
	}
	if bye := c.requests("BYE")[0]; !strings.Contains(strings.Join(stubHeaders(bye, "Reason"), ","), "cause=488") {
		t.Fatalf("BYE Reason %v, want SIP;cause=488", stubHeaders(bye, "Reason"))
	}
}

// TestOfferlessInviteHangupBeforeAckSendsOneByeNoMedia is invariant I6: a
// hangup before the ACK sends our one BYE; the ACK arriving afterwards finds no
// dialog and starts no media.
func TestOfferlessInviteHangupBeforeAckSendsOneByeNoMedia(t *testing.T) {
	c := startOfferless(t, "hup")
	sock, port := laneDMediaSocket(t)
	c.answer(t)
	if err := c.ua.Hangup(context.Background(), c.dlg, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	if !stubWait(func() bool { return c.byeCount() == 1 }, 3*time.Second) {
		t.Fatalf("caller received %d BYEs, want 1", c.byeCount())
	}
	c.goodAck(port)
	if pt := rtpWithin(sock, 300*time.Millisecond); pt != -1 {
		t.Fatalf("RTP (PT %d) after an ACK on a hung-up call", pt)
	}
	if n := c.byeCount(); n != 1 {
		t.Fatalf("caller received %d BYEs, want 1", n)
	}
}

// TestOfferlessAckDuringAnsweringWindowStartsMedia is invariants I2 and I5:
// the ACK lands while Answer still holds phaseAnswering (through the
// post-Respond hook), so Answer's tail applies it; a second, bodyless ACK in
// the same window is a duplicate and changes nothing.
func TestOfferlessAckDuringAnsweringWindowStartsMedia(t *testing.T) {
	c := startOfferless(t, "win")
	sock, port := laneDMediaSocket(t)
	sipua.SetAnswerRespondedHook(func() {
		c.wait200(t)
		c.goodAck(port)
		if !stubWait(func() bool { return sipua.DialogAckedForTest(c.ua, c.dlg) }, 3*time.Second) {
			t.Error("the ACK was not accepted during the answering window")
		}
		c.ack("rfcsweepa", c.toTag(), c.branch+"ack2", "")
		time.Sleep(100 * time.Millisecond)
	})
	t.Cleanup(func() { sipua.SetAnswerRespondedHook(nil) })
	if err := c.ua.Answer(context.Background(), session.AnswerRequest{DialogID: c.dlg}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	sipua.SetAnswerRespondedHook(nil)
	if pt := rtpWithin(sock, 2*time.Second); pt != 8 {
		t.Fatalf("RTP payload type %d at the ACK's port, want 8 (PCMA)", pt)
	}
	if c.ended() {
		t.Fatal("dialog_ended after a valid answer")
	}
}

// TestOfferlessAckWithAForeignTagIsIgnored is invariant I5a: an ACK whose From
// tag is not the caller's, or whose To tag is not our 200's, is not taken as the
// answer, either after Answer or in its answering window.
func TestOfferlessAckWithAForeignTagIsIgnored(t *testing.T) {
	t.Run("AfterAnswer", func(t *testing.T) {
		c := startOfferless(t, "ftag")
		sockA, portA := laneDMediaSocket(t)
		sockB, portB := laneDMediaSocket(t)
		c.answer(t)
		c.ack("foreign", c.toTag(), c.branch+"f1", ackAnswer(portB))
		c.ack("rfcsweepa", "foreign", c.branch+"f2", ackAnswer(portB))
		if pt := rtpWithin(sockB, 300*time.Millisecond); pt != -1 {
			t.Fatalf("RTP (PT %d) at a foreign ACK's port", pt)
		}
		if pt := rtpWithin(sockA, 10*time.Millisecond); pt != -1 {
			t.Fatalf("RTP (PT %d) before the genuine ACK", pt)
		}
		if c.ended() {
			t.Fatal("dialog_ended after a foreign ACK")
		}
		c.goodAck(portA)
		if pt := rtpWithin(sockA, 2*time.Second); pt != 8 {
			t.Fatalf("RTP payload type %d at the genuine ACK's port, want 8", pt)
		}
		if pt := rtpWithin(sockB, 300*time.Millisecond); pt != -1 {
			t.Fatalf("RTP (PT %d) at a foreign ACK's port", pt)
		}
	})
	t.Run("InTheAnsweringWindow", func(t *testing.T) {
		c := startOfferless(t, "fwin")
		sockA, portA := laneDMediaSocket(t)
		sockB, portB := laneDMediaSocket(t)
		sipua.SetAnswerRespondedHook(func() {
			c.wait200(t)
			c.ack("rfcsweepa", "foreign", c.branch+"f2", ackAnswer(portB))
			if pt := rtpWithin(sockB, 300*time.Millisecond); pt != -1 {
				t.Errorf("RTP (PT %d) at a foreign ACK's port", pt)
			}
		})
		t.Cleanup(func() { sipua.SetAnswerRespondedHook(nil) })
		if err := c.ua.Answer(context.Background(), session.AnswerRequest{DialogID: c.dlg}); err != nil {
			t.Fatalf("Answer: %v", err)
		}
		sipua.SetAnswerRespondedHook(nil)
		if pt := rtpWithin(sockB, 300*time.Millisecond); pt != -1 {
			t.Fatalf("RTP (PT %d) at a foreign ACK's port", pt)
		}
		if c.ended() {
			t.Fatal("dialog_ended after a foreign ACK")
		}
		c.goodAck(portA)
		if pt := rtpWithin(sockA, 2*time.Second); pt != 8 {
			t.Fatalf("RTP payload type %d at the genuine ACK's port, want 8", pt)
		}
	})
}

// TestOfferlessAckReusingTheInviteBranchStartsMedia is invariant I5b: an ACK
// that reuses the INVITE's branch matches the held INVITE transaction and is
// forwarded from its Acks channel.
func TestOfferlessAckReusingTheInviteBranchStartsMedia(t *testing.T) {
	c := startOfferless(t, "br")
	sock, port := laneDMediaSocket(t)
	c.answer(t)
	c.ack("rfcsweepa", c.toTag(), c.branch, ackAnswer(port))
	if pt := rtpWithin(sock, 2*time.Second); pt != 8 {
		t.Fatalf("RTP payload type %d at the ACK's port, want 8 (PCMA)", pt)
	}
}

// TestOfferlessAnswerNeverStartsMediaBeforeTheAck is invariant I1: the offer
// session has no remote address, and no media loop is published until the ACK
// answers it (a loop started early would send to :0, which no socket sees, so
// the check is on the dialog itself).
func TestOfferlessAnswerNeverStartsMediaBeforeTheAck(t *testing.T) {
	c := startOfferless(t, "early")
	sock, port := laneDMediaSocket(t)
	c.answer(t)
	time.Sleep(300 * time.Millisecond)
	if sipua.MediaLoopPublishedForTest(c.ua, c.dlg) {
		t.Fatal("a media loop was published before the ACK carried the answer")
	}
	c.goodAck(port)
	if pt := rtpWithin(sock, 2*time.Second); pt != 8 {
		t.Fatalf("control: RTP payload type %d after the ACK, want 8", pt)
	}
}

// TestOfferlessCallRefusesATransferUntilTheAckAnswers: on an offerless call the
// answer arrives in the ACK, and onAck ignores an ACK while a control operation
// holds the dialog, so a transfer claimed before the ACK would lose the answer
// (no media). The claim is refused precondition_failed while the answer is
// awaited, the later ACK still starts media, and the transfer is then allowed.
func TestOfferlessCallRefusesATransferUntilTheAckAnswers(t *testing.T) {
	c := startOfferless(t, "xfer")
	sock, port := laneDMediaSocket(t)
	c.answer(t)
	req := session.TransferRequest{DialogID: c.dlg, Mode: session.TransferBlind, Target: "sip:carol@127.0.0.1:5999"}
	_, err := c.ua.Transfer(context.Background(), req)
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed || !strings.Contains(err.Error(), "call_transfer:") {
		t.Fatalf("Transfer before the ACK: err %v, want call_transfer precondition_failed", err)
	}
	if n := len(c.requests("REFER")); n != 0 {
		t.Fatalf("caller received %d REFERs before the ACK, want 0", n)
	}
	c.goodAck(port)
	if pt := rtpWithin(sock, 2*time.Second); pt != 8 {
		t.Fatalf("RTP payload type %d after the ACK, want 8 (the answer was lost)", pt)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.ua.Transfer(ctx, req); done <- err }()
	if !stubWait(func() bool { return len(c.requests("REFER")) > 0 }, 3*time.Second) {
		t.Fatal("no REFER after the ACK: the transfer was not allowed")
	}
	cancel()
	<-done //nolint:errcheck // wait for the cancelled Transfer goroutine; only the REFER matters
}

// TestOfferlessCallRefusesATransferUntilMediaIsPublished: once the ACK's
// answer is installed but before startMediaLoop publishes the loop, a transfer
// claim would make the publication check drop the loop, and its release never
// retries (Codex Cycle 4 round 2, B2). Paused in that window, the transfer is
// refused precondition_failed (no REFER); media then flows, and a transfer
// afterwards is allowed.
func TestOfferlessCallRefusesATransferUntilMediaIsPublished(t *testing.T) {
	c := startOfferless(t, "pub")
	sock, port := laneDMediaSocket(t)
	c.answer(t)
	req := session.TransferRequest{DialogID: c.dlg, Mode: session.TransferBlind, Target: "sip:carol@127.0.0.1:5999"}
	xctx, xcancel := context.WithCancel(context.Background())
	defer xcancel()
	inWindow := make(chan error, 1)
	sipua.SetAckAnswerAppliedHook(func() {
		sipua.SetAckAnswerAppliedHook(nil)
		done := make(chan error, 1)
		go func() { _, err := c.ua.Transfer(xctx, req); done <- err }()
		select {
		case err := <-done:
			inWindow <- err
		case <-time.After(500 * time.Millisecond):
			inWindow <- nil // claimed: the transfer is in flight (REFER unanswered)
		}
	})
	t.Cleanup(func() { sipua.SetAckAnswerAppliedHook(nil) })
	c.goodAck(port)
	var err error
	select {
	case err = <-inWindow:
	case <-time.After(3 * time.Second):
		t.Fatal("the ACK's answer was never applied")
	}
	xcancel()
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed || !strings.Contains(err.Error(), "call_transfer:") {
		t.Fatalf("Transfer before media publication: err %v, want call_transfer precondition_failed", err)
	}
	if n := len(c.requests("REFER")); n != 0 {
		t.Fatalf("caller received %d REFERs before media was published, want 0", n)
	}
	if pt := rtpWithin(sock, 2*time.Second); pt != 8 {
		t.Fatalf("RTP payload type %d after the ACK, want 8 (media never started)", pt)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.ua.Transfer(ctx, req); done <- err }()
	if !stubWait(func() bool { return len(c.requests("REFER")) > 0 }, 3*time.Second) {
		t.Fatal("no REFER after media started: the transfer was not allowed")
	}
	cancel()
	<-done //nolint:errcheck // wait for the cancelled Transfer goroutine; only the REFER matters
}
