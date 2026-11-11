package sipua_test

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// earlySink is a test-owned UDP media port that records whether anything
// reached it.
type earlySink struct {
	port int
	got  chan struct{}
}

func newEarlySink(t *testing.T) *earlySink {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("media socket: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	e := &earlySink{port: c.LocalAddr().(*net.UDPAddr).Port, got: make(chan struct{}, 1)}
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, rerr := c.ReadFromUDP(buf); rerr != nil {
				return
			}
			select {
			case e.got <- struct{}{}:
			default:
			}
		}
	}()
	return e
}

func (e *earlySink) expectRTP(t *testing.T, d time.Duration, what string) {
	t.Helper()
	select {
	case <-e.got:
	case <-time.After(d):
		t.Errorf("no RTP reached %s", what)
	}
}

func (e *earlySink) expectNoRTP(t *testing.T, what string) {
	t.Helper()
	select {
	case <-e.got:
		t.Errorf("RTP reached %s", what)
	default:
	}
}

func earlySDP(port int, pt string) string {
	return "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio " + strconv.Itoa(port) +
		" RTP/AVP " + pt + "\r\na=rtpmap:" + pt + " " + map[string]string{"0": "PCMU", "8": "PCMA"}[pt] + "/8000\r\n"
}

func earlyUA(t *testing.T) *sipua.UA {
	t.Helper()
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU", "PCMA"}, "disabled")
	_ = collect(t, ua)
	return ua
}

func earlyContact(s *uacStub) string { return "Contact: <sip:stub@" + s.addr() + ">" }

// Guard: a 183 followed by a 401 is a different exchange from the retry's.
func TestEarlySDPOfAChallengedLegIsNotTheAnswer(t *testing.T) {
	a, b := newEarlySink(t), newEarlySink(t)
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		if len(stubHeaders(raw, "Authorization")) == 0 {
			s.send(from, stubResponse(raw, 183, "Session Progress", "stubtag", []string{earlyContact(s)}, earlySDP(a.port, "0")))
			time.Sleep(100 * time.Millisecond)
			s.send(from, stubResponse(raw, 401, "Unauthorized", "stubtag", []string{
				`WWW-Authenticate: Digest realm="cf5e",nonce="fedcba9876543210fedcba9876543210",qop="auth",algorithm=MD5`}, ""))
			return
		}
		s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{earlyContact(s)}, earlySDP(b.port, "0")))
	})
	ua := credUA(t)
	dialStub(t, ua, s)
	b.expectRTP(t, 2*time.Second, "the retry's 200 port")
	a.expectNoRTP(t, "the challenged leg's 183 port")
}

// Guard: the early SDP of one early dialog is not another dialog's answer.
func TestEarlySDPFromAnotherDialogIsNotTheAnswer(t *testing.T) {
	a, b := newEarlySink(t), newEarlySink(t)
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		s.send(from, stubResponse(raw, 183, "Session Progress", "x", []string{earlyContact(s)}, earlySDP(a.port, "0")))
		time.Sleep(100 * time.Millisecond)
		s.send(from, stubResponse(raw, 200, "OK", "y", []string{earlyContact(s)}, earlySDP(b.port, "0")))
	})
	ua := earlyUA(t)
	dialStub(t, ua, s)
	b.expectRTP(t, 2*time.Second, "the 200's port")
	a.expectNoRTP(t, "the other dialog's 183 port")
}

// Guard: a provisional body that is not application/sdp is not an answer.
func TestNonSDPProvisionalBodyIsIgnored(t *testing.T) {
	a, b := newEarlySink(t), newEarlySink(t)
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		body := earlySDP(a.port, "0")
		prov := stubResponse(raw, 183, "Session Progress", "stubtag", []string{earlyContact(s), "Content-Type: text/plain"}, "")
		prov = strings.Replace(prov, "Content-Length: 0\r\n\r\n", "Content-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body, 1)
		s.send(from, prov)
		time.Sleep(100 * time.Millisecond)
		s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{earlyContact(s)}, earlySDP(b.port, "0")))
	})
	ua := earlyUA(t)
	dialStub(t, ua, s)
	b.expectRTP(t, 2*time.Second, "the 200's port")
	a.expectNoRTP(t, "the text/plain 183's port")
}

func TestUnparseableEarlySDPFailsTheCallAtThe200(t *testing.T) {
	b := newEarlySink(t)
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		s.send(from, stubResponse(raw, 183, "Session Progress", "stubtag", []string{earlyContact(s)}, "garbage"))
		time.Sleep(100 * time.Millisecond)
		s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{earlyContact(s)}, earlySDP(b.port, "0")))
	})
	ua := newStubUA(t)
	events := collect(t, ua)
	dialStub(t, ua, s)
	ev := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ev.Cause != session.UACauseMediaNegotiationFailed {
		t.Errorf("dialog_ended cause = %q, want media_negotiation_failed", ev.Cause)
	}
	settle(s, 1, 1)
	if n := len(s.requests("ACK")); n != 1 {
		t.Errorf("ACKs = %d, want 1", n)
	}
	if n := len(s.requests("BYE")); n != 1 {
		t.Errorf("BYEs = %d, want 1", n)
	}
	b.expectNoRTP(t, "the 200's port (the early SDP is the answer and it failed)")
}

func TestEarlyAnswerMapIsBounded(t *testing.T) {
	release := make(chan struct{})
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		sink := earlySDP(40000, "0")
		for i := 0; i < 20; i++ {
			s.send(from, stubResponse(raw, 183, "Session Progress", "tag"+strconv.Itoa(i), []string{earlyContact(s)}, sink))
		}
		go func() {
			<-release
			s.send(from, stubResponse(raw, 200, "OK", "tag0", []string{earlyContact(s)}, sink))
		}()
	})
	ua := newStubUA(t)
	events := collect(t, ua)
	hooked := make(chan struct{})
	sipua.SetDialAnsweringHook(func() { close(hooked) })
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + s.addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n := 0
		for _, ev := range events() {
			if ev.Kind == session.UAEventProvisional {
				n++
			}
		}
		if n >= 20 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := sipua.EarlyAnswerCount(ua, res.DialogID); got != 16 {
		t.Errorf("early answers held = %d, want exactly 16", got)
	}
	close(release)
	// Let the dial reach the answered phase before the test returns: runDial
	// reads the package-level dialAnsweringHook after the ACK, and the next test
	// writes it.
	select {
	case <-hooked:
	case <-time.After(3 * time.Second):
		t.Fatal("runDial never reached the answering window")
	}
	sipua.SetDialAnsweringHook(nil)
}

func TestEarlySDPAndABodilessTwoHundredIsAnswered(t *testing.T) {
	a := newEarlySink(t)
	body := earlySDP(a.port, "0")
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		s.send(from, stubResponse(raw, 183, "Session Progress", "stubtag", []string{earlyContact(s)}, body))
		time.Sleep(100 * time.Millisecond)
		s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{earlyContact(s)}, ""))
	})
	ua := earlyUA(t)
	id := dialStub(t, ua, s)
	a.expectRTP(t, 2*time.Second, "the 183's port")
	if got := string(sipua.AnswerSDPForTest(ua, id)); got != body {
		t.Errorf("answer SDP = %q, want the 183's", got)
	}
}

func TestNoInDialogRequestSeesTheUnansweredOffer(t *testing.T) {
	a := newEarlySink(t)
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{earlyContact(s)}, earlySDP(a.port, "0")))
	})
	ua := earlyUA(t)
	var id atomic.Value
	seen := make(chan string, 1)
	sipua.SetDialAnsweringHook(func() {
		if v, ok := id.Load().(string); ok {
			if mv, ok := ua.MediaView(v); ok {
				seen <- mv.RemoteMediaAddr
			}
		}
	})
	t.Cleanup(func() { sipua.SetDialAnsweringHook(nil) })
	res, err := ua.Dial(context.Background(), session.DialRequest{
		ToURI: "sip:bob@" + s.addr(), OnDialogBound: func(dialogID, _ string) { id.Store(dialogID) },
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = res
	select {
	case got := <-seen:
		if want := "127.0.0.1:" + strconv.Itoa(a.port); got != want {
			t.Errorf("RemoteMediaAddr after the ACK = %q, want the answer's %q", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the answering hook never ran")
	}
}

// Under -race this fails on code that mutates the published offer session in
// place while MediaView reads it.
func TestMediaViewDuringOutboundAnswerIsRaceFree(t *testing.T) {
	s := startUACStub(t, answer200())
	ua := newStubUA(t)
	events := collect(t, ua)
	// Widens the window after the ACK so a parse that still happens there (on
	// code that mutates the published session in place) overlaps the poller.
	sipua.SetDialAnsweringHook(func() { time.Sleep(30 * time.Millisecond) })
	t.Cleanup(func() { sipua.SetDialAnsweringHook(nil) })
	var id atomic.Value
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	started := make(chan struct{})
	go func() {
		defer wg.Done()
		close(started)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if v, ok := id.Load().(string); ok {
				_, _ = ua.MediaView(v)
			}
		}
	}()
	<-started
	_, err := ua.Dial(context.Background(), session.DialRequest{
		ToURI: "sip:bob@" + s.addr(), OnDialogBound: func(dialogID, _ string) { id.Store(dialogID) },
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	close(stop)
	wg.Wait()
}
