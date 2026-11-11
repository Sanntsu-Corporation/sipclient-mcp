package sipua_test

// Lane A (rfc-sweep-a) pins for the A-HDR area: each test pins CURRENT behaviour
// that deviates from RFC 3261, so it passes today and must be inverted when its
// NEW-A finding is fixed. No test here
// calls t.Parallel (parallel_invariant_test.go).

import (
	"bufio"
	"context"
	"io"
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

// TestRFC3261_NEWA1_ProvisionalAndFinalToTagsMatch is NEW-A-1 (A-HDR-49, RFC
// 3261 8.2.6.2: "The same tag MUST be used for all responses to that request,
// both final and provisional (again excepting the 100 (Trying))."
// rfc3261.txt:2774-2776), fixed by CF-072. Evidence: evidence/corpus-udp/03/excerpt.txt frame 3-4.
func TestRFC3261_NEWA1_ProvisionalAndFinalToTagsMatch(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	incoming := waitFor(t, events, session.UAEventInbound, 0)
	waitForCode(t, p, 180)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)

	prov := p.ProvisionalToTags()
	if len(prov) == 0 || p.LastFinalToTag() == "" {
		t.Fatalf("no provisional or final To tag observed: prov=%v final=%q", prov, p.LastFinalToTag())
	}
	if prov[0] != p.LastFinalToTag() {
		t.Errorf("180 To tag %q and 200 To tag %q differ (NEW-A-1, RFC 3261 8.2.6.2)", prov[0], p.LastFinalToTag())
	}
}

// startPeerWithTCPListener starts a UDP peer on an ephemeral port and a TCP
// listener on the same port number. The TCP port may already be held by another
// process, so a bind failure releases that peer (Close is idempotent, so the
// cleanup Start registered stays safe) and retries with a new one.
func startPeerWithTCPListener(t *testing.T) (*peer.Peer, net.Listener) {
	t.Helper()
	var lastErr error
	for i := 0; i < 20; i++ {
		p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
		ln, err := net.Listen("tcp", p.Addr())
		if err == nil {
			return p, ln
		}
		lastErr = err
		p.Close()
	}
	t.Fatalf("tcp listen on the peer's address after 20 attempts: %v", lastErr)
	return nil, nil
}

// TestRFC3261_NEWA6_LargeInviteIsSentOverTCPWithATCPTopVia asserts the fix of
// NEW-A-6 (CF-106; A-HDR-62, RFC 3261 18.1.1: "If a request is within 200 bytes
// of the path MTU, or if it is larger than 1300 bytes and the path MTU is
// unknown, the request MUST be sent using an RFC 2914 [43] congestion
// controlled transport protocol, such as TCP. If this causes a change in the
// transport protocol from the one indicated in the top Via, the value in the
// top Via MUST be changed." rfc3261.txt:7934-7939). The UDP peer receives
// nothing; a TCP listener on the peer's host and port receives the INVITE with
// a SIP/2.0/TCP top Via carrying the UA's sent-by.
func TestRFC3261_NEWA6_LargeInviteIsSentOverTCPWithATCPTopVia(t *testing.T) {
	p, ln := startPeerWithTCPListener(t)
	first := make(chan string, 1)
	acceptAll(t, ln, func(c net.Conn) {
		msg, err := readStreamMsg(bufio.NewReader(c))
		if err == nil {
			select {
			case first <- msg:
			default:
			}
		}
	})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	_ = collect(t, ua)

	_, err := ua.Dial(context.Background(), session.DialRequest{
		ToURI:   "sip:bob@" + p.Addr(),
		Headers: map[string]string{"X-Rfcsweep-Pad": strings.Repeat("a", 1400)},
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	select {
	case msg := <-first:
		if !strings.HasPrefix(msg, "INVITE ") {
			t.Fatalf("first TCP message is not an INVITE: %.80q", msg)
		}
		wantVia := "Via: SIP/2.0/TCP " + ua.BoundAddr().String() + ";"
		if !strings.Contains(msg, wantVia) {
			t.Errorf("INVITE lacks the TCP top Via %q:\n%.400s", wantVia, msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no INVITE reached the peer's TCP listener within 3s")
	}
	if n := p.Count("INVITE"); n != 0 {
		t.Errorf("the UDP peer received %d INVITE(s); the oversize INVITE must go over TCP only", n)
	}
}

// acceptAll serves every connection ln accepts with serve, each on its own
// goroutine, and closes ln and the accepted connections at cleanup.
func acceptAll(t *testing.T, ln net.Listener, serve func(net.Conn)) {
	t.Helper()
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go serve(c)
		}
	}()
}

// readStreamMsg reads one SIP message (head and Content-Length body) from a
// stream connection, skipping CRLF keepalives.
func readStreamMsg(r *bufio.Reader) (string, error) {
	var b strings.Builder
	n := 0
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		if l == "\r\n" && b.Len() == 0 {
			continue
		}
		b.WriteString(l)
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Content-Length") {
			n, _ = strconv.Atoi(strings.TrimSpace(v))
		}
		if l == "\r\n" {
			break
		}
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return "", err
	}
	return b.String() + string(body), nil
}

// newTCPStubUA is a direct-mode UA on TCP 127.0.0.1:0 with an event collector.
func newTCPStubUA(t *testing.T) (*sipua.UA, func() []session.UAEvent) {
	t.Helper()
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "tcp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua, collect(t, ua)
}

// rawOptions sends one OPTIONS datagram to addr from a fresh socket and returns
// the first response datagram.
func rawOptions(t *testing.T, addr string, via, extra string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = pc.Close() }()
	dst, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	msg := "OPTIONS sip:alice@" + addr + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + strings.ReplaceAll(via, "PORT", port) + ";branch=z9hG4bKrfcsweepa\r\n" +
		"From: <sip:probe@127.0.0.1>;tag=rfcsweepa\r\n" +
		"To: <sip:alice@" + addr + ">\r\n" +
		"Call-ID: rfcsweepa-pin@127.0.0.1\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Max-Forwards: 70\r\n" + extra
	if _, err := pc.WriteTo([]byte(msg), dst); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no response to the OPTIONS probe: %v", err)
	}
	return string(buf[:n])
}

// TestRFC3261_NEWA7_ViaGetsReceivedParameter covers NEW-A-7 (A-HDR-83, CF-077,
// RFC 3261 18.2.1: "If the host portion of the "sent-by" parameter contains a
// domain name, or if it contains an IP address that differs from the packet
// source address, the server MUST add a "received" parameter to that Via header
// field value." rfc3261.txt:8097-8100; RFC 3581 4 for an empty rport). Fixed by
// cf5-f; was TestRFC3261Pin_NEWA7_ViaGetsNoReceivedParameter.
func TestRFC3261_NEWA7_ViaGetsReceivedParameter(t *testing.T) {
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	for _, tc := range []struct {
		name, via string
		want      []string
	}{
		{"domain sent-by", "localhost:PORT", []string{"received=127.0.0.1"}},
		{"different IP sent-by", "127.0.0.2:PORT", []string{"received=127.0.0.1"}},
		{"empty rport", "127.0.0.1:PORT;rport", []string{"received=127.0.0.1", "rport="}},
	} {
		resp := rawOptions(t, ua.BoundAddr().String(), tc.via, "Content-Length: 0\r\n\r\n")
		for _, w := range tc.want {
			if !strings.Contains(resp, w) {
				t.Errorf("%s: response Via lacks %q:\n%s", tc.name, w, resp)
			}
		}
	}
}

// TestRFC3261_NEWA7_ResponseGoesToThePacketSource_AcceptedDeviation is the
// tripwire for the destination half of NEW-A-7 / CF-077: RFC 3261 18.2.2 says
// the response goes to `received` and the sent-by port; we send it to the
// packet source (RFC 3581 behaviour), because sending to a peer-chosen sent-by
// port is a reflection vector. CF-077 accepted deviation (cf5 Lane F): a change
// here must be deliberate.
func TestRFC3261_NEWA7_ResponseGoesToThePacketSource_AcceptedDeviation(t *testing.T) {
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	other, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = other.Close() }()
	_, otherPort, _ := net.SplitHostPort(other.LocalAddr().String())
	// rawOptions returns what reached the sending socket.
	resp := rawOptions(t, ua.BoundAddr().String(), "127.0.0.1:"+otherPort, "Content-Length: 0\r\n\r\n")
	if !strings.HasPrefix(resp, "SIP/2.0 ") {
		t.Fatalf("no response on the sending socket:\n%s", resp)
	}
	_ = other.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 4096)
	if n, _, err := other.ReadFrom(buf); err == nil {
		t.Errorf("CF-077 accepted deviation (cf5 Lane F): the response now also reached the sent-by port (%d bytes); a change here must be deliberate", n)
	}
}

// TestRFC3261Pin_NEWA8_ParserIgnoresContentLength pins NEW-A-8 (A-HDR-96, RFC
// 3261 18.3: "If the message is a request, the element SHOULD generate a 400 (Bad
// Request) response." for a message shorter than its Content-Length,
// rfc3261.txt:8195-8196). Evidence: evidence/hdr-rx/excerpt.txt frame 5-6.
//
// PIN OF A DEVIATION: invert this assertion when NEW-A-8 is fixed.
func TestRFC3261Pin_NEWA8_ParserIgnoresContentLength(t *testing.T) {
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	resp := rawOptions(t, ua.BoundAddr().String(), "127.0.0.1:PORT",
		"Content-Type: text/plain\r\nContent-Length: 100\r\n\r\nshort\n")
	if strings.HasPrefix(resp, "SIP/2.0 400") {
		t.Errorf("a request shorter than its Content-Length now draws 400: NEW-A-8 is fixed, invert this pin")
	}
}

// TestRFC3261Pin_NEWA10_NewTCPConnectionPerRequest pins NEW-A-10 (A-HDR-75, RFC
// 3261 18.1.1: "If a request is destined to an IP address, port, and transport
// to which an existing connection is open, it is RECOMMENDED that this
// connection be used to send the request, but another connection MAY be opened
// and used." rfc3261.txt:8033-8036). Evidence: evidence/corpus-tcp/index.md;
// evidence/corpus-tcp/02/excerpt.txt frame 1-9. A raw TCP stub answers the
// INVITE and the BYE on the connection each arrived on and keeps every
// connection open; the INVITE, its ACK and the BYE of one call open more than
// one connection.
//
// PIN OF A DEVIATION: invert this assertion when NEW-A-10 is fixed.
func TestRFC3261Pin_NEWA10_NewTCPConnectionPerRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	conns, byes := 0, 0
	acceptAll(t, ln, func(c net.Conn) {
		mu.Lock()
		conns++
		mu.Unlock()
		r := bufio.NewReader(c)
		for {
			m, err := readStreamMsg(r)
			if err != nil {
				return
			}
			switch stubMethod(m) {
			case "INVITE":
				_, _ = c.Write([]byte(stubResponse(m, 200, "OK", "stubtag",
					[]string{"Contact: <sip:stub@" + ln.Addr().String() + ";transport=tcp>"}, stubSDP)))
			case "BYE":
				mu.Lock()
				byes++
				mu.Unlock()
				_, _ = c.Write([]byte(stubResponse(m, 200, "OK", "", nil, "")))
			}
		}
	})
	ua, events := newTCPStubUA(t)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + ln.Addr().String()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	if !stubWait(func() bool { mu.Lock(); defer mu.Unlock(); return byes > 0 }, 3*time.Second) {
		t.Fatal("the stub never saw a BYE")
	}
	mu.Lock()
	defer mu.Unlock()
	t.Logf("INVITE, ACK and BYE of one call opened %d connection(s)", conns)
	if conns <= 1 {
		t.Errorf("one call's requests shared %d connection: NEW-A-10 is fixed, invert this pin", conns)
	}
}

// TestRFC3261_NEWA12_ICMPUnreachableNotSurfaced_AcceptedDeviation pins NEW-A-12 (A-HDR-98, RFC
// 3261 18.4: "Host, network, port or protocol unreachable errors, or parameter
// problem errors SHOULD cause the transport layer to inform the transport user
// of a failure in sending." rfc3261.txt:8211-8213). Evidence:
// evidence/hdr-icmp/excerpt.txt frame 1-14. On loopback the ICMP port
// unreachable returns at once for each INVITE datagram. Absence pin: 1.5 s
// window (below the UA's 2 s transaction timeout) in which the dial neither
// fails nor ends.
//
// ACCEPTED DEVIATION (CF-082, cf5 Lane F): a SHOULD that needs Linux-only
// IP_RECVERR plumbing, and acting on ICMP lets an off-path spoofer end a dialling
// call; Timer B bounds the wait. The assertion is unchanged.
func TestRFC3261_NEWA12_ICMPUnreachableNotSurfaced_AcceptedDeviation(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closed := pc.LocalAddr().String()
	_ = pc.Close() // nothing listens here now: every datagram draws ICMP port unreachable
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + closed}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)
	ended := false
	for _, ev := range events() {
		ended = ended || ev.Kind == session.UAEventDialogEnded || ev.Kind == session.UAEventFinal
	}
	if ended {
		t.Errorf("the dial to a closed UDP port ended within 1.5 s (%v): CF-082 accepted deviation (cf5 Lane F): a change here must be deliberate", kinds(events()))
	}
}
