package sipua

// CF-058: an accepted TCP/TLS connection must not carry the UA's outbound
// requests. The vendored sipgo pooled every accepted connection under the
// listener's address too, which is this UA's Via sent-by, so
// ClientRequestConnection's Via lookup handed the most recently accepted
// inbound connection to every outbound request, whatever its destination
// (third_party/sipgo/VENDOR.md, the CF-058 section). Responses keep riding the
// accepted connection (RFC 3261 §18.2.2).

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/siptest"
	tlspeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/tlsca"
)

func newAcceptedConnTestUA(t *testing.T, transport, aor string) *UA {
	t.Helper()
	ua, err := New(context.Background(), Config{
		Transport:             transport,
		Mode:                  "direct",
		AOR:                   aor,
		LocalAddr:             "127.0.0.1:0",
		Timeout:               2 * time.Second,
		Clock:                 clock.System(),
		Logger:                testLogger(),
		TLSInsecureSkipVerify: transport == "tls",
	})
	if err != nil {
		t.Fatalf("New(%s): %v", transport, err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua
}

// dialRawAndAwaitAccept opens a raw connection to ua's listener and returns
// once the UA has accepted and pooled it: sipgo answers a double-CRLF ping
// with a CRLF pong only from the accepted connection's reader, which starts
// after initConnection pooled it.
func dialRawAndAwaitAccept(t *testing.T, ua *UA, transport string) net.Conn {
	t.Helper()
	addr := ua.LocalAddr().String()
	var conn net.Conn
	var err error
	if transport == "tls" {
		conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		t.Fatalf("raw %s dial %s: %v", transport, addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte("\r\n\r\n")); err != nil {
		t.Fatalf("raw ping: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	pong := make([]byte, 2)
	if _, err := conn.Read(pong); err != nil || string(pong) != "\r\n" {
		t.Fatalf("raw connection got no CRLF pong (accept not observed): %q, %v", pong, err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn
}

// assertRawReadsNothing fails if conn receives any byte within d.
func assertRawReadsNothing(t *testing.T, conn net.Conn, d time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n > 0 {
		line, _, _ := bytes.Cut(buf[:n], []byte("\r\n"))
		t.Fatalf("the accepted inbound connection carried an outbound message: %q", line)
	}
}

// rawSIPMessages parses the SIP messages arriving on conn onto a channel,
// closed when conn's read fails.
func rawSIPMessages(conn net.Conn) <-chan sip.Message {
	out := make(chan sip.Message, 16)
	go func() {
		defer close(out)
		par := sip.NewParser().NewSIPStream()
		buf := make([]byte, 65535)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			msgs, perr := par.ParseSIPStream(buf[:n])
			if perr != nil && !errors.Is(perr, sip.ErrParseSipPartial) {
				return
			}
			for _, m := range msgs {
				out <- m
			}
		}
	}()
	return out
}

// awaitRequest returns the first request with method m on msgs, within 3 s.
func awaitRequest(t *testing.T, msgs <-chan sip.Message, m sip.RequestMethod, where string) *sip.Request {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case msg, ok := <-msgs:
			if !ok {
				t.Fatalf("%s closed before a %s arrived", where, m)
			}
			if req, isReq := msg.(*sip.Request); isReq && req.Method == m {
				return req
			}
		case <-deadline:
			t.Fatalf("no %s arrived on %s within 3s", m, where)
		}
	}
}

// awaitFinal returns the first 200 for method m on msgs, within 3 s.
func awaitFinal(t *testing.T, msgs <-chan sip.Message, m sip.RequestMethod) *sip.Response {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case msg, ok := <-msgs:
			if !ok {
				t.Fatalf("raw connection closed before the 200 for %s", m)
			}
			if res, isRes := msg.(*sip.Response); isRes && res.StatusCode == 200 && res.CSeq().MethodName == m {
				return res
			}
		case <-deadline:
			t.Fatalf("no 200 for %s on the raw connection within 3s", m)
		}
	}
}

func TestOutboundInviteIgnoresAnAcceptedInboundConnection(t *testing.T) {
	for _, transport := range []string{"tcp", "tls"} {
		t.Run(transport, func(t *testing.T) {
			ctx := context.Background()
			a := newAcceptedConnTestUA(t, transport, "sip:a@example")
			p := newAcceptedConnTestUA(t, transport, "sip:p@example")
			admitted := make(chan session.UAEvent, 1)
			p.OnAdmit(ctx, func(_ context.Context, ev session.UAEvent) session.Admission {
				admitted <- ev
				return session.AdmitAccept()
			})

			raw := dialRawAndAwaitAccept(t, a, transport)

			if _, err := a.Dial(ctx, session.DialRequest{ToURI: "sip:p@" + p.LocalAddr().String()}); err != nil {
				t.Fatalf("Dial: %v", err)
			}
			assertRawReadsNothing(t, raw, time.Second)
			select {
			case <-admitted:
			case <-time.After(3 * time.Second):
				t.Fatal("the INVITE's destination never received it within 3s")
			}
		})
	}
}

func TestRegisterAndItsDigestRetryIgnoreAnAcceptedInboundConnection(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("tlsca.NewCA: %v", err)
	}
	leaf, err := ca.IssueLeaf(tlsca.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	p := tlspeer.Start(t, tlspeer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", TLSCert: &leaf})

	a, err := New(context.Background(), Config{
		Transport:             "tls",
		Mode:                  "register",
		AOR:                   "sip:alice@example",
		Registrar:             "sip:" + p.TLSAddr(),
		AuthUser:              "alice",
		AuthPass:              "s3cr3t",
		Timeout:               2 * time.Second,
		Clock:                 clock.System(),
		Logger:                testLogger(),
		LocalAddr:             "127.0.0.1:0",
		TLSInsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close(context.Background()) })

	raw := dialRawAndAwaitAccept(t, a, "tls")

	res, err := a.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !res.Registered {
		t.Fatalf("Register result = %+v, want registered", res)
	}
	if n := p.Count("REGISTER"); n < 2 {
		t.Fatalf("registrar counted %d REGISTERs, want >= 2 (the challenged one and the digest retry)", n)
	}
	assertRawReadsNothing(t, raw, time.Second)
}

// TestRegisterVerifiesThePeerCertificateOnItsPerRequestTLSDial: the per-request
// outbound TLS dial verifies the registrar's certificate against TLSRootCAs
// (no TLSInsecureSkipVerify). A registrar signed by the trusted CA registers;
// one signed by another CA does not.
func TestRegisterVerifiesThePeerCertificateOnItsPerRequestTLSDial(t *testing.T) {
	trusted, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("tlsca.NewCA: %v", err)
	}
	other, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("tlsca.NewCA (other): %v", err)
	}
	for _, tc := range []struct {
		name     string
		signedBy *tlsca.CA
		want     bool
	}{
		{"trusted CA registers", trusted, true},
		{"unrelated CA is rejected", other, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf, err := tc.signedBy.IssueLeaf(tlsca.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
			if err != nil {
				t.Fatalf("IssueLeaf: %v", err)
			}
			p := tlspeer.Start(t, tlspeer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", TLSCert: &leaf})
			pool := x509.NewCertPool()
			pool.AddCert(trusted.Certificate())
			a, err := New(context.Background(), Config{
				Transport:  "tls",
				Mode:       "register",
				AOR:        "sip:alice@example",
				Registrar:  "sip:" + p.TLSAddr(),
				AuthUser:   "alice",
				AuthPass:   "s3cr3t",
				Timeout:    2 * time.Second,
				Clock:      clock.System(),
				Logger:     testLogger(),
				LocalAddr:  "127.0.0.1:0",
				TLSRootCAs: pool,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() { _ = a.Close(context.Background()) })
			res, err := a.Register(context.Background())
			if tc.want {
				if err != nil || !res.Registered {
					t.Fatalf("Register = %+v, %v; want registered", res, err)
				}
				return
			}
			if err == nil && res.Registered {
				t.Fatalf("Register succeeded against a registrar signed by an untrusted CA: %+v", res)
			}
		})
	}
}

// rawInboundCall makes raw the caller of an inbound TCP call to a: it writes
// an INVITE whose Via and Contact name contactAddr, waits for a to admit and
// answer it, reads the 200 on raw and ACKs it.
func rawInboundCall(t *testing.T, a *UA, raw net.Conn, contactAddr string) (inv *sip.Request, ok *sip.Response, dialogID string, msgs <-chan sip.Message) {
	t.Helper()
	ctx := context.Background()
	media, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("media socket: %v", err)
	}
	t.Cleanup(func() { _ = media.Close() })
	offer := []byte("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=raw\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
		"m=audio " + strconv.Itoa(media.LocalAddr().(*net.UDPAddr).Port) + " RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n")

	admitted := make(chan session.UAEvent, 1)
	a.OnAdmit(ctx, func(_ context.Context, ev session.UAEvent) session.Admission {
		admitted <- ev
		return session.AdmitAccept()
	})

	inv = siptest.BuildInvite(config.Config{
		LocalAddr:  contactAddr,
		TargetURI:  "sip:" + a.LocalAddr().String(),
		FromUser:   "caller",
		FromDomain: "127.0.0.1",
		ToUser:     "a",
		ToDomain:   "127.0.0.1",
	}, "TCP", offer)
	msgs = rawSIPMessages(raw)
	if _, err := raw.Write([]byte(inv.String())); err != nil {
		t.Fatalf("write INVITE: %v", err)
	}

	var ev session.UAEvent
	select {
	case ev = <-admitted:
	case <-time.After(3 * time.Second):
		t.Fatal("a never admitted the raw INVITE")
	}
	if err := a.AnswerEventually(ctx, session.AnswerRequest{DialogID: ev.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	ok = awaitFinal(t, msgs, sip.INVITE)

	ack := sip.NewAckRequest(inv, ok, nil)
	via := inv.Via().Clone()
	via.Params.Add("branch", sip.GenerateBranchN(10))
	ack.PrependHeader(via)
	if _, err := raw.Write([]byte(ack.String())); err != nil {
		t.Fatalf("write ACK: %v", err)
	}
	return inv, ok, ev.DialogID, msgs
}

func TestInboundCallResponsesStillUseTheAcceptedConnection(t *testing.T) {
	a := newAcceptedConnTestUA(t, "tcp", "sip:a@example")
	raw := dialRawAndAwaitAccept(t, a, "tcp")

	inv, ok, _, msgs := rawInboundCall(t, a, raw, raw.LocalAddr().String())

	bye := siptest.BuildByeFromInvite(inv, ok)
	if _, err := raw.Write([]byte(bye.String())); err != nil {
		t.Fatalf("write BYE: %v", err)
	}
	awaitFinal(t, msgs, sip.BYE)
}

func TestCalleeByeOnAnInboundTCPCallGoesToTheCallersContact(t *testing.T) {
	a := newAcceptedConnTestUA(t, "tcp", "sip:a@example")
	contactLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("contact listener: %v", err)
	}
	t.Cleanup(func() { _ = contactLn.Close() })
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := contactLn.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	raw := dialRawAndAwaitAccept(t, a, "tcp")
	_, _, dialogID, rawMsgs := rawInboundCall(t, a, raw, contactLn.Addr().String())

	hungUp := make(chan error, 1)
	go func() { hungUp <- a.Hangup(context.Background(), dialogID, "") }()

	var contactConn net.Conn
	deadline := time.After(3 * time.Second)
	for contactConn == nil {
		select {
		case contactConn = <-accepted:
			t.Cleanup(func() { _ = contactConn.Close() })
		case msg := <-rawMsgs:
			if req, isReq := msg.(*sip.Request); isReq && req.Method == sip.BYE {
				t.Fatal("the callee's BYE rode the accepted INVITE connection instead of going to the caller's Contact")
			}
		case <-deadline:
			t.Fatal("the callee's BYE never opened a connection to the caller's Contact listener within 3s")
		}
	}
	bye := awaitRequest(t, rawSIPMessages(contactConn), sip.BYE, "the Contact listener's connection")
	if _, err := contactConn.Write([]byte(sip.NewResponseFromRequest(bye, 200, "OK", nil).String())); err != nil {
		t.Fatalf("write 200 for BYE: %v", err)
	}
	if err := <-hungUp; err != nil {
		t.Fatalf("Hangup: %v", err)
	}

	settle := time.After(time.Second)
	for {
		select {
		case msg, open := <-rawMsgs:
			if !open {
				return
			}
			if req, isReq := msg.(*sip.Request); isReq && req.Method == sip.BYE {
				t.Fatal("the callee's BYE also rode the accepted INVITE connection")
			}
		case <-settle:
			return
		}
	}
}

// TestStreamUAClosesEveryOutboundConnectionOnClose measures the
// connection-per-transaction behaviour (Task 1 step 2b): each out-of-dialog
// transaction opens its own outbound connection, kept idle afterwards, and
// UA.Close closes them all.
func TestStreamUAClosesEveryOutboundConnectionOnClose(t *testing.T) {
	a, err := New(context.Background(), Config{
		Transport: "tcp",
		Mode:      "direct",
		AOR:       "sip:a@example",
		LocalAddr: "127.0.0.1:0",
		Timeout:   2 * time.Second,
		Clock:     clock.System(),
		Logger:    testLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close(context.Background()) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()

	const n = 5
	for i := 0; i < n; i++ {
		uri := sip.Uri{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, UriParams: sip.NewParams()}
		uri.UriParams.Add("transport", "tcp")
		req := sip.NewRequest(sip.OPTIONS, uri)
		from := &sip.FromHeader{Address: sip.Uri{User: "a", Host: "example"}, Params: sip.NewParams()}
		from.Params.Add("tag", sip.GenerateTagN(10))
		req.AppendHeader(from)
		req.AppendHeader(&sip.ToHeader{Address: uri})
		mf := sip.MaxForwardsHeader(70)
		req.AppendHeader(&mf)
		_, _ = a.Client().RawTransaction(context.Background(), req, 300*time.Millisecond)
	}

	mu.Lock()
	got := append([]net.Conn(nil), conns...)
	mu.Unlock()
	t.Logf("%d sequential OPTIONS opened %d connections", n, len(got))
	if len(got) < 1 || len(got) > n {
		t.Fatalf("%d OPTIONS opened %d connections, want 1..%d", n, len(got), n)
	}

	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	open := 0
	for _, c := range got {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		for {
			_, rerr := c.Read(buf)
			if rerr == nil {
				continue // the unanswered OPTIONS bytes
			}
			var ne net.Error
			if errors.As(rerr, &ne) && ne.Timeout() {
				open++
			}
			break
		}
		_ = c.Close()
	}
	if open > 0 {
		t.Fatalf("%d of %d outbound connections still open 2s after UA.Close", open, len(got))
	}
}

// TestInboundTCPUAInDialogRequestStaysOnTCP (CF-171): a TCP UA's BYE to a caller
// Contact with no transport parameter goes over TCP, and nothing reaches a UDP
// socket bound on the Contact's host:port.
func TestInboundTCPUAInDialogRequestStaysOnTCP(t *testing.T) {
	a := newAcceptedConnTestUA(t, "tcp", "sip:a@example")
	var contactLn net.Listener
	var udp net.PacketConn
	for i := 0; i < 20 && udp == nil; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("contact listener: %v", err)
		}
		pc, err := net.ListenPacket("udp", ln.Addr().String())
		if err != nil {
			_ = ln.Close()
			continue
		}
		contactLn, udp = ln, pc
	}
	if udp == nil {
		t.Skip("no port free for both TCP and UDP")
	}
	t.Cleanup(func() { _ = contactLn.Close(); _ = udp.Close() })
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := contactLn.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	raw := dialRawAndAwaitAccept(t, a, "tcp")
	_, _, dialogID, _ := rawInboundCall(t, a, raw, contactLn.Addr().String())
	hungUp := make(chan error, 1)
	go func() { hungUp <- a.Hangup(context.Background(), dialogID, "") }()

	var c net.Conn
	select {
	case c = <-accepted:
		t.Cleanup(func() { _ = c.Close() })
	case <-time.After(3 * time.Second):
		t.Fatal("no TCP connection to the Contact")
	}
	bye := awaitRequest(t, rawSIPMessages(c), sip.BYE, "the Contact listener")
	if _, err := c.Write([]byte(sip.NewResponseFromRequest(bye, 200, "OK", nil).String())); err != nil {
		t.Fatalf("write 200: %v", err)
	}
	if err := <-hungUp; err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	_ = udp.SetReadDeadline(time.Now().Add(time.Second))
	if n, from, err := udp.ReadFrom(make([]byte, 2048)); err == nil {
		t.Fatalf("a UDP datagram (%d bytes from %v) reached the Contact's UDP port", n, from)
	}
}
