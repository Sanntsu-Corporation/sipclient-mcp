package sip

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// CF-079 (RFC 3261 18.2.2): the response to a request that arrived over a
// stream goes back on the connection it arrived on.

// arrivalPeer is a far end whose reads are collected from the start (a
// net.Pipe write blocks until read).
type arrivalPeer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func newArrivalConn(t *testing.T) (*TCPConnection, *arrivalPeer) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	p := &arrivalPeer{}
	go func() {
		tmp := make([]byte, 4096)
		for {
			n, err := b.Read(tmp)
			if n > 0 {
				p.mu.Lock()
				p.buf.Write(tmp[:n])
				p.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return &TCPConnection{Conn: a, refcount: 1 + IdleConnection}, p
}

func (p *arrivalPeer) got(wait time.Duration) string {
	time.Sleep(wait)
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.String()
}

func (p *arrivalPeer) waitFor(t *testing.T, sub string) {
	t.Helper()
	require.Eventually(t, func() bool { return strings.Contains(p.got(0), sub) }, 2*time.Second, 5*time.Millisecond, "want %q, got %q", sub, p.got(0))
}

func arrivalRequest(t *testing.T, method, branch string) *Request {
	t.Helper()
	raw := method + " sip:alice@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 127.0.0.1:5000;branch=" + branch + "\r\n" +
		"From: <sip:bob@example.test>;tag=ft\r\n" +
		"To: <sip:alice@example.test>\r\n" +
		"Call-ID: arrival-1@example.test\r\n" +
		"CSeq: 1 " + method + "\r\n" +
		"Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
	msg, err := ParseMessage([]byte(raw))
	require.NoError(t, err)
	req := msg.(*Request)
	req.SetTransport("TCP")
	req.SetSource("127.0.0.1:5000")
	return req
}

func arrivalLayer(t *testing.T) (*TransactionLayer, *TransportLayer) {
	t.Helper()
	tpl := NewTransportLayer(net.DefaultResolver, NewParser(), nil, false, nil)
	t.Cleanup(func() { _ = tpl.Close() })
	txl := NewTransactionLayer(tpl)
	t.Cleanup(txl.Close)
	return txl, tpl
}

func TestServerTxRespondsOnTheArrivalConnection(t *testing.T) {
	txl, tpl := arrivalLayer(t)
	a, aPeer := newArrivalConn(t)
	b, bPeer := newArrivalConn(t)
	tpl.tcp.pool.Add("127.0.0.1:5000", b)
	txl.OnRequest(func(req *Request, tx ServerTransaction) {
		require.NoError(t, tx.Respond(NewResponseFromRequest(req, StatusOK, "OK", nil)))
	})

	req := arrivalRequest(t, "INFO", "z9hG4bKarr1")
	req.rxConn = a
	txl.handleRequest(req)

	aPeer.waitFor(t, "SIP/2.0 200 OK")
	require.Empty(t, bPeer.got(300*time.Millisecond), "nothing may leave on the pooled connection")
}

func TestServerTxWithoutArrivalConnectionUsesThePool(t *testing.T) {
	txl, tpl := arrivalLayer(t)
	_, aPeer := newArrivalConn(t)
	b, bPeer := newArrivalConn(t)
	tpl.tcp.pool.Add("127.0.0.1:5000", b)
	txl.OnRequest(func(req *Request, tx ServerTransaction) {
		require.NoError(t, tx.Respond(NewResponseFromRequest(req, StatusOK, "OK", nil)))
	})

	txl.handleRequest(arrivalRequest(t, "INFO", "z9hG4bKarr2"))

	bPeer.waitFor(t, "SIP/2.0 200 OK")
	require.Empty(t, aPeer.got(100*time.Millisecond))
}

func TestArrivalConnectionTakesOneReference(t *testing.T) {
	txl, tpl := arrivalLayer(t)
	a, _ := newArrivalConn(t)
	b, _ := newArrivalConn(t)
	tpl.tcp.pool.Add("127.0.0.1:5000", b)
	txl.OnRequest(func(req *Request, tx ServerTransaction) {})

	before := a.Ref(0)
	req := arrivalRequest(t, "INFO", "z9hG4bKarr3")
	req.rxConn = a
	txl.handleRequest(req)
	require.Equal(t, before+1, a.Ref(0))
}

func TestCancelOKGoesOnTheCancelsArrivalConnection(t *testing.T) {
	txl, tpl := arrivalLayer(t)
	a, aPeer := newArrivalConn(t)
	c, cPeer := newArrivalConn(t)
	tpl.tcp.pool.Add("127.0.0.1:5000", a)
	txl.OnRequest(func(req *Request, tx ServerTransaction) {}) // the INVITE stays open

	inv := arrivalRequest(t, "INVITE", "z9hG4bKarr4")
	inv.rxConn = a
	txl.handleRequest(inv)

	cancel := arrivalRequest(t, "CANCEL", "z9hG4bKarr4")
	cancel.rxConn = c
	txl.handleRequest(cancel)

	cPeer.waitFor(t, "SIP/2.0 200 OK")
	require.NotContains(t, cPeer.got(0), "487")
	aPeer.waitFor(t, "SIP/2.0 487")
	require.NotContains(t, aPeer.got(0), "200 OK")
}

func TestParseStreamTagsRequestsWithTheirConnection(t *testing.T) {
	tr := newTCPTransport(NewParser())
	x, _ := newArrivalConn(t)
	data := "OPTIONS sip:a@example.test SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1:5000;branch=z9hG4bKps\r\n" +
		"From: <sip:b@example.test>;tag=t\r\nTo: <sip:a@example.test>\r\nCall-ID: ps@example.test\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n" +
		"SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP 127.0.0.1:5000;branch=z9hG4bKps2\r\n" +
		"From: <sip:b@example.test>;tag=t\r\nTo: <sip:a@example.test>;tag=u\r\nCall-ID: ps2@example.test\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
	var req *Request
	var res *Response
	tr.parseStream(tr.parser.NewSIPStream(), []byte(data), "127.0.0.1:5000", func(m Message) {
		switch m := m.(type) {
		case *Request:
			req = m
		case *Response:
			res = m
		}
	}, x)
	require.NotNil(t, req)
	require.NotNil(t, res)
	require.Same(t, Connection(x), req.rxConn)
	require.Nil(t, res.rxConn)
}
