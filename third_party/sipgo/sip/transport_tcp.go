package sip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// TCP transport implementation
type transportTCP struct {
	addr      string
	transport string
	parser    *Parser
	log       zerolog.Logger

	pool ConnectionPool

	// dialEphemeralLocalPort is the W2c B2 divergence: when set, an outbound
	// dial binds the Via-derived IP but leaves the local port ephemeral (0)
	// instead of upstream's IP:Port, so a UA listening on that port can still
	// dial out without EADDRINUSE. Default off preserves upstream behavior
	// for consumers that do not opt in (see VENDOR.md).
	dialEphemeralLocalPort bool

	// dialConnWrap is the W2c capture dial-wrap hook divergence: when set, an
	// outbound dial's conn is passed through this func before initConnection
	// takes ownership of it, so a caller can observe/tap the connection.
	// Instance-scoped (never a package-level global) so each UA's own
	// transport instance carries its own wrap without cross-contaminating
	// other concurrently-running UAs (see VENDOR.md).
	dialConnWrap func(net.Conn) net.Conn
}

func newTCPTransport(par *Parser) *transportTCP {
	p := &transportTCP{
		parser:    par,
		pool:      NewConnectionPool(),
		transport: TransportTCP,
	}
	p.log = log.Logger.With().Str("caller", "transport<TCP>").Logger()
	return p
}

// dialLocalAddr derives the outbound dial's local address from the Via-derived
// Addr. W2c B2 divergence: control the IP (BoundIP, deterministic on multihomed
// hosts) but leave the PORT ephemeral (0) — the listener already holds the
// signalling port, so re-binding it would EADDRINUSE. See VENDOR.md.
func dialLocalAddr(laddr Addr) *net.TCPAddr {
	if laddr.IP == nil {
		return nil
	}
	return &net.TCPAddr{IP: laddr.IP, Port: 0} // B2: keep IP, drop port
}

// dialLocalFor returns the local address CreateConnection should dial from,
// gated on t.dialEphemeralLocalPort: default preserves upstream IP:Port,
// opted-in returns IP:0 (dialLocalAddr).
func (t *transportTCP) dialLocalFor(laddr Addr) *net.TCPAddr {
	if t.dialEphemeralLocalPort {
		return dialLocalAddr(laddr)
	}
	if laddr.IP == nil {
		return nil
	}
	return &net.TCPAddr{IP: laddr.IP, Port: laddr.Port}
}

func (t *transportTCP) String() string {
	return "transport<TCP>"
}

func (t *transportTCP) Network() string {
	// return "tcp"
	return t.transport
}

func (t *transportTCP) Close() error {
	// return t.connections.Done()
	t.pool.Clear()
	return nil
}

// Serve is direct way to provide conn on which this worker will listen
func (t *transportTCP) Serve(l net.Listener, handler MessageHandler) error {
	t.log.Debug().Msgf("begin listening on %s %s", t.Network(), l.Addr().String())
	for {
		conn, err := l.Accept()
		if err != nil {
			t.log.Debug().Err(err).Msg("Fail to accept conenction")
			return err
		}

		t.initConnection(conn, conn.RemoteAddr().String(), true, handler)
	}
}

func (t *transportTCP) GetConnection(addr string) (Connection, error) {
	c := t.pool.Get(addr)
	return c, nil
}

func (t *transportTCP) CreateConnection(ctx context.Context, laddr Addr, raddr Addr, handler MessageHandler) (Connection, error) {
	// We are letting transport layer to resolve our address
	// raddr, err := net.ResolveTCPAddr("tcp", addr)
	// if err != nil {
	// 	return nil, err
	// }
	tladdr := t.dialLocalFor(laddr)

	traddr := &net.TCPAddr{
		IP:   raddr.IP,
		Port: raddr.Port,
	}
	return t.createConnection(ctx, tladdr, traddr, handler)
}

func (t *transportTCP) createConnection(ctx context.Context, laddr *net.TCPAddr, raddr *net.TCPAddr, handler MessageHandler) (Connection, error) {
	addr := raddr.String()
	t.log.Debug().Str("raddr", addr).Msg("Dialing new connection")

	d := net.Dialer{
		LocalAddr: laddr,
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%s dial err=%w", t, err)
	}

	// if err := conn.SetKeepAlive(true); err != nil {
	// 	return nil, fmt.Errorf("%s keepalive err=%w", t, err)
	// }

	// if err := conn.SetKeepAlivePeriod(30 * time.Second); err != nil {
	// 	return nil, fmt.Errorf("%s keepalive period err=%w", t, err)
	// }
	var outConn net.Conn = conn
	if t.dialConnWrap != nil {
		outConn = t.dialConnWrap(outConn)
	}
	c := t.initConnection(outConn, addr, false, handler)

	// Increase ref by 1 before returnin
	c.Ref(1)
	return c, nil
}

// initConnection pools c and starts its reader. SIPCLIENT-MCP DIVERGENCE
// (CF-058): an accepted connection (accepted=true, from Serve) is pooled only
// under its remote address. Its local address is the listener's, which is the
// UA's Via sent-by, so pooling it there let ClientRequestConnection's Via
// lookup send every outbound request down the last accepted inbound
// connection, whatever its destination. Responses find the accepted
// connection by the request's source (the remote key), unchanged.
//
// SIPCLIENT-MCP DIVERGENCE (CF-064 part 2): a dialed connection (accepted=false)
// takes its remote key only while the key is free; otherwise the pool tracks
// it (AddOrTrack). A peer that opened TCP from its own listen port keeps the
// accepted connection's key when we dial its Contact back.
func (t *transportTCP) initConnection(conn net.Conn, raddr string, accepted bool, handler MessageHandler) Connection {
	// // conn.SetKeepAlive(true)
	// conn.SetKeepAlivePeriod(3 * time.Second)
	laddr := conn.LocalAddr().String()
	t.log.Debug().Str("raddr", raddr).Msg("New connection")
	c := &TCPConnection{
		Conn:     conn,
		refcount: 1 + IdleConnection,
	}
	if accepted {
		laddr = "" // not pooled under the listen address; readConnection deletes no local key
		t.pool.Add(raddr, c)
	} else {
		t.pool.Add(laddr, c)
		t.pool.AddOrTrack(raddr, c)
	}
	go t.readConnection(c, laddr, raddr, handler)
	return c
}

// This should performe better to avoid any interface allocation
func (t *transportTCP) readConnection(conn *TCPConnection, laddr string, raddr string, handler MessageHandler) {
	buf := make([]byte, transportBufferSize)
	if laddr != "" {
		defer t.pool.Delete(conn, laddr)
	}
	defer t.pool.CloseAndDelete(conn, raddr)

	// Create stream parser context
	par := t.parser.NewSIPStream()

	for {
		num, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				t.log.Debug().Err(err).Msg("connection was closed")
				return
			}

			t.log.Error().Err(err).Msg("Read error")
			return
		}

		data := buf[:num]
		if len(bytes.Trim(data, "\x00")) == 0 {
			continue
		}

		// Check is keep alive
		datalen := len(data)
		if datalen <= 4 {
			// One or 2 CRLF
			// https://datatracker.ietf.org/doc/html/rfc5626#section-3.5.1
			if len(bytes.Trim(data, "\r\n")) == 0 {
				t.log.Debug().Msg("Keep alive CRLF received")
				if datalen == 4 {
					// 2 CRLF is ping
					if _, err := conn.Write(data[:2]); err != nil {
						t.log.Error().Err(err).Msg("Failed to pong keep alive")
						return
					}
				}

				continue
			}
		}

		// TODO fallback to parseFull if message size limit is set

		// t.log.Debug().Str("raddr", raddr).Str("data", string(data)).Msg("new message")
		t.parseStream(par, data, raddr, handler, conn)
	}
}

func (t *transportTCP) parseStream(par *ParserStream, data []byte, src string, handler MessageHandler, conn *TCPConnection) {
	msgs, err := par.ParseSIPStream(data)
	if err == ErrParseSipPartial {
		return
	}

	for _, msg := range msgs {
		if err != nil {
			t.log.Error().Err(err).Str("data", string(data)).Msg("failed to parse")
			return
		}

		msg.SetTransport(t.Network())
		msg.SetSource(src)
		// SIPCLIENT-MCP DIVERGENCE (CF-079): remember the connection a request
		// arrived on. conn is never nil here, so no typed-nil Connection.
		if req, ok := msg.(*Request); ok {
			req.rxConn = conn
		}
		handler(msg)
	}
}

// TODO use this when message size limit is defined
func (t *transportTCP) parseFull(data []byte, src string, handler MessageHandler) {
	msg, err := t.parser.ParseSIP(data) //Very expensive operation
	if err != nil {
		t.log.Error().Err(err).Str("data", string(data)).Msg("failed to parse")
		return
	}

	msg.SetTransport(t.Network())
	msg.SetSource(src)
	handler(msg)
}

type TCPConnection struct {
	net.Conn

	mu       sync.RWMutex
	refcount int

	// writeMu serializes writes so each keeps its own Timer_B deadline
	// (SIPCLIENT-MCP DIVERGENCE CF-069).
	writeMu sync.Mutex
}

func (c *TCPConnection) Ref(i int) int {
	c.mu.Lock()
	c.refcount += i
	ref := c.refcount
	c.mu.Unlock()
	log.Debug().Str("ip", c.LocalAddr().String()).Str("dst", c.RemoteAddr().String()).Int("ref", ref).Msg("TCP reference increment")
	return ref
}

func (c *TCPConnection) Close() error {
	c.mu.Lock()
	c.refcount = 0
	c.mu.Unlock()
	log.Debug().Str("ip", c.LocalAddr().String()).Str("dst", c.RemoteAddr().String()).Int("ref", 0).Msg("TCP doing hard close")
	return c.Conn.Close()
}

func (c *TCPConnection) TryClose() (int, error) {
	c.mu.Lock()
	c.refcount--
	ref := c.refcount
	c.mu.Unlock()
	log.Debug().Str("ip", c.LocalAddr().String()).Str("dst", c.RemoteAddr().String()).Int("ref", ref).Msg("TCP reference decrement")
	if ref > 0 {
		return ref, nil
	}

	if ref < 0 {
		log.Warn().Str("ip", c.LocalAddr().String()).Str("dst", c.RemoteAddr().String()).Int("ref", ref).Msg("TCP ref went negative")
		return 0, nil
	}

	log.Debug().Str("ip", c.LocalAddr().String()).Str("dst", c.RemoteAddr().String()).Int("ref", ref).Msg("TCP closing")
	return ref, c.Conn.Close()
}

func (c *TCPConnection) Read(b []byte) (n int, err error) {
	// Some debug hook. TODO move to proper way
	n, err = c.Conn.Read(b)
	if SIPDebug {
		log.Debug().Msgf("TCP read %s <- %s:\n%s", c.Conn.LocalAddr().String(), c.Conn.RemoteAddr(), string(b[:n]))
	}
	return n, err
}

func (c *TCPConnection) Write(b []byte) (n int, err error) {
	// SIPCLIENT-MCP DIVERGENCE (CF-069): a write to a peer that never reads is
	// bounded by Timer_B (set per write, under writeMu so a second writer cannot
	// move the deadline of a blocked one). A deadline error leaves a partial
	// message on the stream, so the connection is closed before writeMu is
	// released: a queued writer must never append to the partial message.
	c.writeMu.Lock()
	_ = c.Conn.SetWriteDeadline(time.Now().Add(Timer_B))
	n, err = c.Conn.Write(b)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		_ = c.Close()
	}
	c.writeMu.Unlock()
	if SIPDebug {
		log.Debug().Msgf("TCP write %s -> %s:\n%s", c.Conn.LocalAddr().String(), c.Conn.RemoteAddr(), string(b[:n]))
	}
	return n, err
}

func (c *TCPConnection) WriteMsg(msg Message) error {
	buf := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(buf)
	buf.Reset()
	msg.StringWrite(buf)
	data := buf.Bytes()

	n, err := c.Write(data)
	if err != nil {
		return fmt.Errorf("conn %s write err=%w", c.RemoteAddr().String(), err)
	}

	if n == 0 {
		return fmt.Errorf("wrote 0 bytes")
	}

	if n != len(data) {
		return fmt.Errorf("fail to write full message")
	}
	return nil
}
