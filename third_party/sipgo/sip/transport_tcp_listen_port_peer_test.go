//go:build linux

package sip

import (
	"context"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

// listenPortPeer starts a UA transport layer and a peer that dials the UA from
// the very port it then listens on (a SIP peer whose source port is its listen
// port). It returns once the UA pooled the accepted connection and dialed
// back to the peer's listen address for an OPTIONS request.
func listenPortPeer(t *testing.T) (tp *TransportLayer, key string, accepted Connection, peerConn, back net.Conn) {
	t.Helper()
	tp = NewTransportLayer(net.DefaultResolver, NewParser(), nil, true, nil)
	t.Cleanup(func() { tp.Close() })
	uaLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { uaLn.Close() })
	go tp.ServeTCP(uaLn)

	d := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")},
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peerConn, err = d.DialContext(ctx, "tcp", uaLn.Addr().String())
	if err != nil {
		t.Fatalf("peer dial: %v", err)
	}
	t.Cleanup(func() { peerConn.Close() })
	key = peerConn.LocalAddr().String()
	peerLn, err := net.Listen("tcp", key)
	if err != nil {
		t.Fatalf("peer listen on its dial port %s: %v", key, err)
	}
	t.Cleanup(func() { peerLn.Close() })

	deadline := time.Now().Add(2 * time.Second)
	for {
		if c, ok := poolEntry(&tp.tcp.pool, key); ok {
			accepted = c
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the UA never pooled the accepted connection under %s", key)
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := tp.WriteMsg(viaReuseRequest("tcp", uaLn.Addr().(*net.TCPAddr), peerLn.Addr().(*net.TCPAddr))); err != nil {
		t.Fatalf("UA WriteMsg: %v", err)
	}
	_ = peerLn.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	back, err = peerLn.Accept()
	if err != nil {
		t.Fatalf("the UA did not dial back: %v", err)
	}
	t.Cleanup(func() { back.Close() })
	_ = back.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8)
	if n, err := back.Read(buf); err != nil || !strings.HasPrefix(string(buf[:n]), "OPTIONS ") {
		t.Fatalf("dial-back first read = %q, %v; want the OPTIONS request line", buf[:n], err)
	}
	return tp, key, accepted, peerConn, back
}

// TestAListenPortPeersAcceptedConnectionKeepsItsKeyAndClearClosesBoth
// (CF-064 part 2): our dial-back must not take the accepted connection's key,
// and closing the layer must close both connections.
func TestAListenPortPeersAcceptedConnectionKeepsItsKeyAndClearClosesBoth(t *testing.T) {
	tp, key, accepted, peerConn, back := listenPortPeer(t)
	if got, _ := poolEntry(&tp.tcp.pool, key); got != accepted {
		t.Fatalf("after our dial-back %s maps to %p; want the accepted connection %p", key, got, accepted)
	}
	_ = tp.Close()
	for name, c := range map[string]net.Conn{"the peer's dialing connection": peerConn, "our dial-back": back} {
		if err := drainUntilClosed(c); err == nil || isTimeout(err) {
			t.Fatalf("%s was not closed by Close: %v", name, err)
		}
	}
}

// drainUntilClosed reads c until it fails, within one second.
func drainUntilClosed(c net.Conn) error {
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 512)
	for {
		if _, err := c.Read(buf); err != nil {
			return err
		}
	}
}

// TestAListenPortPeersAcceptedConnectionOutlivesOurOutboundOne (CF-064 part 2):
// the server transaction looks the connection up by the request's source; it
// must still find the accepted connection after our dialed one closes.
func TestAListenPortPeersAcceptedConnectionOutlivesOurOutboundOne(t *testing.T) {
	tp, key, accepted, _, back := listenPortPeer(t)
	ourLocal := back.RemoteAddr().String()
	back.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, ok := poolEntry(&tp.tcp.pool, ourLocal); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("our dialed connection's reader did not exit within 3s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	got, err := tp.GetConnection("tcp", key)
	if err != nil || got != accepted {
		t.Fatalf("GetConnection(%s) = %p, %v; want the accepted connection %p", key, got, err, accepted)
	}
	got.TryClose()
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
