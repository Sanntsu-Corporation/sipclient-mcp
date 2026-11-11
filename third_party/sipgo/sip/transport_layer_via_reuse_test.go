package sip

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// N1: ClientRequestConnection looks up GetConnection(<Via sent-by>) before it
// considers the destination. An OUTBOUND stream connection is pooled under its
// remote address, so a connection the UA opened to its OWN listen address
// (a peer's Contact naming that address) is pooled under the UA's Via key and
// was handed to every later outbound request, whatever its destination. A Via
// hit on a stream connection is now used only when it leads to the request's
// destination.

// viaReuseRequest builds an OPTIONS to dst over transport whose Via sent-by is
// via, the shape a UA that hands its listen address to the client produces.
func viaReuseRequest(transport string, via, dst *net.TCPAddr) *Request {
	uri := Uri{Host: dst.IP.String(), Port: dst.Port, UriParams: NewParams()}
	uri.UriParams.Add("transport", transport)
	req := NewRequest(OPTIONS, uri)
	req.AppendHeader(&ViaHeader{
		ProtocolName:    "SIP",
		ProtocolVersion: "2.0",
		Transport:       strings.ToUpper(transport),
		Host:            via.IP.String(),
		Port:            via.Port,
		Params:          NewParams(),
	})
	req.SetTransport(strings.ToUpper(transport))
	return req
}

// firstLines returns a channel carrying the first line of every connection ln
// accepts (a tls.Listener's connection handshakes on that first read).
func firstLines(t *testing.T, ln net.Listener) <-chan string {
	t.Helper()
	out := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err == nil {
					out <- strings.TrimSpace(line)
				}
			}(c)
		}
	}()
	return out
}

func TestStreamViaKeyHitIsUsedOnlyTowardsItsOwnDestination(t *testing.T) {
	for _, transport := range []string{"tcp", "tls"} {
		t.Run(transport, func(t *testing.T) {
			ip := net.ParseIP("127.0.0.1")
			tp := NewTransportLayer(net.DefaultResolver, NewParser(), &tls.Config{InsecureSkipVerify: true}, true, nil)
			t.Cleanup(func() { tp.Close() })

			// The UA's own listener: its address is the Via sent-by.
			uaInner, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen ua: %v", err)
			}
			uaLn := uaInner
			if transport == "tls" {
				uaLn = tls.NewListener(uaInner, selfSignedTLSConfigForTest(t, ip))
			}
			t.Cleanup(func() { uaLn.Close() })
			if transport == "tls" {
				go tp.ServeTLS(uaLn)
			} else {
				go tp.ServeTCP(uaLn)
			}
			uaAddr := uaInner.Addr().(*net.TCPAddr)

			// A different peer, recording the first line it receives.
			peerInner, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen peer: %v", err)
			}
			peerLn := peerInner
			if transport == "tls" {
				peerLn = tls.NewListener(peerInner, selfSignedTLSConfigForTest(t, ip))
			}
			t.Cleanup(func() { peerLn.Close() })
			peerLines := firstLines(t, peerLn)
			peerAddr := peerInner.Addr().(*net.TCPAddr)

			// The UA dials its own listen address (an in-dialog request to a
			// Contact naming it): that connection is pooled under uaAddr, the
			// Via key.
			self, err := tp.ClientRequestConnection(context.Background(), viaReuseRequest(transport, uaAddr, uaAddr))
			if err != nil {
				t.Fatalf("self ClientRequestConnection: %v", err)
			}
			defer self.TryClose()
			if c, _ := tp.GetConnection(transport, uaAddr.String()); c != self {
				t.Fatalf("precondition: the self connection is not pooled under the Via key %s", uaAddr)
			}

			// A later request to the peer must go to the peer.
			req := viaReuseRequest(transport, uaAddr, peerAddr)
			conn, err := tp.ClientRequestConnection(context.Background(), req)
			if err != nil {
				t.Fatalf("peer ClientRequestConnection: %v", err)
			}
			defer conn.TryClose()
			if got := conn.(*TCPConnection).RemoteAddr().String(); got != peerAddr.String() {
				t.Fatalf("request to %s got a connection to %s (the Via-key self connection); want one to its destination", peerAddr, got)
			}
			if err := conn.WriteMsg(req); err != nil {
				t.Fatalf("WriteMsg: %v", err)
			}
			select {
			case line := <-peerLines:
				if !strings.HasPrefix(line, "OPTIONS ") {
					t.Fatalf("peer received %q, want the OPTIONS request line", line)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the peer never received the request within 3s")
			}

			// Legitimate reuse is unchanged: a request towards the UA's own
			// address still takes the Via-key connection that leads there.
			again, err := tp.ClientRequestConnection(context.Background(), viaReuseRequest(transport, uaAddr, uaAddr))
			if err != nil {
				t.Fatalf("second self ClientRequestConnection: %v", err)
			}
			if again != self {
				t.Fatalf("a request to %s did not reuse the Via-key connection that leads there", uaAddr)
			}
		})
	}
}

// TestUDPViaKeyStillFindsTheListener pins the UDP path: the listener
// connection is pooled under its local address, and the Via lookup still
// returns it for a request to any destination (connectionless sending).
func TestUDPViaKeyStillFindsTheListener(t *testing.T) {
	tp := NewTransportLayer(net.DefaultResolver, NewParser(), nil, true, nil)
	t.Cleanup(func() { tp.Close() })
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go tp.ServeUDP(pc)
	laddr := pc.LocalAddr().(*net.UDPAddr)
	via := &net.TCPAddr{IP: laddr.IP, Port: laddr.Port}

	var listener Connection
	deadline := time.Now().Add(2 * time.Second)
	for listener == nil && time.Now().Before(deadline) {
		listener, _ = tp.GetConnection("udp", laddr.String())
		time.Sleep(5 * time.Millisecond)
	}
	if listener == nil {
		t.Fatalf("UDP listener not pooled under %s within 2s", laddr)
	}

	req := viaReuseRequest("udp", via, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9})
	conn, err := tp.ClientRequestConnection(context.Background(), req)
	if err != nil {
		t.Fatalf("ClientRequestConnection: %v", err)
	}
	if conn != listener {
		t.Fatalf("UDP request did not take the listener connection found under the Via key")
	}
}
