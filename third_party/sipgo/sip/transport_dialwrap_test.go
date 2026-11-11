package sip

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

// markerConn is a net.Conn decorator used only to prove identity: when
// dialConnWrap wraps a conn in a markerConn, the id field lets a test assert
// exactly which wrap function produced the value stored on the Connection.
type markerConn struct {
	net.Conn
	id string
}

func acceptAndDiscardTCP(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
}

func acceptAndDiscardTLS(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsC, ok := c.(*tls.Conn)
				if !ok {
					return
				}
				if err := tlsC.Handshake(); err != nil {
					return
				}
				io.Copy(io.Discard, tlsC)
			}(c)
		}
	}()
}

func listenerPort(t *testing.T, ln net.Listener) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}
	return port
}

// selfSignedTLSConfigForTest builds a minimal ephemeral self-signed
// certificate for ip, for use as the server-side tls.Config in tests. Client
// dials in these tests use InsecureSkipVerify, so the cert only needs to be
// well-formed, not verified.
func selfSignedTLSConfigForTest(t *testing.T, ip net.IP) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: ip.String()},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// TestDialConnWrapInvokedOnDialedConnBeforeInitConnection asserts (a): a
// per-instance dialConnWrap set on a transportTCP is invoked on the dialed
// conn, and its return value (not the raw dialed conn) is what ends up stored
// on the Connection initConnection builds -- proving the wrap runs before
// initConnection takes ownership of the conn.
func TestDialConnWrapInvokedOnDialedConnBeforeInitConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	acceptAndDiscardTCP(t, ln)

	tr := newTCPTransport(NewParser())
	var calls int
	tr.dialConnWrap = func(c net.Conn) net.Conn {
		calls++
		return &markerConn{Conn: c, id: "tcp"}
	}

	raddr := Addr{IP: net.ParseIP("127.0.0.1"), Port: listenerPort(t, ln)}
	conn, err := tr.CreateConnection(context.Background(), Addr{}, raddr, func(Message) {})
	if err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}
	defer conn.Close()

	tcpConn, ok := conn.(*TCPConnection)
	if !ok {
		t.Fatalf("Connection is %T, want *TCPConnection", conn)
	}
	marker, ok := tcpConn.Conn.(*markerConn)
	if !ok {
		t.Fatalf("stored conn is %T, want *markerConn (dialConnWrap's return value stored before initConnection)", tcpConn.Conn)
	}
	if marker.id != "tcp" {
		t.Fatalf("marker id = %q, want %q", marker.id, "tcp")
	}
	if calls != 1 {
		t.Fatalf("dialConnWrap invoked %d times, want 1", calls)
	}
}

// TestDialConnWrapInvokedOnPostHandshakeTLSConn asserts (b): for TLS, the
// instance-scoped dialConnWrap (inherited via transportTLS's embedded
// *transportTCP) is invoked on the POST-HANDSHAKE *tls.Conn, not the raw
// pre-handshake TCP conn.
func TestDialConnWrapInvokedOnPostHandshakeTLSConn(t *testing.T) {
	serverIP := net.ParseIP("127.0.0.1")
	serverTLSConf := selfSignedTLSConfigForTest(t, serverIP)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConf)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()
	acceptAndDiscardTLS(t, ln)

	clientTLSConf := &tls.Config{InsecureSkipVerify: true}
	tr := newTLSTransport(NewParser(), clientTLSConf)

	var calls int
	var sawType string
	tr.dialConnWrap = func(c net.Conn) net.Conn {
		calls++
		if _, ok := c.(*tls.Conn); ok {
			sawType = "tls"
		} else {
			sawType = "other"
		}
		return &markerConn{Conn: c, id: "tls"}
	}

	raddr := Addr{IP: serverIP, Port: listenerPort(t, ln)}
	conn, err := tr.CreateConnection(context.Background(), Addr{}, raddr, func(Message) {})
	if err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}
	defer conn.Close()

	if sawType != "tls" {
		t.Fatalf("dialConnWrap saw conn type %q, want the post-handshake *tls.Conn", sawType)
	}

	tcpConn, ok := conn.(*TCPConnection)
	if !ok {
		t.Fatalf("Connection is %T, want *TCPConnection", conn)
	}
	marker, ok := tcpConn.Conn.(*markerConn)
	if !ok {
		t.Fatalf("stored conn is %T, want *markerConn", tcpConn.Conn)
	}
	if marker.id != "tls" {
		t.Fatalf("marker id = %q, want %q", marker.id, "tls")
	}
	if calls != 1 {
		t.Fatalf("dialConnWrap invoked %d times, want 1", calls)
	}
}

// TestDialConnWrapTwoInstancesDoNotInterfere asserts (c): the critical
// multi-UA-safety property. Two independent transportTCP instances, each with
// its own dialConnWrap, must never see the other's wrap invoked -- proving
// dialConnWrap is an instance field, not a package-level global. If it were a
// package-level global, trA's dial would observe trB's later-assigned wrap
// (last-write-wins), which the marker-id assertions below would catch.
func TestDialConnWrapTwoInstancesDoNotInterfere(t *testing.T) {
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer lnA.Close()
	acceptAndDiscardTCP(t, lnA)

	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer lnB.Close()
	acceptAndDiscardTCP(t, lnB)

	trA := newTCPTransport(NewParser())
	trB := newTCPTransport(NewParser())

	var callsA, callsB int
	trA.dialConnWrap = func(c net.Conn) net.Conn {
		callsA++
		return &markerConn{Conn: c, id: "A"}
	}
	// Assigned after trA's, so a package-level global would make trA's dial
	// (below) observe this one instead of its own.
	trB.dialConnWrap = func(c net.Conn) net.Conn {
		callsB++
		return &markerConn{Conn: c, id: "B"}
	}

	raddrA := Addr{IP: net.ParseIP("127.0.0.1"), Port: listenerPort(t, lnA)}
	connA, err := trA.CreateConnection(context.Background(), Addr{}, raddrA, func(Message) {})
	if err != nil {
		t.Fatalf("CreateConnection A: %v", err)
	}
	defer connA.Close()

	raddrB := Addr{IP: net.ParseIP("127.0.0.1"), Port: listenerPort(t, lnB)}
	connB, err := trB.CreateConnection(context.Background(), Addr{}, raddrB, func(Message) {})
	if err != nil {
		t.Fatalf("CreateConnection B: %v", err)
	}
	defer connB.Close()

	tcpConnA, ok := connA.(*TCPConnection)
	if !ok {
		t.Fatalf("connA is %T, want *TCPConnection", connA)
	}
	markerA, ok := tcpConnA.Conn.(*markerConn)
	if !ok || markerA.id != "A" {
		t.Fatalf("trA's connection wrapped with id %v (ok=%v), want \"A\" -- trA saw trB's wrap (not instance-scoped)", markerA, ok)
	}

	tcpConnB, ok := connB.(*TCPConnection)
	if !ok {
		t.Fatalf("connB is %T, want *TCPConnection", connB)
	}
	markerB, ok := tcpConnB.Conn.(*markerConn)
	if !ok || markerB.id != "B" {
		t.Fatalf("trB's connection wrapped with id %v (ok=%v), want \"B\"", markerB, ok)
	}

	if callsA != 1 {
		t.Fatalf("trA's dialConnWrap invoked %d times, want 1 (must not fire for trB's dial)", callsA)
	}
	if callsB != 1 {
		t.Fatalf("trB's dialConnWrap invoked %d times, want 1 (must not fire for trA's dial)", callsB)
	}
}
