package sip

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// CF-058: an ACCEPTED stream connection is pooled only under its remote
// address. Pooling it under the listener's address as well let
// TransportLayer.ClientRequestConnection's Via lookup (the UA's Via sent-by is
// its listen address) hand the most recently accepted inbound connection to
// every outbound request, whatever its destination.

// serveForTest runs tr.Serve on ln in a goroutine and closes ln at cleanup.
func serveForTest(t *testing.T, tr *transportTCP, ln net.Listener) {
	t.Helper()
	t.Cleanup(func() { ln.Close() })
	go tr.Serve(ln, func(Message) {})
}

// awaitPooled polls tr's pool until addr maps to a connection, or fails the
// test after 2 s.
func awaitPooled(t *testing.T, tr *transportTCP, addr string) Connection {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c, _ := tr.GetConnection(addr); c != nil {
			return c
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no pool entry for %s within 2s", addr)
	return nil
}

func TestAcceptedTCPConnectionIsNotPooledUnderTheListenAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tr := newTCPTransport(NewParser())
	serveForTest(t, tr, ln)

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	awaitPooled(t, tr, client.LocalAddr().String())
	if c, _ := tr.GetConnection(ln.Addr().String()); c != nil {
		t.Fatalf("accepted connection is pooled under the listen address %s; want no entry", ln.Addr())
	}
}

func TestAcceptedTLSConnectionIsNotPooledUnderTheListenAddress(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := tls.NewListener(inner, selfSignedTLSConfigForTest(t, net.ParseIP("127.0.0.1")))
	tr := newTLSTransport(NewParser(), &tls.Config{InsecureSkipVerify: true})
	serveForTest(t, tr.transportTCP, ln)

	client, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer client.Close()

	awaitPooled(t, tr.transportTCP, client.LocalAddr().String())
	if c, _ := tr.GetConnection(ln.Addr().String()); c != nil {
		t.Fatalf("accepted TLS connection is pooled under the listen address %s; want no entry", ln.Addr())
	}
}

func TestOutboundTCPConnectionIsStillPooledUnderBothAddresses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	acceptAndDiscardTCP(t, ln)

	tr := newTCPTransport(NewParser())
	raddr := Addr{IP: net.ParseIP("127.0.0.1"), Port: listenerPort(t, ln)}
	conn, err := tr.CreateConnection(context.Background(), Addr{}, raddr, func(Message) {})
	if err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}
	defer conn.Close()

	local := conn.(*TCPConnection).LocalAddr().String()
	if c, _ := tr.GetConnection(local); c != conn {
		t.Fatalf("GetConnection(local %s) = %v, want the outbound connection", local, c)
	}
	if c, _ := tr.GetConnection(ln.Addr().String()); c != conn {
		t.Fatalf("GetConnection(remote %s) = %v, want the outbound connection", ln.Addr(), c)
	}
}

func TestClosingAnAcceptedConnectionLeavesTheListenAddressEntryAlone(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tr := newTCPTransport(NewParser())
	serveForTest(t, tr, ln)

	// Something else owns the listen-address key: an outbound connection
	// stands in for it.
	other, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen other: %v", err)
	}
	defer other.Close()
	acceptAndDiscardTCP(t, other)
	outbound, err := tr.CreateConnection(context.Background(), Addr{},
		Addr{IP: net.ParseIP("127.0.0.1"), Port: listenerPort(t, other)}, func(Message) {})
	if err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}
	defer outbound.Close()
	listenKey := ln.Addr().String()
	tr.pool.Add(listenKey, outbound)

	client, err := net.Dial("tcp", listenKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	clientKey := client.LocalAddr().String()
	awaitPooled(t, tr, clientKey)
	client.Close()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if c, _ := tr.GetConnection(clientKey); c == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("accepted connection's entry %s not removed within 2s of the client closing", clientKey)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// readConnection's defers run remote key first, listen key second, so
	// watch the listen key over a settle window rather than once.
	settle := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(settle) {
		if c, _ := tr.GetConnection(listenKey); c != outbound {
			t.Fatalf("GetConnection(listen %s) = %v after the accepted connection closed; want the outbound connection", listenKey, c)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
