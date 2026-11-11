package sip

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

// connClosedByPeer reports whether a read error means the peer closed the
// connection (EOF, or a reset when it closed with our alert unread), as opposed
// to a read timeout, which means it is still open.
func connClosedByPeer(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)
}

// TestTLSHandshakeFailureClosesTheDialedConnection (CF-066): a handshake that
// fails for a reason other than the context (here an untrusted certificate)
// must close the dialed TCP connection. The server sees it as EOF on the raw
// connection, not as a read timeout.
func TestTLSHandshakeFailureClosesTheDialedConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	serverConf := selfSignedTLSConfigForTest(t, net.ParseIP("127.0.0.1"))
	readErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			readErr <- err
			return
		}
		defer raw.Close()
		_ = tls.Server(raw, serverConf).Handshake() // expected to fail
		_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = raw.Read(make([]byte, 1))
		readErr <- err
	}()

	tr := newTLSTransport(NewParser(), &tls.Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raddr := Addr{IP: net.ParseIP("127.0.0.1"), Port: listenerPort(t, ln)}
	conn, err := tr.CreateConnection(ctx, Addr{}, raddr, nil)
	if err == nil {
		conn.Close()
		t.Fatal("CreateConnection succeeded against an untrusted certificate")
	}
	if !strings.Contains(err.Error(), "TLS handshake error") {
		t.Fatalf("error = %v, want it to contain %q", err, "TLS handshake error")
	}
	if got := <-readErr; !connClosedByPeer(got) {
		t.Fatalf("server read on the raw connection = %v, want EOF or reset (the dialed connection was not closed)", got)
	}
	if n := tr.pool.Size(); n != 0 {
		t.Fatalf("pool size = %d, want 0 (a failed connection must not be pooled)", n)
	}
}

// TestTLSHandshakeDeadlineStillClosesTheDialedConnection pins crypto/tls's own
// close on a context deadline: the closing is not lost by the CF-066 change.
func TestTLSHandshakeDeadlineStillClosesTheDialedConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	readErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			readErr <- err
			return
		}
		defer raw.Close()
		_ = raw.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4096)
		for {
			if _, err := raw.Read(buf); err != nil {
				readErr <- err
				return
			}
		}
	}()

	tr := newTLSTransport(NewParser(), &tls.Config{InsecureSkipVerify: true})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	raddr := Addr{IP: net.ParseIP("127.0.0.1"), Port: listenerPort(t, ln)}
	start := time.Now()
	conn, err := tr.CreateConnection(ctx, Addr{}, raddr, nil)
	if err == nil {
		conn.Close()
		t.Fatal("CreateConnection succeeded against a server that never answers")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want it to wrap context.DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("CreateConnection took %v, want under 2s", d)
	}
	if got := <-readErr; !connClosedByPeer(got) {
		t.Fatalf("server read loop ended with %v, want EOF or reset (the dialed connection was not closed)", got)
	}
}
