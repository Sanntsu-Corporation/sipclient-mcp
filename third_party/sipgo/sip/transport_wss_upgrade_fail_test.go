package sip

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// TestWSSUpgradeFailureClosesTheDialedConnection (CF-069 a): a WSS dial whose
// upgrade fails must close the dialed TCP connection. The server sees EOF (or a
// reset) on the raw connection, not a read timeout.
func TestWSSUpgradeFailureClosesTheDialedConnection(t *testing.T) {
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
		_, _ = raw.Write([]byte("this is not a TLS server\r\n"))
		_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		for {
			if _, err := raw.Read(buf); err != nil {
				readErr <- err
				return
			}
		}
	}()

	tr := newWSSTransport(NewParser(), &tls.Config{InsecureSkipVerify: true})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raddr := Addr{IP: net.ParseIP("127.0.0.1"), Port: listenerPort(t, ln)}
	conn, err := tr.CreateConnection(ctx, Addr{}, raddr, nil)
	if err == nil {
		conn.Close()
		t.Fatal("CreateConnection succeeded against a non-TLS server")
	}
	if !strings.Contains(err.Error(), "failed to upgrade") {
		t.Fatalf("error = %v, want it to contain %q", err, "failed to upgrade")
	}
	if got := <-readErr; !connClosedByPeer(got) {
		t.Fatalf("server read on the raw connection = %v, want EOF or reset (the dialed connection was not closed)", got)
	}
	if n := tr.pool.Size(); n != 0 {
		t.Fatalf("pool size = %d, want 0", n)
	}
}
