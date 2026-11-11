package sip

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// N2: TransportLayer.WriteMsg (the 2xx ACK's path, which has no transaction)
// dialed with context.Background(), so a destination that accepts TCP but
// never completes the TLS handshake held the caller forever. The dial and the
// handshake are now bounded by Timer_B (64*T1), after which the UAS has
// stopped retransmitting the 2xx anyway.
func TestWriteMsgRequestDialIsBoundedByTimerB(t *testing.T) {
	saved := Timer_B
	Timer_B = 200 * time.Millisecond
	t.Cleanup(func() { Timer_B = saved })

	// Accepts TCP and holds the connection without ever answering the TLS
	// ClientHello.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	held := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		held <- c
	}()
	t.Cleanup(func() {
		select {
		case c := <-held:
			c.Close()
		default:
		}
	})

	tp := NewTransportLayer(net.DefaultResolver, NewParser(), nil, true, nil)
	t.Cleanup(func() { tp.Close() })
	dst := ln.Addr().(*net.TCPAddr)
	via := &net.TCPAddr{IP: dst.IP, Port: 5061}
	req := viaReuseRequest("tls", via, dst)

	done := make(chan error, 1)
	go func() { done <- tp.WriteMsg(req) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("WriteMsg = %v, want an error wrapping context.DeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WriteMsg to a destination that stalls the TLS handshake did not return within 5s (Timer_B is 200ms)")
	}
}
