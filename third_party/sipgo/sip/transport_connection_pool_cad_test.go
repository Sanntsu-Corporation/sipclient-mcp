package sip

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// padPair returns a pooled-style TCPConnection over one end of a net.Pipe and
// the other end, whose Read ends once the connection is closed.
func padPair(t *testing.T) (*TCPConnection, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return &TCPConnection{Conn: a, refcount: 1 + IdleConnection}, b
}

func peerSeesClose(t *testing.T, peer net.Conn) bool {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	_, err := peer.Read(make([]byte, 1))
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)
}

func poolEntry(p *ConnectionPool, key string) (Connection, bool) {
	p.RLock()
	defer p.RUnlock()
	c, ok := p.m[key]
	return c, ok
}

// TestCloseAndDeleteLeavesANewerConnectionUnderTheSameKey (CF-064 part 1): an
// exiting connection is closed, but the key now belongs to a newer connection
// and stays.
func TestCloseAndDeleteLeavesANewerConnectionUnderTheSameKey(t *testing.T) {
	p := NewConnectionPool()
	old, oldPeer := padPair(t)
	newer, _ := padPair(t)
	p.Add("k", old)
	p.Add("k", newer)

	p.CloseAndDelete(old, "k")

	if got, ok := poolEntry(&p, "k"); !ok || got != Connection(newer) {
		t.Fatalf("pool entry for k = %v (present=%v), want the newer connection", got, ok)
	}
	if !peerSeesClose(t, oldPeer) {
		t.Fatal("the exiting connection was not closed")
	}
}

// TestCloseAndDeleteStillRemovesItsOwnEntry pins the unchanged case.
func TestCloseAndDeleteStillRemovesItsOwnEntry(t *testing.T) {
	p := NewConnectionPool()
	c, peer := padPair(t)
	p.Add("k", c)

	p.CloseAndDelete(c, "k")

	if got, ok := poolEntry(&p, "k"); ok {
		t.Fatalf("pool still has an entry for k: %v", got)
	}
	if !peerSeesClose(t, peer) {
		t.Fatal("the connection was not closed")
	}
}

// TestAnExitingOutboundConnectionKeepsANewerOnesRemoteKey drives the real
// reader-exit path: two outbound connections to one destination share the
// remote key; the older one's exit must not remove the newer one's entry. The
// second dial no longer overwrites the key (CF-064 part 2); it is tracked, and
// receives the key when the older one exits.
func TestAnExitingOutboundConnectionKeepsANewerOnesRemoteKey(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var accepted []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepted = append(accepted, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range accepted {
			c.Close()
		}
	})

	tr := newTCPTransport(NewParser())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raddr := Addr{IP: net.ParseIP("127.0.0.1"), Port: listenerPort(t, ln)}
	c1, err := tr.CreateConnection(ctx, Addr{}, raddr, func(Message) {})
	if err != nil {
		t.Fatalf("first CreateConnection: %v", err)
	}
	c2, err := tr.CreateConnection(ctx, Addr{}, raddr, func(Message) {})
	if err != nil {
		t.Fatalf("second CreateConnection: %v", err)
	}
	rkey := ln.Addr().String()
	c1local := c1.(*TCPConnection).LocalAddr().String()
	if got, _ := poolEntry(&tr.pool, rkey); got != c1 {
		t.Fatalf("precondition: remote key holds %p, want the first connection %p", got, c1)
	}

	// Close the server side of the first connection (accepted in order).
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(accepted)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	if len(accepted) < 2 {
		mu.Unlock()
		t.Fatal("server did not accept both connections within 2s")
	}
	accepted[0].Close()
	mu.Unlock()

	// readConnection deletes the local key last (declared first among its
	// defers), so once it is gone both deferred deletes have run.
	for {
		if _, ok := poolEntry(&tr.pool, c1local); !ok {
			break
		}
		if time.Now().After(deadline.Add(2 * time.Second)) {
			t.Fatal("the first connection's reader did not exit within 4s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got, ok := poolEntry(&tr.pool, rkey); !ok || got != c2 {
		t.Fatalf("remote key holds %v (present=%v) after the older connection exited, want the second connection", got, ok)
	}
}
