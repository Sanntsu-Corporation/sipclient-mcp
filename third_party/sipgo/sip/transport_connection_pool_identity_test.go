package sip

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestAnExitingOutboundConnectionLeavesItsLocalKeyToANewerHolder (CF-069 b):
// the reader of an outbound TCP connection deletes the connection's own local
// key when it exits; a newer holder of that key must keep it.
func TestAnExitingOutboundConnectionLeavesItsLocalKeyToANewerHolder(t *testing.T) {
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
		t.Fatalf("CreateConnection: %v", err)
	}
	local := c1.(*TCPConnection).LocalAddr().String()
	newer, _ := padPair(t)
	tr.pool.Add(local, newer)

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(accepted)
		mu.Unlock()
		if n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	if len(accepted) < 1 {
		mu.Unlock()
		t.Fatal("server did not accept within 2s")
	}
	accepted[0].Close()
	mu.Unlock()

	rkey := ln.Addr().String()
	for {
		if _, ok := poolEntry(&tr.pool, rkey); !ok {
			break
		}
		if time.Now().After(deadline.Add(2 * time.Second)) {
			t.Fatal("the connection's reader did not exit within 4s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	settle := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(settle) {
		if got, ok := poolEntry(&tr.pool, local); !ok || got != newer {
			t.Fatalf("local key holds %p (present=%v) after the older connection exited, want the newer holder %p", got, ok, newer)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestAnExitingUDPListenerLeavesALearnedAddressToANewerHolder (CF-069 b): a
// UDP listener that exits deletes the remote addresses it learned; one that
// another connection has since taken must stay.
func TestAnExitingUDPListenerLeavesALearnedAddressToANewerHolder(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	tr := newUDPTransport(NewParser())
	go tr.Serve(pc, func(Message) {})

	peer, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { peer.Close() })
	learned := peer.LocalAddr().String()

	deadline := time.Now().Add(3 * time.Second)
	for {
		_, _ = peer.Write([]byte("\x01\x01\x01\x01"))
		if _, ok := poolEntry(&tr.pool, learned); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the listener never pooled the peer's address")
		}
		time.Sleep(10 * time.Millisecond)
	}
	newer, _ := padPair(t)
	tr.pool.Add(learned, newer)
	pc.Close()

	own := pc.LocalAddr().String()
	deadline = time.Now().Add(3 * time.Second)
	for {
		if _, ok := poolEntry(&tr.pool, own); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the listener's reader did not exit within 3s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got, ok := poolEntry(&tr.pool, learned); !ok || got != newer {
		t.Fatalf("learned address holds %p (present=%v) after the listener exited, want the newer holder %p", got, ok, newer)
	}
}

func TestDeleteLeavesAKeyHeldByAnotherConnection(t *testing.T) {
	p := NewConnectionPool()
	old, _ := padPair(t)
	newer, _ := padPair(t)
	p.Add("k", old)
	p.Add("k", newer)
	p.Delete(old, "k")
	if got, ok := poolEntry(&p, "k"); !ok || got != newer {
		t.Fatalf("k holds %p (present=%v) after Delete by the older connection, want %p", got, ok, newer)
	}
	p.Delete(newer, "k")
	if got, ok := poolEntry(&p, "k"); ok {
		t.Fatalf("k still holds %p after Delete by its own connection", got)
	}
}

func TestDeleteMultipleRemovesOnlyTheConnectionsOwnKeys(t *testing.T) {
	p := NewConnectionPool()
	c, _ := padPair(t)
	other, _ := padPair(t)
	p.Add("a", c)
	p.Add("b", other)
	p.DeleteMultiple(c, []string{"a", "b", "absent"})
	if got, ok := poolEntry(&p, "a"); ok {
		t.Fatalf("a still holds %p", got)
	}
	if got, ok := poolEntry(&p, "b"); !ok || got != other {
		t.Fatalf("b holds %p (present=%v), want %p", got, ok, other)
	}
}

func TestAddIfNotExistsStoresUnderAFreeKey(t *testing.T) {
	p := NewConnectionPool()
	c, _ := padPair(t)
	if !p.AddIfNotExists("k", c) {
		t.Fatal("AddIfNotExists on a free key returned false")
	}
	if got, ok := poolEntry(&p, "k"); !ok || got != c {
		t.Fatalf("k holds %p (present=%v), want %p", got, ok, c)
	}
}

func TestAddIfNotExistsLeavesAnExistingEntry(t *testing.T) {
	p := NewConnectionPool()
	holder, _ := padPair(t)
	other, _ := padPair(t)
	p.Add("k", holder)
	if p.AddIfNotExists("k", other) {
		t.Fatal("AddIfNotExists on a held key returned true")
	}
	if got, ok := poolEntry(&p, "k"); !ok || got != holder {
		t.Fatalf("k holds %p (present=%v), want %p", got, ok, holder)
	}
}

// Pin: a store gives a connection with no reference the default one, as Add does.
func TestAddIfNotExistsGivesAnUnreferencedConnectionItsDefaultRef(t *testing.T) {
	p := NewConnectionPool()
	a, _ := net.Pipe()
	t.Cleanup(func() { a.Close() })
	c := &TCPConnection{Conn: a}
	if !p.AddIfNotExists("k", c) {
		t.Fatal("AddIfNotExists on a free key returned false")
	}
	if got := c.Ref(0); got != 1 {
		t.Fatalf("ref after the store = %d, want 1", got)
	}
}
