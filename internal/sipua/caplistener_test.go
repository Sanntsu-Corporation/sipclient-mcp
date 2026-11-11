package sipua

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func capPair(t *testing.T, maxConns int, idle, floor time.Duration) (*capListener, string) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	l := newCapListener(raw, maxConns, idle, floor)
	t.Cleanup(func() { _ = l.Close() })
	return l, raw.Addr().String()
}

func closedWithin(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 1))
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return err != nil
}

// A connection over the cap is closed at accept; a freed slot is reusable.
func TestCapListenerClosesConnectionsOverTheCap(t *testing.T) {
	l, addr := capPair(t, 2, time.Minute, time.Hour)
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	var peers []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer func() { _ = c.Close() }()
		peers = append(peers, c)
	}
	first, second := <-accepted, <-accepted
	if !closedWithin(peers[2], time.Second) {
		t.Fatal("the third connection over a cap of 2 was not closed")
	}
	if closedWithin(peers[0], 150*time.Millisecond) || closedWithin(peers[1], 150*time.Millisecond) {
		t.Fatal("a connection within the cap was closed")
	}

	_ = first.Close()
	_ = first.Close() // a second Close must not free a second slot
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	third := <-accepted
	if closedWithin(c, 150*time.Millisecond) {
		t.Fatal("a connection into the freed slot was closed")
	}
	d, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = d.Close() }()
	if !closedWithin(d, time.Second) {
		t.Fatal("a double Close freed two slots")
	}
	_ = second.Close()
	_ = third.Close()
}

// An idle accepted connection fails its read after the idle deadline.
func TestCapListenerReadsTimeOutWhenIdle(t *testing.T) {
	l, addr := capPair(t, 2, 100*time.Millisecond, time.Hour)
	done := make(chan struct{})
	defer func() { <-done }()
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		_, err = c.Read(make([]byte, 1))
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Errorf("idle read error = %v, want a timeout", err)
		}
		_ = c.Close()
	}()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if !closedWithin(c, 2*time.Second) {
		t.Fatal("the server side did not close the idle connection")
	}
}

// A configured ring timeout longer than the default idle deadline raises it.
func TestInboundTCPIdleCoversALongRingTimeout(t *testing.T) {
	if got := inboundTCPIdle(60 * time.Second); got != inboundTCPIdleTimeout {
		t.Fatalf("default ring timeout: idle = %v, want %v", got, inboundTCPIdleTimeout)
	}
	long := 3 * time.Hour
	if got := inboundTCPIdle(long); got <= long {
		t.Fatalf("idle %v does not exceed a %v ring timeout", got, long)
	}
}

// stepClock is a fake listener clock: base plus an atomic offset, so the accept
// goroutine and the test goroutine share it race-free.
type stepClock struct {
	l   *capListener
	off atomic.Int64
}

func newStepClock(l *capListener) *stepClock {
	c := &stepClock{l: l}
	l.now = c.now
	return c
}

func (c *stepClock) now() time.Time       { return c.l.base.Add(time.Duration(c.off.Load())) }
func (c *stepClock) step(d time.Duration) { c.off.Add(int64(d)) }

// evictHarness runs an Accept loop and hands the accepted server conns out in
// order. Every wait is bounded.
type evictHarness struct {
	t        *testing.T
	l        *capListener
	addr     string
	clk      *stepClock
	accepted chan net.Conn
}

func newEvictHarness(t *testing.T, maxConns int, floor time.Duration) *evictHarness {
	t.Helper()
	l, addr := capPair(t, maxConns, time.Hour, floor)
	h := &evictHarness{t: t, l: l, addr: addr, clk: newStepClock(l), accepted: make(chan net.Conn, 16)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			h.accepted <- c
		}
	}()
	return h
}

// dialAccepted dials and waits for the listener to return the connection.
func (h *evictHarness) dialAccepted() (client, server net.Conn) {
	h.t.Helper()
	client, err := net.Dial("tcp", h.addr)
	if err != nil {
		h.t.Fatalf("dial: %v", err)
	}
	h.t.Cleanup(func() { _ = client.Close() })
	select {
	case server = <-h.accepted:
		return client, server
	case <-time.After(5 * time.Second):
		h.t.Fatal("the listener did not return the connection")
		return nil, nil
	}
}

// dialRefused dials and expects the listener to close the connection without
// returning it.
func (h *evictHarness) dialRefused() {
	h.t.Helper()
	c, err := net.Dial("tcp", h.addr)
	if err != nil {
		h.t.Fatalf("dial: %v", err)
	}
	h.t.Cleanup(func() { _ = c.Close() })
	if !closedWithin(c, 2*time.Second) {
		h.t.Fatal("the connection was not refused")
	}
	select {
	case <-h.accepted:
		h.t.Fatal("a refused connection was returned by Accept")
	default:
	}
}

func (h *evictHarness) requireOpen(c net.Conn, what string) {
	h.t.Helper()
	if closedWithin(c, 150*time.Millisecond) {
		h.t.Fatalf("%s was closed", what)
	}
}

func (h *evictHarness) requireEvicted(c net.Conn, what string) {
	h.t.Helper()
	if !closedWithin(c, 2*time.Second) {
		h.t.Fatalf("%s was not evicted", what)
	}
}

// Server-side WRITE activity protects a connection; the least recently active
// one is evicted even though it was accepted later.
func TestCapListenerEvictsTheLeastRecentlyActiveIdleConnection(t *testing.T) {
	h := newEvictHarness(t, 2, time.Second)
	cA, sA := h.dialAccepted()
	h.clk.step(10 * time.Millisecond)
	cB, _ := h.dialAccepted()
	h.clk.step(2 * time.Second)
	if _, err := sA.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	cC, _ := h.dialAccepted() // evicts B
	h.requireEvicted(cB, "B (least recently active)")
	buf := make([]byte, 1)
	_ = cA.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := cA.Read(buf); err != nil {
		t.Fatalf("A should have received its byte, not %v", err)
	}
	h.requireOpen(cA, "A")
	h.requireOpen(cC, "C")
}

// Server-side READ activity protects a connection too.
func TestCapListenerReadActivityProtectsAConnection(t *testing.T) {
	h := newEvictHarness(t, 2, time.Second)
	cA, sA := h.dialAccepted()
	h.clk.step(10 * time.Millisecond)
	cB, _ := h.dialAccepted()
	h.clk.step(2 * time.Second)
	if _, err := cA.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := sA.Read(make([]byte, 1)); err != nil {
		t.Fatalf("server read: %v", err)
	}
	cC, _ := h.dialAccepted()
	h.requireEvicted(cB, "B")
	h.requireOpen(cA, "A")
	h.requireOpen(cC, "C")
}

// Equal activity: the earliest accepted goes first (deterministic).
func TestCapListenerTieGoesToTheEarliestAccepted(t *testing.T) {
	h := newEvictHarness(t, 2, time.Second)
	cA, _ := h.dialAccepted()
	cB, _ := h.dialAccepted()
	h.clk.step(2 * time.Second)
	cC, _ := h.dialAccepted()
	h.requireEvicted(cA, "A (earliest accepted)")
	h.requireOpen(cB, "B")
	h.requireOpen(cC, "C")
}

// Nothing silent for the floor: refuse, as at baseline.
func TestCapListenerRefusesWhenNoConnectionIsIdleEnough(t *testing.T) {
	h := newEvictHarness(t, 2, time.Second)
	cA, _ := h.dialAccepted()
	cB, _ := h.dialAccepted()
	h.clk.step(500 * time.Millisecond)
	h.dialRefused()
	h.requireOpen(cA, "A")
	h.requireOpen(cB, "B")
}

// Two evictions in a row; closing an evicted connection again, and every
// connection concurrently from several goroutines, releases each slot exactly
// once (the slot count is checked, not inferred from admissions).
func TestCapListenerEvictsTwiceAndReleasesEachSlotOnce(t *testing.T) {
	h := newEvictHarness(t, 2, time.Second)
	cA, sA := h.dialAccepted()
	cB, sB := h.dialAccepted()
	h.clk.step(2 * time.Second)
	_, sC := h.dialAccepted() // evicts A
	h.requireEvicted(cA, "A")
	h.clk.step(2 * time.Second)
	_, sD := h.dialAccepted() // evicts B
	h.requireEvicted(cB, "B")
	if n := len(h.l.slots); n != 2 {
		t.Fatalf("%d slots held after two evictions, want 2", n)
	}

	// Closing the evicted A and B again must not free a slot.
	reclosed := make(chan struct{})
	go func() {
		defer close(reclosed)
		for _, c := range []net.Conn{sA, sA, sB, sB} {
			_ = c.Close()
		}
	}()
	select {
	case <-reclosed:
	case <-time.After(5 * time.Second):
		t.Fatal("re-closing the evicted conns hung (a second slot release)")
	}
	if n := len(h.l.slots); n != 2 {
		t.Fatalf("%d slots held after re-closing the evicted conns, want 2 (a double release)", n)
	}

	// Concurrent closes of the live conns (several goroutines each).
	var wg sync.WaitGroup
	for _, c := range []net.Conn{sC, sC, sC, sD, sD, sD} {
		wg.Add(1)
		go func() { defer wg.Done(); _ = c.Close() }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent closing hung")
	}
	if n := len(h.l.slots); n != 0 {
		t.Fatalf("%d slots held after closing everything, want 0", n)
	}
	h.l.mu.Lock()
	open := len(h.l.conns)
	h.l.mu.Unlock()
	if open != 0 {
		t.Fatalf("%d conns still in the set, want 0", open)
	}
	_, _ = h.dialAccepted()
	_, _ = h.dialAccepted()
	h.dialRefused()
}

func TestInboundTCPEvictIdleUsesTheEffectiveRingTimeout(t *testing.T) {
	for _, c := range []struct{ ring, want time.Duration }{
		{60 * time.Second, 92 * time.Second},
		{0, 92 * time.Second},
		{-5 * time.Second, 92 * time.Second},
		{120 * time.Second, 152 * time.Second},
	} {
		if got := inboundTCPEvictIdle(c.ring); got != c.want {
			t.Errorf("inboundTCPEvictIdle(%v) = %v, want %v", c.ring, got, c.want)
		}
	}
	for _, c := range []struct{ in, want time.Duration }{
		{0, DefaultInboundRingTimeout},
		{-time.Second, DefaultInboundRingTimeout},
		{30 * time.Second, 30 * time.Second},
	} {
		if got := effectiveInboundRingTimeout(c.in); got != c.want {
			t.Errorf("effectiveInboundRingTimeout(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
