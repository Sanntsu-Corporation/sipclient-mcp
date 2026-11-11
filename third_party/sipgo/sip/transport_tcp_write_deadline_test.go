package sip

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func setTimerBForTest(t *testing.T, d time.Duration) {
	t.Helper()
	old := Timer_B
	Timer_B = d
	t.Cleanup(func() { Timer_B = old })
}

func writeTestMsg(t *testing.T) Message {
	t.Helper()
	var uri Uri
	if err := ParseUri("sip:bob@127.0.0.1:5060", &uri); err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	return NewRequest(OPTIONS, uri)
}

// TestStreamWriteToAPeerThatNeverReadsIsBoundedByTimerB (CF-069 d): a write to a
// peer that never reads fails with a deadline error after Timer_B and closes the
// connection (a partial write has corrupted the stream framing).
func TestStreamWriteToAPeerThatNeverReadsIsBoundedByTimerB(t *testing.T) {
	setTimerBForTest(t, 200*time.Millisecond)
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	c := &TCPConnection{Conn: a}

	done := make(chan error, 1)
	go func() { done <- c.WriteMsg(writeTestMsg(t)) }()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("WriteMsg error = %v, want it to wrap os.ErrDeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WriteMsg to a peer that never reads did not return")
	}
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := b.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("peer read after the deadline = %v, want io.EOF (the connection was not closed)", err)
	}
}

// TestStreamWriteDeadlineIsRefreshedPerWrite guards the per-write rule: a write
// after an old deadline has passed still succeeds on a healthy connection.
func TestStreamWriteDeadlineIsRefreshedPerWrite(t *testing.T) {
	setTimerBForTest(t, 200*time.Millisecond)
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	go func() { _, _ = io.Copy(io.Discard, b) }()
	c := &TCPConnection{Conn: a}

	if err := c.WriteMsg(writeTestMsg(t)); err != nil {
		t.Fatalf("first write: %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	if err := c.WriteMsg(writeTestMsg(t)); err != nil {
		t.Fatalf("second write after the first deadline passed: %v", err)
	}
}

// TestTwoBlockedWritersAreBothBoundedByTimerB: a second writer must not move the
// deadline of a first write that is already blocked.
func TestTwoBlockedWritersAreBothBoundedByTimerB(t *testing.T) {
	// A second writer that moved the deadline would end the first at ~1.5*tb;
	// tb is large enough that the 1.25*tb bound leaves 250 ms of slack each side.
	const tb = time.Second
	setTimerBForTest(t, tb)
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	c := &TCPConnection{Conn: a}

	type result struct {
		err error
		d   time.Duration
	}
	start := time.Now()
	first := make(chan result, 1)
	second := make(chan result, 1)
	go func() { err := c.WriteMsg(writeTestMsg(t)); first <- result{err, time.Since(start)} }()
	time.Sleep(tb / 2)
	start2 := time.Now()
	go func() { err := c.WriteMsg(writeTestMsg(t)); second <- result{err, time.Since(start2)} }()

	var r1 result
	select {
	case r1 = <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("first writer did not return")
	}
	if !errors.Is(r1.err, os.ErrDeadlineExceeded) {
		t.Fatalf("first writer error = %v, want it to wrap os.ErrDeadlineExceeded", r1.err)
	}
	if r1.d > tb*5/4 {
		t.Fatalf("first writer returned after %v, want within %v (a second writer moved its deadline)", r1.d, tb*5/4)
	}
	select {
	case r2 := <-second:
		if r2.err == nil {
			t.Fatal("second writer succeeded against a peer that never reads")
		}
		if r2.d > 3*tb {
			t.Fatalf("second writer returned after %v, want within %v", r2.d, 3*tb)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second writer did not return")
	}
}

// partialConn is a controlled stream: its first Write blocks until released,
// then reports a partial write and a deadline error. Close waits briefly for a
// second Write to start, so a writer that gets the stream between the timed-out
// write and its Close is caught deterministically.
type partialConn struct {
	net.Conn // addresses only

	mu           sync.Mutex
	writes       int
	closed       bool
	wroteOnto    bool // a later write was accepted onto the stream before Close
	inFirst      chan struct{}
	releaseFirst chan struct{}
	secondWrite  chan struct{}
}

func (c *partialConn) SetWriteDeadline(time.Time) error { return nil }

func (c *partialConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	k, closed := c.writes, c.closed
	c.mu.Unlock()
	if k == 1 {
		close(c.inFirst)
		<-c.releaseFirst
		return len(b) / 2, os.ErrDeadlineExceeded
	}
	if k == 2 {
		close(c.secondWrite)
	}
	if closed {
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	c.wroteOnto = true
	c.mu.Unlock()
	return len(b), nil
}

func (c *partialConn) Close() error {
	select {
	case <-c.secondWrite:
	case <-time.After(300 * time.Millisecond):
	}
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Conn.Close()
}

// TestAQueuedWriterNeverWritesAfterATimedOutPartialWrite (CF-069 d): a writer
// queued behind a write that timed out part-way must not append its bytes to
// the corrupted stream; the timed-out connection is closed before writeMu is
// released.
func TestAQueuedWriterNeverWritesAfterATimedOutPartialWrite(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	pc := &partialConn{Conn: a, inFirst: make(chan struct{}), releaseFirst: make(chan struct{}), secondWrite: make(chan struct{})}
	c := &TCPConnection{Conn: pc}

	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- c.WriteMsg(writeTestMsg(t)) }()
	<-pc.inFirst
	go func() { second <- c.WriteMsg(writeTestMsg(t)) }()
	time.Sleep(100 * time.Millisecond) // the second writer is queued on writeMu
	close(pc.releaseFirst)

	for i, ch := range []chan error{first, second} {
		select {
		case err := <-ch:
			if err == nil {
				t.Fatalf("writer %d succeeded on a stream left partial by a timed-out write", i+1)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("writer %d did not return", i+1)
		}
	}
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.wroteOnto {
		t.Fatal("a queued writer's bytes were accepted after the partial write, before the connection was closed")
	}
}
