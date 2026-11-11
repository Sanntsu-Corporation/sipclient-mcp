package sipua

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	sippeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// This file is C14/C11's mutation proof: three of runDial's pre-answer
// branches (transport fault, non-2xx final response, ACK write failure) used
// to hand-roll `u.setPhase(d, phaseDone); u.forget(d.id)` — two SEPARATE
// u.calls.mu critical sections — instead of calling the already-existing
// teardownDialog helper, which does both in ONE. The gap between those two
// critical sections is exactly what C11 names: a window in which a concurrent
// reader could observe d.phase == phaseDone while the dialog was still
// present in the registry. It is an in-package (white-box) test file because
// asserting on d.phase and the registry map directly is unexported.

// teardownEventCollector is a minimal OnEvent recorder for these
// outbound-only tests (no OnAdmit needed — nothing here is inbound).
func teardownEventCollector(t *testing.T, u *UA) func() []session.UAEvent {
	t.Helper()
	var mu sync.Mutex
	var got []session.UAEvent
	u.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})
	return func() []session.UAEvent {
		mu.Lock()
		defer mu.Unlock()
		out := make([]session.UAEvent, len(got))
		copy(out, got)
		return out
	}
}

// pollPhaseRegistryAtomicity spins a background goroutine that repeatedly
// reads d.phase and the registry's presence for d.id under ONE u.calls.mu
// acquisition, and reports (via the returned *atomic.Bool) whether it ever
// observed phase == phaseDone while d.id was STILL in the registry. Call the
// returned stop func once the dialog's terminal event has been observed.
//
// This is only capable of catching the pre-fix gap because the poller reads
// BOTH facts together — if the production code sets them in two separate
// critical sections, the poller's own lock acquisition can land in the window
// between them; if production sets them in one critical section (the fix),
// that window has zero width and no amount of polling can ever observe it.
func pollPhaseRegistryAtomicity(u *UA, d *dialog) (raced *atomic.Bool, stop func()) {
	raced = &atomic.Bool{}
	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			u.calls.mu.Lock()
			phase := d.phase
			_, stillRegistered := u.calls.byID[d.id]
			u.calls.mu.Unlock()
			if phase == phaseDone && stillRegistered {
				raced.Store(true)
			}
			runtime.Gosched()
		}
	}()
	return raced, func() {
		close(stopCh)
		wg.Wait()
	}
}

// assertMediaConnClosed confirms conn was actually closed (not merely
// unreferenced) by observing a net.ErrClosed on a read.
func assertMediaConnClosed(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	if conn == nil {
		return
	}
	_, _, err := conn.ReadFromUDP(make([]byte, 1))
	if !strings.Contains(fmt.Sprint(err), "use of closed network connection") {
		t.Fatalf("media conn read after teardown: got %v, want use of closed network connection", err)
	}
}

func newTeardownTestUA(t *testing.T, wrapConn func(net.PacketConn) net.PacketConn) *UA {
	t.Helper()
	cfg := Config{
		Transport:          "udp",
		Mode:               "direct",
		AOR:                "sip:alice@example",
		ExpiresS:           300,
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              fakeclock.New(time.Unix(0, 0)),
		LocalAddr:          "127.0.0.1:0",
	}
	if wrapConn != nil {
		cfg.WrapConn = wrapConn
	}
	u, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = u.Close(context.Background()) })
	return u
}

// TestRunDialTransportFaultTeardownIsAtomic drives call.go's "no response at
// all" branch (C14 site 1).
func TestRunDialTransportFaultTeardownIsAtomic(t *testing.T) {
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := dead.LocalAddr().String()
	_ = dead.Close()

	u := newTeardownTestUA(t, nil)
	events := teardownEventCollector(t, u)

	res, err := u.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + addr})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	d, err := u.lookup(res.DialogID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	conn := d.mediaConn

	raced, stop := pollPhaseRegistryAtomicity(u, d)
	deadline := time.After(3 * time.Second)
	var final *session.UAEvent
waitLoop:
	for {
		for _, ev := range events() {
			if ev.DialogID == res.DialogID && ev.Kind == session.UAEventDialogEnded {
				e := ev
				final = &e
				break waitLoop
			}
		}
		select {
		case <-deadline:
			stop()
			t.Fatal("no UAEventDialogEnded within 3s")
		case <-time.After(2 * time.Millisecond):
		}
	}
	stop()

	if raced.Load() {
		t.Fatal("observed d.phase == phaseDone while the dialog was still registered (C11)")
	}
	u.calls.mu.Lock()
	phase := d.phase
	u.calls.mu.Unlock()
	if phase != phaseDone {
		t.Fatalf("phase=%v want phaseDone", phase)
	}
	if u.RegisteredDialogCount() != 0 {
		t.Fatal("dialog still registered after teardown")
	}
	assertMediaConnClosed(t, conn)

	n := 0
	for _, ev := range events() {
		if ev.DialogID == res.DialogID && ev.Kind == session.UAEventDialogEnded {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("UAEventDialogEnded fired %d times, want exactly 1", n)
	}
	_ = final
}

// TestRunDialNon2xxFinalTeardownIsAtomic drives call.go's non-2xx final
// response branch (C14 site 2): the peer rejects with 486.
func TestRunDialNon2xxFinalTeardownIsAtomic(t *testing.T) {
	// The peer holds its 486 until the test has read d.mediaConn: teardownDialog
	// clears that field under u.calls.mu, so a 486 that raced ahead of the read
	// (CPU-starved box) made both the lookup and the unlocked read flaky (CF-044).
	hold := make(chan struct{})
	p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0", Behaviour: sippeer.Behaviour{RejectStatus: 486, HoldProvisionals: hold}})
	u := newTeardownTestUA(t, nil)
	events := teardownEventCollector(t, u)

	res, err := u.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	d, err := u.lookup(res.DialogID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	u.calls.mu.Lock()
	conn := d.mediaConn
	u.calls.mu.Unlock()
	close(hold)

	raced, stop := pollPhaseRegistryAtomicity(u, d)
	deadline := time.After(3 * time.Second)
waitLoop:
	for {
		for _, ev := range events() {
			if ev.DialogID == res.DialogID && ev.Kind == session.UAEventFinal {
				break waitLoop
			}
		}
		select {
		case <-deadline:
			stop()
			t.Fatal("no UAEventFinal within 3s")
		case <-time.After(2 * time.Millisecond):
		}
	}
	stop()

	if raced.Load() {
		t.Fatal("observed d.phase == phaseDone while the dialog was still registered (C11)")
	}
	u.calls.mu.Lock()
	phase := d.phase
	u.calls.mu.Unlock()
	if phase != phaseDone {
		t.Fatalf("phase=%v want phaseDone", phase)
	}
	if u.RegisteredDialogCount() != 0 {
		t.Fatal("dialog still registered after teardown")
	}
	assertMediaConnClosed(t, conn)

	n := 0
	for _, ev := range events() {
		if ev.DialogID == res.DialogID && ev.Kind == session.UAEventFinal {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("UAEventFinal fired %d times, want exactly 1", n)
	}
}

// ackFailPacketConn makes exactly ONE outbound ACK write fail, letting every
// other datagram through unchanged — the same one-shot technique
// call_dial_media_leak_test.go's ackFailConn (package sipua_test) uses, kept
// separate and local (Rule 15/18: neither test package can see the other's
// unexported helpers, and this file needs no more than the raw "ACK " prefix
// check, not that file's firstLine parse).
type ackFailPacketConn struct {
	net.PacketConn
	fired atomic.Bool
}

func (c *ackFailPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if strings.HasPrefix(string(b), "ACK ") && c.fired.CompareAndSwap(false, true) {
		return 0, fmt.Errorf("injected ack write failure")
	}
	return c.PacketConn.WriteTo(b, addr)
}

// TestRunDialACKSendFailureTeardownIsAtomic drives call.go's mandatory-ACK
// write failure branch (C14 site 3) — the only one of the three reached AFTER
// d.phase has already been set to phaseAnswering and d.sessionTimer built
// (still unarmed), the case the brief singles out for extra scrutiny.
func TestRunDialACKSendFailureTeardownIsAtomic(t *testing.T) {
	p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0"})
	var fc *ackFailPacketConn
	u := newTeardownTestUA(t, func(pc net.PacketConn) net.PacketConn {
		fc = &ackFailPacketConn{PacketConn: pc}
		return fc
	})
	_ = fc
	events := teardownEventCollector(t, u)

	res, err := u.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	d, err := u.lookup(res.DialogID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	conn := d.mediaConn

	raced, stop := pollPhaseRegistryAtomicity(u, d)
	deadline := time.After(3 * time.Second)
waitLoop:
	for {
		for _, ev := range events() {
			if ev.DialogID == res.DialogID && ev.Kind == session.UAEventDialogEnded {
				break waitLoop
			}
		}
		select {
		case <-deadline:
			stop()
			t.Fatal("no UAEventDialogEnded within 3s")
		case <-time.After(2 * time.Millisecond):
		}
	}
	stop()

	if raced.Load() {
		t.Fatal("observed d.phase == phaseDone while the dialog was still registered (C11)")
	}
	u.calls.mu.Lock()
	phase := d.phase
	u.calls.mu.Unlock()
	if phase != phaseDone {
		t.Fatalf("phase=%v want phaseDone", phase)
	}
	if u.RegisteredDialogCount() != 0 {
		t.Fatal("dialog still registered after teardown")
	}
	assertMediaConnClosed(t, conn)

	n := 0
	var reason string
	for _, ev := range events() {
		if ev.DialogID == res.DialogID && ev.Kind == session.UAEventDialogEnded {
			n++
			reason = ev.Reason
		}
	}
	if n != 1 {
		t.Fatalf("UAEventDialogEnded fired %d times, want exactly 1", n)
	}
	if !strings.Contains(reason, "ack send") {
		t.Fatalf("reason=%q want it to contain %q", reason, "ack send")
	}
}
