package sipua_test

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// syncBuf is a goroutine-safe buffer a UA's slog handler can write to.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// newLoggedUA is a direct-mode UA (Timeout 5s) whose slog output is captured, so
// a test can assert the Warn a failed dial's teardown logs. mod, when non-nil,
// adjusts the Config before New (credentials, WrapConn, Timeout, media range).
func newLoggedUA(t *testing.T, mod func(*sipua.Config)) (*sipua.UA, *syncBuf) {
	t.Helper()
	buf := &syncBuf{}
	cfg := sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 5 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		MediaPortRange: [2]int{16384, 32767},
		Logger:         slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if mod != nil {
		mod(&cfg)
	}
	ua, err := sipua.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() {
		_ = ua.Close(context.Background())
		// Close cancels every dial; wait for their runDial goroutines to release
		// their dialogs so none is still running (and reading a package-level
		// test seam such as failedDialHook) when the next test sets it.
		deadline := time.Now().Add(5 * time.Second)
		for ua.RegisteredDialogCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
	})
	return ua, buf
}

// closedUDPAddr is a loopback host:port nothing listens on: a dial to it draws
// no response of any kind.
func closedUDPAddr(t *testing.T) string {
	t.Helper()
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := dead.LocalAddr().String()
	_ = dead.Close()
	return addr
}

// failedDialLog is the captured Warn line(s) endFailedDial logged.
func failedDialLog(logs *syncBuf) string {
	var out []string
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "dial ended without a usable final response") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// dialogEvents returns the events for one dialog, in order.
func dialogEvents(events func() []session.UAEvent, dialogID string) []session.UAEvent {
	var out []session.UAEvent
	for _, ev := range events() {
		if ev.DialogID == dialogID {
			out = append(out, ev)
		}
	}
	return out
}

// assertNoDialogEnd fails when the dialog drew a dialog-ended or transport-fault
// event.
func assertNoDialogEnd(t *testing.T, events func() []session.UAEvent, dialogID string) {
	t.Helper()
	for _, ev := range dialogEvents(events, dialogID) {
		if ev.Kind == session.UAEventDialogEnded || ev.Kind == session.UAEventTransportFault {
			t.Fatalf("a hung-up dial emitted %q (cause %q) for its dialog; want nothing: %v",
				ev.Kind, ev.Cause, kinds(dialogEvents(events, dialogID)))
		}
	}
}

// countDialogEnded counts the UAEventDialogEnded{UACauseTransportFailure} events
// for one dialog.
func countDialogEnded(events func() []session.UAEvent, dialogID string) int {
	n := 0
	for _, ev := range dialogEvents(events, dialogID) {
		if ev.Kind == session.UAEventDialogEnded && ev.Cause == session.UACauseTransportFailure {
			n++
		}
	}
	return n
}

// The timeout/hangup linearization point is teardownDialog's critical section.
// Order 1 (hook, no sleeps): a Hangup that reaches sipua immediately before the
// teardown wins, so the dial's dialog-scoped end is suppressed. Order 2: the
// teardown first, then the Hangup is refused not_found and exactly one end was
// emitted.
func TestHangupJustBeforeTheFailedDialTeardownSuppressesTheEnd(t *testing.T) {
	t.Run("hangup_first", func(t *testing.T) {
		t.Cleanup(sipua.SetOutboundRingBudget(300 * time.Millisecond))
		p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RingThenSilent: true}})
		t.Cleanup(func() { sipua.SetFailedDialHook(nil) }) // before the UA: runs after its drain
		ua, logs := newLoggedUA(t, nil)
		events := collect(t, ua)

		var dialogID atomic.Value
		hookErr := make(chan error, 1)
		sipua.SetFailedDialHook(func() {
			id, _ := dialogID.Load().(string)
			hookErr <- ua.Hangup(context.Background(), id, "")
		})

		res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		dialogID.Store(res.DialogID)

		select {
		case err := <-hookErr:
			if err != nil {
				t.Fatalf("Hangup from the hook = %v, want nil", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the failed-dial hook never ran")
		}
		waitDialogsReaped(t, ua, 2*time.Second)
		waitPeerCount(t, p, "CANCEL", 1) // written before Hangup returned, but delivery is async
		time.Sleep(100 * time.Millisecond)
		if n := p.Count("CANCEL"); n != 1 {
			t.Fatalf("peer received %d CANCEL, want exactly 1", n)
		}
		// The Warn is logged BEFORE the emit decision: wait for it first, so the
		// nothing-was-emitted check below runs after the point where a wrongly
		// emitted end would already have been sent.
		if line := waitFailedDialLog(t, logs); !strings.Contains(line, "ring timeout") {
			t.Fatalf("captured Warn lacks the dial's ring-timeout reason: %q", line)
		}
		assertNoDialogEnd(t, events, res.DialogID)
	})

	t.Run("teardown_first", func(t *testing.T) {
		t.Cleanup(sipua.SetOutboundRingBudget(300 * time.Millisecond))
		p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RingThenSilent: true}})
		ua, _ := newLoggedUA(t, nil)
		events := collect(t, ua)

		res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		waitForDialog(t, events, res.DialogID, session.UAEventDialogEnded, 0)

		err = ua.Hangup(context.Background(), res.DialogID, "")
		if code := apierr.CodeOf(err); code != apierr.CodeNotFound {
			t.Fatalf("Hangup after the teardown = %v (code %v), want not_found", err, code)
		}
		if n := countDialogEnded(events, res.DialogID); n != 1 {
			t.Fatalf("%d dialog-ended events for the dialog, want exactly 1", n)
		}
		if n := p.Count("CANCEL"); n != 0 {
			t.Fatalf("peer received %d CANCEL, want 0 (the dial had already ended)", n)
		}
	})
}

// A dial timeout ends only that dialog: an answered sibling on the same UA stays
// registered with its media socket open, and only the timed-out dialog is gone.
func TestDialTimeoutLeavesTheSiblingDialogAndMediaUp(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	// 1000 ms sits between sipgo's Timer A retransmits (500 ms, 1500 ms): a dial
	// timeout that coincided with one used to panic vendored sipgo (CF-050, guarded
	// since: see TestDialTimeoutOnATimerAInstantDoesNotPanic); the 1000 ms choice stays.
	ua, _ := newLoggedUA(t, func(c *sipua.Config) { c.Timeout = 1000 * time.Millisecond })
	events := collect(t, ua)

	a, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial A: %v", err)
	}
	waitForDialog(t, events, a.DialogID, session.UAEventFinal, 200)
	b, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + closedUDPAddr(t)})
	if err != nil {
		t.Fatalf("Dial B: %v", err)
	}
	waitForDialog(t, events, b.DialogID, session.UAEventDialogEnded, 0)

	if !sipua.DialogMediaConnOpenForTest(ua, a.DialogID) {
		t.Fatal("the answered sibling's dialog or media socket was released by the other dial's timeout")
	}
	if n := ua.RegisteredDialogCount(); n != 1 {
		t.Fatalf("RegisteredDialogCount = %d, want 1 (only the answered sibling)", n)
	}
	if err := ua.Hangup(context.Background(), a.DialogID, ""); err != nil {
		t.Fatalf("Hangup A: %v", err)
	}
}

// After a hangup sends the CANCEL, a far end that never finalises is reaped at
// the post-CANCEL wait. The caller already ended the call, so the reap emits
// nothing; the Warn log names the post-CANCEL wait.
func TestDialTimeoutAfterHangupEmitsNothing(t *testing.T) {
	t.Cleanup(sipua.SetOutboundRingBudget(30 * time.Second))
	t.Cleanup(sipua.SetPostCancelWait(300 * time.Millisecond))
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RingThenSilent: true}})
	ua, logs := newLoggedUA(t, nil)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventProvisional, 180)
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	waitPeerCount(t, p, "CANCEL", 1)
	waitDialogsReaped(t, ua, 2*time.Second)
	assertLoggedPostCancelWait(t, logs) // the Warn precedes any emit
	time.Sleep(100 * time.Millisecond)

	assertNoDialogEnd(t, events, res.DialogID)
}

// waitFailedDialLog polls for the failed-dial Warn (logged after the dialog is
// forgotten and before any event is emitted) and returns it.
func waitFailedDialLog(t *testing.T, logs *syncBuf) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if line := failedDialLog(logs); line != "" {
			return line
		}
		if time.Now().After(deadline) {
			t.Fatalf("no failed-dial Warn logged within 2s:\n%s", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// assertLoggedPostCancelWait asserts the failed-dial Warn names the post-CANCEL
// wait, not a ring timeout: the distinction the reap tests used to read from the
// transport fault's Err.
func assertLoggedPostCancelWait(t *testing.T, logs *syncBuf) {
	t.Helper()
	line := waitFailedDialLog(t, logs)
	if !strings.Contains(line, "following CANCEL") || strings.Contains(line, "ring timeout") {
		t.Fatalf("captured Warn does not name the post-CANCEL wait (and not a ring timeout): %q", line)
	}
}

// The mandatory ACK write failing after a 2xx ends the dial with the same
// dialog-scoped end, reason "ack send: ...", and no UA-wide fault.
func TestACKSendFailureEmitsADialogScopedEnd(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newLoggedUA(t, func(c *sipua.Config) {
		c.WrapConn = func(pc net.PacketConn) net.PacketConn { return &ackFailConn{PacketConn: pc} }
	})
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	assertDialogScopedEnd(t, waitForDialog(t, events, res.DialogID, session.UAEventDialogEnded, 0), res.DialogID)
	ev := dialogEvents(events, res.DialogID)
	for _, e := range ev {
		if e.Kind == session.UAEventTransportFault {
			t.Fatalf("ACK write failure emitted a UA-wide transport fault: %v", kinds(ev))
		}
		if e.Kind == session.UAEventDialogEnded && !strings.HasPrefix(e.Reason, "ack send: ") {
			t.Fatalf("Reason = %q, want the %q prefix", e.Reason, "ack send: ")
		}
	}
}

// assertDialogScopedEnd checks the shape endFailedDial emits: a
// transport_failure dialog end carrying the error and no code or detail.
func assertDialogScopedEnd(t *testing.T, ev session.UAEvent, dialogID string) {
	t.Helper()
	if ev.Cause != session.UACauseTransportFailure {
		t.Errorf("Cause = %q, want %q", ev.Cause, session.UACauseTransportFailure)
	}
	if ev.DialogID != dialogID {
		t.Errorf("DialogID = %q, want %q", ev.DialogID, dialogID)
	}
	if ev.Direction != session.Outbound {
		t.Errorf("Direction = %q, want %q", ev.Direction, session.Outbound)
	}
	if ev.Err == nil {
		t.Error("the end carries no Err; session cannot report why the call ended")
	}
	if ev.Code != 0 {
		t.Errorf("Code = %d, want 0 (no response was received)", ev.Code)
	}
	if ev.Detail != nil {
		t.Errorf("Detail = %v, want nil (a detail would change the call's observable call_events)", ev.Detail)
	}
}
