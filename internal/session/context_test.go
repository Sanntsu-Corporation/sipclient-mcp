package session

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// TestClientDisconnectDoesNotCancelCall protects locked decision 17, D11 point
// 5 and R8. The call's duration-cap timer hangs off the DAEMON context; the
// tool call that created it carries a REQUEST context. Cancelling the request
// context — a dropped client connection — must leave the call live and its
// timer armed.
func TestClientDisconnectDoesNotCancelCall(t *testing.T) {
	m, fc := newTestManager(t)

	reqCtx, dropClient := context.WithCancel(context.Background())
	if err := m.Open(reqCtx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(reqCtx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	c, err := m.CreateCall(reqCtx, "s1", ua.Handle(), Outbound, StateAnswered)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}

	fired := make(chan struct{})
	m.StartDurationCap(c, 300*time.Second, func() { close(fired) })
	fc.BlockUntil(1)

	// The client goes away mid-call.
	dropClient()

	// The call must be unaffected: still live, still resolvable, timer armed.
	if got := c.State(); got != StateAnswered {
		t.Fatalf("state after client disconnect = %q, want %q", got, StateAnswered)
	}
	if _, err := m.ResolveCall(context.Background(), "s1", c.Handle()); err != nil {
		t.Fatalf("resolve after client disconnect: %v", err)
	}
	select {
	case <-fired:
		t.Fatal("duration cap fired early")
	default:
	}

	fc.Advance(300 * time.Second)
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("duration cap never fired: the call's timer was bound to the request " +
			"context, not the daemon context (locked decision 17)")
	}
}

// TestDaemonShutdownStopsCallGoroutines is the symmetric half: the daemon
// context, and only it, tears the call goroutine down.
func TestDaemonShutdownStopsCallGoroutines(t *testing.T) {
	fc := fakeclock.New(time.Unix(1_700_000_000, 0))
	daemonCtx, stopDaemon := context.WithCancel(context.Background())
	m, err := NewManager(ManagerConfig{
		Ctx:    daemonCtx,
		Clock:  fc,
		Policy: newTestStore(t, fc, nil),
		Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) {
			return nopAgent{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}

	done := make(chan struct{})
	m.StartDurationCap(c, 300*time.Second, func() { close(done) })
	fc.BlockUntil(1)

	stopDaemon()
	select {
	case <-done:
		t.Fatal("callback ran on daemon shutdown; the cap must simply stop")
	case <-time.After(100 * time.Millisecond):
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.DurationCapGoroutinesForTest() == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%d duration-cap goroutines still running after daemon shutdown, want 0",
		m.DurationCapGoroutinesForTest())
}
