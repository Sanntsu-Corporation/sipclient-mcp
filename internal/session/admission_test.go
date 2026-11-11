package session

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// inboundEvent builds the protocol-level UAEvent sipua hands to the admit
// channel for an inbound INVITE (I2). The direction is Inbound and the kind is
// UAEventInbound, exactly as (*UA).onInvite constructs it before calling admit.
func inboundEvent(callID string) UAEvent {
	return UAEvent{
		Kind:          UAEventInbound,
		DialogID:      "dlg-" + callID,
		CallID:        callID,
		Direction:     Inbound,
		FromURI:       "sip:caller@203.0.113.21",
		ToURI:         "sip:me@203.0.113.1",
		OfferedCodecs: []string{"PCMU"},
		At:            time.Unix(1_700_000_000, 0),
	}
}

// TestAdmit_RejectsOverConcurrencyCap is I2's load-bearing assertion: the
// session decides accept/reject BEFORE sipua rings. Under the cap the verdict
// is Accept; over it (per-session OR total) the verdict is Reject 486 Busy Here
// (Rule 6a D2 flat mapping), and no Call is created.
func TestAdmit_RejectsOverConcurrencyCap(t *testing.T) {
	m, _ := newManagerWith(t, func(l *policy.Limits) {
		l.MaxConcurrentCallsTotal = 1
		l.MaxConcurrentCallsPerSession = 1
	})
	ctx := context.Background()
	uas := setupSessions(t, m, "s1")

	// First inbound fills the one slot: admitted.
	if v := m.admitInbound(ctx, uas["s1"], inboundEvent("call-1")); !v.Accept {
		t.Fatalf("first inbound verdict = %+v, want Accept under the cap", v)
	}
	// Second inbound is over the cap: rejected 486, and no Call is created.
	v := m.admitInbound(ctx, uas["s1"], inboundEvent("call-2"))
	if v.Accept || v.Status != 486 {
		t.Fatalf("second inbound verdict = %+v, want Reject 486 Busy Here", v)
	}
	if perSession, total := m.DebugLiveCallCounts("s1"); perSession != 1 || total != 1 {
		t.Fatalf("live call counts = (%d, %d), want (1, 1): a rejected admission must not create a Call", perSession, total)
	}
}

// TestAdmit_RejectsDuringShutdown503 pins the other half of Rule 6a D2: a
// CreateCall denied because the server is refusing (§11.4 shutdown) maps to
// 503 Service Unavailable, NOT 486. The classifier keys on apierr.Error.Rule
// == "shutdown".
func TestAdmit_RejectsDuringShutdown503(t *testing.T) {
	m, _ := newManagerWith(t, nil)
	ctx := context.Background()
	uas := setupSessions(t, m, "s1")

	m.RefuseNewDials() // §11.4 step 2: checkConcurrencyLocked now denies with Rule "shutdown"

	v := m.admitInbound(ctx, uas["s1"], inboundEvent("call-x"))
	if v.Accept || v.Status != 503 {
		t.Fatalf("inbound during shutdown verdict = %+v, want Reject 503 Service Unavailable", v)
	}
}

// TestAdmit_LockOrderDoesNotHoldRegistryLockAcrossCallback is I2's §6.0b
// lock-order gate: admitInbound must acquire m.mu ITSELF (via CreateCall) and
// must never be entered while the caller already holds m.mu — the UA calls the
// admit handler OUTSIDE its own registry lock, so the two locks never nest.
//
// The test holds m.mu, then drives the admit path from another goroutine. If
// admitInbound erroneously assumed the caller held m.mu (or did not take it at
// all), the callback would complete while we hold the lock; because it takes
// m.mu itself, the callback blocks until we release, then completes with no
// deadlock. Run under -race.
func TestAdmit_LockOrderDoesNotHoldRegistryLockAcrossCallback(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	agent := &probeAgent{}
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Logger: testLogger(),
		Policy: newTestStore(t, fc, func(l *policy.Limits) {
			l.MaxConcurrentCallsTotal = 10
			l.MaxConcurrentCallsPerSession = 10
		}),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP}); err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	done := make(chan Admission, 1)
	m.mu.Lock()
	go func() { done <- agent.admit(inboundEvent("cid-lock")) }()

	select {
	case <-done:
		m.mu.Unlock()
		t.Fatal("admit completed while the test held m.mu: admitInbound must take m.mu " +
			"itself via CreateCall, so it cannot have completed under the held lock")
	case <-time.After(100 * time.Millisecond):
		// Expected: the callback is blocked on CreateCall's m.mu.Lock.
	}
	m.mu.Unlock()

	select {
	case v := <-done:
		if !v.Accept {
			t.Fatalf("verdict = %+v, want Accept once m.mu was released", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DEADLOCK: admitInbound never completed after m.mu was released")
	}
}

// TestAdmitProbe_ReportsTheInviteVerdictAndAdmitsNothing is the OPTIONS probe
// (RFC 3261 11, owner ruling D-3): under the cap it accepts, at the cap it
// answers the verdict an INVITE would get (486), during shutdown 503, and in no
// case does it create a Call or append an event.
func TestAdmitProbe_ReportsTheInviteVerdictAndAdmitsNothing(t *testing.T) {
	m, _ := newManagerWith(t, func(l *policy.Limits) {
		l.MaxConcurrentCallsTotal = 1
		l.MaxConcurrentCallsPerSession = 1
	})
	ctx := context.Background()
	uas := setupSessions(t, m, "s1")
	probe := func() Admission {
		ev := inboundEvent("probe")
		ev.AdmitProbe = true
		return m.admitInbound(ctx, uas["s1"], ev)
	}

	if v := probe(); !v.Accept {
		t.Fatalf("probe under the cap = %+v, want Accept", v)
	}
	if perSession, total := m.DebugLiveCallCounts("s1"); perSession != 0 || total != 0 {
		t.Fatalf("live calls after an accepted probe = (%d, %d), want (0, 0): a probe admits nothing", perSession, total)
	}
	if v := m.admitInbound(ctx, uas["s1"], inboundEvent("call-1")); !v.Accept {
		t.Fatalf("first inbound = %+v", v)
	}
	if v := probe(); v.Accept || v.Status != 486 {
		t.Fatalf("probe at the cap = %+v, want Reject 486", v)
	}
	m.RefuseNewDials()
	if v := probe(); v.Accept || v.Status != 503 {
		t.Fatalf("probe during shutdown = %+v, want Reject 503", v)
	}
	if perSession, total := m.DebugLiveCallCounts("s1"); perSession != 1 || total != 1 {
		t.Fatalf("live calls = (%d, %d), want (1, 1)", perSession, total)
	}
}
