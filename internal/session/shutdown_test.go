package session

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// TestRefuseNewDials is §11.4 step 2. After it is called, every subsequent
// CreateCall returns resource_limit — §11.2's exact code for "call_dial refused
// during graceful shutdown".
func TestRefuseNewDials(t *testing.T) {
	m, _ := newTestManager(t)
	uas := setupSessions(t, m, "s1")

	if _, err := dial(t, m, "s1", uas["s1"]); err != nil {
		t.Fatalf("dial before shutdown: %v", err)
	}
	m.RefuseNewDials()
	_, err := dial(t, m, "s1", uas["s1"])
	assertCode(t, err, apierr.CodeResourceLimit)

	// It is IDEMPOTENT and IRREVERSIBLE: there is no ResumeDials, because a
	// daemon that has begun shutting down never accepts work again.
	m.RefuseNewDials()
	_, err = dial(t, m, "s1", uas["s1"])
	assertCode(t, err, apierr.CodeResourceLimit)
}

// TestHangupAllLiveBoundedByGrace is §11.4's BYE pass. A far end that never
// answers must not extend shutdown past the grace period — that is the whole
// reason the period is configurable (U12).
func TestHangupAllLiveBoundedByGrace(t *testing.T) {
	agent := newBlockingAgent() // its Hangup never returns unless released
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, nil), Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	for i := 0; i < 3; i++ {
		c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
		if err != nil {
			t.Fatalf("CreateCall %d: %v", i, err)
		}
		c.setDialogIdentity("dlg", "callid")
	}

	done := make(chan struct{})
	var byeSent, confirmed int
	go func() {
		defer close(done)
		byeSent, confirmed = m.HangupAllLive(context.Background(), 100*time.Millisecond)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("HangupAllLive did not return within the grace period — a far end that " +
			"never answers must not extend shutdown indefinitely (§11.4)")
	}
	if byeSent != 3 {
		t.Errorf("byeSent = %d, want 3 (one per live dialog)", byeSent)
	}
	if confirmed != 0 {
		t.Errorf("confirmed = %d, want 0 (the peer swallowed every BYE)", confirmed)
	}

	// Every call carries local_hangup — §10.3's enum gains no shutdown value.
	// THE LENGTH CHECK MATTERS: without it, the loop below asserts nothing at
	// all if terminatedCalls is empty, which passes even on a build that
	// never recorded any of the three calls' termination.
	if got := len(m.session("s1").terminatedCalls); got != 3 {
		t.Fatalf("terminatedCalls = %d, want 3 (one per live dialog HangupAllLive hung up)", got)
	}
	for _, c := range m.session("s1").terminatedCalls {
		if got := c.TerminationReason(); got != "local_hangup" {
			t.Errorf("termination_reason = %q, want local_hangup (§11.4)", got)
		}
	}
	close(agent.release)
}

// failingUnregisterAgent models a registrar that never acknowledges the
// REGISTER Expires: 0. B3 made Unregister BLOCKING — nil only on a 2xx — so
// this is the ordinary unreachable-registrar case, not an exotic one.
type failingUnregisterAgent struct{ nopAgent }

func (failingUnregisterAgent) Unregister(context.Context) error {
	return errors.New("registrar unreachable")
}

// TestUnregisterAllUAs is §11.4's REGISTER Expires: 0 pass. Only REGISTERED UAs
// are unregistered; a direct-mode UA has no registration to end.
//
// IT ASSERTS BOTH COUNTS. `sent` and `confirmed` differ whenever a registrar is
// unreachable or silent, and that difference is the whole reason B3 replaced a
// single return: "we tried 2 and 1 acknowledged" is what §11.4's shutdown line
// must record, and a bare count erases it.
func TestUnregisterAllUAs(t *testing.T) {
	t.Run("all registrars acknowledge", func(t *testing.T) {
		m, _ := newTestManager(t)
		ctx := context.Background()
		if err := m.Open(ctx, "s1"); err != nil {
			t.Fatalf("Open: %v", err)
		}
		reg, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "register", Transport: TransportUDP})
		if err != nil {
			t.Fatalf("CreateUA(register): %v", err)
		}
		reg.setRegistered(true)
		// A direct-mode UA has no registration and must not be counted at
		// all. Phase 1's STRICT one-UA-per-session model (owner-locked
		// decision) puts it on its OWN session s2 — UnregisterAllUAs is
		// SERVER-WIDE, so which session owns which UA is immaterial here.
		if err := m.Open(ctx, "s2"); err != nil {
			t.Fatalf("Open(s2): %v", err)
		}
		if _, err := m.CreateUA(ctx, "s2", UAConfig{Mode: "direct", Transport: TransportUDP}); err != nil {
			t.Fatalf("CreateUA(direct): %v", err)
		}

		sent, confirmed := m.UnregisterAllUAs(ctx)
		if sent != 1 {
			t.Errorf("sent = %d, want 1 — a direct-mode UA has no registration to end", sent)
		}
		if confirmed != 1 {
			t.Errorf("confirmed = %d, want 1", confirmed)
		}
		if reg.Registered() {
			t.Error("the registered UA is still marked registered after shutdown")
		}
	})

	// THE CASE A SINGLE COUNT COULD NOT EXPRESS.
	t.Run("a registrar never answers: sent exceeds confirmed", func(t *testing.T) {
		fc := newFakeClock()
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		m, err := NewManager(ManagerConfig{
			Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, nil), Logger: testLogger(),
			NewUA: func(context.Context, UAConfig) (UserAgent, error) {
				return failingUnregisterAgent{}, nil
			},
		})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		// Phase 1's STRICT one-UA-per-session model (owner-locked decision):
		// each registered UA below gets its OWN session.
		for i := 0; i < 2; i++ {
			sid := fmt.Sprintf("s%d", i+1)
			if err := m.Open(ctx, sid); err != nil {
				t.Fatalf("Open(%s): %v", sid, err)
			}
			u, err := m.CreateUA(ctx, sid, UAConfig{Mode: "register", Transport: TransportUDP})
			if err != nil {
				t.Fatalf("CreateUA %d: %v", i, err)
			}
			u.setRegistered(true)
		}

		sent, confirmed := m.UnregisterAllUAs(ctx)
		if sent != 2 {
			t.Errorf("sent = %d, want 2 — every registered UA is attempted", sent)
		}
		if confirmed != 0 {
			t.Errorf("confirmed = %d, want 0 — no registrar acknowledged", confirmed)
		}
		if sent <= confirmed {
			t.Fatal("sent did not exceed confirmed against an unreachable registrar; the " +
				"two counts are not distinguishable and B3's return shape buys nothing")
		}
		// SHUTDOWN PROCEEDS REGARDLESS. An unconfirmed deregistration is
		// expected, not exceptional — the same reasoning §11.4's BYE grace
		// period applies to a far end that never answers.
	})
}
