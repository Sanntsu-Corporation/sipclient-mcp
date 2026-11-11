package session

import (
	"context"
	"errors"
	"testing"
)

// TestRegisterFailedLeavesLiveCallsAlone is the whole reason UAEventRegisterFailed
// exists. Under the §2.4-as-written "emit a transport fault" reading, this call
// — established, healthy, its media and in-dialog signalling never touching the
// registrar — would be torn down with termination_reason "transport_failure"
// because a REGISTER refresh went unanswered.
func TestRegisterFailedLeavesLiveCallsAlone(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	c.setDialogIdentity("dlg-live", "callid-live")
	if err := c.TryAnswer(fc.Now()); err != nil {
		t.Fatalf("TryAnswer: %v", err)
	}
	ua, err := m.ResolveUA(ctx, "s1", c.UAHandle())
	if err != nil {
		t.Fatalf("ResolveUA: %v", err)
	}

	// Pre-condition: the UA must actually be registered before the give-up, or
	// the "registered must be false afterward" assertion below would pass
	// trivially regardless of whether recordRegistrationLost does anything.
	ua.recordRegistration(RegisterResult{Registered: true, Code: 200, ExpiresS: 60}, fc.Now())
	if !ua.Registered() {
		t.Fatal("ua_status.registered must be true before the give-up (pre-condition)")
	}

	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
		Kind: UAEventRegisterFailed, Err: errors.New("registrar unreachable"), At: fc.Now(),
	})

	if got := c.State(); got != StateAnswered {
		t.Fatalf("state=%q — a registration give-up must not end an established call", got)
	}
	if got := c.TerminationReason(); got != "" {
		t.Fatalf("termination_reason=%q want empty", got)
	}
	if !m.IsLive(string(c.Handle())) {
		t.Fatal("the call left the live set on a registration give-up")
	}
	if ua.Registered() {
		t.Fatal("ua_status.registered must be false after the refresh gave up")
	}
	if ms := ua.NextRefreshMS(fc.Now()); ms != 0 {
		t.Fatalf("next_refresh_ms=%d — an unregistered UA has no refresh to count down to", ms)
	}
}

// TestRegisterFailedClearsTheStaleRegisterCode pins the locked ua_status shape:
// after a give-up, `registered: false` must not sit beside a `register_code: 200`
// left over from the last successful registration. The 200 is planted through the
// ordinary success path first, so the test fails if recordRegistrationLost leaves
// it behind.
func TestRegisterFailedClearsTheStaleRegisterCode(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	ua, err := m.ResolveUA(ctx, "s1", c.UAHandle())
	if err != nil {
		t.Fatalf("ResolveUA: %v", err)
	}
	// recordRegistration is unexported and this test is in package session, so it
	// is reachable directly — the same way the existing ua tests plant state.
	ua.recordRegistration(RegisterResult{Registered: true, Code: 200, ExpiresS: 60}, fc.Now())
	if ua.RegisterCode() != 200 {
		t.Fatalf("register_code=%d want 200 before the give-up", ua.RegisterCode())
	}

	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
		Kind: UAEventRegisterFailed, Err: errors.New("registrar unreachable"), At: fc.Now(),
	})

	if got := ua.RegisterCode(); got != 0 {
		t.Fatalf("register_code=%d after the refresh gave up; ua_status must not report a "+
			"SUCCESS code beside registered:false", got)
	}
	if ua.ExpiresS() != 0 {
		t.Fatalf("expires_s=%d want 0", ua.ExpiresS())
	}
}

// TestRegisterRemovedReportsUnregisteredAndLeavesLiveCallsAlone is the consumer
// half of the granted-0-on-refresh fix (Cycle 4 / C4-A item D gap 3). sipua emits
// UAEventRegisterRemoved when a registrar answers a refresh 200 OK while granting
// expires=0; handleUAEvent's switch has no default, so a kind it does not name is
// a SILENT DROP — the UA would go on reporting registered:true with a live
// countdown to a refresh that has been disarmed.
//
// It also pins the half UAEventRegisterRemoved shares with UAEventRegisterFailed:
// registration bookkeeping only, no live call is touched.
func TestRegisterRemovedReportsUnregisteredAndLeavesLiveCallsAlone(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	c.setDialogIdentity("dlg-removed", "callid-removed")
	if err := c.TryAnswer(fc.Now()); err != nil {
		t.Fatalf("TryAnswer: %v", err)
	}
	ua, err := m.ResolveUA(ctx, "s1", c.UAHandle())
	if err != nil {
		t.Fatalf("ResolveUA: %v", err)
	}
	// Pre-condition, or every assertion below passes on a UA that was never
	// registered in the first place.
	ua.recordRegistration(RegisterResult{Registered: true, Code: 200, ExpiresS: 60}, fc.Now())
	if !ua.Registered() || ua.ExpiresS() != 60 {
		t.Fatalf("pre-condition: registered=%v expires_s=%d want true/60",
			ua.Registered(), ua.ExpiresS())
	}

	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
		Kind: UAEventRegisterRemoved, Reason: "granted expires=0", At: fc.Now(),
	})

	if ua.Registered() {
		t.Fatal("ua_status.registered must be false after the registrar removed the binding")
	}
	if got := ua.ExpiresS(); got != 0 {
		t.Fatalf("expires_s=%d want 0 — the registrar granted no expiry", got)
	}
	if ms := ua.NextRefreshMS(fc.Now()); ms != 0 {
		t.Fatalf("next_refresh_ms=%d — the refresher was disarmed, there is nothing to count down to", ms)
	}
	if got := ua.RegisterCode(); got != 0 {
		t.Fatalf("register_code=%d — ua_status must not report a SUCCESS code beside "+
			"registered:false, exactly as on the give-up path", got)
	}
	if got := c.State(); got != StateAnswered {
		t.Fatalf("state=%q — a removed registration must not end an established call, whose "+
			"media and in-dialog signalling never traverse the registrar", got)
	}
	if !m.IsLive(string(c.Handle())) {
		t.Fatal("the call left the live set when the registrar removed the binding")
	}
}

// TestTransportFaultStillTerminatesLiveCalls pins the behaviour this task must
// NOT change: §11.3.1's UA-wide fault keeps its existing meaning and its
// existing producers.
func TestTransportFaultStillTerminatesLiveCalls(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	c.setDialogIdentity("dlg-fault", "callid-fault")
	if err := c.TryAnswer(fc.Now()); err != nil {
		t.Fatalf("TryAnswer: %v", err)
	}

	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
		Kind: UAEventTransportFault, Err: errors.New("socket closed"), At: fc.Now(),
	})

	if got := c.TerminationReason(); got != "transport_failure" {
		t.Fatalf("termination_reason=%q want transport_failure", got)
	}
}
