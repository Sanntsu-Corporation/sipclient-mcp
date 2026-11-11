package session

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/metrics"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// TestTerminationReasonForCause is U14's mapping table, asserted directly.
//
// THE MAPPING MUST BE TOTAL over the causes P1 emits. A switch with no default,
// falling through to the zero value, would give a call an EMPTY
// termination_reason — a value §10.3's exhaustive enum does not admit, and one
// that no consumer can interpret.
func TestTerminationReasonForCause(t *testing.T) {
	tests := []struct {
		cause   UADialogEndCause
		want    string
		wantErr bool
	}{
		{UACausePeerBYE, "remote_bye", false},
		{UACauseRingTimeout, "inbound_ring_timeout", false},
		{UADialogEndCause("not_a_cause"), "", true},
		{UADialogEndCause(""), "", true},
	}
	for _, tc := range tests {
		t.Run(string(tc.cause), func(t *testing.T) {
			got, err := terminationReasonFor(tc.cause)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("cause %q returned %q with no error — an unrecognised cause is an "+
						"INTERNAL FAULT, never a silent default to some reason", tc.cause, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("cause %q: %v", tc.cause, err)
			}
			if got != tc.want {
				t.Fatalf("cause %q -> %q, want %q", tc.cause, got, tc.want)
			}
		})
	}
}

// TestEveryMappedReasonIsInSection103 stops the mapping drifting out of the
// enum. §10.3 is EXHAUSTIVE — "no termination_reason value appears anywhere
// else in this document that is not listed here" — so a mapping that produced a
// value outside TerminationReasons would be unrepresentable to a consumer.
func TestEveryMappedReasonIsInSection103(t *testing.T) {
	for _, cause := range []UADialogEndCause{UACausePeerBYE, UACauseRingTimeout} {
		reason, err := terminationReasonFor(cause)
		if err != nil {
			t.Fatalf("cause %q: %v", cause, err)
		}
		found := false
		for _, r := range TerminationReasons {
			if r == reason {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("cause %q maps to %q, which is not in §10.3's exhaustive enum %v",
				cause, reason, TerminationReasons)
		}
	}
}

// TestRingTimeoutAndLocalRejectStayDistinguishable is THE conflation U14 exists
// to prevent, asserted on two otherwise identical inbound calls.
//
// Both terminate with a locally-sent 4xx and are INDISTINGUISHABLE ON THE WIRE.
// If the mapping ever collapses them, an agent can no longer tell "my test
// rejected the call" from "nobody answered in time" — which is the difference
// between a passing assertion and a timed-out one.
func TestRingTimeoutAndLocalRejectStayDistinguishable(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()

	// Call A: the local test rejects it.
	rejected := mustCall(t, m, "s1")
	if err := rejected.TryReject(fc.Now(), 480, "Temporarily Unavailable"); err != nil {
		t.Fatalf("reject: %v", err)
	}

	// Call B: identical inbound call, ended by the ring timer. Same 480 on the
	// wire, different fact about what happened. Phase 1's STRICT
	// one-UA-per-session model (owner-locked decision) puts it on its OWN
	// session — mustCall mints a fresh UA each time and s1 already holds one.
	timedOut := mustCall(t, m, "s2")
	timedOut.setDialogIdentity("dlg-b", "callid-b")
	m.handleUAEvent(ctx, timedOut.UAHandle(), UAEvent{
		Kind:     UAEventDialogEnded,
		Cause:    UACauseRingTimeout,
		DialogID: "dlg-b",
		Code:     480,
		At:       fc.Now(),
	})

	if got := rejected.TerminationReason(); got != "rejected_locally" {
		t.Errorf("locally-rejected call: termination_reason = %q, want rejected_locally", got)
	}
	if got := timedOut.TerminationReason(); got != "inbound_ring_timeout" {
		t.Errorf("ring-timed-out call: termination_reason = %q, want inbound_ring_timeout", got)
	}
	if rejected.TerminationReason() == timedOut.TerminationReason() {
		t.Fatal("a locally-rejected call and a ring-timeout are reporting the SAME " +
			"termination_reason — they are indistinguishable on the wire, which is " +
			"precisely why U14 carries the cause out of band")
	}
}

// TestDialogEndedIsAnEntryToTerminationNotASecondPath is the Rule 18 assertion.
// A call terminated by a peer BYE must be indistinguishable, in every
// downstream effect, from one terminated by call_hangup — same terminal
// broadcast, same slot release, same single log line.
func TestDialogEndedIsAnEntryToTerminationNotASecondPath(t *testing.T) {
	m, fc := newManagerWith(t, func(l *policy.Limits) {
		l.MaxConcurrentCallsPerSession = 1 // so the slot release is observable
		l.MaxConcurrentCallsTotal = 10
	})
	ctx := context.Background()
	uas := setupSessions(t, m, "s1")

	c, err := m.CreateCall(ctx, "s1", uas["s1"], Inbound, StateAnswered)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}
	c.setDialogIdentity("dlg-1", "callid-1")

	// A waiter is parked with an `until` the BYE does not match. §6.3 rule 2's
	// terminal broadcast must still wake it.
	woke := make(chan WaitResult, 1)
	go func() {
		r, _ := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "dtmf", TimeoutMs: 300000, Since: 0})
		woke <- r
	}()
	waitForCount(t, m, c, 1)

	// The far end hangs up.
	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
		Kind: UAEventDialogEnded, Cause: UACausePeerBYE,
		DialogID: "dlg-1", At: fc.Now(),
	})

	if got := c.TerminationReason(); got != "remote_bye" {
		t.Fatalf("termination_reason = %q, want remote_bye", got)
	}
	if got := c.State(); got != StateTerminated {
		t.Fatalf("state = %q, want terminated", got)
	}

	// §6.3 rule 2: the parked waiter woke on the terminal state despite its
	// `until` being dtmf.
	select {
	case r := <-woke:
		if r.TimedOut {
			t.Error("the parked waiter timed out; a terminal state must broadcast to ALL " +
				"waiters regardless of their until (§6.3 rule 2)")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("the parked waiter did not return within 100ms of the peer BYE")
	}

	// §12.2.2: the concurrency slot is free IMMEDIATELY, not at eviction. With
	// a per-session cap of 1, a second dial proves it.
	if _, err := m.CreateCall(ctx, "s1", uas["s1"], Outbound, StateDialing); err != nil {
		t.Fatalf("dial after a peer BYE: %v — a remote termination must free its slot at "+
			"TERMINATION, exactly as a local hangup does (§12.2.2)", err)
	}
	assertWaiterAccountsZero(t, m, c, "s1")
}

// TestUnrecognisedCauseDoesNotFabricateAReason pins the failure mode of a
// sipua that gained a cause `session` was never taught. The call must NOT
// acquire an enum value nobody chose.
func TestUnrecognisedCauseDoesNotFabricateAReason(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	c.setDialogIdentity("dlg-1", "callid-1")

	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
		Kind: UAEventDialogEnded, Cause: UADialogEndCause("invented_by_a_later_phase"),
		DialogID: "dlg-1", At: fc.Now(),
	})

	if r := c.TerminationReason(); r != "" {
		t.Fatalf("termination_reason = %q for an unrecognised cause — the call acquired an "+
			"enum value nothing chose. An unmappable cause is an internal fault, and a "+
			"fabricated reason is worse than a loud one", r)
	}
	// An `error` event records the fault so it is visible in call_events rather
	// than only in the server log.
	evs, _, _ := c.Events(0)
	if len(evs) == 0 || evs[len(evs)-1].Type != EventError {
		t.Fatalf("events = %+v, want a trailing error event recording the unmappable cause", evs)
	}
}

// TestHandleDialogEndedCancelledTerminatesCall is D3's session-side half: an
// inbound INVITE the peer CANCELled must reach StateTerminated with reason
// "cancelled", not stay ringing forever. Before this cause is registered,
// terminationReasonFor's default branch appends an EventError and returns
// WITHOUT TryTerminate, which is exactly the non-terminal-call bug this pins.
func TestHandleDialogEndedCancelledTerminatesCall(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	c.setDialogIdentity("dlg-cancel", "callid-cancel")

	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
		Kind: UAEventDialogEnded, Cause: UACauseCancelled,
		DialogID: "dlg-cancel", CallID: "callid-cancel", At: fc.Now(),
	})

	if got := c.State(); got != StateTerminated {
		t.Fatalf("state = %q, want terminated", got)
	}
	if got := c.TerminationReason(); got != "cancelled" {
		t.Fatalf("TerminationReason() = %q, want cancelled", got)
	}
}

// TestHandleResponse180ClaimsRingingAndRecordsLastResponse is Task 11c's
// dialing -> ringing branch. Both assertions are load-bearing on their own
// mutation: removing the recordLastResponse call would leave
// LastResponseCode/Reason at their zero value while the state assertion still
// passed, so this test — not just the state one — is what pins the record.
func TestHandleResponse180ClaimsRingingAndRecordsLastResponse(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	uas := setupSessions(t, m, "s1")
	c, err := dial(t, m, "s1", uas["s1"])
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.setDialogIdentity("dlg-1", "callid-1")

	m.handleUAEvent(ctx, uas["s1"], UAEvent{
		Kind: UAEventProvisional, DialogID: "dlg-1",
		Code: 180, Reason: "Ringing", At: fc.Now(),
	})

	if got := c.State(); got != StateRinging {
		t.Fatalf("state = %q, want ringing", got)
	}
	if got := c.LastResponseCode(); got != 180 {
		t.Fatalf("LastResponseCode() = %d, want 180", got)
	}
	if got := c.LastResponseReason(); got != "Ringing" {
		t.Fatalf("LastResponseReason() = %q, want Ringing", got)
	}
	// Asserts the exact event COUNT and the full sequence, not just the
	// trailing element: TryProgress (call.go) appends EventRinging itself, and
	// handleResponse must NOT append a second one on top of it. A trailing-only
	// assertion here cannot distinguish one ringing event from two identical
	// ones — see the duplicate-Append regression this test now pins.
	evs, _, _ := c.Events(0)
	if len(evs) != 1 || evs[0].Type != EventRinging {
		t.Fatalf("events = %+v, want exactly one ringing event", evs)
	}
}

// TestHandleResponse200OnDialingClaimsAnswered is D96: a 200 OK with NO
// preceding 180/183 is legal on the wire, and TryRemoteAnswer exists
// specifically so it is claimable straight from StateDialing. Constraining
// TryRemoteAnswer back to StateRinging-only (i.e. reusing TryAnswer's
// precondition) kills this test: the call would stay `dialing` forever.
func TestHandleResponse200OnDialingClaimsAnswered(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	uas := setupSessions(t, m, "s1")
	c, err := dial(t, m, "s1", uas["s1"])
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.setDialogIdentity("dlg-1", "callid-1")

	m.handleUAEvent(ctx, uas["s1"], UAEvent{
		Kind: UAEventFinal, DialogID: "dlg-1",
		Code: 200, Reason: "OK", At: fc.Now(),
	})

	if got := c.State(); got != StateAnswered {
		t.Fatalf("state = %q, want answered — a 200 with no preceding 180 is legal "+
			"on the wire and must be claimable straight from dialing (D96)", got)
	}
	// Asserts the exact event COUNT and the full sequence, not just the
	// trailing element: TryRemoteAnswer (call.go) appends EventAnswered itself,
	// and handleResponse must NOT append a second one on top of it. A
	// trailing-only assertion here cannot distinguish one answered event from
	// two identical ones — see the duplicate-Append regression this test now
	// pins.
	evs, _, _ := c.Events(0)
	if len(evs) != 1 || evs[0].Type != EventAnswered {
		t.Fatalf("events = %+v, want exactly one answered event", evs)
	}
}

// TestHandleResponseRejectedInviteClaimsFailedAndRecordsTermination is Task
// 11c's terminal branch: a 3xx-6xx final on an outbound call lands StateFailed
// (not StateTerminated — spec:825's "never reached answered" edge) and is a
// §6.0b INV-1 Form A site, so RecordTermination's full effects must follow.
// Landing StateTerminated instead of StateFailed kills the state assertion
// below; dropping the recordLastResponse call kills the last_response
// assertions independently of it.
func TestHandleResponseRejectedInviteClaimsFailedAndRecordsTermination(t *testing.T) {
	logger, buf := captureLogger()
	reg := metrics.New(TerminationReasons)
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc,
		Policy:  policy.NewStaticStore(policy.Defaults(), fc, testLogger()),
		Logger:  logger,
		Metrics: reg,
		NewUA:   func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	uas := setupSessions(t, m, "s1")
	c, err := dial(t, m, "s1", uas["s1"])
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.setDialogIdentity("dlg-1", "callid-1")

	m.handleUAEvent(context.Background(), uas["s1"], UAEvent{
		Kind: UAEventFinal, DialogID: "dlg-1",
		Code: 486, Reason: "Busy Here", At: fc.Now(),
	})

	if got := c.State(); got != StateFailed {
		t.Fatalf("state = %q, want failed — a rejected outbound INVITE never reached "+
			"answered (spec:825)", got)
	}
	if got := c.LastResponseCode(); got != 486 {
		t.Fatalf("LastResponseCode() = %d, want 486", got)
	}
	if got := c.LastResponseReason(); got != "Busy Here" {
		t.Fatalf("LastResponseReason() = %q, want Busy Here", got)
	}
	// D97: no termination_reason is produced on this branch — the spec's own
	// worked wire result for exactly this case carries no such key.
	if got := c.TerminationReason(); got != "" {
		t.Fatalf("TerminationReason() = %q, want \"\" (D97)", got)
	}

	// INV-1's effects: the concurrency slot is freed IMMEDIATELY, and the N5
	// log line is emitted, exactly as every other terminal Try* site proves.
	if perSession, total := m.DebugLiveCallCounts("s1"); perSession != 0 || total != 0 {
		t.Fatalf("live call counts = (%d, %d), want (0, 0): RecordTermination did not run", perSession, total)
	}
	if !strings.Contains(buf.String(), `"state":"failed"`) {
		t.Fatalf("N5 log line missing or wrong: %s", buf.String())
	}
	// The metrics increment must be SKIPPED for this empty reason, not
	// panicked on: TerminationReasons' enum has no "" label, and
	// IncTerminationReason panics on an unknown one by design.
	var metricsOut bytes.Buffer
	if err := reg.WriteText(&metricsOut); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if !strings.Contains(metricsOut.String(), "active_calls 0") {
		t.Fatalf("active_calls is not 0:\n%s", metricsOut.String())
	}
}

// TestHandleResponseFailRacesLocalHangup is the 486-vs-TryHangup negative
// control (§6.3): a concurrent call_hangup and a rejected outbound INVITE's
// 486 must resolve to EXACTLY ONE WINNER.
//
// THE DETERMINISTIC SUBTESTS BELOW ARE THE PRIMARY CONTROL, NOT THE GOROUTINE
// RACE THAT FOLLOWS. The two claim orders are NOT symmetric: TryTerminate's
// own terminal() guard already blocks a losing call_hangup regardless of
// whether TryFail's guard is intact, so a missing TryFail guard is
// observable ONLY when call_hangup's TryTerminate claims first and the 486's
// TryFail runs second. A goroutine race lets the scheduler pick the winner,
// so with TryFail's guard removed a bare race caught the defect on only
// ~11/20 (55%) of independent `-count=1` runs — the exact ~half where
// call_hangup happened to win the c.mu acquisition first. Round 2's
// `-count=40` validation aggregates 40 runs and is therefore near-certain to
// hit that window at least once, which is what hid the other ~45% of
// `-count=1` runs missing the defect entirely.
//
// "hangup_first" MUST interpose the 486 BETWEEN the winning TryHangup call
// and its own RecordTermination, not after both: RecordTermination deletes
// the call from the registry's live-call set (janitor.go), and
// callByDialogID (registry.go) — handleResponse's own lookup — only searches
// that set. Run hangup fully to completion first (claim, then record) and
// the 486's lookup finds nothing at all, so handleResponse returns before
// ever reaching TryFail — a false pass indistinguishable from a real one
// that happens to have missed the defect. Interposing the 486 between the
// claim and the record reproduces the exact window a real concurrent
// call_hangup leaves open (its own claim and its own record are two separate,
// unlocked steps in its caller — see ToolService.CallHangup), so the 486
// still finds the call live in the registry while c.state is already
// Terminated, and reaches TryFail on every single run. Driving both fixed
// orders directly, with no goroutines at all, makes the missing-guard defect
// fail on every single run instead of about half of them. The goroutine race
// is kept as a second, genuinely concurrent case: it is what would catch an
// actual lock-ordering or data-race regression, which the deterministic
// sequential calls below never exercise since they never contend on c.mu at
// all.
func TestHandleResponseFailRacesLocalHangup(t *testing.T) {
	newRacingCall := func(t *testing.T, i int) (*Manager, *Call, *fakeclock.Clock, Handle) {
		t.Helper()
		m, fc := newTestManager(t)
		uas := setupSessions(t, m, "s1")
		c, err := dial(t, m, "s1", uas["s1"])
		if err != nil {
			t.Fatalf("iteration %d: dial: %v", i, err)
		}
		c.setDialogIdentity("dlg-1", "callid-1")
		return m, c, fc, uas["s1"]
	}
	fail486 := func(m *Manager, ua Handle, fc *fakeclock.Clock) {
		m.handleUAEvent(context.Background(), ua, UAEvent{
			Kind: UAEventFinal, DialogID: "dlg-1",
			Code: 486, Reason: "Busy Here", At: fc.Now(),
		})
	}
	hangup := func(m *Manager, c *Call, fc *fakeclock.Clock) {
		// Mirrors ToolService.CallHangup: TryHangup only claims the state
		// transition, and its caller runs INV-1's record on a win.
		if err := c.TryHangup(fc.Now(), "local_hangup"); err == nil {
			m.RecordTermination(c)
		}
	}

	// hangup_first forces the ONLY order that observes a missing TryFail
	// guard (see the doc comment above): call_hangup's claim lands, the 486
	// is interposed WHILE the call is still registered as live, and only then
	// does the winner's own RecordTermination run — reproducing the real
	// window between those two steps instead of collapsing it.
	t.Run("hangup_first", func(t *testing.T) {
		m, c, fc, ua := newRacingCall(t, 0)
		if err := c.TryHangup(fc.Now(), "local_hangup"); err != nil {
			t.Fatalf("hangup: unexpected error on the first claim: %v", err)
		}
		fail486(m, ua, fc)
		m.RecordTermination(c) // completes the winner's own INV-1 record, per ToolService.CallHangup
		assertExactlyOneTerminalClaim(t, m, c, 0)
	})
	// fail486_first is the other fixed order, kept for symmetry: here
	// TryTerminate's own guard must reject the losing call_hangup regardless
	// of TryFail's guard.
	t.Run("fail486_first", func(t *testing.T) {
		m, c, fc, ua := newRacingCall(t, 0)
		fail486(m, ua, fc)
		hangup(m, c, fc)
		assertExactlyOneTerminalClaim(t, m, c, 0)
	})

	for i := 0; i < 200; i++ {
		m, c, fc, ua := newRacingCall(t, i)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			fail486(m, ua, fc)
		}()
		go func() {
			defer wg.Done()
			hangup(m, c, fc)
		}()
		wg.Wait()
		assertExactlyOneTerminalClaim(t, m, c, i)
	}
}

// assertExactlyOneTerminalClaim is
// TestHandleResponseFailRacesLocalHangup's shared assertion, asserted so a
// double claim cannot pass by construction: `st != StateFailed && st !=
// StateTerminated` (the prior form) accepts both outcomes and never fails,
// and the live-count check alone is satisfied by RecordTermination's own
// idempotence guard (janitor.go:150) regardless of whether a second claim
// wrote over the first. The event log is the tell: a losing claim must be an
// observable no-op, so exactly one terminal event may exist, and the
// surviving state and TerminationReason() must both match that one event —
// not just be "some" terminal state.
func assertExactlyOneTerminalClaim(t *testing.T, m *Manager, c *Call, i int) {
	t.Helper()
	evs, _, _ := c.Events(0)
	var terminalEvents []EventType
	for _, e := range evs {
		if e.Type == EventBye || e.Type == EventError {
			terminalEvents = append(terminalEvents, e.Type)
		}
	}
	if len(terminalEvents) != 1 {
		t.Fatalf("iteration %d: terminal events = %v, want exactly one — a losing "+
			"claim must be a no-op, not a second terminal Append (§6.3)", i, terminalEvents)
	}

	var wantState CallState
	var wantReason string
	switch terminalEvents[0] {
	case EventBye:
		wantState, wantReason = StateTerminated, "local_hangup"
	case EventError:
		wantState, wantReason = StateFailed, ""
	}
	if st := c.State(); st != wantState {
		t.Fatalf("iteration %d: state = %q, want %q matching the sole terminal event "+
			"%s — the loser must not flip the winner's state (§6.3)", i, st, wantState, terminalEvents[0])
	}
	if got := c.TerminationReason(); got != wantReason {
		t.Fatalf("iteration %d: TerminationReason() = %q, want %q matching the sole "+
			"terminal event %s — the loser must not overwrite the winner's reason (§6.3)",
			i, got, wantReason, terminalEvents[0])
	}
	if perSession, total := m.DebugLiveCallCounts("s1"); perSession != 0 || total != 0 {
		t.Fatalf("iteration %d: live call counts = (%d, %d), want (0, 0)", i, perSession, total)
	}
}

func TestTerminationReasonForTransportFailure(t *testing.T) {
	got, err := terminationReasonFor(UACauseTransportFailure)
	if err != nil {
		t.Fatalf("terminationReasonFor: %v", err)
	}
	if got != "transport_failure" {
		t.Fatalf("reason=%q want transport_failure", got)
	}
}

// TestHandleDialogEndedTransportFailureIsDialogScoped is the session half of
// §11.3.1 case 2. It pins BOTH halves of the contract: the failing dialog
// terminates with the fault detail on its terminal EventError (not an EventBye —
// no BYE was sent), and the UA's OTHER live call is untouched, which is exactly
// what routing this through UAEventTransportFault would have broken.
func TestHandleDialogEndedTransportFailureIsDialogScoped(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	dead := mustCall(t, m, "s1")
	dead.setDialogIdentity("dlg-dead", "callid-dead")
	if err := dead.TryAnswer(fc.Now()); err != nil {
		t.Fatalf("TryAnswer: %v", err)
	}
	// A SECOND call on the SAME UA, healthy.
	alive, err := m.CreateCall(ctx, "s1", dead.UAHandle(), Outbound, StateDialing)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}
	alive.setDialogIdentity("dlg-alive", "callid-alive")
	if err := alive.TryRemoteAnswer(fc.Now()); err != nil {
		t.Fatalf("TryRemoteAnswer: %v", err)
	}

	detail := map[string]any{"kind": "transport_failure", "transport": "udp",
		"cause": "in_dialog_timeout", "method": "UPDATE"}
	m.handleUAEvent(ctx, dead.UAHandle(), UAEvent{
		Kind: UAEventDialogEnded, Cause: UACauseTransportFailure,
		DialogID: "dlg-dead", CallID: "callid-dead", Detail: detail, At: fc.Now(),
	})

	if got := dead.State(); got != StateTerminated {
		t.Fatalf("state=%q want terminated (§11.3.1: the call reached answered, so NOT failed)", got)
	}
	if got := dead.TerminationReason(); got != "transport_failure" {
		t.Fatalf("termination_reason=%q want transport_failure", got)
	}
	evs, _, _ := dead.Events(0)
	last := evs[len(evs)-1]
	if last.Type != EventError || last.Detail["cause"] != "in_dialog_timeout" {
		t.Fatalf("terminal event=%+v want an EventError carrying detail.cause", last)
	}
	if got := alive.State(); got != StateAnswered {
		t.Fatalf("the other call on the UA is %q — an in-dialog timeout must not reap it", got)
	}
}

// TestDialogScopedTransportFailureOnADialingCallLeavesSiblingsLive is CF-037's
// session half: a dial that drew no usable final response reaches the session as
// a dialog-scoped UAEventDialogEnded for a call still `dialing`. That call lands
// terminated/transport_failure, and an answered sibling on the same UA (whose
// sipua dialog is still live) is untouched.
func TestDialogScopedTransportFailureOnADialingCallLeavesSiblingsLive(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	a := mustCall(t, m, "s1")
	a.setDialogIdentity("dlg-a", "callid-a")
	if err := a.TryAnswer(fc.Now()); err != nil {
		t.Fatalf("TryAnswer: %v", err)
	}
	b, err := m.CreateCall(ctx, "s1", a.UAHandle(), Outbound, StateDialing)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}
	b.setDialogIdentity("dlg-b", "callid-b")

	m.handleUAEvent(ctx, a.UAHandle(), UAEvent{
		Kind: UAEventDialogEnded, Cause: UACauseTransportFailure,
		DialogID: "dlg-b", CallID: "callid-b", Err: errors.New("invite timeout"), At: fc.Now(),
	})

	if got := b.State(); got != StateTerminated {
		t.Fatalf("dialing call state=%q want terminated", got)
	}
	if got := b.TerminationReason(); got != "transport_failure" {
		t.Fatalf("termination_reason=%q want transport_failure", got)
	}
	evs, _, _ := b.Events(0)
	if last := evs[len(evs)-1]; last.Type != EventError || last.Detail != nil {
		t.Fatalf("terminal event=%+v want an EventError with nil detail", last)
	}
	if got := a.State(); got != StateAnswered {
		t.Fatalf("answered sibling state=%q want answered", got)
	}
	if per, _ := m.DebugLiveCallCounts("s1"); per != 1 {
		t.Fatalf("live calls in the session=%d want 1", per)
	}
}

// TestDialogEndedTransportFailureForAHungUpCallIsIgnored pins the session half
// of D-A's "nothing for a hung-up dial": a hangup the session claimed first but
// that reached sipua only after its teardown leaves sipua emitting a
// dialog-scoped transport_failure end for an already-terminated call. It must
// change nothing, both before RecordTermination (the terminal() guard) and after
// it (the live-only callByDialogID lookup).
func TestDialogEndedTransportFailureForAHungUpCallIsIgnored(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		name := "claimed_not_recorded"
		if recorded {
			name = "recorded"
		}
		t.Run(name, func(t *testing.T) {
			m, fc := newTestManager(t)
			ctx := context.Background()
			c := mustCall(t, m, "s1")
			c.setDialogIdentity("dlg-h", "callid-h")
			if err := c.TryAnswer(fc.Now()); err != nil {
				t.Fatalf("TryAnswer: %v", err)
			}
			if err := c.TryHangup(fc.Now(), "test"); err != nil {
				t.Fatalf("TryHangup: %v", err)
			}
			if recorded {
				m.RecordTermination(c)
			}
			before, _, _ := c.Events(0)

			m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
				Kind: UAEventDialogEnded, Cause: UACauseTransportFailure,
				DialogID: "dlg-h", CallID: "callid-h", Err: errors.New("invite timeout"), At: fc.Now(),
			})

			if got := c.State(); got != StateTerminated {
				t.Fatalf("state=%q want terminated", got)
			}
			if got := c.TerminationReason(); got != "local_hangup" {
				t.Fatalf("termination_reason=%q want local_hangup", got)
			}
			after, _, _ := c.Events(0)
			if len(after) != len(before) {
				t.Fatalf("event count %d -> %d: the late end appended an event", len(before), len(after))
			}
			if last := after[len(after)-1]; last.Type != EventBye {
				t.Fatalf("last event=%q want bye", last.Type)
			}
		})
	}
}

// TestTerminationReasonForSessionTimerExpired is Task 30's mapping entry:
// UACauseSessionTimerExpired -> "session_timer_expired", and it must be one of
// §10.3's enumerated reasons metrics.New labels on.
func TestTerminationReasonForSessionTimerExpired(t *testing.T) {
	got, err := terminationReasonFor(UACauseSessionTimerExpired)
	if err != nil {
		t.Fatalf("terminationReasonFor: %v", err)
	}
	if got != "session_timer_expired" {
		t.Fatalf("reason=%q want session_timer_expired", got)
	}
	var found bool
	for _, r := range TerminationReasons {
		if r == got {
			found = true
		}
	}
	if !found {
		t.Fatalf("%q is not in TerminationReasons", got)
	}
}

// TestEventAppendingHandlersDropAnUnresolvableDialog pins the OTHER half of
// callByDialogIDForEvent's contract. The widened lookup's terminated-set search
// is pinned six ways over (the *SurvivesRecordTermination family); its `nil`
// return — documented on callByDialogID as "the call was evicted, which every
// caller treats as a concurrent actor winning" — was pinned nowhere, and the
// `if c == nil { return }` guard in EVERY event-appending handler had zero
// coverage. Delete all six and the suite stays green, while production takes a
// nil-pointer panic on the daemon's event goroutine.
//
// The window is real and is not a race: registry eviction ends the §N3
// retention window while the UA is still live, so the RX goroutine's next
// digit, a late session_refresh, or the executor's trailing plan_step arrives
// for a dialog neither set holds any more.
func TestEventAppendingHandlersDropAnUnresolvableDialog(t *testing.T) {
	kinds := []struct {
		name   string
		kind   UAEventKind
		detail map[string]any
	}{
		{"dtmf", UAEventDTMF, nil},
		{"session_refresh", UAEventSessionRefresh, map[string]any{"role": "uac"}},
		{"media_error", UAEventMediaError, map[string]any{"kind": "plan_aborted_call_terminated", "index": 0}},
		{"media_start", UAEventMediaStart, nil},
		{"plan_step", UAEventPlanStep, map[string]any{"index": 0, "op": "play", "status": "ok"}},
		{"record_start", UAEventRecordStart, nil},
		{"record_stop", UAEventRecordStop, nil},
		{"transfer", UAEventTransfer, map[string]any{"mode": "blind", "status_code": 200, "reason": "OK", "final": true, "success": true}},
	}
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			m, _ := newTestManager(t)
			ctx := context.Background()
			// The call whose dialog the event names is EVICTED — gone from
			// s.liveCalls and from s.terminatedCalls both.
			// EVICTED, not merely terminated: the *SurvivesRecordTermination
			// family already pins the terminated set, and a call that only
			// reached s.terminatedCalls still RESOLVES. The state under test is
			// the one the §N3 terminated-call cap leaves behind — no Call for
			// this dialog in either set — and EvictCallForTest is the package's
			// own accessor for it.
			gone := mustCall(t, m, "s1")
			gone.setDialogIdentity("dlg-gone", "callid-gone")
			if err := m.EvictCallForTest(ctx, "s1", gone.Handle()); err != nil {
				t.Fatalf("EvictCallForTest: %v", err)
			}
			if m.callByDialogIDForEvent(gone.UAHandle(), "dlg-gone") != nil {
				t.Fatal("the fixture did not reach the state under test: the evicted " +
					"dialog still resolves, so the nil path is never taken")
			}
			// A SECOND, live call on the same UA. The dropped event must not be
			// misdelivered to it either.
			live, err := m.CreateCall(ctx, "s1", gone.UAHandle(), Inbound, StateRinging)
			if err != nil {
				t.Fatalf("CreateCall: %v", err)
			}
			live.setDialogIdentity("dlg-live", "callid-live")
			before, _, _ := live.Events(0)

			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("handling %s for an evicted dialog panicked: %v — "+
							"the handler's `if c == nil { return }` guard is what stands "+
							"between registry eviction and a nil deref on the daemon's "+
							"event goroutine", k.name, r)
					}
				}()
				m.handleUAEvent(ctx, gone.UAHandle(), UAEvent{
					Kind: k.kind, DialogID: "dlg-gone", CallID: "callid-gone",
					Digit: "5", DTMFMode: "rfc2833", DurationMs: 100,
					Detail: k.detail,
				})
			}()

			if after, _, _ := live.Events(0); len(after) != len(before) {
				t.Fatalf("the live call gained %d event(s) from an event addressed to an "+
					"evicted dialog: %+v", len(after)-len(before), after)
			}
			if digits, _ := live.DigitsSince(0); len(digits) != 0 {
				t.Fatalf("the live call recorded %+v from a digit addressed to an evicted dialog", digits)
			}
		})
	}
}
