package sipua

import (
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

func TestPlanDTMFStepSendsInbandAndCompletes(t *testing.T) {
	rec := &recordingEmit{}
	ml := &mediaLoop{emit: rec.emit}
	ml.assemble(nil, nil)
	u := &UA{cfg: Config{DTMFMode: "inband"}}
	d := &dialog{id: "d1", phase: phaseAnswered, mediaLoop: ml, localCSeq: 1}
	u.register(d)

	u.launchMediaPlan(d, ml, []session.MediaPlanStep{
		{Op: "dtmf", Digits: "12", Mode: "inband", DurationMs: 20, GapMs: 0},
	})

	// Assert on the ACTUALLY INSTALLED source before draining it, the same way
	// TestSendDTMFInbandHonoursAnExplicitZeroGap does. Asserting only
	// State=="completed" cannot see the step's timing at all: replacing
	// `int(step.DurationMs), int(step.GapMs)` in launchMediaPlan's SendDTMF call
	// with `0, dtmfGapUnset` — i.e. discarding the plan's own numbers and taking
	// the defaults — left the whole internal/sipua package green, because a
	// pumped source completes identically whatever it renders. This is the only
	// plan test that reaches a SUCCESSFUL send, so it is the only place the
	// pass-through can be pinned, and the plan's `gap_ms: 0 means NO GAP`
	// contract has no other test.
	//
	// A zero-gap two-digit send at 20ms tone renders exactly 40ms; under the
	// defaults it would be 2 x (100ms tone + 50ms gap).
	waitFor(t, func() bool { return ml.currentOp() == opDTMFInband })
	src, ok := ml.currentSrc().(*codec.DTMFSource)
	if !ok {
		t.Fatalf("the dtmf step installed a %T, not a *codec.DTMFSource", ml.currentSrc())
	}
	if src.DurationMs() != 40 {
		t.Fatalf("the dtmf step rendered %dms; the plan's own duration_ms=20/gap_ms=0 must "+
			"reach SendDTMF verbatim, never the 100/50 defaults", src.DurationMs())
	}

	// Drive the TX source the way runTX would, so the inband send can exhaust.
	pumpTX(t, ml)
	waitFor(t, func() bool {
		v, ok := u.MediaPlanView("d1")
		return ok && v.State == "completed"
	})
	if ml.currentOp() != opNone {
		t.Fatal("the dtmf step must leave the media slot free")
	}
}

func TestPlanDTMFStepNotSupportedAbortsAndReleasesTheSlot(t *testing.T) {
	rec := &recordingEmit{}
	ml := &mediaLoop{emit: rec.emit}
	ml.assemble(nil, nil)
	u := &UA{cfg: Config{DTMFMode: "rfc2833"}}
	// telephone-event NOT negotiated => the rfc2833 step must fail not_supported.
	d := &dialog{id: "d1", phase: phaseAnswered, mediaLoop: ml, localCSeq: 1,
		mediaSession: &media.Session{Codec: "PCMU", TelephoneEventPT: 0}}
	u.register(d)

	u.launchMediaPlan(d, ml, []session.MediaPlanStep{
		{Op: "wait", DurationMs: 1},
		{Op: "dtmf", Digits: "1", Mode: "rfc2833", DurationMs: 100, GapMs: 50},
		{Op: "wait", DurationMs: 1},
	})
	waitFor(t, func() bool {
		v, ok := u.MediaPlanView("d1")
		return ok && v.State == "failed"
	})
	v, _ := u.MediaPlanView("d1")
	if v.FailedIndex != 1 || v.FailedOp != "dtmf" {
		t.Fatalf("view=%+v want failed at index 1/dtmf", v)
	}
	// §10.7's acceptance: the abort path leaves the slot free, so a follow-up
	// inband dtmf_send on the same call succeeds.
	if ml.currentOp() != opNone {
		t.Fatalf("op=%d — the abort path must release the media slot", ml.currentOp())
	}
	// No plan_step event for index 2 — the plan stopped.
	for _, ev := range rec.snapshot() {
		if ev.Kind == session.UAEventPlanStep {
			if idx, _ := ev.Detail["index"].(int); idx == 2 {
				t.Fatal("a step after the failure must not run")
			}
		}
	}
	// The failure is reported with code not_supported.
	var found bool
	for _, ev := range rec.snapshot() {
		if ev.Kind == session.UAEventMediaError && ev.Detail["kind"] == "plan_step_failed" {
			if ev.Detail["code"] != "not_supported" {
				t.Fatalf("code=%v want not_supported", ev.Detail["code"])
			}
			found = true
		}
	}
	if !found {
		t.Fatal("no plan_step_failed error event")
	}
}

// TestPlanDTMFStepAbortsWhenTheCallEndsMidSend pins the mid-send teardown
// shape SendDTMF's inband path itself reports as a step failure
// (apierr.PreconditionFailed, code precondition_failed) — but a call ending
// mid-plan must be reported as "aborted" with a plan_aborted_call_terminated
// event, exactly like the play/record arms, never as a "failed" step. Without
// the mp.terminated() guard in execStep's "dtmf" case, this test fails: the
// plan would instead report state=="failed", failedOp=="dtmf",
// code=="precondition_failed", and emit no plan_aborted_call_terminated.
func TestPlanDTMFStepAbortsWhenTheCallEndsMidSend(t *testing.T) {
	rec := &recordingEmit{}
	ml := &mediaLoop{emit: rec.emit}
	ml.assemble(nil, nil)
	u := &UA{cfg: Config{DTMFMode: "inband"}}
	d := &dialog{id: "d1", phase: phaseAnswered, mediaLoop: ml, localCSeq: 1}
	u.register(d)

	// Deliberately NO pumpTX here: the send must block waiting for TX frames,
	// so teardownDialog can race it mid-send rather than after completion.
	u.launchMediaPlan(d, ml, []session.MediaPlanStep{
		{Op: "dtmf", Digits: "123", Mode: "inband", DurationMs: 100, GapMs: 50},
	})

	// Wait for the send to actually be in its blocking select on the TX
	// source (opDTMFInband claimed) — race-free, no sleep-and-hope.
	waitFor(t, func() bool { return ml.currentOp() == opDTMFInband })

	u.teardownDialog(d)

	waitFor(t, func() bool {
		for _, ev := range rec.snapshot() {
			if ev.Kind == session.UAEventMediaError && ev.Detail["kind"] == "plan_aborted_call_terminated" {
				return true
			}
		}
		return false
	})

	var aborted, stepFailed int
	for _, ev := range rec.snapshot() {
		if ev.Kind == session.UAEventMediaError {
			switch ev.Detail["kind"] {
			case "plan_aborted_call_terminated":
				aborted++
			case "plan_step_failed":
				stepFailed++
			}
		}
	}
	if aborted != 1 {
		t.Fatalf("plan_aborted_call_terminated events=%d want 1", aborted)
	}
	if stepFailed != 0 {
		t.Fatalf("plan_step_failed events=%d want 0 — a mid-plan teardown is an abort, not a step failure", stepFailed)
	}
}

// waitDTMFHarness builds the fake-clock harness these tests share. The clock
// is FAKE for the reason every other timing test in this plan uses one: the
// collection window and the trailing wait step are then deterministic instead
// of racing the scheduler on a 4-CPU box.
func waitDTMFHarness(t *testing.T) (*UA, *dialog, *mediaLoop, *fakeclock.Clock, *recordingEmit) {
	t.Helper()
	rec := &recordingEmit{}
	ml := &mediaLoop{emit: rec.emit}
	ml.assemble(nil, nil)
	clk := fakeclock.New(time.Unix(0, 0))
	u := &UA{cfg: Config{Clock: clk}}
	d := &dialog{id: "d1", phase: phaseAnswered, mediaLoop: ml, localCSeq: 1}
	u.register(d)
	return u, d, ml, clk, rec
}

func TestWaitDTMFSatisfiedByTheExpectedCount(t *testing.T) {
	u, d, ml, clk, _ := waitDTMFHarness(t)

	u.launchMediaPlan(d, ml, []session.MediaPlanStep{
		{Op: "wait_dtmf", Digits: "42", TimeoutMs: 5000},
	})
	// Wait for the step to park on the fake clock, then deliver two digits
	// through the funnel. The 5s timeout is never advanced, so the ONLY way this
	// completes is the digits satisfying the waiter.
	clk.BlockUntil(1)
	waitFor(t, func() bool {
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		return d.dtmfWaiter != nil
	})
	u.handleDigit(d, '4', "inband", 100)
	u.handleDigit(d, '2', "inband", 100)

	waitFor(t, func() bool {
		v, ok := u.MediaPlanView("d1")
		return ok && v.State == "completed"
	})
	u.calls.mu.Lock()
	left := d.dtmfWaiter
	u.calls.mu.Unlock()
	if left != nil {
		t.Fatal("the waiter must be cleared when the step ends")
	}
}

func TestWaitDTMFTimeoutIsAStepFailureAndTheCallStaysAnswered(t *testing.T) {
	u, d, ml, clk, rec := waitDTMFHarness(t)

	u.launchMediaPlan(d, ml, []session.MediaPlanStep{
		{Op: "wait_dtmf", Digits: "7", TimeoutMs: 20},
		{Op: "wait", DurationMs: 1},
	})
	// Park on the collection window, then expire it on the fake clock: no digit
	// ever arrives, which is the only condition under which a timeout fires.
	clk.BlockUntil(1)
	clk.Advance(21 * time.Millisecond)
	waitFor(t, func() bool {
		v, ok := u.MediaPlanView("d1")
		return ok && v.State == "failed"
	})
	v, _ := u.MediaPlanView("d1")
	if v.FailedIndex != 0 || v.FailedOp != "wait_dtmf" {
		t.Fatalf("view=%+v want failed at 0/wait_dtmf", v)
	}
	u.calls.mu.Lock()
	phase := d.phase
	u.calls.mu.Unlock()
	if phase != phaseAnswered {
		t.Fatalf("phase=%d — a wait_dtmf timeout aborts the PLAN, never the call", phase)
	}
	var sawFailure bool
	for _, ev := range rec.snapshot() {
		if ev.Kind == session.UAEventMediaError && ev.Detail["kind"] == "plan_step_failed" {
			sawFailure = true
		}
	}
	if !sawFailure {
		t.Fatal("no plan_step_failed error event")
	}
}

func TestWaitDTMFMismatchIsLoggedAndThePlanContinues(t *testing.T) {
	u, d, ml, clk, rec := waitDTMFHarness(t)

	u.launchMediaPlan(d, ml, []session.MediaPlanStep{
		{Op: "wait_dtmf", Digits: "99", TimeoutMs: 5000},
		{Op: "wait", DurationMs: 1},
	})
	clk.BlockUntil(1)
	waitFor(t, func() bool {
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		return d.dtmfWaiter != nil
	})
	u.handleDigit(d, '1', "inband", 100)
	u.handleDigit(d, '2', "inband", 100)

	// The mismatched step SUCCEEDS, so the plan advances to the trailing wait,
	// whose real time.After(1ms) fires on its own almost immediately.
	waitFor(t, func() bool {
		v, ok := u.MediaPlanView("d1")
		return ok && v.State == "completed"
	})
	var sawMismatch bool
	for _, ev := range rec.snapshot() {
		if ev.Kind == session.UAEventMediaError && ev.Detail["kind"] == "wait_dtmf_mismatch" {
			if ev.Detail["expected"] != "99" || ev.Detail["received"] != "12" {
				t.Fatalf("mismatch detail = %+v", ev.Detail)
			}
			sawMismatch = true
		}
	}
	if !sawMismatch {
		t.Fatal("a digit mismatch must be recorded in the event log (decision 14)")
	}
}

// TestWaitDTMFTimeoutMessageDoesNotLeakDigitsOrContradictItself is B-M2's
// regression test. The old message ("no digits within %dms (collected %q)")
// was self-contradictory whenever a PARTIAL prefix had already arrived before
// the timeout fired (as it does here: '7' of the expected "742" lands, then
// the window still expires) and leaked the collected digits into the error
// payload — inconsistent with this codebase's sent-digit-leak discipline
// elsewhere (e.g. sendDTMFInfo's index-only error text).
func TestWaitDTMFTimeoutMessageDoesNotLeakDigitsOrContradictItself(t *testing.T) {
	u, d, ml, clk, rec := waitDTMFHarness(t)

	u.launchMediaPlan(d, ml, []session.MediaPlanStep{
		{Op: "wait_dtmf", Digits: "742", TimeoutMs: 20},
		{Op: "wait", DurationMs: 1},
	})
	clk.BlockUntil(1)
	waitFor(t, func() bool {
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		return d.dtmfWaiter != nil
	})
	// One digit arrives — not enough to satisfy the 3-digit waiter — before
	// the timeout fires.
	u.handleDigit(d, '7', "inband", 100)
	clk.Advance(21 * time.Millisecond)

	waitFor(t, func() bool {
		v, ok := u.MediaPlanView("d1")
		return ok && v.State == "failed"
	})

	var msg string
	for _, ev := range rec.snapshot() {
		if ev.Kind == session.UAEventMediaError && ev.Detail["kind"] == "plan_step_failed" {
			if m, ok := ev.Detail["message"].(string); ok {
				msg = m
			}
		}
	}
	if msg == "" {
		t.Fatal("no plan_step_failed message captured")
	}
	if strings.Contains(msg, "collected") {
		t.Fatalf("message must not name the collected digits: %q", msg)
	}
	if strings.Contains(msg, "no digits") {
		t.Fatalf("message must not claim 'no digits' when a digit actually arrived before the timeout fired: %q", msg)
	}
}

func TestWaitDTMFWithNoExpectedDigitsIsSatisfiedByTheFirst(t *testing.T) {
	u, d, ml, clk, _ := waitDTMFHarness(t)
	u.launchMediaPlan(d, ml, []session.MediaPlanStep{{Op: "wait_dtmf", TimeoutMs: 5000}})
	clk.BlockUntil(1)
	waitFor(t, func() bool {
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		return d.dtmfWaiter != nil
	})
	u.handleDigit(d, '0', "rfc2833", 100)
	waitFor(t, func() bool {
		v, ok := u.MediaPlanView("d1")
		return ok && v.State == "completed"
	})
}

// TestWaitDTMFTeardownMidStepIsAnAbortNotAStepFailure models
// TestPlanDTMFStepAbortsWhenTheCallEndsMidSend above: a call torn down while a
// wait_dtmf step is parked must report the plan as "aborted" with a
// plan_aborted_call_terminated event, never as a "failed" step — the same
// guard the dtmf arm's mp.terminated() check protects, mirrored here in
// waitForDigits' caller.
//
// It reads the plan's state via the *mediaPlan captured BEFORE teardown, not
// via u.MediaPlanView(dialogID): teardownDialog forgets the dialog from the
// registry, and MediaPlanView resolves through that same registry (u.lookup),
// so once torn down it can never again report ok==true no matter what the
// plan's own state is — exactly why the sibling dtmf test this is modeled on
// asserts only on the emitted events, never on MediaPlanView, after its own
// teardown call.
func TestWaitDTMFTeardownMidStepIsAnAbortNotAStepFailure(t *testing.T) {
	u, d, ml, _, rec := waitDTMFHarness(t)

	u.launchMediaPlan(d, ml, []session.MediaPlanStep{
		{Op: "wait_dtmf", Digits: "9", TimeoutMs: 5000},
	})
	waitFor(t, func() bool {
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		return d.dtmfWaiter != nil
	})
	mp := d.mediaPlan

	u.teardownDialog(d)

	countKinds := func() (aborted, stepFailed int) {
		for _, ev := range rec.snapshot() {
			if ev.Kind == session.UAEventMediaError {
				switch ev.Detail["kind"] {
				case "plan_aborted_call_terminated":
					aborted++
				case "plan_step_failed":
					stepFailed++
				}
			}
		}
		return aborted, stepFailed
	}

	// Wait on the EVENT, not on mp.view().State (Cycle 4 / C4-A, item F3).
	// abortTerminated (call.go:658-664) sets state="aborted" and RELEASES mp.mu
	// before it calls emitError, so a barrier on the state can be satisfied
	// while the event this test actually asserts on is still unpublished — the
	// snapshot below then reads zero events and the test fails spuriously.
	// Widening that window with a 150 ms sleep between the unlock and the
	// emitError reproduces it every time. Synchronising on the observable under
	// assertion closes it without touching production ordering.
	waitFor(t, func() bool {
		aborted, _ := countKinds()
		return aborted >= 1
	})
	if got := mp.view().State; got != "aborted" {
		t.Fatalf("plan state=%q want aborted", got)
	}

	aborted, stepFailed := countKinds()
	if aborted != 1 {
		t.Fatalf("plan_aborted_call_terminated events=%d want 1", aborted)
	}
	if stepFailed != 0 {
		t.Fatalf("plan_step_failed events=%d want 0 — a mid-plan teardown is an abort, not a step failure", stepFailed)
	}
}

// TestWaitDTMFDoesNotFalselyCompleteWhenTheDialogIsForgottenBeforeMLStops pins
// the false-success window a wave-level reviewer found in Fix round 1: all
// three teardown paths (teardownDialog, Hangup, onBye) forget the dialog from
// the registry BEFORE ml.stop() closes ml.done — so mp.dialog()'s lookup can
// already return nil for a step that starts in that window, while
// mp.terminated() (which polls ml.done, not the registry) still reads false.
// Before the fix, the "wait_dtmf" arm's `if d == nil { return "", "" }` early
// return fired in exactly that case, and run() — seeing code=="" and
// terminated()==false — fell through to reporting the step (and the whole
// plan, since it is the only step) as a false SUCCESS: "completed", though no
// digit ever arrived and the call was already gone.
//
// This reproduces the window WITHOUT racing the real teardown paths:
// u.forget(d.id) removes the registry entry BEFORE launchMediaPlan ever
// starts the plan goroutine (launchMediaPlan takes *dialog/*mediaLoop
// directly, never through the registry, so the plan still runs against d and
// ml), which guarantees the wait_dtmf step's very first mp.dialog() call
// resolves to nil deterministically — the same nil mp.dialog() would
// eventually return via a real, timing-dependent teardown race, just without
// needing to win that race here.
//
// Reads the plan's state via the *mediaPlan captured right after
// launchMediaPlan, not via u.MediaPlanView(dialogID) — see
// TestWaitDTMFTeardownMidStepIsAnAbortNotAStepFailure's comment above for why
// that lookup is permanently unusable once the dialog leaves the registry
// (which happens here before the plan even starts).
func TestWaitDTMFDoesNotFalselyCompleteWhenTheDialogIsForgottenBeforeMLStops(t *testing.T) {
	u, d, ml, _, _ := waitDTMFHarness(t)

	// Forget the dialog from the registry BEFORE the plan starts, so the
	// wait_dtmf step's mp.dialog() call is guaranteed to see it already gone
	// — deterministic, not a race against the real teardown paths' ordering.
	u.forget(d.id)

	u.launchMediaPlan(d, ml, []session.MediaPlanStep{
		{Op: "wait_dtmf", Digits: "9", TimeoutMs: 5000},
	})
	mp := d.mediaPlan

	// Old, buggy code resolves mp.dialog()==nil and returns "","" SYNCHRONOUSLY
	// with no blocking at all, so run() reaches "completed" as soon as the
	// plan goroutine gets scheduled — deterministic, not a race, so a short
	// bound is ample margin to catch it if the bug were still present. Fixed
	// code instead blocks in waitForDigits on ml.done (still open) and never
	// reaches "completed" here.
	time.Sleep(50 * time.Millisecond)
	if mp.view().State == "completed" {
		t.Fatal("wait_dtmf must not report completed when the dialog was already forgotten and no digit ever arrived")
	}

	// Now finish the teardown the way the real paths do: close ml.done.
	ml.stop()

	waitFor(t, func() bool {
		return mp.view().State == "aborted"
	})
}

// TestDigitWaiterOfferAfterSatisfactionIsASafeNoOp unit-tests digitWaiter
// directly: a digit offered after the waiter is already satisfied must not
// panic (the ch it would otherwise re-close is already closed) and must not
// be recorded.
func TestDigitWaiterOfferAfterSatisfactionIsASafeNoOp(t *testing.T) {
	w := newDigitWaiter(2)
	w.offer('1')
	w.offer('2') // satisfies it, closes ch
	w.offer('3') // must be a safe no-op, not a double-close panic
	if got := w.collected(); got != "12" {
		t.Fatalf("collected=%q want %q", got, "12")
	}

	w2 := newDigitWaiter(0)
	w2.offer('9') // want<=0: the first digit satisfies it
	w2.offer('8') // safe no-op
	if got := w2.collected(); got != "9" {
		t.Fatalf("collected=%q want %q", got, "9")
	}
}
