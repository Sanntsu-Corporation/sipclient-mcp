package session

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestPlanViewIsAbsentUntilAPlanIsRegistered(t *testing.T) {
	c := newCall("call_1", "ua_1", &sessionRecord{id: "s"}, Outbound, StateDialing, 64, time.Unix(0, 0))
	if _, ok := c.PlanView(); ok {
		t.Fatal("PlanView must report absent for a call with no plan")
	}
}

func TestPlanViewTracksStepsFromTheEventStream(t *testing.T) {
	c := newCall("call_1", "ua_1", &sessionRecord{id: "s"}, Outbound, StateDialing, 64, time.Unix(0, 0))
	c.SetPlanTotal(2)
	v, ok := c.PlanView()
	if !ok || v.State != "running" || v.StepsTotal != 2 || v.FailedIndex != -1 {
		t.Fatalf("view=%+v ok=%v", v, ok)
	}
	c.applyPlanStep(map[string]any{"index": 0, "op": "play"}) // entry
	c.applyPlanStep(map[string]any{"index": 0, "op": "play", "status": "ok"})
	c.applyPlanStep(map[string]any{"index": 1, "op": "wait"})
	c.applyPlanStep(map[string]any{"index": 1, "op": "wait", "status": "ok"})
	v, _ = c.PlanView()
	if v.State != "completed" || v.StepsCompleted != 2 {
		t.Fatalf("view=%+v want completed 2/2", v)
	}
}

func TestPlanViewRecordsFailureAndAbort(t *testing.T) {
	c := newCall("call_1", "ua_1", &sessionRecord{id: "s"}, Outbound, StateDialing, 64, time.Unix(0, 0))
	c.SetPlanTotal(3)
	c.applyPlanStep(map[string]any{"index": 1, "op": "dtmf", "status": "failed"})
	v, _ := c.PlanView()
	if v.State != "failed" || v.FailedIndex != 1 || v.FailedOp != "dtmf" {
		t.Fatalf("view=%+v want failed at 1/dtmf", v)
	}

	c2 := newCall("call_2", "ua_1", &sessionRecord{id: "s"}, Outbound, StateDialing, 64, time.Unix(0, 0))
	c2.SetPlanTotal(3)
	c2.applyPlanError(map[string]any{"kind": "plan_aborted_call_terminated", "index": 2})
	v2, _ := c2.PlanView()
	if v2.State != "aborted" || v2.FailedIndex != 2 || v2.FailedOp != "" {
		t.Fatalf("view=%+v want aborted at 2", v2)
	}
}

// TestFailedStepSurvivesALaterAbort is the Rule 9 mutation proof for E-M2:
// applyPlanError used to unconditionally clobber a previously-recorded
// "failed" state on ANY plan_aborted_call_terminated event, even when the
// abort is a downstream CONSEQUENCE of the very failure already recorded —
// discarding the informative detail (WHICH step, which op) in favour of a
// generic abort with a different index.
func TestFailedStepSurvivesALaterAbort(t *testing.T) {
	c := newCall("call_1", "ua_1", &sessionRecord{id: "s"}, Outbound, StateDialing, 64, time.Unix(0, 0))
	c.SetPlanTotal(3)
	c.applyPlanStep(map[string]any{"index": 1, "op": "dtmf", "status": "failed"})
	c.applyPlanError(map[string]any{"kind": "plan_aborted_call_terminated", "index": 2})

	v, _ := c.PlanView()
	if v.State != "failed" {
		t.Fatalf("state = %q, want %q — a later abort must not overwrite a recorded failure", v.State, "failed")
	}
	if v.FailedIndex != 1 || v.FailedOp != "dtmf" {
		t.Fatalf("FailedIndex/FailedOp = %d/%q, want 1/\"dtmf\" — the abort's own index (2) must not "+
			"replace the failure's", v.FailedIndex, v.FailedOp)
	}
}

func TestPlanViewSurvivesTerminationAndEviction(t *testing.T) {
	c := newCall("call_1", "ua_1", &sessionRecord{id: "s"}, Outbound, StateDialing, 64, time.Unix(0, 0))
	c.SetPlanTotal(1)
	c.applyPlanStep(map[string]any{"index": 0, "op": "hangup", "status": "ok"})
	if err := c.TryTerminate(time.Unix(1, 0), "local_hangup", EventBye); err != nil {
		t.Fatal(err)
	}
	v, ok := c.PlanView()
	if !ok || v.State != "completed" {
		t.Fatalf("view=%+v ok=%v — the plan view must outlive the dialog (§2.3)", v, ok)
	}
}

// TestFinalPlanStepSurvivesRecordTermination is the DETERMINISTIC pin for the
// live->terminated event-loss race: it drives the termination to completion
// FIRST and only then delivers the executor's final plan_step, which is the
// state a losing race leaves behind. Under the live-only callByDialogID the
// handler finds nothing and the last step is dropped silently.
func TestFinalPlanStepSurvivesRecordTermination(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	c.setDialogIdentity("dlg-plan", "callid-plan")
	c.SetPlanTotal(2)
	c.applyPlanStep(map[string]any{"index": 0, "op": "play", "status": "ok"})

	// The remote BYE wins: the call is terminated AND already moved out of
	// s.liveCalls before the executor's last event arrives.
	if err := c.TryTerminate(fc.Now(), "remote_bye", EventBye); err != nil {
		t.Fatalf("TryTerminate: %v", err)
	}
	m.RecordTermination(c)

	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
		Kind: UAEventPlanStep, DialogID: "dlg-plan", CallID: "callid-plan",
		Detail: map[string]any{"index": 1, "op": "hangup", "status": "ok"},
	})

	v, ok := c.PlanView()
	if !ok || v.StepsCompleted != 2 {
		t.Fatalf("view=%+v ok=%v — the final plan_step was dropped after RecordTermination", v, ok)
	}
	var logged bool
	evs, _, _ := c.Events(0)
	for _, ev := range evs {
		if ev.Type == EventPlanStep && ev.Detail["index"] == 1 {
			logged = true
		}
	}
	if !logged {
		t.Fatal("the final plan_step never reached the event log")
	}
}

// TestPlanAbortedAfterTerminationReachesTheView pins the case that is
// unreachable in production WITHOUT the widened lookup: the executor emits
// plan_aborted_call_terminated precisely BECAUSE the call terminated, so a
// live-only lookup can never deliver it and PlanView's "aborted" state would
// exist only in unit tests.
func TestPlanAbortedAfterTerminationReachesTheView(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	c.setDialogIdentity("dlg-abort", "callid-abort")
	c.SetPlanTotal(3)
	if err := c.TryTerminate(fc.Now(), "remote_bye", EventBye); err != nil {
		t.Fatalf("TryTerminate: %v", err)
	}
	m.RecordTermination(c)

	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
		Kind: UAEventMediaError, DialogID: "dlg-abort", CallID: "callid-abort",
		Detail: map[string]any{"kind": "plan_aborted_call_terminated", "index": 1},
	})

	v, _ := c.PlanView()
	if v.State != "aborted" || v.FailedIndex != 1 {
		t.Fatalf("view=%+v want aborted at 1 — the abort event was dropped", v)
	}
}

// TestMediaStartSurvivesRecordTermination is the same DETERMINISTIC pin for
// media_start, which an earlier draft wrongly exempted from the widened lookup on
// the argument that "a terminated call has no media loop left to receive on".
// That is a statement about when the event can be EMITTED. This test constructs
// the delivery order that argument overlooks: the media goroutine emitted its
// media_start, the remote BYE then ran termination to completion, and only now
// does the handler get to run. Under the live-only lookup the call's codec and
// latched remote address never reach its log at all.
func TestMediaStartSurvivesRecordTermination(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	c.setDialogIdentity("dlg-media", "callid-media")

	if err := c.TryTerminate(fc.Now(), "remote_bye", EventBye); err != nil {
		t.Fatalf("TryTerminate: %v", err)
	}
	m.RecordTermination(c)

	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
		Kind: UAEventMediaStart, DialogID: "dlg-media", CallID: "callid-media",
		LocalMediaAddr: "127.0.0.1:40000", RemoteMediaAddr: "127.0.0.1:40002",
		MediaLatched: true,
	})

	var found bool
	evs, _, _ := c.Events(0)
	for _, ev := range evs {
		if ev.Type == EventMediaStart {
			found = true
			if ev.Detail["remote_media_addr"] != "127.0.0.1:40002" {
				t.Fatalf("media_start detail=%v lost its remote address", ev.Detail)
			}
		}
	}
	if !found {
		t.Fatal("the media_start event was dropped after RecordTermination — " +
			"handleMediaStart appends, so it MUST use callByDialogIDForEvent " +
			"(THE EVENT-LOOKUP INVARIANT, registry.go)")
	}
}

// TestMediaStartIsNotLostWhenTerminationRacesIt is the concurrent form, following
// TestFinalPlanStepIsNotLostWhenTerminationRacesIt's shape exactly: 50 iterations
// under -race, the assertion holding whichever goroutine wins. A live-only lookup
// fails this non-deterministically rather than never, which is why the
// deterministic sibling above exists as well.
//
// CORRECTION: newTestManager(t) is constructed FRESH inside every iteration
// (not hoisted above the loop) — this policy's max_uas_per_session cap is 20,
// and mustCall creates a new UA per call, so a single manager shared across 50
// iterations dies at iteration 20 with "CreateUA: denied: session already
// holds 20 user agents". This matches waiter_race_test.go/uaevent_test.go's
// own per-iteration-manager idiom in this package.
func TestMediaStartIsNotLostWhenTerminationRacesIt(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		m, fc := newTestManager(t)
		c := mustCall(t, m, "s-media-race")
		dlg := fmt.Sprintf("dlg-media-race-%d", i)
		c.setDialogIdentity(dlg, dlg)

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
				Kind: UAEventMediaStart, DialogID: dlg, CallID: dlg,
				LocalMediaAddr: "127.0.0.1:40000", RemoteMediaAddr: "127.0.0.1:40002",
				MediaLatched: true,
			})
		}()
		go func() {
			defer wg.Done()
			<-start
			if err := c.TryTerminate(fc.Now(), "remote_bye", EventBye); err == nil {
				m.RecordTermination(c)
			}
		}()
		close(start)
		wg.Wait()

		var found bool
		evs, _, _ := c.Events(0)
		for _, ev := range evs {
			if ev.Type == EventMediaStart {
				found = true
			}
		}
		if !found {
			t.Fatalf("iteration %d: the media_start was lost to the live->terminated move", i)
		}
	}
}

// TestFinalPlanStepIsNotLostWhenTerminationRacesIt runs the two goroutines
// concurrently, which is the shape the bug actually takes in production: a
// remote BYE driving RecordTermination while the plan executor emits its last
// step. Run under -race; the assertion must hold on EVERY iteration, whichever
// goroutine wins.
//
// CORRECTION: see TestMediaStartIsNotLostWhenTerminationRacesIt's comment above
// — newTestManager(t) is constructed FRESH inside every iteration, not hoisted.
func TestFinalPlanStepIsNotLostWhenTerminationRacesIt(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		m, fc := newTestManager(t)
		c := mustCall(t, m, "s-race")
		dlg := fmt.Sprintf("dlg-race-%d", i)
		c.setDialogIdentity(dlg, dlg)
		c.SetPlanTotal(1)

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
				Kind: UAEventPlanStep, DialogID: dlg, CallID: dlg,
				Detail: map[string]any{"index": 0, "op": "play", "status": "ok"},
			})
		}()
		go func() {
			defer wg.Done()
			<-start
			if err := c.TryTerminate(fc.Now(), "remote_bye", EventBye); err == nil {
				m.RecordTermination(c)
			}
		}()
		close(start)
		wg.Wait()

		if v, ok := c.PlanView(); !ok || v.StepsCompleted != 1 {
			t.Fatalf("iteration %d: view=%+v ok=%v — the plan_step was lost to the live->terminated move",
				i, v, ok)
		}
	}
}

// TestPlanErrorIgnoresOtherKindsAndDoesNotInventAnIndex pins two guards in
// applyPlanError that had zero statement coverage. Both mutations survived
// internal/session and internal/transport/mcp:
//
//   - deleting the `kind != "plan_aborted_call_terminated"` early return, which
//     lets ANY media error flip a running plan's view to "aborted";
//   - `idx = -1` -> `idx = 0` on a malformed index, which is precisely the
//     "must not silently read as index 0" the code comment names.
//
// The index fixture deliberately starts from a NON-default FailedIndex (a
// FIRST, well-formed abort at index 2) so the assertion distinguishes "wrote
// -1" from both "wrote 0" and "wrote nothing at all". SetPlanTotal already
// initialises the field to -1, so asserting -1 on a fresh call would have
// passed with the line deleted — the coincidence this cycle keeps finding.
//
// It is a SECOND abort, not a "failed" step, that sets up the non-default
// starting point: E-M2 (Phase 4 W1 M2) made applyPlanError a no-op once the
// view is already "failed", so a failed-step fixture would short-circuit
// before ever reaching the malformed-index guard under test here. Two
// aborts in a row sidesteps that entirely — the view stays "aborted"
// throughout, which E-M2's guard does not touch.
func TestPlanErrorIgnoresOtherKindsAndDoesNotInventAnIndex(t *testing.T) {
	t.Run("an unrelated error kind leaves the view alone", func(t *testing.T) {
		c := newCall("call_1", "ua_1", &sessionRecord{id: "s"}, Outbound, StateDialing, 64, time.Unix(0, 0))
		c.SetPlanTotal(3)
		c.applyPlanError(map[string]any{"kind": "dtmf_send_failed", "index": 1})
		if v, _ := c.PlanView(); v.State != "running" || v.FailedIndex != -1 {
			t.Fatalf("view=%+v — only plan_aborted_call_terminated may abort the plan view", v)
		}
	})
	t.Run("a malformed index reads as unknown, not step 0", func(t *testing.T) {
		c := newCall("call_2", "ua_1", &sessionRecord{id: "s"}, Outbound, StateDialing, 64, time.Unix(0, 0))
		c.SetPlanTotal(3)
		c.applyPlanError(map[string]any{"kind": "plan_aborted_call_terminated", "index": 2})
		c.applyPlanError(map[string]any{"kind": "plan_aborted_call_terminated"}) // index absent
		v, _ := c.PlanView()
		if v.State != "aborted" {
			t.Fatalf("view=%+v want aborted", v)
		}
		if v.FailedIndex != -1 {
			t.Fatalf("FailedIndex=%d want -1 — a missing index must read as UNKNOWN; "+
				"0 tells the agent that step 0 aborted the call", v.FailedIndex)
		}
	})
}
