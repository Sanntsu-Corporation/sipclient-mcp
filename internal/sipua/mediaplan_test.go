package sipua

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/artifact"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// recordingEmit captures UAEvents the executor emits.
type recordingEmit struct {
	mu  sync.Mutex
	evs []session.UAEvent
}

func (r *recordingEmit) emit(ev session.UAEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
}

func (r *recordingEmit) snapshot() []session.UAEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]session.UAEvent, len(r.evs))
	copy(out, r.evs)
	return out
}

func TestMediaPlanHappyPathRunsToCompletion(t *testing.T) {
	rec := &recordingEmit{}
	ml := &mediaLoop{emit: rec.emit}
	ml.assemble(nil, nil)
	u := &UA{}
	d := &dialog{id: "d1", phase: phaseAnswered, mediaLoop: ml}
	u.register(d)

	// A plan of two waits (deterministic, no prompt/artifact deps needed to
	// prove sequencing + completion state).
	steps := []session.MediaPlanStep{
		{Op: "wait", DurationMs: 5},
		{Op: "wait", DurationMs: 5},
	}
	u.launchMediaPlan(d, ml, steps)

	waitFor(t, func() bool {
		v, ok := u.MediaPlanView("d1")
		return ok && v.State == "completed"
	})
	v, _ := u.MediaPlanView("d1")
	if v.StepsTotal != 2 || v.StepsCompleted != 2 {
		t.Fatalf("view=%+v want total=2 completed=2", v)
	}
	// plan_step events: entry+completion per step, in order.
	var planSteps int
	for _, ev := range rec.snapshot() {
		if ev.Kind == session.UAEventPlanStep {
			planSteps++
		}
	}
	if planSteps != 4 {
		t.Fatalf("plan_step events=%d want 4 (2 steps × entry+completion)", planSteps)
	}
}

func TestMediaPlanAbortsOnStepFailureLeavesCallOpen(t *testing.T) {
	rec := &recordingEmit{}
	ml := &mediaLoop{emit: rec.emit}
	ml.assemble(nil, nil)
	// Pre-claim the busy slot so the first play step's precondition fails,
	// standing in for the §5 "[{play,wait_complete:false},{play}]" failure.
	ml.claimOp(opPlay, nil)
	u := &UA{cfg: Config{Prompts: map[string]string{}}} // unregistered prompt also fails
	d := &dialog{id: "d1", phase: phaseAnswered, mediaLoop: ml}
	u.register(d)

	steps := []session.MediaPlanStep{
		{Op: "play", Prompt: "prompt-1", Repeat: 1}, // fails: unregistered prompt
		{Op: "wait", DurationMs: 5},                 // must NOT run
	}
	u.launchMediaPlan(d, ml, steps)

	waitFor(t, func() bool {
		v, ok := u.MediaPlanView("d1")
		return ok && v.State == "failed"
	})
	v, _ := u.MediaPlanView("d1")
	if v.FailedIndex != 0 || v.FailedOp != "play" || v.StepsCompleted != 0 {
		t.Fatalf("view=%+v want failedIndex=0 op=play completed=0", v)
	}
	// Exactly one plan_step failed + one error{plan_step_failed}; NO plan_step
	// for index 1.
	var failedSteps, errs, idx1 int
	for _, ev := range rec.snapshot() {
		if ev.Kind == session.UAEventPlanStep && ev.Detail["status"] == "failed" {
			failedSteps++
		}
		if ev.Kind == session.UAEventMediaError && ev.Detail["kind"] == "plan_step_failed" {
			errs++
		}
		if ev.Kind == session.UAEventPlanStep {
			if i, _ := ev.Detail["index"].(int); i == 1 {
				idx1++
			}
		}
	}
	if failedSteps != 1 || errs != 1 || idx1 != 0 {
		t.Fatalf("failedSteps=%d errs=%d idx1=%d want 1,1,0", failedSteps, errs, idx1)
	}
	// The call is still answered/open.
	if d.phase != phaseAnswered {
		t.Fatal("plan failure tore the call down")
	}
}

// TestMediaPlanCallTerminatedMidPlanAborts proves the plan-abort behavior AS
// PRODUCTION ACTUALLY EXPOSES IT: every real teardown path (Hangup, onBye,
// teardownDialog) forgets the dialog from the UA's registry as part of tearing
// down, and MediaPlanView starts with u.lookup(dialogID) — so once teardown
// completes, MediaPlanView permanently returns ok=false. A plan that aborts
// due to call termination is therefore never observable as
// (ok=true, State=="aborted") in production; it is only observable via the
// error{kind:"plan_aborted_call_terminated"} event, which fires from the
// plan's own goroutine independent of the registry.
//
// This test drives REAL teardown (u.teardownDialog, the same shared
// resource-release path used by the answer-side reject, offering-side
// ACK-then-BYE and admission-reject call sites — not a bare close(ml.done)
// stand-in) so the dialog is genuinely forgotten, then asserts both halves of
// that reality: MediaPlanView eventually goes unobservable, AND the abort
// logic itself genuinely ran.
func TestMediaPlanCallTerminatedMidPlanAborts(t *testing.T) {
	rec := &recordingEmit{}
	ml := &mediaLoop{emit: rec.emit}
	ml.assemble(nil, nil)
	u := &UA{}
	d := &dialog{id: "d1", phase: phaseAnswered, mediaLoop: ml}
	u.register(d)

	steps := []session.MediaPlanStep{{Op: "wait", DurationMs: 60000}} // long wait
	u.launchMediaPlan(d, ml, steps)

	// Drive REAL teardown: the same registry-forgetting + media-loop-stop path
	// Hangup/onBye/the reject sites all share. This both closes ml.done (which
	// the plan's run()/sleep() select on to detect termination) and removes
	// "d1" from u.calls.byID.
	time.Sleep(20 * time.Millisecond)
	u.teardownDialog(d)

	// Half 1: the abort logic itself genuinely ran. This is observable via the
	// event log regardless of registry state, since abortTerminated emits
	// through mp.ml.emit directly.
	waitFor(t, func() bool {
		for _, ev := range rec.snapshot() {
			if ev.Kind == session.UAEventMediaError && ev.Detail["kind"] == "plan_aborted_call_terminated" {
				return true
			}
		}
		return false
	})
	var aborted int
	for _, ev := range rec.snapshot() {
		if ev.Kind == session.UAEventMediaError && ev.Detail["kind"] == "plan_aborted_call_terminated" {
			aborted++
		}
	}
	if aborted != 1 {
		t.Fatalf("plan_aborted_call_terminated events=%d want 1", aborted)
	}

	// Half 2: what production ACTUALLY exposes — once the dialog is forgotten,
	// MediaPlanView can never again report ok=true, not even with a terminal
	// "aborted" state. (The dialog was already forgotten by teardownDialog
	// above, so this holds immediately; no further waiting is needed.)
	if v, ok := u.MediaPlanView("d1"); ok {
		t.Fatalf("MediaPlanView after teardown = (ok=true, view=%+v); want ok=false — the dialog was forgotten, so the plan's terminal state is unobservable this way in production", v)
	}
}

func TestMediaPlanRecordStepEmitsRecordStartAndStop(t *testing.T) {
	rec := &recordingEmit{}
	store := artifact.New(t.TempDir(), clock.System())
	ml := &mediaLoop{emit: rec.emit}
	ml.assemble(nil, nil)
	u := &UA{cfg: Config{Artifacts: store}}
	d := &dialog{id: "d1", phase: phaseAnswered, mediaLoop: ml, callHandle: "call-plan-1"}
	u.register(d)
	if err := store.OpenCallDir(context.Background(), "call-plan-1"); err != nil {
		t.Fatal(err)
	}

	steps := []session.MediaPlanStep{{Op: "record", DurationMs: 5}}
	u.launchMediaPlan(d, ml, steps)

	waitFor(t, func() bool {
		v, ok := u.MediaPlanView("d1")
		return ok && v.State == "completed"
	})
	var starts, stops int
	for _, ev := range rec.snapshot() {
		if ev.Kind == session.UAEventRecordStart {
			starts++
			if ev.Detail["name"] != "recording.wav" {
				t.Fatalf("record_start detail=%v want name=recording.wav", ev.Detail)
			}
		}
		if ev.Kind == session.UAEventRecordStop {
			stops++
			if ev.Detail["name"] != "recording.wav" {
				t.Fatalf("record_stop detail=%v want name=recording.wav", ev.Detail)
			}
		}
	}
	if starts != 1 || stops != 1 {
		t.Fatalf("record_start=%d record_stop=%d want 1,1", starts, stops)
	}
}

// TestMediaPlanRecordStepThreadsExplicitName is the Rule 9 mutation proof for
// M2's allowlist fix: a media_plan record step's `name` field used to be
// decoded (mediaplan_validate.go) but then discarded — execStep always called
// RecordStart with "", so RecordStart's own default-naming counter took over
// and every plan-driven recording was named recording.wav/recording-N.wav
// regardless of what the caller asked for. RecordStart passes a non-empty
// name straight through UNCHANGED (call.go's RecordStart: `resolved := name`,
// no extension appended when non-empty) — so "greeting" resolves to exactly
// "greeting", not "greeting.wav".
func TestMediaPlanRecordStepThreadsExplicitName(t *testing.T) {
	rec := &recordingEmit{}
	store := artifact.New(t.TempDir(), clock.System())
	ml := &mediaLoop{emit: rec.emit}
	ml.assemble(nil, nil)
	u := &UA{cfg: Config{Artifacts: store}}
	d := &dialog{id: "d1", phase: phaseAnswered, mediaLoop: ml, callHandle: "call-plan-1"}
	u.register(d)
	if err := store.OpenCallDir(context.Background(), "call-plan-1"); err != nil {
		t.Fatal(err)
	}

	steps := []session.MediaPlanStep{{Op: "record", DurationMs: 5, Name: "greeting"}}
	u.launchMediaPlan(d, ml, steps)

	waitFor(t, func() bool {
		v, ok := u.MediaPlanView("d1")
		return ok && v.State == "completed"
	})
	var starts, stops int
	for _, ev := range rec.snapshot() {
		if ev.Kind == session.UAEventRecordStart {
			starts++
			if ev.Detail["name"] != "greeting" {
				t.Fatalf("record_start detail=%v want name=greeting", ev.Detail)
			}
		}
		if ev.Kind == session.UAEventRecordStop {
			stops++
			if ev.Detail["name"] != "greeting" {
				t.Fatalf("record_stop detail=%v want name=greeting", ev.Detail)
			}
		}
	}
	if starts != 1 || stops != 1 {
		t.Fatalf("record_start=%d record_stop=%d want 1,1", starts, stops)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			t.Fatal("condition not met within 2s")
		case <-time.After(2 * time.Millisecond):
		}
	}
}
