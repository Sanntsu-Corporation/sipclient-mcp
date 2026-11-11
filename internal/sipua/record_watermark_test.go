package sipua

import (
	"context"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/artifact"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// liveCallSet is a minimal artifact.LiveCallChecker fake for these tests: the
// handles in the set are reported live, everything else is not.
type liveCallSet map[string]bool

func (l liveCallSet) IsLive(h string) bool { return l[h] }

// prefillPastWatermark writes n bytes into a new artifact under the given call
// dir. Whether that data is live or reclaimable-non-live is determined by
// whatever artifact.LiveCallChecker the caller has installed on store (via
// store.SetLiveCallChecker) — this helper itself is agnostic to liveness.
func prefillPastWatermark(t *testing.T, store *artifact.Store, callHandle string, n int) {
	t.Helper()
	if err := store.OpenCallDir(context.Background(), callHandle); err != nil {
		t.Fatal(err)
	}
	w, err := store.Create(context.Background(), callHandle, "prefill.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, n)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestRecordStartResourceLimitWhenOverWatermark is the direct-call-path half
// of the §13.3 regression coverage: sipua.UA.RecordStart itself refuses a new
// recording when the store is at/over ArtifactMaxBytes AND nothing is
// evictable (all usage is genuinely live-call data), and does so BEFORE
// claiming the play-or-record slot.
func TestRecordStartResourceLimitWhenOverWatermark(t *testing.T) {
	store := artifact.New(t.TempDir(), clock.System())
	store.SetLiveCallChecker(liveCallSet{testCallHandle: true})
	prefillPastWatermark(t, store, testCallHandle, 4096)

	u := &UA{cfg: Config{Artifacts: store, ArtifactMaxBytes: 1}}
	ml := &mediaLoop{emit: func(session.UAEvent) {}}
	ml.assemble(nil, nil)
	d := &dialog{id: "d1", callID: "call-abc", phase: phaseAnswered, mediaLoop: ml}
	u.register(d)

	_, err := u.RecordStart(context.Background(), "d1", testCallHandle, "")
	if apierr.CodeOf(err) != apierr.CodeResourceLimit {
		t.Fatalf("code=%v err=%v want resource_limit", apierr.CodeOf(err), err)
	}
	if ml.currentOp() != opNone {
		t.Fatal("RecordStart claimed the play-or-record slot despite the watermark refusal")
	}
}

// TestRecordStartAllowedWhenNonLiveHeadroomExists is the regression test for
// the bug this change fixes: the watermark guard used to compare TOTAL usage
// (including protected live-call data) against the cap, so a store could get
// permanently wedged the moment live calls alone pushed it over the cap, even
// though non-live (janitor-reclaimable) data existed and would bring it back
// under cap on the very next sweep. Here total usage is over the (tiny)
// watermark, but the excess lives entirely in a NON-live call dir, so
// NonLiveUsageBytes > 0 and the guard must allow the new recording rather
// than refuse it.
func TestRecordStartAllowedWhenNonLiveHeadroomExists(t *testing.T) {
	const liveCall = "call-live"
	const nonLiveCall = "call-old-evictable"

	store := artifact.New(t.TempDir(), clock.System())
	store.SetLiveCallChecker(liveCallSet{liveCall: true})
	prefillPastWatermark(t, store, liveCall, 2048)    // protected, not evictable
	prefillPastWatermark(t, store, nonLiveCall, 4096) // evictable headroom

	u := &UA{cfg: Config{Artifacts: store, ArtifactMaxBytes: 1}}
	ml := &mediaLoop{emit: func(session.UAEvent) {}}
	ml.assemble(nil, nil)
	d := &dialog{id: "d1", callID: "call-abc", phase: phaseAnswered, mediaLoop: ml}
	u.register(d)

	name, err := u.RecordStart(context.Background(), "d1", liveCall, "")
	if err != nil {
		t.Fatalf("RecordStart refused despite non-live headroom: %v", err)
	}
	if name == "" {
		t.Fatal("RecordStart returned an empty artifact name on success")
	}
}

// TestMediaPlanRecordStepResourceLimitWhenOverWatermark is the REGRESSION test
// for the bug this change fixes: a media_plan's record step calls
// mp.u.RecordStart directly (bypassing ToolService), so before this fix it was
// never subject to the §13.3 watermark guard at all. This proves the
// plan-driven path is now protected via the same UA.RecordStart choke point
// the discrete media_record_start tool goes through.
func TestMediaPlanRecordStepResourceLimitWhenOverWatermark(t *testing.T) {
	rec := &recordingEmit{}
	store := artifact.New(t.TempDir(), clock.System())
	const callHandle = "call-plan-watermark"
	store.SetLiveCallChecker(liveCallSet{callHandle: true})
	prefillPastWatermark(t, store, callHandle, 4096)

	ml := &mediaLoop{emit: rec.emit}
	ml.assemble(nil, nil)
	u := &UA{cfg: Config{Artifacts: store, ArtifactMaxBytes: 1}}
	d := &dialog{id: "d1", phase: phaseAnswered, mediaLoop: ml, callHandle: callHandle}
	u.register(d)

	steps := []session.MediaPlanStep{{Op: "record", DurationMs: 5}}
	u.launchMediaPlan(d, ml, steps)

	waitFor(t, func() bool {
		v, ok := u.MediaPlanView("d1")
		return ok && v.State == "failed"
	})
	v, _ := u.MediaPlanView("d1")
	if v.FailedOp != "record" {
		t.Fatalf("view=%+v want FailedOp=record", v)
	}

	var sawFailure bool
	for _, ev := range rec.snapshot() {
		if ev.Kind == session.UAEventMediaError && ev.Detail["kind"] == "plan_step_failed" {
			sawFailure = true
			if ev.Detail["code"] != string(apierr.CodeResourceLimit) {
				t.Fatalf("plan_step_failed detail=%v want code=resource_limit", ev.Detail)
			}
		}
	}
	if !sawFailure {
		t.Fatal("no plan_step_failed error{} event emitted for the record step")
	}
}
