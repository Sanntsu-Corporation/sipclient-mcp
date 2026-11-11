package sipua_test

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestMediaPlanHangupStepEndsCallWithoutFalseAbort pins call.go's mediaPlan.run
// (~line 428): `if code == "" && mp.terminated() && step.Op != "hangup"` exists
// specifically so a call ended by the PLAN'S OWN hangup step is never mistaken
// for an unexpected mid-step termination. Before this test, nothing in the repo
// drove a media_plan through to a real "hangup" step, so a mutant deleting
// `&& step.Op != "hangup"` would pass the whole suite silently.
//
// This drives a REAL u.Hangup (BuildByeFromInvite + an actual BYE over the
// loopback UDP transport to a fake peer, via ua.Dial's MediaPlan field and
// the SAME newDirectUA/peer harness call_outbound_test.go's Hangup tests use)
// rather than a simulated teardown (mediaplan_test.go's lightweight &UA{} +
// bare dialog{} harness cannot build/send a real BYE — Hangup needs a real
// d.invite/d.ok and a real transport). That real-Hangup path is the whole
// point: the guard must hold against genuine call teardown, not a stand-in.
//
// mediaPlan.execStep's "hangup" case calls u.Hangup, and Hangup forgets the
// dialog from the UA's registry (u.forgetLocked) BEFORE it even sends the BYE
// — the same production reality TestMediaPlanCallTerminatedMidPlanAborts
// documents for the abort path. So by the time the hangup step returns and
// run() reaches mp.setState("completed"), u.MediaPlanView can no longer see
// the dialog at all (ok=false), and polling it for State=="completed" is not
// a viable signal here. The plan's actual terminal state is instead provable
// by elimination from the event log, which mp emits independent of the
// registry: reaching "aborted" would emit plan_aborted_call_terminated,
// reaching "failed" would emit plan_step_failed and a "failed" plan_step for
// the hangup step — neither happens, and both steps get an "ok" plan_step,
// so the plan can only have reached "completed".
func TestMediaPlanHangupStepEndsCallWithoutFalseAbort(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	steps := []session.MediaPlanStep{
		{Op: "wait", DurationMs: 5},
		{Op: "hangup", Reason: "plan complete"},
	}
	if _, err := ua.Dial(context.Background(), session.DialRequest{
		ToURI:     "sip:bob@" + p.Addr(),
		MediaPlan: steps,
	}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	// The call was actually torn down by a real, plan-driven BYE (mirrors
	// TestHangupSendsExactlyOneBYE's own "did it really hang up" signal).
	p.WaitForBye(t, 2*time.Second)
	if n := p.Count("BYE"); n != 1 {
		t.Fatalf("peer saw %d BYEs, want exactly 1", n)
	}

	// Give the plan goroutine time to record the hangup step's own completion
	// (RawTransaction's 200 OK round trip finishes strictly after the BYE hits
	// the wire, so WaitForBye alone does not guarantee run() has returned).
	deadline := time.Now().Add(2 * time.Second)
	var planSteps int
	for time.Now().Before(deadline) {
		planSteps = 0
		for _, ev := range events() {
			if ev.Kind == session.UAEventPlanStep {
				planSteps++
			}
		}
		if planSteps >= 4 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if planSteps != 4 {
		t.Fatalf("plan_step events=%d want 4 (2 steps x entry+completion) within 2s", planSteps)
	}

	var okSteps, failedSteps, mediaErrors int
	for _, ev := range events() {
		if ev.Kind == session.UAEventPlanStep {
			switch ev.Detail["status"] {
			case "ok":
				okSteps++
			case "failed":
				failedSteps++
			}
		}
		if ev.Kind == session.UAEventMediaError {
			mediaErrors++
			t.Errorf("unexpected error event: %+v", ev)
		}
	}
	// THE regression-catching assertions: both steps (including the hangup
	// step itself) completed "ok", none "failed", and — the core claim — no
	// media_error of any kind fired. In particular no
	// plan_aborted_call_terminated, which would mean the `step.Op != "hangup"`
	// guard failed to suppress the false-abort signal for the plan's own
	// terminal hangup.
	if okSteps != 2 {
		t.Fatalf("plan_step ok events=%d want 2 (both steps completed, proving the plan reached \"completed\" rather than \"aborted\" or \"failed\")", okSteps)
	}
	if failedSteps != 0 {
		t.Fatalf("plan_step failed events=%d want 0", failedSteps)
	}
	if mediaErrors != 0 {
		t.Fatalf("media_error events=%d want 0 (no plan_aborted_call_terminated for the plan's own hangup step)", mediaErrors)
	}
}
