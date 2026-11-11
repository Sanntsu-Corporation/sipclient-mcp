package sipua_test

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// waitForCond polls cond until it holds or the deadline passes. The plan
// executor runs on its own goroutine and settles strictly after the events
// waitFor can match on, so a plan-state assertion needs a boolean poll rather
// than an event match.
func waitForCond(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within 3s")
}

// §10.7's step-failure acceptance in FULL. Every clause below is one of the
// design spec §8 requirements; none may be dropped.
func TestPlanDTMFNotSupportedAcceptance(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{StripTelephoneEvent: true},
	})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{
		ToURI: "sip:bob@" + p.Addr(),
		MediaPlan: []session.MediaPlanStep{
			{Op: "wait", DurationMs: 10},
			{Op: "dtmf", Digits: "1", Mode: "rfc2833", DurationMs: 100, GapMs: 50},
			{Op: "wait", DurationMs: 10},
		},
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	// 1. The plan fails at index 1 with not_supported.
	waitForCond(t, func() bool {
		v, ok := ua.MediaPlanView(res.DialogID)
		return ok && v.State == "failed"
	})
	v, _ := ua.MediaPlanView(res.DialogID)
	if v.FailedIndex != 1 || v.FailedOp != "dtmf" {
		t.Fatalf("view=%+v want failed at 1/dtmf", v)
	}
	if v.StepsCompleted != 1 {
		t.Fatalf("steps_completed=%d want 1 (only the first wait ran)", v.StepsCompleted)
	}

	// 2. No plan_step event for index 2, and the failure names not_supported.
	var sawNotSupported bool
	for _, ev := range events() {
		switch ev.Kind {
		case session.UAEventPlanStep:
			if idx, ok := ev.Detail["index"].(int); ok && idx == 2 {
				t.Fatal("a step after the failure must not run")
			}
		case session.UAEventMediaError:
			if ev.Detail["kind"] == "plan_step_failed" && ev.Detail["code"] == "not_supported" {
				sawNotSupported = true
			}
		}
	}
	if !sawNotSupported {
		t.Fatal("the failure must be reported as not_supported")
	}

	// 3. No BYE: the plan aborted, the CALL did not.
	if n := p.ByeCount(); n != 0 {
		t.Fatalf("%d BYEs on the wire — a step failure must not end the call", n)
	}

	// 4. The slot is free, so an inband send on the SAME call succeeds (§2.2).
	sent, _, err := ua.SendDTMF(context.Background(), res.DialogID, "1", session.DTMFModeInband, 20, 0)
	if err != nil {
		t.Fatalf("dtmf_send(inband) after the failed step must succeed: %v", err)
	}
	if sent != 1 {
		t.Fatalf("digits_sent=%d want 1", sent)
	}

	// 5. And an ordinary hangup still works.
	if err := ua.Hangup(context.Background(), res.DialogID, "done"); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	p.WaitForBye(t, 2*time.Second)
}

// §10.8's mode-report acceptance: with telephone-event NEGOTIATED, the same
// rfc2833 send succeeds — so the not_supported above is a real negotiation
// outcome and not a permanently broken arm.
func TestRFC2833SucceedsWhenTelephoneEventIsNegotiated(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	sent, emitted, err := ua.SendDTMF(context.Background(), res.DialogID, "123*#", session.DTMFModeRFC2833, 60, 40)
	if err != nil {
		t.Fatalf("SendDTMF(rfc2833): %v", err)
	}
	if sent != 5 {
		t.Fatalf("digits_sent=%d want 5", sent)
	}
	if emitted != 60 {
		t.Fatalf("emitted duration_ms=%d want 60 (three whole 20ms ticks)", emitted)
	}
}
