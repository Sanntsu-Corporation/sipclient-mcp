// Task 9: media_play/media_record_start/media_record_stop tool handlers.
//
// THIS FILE IS package session_test, NOT package session. internal/session
// cannot import internal/testutil/fakes from an internal test file (fakes
// imports session, so package session -> fakes -> session would be an
// import cycle the Go compiler rejects). Every field this file scripts on
// fakes.UserAgent (PlayDurationMs, PlayErr, RecordStartName, RecordStopInfo,
// RecordStopDurationMs) already exists — added by Tasks 5 and 6 — so no fake
// changes are needed here (Rule 16 reuse).
package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

// newMediaToolFixture builds a Manager + ToolService over a fakes.UserAgent
// (reusing capture_test.go's newFixture/mustDial, Rule 16) and dials one call
// in session "s1". The call sits in `dialing` (mustDial does not answer it) —
// neither MediaPlay/MediaRecordStart/MediaRecordStop gates on call state, and
// fakes.UserAgent returns its scripted values regardless of state, matching
// how quality_get's own tests already work against an unanswered fixture call.
func newMediaToolFixture(t *testing.T) (*session.ToolService, context.Context, *fakes.UserAgent, string) {
	t.Helper()
	ua := fakes.NewUserAgent()
	m, ts, ctx, uaHandle := newFixture(t, fakes.NewArtifactStore(), fakes.NewTap(),
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return ua, nil })
	callHandle, _ := mustDial(t, m, ts, "s1", uaHandle, nil)
	return ts, ctx, ua, callHandle
}

func TestMediaPlayResolvesAndReturnsDuration(t *testing.T) {
	ts, sess, ua, call := newMediaToolFixture(t)
	ua.PlayDurationMs = 1200

	out, err := ts.MediaPlay(sess, "s1", session.MediaPlayInput{Call: call, Prompt: "prompt-1"})
	if err != nil {
		t.Fatalf("MediaPlay: %v", err)
	}
	res := out.(map[string]any)
	if res["prompt"] != "prompt-1" || res["duration_ms"].(int64) != 1200 {
		t.Fatalf("out=%v", res)
	}
}

func TestMediaPlayPropagatesInvalidArgument(t *testing.T) {
	ts, sess, ua, call := newMediaToolFixture(t)
	ua.PlayErr = apierr.InvalidArgument("unregistered prompt x")
	if _, err := ts.MediaPlay(sess, "s1", session.MediaPlayInput{Call: call, Prompt: "x"}); apierr.CodeOf(err) != apierr.CodeInvalidArgument {
		t.Fatalf("code=%v want invalid_argument", apierr.CodeOf(err))
	}
}

func TestMediaRecordStopReturnsFormat(t *testing.T) {
	ts, sess, ua, call := newMediaToolFixture(t)
	ua.RecordStartName = "recording.wav"
	ua.RecordStopInfo = session.ArtifactInfo{Name: "recording.wav", URI: "mcp://sipclient/artifacts/x/recording.wav", Bytes: 6444}
	ua.RecordStopDurationMs = 5000

	if _, err := ts.MediaRecordStart(sess, "s1", session.MediaRecordStartInput{Call: call}); err != nil {
		t.Fatalf("MediaRecordStart: %v", err)
	}
	out, err := ts.MediaRecordStop(sess, "s1", session.MediaRecordStopInput{Call: call})
	if err != nil {
		t.Fatalf("MediaRecordStop: %v", err)
	}
	res := out.(map[string]any)
	format := res["format"].(map[string]any)
	if format["sample_rate"] != 8000 || format["channels"] != 1 || format["bits"] != 16 {
		t.Fatalf("format=%v want 8000/1/16", format)
	}
	if res["bytes"].(int64) != 6444 || res["uri"] != "mcp://sipclient/artifacts/x/recording.wav" {
		t.Fatalf("out=%v", res)
	}
}

// Task 10: media_plan validation + threading, call_status.media_plan, and the
// UAEventPlanStep/UAEventRecordStart/UAEventRecordStop -> EventType mapping.

// call_dial threads a validated media_plan through to sipua's DialRequest.
func TestCallDialThreadsMediaPlanIntoDialRequest(t *testing.T) {
	ua := fakes.NewUserAgent()
	m, ts, ctx, uaHandle := newFixture(t, fakes.NewArtifactStore(), fakes.NewTap(),
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return ua, nil })

	out, err := ts.CallDial(ctx, "s1", session.CallDialInput{
		UA:    uaHandle,
		ToURI: "sip:bob@example.com",
		MediaPlan: []map[string]any{
			{"op": "wait", "duration_ms": float64(1000)},
			{"op": "hangup"},
		},
	})
	if err != nil {
		t.Fatalf("call_dial: %v", err)
	}
	res := out.(map[string]any)
	h, _ := res["call_handle"].(string)
	c, err := m.ResolveCall(ctx, "s1", session.Handle(h))
	if err != nil {
		t.Fatalf("ResolveCall: %v", err)
	}
	// Poll for the Call-ID handshake to settle — the same settle signal
	// mustDial (capture_test.go) uses. The fake's Dial appends to ua.Dials
	// under its mutex and only THEN returns DialResult, and CallDial's
	// goroutine only sets the Call's CallID after Dial returns, so observing
	// a non-empty CallID here gives this read a happens-before edge over the
	// fake's mutexed Dials append.
	deadline := time.Now().Add(2 * time.Second)
	for c.CallID() == "" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.CallID() == "" {
		t.Fatal("call_dial's goroutine never settled a Call-ID within the deadline")
	}

	if len(ua.Dials) != 1 {
		t.Fatalf("Dials=%d want 1", len(ua.Dials))
	}
	plan := ua.Dials[0].MediaPlan
	if len(plan) != 2 || plan[0].Op != "wait" || plan[0].DurationMs != 1000 || plan[1].Op != "hangup" {
		t.Fatalf("threaded MediaPlan=%+v", plan)
	}
}

// call_dial with an invalid media_plan is rejected invalid_argument, end to
// end, before any call is created.
func TestCallDialRejectsInvalidMediaPlan(t *testing.T) {
	ua := fakes.NewUserAgent()
	_, ts, ctx, uaHandle := newFixture(t, fakes.NewArtifactStore(), fakes.NewTap(),
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return ua, nil })
	_, err := ts.CallDial(ctx, "s1", session.CallDialInput{
		UA:        uaHandle,
		ToURI:     "sip:bob@example.com",
		MediaPlan: []map[string]any{{"op": "frobnicate"}},
	})
	if apierr.CodeOf(err) != apierr.CodeInvalidArgument {
		t.Fatalf("code=%v want invalid_argument", apierr.CodeOf(err))
	}
	if len(ua.Dials) != 0 {
		t.Fatalf("Dials=%d want 0: a rejected plan must not reach sipua", len(ua.Dials))
	}
}

// call_answer with an invalid media_plan is rejected invalid_argument before
// TryAnswer/sipua's Answer ever run.
func TestCallAnswerRejectsInvalidMediaPlan(t *testing.T) {
	ts, ctx, ua, call := newMediaToolFixture(t)
	_, err := ts.CallAnswer(ctx, "s1", session.CallAnswerInput{
		Call:      call,
		MediaPlan: []map[string]any{{"op": "frobnicate"}},
	})
	if apierr.CodeOf(err) != apierr.CodeInvalidArgument {
		t.Fatalf("code=%v want invalid_argument", apierr.CodeOf(err))
	}
	if len(ua.Answers) != 0 {
		t.Fatalf("Answers=%d want 0: a rejected plan must not reach sipua", len(ua.Answers))
	}
}

// call_status surfaces media_plan when the Call's own plan_step event stream
// (§2.3) has a plan registered on it. media_plan is Call-sourced, not
// UA-sourced (Task 5) — the fixture drives a real *session.Call through
// SetPlanTotal and a UAEventPlanStep, not the fake UA's MediaPlanView fields.
func TestCallStatusIncludesMediaPlan(t *testing.T) {
	uaFake := fakes.NewUserAgent()
	m, ts, ctx, uaHandle := newFixture(t, fakes.NewArtifactStore(), fakes.NewTap(),
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return uaFake, nil })
	call, c := mustDial(t, m, ts, "s1", uaHandle, nil)
	c.SetPlanTotal(3)
	m.HandleUAEventForTest(ctx, session.Handle(uaHandle), session.UAEvent{
		Kind: session.UAEventPlanStep, DialogID: c.DialogID(),
		Detail: map[string]any{"index": 0, "op": "play", "status": "ok"},
	})

	out, err := ts.CallStatus(ctx, "s1", session.CallStatusInput{Call: call})
	if err != nil {
		t.Fatalf("call_status: %v", err)
	}
	res := out.(map[string]any)
	mp, ok := res["media_plan"].(map[string]any)
	if !ok {
		t.Fatalf("out=%v: no media_plan block", res)
	}
	if mp["state"] != "running" || mp["steps_total"] != 3 || mp["steps_completed"] != 1 || mp["failed_index"] != -1 {
		t.Fatalf("media_plan=%v", mp)
	}
}

// call_status omits media_plan when no plan was ever registered on the Call
// (§2.3: the readout is Call-sourced, not UA-sourced).
func TestCallStatusOmitsMediaPlanWhenAbsent(t *testing.T) {
	ts, ctx, _, call := newMediaToolFixture(t)
	out, err := ts.CallStatus(ctx, "s1", session.CallStatusInput{Call: call})
	if err != nil {
		t.Fatalf("call_status: %v", err)
	}
	res := out.(map[string]any)
	if _, ok := res["media_plan"]; ok {
		t.Fatalf("out=%v: media_plan should be absent", res)
	}
}

// UAEventPlanStep/UAEventRecordStart/UAEventRecordStop map onto
// EventPlanStep/EventRecordStart/EventRecordStop in the call's event log.
func TestUAEventPlanAndRecordEventsAppendEvents(t *testing.T) {
	ua := fakes.NewUserAgent()
	m, ts, ctx, uaHandle := newFixture(t, fakes.NewArtifactStore(), fakes.NewTap(),
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return ua, nil })
	_, call := mustDial(t, m, ts, "s1", uaHandle, nil)

	cases := []struct {
		kind session.UAEventKind
		want session.EventType
	}{
		{session.UAEventPlanStep, session.EventPlanStep},
		{session.UAEventRecordStart, session.EventRecordStart},
		{session.UAEventRecordStop, session.EventRecordStop},
	}
	for _, c := range cases {
		m.HandleUAEventForTest(ctx, session.Handle(uaHandle), session.UAEvent{
			Kind: c.kind, DialogID: call.DialogID(), Detail: map[string]any{"index": 0},
		})
	}

	evs, _, _ := call.Events(0)
	for _, c := range cases {
		found := false
		for _, e := range evs {
			if e.Type == c.want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("no %s event appended for kind %s; events=%+v", c.want, c.kind, evs)
		}
	}
}
