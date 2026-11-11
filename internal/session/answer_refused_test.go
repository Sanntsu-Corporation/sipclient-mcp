package session

// CF-131: a call_answer whose Answer the UA refused (the 422, 488 or 500 it
// sent, with the dialog torn down) ends the daemon call and never appends
// `answered`.

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// answerAgent is nopAgent with a scripted Answer.
type answerAgent struct {
	nopAgent
	answer func(AnswerRequest) error
}

func (a answerAgent) Answer(_ context.Context, req AnswerRequest) error { return a.answer(req) }

// answerRig opens a manager whose UA runs answer, and one ringing inbound call.
func answerRig(t *testing.T, answer func(AnswerRequest) error) (*Manager, *ToolService, *Call, context.Context) {
	t.Helper()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, nil), Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return answerAgent{answer: answer}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, NewToolService(m), mustCall(t, m, "s1"), ctx
}

func eventTypes(c *Call) []EventType {
	evs, _, _ := c.Events(0)
	var out []EventType
	for _, e := range evs {
		out = append(out, e.Type)
	}
	return out
}

func count(c *Call, want EventType) int {
	n := 0
	for _, e := range eventTypes(c) {
		if e == want {
			n++
		}
	}
	return n
}

func TestRFC3261_NEWC19_RefusedAnswerEndsTheDaemonCall(t *testing.T) {
	m, ts, c, ctx := answerRig(t, func(AnswerRequest) error {
		return &AnswerRefusedError{Status: 422, Reason: "Session Interval Too Small", Err: apierr.PreconditionFailed("sent 422")}
	})
	_, err := ts.CallAnswer(ctx, "s1", CallAnswerInput{Call: string(c.Handle())})
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("call_answer error = %v, want precondition_failed", err)
	}
	if got := c.State(); got != StateTerminated {
		t.Fatalf("state = %q, want terminated", got)
	}
	if got := c.TerminationReason(); got != "rejected_locally" {
		t.Errorf("termination_reason = %q, want rejected_locally", got)
	}
	if n := count(c, EventAnswered); n != 0 {
		t.Errorf("%d answered events, want 0", n)
	}
	evs, _, _ := c.Events(0)
	last := evs[len(evs)-1]
	if last.Type != EventBye || last.Detail["sip_code"] != 422 {
		t.Errorf("last event %+v, want bye with sip_code 422", last)
	}
	_, err = ts.CallHangup(ctx, "s1", CallHangupInput{Call: string(c.Handle())})
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Errorf("call_hangup = %v, want precondition_failed (the call is retained, not not_found)", err)
	}
	if per, total := m.DebugLiveCallCounts("s1"); per != 0 || total != 0 {
		t.Errorf("live calls (%d, %d), want (0, 0): RecordTermination must have run once", per, total)
	}
}

func TestCallAnswerRefused488KeepsTheMediaNegotiationCode(t *testing.T) {
	_, ts, c, ctx := answerRig(t, func(AnswerRequest) error {
		return &AnswerRefusedError{Status: 488, Reason: "Not Acceptable Here", Err: apierr.MediaNegotiation("no_common_codec", map[string]any{}, "no common codec")}
	})
	_, err := ts.CallAnswer(ctx, "s1", CallAnswerInput{Call: string(c.Handle())})
	if apierr.CodeOf(err) != apierr.CodeMediaNegotiation {
		t.Fatalf("call_answer error = %v, want media_negotiation", err)
	}
	if c.State() != StateTerminated || c.TerminationReason() != "rejected_locally" {
		t.Errorf("state %q reason %q, want terminated rejected_locally", c.State(), c.TerminationReason())
	}
}

func TestCallAnswerOtherErrorKeepsTodaysOutcome(t *testing.T) {
	_, ts, c, ctx := answerRig(t, func(AnswerRequest) error { return apierr.Internal("", "bind") })
	if _, err := ts.CallAnswer(ctx, "s1", CallAnswerInput{Call: string(c.Handle())}); err == nil {
		t.Fatal("call_answer succeeded")
	}
	if c.State() != StateAnswered || count(c, EventAnswered) != 1 {
		t.Errorf("state %q with %d answered events, want answered with 1", c.State(), count(c, EventAnswered))
	}
}

func TestCallAnswerSuccessAppendsAnsweredOnce(t *testing.T) {
	_, ts, c, ctx := answerRig(t, func(req AnswerRequest) error {
		if req.OnAnswered == nil {
			t.Error("AnswerRequest.OnAnswered is nil")
			return nil
		}
		req.OnAnswered()
		return nil
	})
	if _, err := ts.CallAnswer(ctx, "s1", CallAnswerInput{Call: string(c.Handle())}); err != nil {
		t.Fatal(err)
	}
	if n := count(c, EventAnswered); n != 1 {
		t.Errorf("%d answered events, want 1", n)
	}
}

func TestCallAnswerSuccessWithoutTheHookStillNotes(t *testing.T) {
	_, ts, c, ctx := answerRig(t, func(AnswerRequest) error { return nil })
	if _, err := ts.CallAnswer(ctx, "s1", CallAnswerInput{Call: string(c.Handle())}); err != nil {
		t.Fatal(err)
	}
	if n := count(c, EventAnswered); n != 1 {
		t.Errorf("%d answered events, want 1", n)
	}
}

// I6: a refusal that finds the call already noted (or terminal) changes nothing
// and CallAnswer does not record a termination it did not make.
func TestTryAnswerRefusedOnANotedCallIsPrecondition(t *testing.T) {
	c := newTestCall(t, StateAnswered)
	c.NoteAnswered(time.Unix(1000, 0))
	err := c.TryAnswerRefused(time.Unix(1000, 0), 422, "x")
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("err = %v, want precondition_failed", err)
	}
	if c.State() != StateAnswered || len(eventTypes(c)) != 1 {
		t.Errorf("state %q events %v, want answered with only the answered event", c.State(), eventTypes(c))
	}
}
