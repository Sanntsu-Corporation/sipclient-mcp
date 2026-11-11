package session

import (
	"context"
	"testing"
	"time"
)

func TestTerminationReasonForMediaNegotiation(t *testing.T) {
	got, err := terminationReasonFor(UACauseMediaNegotiationFailed)
	if err != nil {
		t.Fatalf("terminationReasonFor: %v", err)
	}
	if got != "media_negotiation_failed" {
		t.Fatalf("reason=%q", got)
	}
}

func TestTryMediaNegotiationFailedTerminatesWithDetail(t *testing.T) {
	// newTestCall(t, state) is the package's ONE test Call constructor
	// (call_test.go:11) — it takes no Direction argument (hardcoded Inbound),
	// which is irrelevant here: TryMediaNegotiationFailed's behavior does not
	// branch on direction.
	c := newTestCall(t, StateAnswered)
	detail := map[string]any{"kind": "answer_codec_not_offered",
		"offered": []string{"PCMU"}, "answered": []string{"opus"}, "action": "ack_then_bye"}
	if err := c.TryMediaNegotiationFailed(time.Unix(1, 0), detail); err != nil {
		t.Fatalf("TryMediaNegotiationFailed: %v", err)
	}
	if c.State() != StateTerminated {
		t.Fatalf("state=%s want terminated", c.State())
	}
	if c.TerminationReason() != "media_negotiation_failed" {
		t.Fatalf("reason=%q", c.TerminationReason())
	}
	// Events(since) (evs []Event, truncatedBefore, nextSince int64) is the
	// real accessor (call.go:228) — there is no lastEventForTest helper. The
	// terminal EventError is the last entry in the full log (since=0).
	evs, _, _ := c.Events(0)
	if len(evs) == 0 {
		t.Fatal("no events recorded")
	}
	last := evs[len(evs)-1]
	if last.Type != EventError || last.Detail["kind"] != "answer_codec_not_offered" {
		t.Fatalf("terminal event=%+v", last)
	}
}

// TestHandleDialogEndedMediaNegotiationFailedTerminatesCall is Task 9's
// Manager-level pin for handleDialogEnded's UACauseMediaNegotiationFailed
// branch (uaevent.go:163-171). Every other cause in that switch falls through
// to terminationReasonFor + TryTerminate + EventBye; a naive edit (e.g.
// collapsing the branches, or reordering the switch) could silently route
// this cause down that generic path instead. That would still leave
// TerminationReason() == "media_negotiation_failed" (both paths reach
// StateTerminated with the same reason string), so the state and reason
// assertions alone would NOT catch the regression — only checking the
// terminal event's Type (EventError, not EventBye) and its Detail payload
// pins the §11.2.1 contract that TryMediaNegotiationFailed provides and
// TryTerminate/EventBye does not.
func TestHandleDialogEndedMediaNegotiationFailedTerminatesCall(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	c.setDialogIdentity("dlg-medianeg", "callid-medianeg")

	detail := map[string]any{"kind": "answer_codec_not_offered",
		"offered": []string{"PCMU"}, "answered": []string{"opus"}, "action": "ack_then_bye"}

	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
		Kind: UAEventDialogEnded, Cause: UACauseMediaNegotiationFailed,
		DialogID: "dlg-medianeg", CallID: "callid-medianeg", Detail: detail, At: fc.Now(),
	})

	if got := c.State(); got != StateTerminated {
		t.Fatalf("state = %q, want terminated", got)
	}
	if got := c.TerminationReason(); got != "media_negotiation_failed" {
		t.Fatalf("TerminationReason() = %q, want media_negotiation_failed", got)
	}

	evs, _, _ := c.Events(0)
	if len(evs) == 0 {
		t.Fatal("no events recorded")
	}
	last := evs[len(evs)-1]
	if last.Type != EventError {
		t.Fatalf("terminal event Type = %v, want EventError (NOT EventBye)", last.Type)
	}
	if last.Detail["kind"] != detail["kind"] {
		t.Fatalf("terminal event Detail[kind] = %v, want %v", last.Detail["kind"], detail["kind"])
	}
}
