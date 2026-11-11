package session_test

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

// answerFakeCall drives a dialed call to answered through the fake UA's 200 —
// the same path a real outbound answer takes (handleResponse ->
// TryRemoteAnswer).
func answerFakeCall(t *testing.T, agent *fakes.UserAgent, c *session.Call) {
	t.Helper()
	agent.Emit(session.UAEvent{Kind: session.UAEventFinal, DialogID: c.DialogID(), Code: 200, Reason: "OK"})
	deadline := time.Now().Add(2 * time.Second)
	for c.State() != session.StateAnswered {
		if time.Now().After(deadline) {
			t.Fatalf("call never reached answered (state %q)", c.State())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCallTransferPassesTheBlindRequestThroughAndReturnsTheSpecShape(t *testing.T) {
	h := newMediaToolHarness(t)
	answerFakeCall(t, h.agent, h.call)
	var got session.TransferRequest
	h.agent.TransferFn = func(_ context.Context, req session.TransferRequest) (session.TransferResult, error) {
		got = req
		return session.TransferResult{Accepted: true, StatusCode: 202, Reason: "Accepted"}, nil
	}
	out, err := h.tools.CallTransfer(context.Background(), h.sess, session.CallTransferInput{
		Call: string(h.call.Handle()), Mode: "blind", Target: "sip:carol@example.com"})
	if err != nil {
		t.Fatalf("CallTransfer: %v", err)
	}
	if want := (session.TransferRequest{DialogID: h.call.DialogID(), Mode: session.TransferBlind, Target: "sip:carol@example.com"}); got != want {
		t.Fatalf("agent got %+v want %+v", got, want)
	}
	if want := map[string]any{"accepted": true, "status_code": 202, "reason": "Accepted"}; !reflect.DeepEqual(out, want) {
		t.Fatalf("payload=%+v want exactly %+v (spec §4.1)", out, want)
	}
}

func TestCallTransferResolvesConsultCallToItsDialog(t *testing.T) {
	h := newMediaToolHarness(t)
	answerFakeCall(t, h.agent, h.call)
	h.agent.SetDialResult(session.DialResult{DialogID: "fake-dialog-2", CallID: "fake-callid-2@lab.internal"})
	consultHandle, consult := mustDial(t, h.mgr, h.tools, h.sess, string(h.call.UAHandle()), nil)
	answerFakeCall(t, h.agent, consult)

	var got session.TransferRequest
	h.agent.TransferFn = func(_ context.Context, req session.TransferRequest) (session.TransferResult, error) {
		got = req
		return session.TransferResult{Accepted: true, StatusCode: 202, Reason: "Accepted"}, nil
	}
	if _, err := h.tools.CallTransfer(context.Background(), h.sess, session.CallTransferInput{
		Call: string(h.call.Handle()), Mode: "attended", ConsultCall: consultHandle}); err != nil {
		t.Fatalf("CallTransfer: %v", err)
	}
	want := session.TransferRequest{DialogID: "fake-dialog-1", Mode: session.TransferAttended, ConsultDialogID: "fake-dialog-2"}
	if got != want {
		t.Fatalf("agent got %+v want %+v", got, want)
	}
}

func TestCallTransferRefusesAnUnansweredConsultCall(t *testing.T) {
	h := newMediaToolHarness(t)
	answerFakeCall(t, h.agent, h.call)
	h.agent.SetDialResult(session.DialResult{DialogID: "fake-dialog-2", CallID: "fake-callid-2@lab.internal"})
	consultHandle, _ := mustDial(t, h.mgr, h.tools, h.sess, string(h.call.UAHandle()), nil) // left dialing
	called := false
	h.agent.TransferFn = func(context.Context, session.TransferRequest) (session.TransferResult, error) {
		called = true
		return session.TransferResult{}, nil
	}
	_, err := h.tools.CallTransfer(context.Background(), h.sess, session.CallTransferInput{
		Call: string(h.call.Handle()), Mode: "attended", ConsultCall: consultHandle})
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("err=%v want precondition_failed (consult_call not answered, D9)", err)
	}
	if called {
		t.Fatal("the agent was asked to transfer with an unanswered consult call")
	}
}

func TestCallTransferRefusesAnUnansweredCall(t *testing.T) {
	h := newMediaToolHarness(t) // dialing, never answered
	called := false
	h.agent.TransferFn = func(context.Context, session.TransferRequest) (session.TransferResult, error) {
		called = true
		return session.TransferResult{}, nil
	}
	_, err := h.tools.CallTransfer(context.Background(), h.sess, session.CallTransferInput{
		Call: string(h.call.Handle()), Mode: "blind", Target: "sip:carol@example.com"})
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("err=%v want precondition_failed (D9)", err)
	}
	if called {
		t.Fatal("the agent was asked to transfer an unanswered call")
	}
}

func TestCallTransferPropagatesTheAgentsError(t *testing.T) {
	h := newMediaToolHarness(t)
	answerFakeCall(t, h.agent, h.call)
	h.agent.TransferFn = func(context.Context, session.TransferRequest) (session.TransferResult, error) {
		return session.TransferResult{}, apierr.InvalidArgument("call_transfer: mode \"x\" must be blind or attended")
	}
	_, err := h.tools.CallTransfer(context.Background(), h.sess, session.CallTransferInput{
		Call: string(h.call.Handle()), Mode: "x"})
	if apierr.CodeOf(err) != apierr.CodeInvalidArgument {
		t.Fatalf("err=%v want the agent's invalid_argument", err)
	}
}

// TestCallTransferPropagatesADTMFInFlightRefusal is Rule 13 Finding 2a's D10
// half: internal/sipua/transfer_test.go's
// TestSecondTransferAndDTMFAreRefusedWhileATransferIsInFlight pins the REAL
// UA's mutual-exclusion decision (a call_transfer is refused
// precondition_failed while a dtmf_send is in flight on the same dialog), but
// that decision is made entirely INSIDE sipua.UA.Transfer — session.ToolService
// has no interlock of its own and simply forwards whatever error the agent
// returns (CallTransfer's own doc comment, toolservice.go:937-940). This test
// pins the session-layer WIRING: the refusal reaches the tool boundary as
// precondition_failed, unaltered, rather than being swallowed or remapped.
// D10's "in flight" state is simulated the same way ControlOpBlocksHangupFn
// simulates a blocking control op above: TransferFn just returns the refusal
// sipua would.
func TestCallTransferPropagatesADTMFInFlightRefusal(t *testing.T) {
	h := newMediaToolHarness(t)
	answerFakeCall(t, h.agent, h.call)
	h.agent.TransferFn = func(context.Context, session.TransferRequest) (session.TransferResult, error) {
		return session.TransferResult{}, apierr.PreconditionFailed(
			"call_transfer: a dtmf_send is in progress on this dialog (D10)")
	}
	_, err := h.tools.CallTransfer(context.Background(), h.sess, session.CallTransferInput{
		Call: string(h.call.Handle()), Mode: "blind", Target: "sip:carol@example.com"})
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("err=%v want precondition_failed (D10: dtmf_send in flight)", err)
	}
}

// TestDTMFSendPropagatesATransferInFlightRefusal is Finding 2a's other
// direction: session.ToolService.DTMFSend must likewise forward, unaltered, the
// precondition_failed sipua.UA.SendDTMF returns while a call_transfer is in
// flight on the same dialog (transfer_test.go's
// TestSecondTransferAndDTMFAreRefusedWhileATransferIsInFlight again).
func TestDTMFSendPropagatesATransferInFlightRefusal(t *testing.T) {
	h := newMediaToolHarness(t)
	answerFakeCall(t, h.agent, h.call)
	h.agent.SendDTMFFn = func(context.Context, string, string, session.DTMFMode, int, int) (int, int, error) {
		return 0, 0, apierr.PreconditionFailed(
			"dtmf_send: a call_transfer is in progress on this dialog (D10)")
	}
	_, err := h.tools.DTMFSend(context.Background(), h.sess, session.DTMFSendInput{
		Call: string(h.call.Handle()), Digits: "1"})
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("err=%v want precondition_failed (D10: transfer in flight)", err)
	}
}

// TestCallHangupIsRefusedWhileAControlOpBlocksIt is Review Focus #4, D2 and
// D17: the refusal must come BEFORE TryHangup's claim, or session would record
// the call terminated while the dialog stays up. It keys on
// ControlOpBlocksHangup, which sipua reports for a transfer only while the
// REFER's own response is pending. Task 3's
// TestHangupIsRefusedOnlyWhileTheRefersOwnResponseIsPending and
// TestHangupAfterTheReferIsAcceptedSucceedsAndSettlesTheTransfer pin that
// window against a real REFER.
func TestCallHangupIsRefusedWhileAControlOpBlocksIt(t *testing.T) {
	h := newMediaToolHarness(t)
	answerFakeCall(t, h.agent, h.call)
	h.agent.ControlOpBlocksHangupFn = func(id string) (session.ControlOpKind, bool) {
		return session.ControlOpTransfer, id == h.call.DialogID()
	}

	_, err := h.tools.CallHangup(context.Background(), h.sess, session.CallHangupInput{Call: string(h.call.Handle())})
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("err=%v want precondition_failed", err)
	}
	// D15/D17: a transfer-held call names the transfer's pending REFER and says
	// the wait is short (retry once call_transfer returns), NOT "wait for the
	// final transfer event", which is up to 300 s away.
	if msg := err.Error(); !strings.Contains(msg, "call transfer") ||
		!strings.Contains(msg, "retry once call_transfer has returned") {
		t.Fatalf("refusal %q does not tell the caller to retry once call_transfer returns", msg)
	}
	if st := h.call.State(); st != session.StateAnswered {
		t.Fatalf("state=%q after a refused hangup, want answered — the claim ran before the guard", st)
	}
	if n := len(h.agent.Hangups); n != 0 {
		t.Fatalf("%d Hangup calls reached the agent, want 0", n)
	}

	// Once the operation no longer blocks hangup (the REFER was accepted, D17),
	// even though it may still be in flight, the hangup goes through.
	h.agent.ControlOpBlocksHangupFn = func(string) (session.ControlOpKind, bool) { return "", false }
	if _, err := h.tools.CallHangup(context.Background(), h.sess, session.CallHangupInput{Call: string(h.call.Handle())}); err != nil {
		t.Fatalf("CallHangup once the control op stopped blocking it: %v", err)
	}
	if st := h.call.State(); st != session.StateTerminated {
		t.Fatalf("state=%q want terminated", st)
	}
}

// TestCallHangupRefusalForAnUnrecognisedControlOpIsGeneric is D15's
// genericity: a control-op kind CallHangup has no specific wording for — such
// as the future hold operation, if its plan forgets the switch — gets the
// generic, still-correct message, never the transfer one.
func TestCallHangupRefusalForAnUnrecognisedControlOpIsGeneric(t *testing.T) {
	h := newMediaToolHarness(t)
	answerFakeCall(t, h.agent, h.call)
	h.agent.ControlOpBlocksHangupFn = func(string) (session.ControlOpKind, bool) {
		return session.ControlOpKind("some_future_op"), true
	}
	_, err := h.tools.CallHangup(context.Background(), h.sess, session.CallHangupInput{Call: string(h.call.Handle())})
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("err=%v want precondition_failed", err)
	}
	if msg := err.Error(); strings.Contains(msg, "transfer") ||
		!strings.Contains(msg, "a call control operation is in progress") {
		t.Fatalf("refusal %q for an unrecognised kind must be the generic message, naming no transfer", msg)
	}
}
