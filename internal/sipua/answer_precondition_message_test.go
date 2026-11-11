package sipua_test

// C12: e2e/loop/dtmf_receiver.go's AnswerWhenRinging retries on a LITERAL
// substring of this error message ("requires a ringing inbound dialog") because
// no exported UA method reports dialog phase. Nothing pinned that string, so
// rewording call.go's message would silently turn the e2e receiver's retry loop
// into an immediate failure — a gate break with no unit-test warning.
//
// This pins the contract the gate depends on. If the message must change, this
// test fails first and names the consumer to update.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// answerRingingRequirementText is the substring e2e/loop/dtmf_receiver.go's
// notRinging constant holds. The two must stay identical.
const answerRingingRequirementText = "requires a ringing inbound dialog"

func TestAnswerOnANonRingingDialogNamesTheRingingRequirement(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	dialogID, _, _ := establishInboundAnswered(t, ua, p, events)

	// The dialog is now answered (phaseConfirmed), not ringing. A second
	// Answer on it must fail precondition_failed and name the requirement.
	err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: dialogID})
	if err == nil {
		t.Fatal("Answer on a non-ringing dialog succeeded; it must be precondition_failed")
	}
	if got := apierr.CodeOf(err); got != apierr.CodePreconditionFailed {
		t.Fatalf("Answer error code = %v, want precondition_failed", got)
	}
	if !strings.Contains(err.Error(), answerRingingRequirementText) {
		t.Fatalf("Answer error %q does not contain %q — e2e/loop/dtmf_receiver.go's "+
			"AnswerWhenRinging retries on exactly that substring and would fail immediately "+
			"instead of retrying. Update e2e/loop/dtmf_receiver.go's notRinging constant in the "+
			"same commit as any reword.", err.Error(), answerRingingRequirementText)
	}
}
