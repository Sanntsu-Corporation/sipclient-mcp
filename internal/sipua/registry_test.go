package sipua

import (
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// TestRegistry_ForgetsDialogOnTermination pins I3's fix: u.calls.byID grew
// unbounded because no delete existed anywhere. findByCallID is the canonical
// Call-ID lookup (Rule 18) and forget is the canonical registry delete,
// reused by Tasks 6 (onCancel) and 8 (the re-INVITE guard).
func TestRegistry_ForgetsDialogOnTermination(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0))) // existing helper style; bind loopback, no real net
	d := &dialog{id: newDialogID(), direction: session.Inbound, phase: phaseRinging, callID: "call-abc"}
	u.register(d)
	if got := u.findByCallID("call-abc"); got != d {
		t.Fatalf("findByCallID before terminate = %v, want the registered dialog", got)
	}
	u.forget(d.id)
	if got := u.findByCallID("call-abc"); got != nil {
		t.Fatalf("findByCallID after forget = %v, want nil (I3: byID must delete)", got)
	}
	u.calls.mu.Lock()
	n := len(u.calls.byID)
	u.calls.mu.Unlock()
	if n != 0 {
		t.Fatalf("byID len = %d, want 0", n)
	}
}
