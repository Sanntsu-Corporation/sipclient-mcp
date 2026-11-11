package loopback_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// referEventID is "refer;id=<the REFER's own wire CSeq>", the Event header
// value RFC 3515 requires on the NOTIFY that reports its outcome — mirrors
// internal/sipua/transfer_test.go's referEventHeader, restated here because
// that one is unexported in a different package.
func referEventID(t *testing.T, p *peer.Peer) string {
	t.Helper()
	cs := p.CSeqs("REFER")
	if len(cs) == 0 {
		t.Fatal("no REFER reached the peer")
	}
	return fmt.Sprintf("refer;id=%d", cs[len(cs)-1])
}

// sendFinalReferNotify sends the settling sipfrag NOTIFY (RFC 3515) that
// reports call_transfer's outcome, on p's most recently answered dialog.
func sendFinalReferNotify(t *testing.T, p *peer.Peer, statusLine string) {
	t.Helper()
	p.SendToCaller(t, sip.NOTIFY, []sip.Header{
		sip.NewHeader("Event", referEventID(t, p)),
		sip.NewHeader("Subscription-State", "terminated"),
		sip.NewHeader("Content-Type", "message/sipfrag;version=2.0"),
	}, []byte(statusLine+"\r\n"))
}

// TestCallTransferEndToEndThroughTheRealStackReturnsTheFinalOutcome is Rule 13
// Finding 2c: the full MCP -> session -> sipua chain for call_transfer had
// ZERO automated regression coverage — every layer was only ever tested
// against a fake/mock immediately below it, and the one genuine full-stack
// proof was the manual e2e/asterisk-xfer/ interop rig. This drives
// call_transfer through the real loopback stack (real mcp.Server, real
// session.ToolService, real sipua.UA, a real wire REFER and a real wire
// NOTIFY from the harness's own peer) and confirms call_wait(until="transfer")
// — Finding 1's fix — hands back the settled, final outcome.
func TestCallTransferEndToEndThroughTheRealStackReturnsTheFinalOutcome(t *testing.T) {
	h := loopback.New(t, loopback.WithPeerBehaviour(loopback.PeerBehaviour{ReferStatus: 202}))
	defer h.Close()
	call := h.MustDialAnswered(t)

	out, err := h.CallTool("call_transfer", map[string]any{
		"call": call, "mode": "blind", "target": "sip:carol@example.com"})
	if err != nil {
		t.Fatalf("call_transfer: %v", err)
	}
	if accepted, _ := out["accepted"].(bool); !accepted {
		t.Fatalf("call_transfer result=%+v, want accepted:true", out)
	}
	if n := h.Peer().Count("REFER"); n != 1 {
		t.Fatalf("%d REFERs reached the peer, want 1 — the REFER never went out on the real wire", n)
	}

	sendFinalReferNotify(t, h.Peer(), "SIP/2.0 200 OK")

	res := h.MustWait(t, call, "transfer", 5000)
	if res.Event == nil || res.Event.Type != session.EventTransfer {
		t.Fatalf("call_wait(until=transfer) returned %+v, want a transfer event", res)
	}
	if res.Detail["final"] != true || res.Detail["success"] != true {
		t.Fatalf("call_wait(until=transfer) detail=%+v, want final:true success:true (the SETTLED "+
			"outcome, not a provisional NOTIFY)", res.Detail)
	}
	if code, _ := res.Detail["status_code"].(float64); code != 200 {
		t.Fatalf("call_wait(until=transfer) status_code=%v, want 200", res.Detail["status_code"])
	}
}

// TestCallHangupIsRefusedDuringTheRealReferPendingWindow is Rule 13 Finding
// 2b: D2/D17's "the guard check must run before TryHangup's irreversible
// claim" invariant (toolservice.go:835-845) was only proven against a FAKE
// guard's programmed timing at the session layer, and against the REAL guard
// by calling sipua.UA.Hangup directly — never through the actual
// session.ToolService.CallHangup tool call while a REAL, wire-driven REFER is
// pending. This drives that: the peer swallows the REFER's own response, so
// call_transfer blocks in that transaction while call_hangup is raced against
// it through the real MCP tool boundary.
func TestCallHangupIsRefusedDuringTheRealReferPendingWindow(t *testing.T) {
	h := loopback.New(t, loopback.WithPeerBehaviour(loopback.PeerBehaviour{SwallowRefer: true}))
	defer h.Close()
	call := h.MustDialAnswered(t)

	type transferOutcome struct {
		out map[string]any
		err error
	}
	done := make(chan transferOutcome, 1)
	go func() {
		out, err := h.CallTool("call_transfer", map[string]any{
			"call": call, "mode": "blind", "target": "sip:carol@example.com"})
		done <- transferOutcome{out, err}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for h.Peer().Count("REFER") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the REFER never reached the peer")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// D2/D17: refused BEFORE TryHangup's claim, against the REAL guard,
	// through the REAL tool call.
	if _, err := h.CallTool("call_hangup", map[string]any{"call": call}); loopback.ErrorCode(err) != "precondition_failed" {
		t.Fatalf("call_hangup while the REFER's own response is pending: err=%v, want precondition_failed", err)
	}
	if st := h.MustCallStatus(t, call); st.State != "answered" {
		t.Fatalf("call state=%q after the refused hangup, want answered — the guard must run "+
			"BEFORE TryHangup's claim, not after", st.State)
	}

	// Let the REFER settle: sipgo's non-INVITE client transaction will retry
	// it, and the peer now answers 202 on the retry, so the transfer resolves
	// in well under a second instead of riding out sipua's own 32s
	// per-transaction budget.
	h.Peer().SetBehaviour(loopback.PeerBehaviour{ReferStatus: 202})
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("call_transfer: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("call_transfer did not return after the REFER was allowed through on retry")
	}

	// D17's owner ruling: once the REFER's own response has arrived the guard
	// clears, even though the transfer's NOTIFY outcome is still pending, and
	// a real hangup succeeds.
	h.MustHangup(t, call)
	if st := h.MustCallStatus(t, call); st.State != "terminated" {
		t.Fatalf("call state=%q after hangup, want terminated", st.State)
	}
}
