// internal/sipua/transfer_test.go
package sipua_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

func startTransferPeer(t *testing.T, b peer.Behaviour) *peer.Peer {
	t.Helper()
	return peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: b})
}

// transferEvents is every UAEventTransfer for dialogID, in emission order.
func transferEvents(events func() []session.UAEvent, dialogID string) []session.UAEvent {
	var out []session.UAEvent
	for _, ev := range events() {
		if ev.Kind == session.UAEventTransfer && ev.DialogID == dialogID {
			out = append(out, ev)
		}
	}
	return out
}

func waitTransferEvents(t *testing.T, events func() []session.UAEvent, dialogID string, n int) []session.UAEvent {
	t.Helper()
	waitForCond(t, func() bool { return len(transferEvents(events, dialogID)) >= n })
	return transferEvents(events, dialogID)
}

// referEventHeader is "refer;id=<the last REFER's wire CSeq>", read off what the
// PEER received — so a UA that expected a different id than it actually put on
// the wire fails every test here (RFC 3515 §2.4.4).
func referEventHeader(t *testing.T, p *peer.Peer) string {
	t.Helper()
	cs := p.CSeqs("REFER")
	if len(cs) == 0 {
		t.Fatal("no REFER reached the peer")
	}
	return fmt.Sprintf("refer;id=%d", cs[len(cs)-1])
}

func sendReferNotify(t *testing.T, p *peer.Peer, event, statusLine, subState string) {
	t.Helper()
	p.SendToCaller(t, sip.NOTIFY, []sip.Header{
		sip.NewHeader("Event", event),
		sip.NewHeader("Subscription-State", subState),
		sip.NewHeader("Content-Type", "message/sipfrag;version=2.0"),
	}, []byte(statusLine+"\r\n"))
}

func detail(mode string, code int, reason string, final bool) map[string]any {
	return map[string]any{
		"mode": mode, "status_code": code, "reason": reason,
		"final": final, "success": final && code >= 200 && code < 300,
	}
}

func mustTransfer(t *testing.T, ua *sipua.UA, req session.TransferRequest) session.TransferResult {
	t.Helper()
	out, err := ua.Transfer(context.Background(), req)
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	return out
}

// TestReferOnAnAlreadyEndedDialogFailsFastWithoutDispatching is CF-008: a
// peer BYE that ends the dialog in the narrow window between claiming the
// control op and dispatching the REFER must not still send a REFER on a dead
// dialog. The outcome was already correct before this fix (a 481 plus a
// final transfer event); this proves the REFER is no longer sent at all.
func TestReferOnAnAlreadyEndedDialogFailsFastWithoutDispatching(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
	ua, cc := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)

	sipua.SetTransferBeforeSendHookForTest(func(ended <-chan struct{}) {
		p.SendBye(t)
		select {
		case <-ended:
		case <-time.After(2 * time.Second):
			t.Fatal("dialog did not end after the peer BYE")
		}
	})
	t.Cleanup(func() { sipua.SetTransferBeforeSendHookForTest(nil) })

	_, err := ua.Transfer(context.Background(), session.TransferRequest{
		DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("err=%v want precondition_failed", err)
	}
	if n := cc.Sent("REFER"); n != 0 {
		t.Fatalf("REFER was dispatched %d time(s) on an already-ended dialog", n)
	}
}

func TestBlindTransferReportsEveryNotifyAndReleasesOnTheFinalOne(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)

	out := mustTransfer(t, ua, session.TransferRequest{
		DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
	if !out.Accepted || out.StatusCode != 202 || out.Reason != "Accepted" {
		t.Fatalf("result=%+v want {Accepted:true 202 Accepted}", out)
	}
	if kind, held := ua.ControlOpState(res.DialogID); !held || kind != session.ControlOpTransfer {
		t.Fatalf("ControlOpState=(%q,%v) during the transfer, want (%q,true) (D15)", kind, held, session.ControlOpTransfer)
	}
	if got := p.LastRequestHeader("REFER", "Refer-To"); got != "<sip:carol@example.com>" {
		t.Fatalf("Refer-To=%q", got)
	}
	if got := p.LastRequestHeader("REFER", "Referred-By"); got != "<sip:alice@example>" {
		t.Fatalf("Referred-By=%q want our AOR", got)
	}
	if got := p.CallIDs("REFER"); len(got) != 1 || got[0] != res.CallID {
		t.Fatalf("REFER Call-IDs=%v want [%s] — the REFER must be IN the dialog", got, res.CallID)
	}
	if !inControlOp(ua, res.DialogID) {
		t.Fatal("the dialog is not held while the NOTIFY subscription is pending")
	}

	sendReferNotify(t, p, referEventHeader(t, p), "SIP/2.0 100 Trying", "active;expires=60")
	waitTransferEvents(t, events, res.DialogID, 1)
	sendReferNotify(t, p, referEventHeader(t, p), "SIP/2.0 200 OK", "terminated;reason=noresource")
	evs := waitTransferEvents(t, events, res.DialogID, 2)

	want := []map[string]any{detail("blind", 100, "Trying", false), detail("blind", 200, "OK", true)}
	for i := range want {
		if !reflect.DeepEqual(evs[i].Detail, want[i]) {
			t.Fatalf("transfer event %d detail=%+v want %+v", i, evs[i].Detail, want[i])
		}
	}
	waitForCond(t, func() bool { return !inControlOp(ua, res.DialogID) })
	if codes := p.ResponseCodes(); len(codes) < 2 || codes[0] != 200 || codes[1] != 200 {
		t.Fatalf("NOTIFY responses=%v want 200s (locked decision 5)", codes)
	}

	// A duplicate final NOTIFY is still answered 200 but reports nothing new.
	sendReferNotify(t, p, referEventHeader(t, p), "SIP/2.0 200 OK", "terminated")
	waitForCond(t, func() bool { return len(p.ResponseCodes()) >= 3 })
	if got := p.ResponseCodes()[2]; got != 200 {
		t.Fatalf("duplicate final NOTIFY drew %d want 200", got)
	}
	if n := len(transferEvents(events, res.DialogID)); n != 2 {
		t.Fatalf("%d transfer events after a duplicate final NOTIFY, want 2", n)
	}

	// One strictly-increasing in-dialog CSeq space: a later BYE follows the REFER.
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	if refer, bye := p.CSeqs("REFER")[0], p.LastByeCSeq(); bye <= refer {
		t.Fatalf("BYE CSeq %d <= REFER CSeq %d (RFC 3261 §12.2.1.1)", bye, refer)
	}
}

// TestReferNotifyMatchingToleratesMissingIdsAndIgnoresStrangers is Review Focus
// #1 and D6.
func TestReferNotifyMatchingToleratesMissingIdsAndIgnoresStrangers(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)
	mustTransfer(t, ua, session.TransferRequest{
		DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
	id := p.CSeqs("REFER")[0]

	// A stale subscription's id: answered, ignored.
	sendReferNotify(t, p, fmt.Sprintf("refer;id=%d", id+7), "SIP/2.0 200 OK", "terminated")
	// A body that is not a sipfrag status line: answered, ignored.
	sendReferNotify(t, p, fmt.Sprintf("refer;id=%d", id), "garbage", "active")
	waitForCond(t, func() bool { return len(p.ResponseCodes()) >= 2 })
	for i, c := range p.ResponseCodes() {
		if c != 200 {
			t.Fatalf("NOTIFY %d drew %d want 200 — every NOTIFY on a live dialog is answered 200", i, c)
		}
	}
	if n := len(transferEvents(events, res.DialogID)); n != 0 {
		t.Fatalf("%d transfer events from a stale id and a garbage body, want 0", n)
	}
	if !inControlOp(ua, res.DialogID) {
		t.Fatal("an ignored NOTIFY released the transfer")
	}

	// No id at all: the ONE in-flight REFER's subscription (D6).
	sendReferNotify(t, p, "refer", "SIP/2.0 503 Service Unavailable", "terminated")
	evs := waitTransferEvents(t, events, res.DialogID, 1)
	if want := detail("blind", 503, "Service Unavailable", true); !reflect.DeepEqual(evs[0].Detail, want) {
		t.Fatalf("detail=%+v want %+v", evs[0].Detail, want)
	}
	waitForCond(t, func() bool { return !inControlOp(ua, res.DialogID) })
}

func TestRejectedReferIsAResultWithOneFinalEvent(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 603})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)
	req := session.TransferRequest{DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"}

	out := mustTransfer(t, ua, req)
	if out.Accepted || out.StatusCode != 603 || out.Reason != "Decline" {
		t.Fatalf("result=%+v want {Accepted:false 603 Decline}", out)
	}
	evs := transferEvents(events, res.DialogID)
	if len(evs) != 1 || !reflect.DeepEqual(evs[0].Detail, detail("blind", 603, "Decline", true)) {
		t.Fatalf("transfer events=%+v want exactly one final 603", evs)
	}
	if inControlOp(ua, res.DialogID) {
		t.Fatal("a rejected REFER left the dialog held")
	}
	// Released, so a retry is allowed (and is rejected again by this peer).
	if again := mustTransfer(t, ua, req); again.StatusCode != 603 {
		t.Fatalf("retry result=%+v", again)
	}
}

// TestTransferNonSuccessReasonIsCappedInTheReturnedResult is CF-006 (Cycle C
// round 4 fix): a non-2xx REFER response's reason phrase reaches
// TransferResult.Reason through a SEPARATE seam from concludeRefer's own cap
// — Transfer's non-2xx branch used to return res.Reason directly, bypassing
// it entirely.
func TestTransferNonSuccessReasonIsCappedInTheReturnedResult(t *testing.T) {
	long := strings.Repeat("B", 300)
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 603, ReferReason: long})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)

	out := mustTransfer(t, ua, session.TransferRequest{
		DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
	if out.Accepted || out.StatusCode != 603 {
		t.Fatalf("result=%+v want {Accepted:false 603 ...}", out)
	}
	// 256 is referReasonMaxLen's value (transfer.go); this file is package
	// sipua_test and cannot reference the unexported constant directly.
	if len(out.Reason) != 256 || out.Reason != long[:256] {
		t.Fatalf("TransferResult.Reason len=%d want 256 (capped), got %q", len(out.Reason), out.Reason)
	}
	evs := transferEvents(events, res.DialogID)
	if len(evs) != 1 || evs[0].Detail["reason"] != out.Reason {
		t.Fatalf("transfer event reason=%v want it to match the capped TransferResult.Reason (%q)",
			evs[0].Detail["reason"], out.Reason)
	}
}

// TestTransferAcceptedReasonIsCappedInTheReturnedResult is CF-006 (fallback
// architectural review finding, post-Cycle-C): a 2xx REFER response's reason
// phrase reaches TransferResult.Reason on the ACCEPTED path too — a fourth,
// independent seam from the non-2xx branch, since this value is never passed
// through concludeRefer (the accepted REFER's outcome settles later,
// asynchronously).
func TestTransferAcceptedReasonIsCappedInTheReturnedResult(t *testing.T) {
	long := strings.Repeat("C", 300)
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202, ReferReason: long})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)

	out := mustTransfer(t, ua, session.TransferRequest{
		DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
	if !out.Accepted || out.StatusCode != 202 {
		t.Fatalf("result=%+v want {Accepted:true 202 ...}", out)
	}
	// 256 is referReasonMaxLen's value (transfer.go); this file is package
	// sipua_test and cannot reference the unexported constant directly.
	if len(out.Reason) != 256 || out.Reason != long[:256] {
		t.Fatalf("TransferResult.Reason len=%d want 256 (capped), got %q", len(out.Reason), out.Reason)
	}
}

// failFirstWriteConn fails the first outbound datagram whose SIP method line
// starts with method, then behaves normally — simulating an immediate
// transport-level dispatch failure (CF-009), as distinct from a transaction
// that sent successfully and then simply drew no final response.
type failFirstWriteConn struct {
	net.PacketConn
	method string
	mu     sync.Mutex
	failed bool
}

func (c *failFirstWriteConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	fail := !c.failed && strings.HasPrefix(firstLine(b), c.method+" ")
	if fail {
		c.failed = true
	}
	c.mu.Unlock()
	if fail {
		return 0, errors.New("simulated immediate transport failure")
	}
	return c.PacketConn.WriteTo(b, addr)
}

// TestReferThatFailsToDispatchIsLabeledDistinctlyFromNoResponse is CF-009: an
// immediate transport failure (nothing reached the wire) gets a different
// reason than TestReferThatDrawsNoResponseEndsTheDialog's genuine
// "sent, then Timer F expired" case.
func TestReferThatFailsToDispatchIsLabeledDistinctlyFromNoResponse(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{})
	var fc *failFirstWriteConn
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example",
		ExpiresS: 300, Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			fc = &failFirstWriteConn{PacketConn: pc, method: "REFER"}
			return fc
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)

	out := mustTransfer(t, ua, session.TransferRequest{
		DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
	if out.Accepted || out.StatusCode != 0 || out.Reason != "the REFER could not be dispatched" {
		t.Fatalf("result=%+v want {false 0 \"the REFER could not be dispatched\"}", out)
	}
	evs := transferEvents(events, res.DialogID)
	if len(evs) != 1 || !reflect.DeepEqual(evs[0].Detail, detail("blind", 0, "the REFER could not be dispatched", true)) {
		t.Fatalf("transfer events=%+v", evs)
	}
	// Rule 13 wave review, Cycle 3 fix: nothing reached the wire, so no
	// subscription can exist for it — no earlier subscription may be live (ReferSubMaybeLiveForTest false),
	// unlike TestReferThatDrawsNoResponseEndsTheDialog's genuinely
	// dispatched-but-unanswered case.
	if sipua.ReferSubMaybeLiveForTest(ua, res.DialogID) {
		t.Fatal("an earlier subscription is recorded as maybe-live after a REFER that never reached the wire (CF-009)")
	}
}

// TestReferNeverSentKeepsTheDialog (S12): a REFER that never reached the wire
// teaches nothing about the dialog, so it is kept and Hangup ends it normally.
func TestReferNeverSentKeepsTheDialog(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{})
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example",
		ExpiresS: 300, Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			return &failFirstWriteConn{PacketConn: pc, method: "REFER"}
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)
	out := mustTransfer(t, ua, session.TransferRequest{
		DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
	if out.Accepted || out.Reason != "the REFER could not be dispatched" {
		t.Fatalf("result=%+v, want the not-dispatched result", out)
	}
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup after a REFER that was never sent: %v (the dialog was ended)", err)
	}
}

// TestReferThatDrawsNoResponseEndsTheDialog is D8 reversed by the owner (CF-110,
// round 5; RFC 3261 12.2.1.2): the transfer is still a RESULT, but the dialog is
// ended locally. Was the D8 test ReferThatDrawsNoResponseIsAResultAndKeepsTheCall. Timer
// F is a real timer; newDirectUA's 2s Timeout bounds this test.
func TestReferThatDrawsNoResponseEndsTheDialog(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{SwallowRefer: true})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)

	out := mustTransfer(t, ua, session.TransferRequest{
		DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
	if out.Accepted || out.StatusCode != 0 || out.Reason != "REFER drew no final response" {
		t.Fatalf("result=%+v want {false 0 \"REFER drew no final response\"}", out)
	}
	evs := transferEvents(events, res.DialogID)
	if len(evs) != 1 || !reflect.DeepEqual(evs[0].Detail, detail("blind", 0, "REFER drew no final response", true)) {
		t.Fatalf("transfer events=%+v", evs)
	}
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err == nil || apierr.CodeOf(err) != apierr.CodeNotFound {
		t.Fatalf("an unanswered REFER must end the dialog (CF-110), Hangup = %v, want not_found", err)
	}
}

// armedWaits installs the outcome-timer arm hook (D14) for one test and returns
// the channel every (re)arm reports its window on. The hook runs AFTER the
// timer is armed, so a value received here means the fake clock already holds
// that deadline — an Advance issued after it cannot race the arm.
func armedWaits(t *testing.T) <-chan time.Duration {
	t.Helper()
	ch := make(chan time.Duration, 16)
	sipua.SetReferOutcomeArmHook(func(d time.Duration) { ch <- d })
	t.Cleanup(func() { sipua.SetReferOutcomeArmHook(nil) })
	return ch
}

func nextArm(t *testing.T, armed <-chan time.Duration) time.Duration {
	t.Helper()
	select {
	case d := <-armed:
		return d
	case <-time.After(3 * time.Second):
		t.Fatal("the transfer outcome timer was never (re)armed")
		return 0
	}
}

// TestTransferOutcomeWaitFallsBackToTheInternalDefaultNotTheTransactionTimeout
// is D14 (Cycle C finding 3, case b). No NOTIFY states a subscription duration,
// so the window is the internal 120 s default. It is NOT u.cfg.Timeout, which is
// the REFER transaction's budget (2 s on newDirectUA).
func TestTransferOutcomeWaitFallsBackToTheInternalDefaultNotTheTransactionTimeout(t *testing.T) {
	armed := armedWaits(t)
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newDirectUA(t, clk)
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)
	mustTransfer(t, ua, session.TransferRequest{
		DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})

	if got := nextArm(t, armed); got != sipua.ReferOutcomeDefaultWait || got <= 2*time.Second {
		t.Fatalf("outcome window armed at %v, want the internal default %v (never the 2 s transaction Timeout)",
			got, sipua.ReferOutcomeDefaultWait)
	}
	// The outcome timer is the ONLY fake-clock waiter on this outbound,
	// timer-less dialog (the ring budget and RTP pacing run on real time).
	clk.Advance(sipua.ReferOutcomeDefaultWait)
	evs := waitTransferEvents(t, events, res.DialogID, 1)
	if want := detail("blind", 0, "no final NOTIFY before the transfer outcome deadline", true); !reflect.DeepEqual(evs[0].Detail, want) {
		t.Fatalf("detail=%+v want %+v", evs[0].Detail, want)
	}
	waitForCond(t, func() bool { return !inControlOp(ua, res.DialogID) })
}

// TestTransferOutcomeWaitFollowsTheNotifiersSubscriptionExpires is D14 case a.
// The first NOTIFY's `Subscription-State: active;expires=90` re-bases the window
// to 90 s: shorter than the 120 s default, and still far past the 2 s
// transaction Timeout.
func TestTransferOutcomeWaitFollowsTheNotifiersSubscriptionExpires(t *testing.T) {
	armed := armedWaits(t)
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newDirectUA(t, clk)
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)
	mustTransfer(t, ua, session.TransferRequest{
		DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
	if got := nextArm(t, armed); got != sipua.ReferOutcomeDefaultWait {
		t.Fatalf("initial window %v, want %v", got, sipua.ReferOutcomeDefaultWait)
	}

	sendReferNotify(t, p, referEventHeader(t, p), "SIP/2.0 180 Ringing", "active;expires=90")
	if got := nextArm(t, armed); got != 90*time.Second {
		t.Fatalf("window after the notifier stated expires=90: %v, want 90s", got)
	}
	clk.Advance(90 * time.Second)
	evs := waitTransferEvents(t, events, res.DialogID, 2) // the 180, then the timeout
	if want := detail("blind", 0, "no final NOTIFY before the transfer outcome deadline", true); !reflect.DeepEqual(evs[1].Detail, want) {
		t.Fatalf("final detail=%+v want %+v", evs[1].Detail, want)
	}
}

// TestADelayedIdlessNotifyForAnEarlierTransferCannotSettleALaterOne is D13
// (Cycle C finding 2, case a). Transfer A times out, so A's subscription may
// still be live at the notifier and an earlier subscription is recorded as maybe-live.
// Transfer B then starts on the SAME dialog. A's late final NOTIFY arrives
// WITHOUT an id. It is ambiguous (it could be A's), so it must not settle B.
// Only B's own id does.
func TestADelayedIdlessNotifyForAnEarlierTransferCannotSettleALaterOne(t *testing.T) {
	armed := armedWaits(t)
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newDirectUA(t, clk)
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)
	req := session.TransferRequest{DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"}

	mustTransfer(t, ua, req) // transfer A
	nextArm(t, armed)
	clk.Advance(sipua.ReferOutcomeDefaultWait)
	waitTransferEvents(t, events, res.DialogID, 1) // A's timeout
	waitForCond(t, func() bool { return !inControlOp(ua, res.DialogID) })

	mustTransfer(t, ua, req) // transfer B
	nextArm(t, armed)
	before := len(p.ResponseCodes())
	sendReferNotify(t, p, "refer", "SIP/2.0 200 OK", "terminated") // A's, delayed, id-less
	waitForCond(t, func() bool { return len(p.ResponseCodes()) > before })
	if got := p.ResponseCodes()[before]; got != 200 {
		t.Fatalf("stale id-less NOTIFY drew %d, want 200 (locked decision 5)", got)
	}
	if n := len(transferEvents(events, res.DialogID)); n != 1 {
		t.Fatalf("%d transfer events after a stale id-less NOTIFY, want 1 (A's timeout only)", n)
	}
	if !inControlOp(ua, res.DialogID) {
		t.Fatal("a stale id-less NOTIFY settled transfer B")
	}

	sendReferNotify(t, p, referEventHeader(t, p), "SIP/2.0 200 OK", "terminated") // B's own id
	evs := waitTransferEvents(t, events, res.DialogID, 2)
	if want := detail("blind", 200, "OK", true); !reflect.DeepEqual(evs[1].Detail, want) {
		t.Fatalf("B's final detail=%+v want %+v", evs[1].Detail, want)
	}
}

// TestFinalNotifyTimeoutAndPeerByeRacingSettleExactlyOnce is Cycle C finding 5.
// A final NOTIFY, the outcome timeout and a peer BYE are released from ONE
// barrier. Whichever wins, there is exactly one final transfer event, no
// provisional after it, and the dialog is no longer held. Repeated so the three
// arrivals interleave differently across iterations. "No leaked goroutine"
// follows from "exactly one final event": concludeRefer emits the only final
// event of an accepted REFER and is awaitReferOutcome's LAST statement, so an
// observed final event means that goroutine has returned. A goroutine stuck in
// its select would show up as zero finals, and a double settle as two.
// sendReferNotify/SendBye can t.Fatalf off the test goroutine only on a
// socket write error. That is test-harness failure, not a result of the race
// under test.
func TestFinalNotifyTimeoutAndPeerByeRacingSettleExactlyOnce(t *testing.T) {
	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			armed := armedWaits(t)
			p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
			clk := fakeclock.New(time.Unix(0, 0))
			ua, _ := newDirectUA(t, clk)
			events := collect(t, ua)
			res := dialAnswered(t, ua, p, events)
			mustTransfer(t, ua, session.TransferRequest{
				DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
			nextArm(t, armed)
			event := referEventHeader(t, p)

			barrier := make(chan struct{})
			var wg sync.WaitGroup
			// CF-101 (round 5): the peer numbers each request when it BUILDS it, and
			// the UA now answers a request whose CSeq is lower than one already
			// handled with 500 (RFC 3261 12.2.2). A real peer's final NOTIFY precedes
			// its BYE on the wire and in CSeq order, so the BYE is built and sent
			// only after the NOTIFY is on the wire; the three arrivals still race.
			notifySent := make(chan struct{})
			for _, fire := range []func(){
				func() {
					sendReferNotify(t, p, event, "SIP/2.0 200 OK", "terminated")
					close(notifySent)
				},
				func() { clk.Advance(sipua.ReferOutcomeDefaultWait) },
				func() {
					<-notifySent
					p.SendBye(t)
				},
			} {
				wg.Add(1)
				go func(fire func()) {
					defer wg.Done()
					<-barrier
					fire()
				}(fire)
			}
			close(barrier)
			wg.Wait()

			waitForCond(t, func() bool { return !inControlOp(ua, res.DialogID) })
			waitFor(t, events, session.UAEventDialogEnded, 0) // the BYE was processed
			var finals int
			for _, ev := range transferEvents(events, res.DialogID) {
				if ev.Detail["final"] == true {
					finals++
				} else if finals > 0 {
					t.Fatalf("a provisional transfer event followed the final one: %+v", ev.Detail)
				}
			}
			if finals != 1 {
				t.Fatalf("%d final transfer events, want exactly 1 (no double settle, no lost settle)", finals)
			}
		})
	}
}

// TestDialogTeardownSettlesAPendingTransfer is Review Focus #2 and spec §8's
// second open item.
func TestDialogTeardownSettlesAPendingTransfer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		end    func(t *testing.T, ua *sipua.UA, p *peer.Peer, dialogID string)
		reason string
	}{
		{"peer BYE", func(t *testing.T, _ *sipua.UA, p *peer.Peer, _ string) { p.SendBye(t) },
			"the dialog ended before a final NOTIFY"},
		// D17: OUR OWN BYE is reported distinctly.
		{"local hangup", func(t *testing.T, ua *sipua.UA, _ *peer.Peer, dialogID string) {
			if err := ua.Hangup(context.Background(), dialogID, ""); err != nil {
				t.Fatalf("Hangup: %v", err)
			}
		}, "the transferor hung up before a final NOTIFY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
			ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
			events := collect(t, ua)
			res := dialAnswered(t, ua, p, events)
			mustTransfer(t, ua, session.TransferRequest{
				DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
			event := referEventHeader(t, p)

			tc.end(t, ua, p, res.DialogID)
			evs := waitTransferEvents(t, events, res.DialogID, 1)
			if want := detail("blind", 0, tc.reason, true); !reflect.DeepEqual(evs[0].Detail, want) {
				t.Fatalf("detail=%+v want %+v", evs[0].Detail, want)
			}
			// A late NOTIFY on the dead dialog: 481 (D6), and no second event.
			// Waits for a 481 to APPEAR rather than for "the next response": in
			// the peer-BYE case the UA's 200 to that BYE also lands in
			// ResponseCodes, possibly after this point, so position-based reads
			// would race it. If the UA wrongly answers 200, this times out.
			sendReferNotify(t, p, event, "SIP/2.0 200 OK", "terminated")
			waitForCond(t, func() bool {
				for _, c := range p.ResponseCodes() {
					if c == 481 {
						return true
					}
				}
				return false
			})
			if n := len(transferEvents(events, res.DialogID)); n != 1 {
				t.Fatalf("%d transfer events, want exactly 1", n)
			}
		})
	}
}

// TestAnIdlessNotifyIsAcceptedForARetryWhenNoEarlierSubscriptionCanBeLive is
// Cycle C round 2's B2. A first attempt leaves NO subscription that could still
// be alive, so a retry on the same call must correlate its id-less NOTIFYs.
// Some notifiers omit the id on every REFER's NOTIFYs, not only the first
// (D13). Under the old "first REFER only" rule the retry would sit in
// phaseControlOp until the outcome deadline and be reported as a timeout.
func TestAnIdlessNotifyIsAcceptedForARetryWhenNoEarlierSubscriptionCanBeLive(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first func(t *testing.T, ua *sipua.UA, p *peer.Peer, req session.TransferRequest)
	}{
		// A non-2xx REFER response creates no subscription (RFC 3515 §2.4.2).
		{"first REFER rejected", func(t *testing.T, ua *sipua.UA, p *peer.Peer, req session.TransferRequest) {
			p.SetBehaviour(peer.Behaviour{ReferStatus: 603})
			if out := mustTransfer(t, ua, req); out.Accepted {
				t.Fatalf("first attempt result=%+v, want rejected", out)
			}
			p.SetBehaviour(peer.Behaviour{ReferStatus: 202})
		}},
		// The notifier TERMINATED the first subscription with its final NOTIFY
		// (a busy target — the common reason to retry).
		{"first transfer's subscription terminated", func(t *testing.T, ua *sipua.UA, p *peer.Peer, req session.TransferRequest) {
			mustTransfer(t, ua, req)
			sendReferNotify(t, p, referEventHeader(t, p), "SIP/2.0 486 Busy Here", "terminated;reason=noresource")
			waitForCond(t, func() bool { return !inControlOp(ua, req.DialogID) })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
			ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
			events := collect(t, ua)
			res := dialAnswered(t, ua, p, events)
			req := session.TransferRequest{DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"}

			tc.first(t, ua, p, req)
			n := len(transferEvents(events, res.DialogID))
			mustTransfer(t, ua, req) // the retry
			sendReferNotify(t, p, "refer", "SIP/2.0 200 OK", "terminated;reason=noresource")
			evs := waitTransferEvents(t, events, res.DialogID, n+1)
			if want := detail("blind", 200, "OK", true); !reflect.DeepEqual(evs[n].Detail, want) {
				t.Fatalf("the retry's final detail=%+v want %+v — its id-less NOTIFY was not attributed to it", evs[n].Detail, want)
			}
			waitForCond(t, func() bool { return !inControlOp(ua, res.DialogID) })
		})
	}
}

// TestHangupIsRefusedOnlyWhileTheRefersOwnResponseIsPending is D17's refused
// half (spec §3 amendment). The peer swallows the REFER, so Transfer blocks in
// the REFER's own transaction for the full 2 s Timeout. Throughout that window
// the control op must block call_hangup. Once Transfer has returned (no
// response: the op concluded) it must not.
func TestHangupIsRefusedOnlyWhileTheRefersOwnResponseIsPending(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{SwallowRefer: true})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)

	done := make(chan session.TransferResult, 1)
	go func() {
		out, _ := ua.Transfer(context.Background(), session.TransferRequest{
			DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
		done <- out
	}()
	waitForCond(t, func() bool { return p.Count("REFER") == 1 }) // on the wire, its response swallowed
	if kind, blocked := ua.ControlOpBlocksHangup(res.DialogID); !blocked || kind != session.ControlOpTransfer {
		t.Fatalf("ControlOpBlocksHangup=(%q,%v) while the REFER's own response is pending, want (%q,true)",
			kind, blocked, session.ControlOpTransfer)
	}
	select {
	case out := <-done:
		if out.Accepted || out.StatusCode != 0 {
			t.Fatalf("result=%+v want the no-response result", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Transfer did not return within its 2 s transaction Timeout")
	}
	if _, blocked := ua.ControlOpBlocksHangup(res.DialogID); blocked {
		t.Fatal("call_hangup is still blocked after the REFER's transaction ended")
	}
}

// TestHangupAfterTheReferIsAcceptedSucceedsAndSettlesTheTransfer is D17's
// allowed half, and the owner ruling itself. Once the REFER is accepted the
// NOTIFY outcome is still pending (the dialog stays in phaseControlOp), but a
// hangup must succeed, put a BYE on the wire, and settle the transfer with the
// distinct "transferor hung up" reason.
func TestHangupAfterTheReferIsAcceptedSucceedsAndSettlesTheTransfer(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)
	if out := mustTransfer(t, ua, session.TransferRequest{
		DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"}); !out.Accepted {
		t.Fatalf("result=%+v want accepted", out)
	}
	if !inControlOp(ua, res.DialogID) {
		t.Fatal("the dialog is not held while the NOTIFY outcome is pending")
	}
	if kind, blocked := ua.ControlOpBlocksHangup(res.DialogID); blocked {
		t.Fatalf("ControlOpBlocksHangup=(%q,true) after the REFER was accepted, want false (spec §3 amendment)", kind)
	}
	// The rest of the guard still holds (spec §3: the exception is call_hangup only).
	if _, _, err := ua.SendDTMF(context.Background(), res.DialogID, "1", session.DTMFModeInfo, 100, 0); apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("SendDTMF during the outcome wait err=%v want precondition_failed", err)
	}

	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup after the REFER was accepted: %v", err)
	}
	if n := p.ByeCount(); n != 1 {
		t.Fatalf("%d BYEs, want 1", n)
	}
	evs := waitTransferEvents(t, events, res.DialogID, 1)
	if want := detail("blind", 0, "the transferor hung up before a final NOTIFY", true); !reflect.DeepEqual(evs[0].Detail, want) {
		t.Fatalf("detail=%+v want %+v", evs[0].Detail, want)
	}
	waitForCond(t, func() bool { return !inControlOp(ua, res.DialogID) })
	if n := len(transferEvents(events, res.DialogID)); n != 1 {
		t.Fatalf("%d transfer events, want exactly 1", n)
	}
}

func TestSecondTransferAndDTMFAreRefusedWhileATransferIsInFlight(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)
	req := session.TransferRequest{DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"}
	mustTransfer(t, ua, req)

	if _, err := ua.Transfer(context.Background(), req); apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("second Transfer err=%v want precondition_failed", err)
	}
	if n := p.Count("REFER"); n != 1 {
		t.Fatalf("%d REFERs on the wire, want 1", n)
	}
	if _, _, err := ua.SendDTMF(context.Background(), res.DialogID, "1", session.DTMFModeInfo, 100, 0); apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("SendDTMF err=%v want precondition_failed", err)
	}

	sendReferNotify(t, p, referEventHeader(t, p), "SIP/2.0 200 OK", "terminated")
	waitForCond(t, func() bool { return !inControlOp(ua, res.DialogID) })
	if _, _, err := ua.SendDTMF(context.Background(), res.DialogID, "1", session.DTMFModeInfo, 100, 0); err != nil {
		t.Fatalf("SendDTMF after the transfer settled: %v", err)
	}
}

// TestAttendedTransferReplacesTheConsultDialogAndLeavesItUntouched covers spec
// §4.2's Replaces construction on the wire and §4.6. The CONSULT call is dialed
// FIRST so the transferred call is the peer's most recent UAS call, which is
// the one SendToCaller addresses.
func TestAttendedTransferReplacesTheConsultDialogAndLeavesItUntouched(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	consult := dialAnswered(t, ua, p, events)
	consultFromTag := tagOf(p.LastRequestHeader("INVITE", "From"))
	callA := dialAnswered(t, ua, p, events)

	out := mustTransfer(t, ua, session.TransferRequest{
		DialogID: callA.DialogID, Mode: session.TransferAttended, ConsultDialogID: consult.DialogID})
	if !out.Accepted {
		t.Fatalf("result=%+v", out)
	}
	want := "<sip:bob@" + p.Addr() + "?Replaces=" + url.QueryEscape(
		consult.CallID+";to-tag="+p.AnsweredToTag(consult.CallID)+";from-tag="+consultFromTag) + ">"
	if got := p.LastRequestHeader("REFER", "Refer-To"); got != want {
		t.Fatalf("Refer-To\n got %s\nwant %s", got, want)
	}
	if got := p.CallIDs("REFER"); len(got) != 1 || got[0] != callA.CallID {
		t.Fatalf("REFER went out on %v, want the transferred call %s", got, callA.CallID)
	}
	// §4.6: the consult dialog is only READ — not held, still fully usable.
	if inControlOp(ua, consult.DialogID) {
		t.Fatal("the consult dialog was put into phaseControlOp")
	}
	if _, _, err := ua.SendDTMF(context.Background(), consult.DialogID, "5", session.DTMFModeInfo, 100, 0); err != nil {
		t.Fatalf("dtmf_send on the consult call during the transfer: %v", err)
	}

	sendReferNotify(t, p, referEventHeader(t, p), "SIP/2.0 200 OK", "terminated")
	evs := waitTransferEvents(t, events, callA.DialogID, 1)
	if !reflect.DeepEqual(evs[0].Detail, detail("attended", 200, "OK", true)) {
		t.Fatalf("detail=%+v", evs[0].Detail)
	}
	if n := len(transferEvents(events, consult.DialogID)); n != 0 {
		t.Fatalf("%d transfer events on the consult dialog, want 0", n)
	}
	if p.ByeCount() != 0 {
		t.Fatalf("%d BYEs — this feature never BYEs either dialog (spec §4.5)", p.ByeCount())
	}
}

func TestAttendedTransferRefusesAnUnansweredConsultCall(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	callA := dialAnswered(t, ua, p, events)
	p.SetBehaviour(peer.Behaviour{ReferStatus: 202, AnswerAfter: 10 * time.Second})
	consult, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}

	_, err = ua.Transfer(context.Background(), session.TransferRequest{
		DialogID: callA.DialogID, Mode: session.TransferAttended, ConsultDialogID: consult.DialogID})
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed || !strings.Contains(err.Error(), "consult_call") {
		t.Fatalf("err=%v want precondition_failed naming consult_call", err)
	}
	if n := p.Count("REFER"); n != 0 {
		t.Fatalf("%d REFERs on the wire, want 0", n)
	}
	if inControlOp(ua, callA.DialogID) {
		t.Fatal("a refused attended transfer left the transferred call held")
	}
}

// TestTransferRejectsInvalidRequestsBeforeTouchingTheWire is Review Focus #3.
// Validation runs before the dialog lookup, so "nope" never matters except in
// the last row.
func TestTransferRejectsInvalidRequestsBeforeTouchingTheWire(t *testing.T) {
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	blind, att := session.TransferBlind, session.TransferAttended
	for _, tc := range []struct {
		name string
		req  session.TransferRequest
		want apierr.Code
	}{
		{"unknown mode", session.TransferRequest{DialogID: "nope", Mode: "consultative", Target: "sip:c@x"}, apierr.CodeInvalidArgument},
		{"blind without target", session.TransferRequest{DialogID: "nope", Mode: blind}, apierr.CodeInvalidArgument},
		{"blind target without scheme", session.TransferRequest{DialogID: "nope", Mode: blind, Target: "carol@example.com"}, apierr.CodeInvalidArgument},
		{"blind target breaking out of <>", session.TransferRequest{DialogID: "nope", Mode: blind, Target: "sip:carol@example.com>;x=y"}, apierr.CodeInvalidArgument},
		{"blind target with CRLF", session.TransferRequest{DialogID: "nope", Mode: blind, Target: "sip:carol@example.com\r\nX-Evil: 1"}, apierr.CodeInvalidArgument},
		{"blind with consult_call", session.TransferRequest{DialogID: "nope", Mode: blind, Target: "sip:c@x", ConsultDialogID: "other"}, apierr.CodeInvalidArgument},
		{"attended without consult_call", session.TransferRequest{DialogID: "nope", Mode: att}, apierr.CodeInvalidArgument},
		{"attended with target", session.TransferRequest{DialogID: "nope", Mode: att, ConsultDialogID: "other", Target: "sip:c@x"}, apierr.CodeInvalidArgument},
		{"attended consult == call", session.TransferRequest{DialogID: "nope", Mode: att, ConsultDialogID: "nope"}, apierr.CodeInvalidArgument},
		{"valid request, unknown dialog", session.TransferRequest{DialogID: "nope", Mode: blind, Target: "sip:c@x"}, apierr.CodeNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ua.Transfer(context.Background(), tc.req); apierr.CodeOf(err) != tc.want {
				t.Fatalf("err=%v want %s", err, tc.want)
			}
		})
	}
}

// TestTheArrivalObserverRunsOnTheRealTransport pins D18's installation. The
// white-box order tests call observeArrival directly, so only a real packet
// through sipgo's transport can prove installHandlers registered it on the
// read loop.
func TestTheArrivalObserverRunsOnTheRealTransport(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)

	sendReferNotify(t, p, "refer", "SIP/2.0 100 Trying", "active;expires=60")
	waitForCond(t, func() bool { return sipua.ArrivalsObservedForTest(ua, res.DialogID) >= 1 })
}

// TestAReferCancelledAfterDispatchIsReportedAndMarksItsSubscriptionMaybeLive
// covers Transfer's cancelled-after-dispatch branch (Rule 13 fix batch A,
// finding 3). The peer swallows the REFER, so it is on the wire with no final
// response when the caller's ctx is cancelled. Transfer returns cancelled, one
// final transfer event carries "the call_transfer request was cancelled", the
// control op is released, and, because the peer may have accepted the REFER,
// an earlier subscription is recorded as maybe-live (D13).
func TestAReferCancelledAfterDispatchIsReportedAndMarksItsSubscriptionMaybeLive(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{SwallowRefer: true})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res := dialAnswered(t, ua, p, events)
	if sipua.ReferSubMaybeLiveForTest(ua, res.DialogID) {
		t.Fatal("an earlier subscription recorded as maybe-live before any REFER")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		out session.TransferResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		out, err := ua.Transfer(ctx, session.TransferRequest{
			DialogID: res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
		done <- outcome{out, err}
	}()
	waitForCond(t, func() bool { return p.Count("REFER") == 1 }) // dispatched, response swallowed
	cancel()
	var got outcome
	select {
	case got = <-done:
	case <-time.After(1500 * time.Millisecond): // well inside the 2 s Timer F
		t.Fatal("Transfer did not return promptly after its ctx was cancelled")
	}
	if apierr.CodeOf(got.err) != apierr.CodeCancelled {
		t.Fatalf("Transfer err=%v result=%+v, want cancelled", got.err, got.out)
	}
	evs := waitTransferEvents(t, events, res.DialogID, 1)
	if want := detail("blind", 0, "the call_transfer request was cancelled", true); len(evs) != 1 || !reflect.DeepEqual(evs[0].Detail, want) {
		t.Fatalf("transfer events=%+v want exactly one %+v", evs, want)
	}
	if inControlOp(ua, res.DialogID) {
		t.Fatal("a cancelled transfer left the dialog held")
	}
	if !sipua.ReferSubMaybeLiveForTest(ua, res.DialogID) {
		t.Fatal("an earlier subscription not recorded as maybe-live after a dispatched REFER's outcome became unknown (D13)")
	}
}

// refersRig is an answered call plus a peer that accepts every REFER with 202,
// on an injected clock, for the CF-012 window tests: transfers are started
// with start, and ended without a final NOTIFY with timeOut, which leaves an
// earlier subscription that may still be live.
type refersRig struct {
	armed  <-chan time.Duration
	p      *peer.Peer
	clk    *fakeclock.Clock
	ua     *sipua.UA
	events func() []session.UAEvent
	res    session.DialResult
	req    session.TransferRequest
}

func newRefersRig(t *testing.T) *refersRig {
	t.Helper()
	r := &refersRig{armed: armedWaits(t), p: startTransferPeer(t, peer.Behaviour{ReferStatus: 202}),
		clk: fakeclock.New(time.Unix(0, 0))}
	r.ua, _ = newDirectUA(t, r.clk)
	r.events = collect(t, r.ua)
	r.res = dialAnswered(t, r.ua, r.p, r.events)
	r.req = session.TransferRequest{DialogID: r.res.DialogID, Mode: session.TransferBlind, Target: "sip:carol@example.com"}
	return r
}

// start begins a transfer and waits for its outcome timer to arm.
func (r *refersRig) start(t *testing.T) {
	t.Helper()
	mustTransfer(t, r.ua, r.req)
	nextArm(t, r.armed)
}

// timeOut starts a transfer, lets it run out its default deadline and waits for
// event number n (its timeout) and for the control op to be released.
func (r *refersRig) timeOut(t *testing.T, n int) {
	t.Helper()
	r.start(t)
	r.clk.Advance(sipua.ReferOutcomeDefaultWait)
	waitTransferEvents(t, r.events, r.res.DialogID, n)
	waitForCond(t, func() bool { return !inControlOp(r.ua, r.res.DialogID) })
}

// requireIdlessFinalSettles sends an id-less 200 OK terminated NOTIFY and
// requires the in-flight transfer to settle with success as transfer event n.
// If it does not within 3 s (the id-less NOTIFY was refused), it advances the
// default deadline so the failure message names the cost CF-012 measured.
func (r *refersRig) requireIdlessFinalSettles(t *testing.T, n int) {
	t.Helper()
	sendReferNotify(t, r.p, "refer", "SIP/2.0 200 OK", "terminated;reason=noresource")
	deadline := time.Now().Add(3 * time.Second)
	for len(transferEvents(r.events, r.res.DialogID)) < n {
		if time.Now().After(deadline) {
			r.clk.Advance(sipua.ReferOutcomeDefaultWait)
			evs := waitTransferEvents(t, r.events, r.res.DialogID, n)
			t.Fatalf("the id-less final NOTIFY was refused; the transfer settled only at the outcome deadline: %+v", evs[n-1].Detail)
		}
		time.Sleep(5 * time.Millisecond)
	}
	evs := transferEvents(r.events, r.res.DialogID)
	if want := detail("blind", 200, "OK", true); !reflect.DeepEqual(evs[n-1].Detail, want) {
		t.Fatalf("transfer event %d detail=%+v want %+v", n, evs[n-1].Detail, want)
	}
	waitForCond(t, func() bool { return !inControlOp(r.ua, r.res.DialogID) })
}

// requireIdlessNotifyRefused sends an id-less NOTIFY and requires that it draws
// its 200 and settles nothing: the transfer stays in flight and no event is
// added to the running count of n.
func (r *refersRig) requireIdlessNotifyRefused(t *testing.T, n int, statusLine, subState string) {
	t.Helper()
	before := len(r.p.ResponseCodes())
	sendReferNotify(t, r.p, "refer", statusLine, subState)
	waitForCond(t, func() bool { return len(r.p.ResponseCodes()) > before })
	time.Sleep(300 * time.Millisecond)
	if got := len(transferEvents(r.events, r.res.DialogID)); got != n {
		t.Fatalf("%d transfer events after an id-less NOTIFY that should be refused, want %d", got, n)
	}
	if !inControlOp(r.ua, r.res.DialogID) {
		t.Fatal("an id-less NOTIFY inside the window settled the transfer")
	}
}

// TestALaterTransferSettlesOnItsIdlessNotifyOnceTheEarlierWindowHasPassed is the
// loopback reproduction of CF-012's measured cost: after transfer A ended
// inconclusively, B's id-less final NOTIFY (what Asterisk sends) must settle B
// once no stray from A is plausible, instead of B waiting out the 120 s deadline.
func TestALaterTransferSettlesOnItsIdlessNotifyOnceTheEarlierWindowHasPassed(t *testing.T) {
	r := newRefersRig(t)
	r.timeOut(t, 1) // A
	r.clk.Advance(sipua.ReferOutcomeMaxWait + sip.Timer_F)
	r.start(t) // B
	r.requireIdlessFinalSettles(t, 2)
}

// TestAnEarlierSubscriptionsTerminatedNotifyLetsTheNextTransferRouteIdlessNotifies:
// A's own terminated NOTIFY, arriving while no transfer is in flight, ends A's
// subscription, so B's id-less NOTIFYs route at once.
func TestAnEarlierSubscriptionsTerminatedNotifyLetsTheNextTransferRouteIdlessNotifies(t *testing.T) {
	r := newRefersRig(t)
	r.timeOut(t, 1) // A
	before := len(r.p.ResponseCodes())
	sendReferNotify(t, r.p, "refer", "SIP/2.0 486 Busy Here", "terminated;reason=noresource")
	waitForCond(t, func() bool { return len(r.p.ResponseCodes()) > before })
	if got := r.p.ResponseCodes()[before]; got != 200 {
		t.Fatalf("the terminated NOTIFY drew %d, want 200", got)
	}
	if n := len(transferEvents(r.events, r.res.DialogID)); n != 1 {
		t.Fatalf("%d transfer events after a NOTIFY with no transfer in flight, want 1", n)
	}
	r.start(t) // B, no clock advance
	r.requireIdlessFinalSettles(t, 2)
}

// TestAnIdlessNotifyIsRefusedUntilTheWindowEndsThenRouted pins routing-time
// evaluation and the boundary: B starts one second inside A's window; an id-less
// NOTIFY is refused; once the clock reaches the window's end exactly, the next
// one routes.
func TestAnIdlessNotifyIsRefusedUntilTheWindowEndsThenRouted(t *testing.T) {
	r := newRefersRig(t)
	r.timeOut(t, 1) // A concludes at t=120: the window ends at 120 + M + F
	r.clk.Advance(sipua.ReferOutcomeMaxWait + sip.Timer_F - time.Second)
	r.start(t) // B
	r.requireIdlessNotifyRefused(t, 1, "SIP/2.0 180 Ringing", "active")
	r.clk.Advance(time.Second)
	r.requireIdlessFinalSettles(t, 2)
}

// TestANotifierStatedExpiryBeyondTheCeilingExtendsTheWindow: A's provisional
// NOTIFY states expires=900, so A's window ends at 900 s + Timer_F, not at the
// ceiling's 632 s. B at t=640 is still inside it; C at the stated end is not.
func TestANotifierStatedExpiryBeyondTheCeilingExtendsTheWindow(t *testing.T) {
	r := newRefersRig(t)
	r.start(t) // A
	sendReferNotify(t, r.p, "refer", "SIP/2.0 180 Ringing", "active;expires=900")
	if got := nextArm(t, r.armed); got != sipua.ReferOutcomeMaxWait {
		t.Fatalf("A's window re-armed at %v, want the ceiling %v", got, sipua.ReferOutcomeMaxWait)
	}
	waitTransferEvents(t, r.events, r.res.DialogID, 1) // A's provisional
	r.clk.Advance(sipua.ReferOutcomeMaxWait)
	waitTransferEvents(t, r.events, r.res.DialogID, 2) // A's timeout, t=300
	waitForCond(t, func() bool { return !inControlOp(r.ua, r.res.DialogID) })

	// t = 2M + F + 8s = 640: past the unextended window (632), inside the stated one (932).
	r.clk.Advance(sipua.ReferOutcomeMaxWait + sip.Timer_F + 8*time.Second)
	r.start(t) // B
	r.requireIdlessNotifyRefused(t, 2, "SIP/2.0 200 OK", "terminated;reason=noresource")
	sendReferNotify(t, r.p, referEventHeader(t, r.p), "SIP/2.0 200 OK", "terminated;reason=noresource")
	evs := waitTransferEvents(t, r.events, r.res.DialogID, 3)
	if want := detail("blind", 200, "OK", true); !reflect.DeepEqual(evs[2].Detail, want) {
		t.Fatalf("B's final detail=%+v want %+v", evs[2].Detail, want)
	}
	waitForCond(t, func() bool { return !inControlOp(r.ua, r.res.DialogID) })

	// t = 900 s + F = 932 exactly: the stated window has ended.
	r.clk.Advance(900*time.Second + sip.Timer_F - (2*sipua.ReferOutcomeMaxWait + sip.Timer_F + 8*time.Second))
	r.start(t) // C
	r.requireIdlessFinalSettles(t, 4)
}
