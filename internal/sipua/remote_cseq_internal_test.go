package sipua

// CF-101 (RFC 3261 12.2.2): the dialog's remote CSeq, its compare/raise helpers
// and their interplay with the arrival gate (D18).

import (
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

func cseqReq(method sip.RequestMethod, n uint32) *sip.Request {
	req := sip.NewRequest(method, sip.Uri{User: "alice", Host: "here"})
	req.AppendHeader(&sip.CSeqHeader{SeqNo: n, MethodName: method})
	return req
}

func TestRemoteCSeqInOrderLockedTable(t *testing.T) {
	inbound := &dialog{direction: session.Inbound, invite: cseqReq(sip.INVITE, 10)}
	steps := []struct {
		cseq uint32
		want bool
		rem  uint32
	}{{9, false, 10}, {10, true, 10}, {11, true, 11}, {11, true, 11}, {10, false, 11}}
	for _, s := range steps {
		if got := remoteCSeqInOrderLocked(inbound, cseqReq(sip.INFO, s.cseq)); got != s.want || inbound.remoteCSeq != s.rem {
			t.Fatalf("inbound CSeq %d: got %v remote %d; want %v remote %d", s.cseq, got, inbound.remoteCSeq, s.want, s.rem)
		}
	}
	outbound := &dialog{direction: session.Outbound, invite: cseqReq(sip.INVITE, 5)}
	for _, s := range []struct {
		cseq uint32
		want bool
		rem  uint32
	}{{100, true, 100}, {50, false, 100}, {101, true, 101}} {
		if got := remoteCSeqInOrderLocked(outbound, cseqReq(sip.INFO, s.cseq)); got != s.want || outbound.remoteCSeq != s.rem {
			t.Fatalf("outbound CSeq %d: got %v remote %d; want %v remote %d", s.cseq, got, outbound.remoteCSeq, s.want, s.rem)
		}
	}
	noCSeq := sip.NewRequest(sip.INFO, sip.Uri{Host: "h"})
	before := outbound.remoteCSeq
	if !remoteCSeqInOrderLocked(outbound, noCSeq) || outbound.remoteCSeq != before {
		t.Fatal("a request without CSeq must pass and leave the remote number alone")
	}
}

// TestOutOfOrderGatedRequestLeavesItsTicket: during a held control operation a
// ticketed lower-CSeq BYE is answered 500 and a following in-order NOTIFY is
// applied without having to wait out the arrival bound behind it (C10).
func TestOutOfOrderGatedRequestLeavesItsTicket(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-ooo-ticket")
	evs := startNotifyTransfer(t, u, d, newReferWaiter(7, session.TransferBlind))
	u.calls.mu.Lock()
	d.remoteCSeq, d.remoteCSeqSet = 20, true
	u.calls.mu.Unlock()
	bye := peerByeReq("cid-ooo-ticket", ours) // CSeq 10 < 20
	notify := referNotifyReq("cid-ooo-ticket", "peer-tag", ours, "refer;id=7", "SIP/2.0 200 OK")
	notify.CSeq().SeqNo = 25
	waiting := setArrivalWaitHook(t, sip.NOTIFY)

	u.observeArrival(bye)
	u.observeArrival(notify)
	byeTx := &stubServerTx{}
	u.onBye(bye, byeTx)
	if got := byeTx.last().StatusCode; got != 500 {
		t.Fatalf("the lower-CSeq BYE drew %d, want 500", got)
	}
	notifyTx := &stubServerTx{}
	notifyDone := make(chan struct{})
	go func() {
		defer close(notifyDone)
		u.onNotify(notify, notifyTx)
	}()
	select {
	case <-notifyDone:
	case <-waiting:
		t.Fatal("the NOTIFY waited behind the out-of-order BYE's ticket")
	case <-time.After(3 * time.Second):
		t.Fatal("the NOTIFY did not finish")
	}
	if got := notifyTx.last().StatusCode; got != 200 {
		t.Fatalf("the in-order NOTIFY drew %d, want 200", got)
	}
	select {
	case ev := <-evs:
		if ev.Detail["success"] != true {
			t.Fatalf("transfer event %+v, want success", ev.Detail)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the transfer never settled")
	}
	u.calls.mu.Lock()
	phase := d.phase
	u.calls.mu.Unlock()
	if phase == phaseDone {
		t.Fatal("the out-of-order BYE tore the dialog down")
	}
}

// TestByeComparesButNeverRaisesTheRemoteCSeq (C8a): with the remote number at 8,
// NOTIFY 9 then BYE 10 on the wire and the BYE's handler running first, the BYE
// must not raise the remote number to 10, or the NOTIFY would draw 500.
func TestByeComparesButNeverRaisesTheRemoteCSeq(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-bye-no-raise")
	evs := startNotifyTransfer(t, u, d, newReferWaiter(7, session.TransferBlind))
	u.calls.mu.Lock()
	d.remoteCSeq, d.remoteCSeqSet = 8, true
	u.calls.mu.Unlock()
	notify := referNotifyReq("cid-bye-no-raise", "peer-tag", ours, "refer;id=7", "SIP/2.0 200 OK") // CSeq 9
	bye := peerByeReq("cid-bye-no-raise", ours)                                                    // CSeq 10
	waiting := setArrivalWaitHook(t, sip.BYE)
	u.observeArrival(notify)
	u.observeArrival(bye)
	byeDone := make(chan struct{})
	go func() {
		defer close(byeDone)
		u.onBye(bye, &stubServerTx{})
	}()
	select {
	case <-waiting:
	case <-time.After(3 * time.Second):
		t.Fatal("onBye did not wait for the earlier NOTIFY")
	}
	u.calls.mu.Lock()
	got := d.remoteCSeq
	u.calls.mu.Unlock()
	if got != 8 {
		t.Fatalf("remote CSeq = %d after the BYE's first section, want 8 (a BYE never raises it)", got)
	}
	notifyTx := &stubServerTx{}
	u.onNotify(notify, notifyTx)
	if c := notifyTx.last().StatusCode; c != 200 {
		t.Fatalf("the NOTIFY drew %d, want 200", c)
	}
	select {
	case ev := <-evs:
		if ev.Detail["success"] != true {
			t.Fatalf("transfer event %+v, want success", ev.Detail)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the transfer never settled")
	}
	<-byeDone
}
