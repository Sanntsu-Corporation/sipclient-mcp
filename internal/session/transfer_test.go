package session

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// TestTransferEventLandsVerbatimAndSurvivesRecordTermination mirrors
// TestSessionRefreshSurvivesRecordTermination: the transferee's BYE (spec §4.5)
// routinely races the final NOTIFY, and the outcome must still land in the log
// that explains why the call ended.
func TestTransferEventLandsVerbatimAndSurvivesRecordTermination(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	c.setDialogIdentity("dlg-xfer", "callid-xfer")
	prov := map[string]any{"mode": "blind", "status_code": 100, "reason": "Trying", "final": false, "success": false}
	final := map[string]any{"mode": "blind", "status_code": 200, "reason": "OK", "final": true, "success": true}

	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{Kind: UAEventTransfer, DialogID: "dlg-xfer", CallID: "callid-xfer", Code: 100, Detail: prov})
	if err := c.TryTerminate(fc.Now(), "remote_bye", EventBye); err != nil {
		t.Fatalf("TryTerminate: %v", err)
	}
	m.RecordTermination(c)
	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{Kind: UAEventTransfer, DialogID: "dlg-xfer", CallID: "callid-xfer", Code: 200, Detail: final})

	evs, _, _ := c.Events(0)
	var got []map[string]any
	for _, ev := range evs {
		if ev.Type == EventTransfer {
			got = append(got, ev.Detail)
		}
	}
	if want := []map[string]any{prov, final}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transfer events=%+v want %+v", got, want)
	}
}

// TestCallWaitUntilTransferReturnsATransferEvent is D7.
func TestCallWaitUntilTransferReturnsATransferEvent(t *testing.T) {
	m, fc := newTestManager(t)
	c := mustCall(t, m, "s1")
	c.Append(fc.Now(), EventDTMF, map[string]any{"digit": "1"})
	c.Append(fc.Now(), EventTransfer, map[string]any{"final": true})
	res, err := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "transfer", TimeoutMs: 1000, Since: 0})
	if err != nil {
		t.Fatalf("Wait(until=transfer): %v", err)
	}
	if res.Event == nil || res.Event.Type != EventTransfer || res.Detail["final"] != true {
		t.Fatalf("Wait returned %+v, want the transfer event", res)
	}
}

// TestCallWaitUntilTransferReturnsFinalNotProvisional is Rule 13 Finding 1:
// call_wait(until="transfer") must match on detail.final, not just the bare
// EventTransfer type, so it never hands back an in-flight provisional NOTIFY
// as if it were the transfer's outcome. Both a provisional and a final event
// are already in the log when Wait registers (the register() path), so this
// exercises the predicate applied to c.log.since(0), not signalLocked.
func TestCallWaitUntilTransferReturnsFinalNotProvisional(t *testing.T) {
	m, fc := newTestManager(t)
	c := mustCall(t, m, "s1")
	c.Append(fc.Now(), EventTransfer, map[string]any{
		"mode": "blind", "status_code": 100, "reason": "Trying", "final": false, "success": false})
	c.Append(fc.Now(), EventTransfer, map[string]any{
		"mode": "blind", "status_code": 200, "reason": "OK", "final": true, "success": true})

	res, err := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "transfer", TimeoutMs: 1000, Since: 0})
	if err != nil {
		t.Fatalf("Wait(until=transfer): %v", err)
	}
	if res.TimedOut {
		t.Fatal("Wait timed out; want the already-final transfer event returned immediately")
	}
	if res.Event == nil || res.Event.Type != EventTransfer || res.Detail["final"] != true {
		t.Fatalf("Wait returned %+v, want the FINAL transfer event, not the provisional", res)
	}
	if res.Detail["status_code"] != 200 {
		t.Fatalf("Wait returned status_code %v (the provisional's), want 200 (the final's)",
			res.Detail["status_code"])
	}
}

// TestCallWaitUntilTransferIgnoresLiveProvisionalNotify is Finding 1's live
// (signalLocked) counterpart: a provisional UAEventTransfer delivered WHILE a
// call_wait(until="transfer") is parked must not wake it, and the final event
// that follows must.
func TestCallWaitUntilTransferIgnoresLiveProvisionalNotify(t *testing.T) {
	m, fc := newTestManager(t)
	c := mustCall(t, m, "s1")

	done := make(chan WaitResult, 1)
	go func() {
		r, err := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "transfer", TimeoutMs: 60000, Since: 0})
		if err != nil {
			t.Errorf("Wait: %v", err)
		}
		done <- r
	}()
	waitForCount(t, m, c, 1)

	c.Append(fc.Now(), EventTransfer, map[string]any{
		"mode": "blind", "status_code": 100, "reason": "Trying", "final": false, "success": false})
	select {
	case r := <-done:
		t.Fatalf("Wait returned on a provisional transfer event: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}

	c.Append(fc.Now(), EventTransfer, map[string]any{
		"mode": "blind", "status_code": 200, "reason": "OK", "final": true, "success": true})
	select {
	case r := <-done:
		if r.TimedOut || r.Detail["final"] != true {
			t.Fatalf("Wait returned %+v, want the final transfer event", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not return after the final transfer event was appended")
	}
	assertWaiterAccountsZero(t, m, c, "s1")
}
