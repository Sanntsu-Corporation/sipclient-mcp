package session

import (
	"context"
	"testing"
	"time"
)

func TestRecordDigitAppendsBothTheRingAndTheEventLog(t *testing.T) {
	c := newCall("call_1", "ua_1", &sessionRecord{id: "s"}, Inbound, StateAnswered, 64, time.Unix(0, 0))
	at := time.Unix(10, 0)
	c.RecordDigit(at, "5", "rfc2833", 120)

	digits, next := c.DigitsSince(0)
	if len(digits) != 1 || digits[0].Digit != "5" || digits[0].Mode != "rfc2833" ||
		digits[0].DurationMs != 120 || digits[0].AtMs != at.UnixMilli() {
		t.Fatalf("digits=%+v", digits)
	}
	if next != digits[0].Seq {
		t.Fatalf("next_since=%d want %d", next, digits[0].Seq)
	}
	evs, _, _ := c.Events(0)
	if len(evs) != 1 || evs[0].Type != EventDTMF {
		t.Fatalf("events=%+v want one dtmf event", evs)
	}
	// Decision 16: the event detail mirrors dtmf_received's element shape.
	if evs[0].Detail["digit"] != "5" || evs[0].Detail["mode"] != "rfc2833" ||
		evs[0].Detail["duration_ms"] != 120 {
		t.Fatalf("detail=%+v want {digit, mode, duration_ms}", evs[0].Detail)
	}
}

func TestDigitsSinceIsASeqCursor(t *testing.T) {
	c := newCall("call_1", "ua_1", &sessionRecord{id: "s"}, Inbound, StateAnswered, 64, time.Unix(0, 0))
	for _, d := range []string{"1", "2", "3"} {
		c.RecordDigit(time.Unix(0, 0), d, "inband", 100)
	}
	all, next := c.DigitsSince(0)
	if len(all) != 3 {
		t.Fatalf("len=%d want 3", len(all))
	}
	rest, next2 := c.DigitsSince(all[0].Seq)
	if len(rest) != 2 || rest[0].Digit != "2" {
		t.Fatalf("rest=%+v", rest)
	}
	if next2 != next {
		t.Fatalf("next_since drifted: %d vs %d", next2, next)
	}
	none, _ := c.DigitsSince(next)
	if len(none) != 0 {
		t.Fatalf("draining past the cursor returned %d digits", len(none))
	}
}

func TestDigitRingIsBoundedAndDropsOldest(t *testing.T) {
	c := newCall("call_1", "ua_1", &sessionRecord{id: "s"}, Inbound, StateAnswered, 4, time.Unix(0, 0))
	for i := 0; i < 6; i++ {
		c.RecordDigit(time.Unix(0, 0), "1", "inband", 100)
	}
	digits, _ := c.DigitsSince(0)
	if len(digits) != 4 {
		t.Fatalf("ring held %d digits, want the 4-entry bound", len(digits))
	}
	if digits[0].Seq != 3 {
		t.Fatalf("oldest surviving seq=%d want 3 (the first two were dropped)", digits[0].Seq)
	}
}

func TestDigitsReadableAfterTermination(t *testing.T) {
	c := newCall("call_1", "ua_1", &sessionRecord{id: "s"}, Inbound, StateAnswered, 64, time.Unix(0, 0))
	c.RecordDigit(time.Unix(0, 0), "9", "inband", 100)
	if err := c.TryTerminate(time.Unix(1, 0), "local_hangup", EventBye); err != nil {
		t.Fatal(err)
	}
	digits, _ := c.DigitsSince(0)
	if len(digits) != 1 {
		t.Fatal("dtmf_received must answer after hangup (§N3)")
	}
}

// TestLastDigitSurvivesRecordTermination is the DTMF half of Task 5's
// event-loss race: the digit a peer sends immediately before it BYEs is
// detected on the RX goroutine and can arrive after RecordTermination has moved
// the call out of s.liveCalls. handleDTMF must still find it (Task 5's
// callByDialogIDForEvent), or the most interesting digit of the call — the one
// a wait_dtmf or dtmf_received is watching for — is dropped in silence.
func TestLastDigitSurvivesRecordTermination(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	c.setDialogIdentity("dlg-dtmf", "callid-dtmf")
	if err := c.TryTerminate(fc.Now(), "remote_bye", EventBye); err != nil {
		t.Fatalf("TryTerminate: %v", err)
	}
	m.RecordTermination(c)

	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
		Kind: UAEventDTMF, DialogID: "dlg-dtmf", CallID: "callid-dtmf",
		Digit: "7", DTMFMode: "rfc2833", DurationMs: 100,
	})

	digits, _ := c.DigitsSince(0)
	if len(digits) != 1 || digits[0].Digit != "7" {
		t.Fatalf("digits=%+v — the last digit was dropped by the live-only lookup", digits)
	}
}

// TestSessionRefreshSurvivesRecordTermination mirrors
// TestLastDigitSurvivesRecordTermination for handleSessionRefresh: a refresh
// completing on the RX goroutine right as the peer BYEs must still resolve
// through callByDialogIDForEvent and land in the event log with its Detail
// intact, both while the call is still live and after RecordTermination has
// moved it out of s.liveCalls.
func TestSessionRefreshSurvivesRecordTermination(t *testing.T) {
	m, fc := newTestManager(t)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	c.setDialogIdentity("dlg-refresh", "callid-refresh")
	detail := map[string]any{"role": "uac", "requested_s": 1800}

	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
		Kind: UAEventSessionRefresh, DialogID: "dlg-refresh", CallID: "callid-refresh",
		Detail: detail,
	})

	if err := c.TryTerminate(fc.Now(), "remote_bye", EventBye); err != nil {
		t.Fatalf("TryTerminate: %v", err)
	}
	m.RecordTermination(c)

	m.handleUAEvent(ctx, c.UAHandle(), UAEvent{
		Kind: UAEventSessionRefresh, DialogID: "dlg-refresh", CallID: "callid-refresh",
		Detail: detail,
	})

	evs, _, _ := c.Events(0)
	count := 0
	for _, ev := range evs {
		if ev.Type != EventSessionRefresh {
			continue
		}
		count++
		if ev.Detail["role"] != "uac" || ev.Detail["requested_s"] != 1800 {
			t.Fatalf("detail=%+v want {role, requested_s}", ev.Detail)
		}
	}
	if count != 2 {
		t.Fatalf("events=%+v want two session_refresh events (before and after termination)", evs)
	}
}
