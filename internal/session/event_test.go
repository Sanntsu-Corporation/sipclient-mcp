package session

import (
	"encoding/json"
	"testing"
)

func TestEventLogBounded(t *testing.T) {
	tests := []struct {
		name                string
		capacity            int
		appends             int
		since               int64
		wantLen             int
		wantFirstSeq        int64
		wantLastSeq         int64
		wantTruncatedBefore int64
	}{
		{"under capacity", 4, 3, 0, 3, 1, 3, 0},
		{"exactly capacity", 4, 4, 0, 4, 1, 4, 0},
		{"over capacity", 4, 6, 0, 4, 3, 6, 3},
		{"since mid", 4, 4, 2, 2, 3, 4, 0},
		{"since beyond head", 4, 4, 99, 0, 0, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := newEventLog(tc.capacity)
			for i := 0; i < tc.appends; i++ {
				l.append(int64(i)*10, EventRinging, nil)
			}
			got := l.since(tc.since)
			if len(got) != tc.wantLen {
				t.Fatalf("since(%d) len = %d, want %d", tc.since, len(got), tc.wantLen)
			}
			if tc.wantLen > 0 {
				if got[0].Seq != tc.wantFirstSeq {
					t.Errorf("first seq = %d, want %d", got[0].Seq, tc.wantFirstSeq)
				}
				if got[len(got)-1].Seq != tc.wantLastSeq {
					t.Errorf("last seq = %d, want %d", got[len(got)-1].Seq, tc.wantLastSeq)
				}
			}
			for i := 1; i < len(got); i++ {
				if got[i].Seq != got[i-1].Seq+1 {
					t.Fatalf("seq not monotonic by 1: %d then %d", got[i-1].Seq, got[i].Seq)
				}
			}
			if tb := l.truncatedBefore(); tb != tc.wantTruncatedBefore {
				t.Errorf("truncatedBefore = %d, want %d", tb, tc.wantTruncatedBefore)
			}
		})
	}
}

func TestAllEventTypesExhaustive(t *testing.T) {
	want := []EventType{
		EventIncomingCall, EventRinging, EventAnswered, EventMediaStart, EventMediaStop,
		EventDTMF, EventRecordStart, EventRecordStop, EventPlanStep, EventSessionRefresh,
		EventBye, EventPolicyTimeout, EventError, EventTransfer,
	}
	got := AllEventTypes()
	if len(got) != len(want) {
		t.Fatalf("AllEventTypes len = %d, want %d (§10.5's list is exhaustive)", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("AllEventTypes[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestWaitResultMarshalShapes is contract §2.5.2's Rule 7 acceptance for Task
// 8 (line 704): a timeout WaitResult must marshal to EXACTLY the key set
// {elapsed_ms, timed_out, call_state} — no event, seq or detail — and a
// success WaitResult to EXACTLY {event, seq, detail, elapsed_ms, timed_out,
// call_state}. This is the WaitResult declaration's own acceptance test; the
// method that produces one (Wait) is Task 9's.
func TestWaitResultMarshalShapes(t *testing.T) {
	keySet := func(t *testing.T, v any) map[string]bool {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		keys := make(map[string]bool, len(m))
		for k := range m {
			keys[k] = true
		}
		return keys
	}

	timeout := WaitResult{ElapsedMs: 30000, TimedOut: true, CallState: StateRinging}
	got := keySet(t, timeout)
	want := map[string]bool{"elapsed_ms": true, "timed_out": true, "call_state": true}
	if len(got) != len(want) {
		t.Fatalf("timeout key set = %v, want %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("timeout marshal missing key %q", k)
		}
	}

	seq := int64(3)
	success := WaitResult{
		Event:     &Event{Seq: seq, AtMs: 10, Type: EventAnswered},
		Seq:       &seq,
		Detail:    map[string]any{"sip_code": 200},
		ElapsedMs: 120,
		TimedOut:  false,
		CallState: StateAnswered,
	}
	got = keySet(t, success)
	want = map[string]bool{
		"event": true, "seq": true, "detail": true,
		"elapsed_ms": true, "timed_out": true, "call_state": true,
	}
	if len(got) != len(want) {
		t.Fatalf("success key set = %v, want %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("success marshal missing key %q", k)
		}
	}
}
