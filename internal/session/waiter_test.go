package session

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// newWaiterManager is a named wrapper over Task 8's newManagerWith — ONE
// manager constructor for the whole package (Rule 18); the name documents which
// limits the test is about.
// ciScaled stretches a poll deadline on CI only; every caller returns as soon
// as its condition holds, and slow shared runners under -race need headroom.
func ciScaled(d time.Duration) time.Duration {
	if os.Getenv("CI") != "" {
		return d * 5
	}
	return d
}

func newWaiterManager(t *testing.T, mut func(*policy.Limits)) (*Manager, *fakeclock.Clock) {
	t.Helper()
	return newManagerWith(t, mut)
}

func waitForCount(t *testing.T, m *Manager, c *Call, want int) {
	t.Helper()
	deadline := time.Now().Add(ciScaled(2 * time.Second))
	for time.Now().Before(deadline) {
		if m.WaiterCount(string(c.Handle())) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("call waiter count never reached %d (last %d)", want, m.WaiterCount(string(c.Handle())))
}

func waitForSessionCount(t *testing.T, m *Manager, sid string, want int64) {
	t.Helper()
	deadline := time.Now().Add(ciScaled(2 * time.Second))
	for time.Now().Before(deadline) {
		if m.SessionWaiterCount(sid) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("session waiter count never reached %d (last %d)", want, m.SessionWaiterCount(sid))
}

func assertWaiterAccountsZero(t *testing.T, m *Manager, c *Call, sid string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.WaiterCount(string(c.Handle())) == 0 && m.SessionWaiterCount(sid) == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("waiter accounts not both zero: call=%d session=%d",
		m.WaiterCount(string(c.Handle())), m.SessionWaiterCount(sid))
}

func TestWaitBoundsRejectBeforeRegistration(t *testing.T) {
	tests := []struct {
		name      string
		limits    func(*policy.Limits)
		timeoutMs int
		until     string
		wantCode  apierr.Code
		wantKey   string
	}{
		{"timeout above the cap", func(l *policy.Limits) { l.MaxWaitTimeoutMS = 5000 }, 5001, "answered",
			apierr.CodeResourceLimit, "max_wait_timeout_ms"},
		{"timeout at the cap is accepted", func(l *policy.Limits) { l.MaxWaitTimeoutMS = 5000 }, 5000, "answered", "", ""},
		{"zero timeout", nil, 0, "answered", apierr.CodeInvalidArgument, ""},
		{"negative timeout", nil, -1, "answered", apierr.CodeInvalidArgument, ""},
		{"unknown until", nil, 1000, "banana", apierr.CodeInvalidArgument, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, fc := newWaiterManager(t, tc.limits)
			c := mustCall(t, m, "s1")

			if tc.wantCode == "" {
				// Accepted: park it, then time it out so the test terminates.
				done := make(chan WaitResult, 1)
				go func() {
					r, err := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: tc.until, TimeoutMs: tc.timeoutMs, Since: 0})
					if err != nil {
						t.Errorf("Wait: %v", err)
					}
					done <- r
				}()
				waitForCount(t, m, c, 1)
				fc.BlockUntil(1)
				fc.Advance(time.Duration(tc.timeoutMs) * time.Millisecond)
				r := <-done
				if !r.TimedOut {
					t.Errorf("TimedOut = false, want true")
				}
				assertWaiterAccountsZero(t, m, c, "s1")
				return
			}

			_, err := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: tc.until, TimeoutMs: tc.timeoutMs, Since: 0})
			var ae *apierr.Error
			if !errors.As(err, &ae) {
				t.Fatalf("err = %v, want *apierr.Error", err)
			}
			if ae.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", ae.Code, tc.wantCode)
			}
			if tc.wantKey != "" && ae.Rule != tc.wantKey {
				t.Errorf("rule = %q, want %q (the response must NAME the key)", ae.Rule, tc.wantKey)
			}
			// A rejected wait consumes nothing.
			assertWaiterAccountsZero(t, m, c, "s1")
		})
	}
}

func TestWaitPerCallCap(t *testing.T) {
	m, fc := newWaiterManager(t, func(l *policy.Limits) { l.MaxWaitersPerCall = 2 })
	c := mustCall(t, m, "s1")

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "answered", TimeoutMs: 60000, Since: 0}); err != nil {
				t.Errorf("parked wait: %v", err)
			}
		}()
	}
	waitForCount(t, m, c, 2)

	_, err := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "answered", TimeoutMs: 60000, Since: 0})
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != apierr.CodeResourceLimit || ae.Rule != "max_waiters_per_call" {
		t.Fatalf("third wait err = %v, want resource_limit naming max_waiters_per_call", err)
	}
	if got := m.WaiterCount(string(c.Handle())); got != 2 {
		t.Fatalf("waiter count = %d, want 2 — the rejected wait must consume nothing", got)
	}

	fc.BlockUntil(2)
	fc.Advance(60 * time.Second)
	wg.Wait()
	assertWaiterAccountsZero(t, m, c, "s1")
}

func TestWaitPerSessionCap(t *testing.T) {
	m, fc := newWaiterManager(t, func(l *policy.Limits) { l.MaxWaitersPerSession = 3 })
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	calls := make([]*Call, 4)
	for i := range calls {
		c, err := m.CreateCall(ctx, "s1", ua.Handle(), Inbound, StateRinging)
		if err != nil {
			t.Fatalf("CreateCall: %v", err)
		}
		calls[i] = c
	}

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(c *Call) {
			defer wg.Done()
			if _, err := m.Wait(ctx, WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "answered", TimeoutMs: 60000, Since: 0}); err != nil {
				t.Errorf("parked wait: %v", err)
			}
		}(calls[i])
	}
	waitForSessionCount(t, m, "s1", 3)

	_, err = m.Wait(ctx, WaitRequest{SessionID: "s1", Handle: calls[3].Handle(), Until: "answered", TimeoutMs: 60000, Since: 0})
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != apierr.CodeResourceLimit || ae.Rule != "max_waiters_per_session" {
		t.Fatalf("fourth wait err = %v, want resource_limit naming max_waiters_per_session", err)
	}

	fc.BlockUntil(3)
	fc.Advance(60 * time.Second)
	wg.Wait()
	if got := m.SessionWaiterCount("s1"); got != 0 {
		t.Fatalf("session waiter count = %d, want 0", got)
	}

	// Rule 5's decrement releases the session account rather than leaking it:
	// a fresh wait is ACCEPTED after the budget has been issued and released.
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		if _, err := m.Wait(ctx, WaitRequest{SessionID: "s1", Handle: calls[0].Handle(), Until: "answered", TimeoutMs: 60000, Since: 0}); err != nil {
			t.Errorf("post-release wait: %v", err)
		}
	}()
	waitForSessionCount(t, m, "s1", 1)
	fc.BlockUntil(1)
	fc.Advance(60 * time.Second)
	<-accepted
}

// TestWaitTimeoutCarriesNoEventOverTheRealPath is the same property Task 8's
// TestWaitResultMarshalShapes (event_test.go) pins over a hand-built struct,
// driven here through Manager.Wait instead, so a future change to Wait's
// return cannot pass the shape test while emitting the wrong thing.
//
// The brief's own TestWaitResultWireShapes is DROPPED here (D39): it
// duplicates event_test.go's TestWaitResultMarshalShapes, which already
// asserts both key sets AND pins the pointer shape at COMPILE time —
// event_test.go:110-111 assigns `res.Event` and `res.Seq` as pointers
// directly, so the brief's own mutation criterion for that test ("change
// WaitResult.Event to a value type, re-run, confirm UNEXPECTED key") is
// unreachable: the build fails at event_test.go:110-111 before any test runs.
func TestWaitTimeoutCarriesNoEventOverTheRealPath(t *testing.T) {
	m, fc := newWaiterManager(t, nil)
	c := mustCall(t, m, "s1")

	done := make(chan WaitResult, 1)
	go func() {
		r, err := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "dtmf", TimeoutMs: 60000, Since: 0})
		if err != nil {
			t.Errorf("Wait: %v", err)
		}
		done <- r
	}()
	waitForCount(t, m, c, 1)
	fc.BlockUntil(1)
	fc.Advance(60 * time.Second)
	res := <-done

	if !res.TimedOut {
		t.Fatal("TimedOut = false, want true")
	}
	if res.Event != nil {
		t.Errorf("a timed-out wait carries an event: %+v — §10.5's timeout shape has no "+
			"`event` key at all", *res.Event)
	}
	if res.Seq != nil {
		t.Errorf("a timed-out wait carries seq %d, want no seq key", *res.Seq)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), `"event"`) || strings.Contains(string(raw), `"seq"`) {
		t.Fatalf("timeout response contains event or seq: %s", raw)
	}
}

// TestFirstEventSeqIsOne pins the numbering §10.5's `since` default depends on.
// If the first seq were 0, call_events(since=0) — the documented default,
// meaning "everything" — would silently skip the first event of every call,
// which on an inbound call is `incoming_call` (R14).
func TestFirstEventSeqIsOne(t *testing.T) {
	m, fc := newWaiterManager(t, nil)
	c := mustCall(t, m, "s1")
	first := c.Append(fc.Now(), EventIncomingCall, nil)
	if first.Seq != 1 {
		t.Fatalf("first event seq = %d, want 1 — since=0 means \"everything\", so no real "+
			"event may carry seq 0", first.Seq)
	}
	evs, _, _ := c.Events(0)
	if len(evs) != 1 {
		t.Fatalf("Events(0) returned %d events, want 1 — since=0 must return the first event",
			len(evs))
	}
}

func TestTerminalBroadcastWakesEveryWaiter(t *testing.T) {
	m, _ := newWaiterManager(t, func(l *policy.Limits) { l.MaxWaitersPerCall = 8 })
	c := mustCall(t, m, "s1")

	untils := []string{"answered", "dtmf", "terminated", "any"}
	results := make([]WaitResult, len(untils))
	errs := make([]error, len(untils))
	var wg sync.WaitGroup
	for i, u := range untils {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			results[i], errs[i] = m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: u, TimeoutMs: 300000, Since: 0})
		}(i, u)
	}
	waitForCount(t, m, c, len(untils))

	// The far end rejects the INVITE with 486.
	if err := c.TryReject(time.Unix(1_700_000_001, 0), 486, "Busy Here"); err != nil {
		t.Fatalf("reject: %v", err)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("not all waiters returned within 100ms of the terminal event (§6.3 rule 2)")
	}

	for i, u := range untils {
		if errs[i] != nil {
			t.Fatalf("waiter %q: %v", u, errs[i])
		}
		if results[i].TimedOut {
			t.Errorf("waiter %q timed out; a terminal state must broadcast to ALL waiters "+
				"regardless of their until", u)
		}
		if results[i].CallState != StateTerminated {
			t.Errorf("waiter %q call_state = %q, want terminated", u, results[i].CallState)
		}
		if results[i].Seq == nil {
			t.Errorf("waiter %q returned no seq", u)
		}
	}
	assertWaiterAccountsZero(t, m, c, "s1")
}

func TestCancellationRemovesWaiterImmediately(t *testing.T) {
	m, _ := newWaiterManager(t, nil)
	c := mustCall(t, m, "s1")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := m.Wait(ctx, WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "answered", TimeoutMs: 300000, Since: 0})
		done <- err
	}()
	waitForCount(t, m, c, 1)

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("waiter did not return within 100ms of cancellation (§6.3 rule 4)")
	}
	assertWaiterAccountsZero(t, m, c, "s1")

	// The call proceeds unaffected: a dropped client must not touch it.
	if got := c.State(); got != StateRinging {
		t.Fatalf("call state = %q after waiter cancellation, want ringing", got)
	}
}

func TestEvictionWhileParkedReturnsGone(t *testing.T) {
	m, _ := newWaiterManager(t, nil)
	c := mustCall(t, m, "s1")

	done := make(chan error, 1)
	go func() {
		_, err := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "answered", TimeoutMs: 300000, Since: 0})
		done <- err
	}()
	waitForCount(t, m, c, 1)

	c.MarkGoneAndWake()
	select {
	case err := <-done:
		var ae *apierr.Error
		if !errors.As(err, &ae) || ae.Code != apierr.CodeGone {
			t.Fatalf("err = %v, want gone", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("parked waiter did not return gone within 100ms")
	}
	assertWaiterAccountsZero(t, m, c, "s1")
}

func TestGoneFlagIsTerminalAndNeverCleared(t *testing.T) {
	m, _ := newWaiterManager(t, nil)
	c := mustCall(t, m, "s1")
	c.MarkGoneAndWake()
	for i := 0; i < 3; i++ {
		_, err := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "answered", TimeoutMs: 300000, Since: 0})
		var ae *apierr.Error
		if !errors.As(err, &ae) || ae.Code != apierr.CodeGone {
			t.Fatalf("attempt %d: err = %v, want gone", i, err)
		}
	}
	assertWaiterAccountsZero(t, m, c, "s1")
}

// TestCallWaitSinceReturnsOnlyEventsAfterTheCursor is CF-015: register()
// always scanned the whole log from offset 0, so call_wait(until=X) returned
// the FIRST matching event ever logged rather than the next new one, for
// every until value. A since cursor (mirroring CallEventsInput's existing
// field) fixes this for all of them, not just "transfer".
func TestCallWaitSinceReturnsOnlyEventsAfterTheCursor(t *testing.T) {
	for _, tc := range []struct {
		until      string
		firstType  EventType
		firstDet   map[string]any
		secondType EventType
		secondDet  map[string]any
	}{
		{"ringing", EventRinging, nil, EventRinging, nil},
		{"answered", EventAnswered, nil, EventAnswered, nil},
		{"media_start", EventMediaStart, nil, EventMediaStart, nil},
		{"dtmf", EventDTMF, map[string]any{"digit": "1"}, EventDTMF, map[string]any{"digit": "2"}},
		{"completed", EventBye, nil, EventBye, nil},
		{"transfer", EventTransfer, map[string]any{"final": true}, EventTransfer, map[string]any{"final": true}},
	} {
		t.Run(tc.until, func(t *testing.T) {
			m, fc := newTestManager(t)
			c := mustCall(t, m, "s1")
			c.Append(fc.Now(), tc.firstType, tc.firstDet)

			first, err := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: tc.until, TimeoutMs: 1000, Since: 0})
			if err != nil {
				t.Fatalf("first Wait: %v", err)
			}
			if first.Seq == nil {
				t.Fatal("first Wait returned no seq")
			}

			c.Append(fc.Now(), tc.secondType, tc.secondDet)

			second, err := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: tc.until, TimeoutMs: 1000, Since: *first.Seq})
			if err != nil {
				t.Fatalf("second Wait with since=%d: %v", *first.Seq, err)
			}
			if second.Seq == nil || *second.Seq != *first.Seq+1 {
				t.Fatalf("second Wait returned seq %+v, want the SECOND event's seq (%d), not the first's",
					second.Seq, *first.Seq+1)
			}
		})
	}
}

// TestCallWaitSinceAheadOfTheLogParksAndWakesOnANewerEvent is Rule 13 wave
// review, Cycle 4: every existing `since` test seeds it AT an event already in
// the log. This seeds it 100 PAST the log's current tail (register's `evs :=
// c.log.since(since)` then returns nothing to scan, and the call is not
// terminal, so it must park exactly like since=0 would) and confirms Wait
// still parks normally — no panic, no immediate (wrong) match on a stale
// event — and wakes on the next genuinely NEW event once its seq exceeds
// since.
func TestCallWaitSinceAheadOfTheLogParksAndWakesOnANewerEvent(t *testing.T) {
	m, fc := newTestManager(t)
	c := mustCall(t, m, "s1")
	c.Append(fc.Now(), EventRinging, nil)

	done := make(chan WaitResult, 1)
	go func() {
		res, err := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "ringing", TimeoutMs: 1000, Since: 100})
		if err != nil {
			t.Errorf("Wait: %v", err)
			return
		}
		done <- res
	}()

	waitForCount(t, m, c, 1)
	c.Append(fc.Now(), EventRinging, nil)

	select {
	case res := <-done:
		if res.TimedOut || res.Seq == nil {
			t.Fatalf("Wait result %+v, want a real (non-timeout) match on the newly appended event", res)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Wait never woke on the new event after since ahead of the log's tail")
	}
}

// TestCallWaitOmittedSinceMatchesTodaysBehavior pins backward compatibility
// (Review Focus #3). since is a REQUIRED parameter on (*Manager).Wait, not
// variadic, so "since omitted" is a JSON-seam concept — an absent
// CallWaitInput.Since field deserializes to the zero value — rather than a
// Wait call that leaves the argument off. This test exercises that zero value
// directly and confirms it still gets the FIRST matching event, exactly as
// before this fix.
func TestCallWaitOmittedSinceMatchesTodaysBehavior(t *testing.T) {
	m, fc := newTestManager(t)
	c := mustCall(t, m, "s1")
	c.Append(fc.Now(), EventDTMF, map[string]any{"digit": "1"})
	c.Append(fc.Now(), EventDTMF, map[string]any{"digit": "2"})

	res, err := m.Wait(context.Background(), WaitRequest{SessionID: "s1", Handle: c.Handle(), Until: "dtmf", TimeoutMs: 1000, Since: 0})
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if res.Detail["digit"] != "1" {
		t.Fatalf("Wait with since=0 returned digit %v, want the FIRST event's (\"1\")", res.Detail["digit"])
	}
}
