package session

import (
	"context"
	"fmt"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// waiter is a registration on a call, not a free-floating goroutine (§6.3).
//
// THE CHANNEL IS BUFFERED WITH CAPACITY 1 AND EVERY SIGNAL IS A NON-BLOCKING
// SEND. This is normative, not an implementation detail. Rule 1 signals
// matching waiters WHILE HOLDING THE CALL MUTEX, and rules 4 and 5 have
// waiters remove themselves UNDER THAT SAME MUTEX. With an unbuffered channel
// the signaller would block, holding the mutex, on a waiter that is itself
// blocked acquiring it — a deadlock that no amount of care elsewhere prevents.
//
// A waiter MAY be signalled more than once: a terminal broadcast from
// signalLocked can be followed by MarkGoneAndWake. Capacity 1 plus the
// non-blocking send means the FIRST signal to reach the channel wins and every
// later one is dropped at the `default:` branch below — safe because the
// FIRST signal is always already a valid answer to this wait (it either
// matched the waiter's predicate or was a terminal broadcast), so dropping
// later signals cannot produce a wrong answer.
type waiter struct {
	until EventType
	anyEv bool
	ch    chan waitSignal
}

type waitSignal struct {
	event Event
	state CallState
	gone  bool
}

// signalLocked wakes every waiter this event matches. MUST be called with
// c.mu held.
//
// RULE 2: a TERMINAL state broadcasts to ALL waiters regardless of their
// `until`. A waiter parked on "answered" for a call that goes straight to
// failed returns in milliseconds with the terminal outcome, which is what
// makes call_wait safe to use with a long timeout.
func (c *Call) signalLocked(e Event) {
	terminal := c.state.terminal()
	for w := range c.waiters {
		if !terminal && !w.anyEv && !eventMatchesUntil(e, w.until) {
			continue
		}
		select {
		case w.ch <- waitSignal{event: e, state: c.state}:
		default: // capacity-1 buffer already holds a signal; never block.
		}
	}
}

// MarkGoneAndWake is §6.3 RULE 3, and the order inside it is normative:
// the terminal `gone` flag is set UNDER THE CALL MUTEX, and THEN the remaining
// waiters are woken — in that order, under that ONE hold.
//
// The flag is what makes rule 1's check meaningful. Without it, a call_wait
// that had released the registry read-lock but not yet taken the call mutex
// would register on an already-evicted call AFTER the broadcast had passed and
// then park until its timeout — up to the five-minute max_wait_timeout_ms cap
// — against a handle the server no longer holds.
//
// The flag is NEVER CLEARED. Eviction is terminal.
//
// Waiters are not removed here: rule 5 makes each waiter remove itself on its
// own exit path, which is what keeps both accounts balanced.
func (c *Call) MarkGoneAndWake() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gone = true
	for w := range c.waiters {
		select {
		case w.ch <- waitSignal{gone: true, state: c.state}:
		default:
		}
	}
}

// register is §6.3 RULE 1: the predicate check, the terminal `gone` check and
// the registration itself all happen under ONE mutex hold. There is therefore
// no window in which an event is appended, or the call evicted, between a
// waiter's predicate check and its registration. Missing a wakeup is not a
// race to be made unlikely; it is unrepresentable.
//
// Returns (result, nil, nil) when the waiter returned immediately and was
// never registered; (zero, w, nil) when it was registered; (zero, nil, err) on
// gone or the per-call cap.
func (c *Call) register(until EventType, anyEv bool, maxPerCall int, since int64) (WaitResult, *waiter, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.gone {
		return WaitResult{}, nil, apierr.Gone(
			fmt.Sprintf("call handle %s has been reclaimed", c.handle))
	}
	evs := c.log.since(since)
	for _, e := range evs {
		if anyEv || eventMatchesUntil(e, until) {
			return eventResult(e, c.state, 0), nil, nil
		}
	}
	if c.state.terminal() {
		// Rule 2 applied to the EXISTING log: a call already terminated must
		// not park a waiter whose `until` the terminal event did not match.
		if len(evs) > 0 {
			return eventResult(evs[len(evs)-1], c.state, 0), nil, nil
		}
		// No event since `since` to hand back here: either the log is
		// genuinely empty, or `since` is at or past the last logged event's
		// seq (Task 3's cursor) — either way there is nothing unmatched to
		// return, so `event` and `seq` are absent. NOT a timeout — TimedOut
		// stays false, because the wait resolved immediately on the call's
		// state.
		return WaitResult{CallState: c.state}, nil, nil
	}
	if len(c.waiters) >= maxPerCall {
		return WaitResult{}, nil, apierr.ResourceLimit(
			"max_waiters_per_call", maxPerCall, len(c.waiters),
			fmt.Sprintf("call already has %d parked call_wait callers "+
				"(policy max_waiters_per_call=%d)", len(c.waiters), maxPerCall))
	}
	w := &waiter{until: until, anyEv: anyEv, ch: make(chan waitSignal, 1)}
	c.waiters[w] = struct{}{}
	return WaitResult{}, w, nil
}

// remove is §6.3 RULE 5: removal is UNCONDITIONAL on EVERY exit path —
// predicate satisfied, terminal broadcast, eviction, timeout, or context
// cancellation — and it releases BOTH accounts: the call's waiter set and the
// owning session's waiter count.
//
// The session decrement ACQUIRES NOTHING. sess.waiters is an atomic.Int64 LEAF
// explicitly outside the registry -> UA -> call hierarchy. If it were guarded
// by a session or registry lock, this decrement would hold the CALL mutex and
// reach for the REGISTRY lock, while rule 3's janitor holds the REGISTRY lock
// and takes the CALL mutex — a textbook ABBA deadlock, with §12.7's admin
// DELETE walking the same path as a third participant.
func (c *Call) remove(w *waiter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.waiters[w]; !ok {
		return
	}
	delete(c.waiters, w)
	c.sess.waiters.Add(-1)
}

func (c *Call) waiterCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}

// eventResult builds the SUCCESS shape from a delivered event, in one place so
// the pointer discipline is not re-derived at each of the three sites that
// return it.
func eventResult(e Event, state CallState, elapsedMs int64) WaitResult {
	seq := e.Seq
	ev := e
	return WaitResult{
		Event:     &ev,
		Seq:       &seq,
		Detail:    e.Detail,
		ElapsedMs: elapsedMs,
		CallState: state,
	}
}

// eventMatchesUntil reports whether e satisfies an `until` predicate. A bare
// type match is enough for every `until` value except "transfer": §10.14's
// call_transfer emits a PROVISIONAL UAEventTransfer (detail final:false) for
// each intermediate NOTIFY before the outcome settles, so call_wait(until=
// "transfer") must keep waiting past a provisional and only return the
// event whose detail carries final:true — otherwise it hands back the
// transfer's in-progress status as if it were the outcome. No other `until`
// value needs to look inside detail today, so this stays a one-case special,
// not a general per-type predicate table (Rule 15).
func eventMatchesUntil(e Event, until EventType) bool {
	if e.Type != until {
		return false
	}
	if until == EventTransfer {
		final, _ := e.Detail["final"].(bool)
		return final
	}
	return true
}

func parseUntil(until string) (EventType, bool, error) {
	switch until {
	case "any":
		return "", true, nil
	case "ringing":
		return EventRinging, false, nil
	case "answered":
		return EventAnswered, false, nil
	case "media_start":
		return EventMediaStart, false, nil
	case "dtmf":
		return EventDTMF, false, nil
	case "completed", "terminated":
		return EventBye, false, nil
	case "transfer":
		return EventTransfer, false, nil
	default:
		return "", false, apierr.InvalidArgument("unknown until value " + until)
	}
}

// WaitRequest groups (*Manager).Wait's five domain inputs. It is the Go-level
// counterpart to CallWaitInput (toolservice.go), which names the same fields
// at the JSON seam; introduced by CF-020 once Wait's positional argument list
// grew to five and several test call sites were passing an opaque trailing
// `0` for a parameter they didn't care about.
type WaitRequest struct {
	SessionID string
	Handle    Handle
	Until     string
	TimeoutMs int
	Since     int64
}

// Wait implements call_wait (§10.5), the only blocking tool.
//
// ctx MUST be the HTTP REQUEST context (§6.3 rule 4, locked decision 17).
// Client disconnect, client-side cancellation and server shutdown cancel it,
// and the waiter is removed IMMEDIATELY — before this function returns — so a
// dropped connection cannot leave a registration behind. The call itself lives
// on the daemon context and is unaffected.
func (m *Manager) Wait(ctx context.Context, req WaitRequest) (WaitResult, error) {
	// Limits are read LIVE, once, at the top of the call (U9). A SIGHUP that
	// tightens a cap binds the next call_wait with nothing to refresh.
	lim := m.limits()

	// All three bounds are checked BEFORE registration, so a rejected wait
	// consumes nothing.
	untilType, anyEv, err := parseUntil(req.Until)
	if err != nil {
		return WaitResult{}, err
	}
	if req.TimeoutMs <= 0 {
		// NOT an infinite wait: there is no unbounded wait in this design.
		return WaitResult{}, apierr.InvalidArgument("timeout_ms must be positive")
	}
	if req.TimeoutMs > lim.MaxWaitTimeoutMS {
		// REJECTED, NEVER SILENTLY CLAMPED. N2 guarantees call_wait returns
		// within +/-100ms of timeout_ms; clamping would break that invisibly
		// and leave an agent believing it had waited five minutes when it had
		// waited one. A rejection is a fact the agent can act on.
		return WaitResult{}, apierr.ResourceLimit(
			"max_wait_timeout_ms", lim.MaxWaitTimeoutMS, req.TimeoutMs,
			fmt.Sprintf("timeout_ms %d exceeds policy max_wait_timeout_ms=%d",
				req.TimeoutMs, lim.MaxWaitTimeoutMS))
	}

	c, err := m.ResolveCall(ctx, req.SessionID, req.Handle)
	if err != nil {
		return WaitResult{}, err
	}
	sess := m.session(req.SessionID)
	if sess == nil {
		return WaitResult{}, apierr.NotFound(fmt.Sprintf("unknown call handle %s", req.Handle))
	}

	// Session cap on the LEAF ATOMIC — outside the lock hierarchy, so this
	// acquires nothing. Increment-then-check-then-back-off, which is the
	// check-then-increment §6.3 rule 5 specifies: concurrent registrations may
	// transiently overshoot by at most the number of racing callers, decaying
	// as losers unwind. The SETTLED excess is bounded by max_waiters_per_call
	// per call in flight, and that is the quantity acceptance asserts against.
	//
	// policy.Limits.MaxWaitersPerSession is an int; the counter is an
	// atomic.Int64, so the comparison converts explicitly rather than relying
	// on the deleted session.Limits' int64 field.
	if n := sess.waiters.Add(1); n > int64(lim.MaxWaitersPerSession) {
		sess.waiters.Add(-1)
		return WaitResult{}, apierr.ResourceLimit(
			"max_waiters_per_session", lim.MaxWaitersPerSession, int(n-1),
			fmt.Sprintf("session already has %d parked call_wait callers "+
				"(policy max_waiters_per_session=%d)", n-1, lim.MaxWaitersPerSession))
	}

	res, w, err := c.register(untilType, anyEv, lim.MaxWaitersPerCall, req.Since)
	if w == nil {
		// Returned immediately or rejected: never registered, so release the
		// session account here.
		sess.waiters.Add(-1)
		return res, err
	}
	// RULE 5: unconditional removal on EVERY exit path below.
	defer c.remove(w)

	start := m.clk.Now()
	timer := m.clk.NewTimer(time.Duration(req.TimeoutMs) * time.Millisecond)
	defer timer.Stop()

	select {
	case sig := <-w.ch:
		if sig.gone {
			return WaitResult{}, apierr.Gone(
				fmt.Sprintf("call handle %s has been reclaimed", req.Handle))
		}
		return eventResult(sig.event, sig.state, m.clk.Now().Sub(start).Milliseconds()), nil
	case <-ctx.Done():
		// THE ONE ERROR PATH IN THIS PACKAGE THAT IS NOT AN *apierr.Error, AND
		// DELIBERATELY SO. ctx here is the HTTP REQUEST context (§6.3 rule 4).
		// This does NOT mean the client is already gone: under an MCP
		// notifications/cancelled cancellation the connection stays open and
		// the envelope IS delivered on it — the go-sdk writes the response for
		// a cancelled call unconditionally (jsonrpc2/conn.go:664), which is
		// exactly what makes §11.2's `cancelled` code (D360/D361) observable.
		// Returning the plain context error here rather than an *apierr.Error
		// keeps that §11.2 mapping in the one place locked decision 10 assigns
		// it — internal/transport/mcp — instead of duplicating it here.
		// context.Canceled is also what callers test with errors.Is, which is
		// what the §6.3 rule 4 acceptance asserts.
		return WaitResult{}, ctx.Err()
	case <-timer.C():
		return WaitResult{
			TimedOut:  true,
			ElapsedMs: int64(req.TimeoutMs),
			CallState: c.State(),
		}, nil
	}
}

// WaiterCount is a DEBUG-ONLY accessor for tests (§10.5). It must read 0 after
// every waiter exit path.
//
// It takes a plain string, not a Handle: every caller — P1e's acceptance suites
// and the loopback harness's wrappers — sits at a boundary that has just
// decoded JSON (contract §2.5.5, §2.10).
func (m *Manager) WaiterCount(callHandle string) int {
	m.mu.RLock()
	c, ok := m.calls[Handle(callHandle)]
	m.mu.RUnlock()
	if !ok {
		return 0
	}
	return c.waiterCount()
}

// SessionWaiterCount is a DEBUG-ONLY accessor for tests (§10.5). It must read 0
// whenever no call_wait is in flight anywhere in that session.
func (m *Manager) SessionWaiterCount(sessionID string) int64 {
	s := m.session(sessionID)
	if s == nil {
		return 0
	}
	return s.waiters.Load()
}

// EvictCallForTest drives the janitor's registry -> call path (§6.3 rule 5),
// via evictCallLocked — the ONE eviction implementation (Rule 18). Task 9's
// tests exercise the registry -> call locking order through this seam; Task
// 10 is what gives it a real body to call.
//
// ctx and the error return are the CONTRACT's shape (contract:1470), not the
// brief's: contract:3895 states P1e Tasks 23/24's Interfaces blocks are
// correct against this shape, and returning apierr.NotFound rather than a
// silent no-op closes a gap where a lookup bug would otherwise go unnoticed.
// ctx stays unused, exactly like ResolveCall/ResolveUA above: evictCallLocked
// takes m.daemonCtx for its own Tap.Evict call, never the caller's ctx.
func (m *Manager) EvictCallForTest(_ context.Context, sid string, h Handle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sid]
	if !ok {
		return apierr.NotFound(fmt.Sprintf("unknown session %s", sid))
	}
	c, ok := s.liveCalls[h]
	if !ok {
		return apierr.NotFound(fmt.Sprintf("unknown call handle %s", h))
	}
	delete(s.liveCalls, h)
	m.liveTotal--
	// This seam decrements m.liveTotal itself, so it must claim the call's
	// accounting flag too — otherwise a later RecordTermination would see an
	// unaccounted call and decrement a second time. (Before the flag existed
	// the `s.liveCalls` membership test above did this implicitly.)
	c.accounted = true
	m.evictCallLocked(s, c) // ONE implementation (Rule 18)
	return nil
}
