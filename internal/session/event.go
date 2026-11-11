package session

// EventType is §10.5's canonical, exhaustive event-type list. The enum is
// declared WHOLE at P1 even though only a subset is reachable here:
// incoming_call, ringing, answered, bye, policy_timeout and error are appended
// by P1 code paths; media_start, media_stop, dtmf, record_start, record_stop,
// plan_step and session_refresh arrive with media (P2), the media plan (§10.7)
// and RFC 4028 (R9). Declaring the enum whole keeps §10.5's exhaustiveness a
// single reviewable list rather than one that grows by accretion.
type EventType string

// The fourteen EventType values, in §10.5 document order.
const (
	EventIncomingCall   EventType = "incoming_call"
	EventRinging        EventType = "ringing"
	EventAnswered       EventType = "answered"
	EventMediaStart     EventType = "media_start"
	EventMediaStop      EventType = "media_stop"
	EventDTMF           EventType = "dtmf"
	EventRecordStart    EventType = "record_start"
	EventRecordStop     EventType = "record_stop"
	EventPlanStep       EventType = "plan_step"
	EventSessionRefresh EventType = "session_refresh"
	EventBye            EventType = "bye"
	EventPolicyTimeout  EventType = "policy_timeout"
	EventError          EventType = "error"
	// EventTransfer is §10.14's call_transfer outcome (spec 2026-09-26 §4.4),
	// appended from UAEventTransfer with detail
	// {mode, status_code, reason, final, success}.
	EventTransfer EventType = "transfer"
)

// AllEventTypes returns §10.5's list in document order.
func AllEventTypes() []EventType {
	return []EventType{
		EventIncomingCall, EventRinging, EventAnswered, EventMediaStart, EventMediaStop,
		EventDTMF, EventRecordStart, EventRecordStop, EventPlanStep, EventSessionRefresh,
		EventBye, EventPolicyTimeout, EventError, EventTransfer,
	}
}

// Event is one entry in a call's ordered log (§10.5).
type Event struct {
	Seq    int64          `json:"seq"`
	AtMs   int64          `json:"at_ms"`
	Type   EventType      `json:"type"`
	Detail map[string]any `json:"detail,omitempty"`
}

// WaitResult is what (*Manager).Wait (Task 9) returns, marshalling to §10.5's
// two normative shapes and nothing else:
//
//	success: {ok, event, seq, elapsed_ms, timed_out:false, call_state, detail:{...}}
//	timeout: {ok:true, timed_out:true, elapsed_ms, call_state}
//
// POINTERS ARE MANDATORY on Event and Seq, with the convention pointer +
// omitempty used consistently (not omitzero): omitempty has no effect on a
// struct value, so a plain `Event` field would emit
// `"event":{"seq":0,"at_ms":0,"type":""}` on every timeout, and a plain
// `Seq int64` with omitempty would drop a genuine seq 0 (unreachable now that
// the first seq is 1, but the pointer makes "absent" and "zero" distinguishable
// by construction). Detail is the matched event's detail, hoisted to the top
// level; nil (and therefore absent) on a timeout. `ok` is not a field here:
// envelope construction belongs to transport/mcp, once (decision 11).
type WaitResult struct {
	Event     *Event         `json:"event,omitempty"`
	Seq       *int64         `json:"seq,omitempty"`
	Detail    map[string]any `json:"detail,omitempty"`
	ElapsedMs int64          `json:"elapsed_ms"`
	TimedOut  bool           `json:"timed_out"` // no omitempty: the success shape names timed_out:false explicitly
	CallState CallState      `json:"call_state"`
}

// eventLog is a bounded ordered log (N3: default 1024 events). Every method
// MUST be called with the owning call's mutex held — the log carries no lock
// of its own, because §6.3 requires the append, the seq assignment and the
// waiter signal to occur in ONE critical section.
type eventLog struct {
	capacity int
	evs      []Event
	nextSeq  int64
	dropped  int64
}

func newEventLog(capacity int) *eventLog {
	if capacity <= 0 {
		capacity = 1
	}
	return &eventLog{capacity: capacity, evs: make([]Event, 0, capacity)}
}

// append assigns the next seq and returns the stored event.
//
// THE FIRST SEQ IS 1, NOT 0 — the increment precedes the assignment for exactly
// that reason. §10.5's `since` parameter defaults to 0 and means "everything",
// which only holds if no real event ever carries seq 0. A zero-based log would
// make call_events(since=0) silently skip the first event of every call, and
// `incoming_call` — appended first on every inbound call (R14) — is the one it
// would drop.
func (l *eventLog) append(atMs int64, t EventType, detail map[string]any) Event {
	l.nextSeq++
	e := Event{Seq: l.nextSeq, AtMs: atMs, Type: t, Detail: detail}
	l.evs = append(l.evs, e)
	if over := len(l.evs) - l.capacity; over > 0 {
		l.evs = append(l.evs[:0], l.evs[over:]...)
		l.dropped += int64(over)
	}
	return e
}

func (l *eventLog) since(seq int64) []Event {
	out := make([]Event, 0, len(l.evs))
	for _, e := range l.evs {
		if e.Seq > seq {
			out = append(out, e)
		}
	}
	return out
}

// truncatedBefore reports the lowest surviving seq when events have been
// evicted, and 0 when none have (§10.5).
func (l *eventLog) truncatedBefore() int64 {
	if l.dropped == 0 || len(l.evs) == 0 {
		return 0
	}
	return l.evs[0].Seq
}

func (l *eventLog) lastSeq() int64 { return l.nextSeq }
