package loopback

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// ---- UA / call control ------------------------------------------------------

// MustCreateUA creates a "direct" mode UA on the harness's own session and
// returns its handle, failing the test on any error.
func (h *Harness) MustCreateUA(t *testing.T, mode string) string {
	t.Helper()
	env := h.MustCallTool(t, "ua_create", map[string]any{"mode": mode, "transport": h.opts.transport})
	handle, _ := env["ua_handle"].(string)
	if handle == "" {
		t.Fatalf("loopback: ua_create returned no ua_handle: %+v", env)
	}
	h.rememberHandle(handle, h.sessionID)
	return handle
}

// MustCreateUAWithArgs creates a UA on the harness's own session from the
// given ua_create arguments (transport defaults to the harness's), for a test
// that needs inline settings such as srtp.
func (h *Harness) MustCreateUAWithArgs(t *testing.T, args map[string]any) string {
	t.Helper()
	a := map[string]any{"transport": h.opts.transport}
	for k, v := range args {
		a[k] = v
	}
	env := h.MustCallTool(t, "ua_create", a)
	handle, _ := env["ua_handle"].(string)
	if handle == "" {
		t.Fatalf("loopback: ua_create returned no ua_handle: %+v", env)
	}
	h.rememberHandle(handle, h.sessionID)
	return handle
}

// MustCreateUAWithAccount creates a "register" mode UA against the named
// Account fixture (see WithAccounts/TestAccount) and returns its handle,
// failing the test if registration did not succeed.
//
// PHASE 1 REPLACEMENT for MustCreateUAWithProfile: the account's fields go
// straight onto ua_create's own inline arguments (D6) instead of naming a
// policy.yaml profile. The registrar address is resolved HERE, at call time
// — the harness's own in-process registrar, or the peer's TLS listener for a
// "tls"-transport account (Phase 4 W1 M7c §6) — because the fixture itself
// (TestAccount) runs before New() starts either and cannot know their
// ephemeral ports.
func (h *Harness) MustCreateUAWithAccount(t *testing.T, name string) string {
	t.Helper()
	env := h.MustCallTool(t, "ua_create", h.UACreateArgsForAccount(t, name))
	handle, _ := env["ua_handle"].(string)
	if handle == "" {
		t.Fatalf("loopback: ua_create returned no ua_handle: %+v", env)
	}
	h.rememberHandle(handle, h.sessionID)
	return handle
}

// UACreateArgsForAccount builds ua_create's inline register-mode argument map
// for the named Account fixture, resolving the registrar address (the
// harness's own, or the peer's TLS listener for a "tls"-transport account —
// see MustCreateUAWithAccount's doc comment) at CALL time. Exported so a test
// that needs the raw ua_create response (e.g. to assert `registered`) can
// call h.MustCallTool(t, "ua_create", h.UACreateArgsForAccount(t, name))
// directly instead of duplicating this lookup.
func (h *Harness) UACreateArgsForAccount(t *testing.T, name string) map[string]any {
	t.Helper()
	var acct Account
	found := false
	for _, a := range h.opts.accounts {
		if a.Name == name {
			acct, found = a, true
			break
		}
	}
	if !found {
		t.Fatalf("loopback: UACreateArgsForAccount: no account named %q (pass it via WithAccounts)", name)
	}
	registrar := "sip:" + h.registrar.Addr()
	if acct.Transport == "tls" {
		registrar = "sip:" + h.peer.TLSAddr()
	}
	args := map[string]any{
		"mode":      "register",
		"aor":       acct.AOR,
		"auth_user": acct.AuthUser,
		"auth_pass": acct.AuthPass,
		"registrar": registrar,
		"transport": defaultStr2(acct.Transport, h.opts.transport),
	}
	if acct.ExpiresS != 0 {
		args["expires_s"] = acct.ExpiresS
	}
	return args
}

// defaultStr2 returns d when v is empty, v otherwise.
func defaultStr2(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// MustDial dials toURI from ua and returns the call handle, failing the test
// on any error. It does NOT wait for any state past `dialing` — see
// MustDialAnswered/MustDialRinging for that.
func (h *Harness) MustDial(t *testing.T, ua, toURI string) string {
	t.Helper()
	env := h.MustCallTool(t, "call_dial", map[string]any{"ua": ua, "to_uri": toURI})
	handle, _ := env["call_handle"].(string)
	if handle == "" {
		t.Fatalf("loopback: call_dial returned no call_handle: %+v", env)
	}
	h.rememberHandle(handle, h.sessionID)
	return handle
}

// MustDialAnswered dials a fresh "direct" UA at the harness's own peer and
// waits for `answered`, returning the call handle.
func (h *Harness) MustDialAnswered(t *testing.T) string {
	t.Helper()
	ua := h.MustCreateUA(t, "direct")
	return h.MustDialAnsweredOn(t, ua)
}

// MustDialAnsweredOn dials on a CALLER-SUPPLIED ua (Task 24's admin-DELETE
// collision needs the ua handle to DELETE, so it cannot let the harness mint
// one privately) and waits for `answered`.
func (h *Harness) MustDialAnsweredOn(t *testing.T, ua string) string {
	t.Helper()
	c := h.MustDial(t, ua, h.PeerURI())
	h.MustWait(t, c, "answered", 5000)
	return c
}

// MustDialRinging dials a fresh UA at the harness's own peer and waits for
// `ringing`, returning the call handle. The far end must be configured with
// a non-zero PeerBehaviour.AnswerAfter or this races the peer's own answer.
func (h *Harness) MustDialRinging(t *testing.T) string {
	t.Helper()
	ua := h.MustCreateUA(t, "direct")
	c := h.MustDial(t, ua, h.PeerURI())
	h.MustWait(t, c, "ringing", 5000)
	return c
}

// MustHangup hangs c up and fails the test on any error.
func (h *Harness) MustHangup(t *testing.T, c string) {
	t.Helper()
	h.MustCallTool(t, "call_hangup", map[string]any{"call": c})
}

// Hangup hangs c up, returning the error rather than failing the test.
func (h *Harness) Hangup(c string) error {
	_, err := h.CallTool("call_hangup", map[string]any{"call": c})
	return err
}

// Answer answers c, returning the error rather than failing the test.
func (h *Harness) Answer(c string) error {
	_, err := h.CallTool("call_answer", map[string]any{"call": c})
	return err
}

// Reject rejects c with status, returning the error rather than failing the
// test.
func (h *Harness) Reject(c string, status int) error {
	_, err := h.CallTool("call_reject", map[string]any{"call": c, "status": status})
	return err
}

// TripDurationCap forces the policy duration cap to fire for callHandle, so
// §6.3's "call_hangup racing the policy duration cap" pair has a
// deterministic second racer. It advances the fake clock past the call's
// deadline and runs one janitor pass; on a harness built without
// WithFakeClock it fails the test rather than sleeping — a sleep-based
// version would make the 1000-iteration concurrency loops unbounded in
// wall-clock time.
func (h *Harness) TripDurationCap(callHandle string) error {
	if !h.HasFakeClock() {
		h.t.Fatal("loopback: TripDurationCap requires a harness built WithFakeClock()")
	}
	lim := h.PolicyLimits(h.t)
	h.fake.Advance(time.Duration(lim.MaxCallDurationS+1) * time.Second)
	h.mgr.JanitorSweep(h.clk.Now())
	if s := h.MustCallStatusRaw(callHandle); s.State != "terminated" {
		return fmt.Errorf("loopback: TripDurationCap: call %s state = %q after sweep, want terminated",
			callHandle, s.State)
	}
	return nil
}

// ---- waiting on tool_wait ---------------------------------------------------

// WaitResult is the harness-local wrapper carrying BOTH channels honestly:
// the session.WaitResult payload (zero when Err != nil) and Err, the
// *apierr.Error or context error a §10.5 cap or cancellation returns.
type WaitResult struct {
	session.WaitResult
	Err error
}

// ErrorCodeOf reads r.Err's apierr code, "" if Err is nil.
func ErrorCodeOf(r WaitResult) string { return ErrorCode(r.Err) }

// ErrorRuleOf reads r.Err's apierr rule, "" if Err is nil.
func ErrorRuleOf(r WaitResult) string { return ErrorRule(r.Err) }

// Cancelled reports whether the wait ended because its REQUEST context was
// cancelled (§6.3 rule 4) rather than by a payload or a cap.
func (r WaitResult) Cancelled() bool { return errorsIsContextCanceled(r.Err) }

func errorsIsContextCanceled(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "context canceled") ||
		strings.Contains(err.Error(), "context.Canceled"))
}

// CallWait calls call_wait and decodes it into a WaitResult, under
// context.Background() and no extra timeout beyond timeoutMs itself.
func (h *Harness) CallWait(callHandle, until string, timeoutMs int) WaitResult {
	return h.CallWaitCtx(context.Background(), callHandle, until, timeoutMs)
}

// CallWaitCtx calls call_wait under ctx, decoding its two normative shapes
// (§10.5) into one WaitResult.
func (h *Harness) CallWaitCtx(ctx context.Context, callHandle, until string, timeoutMs int) WaitResult {
	// call_wait can legitimately block up to timeoutMs; give the HTTP round
	// trip headroom beyond that rather than racing it.
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond+5*time.Second)
	defer cancel()
	env, err := h.CallToolCtx(callCtx, "call_wait",
		map[string]any{"call": callHandle, "until": until, "timeout_ms": timeoutMs})
	return decodeWaitResult(env, err)
}

// callWaitWire is call_wait's ACTUAL wire shape (toolservice.go's CallWait
// builds this map by hand; it does NOT marshal session.WaitResult directly).
// "event" on the wire is the bare EVENT TYPE STRING (res.Event.Type), not a
// nested {seq, at_ms, type, detail} object — session.WaitResult.Event is a
// *session.Event, a DIFFERENT shape. decodeWaitResult bridges the two so the
// documented loopback.WaitResult (which embeds session.WaitResult per
// contract §2.10) is honestly populated rather than silently zero from a
// failed direct unmarshal.
type callWaitWire struct {
	TimedOut  bool           `json:"timed_out"`
	ElapsedMs int64          `json:"elapsed_ms"`
	CallState string         `json:"call_state"`
	Event     string         `json:"event"`
	Seq       *int64         `json:"seq"`
	Detail    map[string]any `json:"detail"`
}

func decodeWaitResult(env map[string]any, err error) WaitResult {
	if err != nil {
		return WaitResult{Err: err}
	}
	b, _ := json.Marshal(env)
	var w callWaitWire
	if uerr := json.Unmarshal(b, &w); uerr != nil {
		return WaitResult{Err: fmt.Errorf("loopback: decode call_wait result: %w (%s)", uerr, b)}
	}
	wr := session.WaitResult{
		ElapsedMs: w.ElapsedMs,
		TimedOut:  w.TimedOut,
		CallState: session.CallState(w.CallState),
		Detail:    w.Detail,
	}
	if w.Event != "" {
		wr.Event = &session.Event{Type: session.EventType(w.Event)}
		wr.Seq = w.Seq
	}
	return WaitResult{WaitResult: wr}
}

// MustWait calls call_wait(until) repeatedly is NOT what this does: it calls
// call_wait ONCE with timeoutMs and fails the test unless the matching event
// arrived (not a timeout, not an error).
func (h *Harness) MustWait(t *testing.T, callHandle, until string, timeoutMs int) WaitResult {
	t.Helper()
	res := h.CallWait(callHandle, until, timeoutMs)
	if res.Err != nil {
		t.Fatalf("loopback: call_wait(%s, %s): %v", callHandle, until, res.Err)
	}
	if res.TimedOut {
		t.Fatalf("loopback: call_wait(%s, %s) timed out after %dms, call_state=%s",
			callHandle, until, timeoutMs, res.CallState)
	}
	return res
}

// ---- decoded status/list/events --------------------------------------------

// CallStatus is the decoded call_status/ua_status payload, restricted to the
// fields Tasks 23/24 read.
type CallStatus struct {
	State             string
	Direction         string
	TerminationReason string
	SIPCode           int
	DurationMS        int64
	LocalAddr         string // ua_status only; "" on a call
	Registered        bool   // ua_status only
}

type callStatusWire struct {
	State             string `json:"state"`
	Direction         string `json:"direction"`
	TerminationReason string `json:"termination_reason"`
	DurationMS        int64  `json:"duration_ms"`
	LastResponse      struct {
		Code int `json:"code"`
	} `json:"last_response"`
}

// MustCallStatus fails the test on any tool error.
func (h *Harness) MustCallStatus(t *testing.T, callHandle string) CallStatus {
	t.Helper()
	env := h.MustCallTool(t, "call_status", map[string]any{"call": callHandle})
	return decodeCallStatus(t, env)
}

// MustCallStatusRaw is MustCallStatus's UNASSERTED twin — it does not fail
// the test on a tool error, it returns the zero CallStatus. "Raw" here means
// "unasserted", not "undecoded": st.State == "" must never be read by a
// caller as success.
func (h *Harness) MustCallStatusRaw(callHandle string) CallStatus {
	env, err := h.CallTool("call_status", map[string]any{"call": callHandle})
	if err != nil {
		return CallStatus{}
	}
	return decodeCallStatusEnv(env)
}

func decodeCallStatus(t *testing.T, env map[string]any) CallStatus {
	t.Helper()
	return decodeCallStatusEnv(env)
}

func decodeCallStatusEnv(env map[string]any) CallStatus {
	b, _ := json.Marshal(env)
	var w callStatusWire
	_ = json.Unmarshal(b, &w)
	cs := CallStatus{
		State: w.State, Direction: w.Direction, TerminationReason: w.TerminationReason,
		DurationMS: w.DurationMS, SIPCode: w.LastResponse.Code,
	}
	return cs
}

// MustUAStatus fails the test on any tool error. LocalAddr is resolved
// SEPARATELY from the ua_status tool response — §10.2's canonical ua_status
// payload carries no local_addr key — by reaching into the harness's own
// session.Manager for the UA's real bound address (UserAgent.LocalAddr()),
// the same value session's own AdminUAView/Config machinery is built on.
func (h *Harness) MustUAStatus(t *testing.T, uaHandle string) CallStatus {
	t.Helper()
	env := h.MustCallTool(t, "ua_status", map[string]any{"ua": uaHandle})
	uas, _ := env["uas"].([]any)
	if len(uas) == 0 {
		t.Fatalf("loopback: ua_status(%s) returned no UAs: %+v", uaHandle, env)
	}
	u, _ := uas[0].(map[string]any)
	registered, _ := u["registered"].(bool)

	cs := CallStatus{Registered: registered}
	sid := h.ownerOf(t, uaHandle)
	ua, err := h.mgr.ResolveUA(context.Background(), sid, session.Handle(uaHandle))
	if err != nil {
		t.Fatalf("loopback: MustUAStatus: resolve %s: %v", uaHandle, err)
	}
	cs.LocalAddr = ua.Agent().LocalAddr().String()
	return cs
}

// MustCallEvents fails the test on any tool error and returns the decoded
// event log.
func (h *Harness) MustCallEvents(t *testing.T, callHandle string, since int64) []session.Event {
	t.Helper()
	env := h.MustCallTool(t, "call_events", map[string]any{"call": callHandle, "since": since})
	b, _ := json.Marshal(env["events"])
	var out []session.Event
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("loopback: decode call_events: %v", err)
	}
	return out
}

// CallListEntry is call_list's per-call shape (§10.3).
type CallListEntry struct {
	CallHandle string `json:"call_handle"`
	UAHandle   string `json:"ua_handle"`
	State      string `json:"state"`
	ToURI      string `json:"to_uri"`
	DurationMS int64  `json:"duration_ms"`
}

// MustCallList fails the test on any tool error.
func (h *Harness) MustCallList(t *testing.T) []CallListEntry {
	t.Helper()
	env := h.MustCallTool(t, "call_list", nil)
	return decodeCallList(t, env)
}

// CallListFor calls call_list AS sessionID/token rather than the harness's
// own session — for asserting another session's (or a session presenting a
// different token's) view of call_list, e.g. that a fresh session's list is
// empty. It fails the test on any tool error.
func (h *Harness) CallListFor(t *testing.T, sessionID, token string) []CallListEntry {
	t.Helper()
	env, _, err := h.rpc.callTool(context.Background(), token, sessionID, "call_list", nil)
	if err != nil {
		t.Fatalf("loopback: call_list for session %s: %v", sessionID, err)
	}
	return decodeCallList(t, env)
}

func decodeCallList(t *testing.T, env map[string]any) []CallListEntry {
	t.Helper()
	b, _ := json.Marshal(env["calls"])
	var out []CallListEntry
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("loopback: decode call_list: %v", err)
	}
	return out
}

// MustWaitForInboundCall polls call_list, bounded by d, for a call handle not
// already known to this harness — the agent has no push notification for an
// inbound INVITE and must discover its handle this way — and returns it,
// registering its owning session (this harness's own).
func (h *Harness) MustWaitForInboundCall(t *testing.T, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		for _, c := range h.MustCallList(t) {
			h.handleMu.Lock()
			_, known := h.handleOwner[c.CallHandle]
			h.handleMu.Unlock()
			if !known {
				h.rememberHandle(c.CallHandle, h.sessionID)
				return c.CallHandle
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("loopback: MustWaitForInboundCall: no new inbound call within %s", d)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// UAContactURI is the SIP URI at which ua is reachable — its own bound
// signalling address — for driving an inbound INVITE at it via
// h.Peer().Dial(t, h.UAContactURI(t, ua)).
func (h *Harness) UAContactURI(t *testing.T, uaHandle string) string {
	t.Helper()
	sid := h.ownerOf(t, uaHandle)
	ua, err := h.mgr.ResolveUA(context.Background(), sid, session.Handle(uaHandle))
	if err != nil {
		t.Fatalf("loopback: UAContactURI: resolve %s: %v", uaHandle, err)
	}
	return "sip:" + uaHandle + "@" + ua.Agent().LocalAddr().String()
}

// AORFor returns the configured AOR for the named Account fixture (Phase 1
// replacement: accounts are no longer resolved through the harness's loaded
// policy — see WithAccounts/TestAccount).
func (h *Harness) AORFor(name string) string {
	for _, a := range h.opts.accounts {
		if a.Name == name {
			return a.AOR
		}
	}
	h.t.Fatalf("loopback: AORFor(%s): no account named %q (pass it via WithAccounts)", name, name)
	return ""
}

// Ladder calls call_ladder(call, format) and returns the rendered ladder
// string, failing the test on any tool error.
func (h *Harness) Ladder(t *testing.T, call, format string) string {
	t.Helper()
	env := h.MustCallTool(t, "call_ladder", map[string]any{"call": call, "format": format})
	rendered, _ := env["ladder"].(string)
	return rendered
}

// MustMetrics scrapes /metrics and returns COUNTER NAME -> VALUE as int64,
// keyed byte-for-byte as emitted (metric name including its label set). A key
// absent from the scrape reads 0, NOT a failure — every metrics assertion
// built on this must be a DELTA across an operation, never a bare == 0.
func (h *Harness) MustMetrics(t *testing.T) map[string]int64 {
	t.Helper()
	status, body := h.GetAuthed(t, "/metrics", testBearer)
	if status != 200 {
		t.Fatalf("loopback: GET /metrics: HTTP %d: %s", status, body)
	}
	return parsePrometheusText(body)
}

// parsePrometheusText parses the Prometheus exposition format's counter
// lines into name(incl. label set)->value, skipping HELP/TYPE comments.
func parsePrometheusText(body string) map[string]int64 {
	out := map[string]int64{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			continue
		}
		key := line[:i]
		var v float64
		if _, err := fmt.Sscanf(strings.TrimSpace(line[i+1:]), "%g", &v); err != nil {
			continue
		}
		out[key] = int64(v)
	}
	return out
}

// ---- logs -------------------------------------------------------------------

// isCallLogLine reports whether a decoded slog line is the §5 N5 per-call
// log record. D335: the emitter (session.Manager.emitCallLog) writes it as
// slog's MESSAGE — `m.log.Info("call terminated", ...)` — so slog's JSON
// handler renders it under "msg". There is no "event" key on that line at
// all. Matching only on `m["event"] == "call_log"` therefore NEVER matched,
// and CallLogLines/CallLogLineFor/CallLogLineCountFor returned empty
// unconditionally. LogHasEvent in this same file already got this right by
// checking both keys; these three did not.
func isCallLogLine(m map[string]any) bool {
	return m["event"] == "call_log" || m["msg"] == callLogMsg
}

// callLogMsg is the slog message session.Manager.emitCallLog uses. Pinned
// here so a future rename of that string fails this package's own test
// rather than silently emptying every call-log assertion built on it.
const callLogMsg = "call terminated"

// RawLog returns the harness's own captured slog JSON lines, verbatim.
func (h *Harness) RawLog() string { return h.logBuf.String() }

// CallLogLines returns every §5 N5 per-call log line, as decoded JSON
// objects, filtered to the "call_log" event.
func (h *Harness) CallLogLines(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(h.RawLog(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if isCallLogLine(m) {
			out = append(out, m)
		}
	}
	return out
}

// CallLogLineFor returns the FIRST §5 N5 per-call log line naming
// callHandle, and whether one was found.
func (h *Harness) CallLogLineFor(t *testing.T, callHandle string) (map[string]any, bool) {
	t.Helper()
	for _, m := range h.CallLogLines(t) {
		if m["call_handle"] == callHandle {
			return m, true
		}
	}
	return nil, false
}

// CallLogLineCountFor returns how many §5 N5 per-call log lines name this
// call handle. Exactly 1 is the invariant: a call terminates once, with one
// termination_reason. Distinguishes 0 from "call unknown" — both return 0,
// by design: a count is the honest answer to "how many", not a presence
// check.
func (h *Harness) CallLogLineCountFor(callHandle string) int {
	n := 0
	for _, line := range strings.Split(h.RawLog(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if isCallLogLine(m) && m["call_handle"] == callHandle {
			n++
		}
	}
	return n
}

// LogHasEvent reports whether any captured log line's "event" field equals
// event (msg, in slog's own field, if event is unset).
func (h *Harness) LogHasEvent(event string) bool {
	for _, line := range strings.Split(h.RawLog(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if m["event"] == event || m["msg"] == event {
			return true
		}
	}
	return false
}

// WaitForLog polls, bounded by d, until LogHasEvent(event) is true, or fails
// the test naming what it observed instead.
func (h *Harness) WaitForLog(t *testing.T, event string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if h.LogHasEvent(event) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("loopback: WaitForLog(%q): not observed within %s", event, d)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ---- waiter counts, eviction, janitor ---------------------------------------

// WaiterCount wraps (*session.Manager).WaiterCount(callHandle).
func (h *Harness) WaiterCount(callHandle string) int { return h.mgr.WaiterCount(callHandle) }

// SessionWaiterCount wraps (*session.Manager).SessionWaiterCount(h.sessionID).
func (h *Harness) SessionWaiterCount() int64 { return h.mgr.SessionWaiterCount(h.sessionID) }

// TotalWaiterCount sums WaiterCount over each of callHandles.
func (h *Harness) TotalWaiterCount(callHandles ...string) int {
	n := 0
	for _, c := range callHandles {
		n += h.WaiterCount(c)
	}
	return n
}

// WaitForWaiterCount polls, bounded by d, until WaiterCount(callHandle)==n,
// or fails the test naming observed-vs-wanted.
func (h *Harness) WaitForWaiterCount(t *testing.T, callHandle string, n int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if got := h.WaiterCount(callHandle); got == n {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("loopback: WaitForWaiterCount(%s): observed %d, want %d after %s", callHandle, got, n, d)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// EvictNow drives the janitor's registry -> call eviction path for ONE call.
// It takes ONLY the call handle; the owning session is resolved internally
// from bookkeeping every Must*Dial/MustCreateUA/MustWaitForInboundCall
// registers. It t.Fatals on a non-nil error AND if the handle is unknown to
// this harness — a silent no-op here would make the eviction race in Task
// 24 pass by never racing anything (D307/D311).
func (h *Harness) EvictNow(callHandle string) {
	h.t.Helper()
	sid := h.ownerOf(h.t, callHandle)
	if err := h.mgr.EvictCallForTest(context.Background(), sid, session.Handle(callHandle)); err != nil {
		h.t.Fatalf("loopback: EvictNow(%s): %v", callHandle, err)
	}
}

// RunJanitor runs one janitor sweep against the harness's own clock.
func (h *Harness) RunJanitor(t *testing.T) {
	t.Helper()
	h.mgr.JanitorSweep(h.clk.Now())
}

// AdvanceClockAndSweep advances the harness's fake clock by d and runs one
// janitor sweep, failing the test if the harness was not built
// WithFakeClock().
func (h *Harness) AdvanceClockAndSweep(t *testing.T, d time.Duration) {
	t.Helper()
	h.Clock().Advance(d)
	h.mgr.JanitorSweep(h.clk.Now())
}

// ---- bridges onto the canonical peer, keyed by CALL HANDLE -----------------

// PeerSendBye maps callHandle onto the peer's most recently answered call
// (D305/D128: the peer cannot address by sipua's internal dialog handle, and
// SendBye's own no-dialog signature is the correction, not a defect — see
// peer.SendBye's doc). It returns an error, never t.Fatal-ing, so Task 23's
// conflicting-pair racers can share the func(*Harness, string) error shape.
//
// It fails loudly if callHandle is unknown to this harness, if callHandle's
// own call is not currently answered, or if MORE THAN ONE of this harness's
// tracked calls is currently answered — in that case "the most recent" is
// genuinely ambiguous, and silently hanging up the wrong one is worse than
// refusing (D305).
func (h *Harness) PeerSendBye(callHandle string) error {
	h.handleMu.Lock()
	_, ok := h.handleOwner[callHandle]
	handles := make([]string, 0, len(h.handleOwner))
	for k := range h.handleOwner {
		handles = append(handles, k)
	}
	h.handleMu.Unlock()
	if !ok {
		return fmt.Errorf("loopback: PeerSendBye: handle %q was never minted by this harness", callHandle)
	}

	answered := 0
	target := false
	for _, hd := range handles {
		if !strings.HasPrefix(hd, "call_") {
			continue
		}
		hSid := h.ownerOfUnchecked(hd)
		c, err := h.mgr.ResolveCall(context.Background(), hSid, session.Handle(hd))
		if err != nil {
			continue
		}
		if c.State() == session.StateAnswered {
			answered++
			if hd == callHandle {
				target = true
			}
		}
	}
	if !target {
		return fmt.Errorf("loopback: PeerSendBye: call %q is not currently answered", callHandle)
	}
	if answered > 1 {
		return fmt.Errorf(
			"loopback: PeerSendBye: %d calls are currently answered; the far end's "+
				"\"most recently answered call\" is ambiguous (D305) — narrow the harness state first",
			answered)
	}
	return h.peer.SendByeErr()
}

// ownerOfUnchecked is ownerOf without the t.Fatal — used by PeerSendBye,
// which must return an error rather than fail the test.
func (h *Harness) ownerOfUnchecked(handle string) string {
	h.handleMu.Lock()
	defer h.handleMu.Unlock()
	return h.handleOwner[handle]
}

// PeerSendFinal sends a final response with the given status for the inbound
// INVITE that established callHandle, addressed by the SIP Call-ID the peer
// genuinely observed off the wire (session.Call.CallID()) — not sipua's
// internal dialog handle, which the peer never sees.
func (h *Harness) PeerSendFinal(t *testing.T, callHandle string, status int) {
	t.Helper()
	sid := h.ownerOf(t, callHandle)
	c, err := h.mgr.ResolveCall(context.Background(), sid, session.Handle(callHandle))
	if err != nil {
		t.Fatalf("loopback: PeerSendFinal: resolve %s: %v", callHandle, err)
	}
	h.peer.SendFinal(t, c.CallID(), status)
}

// ---- shutdown hygiene --------------------------------------------------------

// WaitForGoroutineBaseline blocks until runtime.NumGoroutine() is back within
// a small slack of baseline, or fails after d. Slack, not equality: the
// httptest server and the sipgo transport pool keep their own goroutines
// alive. This is a shutdown-HYGIENE check, never a race detector.
func (h *Harness) WaitForGoroutineBaseline(t *testing.T, baseline int, d time.Duration) {
	t.Helper()
	const slack = 20
	deadline := time.Now().Add(d)
	for {
		n := runtime.NumGoroutine()
		if n <= baseline+slack {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("loopback: WaitForGoroutineBaseline: NumGoroutine()=%d, want <= baseline(%d)+%d after %s",
				n, baseline, slack, d)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
