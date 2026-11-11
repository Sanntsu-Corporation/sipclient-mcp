package fakes

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// ToolCall is one recorded invocation. In is the decoded input struct, kept
// as any so one recorder serves all thirteen tools without thirteen
// near-identical fields.
type ToolCall struct {
	Tool    string
	Session string
	In      any
}

// Tools is a hand-written fake of the Tools interface
// internal/transport/mcp declares. P1d Task 18's registration and envelope
// tests drive it: they assert that a tool NAME reaches the right method with
// the right session id and a correctly decoded input, and that the §11.2
// envelope is built once — none of which needs a real session.Manager.
//
// Payloads, errors and delays are keyed by tool name, so a test scripts only
// the tools it exercises. An unscripted tool returns (nil, nil), which the
// envelope renders as ok:true with a null payload.
type Tools struct {
	mu sync.Mutex

	payloads map[string]any
	errs     map[string]error
	delays   map[string]time.Duration
	lastErr  map[string]error

	// uaLimit, when bound, makes UACreate honour a server-wide cap. See
	// BindUALimit.
	uaLimit *Admin

	Calls []ToolCall
}

// NewTools returns an empty Tools fake with every tool unscripted.
func NewTools() *Tools {
	return &Tools{
		payloads: make(map[string]any),
		errs:     make(map[string]error),
		delays:   make(map[string]time.Duration),
		lastErr:  make(map[string]error),
	}
}

// SetPayload scripts the successful payload one tool returns.
func (t *Tools) SetPayload(tool string, payload any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.payloads[tool] = payload
}

// SetErr scripts the error one tool returns. An *apierr.Error is what the
// §11.2 envelope renders as ok:false with a code.
func (t *Tools) SetErr(tool string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.errs[tool] = err
}

// SetDelay makes one tool really block for d.
//
// THIS MUST ACTUALLY SLEEP, and outside the mutex. P1d's TestN2LatencyBudget
// delays call_wait and asserts that it — and ONLY it — exceeds N2's 50 ms
// budget, which is D2's async-returns-immediately invariant made testable. A
// no-op delay would make that test assert nothing, and a delay taken under
// the mutex would serialise the twelve non-blocking subtests against it and
// produce a false failure.
func (t *Tools) SetDelay(tool string, d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.delays[tool] = d
}

// BindUALimit makes ua_create honour the bound Admin's server-wide UA cap,
// returning resource_limit naming max_uas_total while it is full and
// succeeding once slots are freed. It is what lets P1d's §12.7
// exhaustion-recovery test observe the cap being RELEASED by the admin
// DELETE — the whole justification for the admin plane existing.
func (t *Tools) BindUALimit(a *Admin) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.uaLimit = a
}

// uaLimitErr returns the resource_limit error when the bound Admin is full.
// It reads the CAP AND THE CURRENT COUNT LIVE on every call, so freeing a
// slot changes the answer with nothing to refresh.
func (t *Tools) uaLimitErr() error {
	t.mu.Lock()
	a := t.uaLimit
	t.mu.Unlock()
	if a == nil {
		return nil
	}
	limit := a.MaxUAsTotal()
	if limit <= 0 {
		return nil
	}
	if cur := a.LiveCount(); cur >= limit {
		return apierr.ResourceLimit("max_uas_total", limit, cur,
			fmt.Sprintf("server-wide UA cap reached (%d/%d)", cur, limit))
	}
	return nil
}

// record is the single body every tool method delegates to. One recorder,
// one behaviour (Rule 18 applies inside the package too).
func (t *Tools) record(tool, sess string, in any) (any, error) {
	return t.recordResult(tool, sess, in, nil)
}

// recordResult is record with an override error, for the one tool that
// computes its own outcome (ua_create, via BindUALimit).
func (t *Tools) recordResult(tool, sess string, in any, override error) (any, error) {
	t.mu.Lock()
	t.Calls = append(t.Calls, ToolCall{Tool: tool, Session: sess, In: in})
	payload, err, delay := t.payloads[tool], t.errs[tool], t.delays[tool]
	t.mu.Unlock()

	if override != nil {
		payload, err = nil, override
	}

	// Outside the mutex — see SetDelay.
	if delay > 0 {
		time.Sleep(delay)
	}

	t.mu.Lock()
	t.lastErr[tool] = err
	t.mu.Unlock()
	return payload, err
}

// LastSession reports the logical session id the most recent call to one tool
// carried. §12.6 scopes every handle by it, so a transport that dropped or
// substituted it would be an R11 isolation bug.
func (t *Tools) LastSession(tool string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := len(t.Calls) - 1; i >= 0; i-- {
		if t.Calls[i].Tool == tool {
			return t.Calls[i].Session
		}
	}
	return ""
}

// LastEnvelopeCode reports the §11.2 code the most recent call to one tool
// would render — "" when it succeeded, so a test can assert BOTH that a
// denial happened and that it later stopped happening.
func (t *Tools) LastEnvelopeCode(tool string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var ae *apierr.Error
	if errors.As(t.lastErr[tool], &ae) {
		return string(ae.Code)
	}
	return ""
}

// LastEnvelopeRule reports the policy key the most recent denial named.
func (t *Tools) LastEnvelopeRule(tool string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var ae *apierr.Error
	if errors.As(t.lastErr[tool], &ae) {
		return ae.Rule
	}
	return ""
}

// CallsFor returns every recorded invocation of one tool, in order.
func (t *Tools) CallsFor(tool string) []ToolCall {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []ToolCall
	for _, c := range t.Calls {
		if c.Tool == tool {
			out = append(out, c)
		}
	}
	return out
}

// SessionKeepalive records the call and returns the scripted payload for
// session_keepalive.
func (t *Tools) SessionKeepalive(_ context.Context, sess string, in session.SessionKeepaliveInput) (any, error) {
	return t.record("session_keepalive", sess, in)
}

// UACreate records the call, honouring a bound Admin's server-wide UA cap
// (see BindUALimit), and returns the scripted payload for ua_create.
func (t *Tools) UACreate(_ context.Context, sess string, in session.UACreateInput) (any, error) {
	return t.recordResult("ua_create", sess, in, t.uaLimitErr())
}

// UAStatus records the call and returns the scripted payload for ua_status.
func (t *Tools) UAStatus(_ context.Context, sess string, in session.UAStatusInput) (any, error) {
	return t.record("ua_status", sess, in)
}

// UADestroy records the call and returns the scripted payload for ua_destroy.
func (t *Tools) UADestroy(_ context.Context, sess string, in session.UADestroyInput) (any, error) {
	return t.record("ua_destroy", sess, in)
}

// CallDial records the call and returns the scripted payload for call_dial.
func (t *Tools) CallDial(_ context.Context, sess string, in session.CallDialInput) (any, error) {
	return t.record("call_dial", sess, in)
}

// CallAnswer records the call and returns the scripted payload for
// call_answer.
func (t *Tools) CallAnswer(_ context.Context, sess string, in session.CallAnswerInput) (any, error) {
	return t.record("call_answer", sess, in)
}

// CallReject records the call and returns the scripted payload for
// call_reject.
func (t *Tools) CallReject(_ context.Context, sess string, in session.CallRejectInput) (any, error) {
	return t.record("call_reject", sess, in)
}

// CallHangup records the call and returns the scripted payload for
// call_hangup.
func (t *Tools) CallHangup(_ context.Context, sess string, in session.CallHangupInput) (any, error) {
	return t.record("call_hangup", sess, in)
}

// CallStatus records the call and returns the scripted payload for
// call_status.
func (t *Tools) CallStatus(_ context.Context, sess string, in session.CallStatusInput) (any, error) {
	return t.record("call_status", sess, in)
}

// CallList records the call and returns the scripted payload for call_list.
func (t *Tools) CallList(_ context.Context, sess string, in session.CallListInput) (any, error) {
	return t.record("call_list", sess, in)
}

// CallWait records the call and returns the scripted payload for call_wait.
func (t *Tools) CallWait(_ context.Context, sess string, in session.CallWaitInput) (any, error) {
	return t.record("call_wait", sess, in)
}

// CallEvents records the call and returns the scripted payload for
// call_events.
func (t *Tools) CallEvents(_ context.Context, sess string, in session.CallEventsInput) (any, error) {
	return t.record("call_events", sess, in)
}

// CallLadder records the call and returns the scripted payload for
// call_ladder.
func (t *Tools) CallLadder(_ context.Context, sess string, in session.CallLadderInput) (any, error) {
	return t.record("call_ladder", sess, in)
}

// CaptureStart records the call and returns the scripted payload for
// capture_start.
func (t *Tools) CaptureStart(_ context.Context, sess string, in session.CaptureStartInput) (any, error) {
	return t.record("capture_start", sess, in)
}

// CaptureStop records the call and returns the scripted payload for
// capture_stop.
func (t *Tools) CaptureStop(_ context.Context, sess string, in session.CaptureStopInput) (any, error) {
	return t.record("capture_stop", sess, in)
}

// QualityGet records the call and returns the scripted payload for
// quality_get.
func (t *Tools) QualityGet(_ context.Context, sess string, in session.QualityGetInput) (any, error) {
	return t.record("quality_get", sess, in)
}

// MediaPlay records the call and returns the scripted payload for
// media_play.
func (t *Tools) MediaPlay(_ context.Context, sess string, in session.MediaPlayInput) (any, error) {
	return t.record("media_play", sess, in)
}

// MediaRecordStart records the call and returns the scripted payload for
// media_record_start.
func (t *Tools) MediaRecordStart(_ context.Context, sess string, in session.MediaRecordStartInput) (any, error) {
	return t.record("media_record_start", sess, in)
}

// MediaRecordStop records the call and returns the scripted payload for
// media_record_stop.
func (t *Tools) MediaRecordStop(_ context.Context, sess string, in session.MediaRecordStopInput) (any, error) {
	return t.record("media_record_stop", sess, in)
}

// DTMFSend records the call and returns the scripted payload for dtmf_send.
func (t *Tools) DTMFSend(_ context.Context, sess string, in session.DTMFSendInput) (any, error) {
	return t.record("dtmf_send", sess, in)
}

// ConfigGet records the call and returns the scripted payload for
// config_get.
func (t *Tools) ConfigGet(_ context.Context, sess string, in session.ConfigGetInput) (any, error) {
	return t.record("config_get", sess, in)
}

// ConfigSet records the call and returns the scripted payload for
// config_set.
func (t *Tools) ConfigSet(_ context.Context, sess string, in session.ConfigSetInput) (any, error) {
	return t.record("config_set", sess, in)
}

// AdminTokenRotate records the call and returns the scripted payload for
// admin_token_rotate.
func (t *Tools) AdminTokenRotate(_ context.Context, sess string, in session.AdminTokenRotateInput) (any, error) {
	return t.record("admin_token_rotate", sess, in)
}

// DTMFReceived records the call and returns the scripted payload for
// dtmf_received.
func (t *Tools) DTMFReceived(_ context.Context, sess string, in session.DTMFReceivedInput) (any, error) {
	return t.record("dtmf_received", sess, in)
}

// CallTransfer records the call and returns the scripted payload for
// call_transfer.
func (t *Tools) CallTransfer(_ context.Context, sess string, in session.CallTransferInput) (any, error) {
	return t.record("call_transfer", sess, in)
}
