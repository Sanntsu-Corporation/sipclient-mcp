package fakes

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

var _ session.UserAgent = (*UserAgent)(nil)

// UserAgent is a hand-written fake of session.UserAgent (§6.2.1: each
// interface is deliberately small enough to fake by hand — no mocking
// framework). It records every call and lets a test script each return
// value and fire arbitrary upward events.
//
// Every field is guarded by mu, because session drives a UA from several
// goroutines and the fakes must be usable under -race.
type UserAgent struct {
	mu sync.Mutex

	// Scripted returns.
	RegisterResult session.RegisterResult
	RegisterErr    error
	UnregisterErr  error
	DialResult     session.DialResult
	DialErr        error
	AnswerErr      error
	RejectErr      error
	HangupErr      error
	CloseErr       error

	// MediaViewResult/MediaViewOK script MediaView's return. Zero value
	// (MediaViewOK: false) is the correct default — most existing tests never
	// negotiate media and must keep seeing ok=false, exactly like every other
	// scripted-false field in this fake.
	MediaViewResult session.MediaView
	MediaViewOK     bool

	// QualityViewResult/QualityViewOK script QualityView's return, same
	// zero-value-is-false convention as MediaView above.
	QualityViewResult session.QualityView
	QualityViewOK     bool

	// TLSVerifiedResult/TLSVerifiedOK script TLSVerified's return (Phase 4
	// W1 M7c), same zero-value-is-false convention as MediaView above.
	TLSVerifiedResult bool
	TLSVerifiedOK     bool

	// PlayDurationMs/PlayErr script Play's return.
	PlayDurationMs int64
	PlayErr        error

	// RecordStartName/RecordStartErr script RecordStart's return.
	RecordStartName string
	RecordStartErr  error

	// RecordStopInfo/RecordStopDurationMs/RecordStopErr script RecordStop's return.
	RecordStopInfo       session.ArtifactInfo
	RecordStopDurationMs int64
	RecordStopErr        error

	// MediaPlanViewResult/MediaPlanViewOK script MediaPlanView's return, same
	// zero-value-is-false convention as MediaView above.
	MediaPlanViewResult session.MediaPlanView
	MediaPlanViewOK     bool

	// SendDTMFFn/DTMFModeFn/SessionTimerViewFn are FUNC-HOOK fields, unlike
	// every scripted-value field above: three of Task 16's required tests must
	// CAPTURE the arguments a call was made with (digits, mode, duration, gap),
	// which a plain value field cannot express. A nil hook is an UNSCRIPTED
	// call, and each method says so in the only way its own signature allows:
	// DTMFMode and SessionTimerView report ok=false, SendDTMF returns
	// ErrSendDTMFUnscripted.
	SendDTMFFn         func(ctx context.Context, dialogID, digits string, mode session.DTMFMode, durationMs, gapMs int) (int, int, error)
	DTMFModeFn         func(dialogID string) (string, bool)
	SessionTimerViewFn func(dialogID string) (session.SessionTimerView, bool)

	// TransferFn/ControlOpBlocksHangupFn are func hooks, same convention as
	// SendDTMFFn: a nil TransferFn returns ErrTransferUnscripted, and a nil
	// ControlOpBlocksHangupFn reports ("", false) (nothing blocks hangup).
	TransferFn              func(ctx context.Context, req session.TransferRequest) (session.TransferResult, error)
	ControlOpBlocksHangupFn func(dialogID string) (session.ControlOpKind, bool)

	// Bound is what LocalAddr reports: the CONCRETE post-bind signalling
	// address of §3d. It defaults to a concrete 127.0.0.1:PORT and is NEVER
	// a wildcard, because a wildcard is exactly the state §3d forbids and a
	// fake that returned one would let a caller's concrete-bind assertion
	// pass vacuously.
	Bound *net.UDPAddr

	// EmptyCallIDOK disables Emit's non-empty-CallID defaulting, for the one
	// kind of test that deliberately exercises a missing Call-ID.
	EmptyCallIDOK bool

	// Recorded calls.
	RegisterCalls   int
	UnregisterCalls int
	Dials           []session.DialRequest
	Answers         []session.AnswerRequest
	Rejects         []RejectCall
	Hangups         []HangupCall
	CloseCalls      int

	handler session.UAEventFunc
	hctx    context.Context

	// admitHandler is the SYNCHRONOUS inbound-admission callback (I2),
	// registered via OnAdmit and DISTINCT from the one-way handler above. actx
	// is the context it was registered with.
	admitHandler session.AdmitFunc
	actx         context.Context
}

// RejectCall is one recorded Reject call.
type RejectCall struct {
	DialogID string
	Status   int
	Reason   string
}

// HangupCall is one recorded Hangup call.
type HangupCall struct {
	DialogID string
	Reason   string
}

// NewUserAgent returns a UserAgent fake scripted with plausible defaults.
func NewUserAgent() *UserAgent {
	return &UserAgent{
		RegisterResult: session.RegisterResult{
			Registered: true, Code: 200, Reason: "OK", ExpiresS: 300,
		},
		// The scripted DialResult carries a plausible NON-EMPTY Call-ID.
		// This is not cosmetic: (*Call).CallID() is the Tap's ladder key and
		// U7 keys every per-call Tap method by it, so a fake that returned ""
		// would let a call_ladder or Tap.Evict test pass against a ladder
		// keyed on the empty string — a vacuous green, which is the failure
		// mode this wave has already hit twice.
		DialResult: session.DialResult{
			DialogID: "fake-dialog-1",
			CallID:   "fake-callid-1@lab.internal",
		},
		Bound: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060},
	}
}

// Register records the call and returns the scripted RegisterResult.
func (u *UserAgent) Register(_ context.Context) (session.RegisterResult, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.RegisterCalls++
	return u.RegisterResult, u.RegisterErr
}

// Unregister records the call.
func (u *UserAgent) Unregister(_ context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.UnregisterCalls++
	return u.UnregisterErr
}

// Dial records req and returns the scripted DialResult.
func (u *UserAgent) Dial(_ context.Context, req session.DialRequest) (session.DialResult, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.Dials = append(u.Dials, req)
	return u.DialResult, u.DialErr
}

// Answer records req.
func (u *UserAgent) Answer(_ context.Context, req session.AnswerRequest) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.Answers = append(u.Answers, req)
	return u.AnswerErr
}

// Reject records the rejection.
func (u *UserAgent) Reject(_ context.Context, dialogID string, status int, reason string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.Rejects = append(u.Rejects, RejectCall{DialogID: dialogID, Status: status, Reason: reason})
	return u.RejectErr
}

// Hangup records the hangup.
func (u *UserAgent) Hangup(_ context.Context, dialogID string, reason string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.Hangups = append(u.Hangups, HangupCall{DialogID: dialogID, Reason: reason})
	return u.HangupErr
}

// Close records the call.
func (u *UserAgent) Close(_ context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.CloseCalls++
	return u.CloseErr
}

// LocalAddr reports the concrete post-bind signalling address (§3d).
//
// The RETURN TYPE is net.Addr, matching the interface exactly (U17) — Go
// requires an exact signature match, so returning *net.UDPAddr here would
// fail this file's compile-time interface-satisfaction assertion above, even
// though *net.UDPAddr implements net.Addr. The VALUE handed back is still a
// concrete, non-wildcard *net.UDPAddr, so §3d's assertion is unweakened:
// U17 widens the declared type, it does not weaken the fake.
func (u *UserAgent) LocalAddr() net.Addr {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.Bound
}

// TLSVerified returns the scripted TLSVerifiedResult/TLSVerifiedOK pair, same
// zero-value-is-false convention as MediaView above: the zero value
// (TLSVerifiedOK: false) is the correct default, so every existing test
// keeps seeing tls_verified omitted/null with no script change required.
func (u *UserAgent) TLSVerified() (bool, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.TLSVerifiedResult, u.TLSVerifiedOK
}

// MediaView returns the scripted MediaView/ok pair.
func (u *UserAgent) MediaView(_ string) (session.MediaView, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.MediaViewResult, u.MediaViewOK
}

// QualityView returns the scripted QualityView/ok pair.
func (u *UserAgent) QualityView(_ string) (session.QualityView, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.QualityViewResult, u.QualityViewOK
}

// Play returns the scripted duration/err.
func (u *UserAgent) Play(context.Context, string, string, int, bool) (int64, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.PlayDurationMs, u.PlayErr
}

// RecordStart returns the scripted resolved name/err.
func (u *UserAgent) RecordStart(context.Context, string, string, string) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.RecordStartName, u.RecordStartErr
}

// RecordStop returns the scripted info/duration/err.
func (u *UserAgent) RecordStop(context.Context, string, string, string) (session.ArtifactInfo, int64, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.RecordStopInfo, u.RecordStopDurationMs, u.RecordStopErr
}

// MediaPlanView returns the scripted MediaPlanView/ok pair.
func (u *UserAgent) MediaPlanView(_ string) (session.MediaPlanView, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.MediaPlanViewResult, u.MediaPlanViewOK
}

// ErrSendDTMFUnscripted is what SendDTMF returns when no SendDTMFFn is
// scripted. Its two siblings, DTMFMode and SessionTimerView, both report
// ok=false in that case; SendDTMF's signature carries no ok, so the error is
// the only channel it has to say the same thing. It previously returned
// (0, 0, nil) — SILENT SUCCESS, indistinguishable from a UA that really did
// send zero digits without fault, which is the one answer a test double must
// never give for a call it was never told how to handle.
var ErrSendDTMFUnscripted = errors.New("fakes.UserAgent: SendDTMF called with no SendDTMFFn scripted")

// ErrTransferUnscripted is what Transfer returns when no TransferFn is scripted.
var ErrTransferUnscripted = errors.New("fakes.UserAgent: Transfer called with no TransferFn scripted")

// SendDTMF delegates to the scripted SendDTMFFn, under mu like every other
// field in this fake. A nil hook is a failure, not a benign zero — see
// ErrSendDTMFUnscripted.
func (u *UserAgent) SendDTMF(ctx context.Context, dialogID, digits string, mode session.DTMFMode, durationMs, gapMs int) (int, int, error) {
	u.mu.Lock()
	fn := u.SendDTMFFn
	u.mu.Unlock()
	if fn == nil {
		return 0, 0, ErrSendDTMFUnscripted
	}
	return fn(ctx, dialogID, digits, mode, durationMs, gapMs)
}

// DTMFMode delegates to the scripted DTMFModeFn. A nil hook returns ok=false.
func (u *UserAgent) DTMFMode(dialogID string) (string, bool) {
	u.mu.Lock()
	fn := u.DTMFModeFn
	u.mu.Unlock()
	if fn == nil {
		return "", false
	}
	return fn(dialogID)
}

// SessionTimerView delegates to the scripted SessionTimerViewFn. A nil hook
// returns ok=false.
func (u *UserAgent) SessionTimerView(dialogID string) (session.SessionTimerView, bool) {
	u.mu.Lock()
	fn := u.SessionTimerViewFn
	u.mu.Unlock()
	if fn == nil {
		return session.SessionTimerView{}, false
	}
	return fn(dialogID)
}

// Transfer delegates to the scripted TransferFn.
func (u *UserAgent) Transfer(ctx context.Context, req session.TransferRequest) (session.TransferResult, error) {
	u.mu.Lock()
	fn := u.TransferFn
	u.mu.Unlock()
	if fn == nil {
		return session.TransferResult{}, ErrTransferUnscripted
	}
	return fn(ctx, req)
}

// ControlOpBlocksHangup delegates to the scripted ControlOpBlocksHangupFn; nil
// reports ("", false).
func (u *UserAgent) ControlOpBlocksHangup(dialogID string) (session.ControlOpKind, bool) {
	u.mu.Lock()
	fn := u.ControlOpBlocksHangupFn
	u.mu.Unlock()
	if fn == nil {
		return "", false
	}
	return fn(dialogID)
}

// SetDialResult replaces the scripted DialResult under the fake's lock, so a
// test can give a SECOND dial a distinct dialog id without racing the first
// dial's goroutine.
func (u *UserAgent) SetDialResult(res session.DialResult) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.DialResult = res
}

// OnEvent registers the single upward event callback.
func (u *UserAgent) OnEvent(ctx context.Context, fn session.UAEventFunc) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.handler = fn
	u.hctx = ctx
}

// OnAdmit registers the SYNCHRONOUS inbound-admission callback (I2), DISTINCT
// from OnEvent's one-way delivery.
func (u *UserAgent) OnAdmit(ctx context.Context, fn session.AdmitFunc) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.admitHandler = fn
	u.actx = ctx
}

// Admit simulates the UA's inbound-INVITE admission (I2): it calls the stored
// AdmitFunc SYNCHRONOUSLY and returns its verdict, mirroring sipua's own admit.
// Like sipua it copies the callback out under mu and invokes it AFTER releasing
// the lock, and accepts when no admitter is registered. Emit routes an inbound
// event here; a test may also call it directly to inspect the verdict.
func (u *UserAgent) Admit(ev session.UAEvent) session.Admission {
	u.mu.Lock()
	fn, ctx := u.admitHandler, u.actx
	u.mu.Unlock()
	if fn == nil {
		return session.AdmitAccept()
	}
	return fn(ctx, ev)
}

// Emit delivers an event upward on the context registered with OnEvent,
// letting a test drive an inbound INVITE, a provisional or final response, a
// refresh or a transport fault. It is a no-op before OnEvent is called.
//
// An event emitted with an EMPTY CallID is given a plausible one. The
// INBOUND path is why UAEvent.CallID exists at all — an inbound call never
// returns a DialResult, so this callback is `session`'s ONLY channel for the
// Call-ID on R14's incoming_call path. A fake that let "" through would key a
// ladder on the empty string and any call_ladder or Tap.Evict assertion
// downstream would pass vacuously. A test that specifically wants the empty
// case sets EmptyCallIDOK.
func (u *UserAgent) Emit(ev session.UAEvent) {
	u.mu.Lock()
	fn, ctx := u.handler, u.hctx
	allowEmpty := u.EmptyCallIDOK
	u.mu.Unlock()
	if ev.CallID == "" && !allowEmpty {
		ev.CallID = "fake-callid-inbound-1@lab.internal"
	}
	// An inbound INVITE is admitted SYNCHRONOUSLY (I2): after the session drops
	// its one-way UAEventInbound case, Emit(UAEventInbound) must call the stored
	// AdmitFunc, not the OnEvent handler, or it reaches nothing.
	if ev.Kind == session.UAEventInbound {
		u.Admit(ev)
		return
	}
	if fn != nil {
		fn(ctx, ev)
	}
}

// EmitDialogEnded delivers U14's dialog_ended event with a protocol-level
// cause. It exists because `session`'s mapping from these causes onto
// §10.3's termination_reason enum (P1b) is a P1 behaviour that MUST be
// testable against fakes — a fake that could not emit one would leave the
// only path to termination_reason `remote_bye` and `inbound_ring_timeout`
// unreachable without a live UA, defeating §6.2.1's fakeability requirement.
//
// It sets Kind for the caller, so a test cannot accidentally attach a Cause
// to some other kind and thereby assert against a shape sipua never emits.
func (u *UserAgent) EmitDialogEnded(dialogID string, cause session.UADialogEndCause) {
	u.Emit(session.UAEvent{
		Kind:     session.UAEventDialogEnded,
		DialogID: dialogID,
		Cause:    cause,
	})
}
