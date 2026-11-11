package sipua

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// MaxInboundTCPConnsForTest is the connection cap of every UA's inbound TCP
// listener.
const MaxInboundTCPConnsForTest = maxInboundTCPConns

// This file exposes package-internal seams to the EXTERNAL (sipua_test) suite.
// It compiles only under `go test`, so nothing here is production surface.

// AnswerEventually retries Answer until it succeeds or 2s elapses. It dates
// from P2 W3 Task 7 (M2), which keeps an inbound dialog unanswerable until its
// 180 Ringing is confirmed on the wire (phaseAdmitting -> phaseRinging): then
// Answer failed during that window. Since CF-052 Answer WAITS for the admission
// to finish, so the retry is no longer needed; the helper stays, harmless, for
// the tests that use it. Answer must not be called from the OnAdmit handler of
// the dialog being admitted (it would wait on its own onInvite); internal/session
// never does.
func (u *UA) AnswerEventually(ctx context.Context, req session.AnswerRequest) error {
	deadline := time.Now().Add(2 * time.Second)
	var err error
	for {
		if err = u.Answer(ctx, req); err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(time.Millisecond)
	}
}

// SetOutboundRingBudget overrides the finite post-ring bound driveTx re-arms to
// on the first provisional (B1), returning a restore func. Production always
// uses the outboundRingBudget const (180s); the reap test needs a small budget
// so it does not wait the real three minutes. Tests run sequentially (no
// t.Parallel here), so the single package-level override is race-free.
func SetOutboundRingBudget(d time.Duration) (restore func()) {
	old := ringBudgetOverride
	ringBudgetOverride = d
	return func() { ringBudgetOverride = old }
}

// SetInboundTCPEvictIdleForTest overrides the silence after which a listener at
// its cap may close a connection to admit a new one (CF-189, D6C-8), returning
// a restore func. Same no-t.Parallel invariant as SetOutboundRingBudget.
func SetInboundTCPEvictIdleForTest(d time.Duration) (restore func()) {
	old := evictIdleOverride
	evictIdleOverride = d
	return func() { evictIdleOverride = old }
}

// SetDNSResolverForTest makes UAs built afterwards resolve through r (the sipgo
// agent's DNS resolver and the digest pins), returning a restore func. Same
// no-t.Parallel invariant as SetOutboundRingBudget.
func SetDNSResolverForTest(r *net.Resolver) (restore func()) {
	old := dnsResolverOverride
	dnsResolverOverride = r
	return func() { dnsResolverOverride = old }
}

// SetPostCancelWait overrides the bound driveTx re-arms to once a CANCEL has
// been written (CF-030), returning a restore func. Production uses the
// postCancelWait const (64*T1 = 32s). Same no-t.Parallel invariant as
// SetOutboundRingBudget.
func SetPostCancelWait(d time.Duration) (restore func()) {
	old := postCancelWaitOverride
	postCancelWaitOverride = d
	return func() { postCancelWaitOverride = old }
}

// SetMediaTeardownHook installs (or clears, with nil) the phaseMediaTeardown
// widening hook for a test.
func SetMediaTeardownHook(fn func()) { mediaTeardownHook = fn }

// SetDialAnsweringHook installs (or clears, with nil) the seam that widens
// runDial's ACK -> phaseAnswered window, so a test can land an in-dialog
// request inside it. Like SetOutboundRingBudget, the single package-level
// override is race-free because these tests do not run in parallel.
func SetDialAnsweringHook(fn func()) { dialAnsweringHook = fn }

// SetHangupByeHook installs (or clears, with nil) the seam between runDial's
// claim of a hung-up answering-window dial and its BYE, so a test can land a
// peer BYE there.
func SetHangupByeHook(fn func()) { hangupByeHook = fn }

// SetFailedDialHook installs (or clears, with nil) the seam endFailedDial runs
// immediately before teardownDialog, so a test can land a Hangup at the
// timeout/hangup linearization point.
func SetFailedDialHook(fn func()) { failedDialHook = fn }

// SetAnswerRespondedHook installs (or clears, with nil) the seam between
// Answer's 200 write and its final claim, so a test can land the caller's ACK
// while the inbound dialog is still phaseAnswering.
func SetAnswerRespondedHook(fn func()) { answerRespondedHook = fn }

// SetAckAnswerAppliedHook installs (or clears, with nil) the seam between
// applyAckAnswer's installation of a valid ACK answer and its startMediaLoop.
func SetAckAnswerAppliedHook(fn func()) {
	if fn == nil {
		ackAnswerAppliedHook.Store(nil)
		return
	}
	ackAnswerAppliedHook.Store(&fn)
}

// MediaLoopPublishedForTest reports whether a media loop is installed on the
// dialog (false for an unknown dialog).
func MediaLoopPublishedForTest(u *UA, dialogID string) bool {
	d, err := u.lookup(dialogID)
	if err != nil {
		return false
	}
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	return d.mediaLoop != nil
}

// DialogAckedForTest reports whether onAck has accepted the INVITE's ACK on
// the dialog (false for an unknown dialog).
func DialogAckedForTest(u *UA, dialogID string) bool {
	d, err := u.lookup(dialogID)
	if err != nil {
		return false
	}
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	return d.acked
}

// RegisteredDialogCount is the number of live dialogs in the registry. B1's
// reap test asserts it returns to 0 after a ring-then-silent dial is reaped —
// i.e. no Call is left parked in ringing.
func (u *UA) RegisteredDialogCount() int {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	return len(u.calls.byID)
}

// KeepaliveArmed reports whether startKeepalive built a keepalive refresher.
// "keepalive: none" must arm NOTHING; asserting only that the wire is quiet
// passes even when a refresher is armed and fails on an unknown mode every
// interval.
func (u *UA) KeepaliveArmed() bool {
	u.reg.mu.Lock()
	defer u.reg.mu.Unlock()
	return u.reg.keepalive != nil
}

// RegisterRefresherStopped reports whether the register refresher's loop has
// ENDED — its goroutine returned and closed `done`.
//
// It exists because "the refresh loop ended quietly" is not observable from
// outside the package any other way, and the difference between "ended" and
// "still inside its retry backoff" is exactly what a test asserting the ABSENCE
// of a give-up event has to wait for: OnGiveUp can only fire after the whole
// backoff schedule has been driven off the fake clock, so a scan taken before
// then cannot fail.
func (u *UA) RegisterRefresherStopped() bool {
	u.reg.mu.Lock()
	r := u.reg.refresher
	u.reg.mu.Unlock()
	if r == nil {
		// FALSE, NOT TRUE, and deliberately so. Unregister/Close clear
		// u.reg.refresher BEFORE stopRefresher's Stop() joins the goroutine, so
		// a nil field does not mean the loop has ended — there is a window where
		// it is still running. Reporting "stopped" there would make any caller
		// that races teardown against this poll pass without the property
		// holding, which is the exact vacuity this seam exists to avoid.
		// A UA that never armed a refresher therefore never reports stopped;
		// that surfaces as waitForCond's 3s deadline, which is loud and fast.
		return false
	}
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

// RunDialGoroutinePresent reports whether any live goroutine is executing
// runDial — the direct signal that a dial runner has (not) leaked. It reuses
// ua_test.go's goroutineStackContains, matching runDial's own stack frame.
func RunDialGoroutinePresent() bool {
	return goroutineStackContains("UA).runDial(")
}

// StopMediaLoopForTest tears down a dialog's media loop while leaving the
// dialog answered, so a test can prove that a path which must not depend on
// media (SIP INFO DTMF, §2.2) genuinely does not.
func StopMediaLoopForTest(t *testing.T, u *UA, dialogID string) {
	t.Helper()
	d, err := u.lookup(dialogID)
	if err != nil {
		t.Fatalf("StopMediaLoopForTest: %v", err)
	}
	u.calls.mu.Lock()
	ml := d.mediaLoop
	d.mediaLoop = nil
	u.calls.mu.Unlock()
	if ml != nil {
		ml.stop()
	}
}

// DialogMediaConnOpenForTest reports whether the dialog is still registered and
// its media socket is still open: it looks the dialog up (a forgotten one is
// false) and probes the answered dialog's media loop conn through its raw
// descriptor, which errors once the conn is closed and has no other effect.
func DialogMediaConnOpenForTest(u *UA, dialogID string) bool {
	d, err := u.lookup(dialogID)
	if err != nil {
		return false
	}
	u.calls.mu.Lock()
	ml := d.mediaLoop
	u.calls.mu.Unlock()
	if ml == nil {
		return false
	}
	rc, err := ml.conn.SyscallConn()
	if err != nil {
		return false
	}
	return rc.Control(func(uintptr) {}) == nil
}

// ZeroUALifecycleFieldsForTest nils u's uaCtx and cfg.Clock and returns a
// restore func, so a test can drive sendDTMFInfo's B-M1 nil-guard path (a *UA
// built any other way than New(), which always sets both, would otherwise
// SIGSEGV there) against a REAL established call rather than a synthetic one.
func ZeroUALifecycleFieldsForTest(u *UA) (restore func()) {
	oldCtx, oldClock := u.uaCtx, u.cfg.Clock
	u.uaCtx, u.cfg.Clock = nil, nil
	return func() { u.uaCtx, u.cfg.Clock = oldCtx, oldClock }
}

// HangupWithReasonForTest exercises the unexported hangupWithReason from the
// sipua_test package. Production callers are inside this package (the
// session-timer watchdog); the exported Hangup deliberately does NOT accept a
// header, so this seam is the only way a test can drive one.
func HangupWithReasonForTest(u *UA, dialogID, reason string) error {
	return u.hangupWithReason(context.Background(), dialogID, sip.NewHeader("Reason", reason))
}

// ClaimControlOpForTest claims phaseControlOp on dialogID exactly as a
// production control operation (call_transfer) does, returning the dialog's
// controlOpEnded channel and a release func. It exists so the guard's own
// tests (controlop_test.go) can hold the phase without a REFER in flight. It
// claims with TestControlOpKind — deliberately NOT ControlOpTransfer, so the
// guard's tests prove it reports whatever kind its owner stored (D15).
func ClaimControlOpForTest(u *UA, dialogID string) (<-chan struct{}, func(), error) {
	d, err := u.lookup(dialogID)
	if err != nil {
		return nil, nil, err
	}
	u.calls.mu.Lock()
	ended, err := claimControlOpLocked(d, TestControlOpKind, "test_control_op")
	u.calls.mu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	return ended, func() {
		u.calls.mu.Lock()
		releaseControlOpLocked(d)
		u.calls.mu.Unlock()
	}, nil
}

// TestControlOpKind is the kind ClaimControlOpForTest stores: a value no
// production operation uses.
var TestControlOpKind session.ControlOpKind = "test_control_op"

// SetReferOutcomeArmHook installs (or clears, with nil) the seam that reports
// every (re)arm of a transfer's outcome-deadline timer (plan D14). UNLIKE
// SetMediaTeardownHook's plain package-level var, this hook is backed by an
// atomic.Pointer (see referOutcomeArmHook's doc comment in transfer.go):
// awaitReferOutcome's goroutine can still be reading it after the test that
// armed it has returned, so a plain var here is a genuine data race across
// tests, not just a parallel-test hazard.
func SetReferOutcomeArmHook(fn func(time.Duration)) {
	if fn == nil {
		referOutcomeArmHook.Store(nil)
		return
	}
	referOutcomeArmHook.Store(&fn)
}

// SetTransferBeforeSendHookForTest installs (or clears, with nil) the seam
// that runs right before Transfer dispatches its REFER, with the control op's
// ended channel (CF-008).
func SetTransferBeforeSendHookForTest(fn func(ended <-chan struct{})) { transferBeforeSendHook = fn }

// ReferOutcomeDefaultWait is the outcome window used until a NOTIFY states the
// subscription's duration.
const ReferOutcomeDefaultWait = referOutcomeDefaultWait

// ReferOutcomeMaxWait is the hard ceiling of the outcome window, measured from
// the REFER's 2xx.
const ReferOutcomeMaxWait = referOutcomeMaxWait

// ArrivalsObservedForTest reports how many gated inbound requests (plan D18)
// sipgo's transport read loop has handed observeArrival for the dialog. 0 for an
// unknown dialog.
func ArrivalsObservedForTest(u *UA, dialogID string) uint64 {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	d, ok := u.calls.byID[dialogID]
	if !ok {
		return 0
	}
	return d.arrivals.observed
}

// InboundNotYetAnsweringForTest reports whether dialogID is a live inbound
// dialog Answer has not claimed yet (phaseAdmitting or phaseRinging) — the
// phases in which Hangup now DECLINES the call rather than refusing.
func InboundNotYetAnsweringForTest(u *UA, dialogID string) bool {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	d, ok := u.calls.byID[dialogID]
	return ok && (d.phase == phaseAdmitting || d.phase == phaseRinging)
}

// HangupPendingForTest reports whether a Hangup has recorded its intent on the
// still-registered dialog (cancelRequested): outbound before it is established,
// or inbound while Answer is writing its 200. false for an unknown
// dialog.
func HangupPendingForTest(u *UA, dialogID string) bool {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	d, ok := u.calls.byID[dialogID]
	return ok && d.cancelRequested
}

// ReferSubMaybeLiveForTest reports whether an id-less NOTIFY is ambiguous on
// the dialog now (D13, CF-012): an earlier REFER's subscription may still be
// live. false for an unknown dialog.
func ReferSubMaybeLiveForTest(u *UA, dialogID string) bool {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	d, ok := u.calls.byID[dialogID]
	return ok && referIdlessAmbiguousLocked(d, u.now())
}

// HoldSendOrderTokenForTest takes dialogID's per-dialog send-order token (plan
// D12) and returns its idempotent release, so a test can make an in-dialog
// sender wait its turn (CF-018).
func HoldSendOrderTokenForTest(t *testing.T, u *UA, dialogID string) (release func()) {
	t.Helper()
	d, err := u.lookup(dialogID)
	if err != nil {
		t.Fatalf("HoldSendOrderTokenForTest: %v", err)
	}
	u.calls.mu.Lock()
	tok := sendOrderTokLocked(d)
	u.calls.mu.Unlock()
	select {
	case tok <- struct{}{}:
	default:
		t.Fatal("HoldSendOrderTokenForTest: the send-order token is already held")
	}
	var once sync.Once
	return func() { once.Do(func() { <-tok }) }
}

// SetInDialogSendContendedHookForTest installs (or clears, with nil)
// inDialogSendContendedHook: it runs when an in-dialog send finds its dialog's
// send-order token held, just before it blocks for it.
func SetInDialogSendContendedHookForTest(fn func(sip.RequestMethod)) { inDialogSendContendedHook = fn }

// HeldInviteCounts reports the held initial-INVITE handlers and the size of
// the merged-request table (CF-177, CF-097).
func (u *UA) HeldInviteCounts() (held, merged int) {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	return u.calls.heldInvites, len(u.calls.merged)
}

// SetAck2xxT1 overrides the base interval of the inbound 2xx retransmission
// (and so its 64*T1 no-ACK deadline) for a test, returning a restore func.
// Production uses sip.T1. Same no-t.Parallel invariant as the other setters.
func SetAck2xxT1(d time.Duration) (restore func()) {
	old := ack2xxT1
	ack2xxT1 = d
	return func() { ack2xxT1 = old }
}

// EndUnacknowledgedForTest runs the no-ACK teardown on a dialog now.
func (u *UA) EndUnacknowledgedForTest(dialogID string) {
	if d, err := u.lookup(dialogID); err == nil {
		u.endUnacknowledged(d)
	}
}

// CloseMarkedForTest marks the UA closed without tearing it down, as Close
// does before it cancels the UA context.
func (u *UA) CloseMarkedForTest() {
	u.calls.mu.Lock()
	u.calls.closed = true
	u.calls.mu.Unlock()
}

// MediaSessionForTest returns the dialog's negotiated media session (nil for
// an unknown dialog).
func MediaSessionForTest(u *UA, dialogID string) *media.Session {
	d, err := u.lookup(dialogID)
	if err != nil {
		return nil
	}
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	return d.mediaSession
}

// EarlyAnswerCount is the number of early SDP bodies held for the outbound
// dialog (-1 when the dialog is not found).
func EarlyAnswerCount(u *UA, dialogID string) int {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	d, ok := u.calls.byID[dialogID]
	if !ok {
		return -1
	}
	return len(d.earlyAnswers)
}

// EarlyAnswerBytes is the total bytes held in the outbound dialog's early
// answers (-1 when the dialog is not found).
func EarlyAnswerBytes(u *UA, dialogID string) int {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	d, ok := u.calls.byID[dialogID]
	if !ok {
		return -1
	}
	n := 0
	for _, b := range d.earlyAnswers {
		n += len(b)
	}
	return n
}

// AnswerSDPForTest is a copy of the outbound answer body runDial applied.
func AnswerSDPForTest(u *UA, dialogID string) []byte {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	d, ok := u.calls.byID[dialogID]
	if !ok {
		return nil
	}
	return append([]byte(nil), d.answerSDP...)
}

// SetMediaLoopBuiltHook installs (or clears, with nil) the seam between
// startMediaLoop's build and its publish.
func SetMediaLoopBuiltHook(fn func()) { mediaLoopBuiltHook = fn }

// SetReAnswerParsedHook installs fn between applyReAnswer's unlocked part and its
// publishing section, returning a restore func. Same no-t.Parallel invariant.
func SetReAnswerParsedHook(fn func()) (restore func()) {
	reAnswerParsedHook.Store(&fn)
	return func() { reAnswerParsedHook.Store(nil) }
}
