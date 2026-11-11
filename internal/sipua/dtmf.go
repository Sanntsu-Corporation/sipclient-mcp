package sipua

// B-M7 (D20, W2): READING THE REVIEW-PROCESS REFERENCES IN THIS FILE. Comments
// below cite "Task 12", "Task 13 review", "Correction 2", "the brief" and
// "WIRE-VERIFIED FIX". They are not noise and are deliberately kept — each marks
// a specific defect that was found and fixed, and knowing that is why the code
// resists an "obvious" simplification. Their sources:
//
//   Task NN, "the brief"   -> the Phase 3 DTMF/session-timers implementation plan (internal)
//   "Correction N"         -> the same plan's correction list
//   "Task NN review"       -> internal per-task review notes (not part of this repository)
//   "WIRE-VERIFIED FIX"    -> confirmed against the live §14.5 Asterisk rig, not
//                             only in-process; see e2e/asterisk/USAGE.md
//
// A future reader who cannot find one of these has hit an internal artifact, not
// a stale reference.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/siptest"
)

// dtmfEventVolume is RFC 4733 §2.5.1.2's volume field: the tone's power
// relative to 0 dBm0, expressed as a positive number of dB BELOW it. 10 is the
// conventional value every interop target we test against sends.
const dtmfEventVolume = 10

// dtmfEndRetransmits is RFC 4733 §2.5.1.4: the final packet of an event, with
// the E bit set, is sent three times in total so a single loss cannot leave the
// far end holding a tone forever.
const dtmfEndRetransmits = 3

// dtmfMaxDurationMs is the per-digit tone length limit enforced against RFC
// 4733 §2.3's 16-bit duration field at 8 kHz: 409 ticks x 160 samples/tick =
// 65440, the largest whole-tick sample count a uint16 can hold — a true hard
// ceiling of 409 ticks x 20 ms = 8180 ms. 8000 is a round number chosen WITH
// MARGIN below that 8180 ms ceiling, not the ceiling itself. A caller
// requesting more than dtmfMaxDurationMs would, if this were unbounded,
// silently wrap the wire duration partway through the retransmits (measured:
// wraps at tick 409, 65440 -> 64), advertising a bogus short duration for a
// long tone. This is rejected rather than clamped or truncated, matching this
// codebase's convention of reporting a real error instead of silently
// producing a malformed result.
const dtmfMaxDurationMs = 8000

// dtmfTick is one 20 ms TX tick's contribution to a telephone-event send. A nil
// payload is a GAP tick: nothing is sent and that tick's ordinary audio frame
// goes out instead.
type dtmfTick struct {
	payload []byte
	marker  bool // RFC 4733: set on the first packet of each event
	newTS   bool // set on the first packet of each event: latch a fresh RTP ts
}

// dtmfEventTX renders a digit string as a pre-computed sequence of per-tick RFC
// 4733 telephone-event payloads.
//
// IT IS DRIVEN BY runTX, NOT BY ITS OWN GOROUTINE, and that is the whole design
// (spec §2.2). runTX stays the SINGLE writer of the dialog's RTP socket, so the
// sequence-number space, the SSRC and the SRTP Protect context need no second
// lock; and because an event packet REPLACES that tick's audio frame, RFC 4733
// §2.5.2.2's audio suppression during an event falls out for free.
//
// It is single-consumer-affine to the TX goroutine — next() is called from
// nowhere else — so it carries no lock, exactly like codec.PromptSource.
type dtmfEventTX struct {
	pt     uint8
	ticks  []dtmfTick
	idx    int
	onDone func()
	doneCh chan struct{}
	// release is installed by mediaLoop.claimEventTX at claim time and fires
	// from finish(), BEFORE close(doneCh), so the compare-and-clear release of
	// the media loop's claimed-event slot happens at essentially the same
	// moment Done() closes rather than one statement later in runTX. That
	// closes the race where a caller unblocked by Done() tries to claim a new
	// event before the old one's slot has actually been cleared. It is nil
	// for an event that was never claimed (e.g. constructed directly in a
	// unit test), in which case finish() simply skips it.
	release func()
	// toneMs is the PER-DIGIT tone length actually signalled — toneTicks x 20 ms,
	// which is also the value the last packet's duration field carries. It is
	// NOT derived from DurationMs(), which additionally counts the three end
	// retransmits and the inter-digit gap ticks. dtmf_send reports this (§4).
	toneMs int
}

// newDTMFEventTX pre-computes every tick. pt is the NEGOTIATED telephone-event
// payload type (media.Session.TelephoneEventPT), never a literal. durationMs and
// gapMs are rounded UP to whole 20 ms ticks, matching codec.DTMFSource, so the
// two modes report the same duration_ms for the same request. durationMs must
// not exceed dtmfMaxDurationMs (see its doc comment): the RFC 4733 duration
// field is a uint16 timestamp-units count and a longer tone would silently
// wrap on the wire.
func newDTMFEventTX(pt uint8, digits string, durationMs, gapMs int, onDone func()) (*dtmfEventTX, error) {
	if pt == 0 {
		return nil, fmt.Errorf("dtmf: telephone-event payload type is 0 (not negotiated)")
	}
	if !codec.ValidDTMFDigits(digits) {
		return nil, fmt.Errorf("dtmf: digits %q must be non-empty and drawn from %s", digits, codec.DTMFAlphabet)
	}
	if durationMs <= 0 {
		return nil, fmt.Errorf("dtmf: duration_ms must be > 0")
	}
	if durationMs > dtmfMaxDurationMs {
		return nil, fmt.Errorf("dtmf: duration_ms %d exceeds the RFC 4733 wire-safe maximum of %d ms", durationMs, dtmfMaxDurationMs)
	}
	if gapMs < 0 {
		return nil, fmt.Errorf("dtmf: gap_ms must be >= 0")
	}
	const frameMs = 20
	const samplesPerTick = 160 // 20 ms at 8 kHz, in RTP timestamp units
	toneTicks := (durationMs + frameMs - 1) / frameMs
	gapTicks := (gapMs + frameMs - 1) / frameMs

	e := &dtmfEventTX{
		pt:     pt,
		onDone: onDone,
		doneCh: make(chan struct{}),
		toneMs: toneTicks * frameMs,
	}
	for i := 0; i < len(digits); i++ {
		code, ok := codec.DTMFEventCode(digits[i])
		if !ok {
			return nil, fmt.Errorf("dtmf: %q has no RFC 4733 event code", digits[i])
		}
		for k := 1; k <= toneTicks; k++ {
			e.ticks = append(e.ticks, dtmfTick{
				payload: dtmfEventPayload(code, false, uint16(k*samplesPerTick)),
				marker:  k == 1,
				newTS:   k == 1,
			})
		}
		final := uint16(toneTicks * samplesPerTick)
		for r := 0; r < dtmfEndRetransmits; r++ {
			e.ticks = append(e.ticks, dtmfTick{
				payload: dtmfEventPayload(code, true, final),
			})
		}
		// B-M9: no gap after the FINAL digit — there is no successor tone to
		// separate it from, so appending one here only inflates the total
		// hold time on the loop's claimed-event slot for no signalling
		// purpose.
		if i+1 < len(digits) {
			for g := 0; g < gapTicks; g++ {
				e.ticks = append(e.ticks, dtmfTick{})
			}
		}
	}
	return e, nil
}

// dtmfEventPayload renders RFC 4733 §2.3's four-octet telephone-event payload:
// event code, then E|R|volume, then a 16-bit big-endian duration in timestamp
// units. R (reserved) is always 0.
func dtmfEventPayload(code uint8, end bool, durationTS uint16) []byte {
	b := make([]byte, 4)
	b[0] = code
	b[1] = dtmfEventVolume & 0x3F
	if end {
		b[1] |= 0x80
	}
	binary.BigEndian.PutUint16(b[2:], durationTS)
	return b
}

// next hands runTX this tick's contribution. ok is false once the whole digit
// string has been sent, at which point onDone has fired once, the media loop's
// claimed-event slot has been released (compare-and-clear against this event,
// if it was ever claimed), and Done() is closed. A nil payload with ok == true
// is a gap tick: send audio instead.
func (e *dtmfEventTX) next() (payload []byte, marker, newTS, ok bool) {
	if e.idx >= len(e.ticks) {
		e.finish()
		return nil, false, false, false
	}
	t := e.ticks[e.idx]
	e.idx++
	return t.payload, t.marker, t.newTS, true
}

func (e *dtmfEventTX) finish() {
	select {
	case <-e.doneCh:
		return
	default:
	}
	if e.release != nil {
		e.release()
	}
	if e.onDone != nil {
		e.onDone()
	}
	close(e.doneCh)
}

// Done is closed once every tick has been consumed.
func (e *dtmfEventTX) Done() <-chan struct{} { return e.doneCh }

// DurationMs is the deterministic wall length of the whole send: ticks x 20 ms,
// which INCLUDES the three end retransmits and the gap ticks of every digit.
func (e *dtmfEventTX) DurationMs() int64 { return int64(len(e.ticks)) * 20 }

// EmittedDurationMs is the PER-DIGIT tone length actually signalled: the request
// rounded UP to whole 20 ms ticks, matching codec.DTMFSource exactly so the two
// RTP-path modes report the same duration_ms for the same request. It is what
// dtmf_send reports (§4) — never the raw request, and never DurationMs(), which
// counts the end retransmits that are not tone.
func (e *dtmfEventTX) EmittedDurationMs() int { return e.toneMs }

// dtmfGapUnset is an ALIAS of session.DTMFGapUnset, not a second definition of
// it: the sentinel that means "the caller named no gap at all", as distinct from
// an explicit zero. It is spelled locally only so this package's call sites read
// in this package's own vocabulary and get int rather than int64.
const dtmfGapUnset = session.DTMFGapUnset

// resolveDTMFTiming is the int-typed ADAPTER over session.ResolveDTMFTiming, for
// SendDTMF's int arguments. IT HOLDS NO DEFAULT VALUE AND NO RULE OF ITS OWN
// (Rule 18) — 100 ms, 50 ms and the tri-state are stated once, in
// session/collaborators.go, and this function exists purely to cross the
// int64/int boundary.
//
// THERE ARE TWO CALL SITES OF THE SHARED RESOLVER AND BOTH ARE NECESSARY. This
// one runs at SEND time, at the top of SendDTMF — the choke point every mode arm
// and the media_plan `dtmf` step executor reaches. The other, decodeDTMF, runs at
// VALIDATION time, because §4's plan bound needs concrete numbers before the call
// is dialed and cannot defer to call time. The shared function's idempotence is
// what makes an already-resolved plan step pass through here unchanged, including
// a deliberate 0 gap.
func resolveDTMFTiming(durationMs, gapMs int) (int, int) {
	d, g := session.ResolveDTMFTiming(int64(durationMs), int64(gapMs))
	return int(d), int(g)
}

// DTMFMode implements session.UserAgent.DTMFMode: the EFFECTIVE mode for a
// dialog — the per-dialog override if one was set, else the profile default.
// ok is false for an unknown dialog.
func (u *UA) DTMFMode(dialogID string) (string, bool) {
	d, err := u.lookup(dialogID)
	if err != nil {
		return "", false
	}
	u.calls.mu.Lock()
	mode := d.dtmfMode
	u.calls.mu.Unlock()
	if mode == "" {
		return u.dtmfModeDefault(), true
	}
	return mode, true
}

// recordDTMFMode stores mode as dialog d's effective DTMF mode, under
// u.calls.mu. Callers gate this on mode having already been validated as one of
// the three recognized DTMFMode values (correction: an unrecognized mode string
// must never be persisted, or call_status.dtmf_mode would report garbage after
// a rejected dtmf_send).
func (u *UA) recordDTMFMode(d *dialog, mode string) {
	u.calls.mu.Lock()
	d.dtmfMode = mode
	u.calls.mu.Unlock()
}

// isRecognizedDTMFMode reports whether mode is one of §10.8's three DTMFMode
// values. SendDTMF calls this ONCE, before its mode switch, so the
// "only record a recognized mode" rule (see recordDTMFMode) is stated in
// exactly one place rather than repeated in every switch arm — that repetition
// is what let Task 13 review's mode-corruption bug slip in the first place, and
// duplicating the check per-arm would let Tasks 14/15 silently drop it when
// they rewrite the rfc2833/info arms.
func isRecognizedDTMFMode(mode string) bool {
	switch mode {
	case "inband", "rfc2833", "info":
		return true
	default:
		return false
	}
}

// inbandDetectionEnabled reports whether this UA runs the Goertzel tap on its
// calls' RX audio. Detection mode is NOT agent-selectable (decision 4), so the
// switch is the profile's own dtmf_mode.
func (u *UA) inbandDetectionEnabled() bool { return u.dtmfModeDefault() == "inband" }

// digitWaiter collects the digits of ONE in-flight wait_dtmf step (§10.7). It
// is created by waitForDigits on the media-plan executor's goroutine, published
// on the dialog under u.calls.mu, and fed by offer from the RX goroutine — so
// its own state carries its OWN mutex rather than borrowing u.calls.mu. That
// keeps offer's critical section off the UA-wide lock and keeps the lock order
// one-way (u.calls.mu -> w.mu is never inverted: wait/collected take w.mu only).
type digitWaiter struct {
	mu sync.Mutex
	// want is the number of digits that satisfies this waiter. 0 means "the
	// FIRST digit satisfies it" — see newDigitWaiter for why.
	want int
	got  []byte
	// done latches the ONE close of ch. Without it a digit arriving after the
	// waiter is already satisfied — which is entirely possible, since the RX
	// goroutine keeps delivering digits until waitForDigits' deferred clear runs
	// — would close an already-closed channel and panic.
	done bool
	ch   chan struct{}
}

// newDigitWaiter builds a collector satisfied by `want` digits, or by the FIRST
// digit when want <= 0.
//
// WHY "FIRST DIGIT" IS THE want<=0 RULE. Decision 14 says effective max-digits
// is len(digits) when digits is given and "unbounded otherwise", which leaves
// the no-digits case with no completion condition at all — read literally it
// would always run the full window and then fail as a timeout, making
// timeout-as-failure unreachable-when-successful and meaningless. Satisfying on
// the first digit is the only reading under which the timeout failure fires
// exactly when NO digits arrived.
func newDigitWaiter(want int) *digitWaiter {
	if want < 0 {
		want = 0
	}
	return &digitWaiter{want: want, ch: make(chan struct{})}
}

// offer records one digit and, once the waiter is satisfied, closes ch EXACTLY
// ONCE to wake wait. A digit offered after satisfaction is recorded nowhere and
// is a safe no-op: the step's collected digits are frozen at the moment it was
// satisfied, so collected() cannot report more digits than the step asked for.
func (w *digitWaiter) offer(digit byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return
	}
	w.got = append(w.got, digit)
	if len(w.got) >= w.want {
		// want == 0 also lands here: the first digit makes len(got) == 1 >= 0.
		w.done = true
		close(w.ch)
	}
}

// wait blocks until the waiter is satisfied, the call ends, or the timeout
// fires. It reports true when satisfied.
func (w *digitWaiter) wait(callEnded <-chan struct{}, timeout <-chan time.Time) bool {
	select {
	case <-w.ch:
		return true
	case <-callEnded:
		return false
	case <-timeout:
		return false
	}
}

// collected returns the digits received so far, in arrival order.
func (w *digitWaiter) collected() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.got)
}

// waitForDigits installs a digitWaiter on the dialog, parks for up to timeoutMs,
// and ALWAYS clears the waiter before returning — so a later wait_dtmf step
// never inherits a stale collector, and handleDigit's `if w != nil` sees only a
// live one. The clear is a COMPARE-AND-CLEAR against this waiter (the same
// idiom releaseEventTX uses for the claimed-event slot), so a step that has
// already been superseded cannot clear its successor's waiter.
//
// d MAY be nil: the registry forgets a dialog BEFORE ml.stop() closes ml.done
// (all three teardown paths — teardownDialog, Hangup, onBye — do this in that
// order), so execStep's mp.dialog() lookup can already miss while the call is
// still tearing down. A nil d skips the install/clear (there is nothing to
// dereference) but still parks on ml.done via wait() below, so this returns
// timedOut==true once ml.done closes shortly after — never a spurious
// immediate success.
//
// It takes the clock from Config so a timing test runs on the FAKE clock, like
// every other stateful timer in this package.
func (u *UA) waitForDigits(d *dialog, ml *mediaLoop, expected string, timeoutMs int64) (string, bool) {
	w := newDigitWaiter(len(expected))
	if d != nil {
		u.calls.mu.Lock()
		d.dtmfWaiter = w
		u.calls.mu.Unlock()
		defer func() {
			u.calls.mu.Lock()
			if d.dtmfWaiter == w {
				d.dtmfWaiter = nil
			}
			u.calls.mu.Unlock()
		}()
	}

	clk := u.cfg.Clock
	if clk == nil {
		clk = clock.System()
	}
	satisfied := w.wait(ml.done, clk.After(time.Duration(timeoutMs)*time.Millisecond))
	return w.collected(), !satisfied
}

// handleDigit is §2.2's single funnel for every detected digit, whichever mode
// detected it. It emits UAEventDTMF unconditionally, which session.Call turns
// into a ring entry and a §10.5 dtmf event in one critical section (§6.3 rule
// 1), and THEN offers the digit to a parked wait_dtmf waiter if one is
// installed.
//
// THE ORDER IS DELIBERATE: offering first could let the plan executor advance
// to the next step, and emit that step's events, BEFORE the digit that released
// it appears in the call's event log — an out-of-order log for no benefit. The
// waiter read takes u.calls.mu (lock order u.calls.mu -> ml.st.mu is preserved:
// the RX goroutine reaches here holding neither), and offer is called OUTSIDE
// that lock so the waiter's own mutex is never nested under the UA-wide one.
func (u *UA) handleDigit(d *dialog, digit byte, mode string, durationMs int) {
	u.emit(session.UAEvent{
		Kind: session.UAEventDTMF, DialogID: d.id, CallID: d.callID,
		Direction: d.direction, Digit: string(digit), DTMFMode: mode, DurationMs: durationMs,
	})
	u.calls.mu.Lock()
	w := d.dtmfWaiter
	u.calls.mu.Unlock()
	if w != nil {
		w.offer(digit)
	}
}

// SendDTMF implements session.UserAgent.SendDTMF (§10.8 dtmf_send). mode "" is
// the profile default.
//
// ERROR MAP — §10.8's table, extended below where an arm's error surface goes
// beyond it (this is NOT "exactly" the table for every arm any more: info
// alone can also surface cancelled and internal, because it is the only arm
// that makes its own network request per digit rather than driving a local
// renderer against a media loop):
//   - invalid_argument     — a digit outside 0-9A-D*#, an unknown mode, or a
//     duration_ms above dtmfMaxDurationMs
//   - precondition_failed  — the call is not answered; (inband only) the
//     single media slot is occupied by a play or
//     record; (EVERY mode) a DTMF send of ANY mode is
//     already active on this dialog (F1: the dialog-level
//     dtmfSendInFlight claim, generalized from the old
//     info-only field — see its doc comment in call.go);
//     (inband/rfc2833 only)
//     the call ended before the digits could be sent; or
//     (info only) the far end answered an INFO with a
//     non-2xx that is not one of the not_supported codes
//     below
//   - not_supported        — (rfc2833 only) mode "rfc2833" requested but
//     telephone-event was not negotiated — REPORTED, NEVER
//     SILENTLY DOWNGRADED: an agent that asked for
//     out-of-band signalling and got audible tones on a
//     compressed trunk has been lied to; (info only) the
//     far end answered an INFO 405/501/415 — it cannot or
//     will not accept DTMF-over-INFO, matching the same
//     "the far end can't/won't do this" convention
//   - cancelled            — (info only) the caller's ctx, or the UA's own
//     lifecycle ctx, was done before the send finished
//   - internal             — (info only) the INFO transaction itself failed
//     at the transport layer (not a SIP response at all)
//
// It BLOCKS until the whole digit string has been emitted, so digits_sent is a
// fact rather than an intention — AND SO IS THE SECOND RETURN VALUE, and its
// MEANING is the SAME across all three arms: the PER-DIGIT emitted duration,
// never a total. Both RTP-path senders round each digit up to a whole number
// of 20 ms ticks, so a 50 ms request puts 60 ms of tone on the wire;
// emittedDurationMs is that per-digit figure, read directly from the sender's
// own EmittedDurationMs() — never derived by dividing the sender's total
// elapsed DurationMs() (which also counts gaps, and for rfc2833 the end
// retransmits) by the digit count. The info arm reports the plain resolved
// durationMs per digit the same way: an INFO's Duration field is per-message,
// not part of one continuous tone stream, but that does not change what this
// return value MEANS — it is documented (design doc) as the emitted PER-DIGIT
// duration for dtmf_send as a whole, and Task 16 reports it straight through
// as duration_ms, so an accumulated total here would be misread by any agent
// reading the spec. digits_sent alone communicates how many digits succeeded
// on a partial send; emittedDurationMs never also encodes that.
//
// gapMs is TRI-STATE: a positive value is a gap, 0 means NO GAP, and dtmfGapUnset
// (negative) means the caller named none and wants the default. resolveDTMFTiming
// below is where the send path collapses that distinction, by delegating to
// session.ResolveDTMFTiming — the one function that holds the rule and the two
// default values, shared with the media-plan decoder's validation-time call.
func (u *UA) SendDTMF(ctx context.Context, dialogID, digits string, mode session.DTMFMode,
	durationMs, gapMs int) (int, int, error) {
	if !codec.ValidDTMFDigits(digits) {
		return 0, 0, apierr.InvalidArgument(
			"dtmf_send: digits must be non-empty and drawn from " + codec.DTMFAlphabet)
	}
	effective := string(mode)
	if effective == "" {
		effective = u.dtmfModeDefault()
	}
	// The shared resolver, once, for every mode and for the plan executor alike
	// (Rule 18). Idempotent, so a plan step already resolved at validation time is
	// unchanged here.
	durationMs, gapMs = resolveDTMFTiming(durationMs, gapMs)
	if durationMs > dtmfMaxDurationMs {
		// dtmfMaxDurationMs is fundamentally an RTP/RFC 4733 wire-format
		// constraint (its own doc comment: the largest whole-tick count a
		// uint16 duration field can carry) and has no direct bearing on the
		// future SIP INFO arm, which carries no such field. It is applied here,
		// in the shared prologue, purely for CROSS-MODE CONSISTENCY (Task 12's
		// rfc2833 sender already enforces it) — not because info needs it.
		return 0, 0, apierr.InvalidArgument(fmt.Sprintf(
			"dtmf_send: duration_ms %d exceeds the wire-safe maximum of %d ms", durationMs, dtmfMaxDurationMs))
	}
	if !isRecognizedDTMFMode(effective) {
		return 0, 0, apierr.InvalidArgument(
			"dtmf_send: mode " + effective + " must be rfc2833, inband or info")
	}

	d, err := u.lookup(dialogID)
	if err != nil {
		return 0, 0, err
	}
	u.calls.mu.Lock()
	ml, phase, sess := d.mediaLoop, d.phase, d.mediaSession
	u.calls.mu.Unlock()

	// The write happens in this ONE place, gated only on isRecognizedDTMFMode
	// having already passed above — never for a garbage mode string. Stating
	// this once, rather than once per switch arm below, is what keeps Tasks
	// 14/15 from being able to silently drop the record call when they rewrite
	// the rfc2833/info arms.
	if mode != "" {
		u.recordDTMFMode(d, effective)
	}

	// F1: single-flight the WHOLE dispatch below, not just one mode's own
	// per-arm claim (see d.dtmfSendInFlight's doc comment, call.go) — two
	// sends of DIFFERENT modes on the same dialog were never excluded from
	// each other before this claim existed, which is what let an rfc2833
	// event's tick-stealing corrupt an inband DTMFSource running
	// concurrently on the same call.
	u.calls.mu.Lock()
	// D10: refused during a call control operation, checked under the SAME lock
	// claimControlOpLocked checks dtmfSendInFlight under, so a dtmf_send and a
	// control op exclude each other in both directions.
	if d.phase == phaseControlOp {
		u.calls.mu.Unlock()
		return 0, 0, apierr.PreconditionFailed("dtmf_send: " + controlOpBusyMsg)
	}
	if d.dtmfSendInFlight {
		u.calls.mu.Unlock()
		return 0, 0, apierr.PreconditionFailed(
			"dtmf_send: a DTMF send is already active on this call")
	}
	d.dtmfSendInFlight = true
	u.calls.mu.Unlock()
	defer func() {
		u.calls.mu.Lock()
		d.dtmfSendInFlight = false
		u.calls.mu.Unlock()
	}()

	switch effective {
	case "inband":
		if ml == nil || phase != phaseAnswered {
			return 0, 0, apierr.PreconditionFailed("dtmf_send: call has no media stream (not answered)")
		}
		if ml.neg().txOff {
			return 0, 0, apierr.PreconditionFailed(dtmfNoTXMsg)
		}
		return u.sendDTMFInband(ctx, ml, digits, durationMs, gapMs)
	case "rfc2833":
		if ml == nil || phase != phaseAnswered {
			return 0, 0, apierr.PreconditionFailed("dtmf_send: call has no media stream (not answered)")
		}
		if ml.neg().txOff {
			return 0, 0, apierr.PreconditionFailed(dtmfNoTXMsg)
		}
		return u.sendDTMFRFC2833(ctx, ml, sess, digits, durationMs, gapMs)
	case "info":
		if phase != phaseAnswered {
			return 0, 0, apierr.PreconditionFailed("dtmf_send: call is not answered")
		}
		// §2.2: SIP INFO is an in-dialog signalling request and NEVER touches
		// mediaLoop — no slot, no media stream required.
		return u.sendDTMFInfo(ctx, d, digits, durationMs, gapMs)
	default:
		// Defensive only: isRecognizedDTMFMode already rejected anything else
		// above, so this arm cannot be reached.
		//
		// B-M4 (D20, W2): UNREACHABLE — the mode guard earlier in this function has
		// already rejected anything not handled above, so this arm cannot execute
		// today. KEPT, not deleted (Rule 19: pre-existing defensive code is reported,
		// not removed): it is the compiler's only guard against a future mode being
		// added to the guard's accept-set and not here, which is a real and cheap
		// protection. The duplicated error string is the cost of that.
		return 0, 0, apierr.InvalidArgument(
			"dtmf_send: mode " + effective + " must be rfc2833, inband or info")
	}
}

// dtmfNoTXMsg refuses an RTP DTMF send on a call whose negotiated media
// direction does not send (A-8): the digits would never reach the wire.
const dtmfNoTXMsg = "dtmf_send: the call's media direction does not send (held or inactive)"

// sendDTMFInband claims the single media slot (opDTMFInband) and installs a
// codec.DTMFSource, whose completion callback releases the slot and restores
// the prior TX source — the same contract media_play's PromptSource uses, which
// is exactly why §2.2 gave both ops one slot rather than two mechanisms.
//
// IT CANNOT INTERRUPT A PLAY OR A RECORD (§7's landmine table): a busy slot is
// precondition_failed, unchanged from W5.
func (u *UA) sendDTMFInband(ctx context.Context, ml *mediaLoop, digits string, durationMs, gapMs int) (int, int, error) {
	// B12: the onExhaust hook releases via releaseOpFor(src), NOT the bare
	// releaseOp() — see releaseOpFor's doc comment (medialoop.go). var+assign
	// (rather than :=) lets the closure capture src by reference before
	// NewDTMFSource itself returns.
	var src *codec.DTMFSource
	src, err := codec.NewDTMFSource(digits, durationMs, gapMs, func() { ml.releaseOpFor(src) })
	if err != nil {
		return 0, 0, apierr.InvalidArgument("dtmf_send: " + err.Error())
	}
	if !ml.claimOp(opDTMFInband, src) {
		return 0, 0, apierr.PreconditionFailed(
			"dtmf_send: a play, recording or DTMF send is already active on this call")
	}
	// B-M3 (D20, W2): THIS BLOCK IS DUPLICATED near-verbatim in the sibling arm
	// below (the rfc2833 one; grep "src.Done()" in this file for both). NOT
	// extracted into a shared helper: the two differ in which source they poll
	// and both sit on the blocking send path, so a helper would take a closure
	// per arm and buy nothing but a level of indirection on the code most worth
	// reading straight through. Recorded, deliberately not refactored — if a
	// THIRD arm ever appears, extract then (Rule 15: no abstraction until the
	// second real caller, and these two are not it).
	select {
	case <-src.Done():
	case <-ml.done:
		// TIE-BREAK: src.Done() and ml.done can both become ready at nearly
		// the same moment — the last frame is pulled (closing src.Done())
		// right as the call tears down (closing ml.done) — and a select
		// between two ready channels picks one at random. If the source had
		// in fact already finished, that must NOT be reported as a failure:
		// doing so would fabricate a failure for a fully-successful send, the
		// mirror image of the bug this arm exists to prevent. Re-check
		// src.Done() (non-blocking; closed channels are always ready) before
		// deciding this is a genuine teardown.
		select {
		case <-src.Done():
			// Falls through to the success return below — every digit
			// actually reached the wire.
		default:
			// Genuine teardown before the source finished: the number of
			// digits actually sent is unknowable from here, so report none
			// and fail rather than guess — that would be a fabricated fact,
			// breaking this method's own "digits_sent is a fact" contract.
			// Free the slot so a subsequent op on a still-open call is not
			// wedged, exactly as Play does. B12: releaseOpFor(src), not the
			// bare releaseOp() — this is the exact stale-release race
			// releaseOpFor exists to close (see its doc comment).
			ml.releaseOpFor(src)
			return 0, 0, apierr.PreconditionFailed("dtmf_send: the call ended before the digits were sent")
		}
	case <-ctx.Done():
		// B13: the caller's ctx was cancelled while blocked waiting for the
		// tone source to exhaust. Same tie-break reasoning as the ml.done arm
		// above: a fully-successful send racing the caller's own
		// cancellation must not be reported as a failure.
		select {
		case <-src.Done():
			// Falls through to the success return below.
		default:
			// B12: releaseOpFor(src), not the bare releaseOp() — this arm has
			// the EXACT SAME stale-release hazard as the ml.done arm above:
			// src.Done() and ctx.Done() can both be ready near-simultaneously
			// (src exhausts and releases itself via onExhaust right as the
			// caller's ctx is cancelled), and if a NEW op had already claimed
			// the slot in that window, an unconditional releaseOp() here
			// would clobber it exactly like the ml.done arm's would.
			ml.releaseOpFor(src)
			return 0, 0, classifyCtxErr(ctx, "dtmf_send")
		}
	}
	// The SOURCE reports what it rendered, per digit — not the request. This is
	// the same fact-not-intention rule digits_sent obeys (§4).
	return len(digits), src.EmittedDurationMs(), nil
}

// sendDTMFRFC2833 sends the digits as RFC 4733 telephone-event packets on the
// NEGOTIATED payload type. It takes the loop's independent rtpEvent slot, NOT
// the media slot, so it coexists with an active play or record (§2.2).
//
// A dialog on which telephone-event was not negotiated is not_supported —
// never a silent fall back to inband tones (§10.8).
func (u *UA) sendDTMFRFC2833(ctx context.Context, ml *mediaLoop, sess *media.Session, digits string, durationMs, gapMs int) (int, int, error) {
	if sess == nil || sess.TelephoneEventPT == 0 {
		return 0, 0, apierr.NotSupported(
			"dtmf_send: telephone-event was not negotiated on this call; rfc2833 is unavailable")
	}
	if sess.TelephoneEventPT < 0 || sess.TelephoneEventPT > 127 {
		// A peer's SDP can produce a value outside the valid RTP payload-type
		// range (parseSDP's PT parsing accepts any int, negative included) —
		// converting that straight to uint8 below would silently wrap to some
		// other, wrong PT number rather than reject the malformed negotiation.
		return 0, 0, apierr.NotSupported(
			"dtmf_send: the negotiated telephone-event payload type is out of the valid RTP range (0-127); rfc2833 is unavailable")
	}
	// RFC 4733 2.5.1.1: restrict the events we send to the peer's events list.
	// The whole string is refused before anything is sent. A digit with no event
	// code is skipped here so newDTMFEventTX keeps its own error for it.
	for i := 0; i < len(digits); i++ {
		if code, ok := codec.DTMFEventCode(digits[i]); ok && !sess.PeerAcceptsEvent(code) {
			return 0, 0, apierr.InvalidArgument(fmt.Sprintf(
				"dtmf_send: digit %q (event %d) is outside the peer's telephone-event list (%s)",
				string(digits[i]), code, sess.PeerEventsText()))
		}
	}
	// onDone is nil here on purpose — the event's own finish() already releases
	// the claimed slot via the compare-and-clear hook claimEventTX installs at
	// claim time (see dtmfEventTX.release's doc comment), so there is nothing
	// left for a completion callback to do.
	ev, err := newDTMFEventTX(uint8(sess.TelephoneEventPT), digits, durationMs, gapMs, nil)
	if err != nil {
		return 0, 0, apierr.InvalidArgument("dtmf_send: " + err.Error())
	}
	if !ml.claimEventTX(ev) {
		return 0, 0, apierr.PreconditionFailed(
			"dtmf_send: an rfc2833 DTMF send is already active on this call")
	}
	select {
	case <-ev.Done():
	case <-ml.done:
		// TIE-BREAK: ev.Done() and ml.done can both become ready at nearly the
		// same moment — the last tick is consumed (closing ev.Done()) right as
		// the call tears down (closing ml.done) — and a select between two
		// ready channels picks one at random. If the event had in fact already
		// finished, that must NOT be reported as a failure: doing so would
		// fabricate a failure for a fully-successful send, the mirror image of
		// the bug this arm exists to prevent. Re-check ev.Done() (non-blocking;
		// closed channels are always ready) before deciding this is a genuine
		// teardown.
		select {
		case <-ev.Done():
			// Falls through to the success return below — every digit
			// actually reached the wire.
		default:
			// Genuine teardown before the event finished: the number of digits
			// actually sent is unknowable from here, so report none and fail
			// rather than guess — that would be a fabricated fact, breaking
			// this method's own "digits_sent is a fact" contract. Free the slot
			// so a subsequent op on a still-open call is not wedged, exactly as
			// the inband path does.
			ml.releaseEventTX(ev)
			return 0, 0, apierr.PreconditionFailed("dtmf_send: the call ended before the digits were sent")
		}
	case <-ctx.Done():
		// B13: the caller's ctx was cancelled while blocked waiting for the
		// event to finish. Same tie-break reasoning as the ml.done arm above.
		select {
		case <-ev.Done():
			// Falls through to the success return below.
		default:
			ml.releaseEventTX(ev)
			return 0, 0, classifyCtxErr(ctx, "dtmf_send")
		}
	}
	// The SENDER reports what it signalled, per digit — the same fact-not-intention
	// rule the inband path obeys, and the same rounding, so both RTP-path modes
	// answer identically for an identical request (§4).
	return len(digits), ev.EmittedDurationMs(), nil
}

// sendDTMFInfo sends ONE INFO per digit with an application/dtmf-relay body
// (decision 15), sleeping gapMs between them so duration_ms/gap_ms mean the same
// thing they do in the other two modes. It BLOCKS until the last INFO's final
// response, so digits_sent counts what the far end actually acknowledged.
//
// A non-2xx on any digit, or a cancelled ctx, stops the send. emittedDurationMs
// is ALWAYS the plain PER-DIGIT durationMs, on every return path — success or
// failure alike — matching the two RTP-path arms exactly and the spec's
// documented contract (design doc, "duration_ms is the EMITTED PER-DIGIT
// duration, not the requested one"): Task 16 reports this value straight
// through as dtmf_send's duration_ms, and an accumulated total there would be
// misread as "each digit played for N ms" when N is actually the TOTAL across
// however many digits landed. sent alone communicates how many digits
// succeeded; emittedDurationMs never also encodes that.
//
// Every ctx-driven return is a classifiable *apierr.Error via classifyCtxErr,
// never a bare ctx.Err()/context.Canceled — that includes the UA's own
// lifecycle ctx (u.uaCtx), not just the caller's, so the SAME kind of
// cancellation produces the SAME classifiable error regardless of which of the
// two contexts happened to fire it or at what point in the loop.
func (u *UA) sendDTMFInfo(ctx context.Context, d *dialog, digits string, durationMs, gapMs int) (int, int, error) {
	// F1: this arm used to carry its OWN single-flight claim here
	// (d.dtmfInfoInFlight) — the only one of the three arms with no other
	// serialisation, since it touches no media loop at all (§2.2) and so took
	// neither of the loop's own slots. That claim is now SendDTMF's
	// dialog-level dtmfSendInFlight (see its doc comment, call.go), claimed
	// once for every mode before the dispatch below is even reached, so this
	// arm needs no claim of its own any more.
	for i := 0; i < len(digits); i++ {
		// THE DIALOG IS RE-CHECKED PER DIGIT, NOT ONCE AT ENTRY. SendDTMF's
		// phaseAnswered gate runs before the first digit and this loop then
		// spends the whole send — up to gapMs per digit — outside it, so a
		// teardown landing mid-send was invisible here: at the time this was
		// measured, buildInDialogRequest only refused a dialog whose
		// d.invite was nil, and a terminated dialog kept its INVITE. CF-018
		// has since closed that gap (buildInDialogRequest now also refuses a
		// non-established dialog under the send-order token), but this
		// per-digit check remains the cheap early exit. Measured on the
		// session-timer watchdog path (the
		// peer holds the refresher role and stops refreshing, so our watchdog
		// BYEs the call at the full interval): the wire carried
		// INVITE, ACK, INFO, BYE, INFO — an in-dialog request issued AFTER our
		// own BYE — and SendDTMF returned sent=2, err=nil, reporting a
		// completed send on a call that no longer existed.
		//
		// Both RTP-path arms already refuse this, which is why only info
		// carried it: they are driven by the media loop, and every teardown
		// path stops that loop, so their in-flight send fails on its own
		// (TestSendDTMFInbandReturnsAnErrorWhenTheCallEndsMidSend and its
		// rfc2833 twin pin exactly that contract — "not a fabricated success
		// count"). §2.2 keeps info off the media loop deliberately, so it needs
		// its own check. precondition_failed matches what those two arms
		// return for the same situation.
		u.calls.mu.Lock()
		phase := d.phase
		u.calls.mu.Unlock()
		if phase != phaseAnswered {
			return i, durationMs, apierr.PreconditionFailed(fmt.Sprintf(
				"dtmf_send: the call ended before the digit at index %d could be sent", i))
		}
		digit := digits[i]
		req, res, err := u.sendInDialog(ctx, d, sip.INFO, func(req *sip.Request) {
			setDTMFInfoBody(req, digit, durationMs)
		})
		if err != nil {
			if ctx.Err() != nil {
				return i, durationMs, classifyCtxErr(ctx, "dtmf_send")
			}
			if req == nil {
				// Never built: buildInDialogRequest's own refusal, returned
				// unwrapped exactly as before the seam (plan D12).
				return i, durationMs, err
			}
			return i, durationMs, apierr.Internal("", "dtmf_send: INFO: "+err.Error())
		}
		if !res.IsSuccess() {
			// The digit itself is NEVER interpolated into the message: a DTMF
			// string routinely carries a PIN or a card number, and an error
			// naming the actual digit would leak it into an MCP error payload
			// and into logs. The digit's INDEX identifies which one failed
			// without that leak.
			msg := fmt.Sprintf("dtmf_send: INFO for digit at index %d was rejected: %d %s", i, res.StatusCode, res.Reason)
			switch res.StatusCode {
			case 405, 501, 415:
				// Matches the rfc2833 arm's convention: "the far end can't/won't
				// do this" is not_supported, reserving precondition_failed for
				// local state problems.
				return i, durationMs, apierr.NotSupported(msg)
			default:
				return i, durationMs, apierr.PreconditionFailed(msg)
			}
		}
		if gapMs > 0 && i+1 < len(digits) {
			// B-M1: nil-guarded exactly like waitForDigits' own `clk := u.cfg.Clock;
			// if clk == nil {...}` idiom — every other user of u.uaCtx/u.cfg.Clock
			// in this package reaches them only through a *UA built by New(), which
			// always sets both, but this arm (unlike waitForDigits) dereferenced
			// them directly with no such guard, so a *UA built any other way (e.g.
			// a whitebox test's bare &UA{} literal) SIGSEGVs here instead of
			// returning a clean error. Production behaviour is unchanged: New()
			// always sets both, so this fallback never fires outside a test.
			uaCtx := u.uaCtx
			if uaCtx == nil {
				uaCtx = context.Background()
			}
			clk := u.cfg.Clock
			if clk == nil {
				clk = clock.System()
			}
			select {
			case <-uaCtx.Done():
				return i + 1, durationMs, classifyCtxErr(uaCtx, "dtmf_send")
			case <-ctx.Done():
				return i + 1, durationMs, classifyCtxErr(ctx, "dtmf_send")
			case <-clk.After(time.Duration(gapMs) * time.Millisecond):
			}
		}
	}
	return len(digits), durationMs, nil
}

// classifyCtxErr wraps c.Err() (called only once c.Done() has fired, or a
// caller has already observed it non-nil) as a classifiable *apierr.Error —
// context.Canceled becomes apierr.Cancelled, matching the SAME mapping
// internal/transport/mcp/envelope.go applies for a client-cancelled MCP
// request; anything else (e.g. context.DeadlineExceeded) becomes
// apierr.Internal, which is still classifiable via apierr.CodeOf, unlike a
// bare context error, which apierr.CodeOf cannot classify at all.
//
// prefix names the calling operation ("dtmf_send", "media_play", ...) so this
// ONE classification funnel serves every ctx-cancellation return in the
// package (B13: Play gained a ctx.Done() arm alongside SendDTMF's three) with
// a message that still identifies which request was cancelled, rather than
// three copies of the context.Canceled/else-Internal mapping (Rule 16/18).
//
// DEFENSIVE: none of today's call sites can reach this with a live (nil-Err)
// ctx — each only calls it after Done()/Err()!=nil — but as the single funnel
// for this classification, a nil c.Err() (a future caller invoking it too
// early) must not nil-deref calling .Error() on it.
func classifyCtxErr(c context.Context, prefix string) error {
	ctxErr := c.Err()
	if ctxErr == nil {
		return apierr.Internal("", prefix+": classifyCtxErr called with a live (non-Done) ctx")
	}
	if errors.Is(ctxErr, context.Canceled) {
		return apierr.Cancelled(prefix + ": the request was cancelled")
	}
	return apierr.Internal("", prefix+": "+ctxErr.Error())
}

// setDTMFInfoBody gives an in-dialog INFO decision 15's application/dtmf-relay
// body. It is sendInDialog's prepare step for dtmf_send's info mode — the
// request itself (and its CSeq) comes from the seam (plan D12).
func setDTMFInfoBody(req *sip.Request, digit byte, durationMs int) {
	body := fmt.Sprintf("Signal=%c\r\nDuration=%d\r\n", digit, durationMs)
	req.SetBody([]byte(body))
	req.RemoveHeader("Content-Type")
	req.AppendHeader(sip.NewHeader("Content-Type", "application/dtmf-relay"))
}

// buildInDialogRequest builds an in-dialog request of the given method for an
// ANSWERED dialog, applying the SAME four corrections Hangup's BYE construction
// documents at length (call.go): the To/From orientation differs for a dialog
// we answered versus one we dialled; an inbound dialog's Request-URI must come
// from the peer's Contact, not from the received INVITE's own recipient; and the
// CSeq must exceed the answered INVITE's, which a digest-challenged INVITE
// pushes well above the vendored builder's hardcoded 2.
//
// It exists so INFO and (from Task 29) BYE share one derivation. Re-deriving
// them per method is precisely how a 481 Call/Transaction Does Not Exist gets
// shipped on one method and not the other.
//
// It MUST be called with d's send-order token held (sendInDialog, its only
// production caller, does): the CF-018 liveness check below orders against our own BYE
// only because that BYE needs the same token.
func (u *UA) buildInDialogRequest(d *dialog, method sip.RequestMethod) (*sip.Request, sip.Uri, error) {
	u.calls.mu.Lock()
	inv, ok, dir, refreshed := d.invite, d.ok, d.direction, d.remoteTarget
	// B-M8: the nil check comes BEFORE the CSeq increment below, not after —
	// a failed build (no dialog to build from) must not burn a sequence
	// number, or a later successful request on this dialog silently skips
	// one.
	if inv == nil {
		u.calls.mu.Unlock()
		return nil, sip.Uri{}, apierr.PreconditionFailed("call has no dialog")
	}
	// CF-018: refused HERE, under the send-order token sendInDialog holds for
	// every call to this builder, and BEFORE the CSeq is reserved. Every BYE this
	// UA sends first moves the dialog out of an established phase (phaseDone in
	// hangupWithReason; phaseMediaTeardown in runDial's ACK-then-BYE branch) and
	// only then needs that same token, so a non-BYE request that opens a new
	// transaction either has its first transmission on the wire before our BYE
	// or is refused — never after it. BYE is exempt precisely because its
	// senders have already left an established phase.
	if method != sip.BYE && !dialogEstablished(d.phase) {
		u.calls.mu.Unlock()
		return nil, sip.Uri{}, apierr.PreconditionFailed(fmt.Sprintf(
			"dialog ended before the %s could be sent", method))
	}
	// CF-086/105/108/171: addressing is decided before the CSeq is reserved, so a
	// refusal (a sips: dialog on a non-TLS UA) burns no number.
	target, routes := dialogRoute(dir, inv, ok, refreshed)
	transport, terr := inDialogTransport(u.Transport(), target, routes)
	if terr != nil {
		u.calls.mu.Unlock()
		return nil, sip.Uri{}, terr
	}
	nextCSeq := d.localCSeq
	d.localCSeq++
	u.calls.mu.Unlock()
	if ok == nil {
		// Inbound: the 200 OK we SENT is the To-tag source.
		ok = sip.NewResponseFromRequest(inv, 200, "OK", nil)
	}
	// BuildByeFromInvite already encodes the dialog-orientation rules; reuse it
	// and rewrite the method, rather than hand-rolling a second orientation.
	req := siptest.BuildByeFromInvite(inv, ok)
	req.Method = method
	// WIRE-VERIFIED FIX: BuildByeFromInvite clones the INVITE's Via header
	// WHOLESALE, branch included (siptest/builders.go). Left as-is, every
	// in-dialog request built here on the SAME dialog would carry the
	// IDENTICAL branch — and a non-INVITE transaction is matched by
	// branch|host|port|method (RFC 3261 §17.1.3), so a compliant peer
	// (including this UA's own onInfo below) treats request #2..#N as
	// RETRANSMISSIONS of #1 and absorbs them silently for Timer J's ~32s,
	// never actually delivering them, while digits_sent still reports all N
	// as sent. Removing the cloned Via here makes the transport layer mint a
	// FRESH branch per request when it dispatches (RawTransaction has no
	// options, so sipgo's clientRequestBuildReq adds one via
	// ClientRequestAddVia exactly as it does when Hangup's BYE already omits
	// a pre-set Via) — the same idiom sipgo's own digestTransactionRequest
	// uses (client.go: `req.RemoveHeader("Via")` before retrying).
	req.RemoveHeader("Via")
	// Contact is the SAME direction-blindness species as the From/To swap
	// below, one header over: BuildByeFromInvite also clones the dialog
	// INVITE's Contact (siptest/builders.go), and on a dialog we ANSWERED that
	// INVITE is the PEER's, so its Contact is the peer's own URI. Left as-is,
	// every in-dialog request built here on an inbound dialog asserts the peer
	// as OUR reachability — and a peer or proxy that refreshes its remote
	// target from it then addresses its next in-dialog request to itself.
	// Deriving it HERE rather than at each call site is the point of this
	// builder (Rule 18): refreshSession found this bug first and patched its
	// own request, which is exactly why INFO and BYE still shipped it.
	//
	// THE OVERRIDE IS SCOPED, AND EACH HALF OF THE SCOPE IS LOAD-BEARING.
	// u.localContact() is NOT the same value as the cloned Contact on an
	// OUTBOUND dialog, and both divergences were measured on the wire:
	//   - the user comes from aorUser(u.cfg.AOR), which DialRequest.FromUser
	//     (a public input; call.go's Dial overrides ecfg.FromUser from it)
	//     never reaches — INVITE <sip:charlie@…>, BYE <sip:alice@…>;
	//   - the host:port is the RFC 3581 LEARNED public address when one was
	//     learned, where the INVITE carried the BOUND one — INVITE
	//     <sip:alice@127.0.0.1:43472>, BYE <sip:alice@198.51.100.9:40000>.
	// So on an outbound dialog the clone is already OURS — it is precisely the
	// URI we advertised to this peer — and rewriting it would move the dialog's
	// advertised contact mid-dialog for a bug that exists only inbound. BYE and
	// INFO therefore inherit it, exactly as they did before this correction.
	//
	// UPDATE and re-INVITE are the exception in BOTH directions, because they
	// are TARGET-REFRESH requests (RFC 3261 §12.2.2 / RFC 3311 §5): their
	// Contact REPLACES the peer's remote target, so it must be the address we
	// actually want addressed — the learned public one when we have it. That is
	// the patch refreshSession used to apply at its own call site and dropped
	// once this builder took it over; keeping it here is what makes the drop
	// safe.
	//
	// FOUR methods reach this guard, not three: INFO and BYE (overridden only
	// inbound), UPDATE, and the re-INVITE refresh that refreshMethodFor falls
	// back to whenever the peer's Allow omits UPDATE (sessiontimer.go). The
	// inbound clause needs no special configuration to pin — there the cloned
	// Contact is the PEER's, so the two candidate values always differ — but
	// each METHOD clause does: on an outbound dialog they are the SAME STRING
	// under default configuration, so a test of one cannot fail whichever value
	// this emits unless it FIRST asserts a divergence vector is live. Do not
	// trust this paragraph — verify by mutation: deleting any ONE clause below
	// must turn `go test ./internal/sipua` red.
	if dir == session.Inbound || method == sip.UPDATE || method == sip.INVITE {
		req.RemoveHeader("Contact")
		req.AppendHeader(u.localContact())
	}
	// B-M8: no hardcoded CSeq:2 fallback — an unexpectedly nil CSeq on either
	// side is reported as an error instead of silently shipping the
	// vendored builder's placeholder value.
	// B-M8: no hardcoded CSeq:2 fallback — an unexpectedly nil CSeq on either
	// side is reported as an error instead of silently shipping the
	// vendored builder's placeholder value.
	okCSeq, reqCSeq := ok.CSeq(), req.CSeq()
	if okCSeq == nil || reqCSeq == nil {
		return nil, sip.Uri{}, apierr.Internal("", "buildInDialogRequest: CSeq header missing on the answered INVITE or the built request")
	}
	reqCSeq.SeqNo = okCSeq.SeqNo + nextCSeq
	reqCSeq.MethodName = method
	if dir == session.Inbound {
		if okTo, invFrom := ok.To(), inv.From(); okTo != nil && invFrom != nil {
			if reqFrom, reqTo := req.From(), req.To(); reqFrom != nil && reqTo != nil {
				// D19: sip.HeaderParams is a Go map (header_params.go) and
				// Address is a sip.Uri value carrying two MORE maps of its
				// own (UriParams, Headers — uri.go), so a direct field
				// assignment here aliases both this dialog's stored
				// d.ok/d.invite headers AND the new request two levels
				// deep. Clone() (HeaderParams.Clone, Uri.Clone) copies all
				// three maps so a later mutation of req's From/To can never
				// reach back into the dialog's own stored headers.
				reqFrom.DisplayName, reqFrom.Address, reqFrom.Params =
					okTo.DisplayName, *okTo.Address.Clone(), okTo.Params.Clone()
				reqTo.DisplayName, reqTo.Address, reqTo.Params =
					invFrom.DisplayName, *invFrom.Address.Clone(), invFrom.Params.Clone()
			}
		}
	}
	// RFC 3261 12.2.1.1 addressing (CF-105/086/108): remote target and route set,
	// loose or strict. The Via is stripped above, so the transport is stated
	// explicitly (CF-171); a strict first hop is also the destination, because
	// the fork would otherwise send to the first Route header.
	hop := addressInDialog(req, target, routes, transport)
	ensureSupportedTimer(req) // RFC 4028 7.1: every request except ACK (CF-113)
	return req, hop, nil
}

// onInfo answers an inbound in-dialog INFO. DTMF-over-INFO RECEPTION is NOT in
// this phase's scope (decision 3: detect covers the two RTP-path modes only), so
// the body is not parsed and no digit is reported — but a request that targets a
// KNOWN, answered dialog must still be acknowledged, because a peer whose INFO
// draws no response retransmits it for 32 s and some peers tear the dialog down.
//
// WIRE-VERIFIED FIX: an INFO naming a Call-ID this UA has no answered dialog
// for — unsolicited or misdirected — does NOT get an unconditional 200,
// mirroring onInvite's own targeting validation; it draws 481 Call/Transaction
// Does Not Exist instead (RFC 3261 §12.2.2's response for an in-dialog request
// matching no known dialog).
//
// B-M12 (D20, W2): ITS TEST LIVES IN sessiontimer_test.go, NOT dtmf_test.go —
// TestOnInfoAccepts481UnlessTheDialogIsAnsweredOrAnswering. That is where the
// in-dialog request fixtures already are, so the placement is deliberate; the
// missing pointer was the defect. Change onInfo's 481 conditions and that is the
// test that reddens.
func (u *UA) onInfo(req *sip.Request, tx sip.ServerTransaction) {
	u.calls.mu.Lock()
	d := u.findDialogForRequestLocked(req)
	// phaseAnswering is accepted ALONGSIDE phaseAnswered, the third and last of
	// the gates that carried this shape (onInvite's in-dialog branch and onUpdate
	// were widened first). runDial claims phaseAnswering before its ACK reaches
	// the wire and Answer holds it while its own 200 OK is being written, so an
	// INFO arriving in either window would otherwise draw a 481 — which RFC 3261
	// §12.2.1.2 makes TERMINAL to the dialog, the same hazard for a peer that
	// signals DTMF over INFO the instant a call is answered. The dialog is matched
	// by Call-ID and both tags (findDialogForRequestLocked, CF-130); a dialog so
	// matched in either answering window is a real dialog, and acknowledging its
	// INFO is strictly safer than tearing the call down.
	known := d != nil && (dialogEstablished(d.phase) || d.phase == phaseAnswering)
	ordered := known && remoteCSeqInOrderLocked(d, req) // CF-101
	u.calls.mu.Unlock()
	if !known {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
		return
	}
	if !ordered {
		respondOutOfOrder(req, tx)
		return
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
}
