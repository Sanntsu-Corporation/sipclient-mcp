// internal/sipua/dtmf_test.go
package sipua

import (
	"context"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

func TestDTMFEventTXRendersOneDigitPerRFC4733(t *testing.T) {
	// 40 ms tone => 2 tone ticks, + 3 end retransmits. No gap tick: this is a
	// SINGLE (and so also the LAST) digit, and B-M9 says the last digit gets
	// no trailing gap — there is no successor tone to separate it from.
	e, err := newDTMFEventTX(101, "5", 40, 20, nil)
	if err != nil {
		t.Fatalf("newDTMFEventTX: %v", err)
	}
	type got struct {
		code, volEnd  byte
		dur           uint16
		marker, newTS bool
		silent        bool
	}
	var seen []got
	for {
		payload, marker, newTS, ok := e.next()
		if !ok {
			break
		}
		if payload == nil {
			seen = append(seen, got{silent: true})
			continue
		}
		if len(payload) != 4 {
			t.Fatalf("payload len=%d want 4", len(payload))
		}
		seen = append(seen, got{
			code: payload[0], volEnd: payload[1],
			dur: binary.BigEndian.Uint16(payload[2:]), marker: marker, newTS: newTS,
		})
	}
	if len(seen) != 5 {
		t.Fatalf("%d ticks want 5 (2 tone + 3 end, no trailing gap on the last digit): %+v", len(seen), seen)
	}
	if seen[0].code != 5 || !seen[0].marker || !seen[0].newTS {
		t.Fatalf("first packet = %+v want code 5, marker, newTS", seen[0])
	}
	if seen[1].marker {
		t.Fatal("only the FIRST packet of an event carries the marker bit")
	}
	if seen[0].dur != 160 || seen[1].dur != 320 {
		t.Fatalf("durations %d,%d want 160,320 timestamp units", seen[0].dur, seen[1].dur)
	}
	for i := 0; i < 5; i++ {
		// B-M6 (D20, W2): AGAINST THE LITERAL 10, not against the constant. The old
		// form (`&0x3F != dtmfEventVolume`) was self-referential — it would pass for
		// any value the constant happened to hold, so the RFC 4733 volume the design
		// specifies was unpinned.
		if got := seen[i].volEnd & 0x3F; got != 10 {
			t.Errorf("telephone-event volume = %d, want 10 (RFC 4733 §2.5.1.3, the design's chosen level); "+
				"dtmfEventVolume = %d", got, dtmfEventVolume)
		}
		if seen[i].volEnd&0x40 != 0 {
			t.Fatalf("packet %d reserved (R) bit must stay 0, got byte %#x", i, seen[i].volEnd)
		}
	}
	for i := 0; i < 2; i++ {
		if seen[i].volEnd&0x80 != 0 {
			t.Fatalf("tone packet %d must NOT carry the E bit, got byte %#x", i, seen[i].volEnd)
		}
	}
	for i := 2; i < 5; i++ {
		if seen[i].volEnd&0x80 == 0 {
			t.Fatalf("packet %d must carry the E bit (RFC 4733 §2.5.1.4's 3 retransmits)", i)
		}
		if seen[i].dur != 320 {
			t.Fatalf("end packet %d duration=%d want the final 320", i, seen[i].dur)
		}
	}
}

func TestDTMFEventTXNewTSOnlyAtEachEventStart(t *testing.T) {
	e, err := newDTMFEventTX(101, "12", 20, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	var starts int
	for {
		_, _, newTS, ok := e.next()
		if !ok {
			break
		}
		if newTS {
			starts++
		}
	}
	if starts != 2 {
		t.Fatalf("%d event starts want 2 (one per digit)", starts)
	}
}

// TestDTMFEventTXTickCountMatchesTheNoTrailingGapFormula is B-M9's regression
// test for internal/sipua/dtmf.go's gapTicks loop: trailing gap ticks used to
// be appended after the FINAL digit too, inflating hold time on the loop's
// claimed-event slot for no signalling purpose. The pinned formula —
// len(ticks) == len(digits)*(toneTicks+3) + (len(digits)-1)*gapTicks — only
// holds once the last digit's gap is excluded.
func TestDTMFEventTXTickCountMatchesTheNoTrailingGapFormula(t *testing.T) {
	const digits = "123"
	const durationMs, gapMs = 40, 20 // toneTicks=2, gapTicks=1
	const toneTicks, gapTicks = 2, 1

	e, err := newDTMFEventTX(101, digits, durationMs, gapMs, nil)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		_, _, _, ok := e.next()
		if !ok {
			break
		}
		n++
	}
	want := len(digits)*(toneTicks+3) + (len(digits)-1)*gapTicks
	if n != want {
		t.Fatalf("tick count=%d want %d (len(digits)*(toneTicks+3) + (len(digits)-1)*gapTicks — "+
			"no gap after the LAST digit)", n, want)
	}
}

func TestDTMFEventTXFiresOnDoneOnceAndClosesDone(t *testing.T) {
	var fired int
	e, err := newDTMFEventTX(101, "1", 20, 0, func() { fired++ })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		e.next()
	}
	select {
	case <-e.Done():
	default:
		t.Fatal("Done() must be closed once every tick is consumed")
	}
	if fired != 1 {
		t.Fatalf("onDone fired %d times want 1", fired)
	}
}

func TestEventTXIsSingleFlightAndIndependentOfTheMediaSlot(t *testing.T) {
	ml := &mediaLoop{emit: func(session.UAEvent) {}}
	ml.assemble(nil, nil)
	// An active play must NOT block an rfc2833 send (§2.2).
	if !ml.claimOp(opPlay, nil) {
		t.Fatal("claimOp(opPlay)")
	}
	e1, _ := newDTMFEventTX(101, "1", 20, 0, nil)
	if !ml.claimEventTX(e1) {
		t.Fatal("rfc2833 must coexist with an active play")
	}
	e2, _ := newDTMFEventTX(101, "2", 20, 0, nil)
	if ml.claimEventTX(e2) {
		t.Fatal("two concurrent rfc2833 sends on one call must not both win")
	}
	ml.releaseEventTX(e1)
	if !ml.claimEventTX(e2) {
		t.Fatal("the event slot must be free after release")
	}
}

// TestReleaseEventTXIsCompareAndClear covers correction 2's fix: releasing a
// stale event pointer (one no longer installed in the slot, e.g. because a
// newer event already replaced it) must be a no-op, never clearing whatever
// event currently holds the slot. Without this, a delayed release from a
// finished event could clear a DIFFERENT, newer event's claim out from under
// it, hanging that newer event's Done() forever.
func TestReleaseEventTXIsCompareAndClear(t *testing.T) {
	ml := &mediaLoop{emit: func(session.UAEvent) {}}
	ml.assemble(nil, nil)
	e1, _ := newDTMFEventTX(101, "1", 20, 0, nil)
	if !ml.claimEventTX(e1) {
		t.Fatal("claimEventTX(e1)")
	}
	ml.releaseEventTX(e1)
	e2, _ := newDTMFEventTX(101, "2", 20, 0, nil)
	if !ml.claimEventTX(e2) {
		t.Fatal("claimEventTX(e2) after e1 released")
	}
	// A stale release of e1 (already superseded by e2) must not clear e2.
	ml.releaseEventTX(e1)
	if ml.eventTX() != e2 {
		t.Fatal("releasing a stale event pointer must not clear a newer claim")
	}
}

// TestDTMFEventTXFinishReleasesTheClaimedSlot covers correction 2's other
// half: the release must actually happen, driven from finish() (the same
// callback that closes Done()), not merely be safe to call redundantly.
func TestDTMFEventTXFinishReleasesTheClaimedSlot(t *testing.T) {
	ml := &mediaLoop{emit: func(session.UAEvent) {}}
	ml.assemble(nil, nil)
	e, _ := newDTMFEventTX(101, "1", 20, 0, nil)
	if !ml.claimEventTX(e) {
		t.Fatal("claimEventTX(e)")
	}
	for {
		_, _, _, ok := e.next()
		if !ok {
			break
		}
	}
	select {
	case <-e.Done():
	default:
		t.Fatal("Done() must be closed once every tick is consumed")
	}
	if ml.eventTX() != nil {
		t.Fatal("finish() must release the claimed slot, not just close Done()")
	}
}

func TestNewDTMFEventTXRejectsDurationOverWireSafeMax(t *testing.T) {
	if _, err := newDTMFEventTX(101, "1", dtmfMaxDurationMs, 0, nil); err != nil {
		t.Fatalf("newDTMFEventTX at the max (%d ms) must succeed: %v", dtmfMaxDurationMs, err)
	}
	if _, err := newDTMFEventTX(101, "1", dtmfMaxDurationMs+1, 0, nil); err == nil {
		t.Fatal("newDTMFEventTX must reject a duration_ms above the wire-safe max, not silently wrap the uint16 duration field")
	}
}

// dtmfHarness builds a UA with one answered dialog carrying a live mediaLoop
// whose goroutines are NOT started (frames are pulled by hand), mirroring
// playHarness in play_test.go.
func dtmfHarness(t *testing.T, mode string) (*UA, *dialog, *mediaLoop) {
	t.Helper()
	u := &UA{cfg: Config{DTMFMode: mode}}
	ml := &mediaLoop{emit: func(session.UAEvent) {}}
	ml.assemble(nil, nil)
	d := &dialog{id: "d1", callID: "call-abc", phase: phaseAnswered, mediaLoop: ml}
	u.register(d)
	return u, d, ml
}

// pumpTX drains the loop's TX source the way runTX would, so a BLOCKING
// SendDTMF(inband) can reach exhaustion in a harness whose goroutines were never
// started. SendDTMF(inband) waits on the source's Done() — that is what makes
// digits_sent a fact — so any test that calls it and expects a return needs
// this, exactly as Task 20's plan test does.
func pumpTX(t *testing.T, ml *mediaLoop) {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				ml.currentSrc().Frame()
				// Yield instead of busy-spinning: once the source is
				// exhausted, Frame() returns silence immediately forever, so
				// without this the goroutine burns a full core for the rest
				// of the test (this project's sandbox has only 4 CPUs — see
				// the -race contention note in project memory).
				runtime.Gosched()
			}
		}
	}()
}

func TestResolveDTMFTimingTreatsZeroGapAsNoGap(t *testing.T) {
	// The expectations name the SHARED constants rather than 100/50: a
	// hand-duplicated literal here is exactly the drift the shared resolver exists
	// to prevent, and would keep passing after the canonical default moved.
	cases := []struct {
		name             string
		dur, gap         int
		wantDur, wantGap int
	}{
		{"both given", 80, 40, 80, 40},
		{"explicit zero gap means NO gap", 80, 0, 80, 0},
		{"unset gap defaults", 80, dtmfGapUnset, 80, session.DefaultDTMFGapMs},
		{"unset duration defaults", 0, 20, session.DefaultDTMFDurationMs, 20},
		{"both unset", 0, dtmfGapUnset, session.DefaultDTMFDurationMs, session.DefaultDTMFGapMs},
		{"already-resolved values are unchanged (idempotent)",
			session.DefaultDTMFDurationMs, session.DefaultDTMFGapMs,
			session.DefaultDTMFDurationMs, session.DefaultDTMFGapMs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotDur, gotGap := resolveDTMFTiming(tc.dur, tc.gap)
			if gotDur != tc.wantDur || gotGap != tc.wantGap {
				t.Fatalf("resolveDTMFTiming(%d, %d) = %d, %d want %d, %d",
					tc.dur, tc.gap, gotDur, gotGap, tc.wantDur, tc.wantGap)
			}
		})
	}
}

// TestSipuaResolverDelegatesToTheSharedResolver is the other half of the
// anti-drift pin (its sibling is session's TestDTMFTimingDefaultsComeFromThe-
// SharedResolver). resolveDTMFTiming exists ONLY to adapt session's int64
// signature to SendDTMF's int arguments; it must hold no defaulting rule of its
// own, so its answer has to agree with the shared function over the whole domain
// — including the sentinel, which is why dtmfGapUnset is an alias rather than a
// second -1.
func TestSipuaResolverDelegatesToTheSharedResolver(t *testing.T) {
	if dtmfGapUnset != session.DTMFGapUnset {
		t.Fatalf("dtmfGapUnset=%d but session.DTMFGapUnset=%d — the sentinel must be "+
			"the SAME value, not a second copy of -1", dtmfGapUnset, session.DTMFGapUnset)
	}
	for _, dur := range []int{-5, 0, 1, 20, session.DefaultDTMFDurationMs, 5000} {
		for _, gap := range []int{dtmfGapUnset, -5, 0, 1, session.DefaultDTMFGapMs, 5000} {
			gotDur, gotGap := resolveDTMFTiming(dur, gap)
			wantDur, wantGap := session.ResolveDTMFTiming(int64(dur), int64(gap))
			if int64(gotDur) != wantDur || int64(gotGap) != wantGap {
				t.Fatalf("resolveDTMFTiming(%d, %d) = %d, %d but session.ResolveDTMFTiming "+
					"= %d, %d — sipua is applying its own defaults", dur, gap, gotDur, gotGap,
					wantDur, wantGap)
			}
		}
	}
}

func TestSendDTMFInbandInstallsAToneSourceAndReportsCount(t *testing.T) {
	u, _, ml := dtmfHarness(t, "inband")
	type result struct{ sent, emitted int }
	done := make(chan result, 1)
	go func() {
		sent, emitted, err := u.SendDTMF(context.Background(), "d1", "123", session.DTMFModeInband, 100, 50)
		if err != nil {
			t.Errorf("SendDTMF: %v", err)
		}
		done <- result{sent, emitted}
	}()

	// SendDTMF BLOCKS until the source exhausts, so the claim and the installed
	// source are only observable while the send is in flight.
	waitFor(t, func() bool { return ml.currentOp() == opDTMFInband })
	var energy int64
	for _, v := range ml.currentSrc().Frame() {
		energy += int64(v) * int64(v)
	}
	if energy == 0 {
		t.Fatal("SendDTMF(inband) did not install a tone source")
	}

	pumpTX(t, ml) // drain the remainder so the send completes
	res := <-done
	if res.sent != 3 {
		t.Fatalf("digits_sent=%d want 3", res.sent)
	}
	if res.emitted != 100 {
		t.Fatalf("emitted duration_ms=%d want 100 (already a whole number of 20ms ticks)", res.emitted)
	}
}

// TestSendDTMFInbandReportsTheEMITTEDDurationNotTheRequestedOne pins §4's
// "duration_ms is a fact" contract: 50 ms is not a whole number of 20 ms ticks,
// so codec.DTMFSource renders 60 ms of tone and 60 is what must be reported.
func TestSendDTMFInbandReportsTheEMITTEDDurationNotTheRequestedOne(t *testing.T) {
	u, _, ml := dtmfHarness(t, "inband")
	pumpTX(t, ml)
	sent, emitted, err := u.SendDTMF(context.Background(), "d1", "12", session.DTMFModeInband, 50, 0)
	if err != nil {
		t.Fatalf("SendDTMF: %v", err)
	}
	if sent != 2 {
		t.Fatalf("digits_sent=%d want 2", sent)
	}
	if emitted != 60 {
		t.Fatalf("emitted duration_ms=%d want 60 — a 50ms request is rounded UP to three "+
			"20ms ticks, and the report must be what went out, not what was asked for", emitted)
	}
}

// TestSendDTMFInbandHonoursAnExplicitZeroGap is a REWRITE of the brief's
// original version, which built its OWN separate codec.NewDTMFSource and
// asserted against THAT — never touching the source SendDTMF actually installs
// on the media loop. That version would keep passing even if SendDTMF silently
// ignored an explicit gap_ms=0 and substituted the default gap (verified: the
// bug was injected and the original test still passed). This version calls
// SendDTMF in a goroutine, waits for the opDTMFInband claim to land, and asserts
// on the ACTUALLY INSTALLED *codec.DTMFSource — a zero-gap two-digit send at 20ms
// tone renders exactly 40ms (2 x one 20ms frame), not 160ms (2 x (1 tone + 3
// default-gap frames)).
func TestSendDTMFInbandHonoursAnExplicitZeroGap(t *testing.T) {
	u, _, ml := dtmfHarness(t, "inband")
	type result struct {
		sent, emitted int
		err           error
	}
	done := make(chan result, 1)
	go func() {
		sent, emitted, err := u.SendDTMF(context.Background(), "d1", "12", session.DTMFModeInband, 20, 0)
		done <- result{sent, emitted, err}
	}()

	waitFor(t, func() bool { return ml.currentOp() == opDTMFInband })
	src, ok := ml.currentSrc().(*codec.DTMFSource)
	if !ok {
		t.Fatalf("SendDTMF(inband) installed a %T, not a *codec.DTMFSource", ml.currentSrc())
	}
	if src.DurationMs() != 40 {
		t.Fatalf("a zero-gap two-digit send renders %dms; gap_ms=0 must mean NO gap, never the "+
			"default 50ms", src.DurationMs())
	}

	pumpTX(t, ml) // drain the remainder so the send completes
	res := <-done
	if res.err != nil {
		t.Fatal(res.err)
	}
	if res.sent != 2 {
		t.Fatalf("digits_sent=%d want 2", res.sent)
	}
}

func TestSendDTMFInbandReleasesTheSlotOnExhaustion(t *testing.T) {
	u, _, ml := dtmfHarness(t, "inband")
	pumpTX(t, ml)
	if _, _, err := u.SendDTMF(context.Background(), "d1", "1", session.DTMFModeInband, 20, 0); err != nil {
		t.Fatal(err)
	}
	if ml.currentOp() != opNone {
		t.Fatal("the media slot must be released on exhaustion")
	}
}

func TestSendDTMFInbandRefusesADialogWithAnActivePlay(t *testing.T) {
	u, _, ml := dtmfHarness(t, "inband")
	if !ml.claimOp(opPlay, nil) {
		t.Fatal("claimOp")
	}
	_, _, err := u.SendDTMF(context.Background(), "d1", "1", session.DTMFModeInband, 100, 50)
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("code=%v want precondition_failed", apierr.CodeOf(err))
	}
}

func TestSendDTMFRejectsIllegalDigitsAndUnknownModes(t *testing.T) {
	u, _, _ := dtmfHarness(t, "inband")
	if _, _, err := u.SendDTMF(context.Background(), "d1", "12X", session.DTMFModeInband, 100, 50); apierr.CodeOf(err) != apierr.CodeInvalidArgument {
		t.Fatalf("illegal digit: code=%v want invalid_argument", apierr.CodeOf(err))
	}
	if _, _, err := u.SendDTMF(context.Background(), "d1", "1", session.DTMFMode("morse"), 100, 50); apierr.CodeOf(err) != apierr.CodeInvalidArgument {
		t.Fatalf("unknown mode: code=%v want invalid_argument", apierr.CodeOf(err))
	}
}

// TestSendDTMFUnknownModeDoesNotCorruptTheRecordedMode covers correction 2's
// fix: the brief's original code wrote d.dtmfMode BEFORE validating that mode
// was one of the three recognized values, so a rejected mode like "morse" was
// permanently recorded as the call's effective mode even though SendDTMF
// correctly returned invalid_argument (verified empirically). An unrecognized
// mode string must never be persisted.
func TestSendDTMFUnknownModeDoesNotCorruptTheRecordedMode(t *testing.T) {
	u, _, _ := dtmfHarness(t, "inband")
	if _, _, err := u.SendDTMF(context.Background(), "d1", "1", session.DTMFMode("morse"), 100, 50); apierr.CodeOf(err) != apierr.CodeInvalidArgument {
		t.Fatalf("code=%v want invalid_argument", apierr.CodeOf(err))
	}
	mode, ok := u.DTMFMode("d1")
	if !ok || mode != "inband" {
		t.Fatalf("mode=%q ok=%v want inband/true — a rejected mode string must never be "+
			"recorded as the call's effective mode (regression pin)", mode, ok)
	}
}

// TestSendDTMFRecordsAValidModeEvenWhenTheSendItselfIsRejected is the
// positive-coverage counterpart TestSendDTMFUnknownModeDoesNotCorruptTheRecordedMode
// needed but did not have: every other SendDTMF test names "inband" both as the
// requested mode and as cfg.DTMFMode's default, so a correctly-recorded
// "inband" was indistinguishable from dtmfModeDefault()'s fallback value —
// recordDTMFMode's three call sites had ZERO positive test coverage, and could
// be deleted outright without failing the suite (found in Task 13 review).
// rfc2833 is a genuinely different value from the harness's "inband" default,
// so this pins that a valid override IS recorded even when the send itself is
// rejected — here because this harness's dialog has no negotiated
// telephone-event payload type, so sendDTMFRFC2833 correctly reports
// not_supported.
func TestSendDTMFRecordsAValidModeEvenWhenTheSendItselfIsRejected(t *testing.T) {
	u, _, _ := dtmfHarness(t, "inband")
	_, _, err := u.SendDTMF(context.Background(), "d1", "1", session.DTMFModeRFC2833, 100, 50)
	if apierr.CodeOf(err) != apierr.CodeNotSupported {
		t.Fatalf("code=%v want not_supported (telephone-event was not negotiated on this dialog)", apierr.CodeOf(err))
	}
	mode, ok := u.DTMFMode("d1")
	if !ok || mode != "rfc2833" {
		t.Fatalf("mode=%q ok=%v want rfc2833/true — a valid override must be recorded even when "+
			"the send itself is rejected", mode, ok)
	}
}

// TestSendDTMFInbandReturnsAnErrorWhenTheCallEndsMidSend covers correction 3's
// fix: the brief's <-ml.done teardown-race arm released the slot but then fell
// through to returning len(digits) regardless of whether any audio had actually
// been sent (verified: tearing the call down before a single frame is pulled
// still reported all digits as "sent" with no error). SendDTMF's own doc comment
// promises digits_sent is a FACT, not an intention, so a teardown mid-send must
// report an honest failure instead.
func TestSendDTMFInbandReturnsAnErrorWhenTheCallEndsMidSend(t *testing.T) {
	u, _, ml := dtmfHarness(t, "inband")
	type result struct {
		sent, emitted int
		err           error
	}
	done := make(chan result, 1)
	go func() {
		sent, emitted, err := u.SendDTMF(context.Background(), "d1", "123", session.DTMFModeInband, 100, 50)
		done <- result{sent, emitted, err}
	}()

	// Tear the call down before a single frame is pulled — no audio is known to
	// have reached the wire.
	waitFor(t, func() bool { return ml.currentOp() == opDTMFInband })
	close(ml.done)

	res := <-done
	if res.err == nil {
		t.Fatal("SendDTMF must report an error when the call ends before the digits are sent, " +
			"not a fabricated success count")
	}
	if apierr.CodeOf(res.err) != apierr.CodePreconditionFailed {
		t.Fatalf("code=%v want precondition_failed", apierr.CodeOf(res.err))
	}
	if res.sent != 0 {
		t.Fatalf("digits_sent=%d want 0 — nothing is known to have reached the wire", res.sent)
	}
	if ml.currentOp() != opNone {
		t.Fatal("the media slot must be released when the call ends mid-send")
	}
}

// TestSendDTMFInbandCtxCancellationUnblocksAndFreesTheSlot is B13's inband
// mutation proof. Before the fix, sendDTMFInband's blocking select had no
// ctx.Done() arm at all: a caller cancelling mid-send had no effect, and the
// call stayed blocked until src.Done() (never — this test deliberately never
// drains the source via pumpTX) or ml.done (never — the loop is never
// stopped) — i.e. forever.
func TestSendDTMFInbandCtxCancellationUnblocksAndFreesTheSlot(t *testing.T) {
	u, _, ml := dtmfHarness(t, "inband")
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		sent, emitted int
		err           error
	}
	done := make(chan result, 1)
	go func() {
		sent, emitted, err := u.SendDTMF(ctx, "d1", "123", session.DTMFModeInband, 100, 50)
		done <- result{sent, emitted, err}
	}()

	waitFor(t, func() bool { return ml.currentOp() == opDTMFInband })
	cancel()

	select {
	case res := <-done:
		if apierr.CodeOf(res.err) != apierr.CodeCancelled {
			t.Fatalf("code=%v want cancelled", apierr.CodeOf(res.err))
		}
		if res.sent != 0 {
			t.Fatalf("digits_sent=%d want 0 — nothing is known to have reached the wire", res.sent)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendDTMF(inband) did not return within 2s of ctx cancellation — it is still " +
			"blocked on src.Done()/ml.done, neither of which this test ever triggers (B13)")
	}
	if ml.currentOp() != opNone {
		t.Fatal("the media slot must be free after a ctx-cancelled SendDTMF(inband)")
	}
	// The slot is PROVABLY free: a subsequent claim on the same loop succeeds.
	if !ml.claimOp(opDTMFInband, nil) {
		t.Fatal("claimOp after a ctx-cancelled SendDTMF(inband) should succeed — the slot must be provably free")
	}
}

// TestSendDTMFInbandCtxCancelReleaseIsInstanceScopedNotBareRelease is a Rule 9
// fix-round mutation proof (a fresh verifier subagent found this after
// B11/B13/B12 landed): sendDTMFInband's ctx.Done() arm called the bare,
// unconditional releaseOp() instead of the instance-scoped releaseOpFor(src)
// its OWN ml.done tie-break arm — and B12's whole point — already uses.
// DTMFSource.finish() calls onExhaust (which correctly releases via
// releaseOpFor) BEFORE closing Done(), so there is a real window where A's
// slot has already been freed and re-claimed by a newer op (B) by the time
// A's ctx.Done() arm actually runs — a bare releaseOp() there clobbers B's
// claim exactly like the ml.done arm's would have, pre-B12.
//
// Like the Play mirror of this test (play_test.go), A's own release is
// simulated directly via releaseOpFor rather than raced through the select:
// it frees the slot WITHOUT closing src.Done(), so A's own SendDTMF call
// stays parked in its select with only ctx.Done() live to fire once
// cancelled — deterministic, no race required.
func TestSendDTMFInbandCtxCancelReleaseIsInstanceScopedNotBareRelease(t *testing.T) {
	u, _, ml := dtmfHarness(t, "inband")
	ctxA, cancelA := context.WithCancel(context.Background())

	doneA := make(chan struct{})
	go func() {
		_, _, _ = u.SendDTMF(ctxA, "d1", "1", session.DTMFModeInband, 100, 50)
		close(doneA)
	}()
	waitFor(t, func() bool { return ml.currentOp() == opDTMFInband })
	srcA := ml.currentSrc()

	// Simulate A's onExhaust having ALREADY fired legitimately — the same
	// release call DTMFSource.finish() itself makes. A's src.Done() is
	// deliberately NOT closed here, so A's own SendDTMF goroutine stays
	// parked in its select.
	ml.releaseOpFor(srcA)
	if ml.currentOp() != opNone {
		t.Fatal("releaseOpFor(A) did not free the slot")
	}

	// A NEWER op (B) claims the now-free slot.
	srcB, err := codec.NewDTMFSource("2", 100, 50, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if !ml.claimOp(opDTMFInband, srcB) {
		t.Fatal("claimOp(B)")
	}

	// NOW cancel A's ORIGINAL ctx. A's select has only ctx.Done() ready
	// (src.Done() was never closed, ml.done was never closed), so this
	// deterministically drives A's ctx.Done() arm.
	cancelA()
	select {
	case <-doneA:
	case <-time.After(2 * time.Second):
		t.Fatal("SendDTMF(inband, A) did not return within 2s of its own ctx cancellation")
	}

	// B's claim MUST survive: A's now-stale release must be a no-op.
	if ml.currentOp() != opDTMFInband {
		t.Fatal("B's claim was cleared by A's stale ctx-cancellation release — sendDTMFInband's " +
			"ctx.Done() arm must use releaseOpFor(src), not the bare releaseOp()")
	}
	if ml.currentSrc() != codec.AudioSource(srcB) {
		t.Fatal("B's installed source was clobbered by A's stale ctx-cancellation release")
	}
}

// TestSendDTMFRFC2833CtxCancellationUnblocksAndFreesTheSlot is B13's rfc2833
// mirror of the inband test above: the same missing ctx.Done() arm, on the
// independent rtpEvent slot instead of the media op slot.
func TestSendDTMFRFC2833CtxCancellationUnblocksAndFreesTheSlot(t *testing.T) {
	u, d, ml := dtmfHarness(t, "rfc2833")
	u.calls.mu.Lock()
	d.mediaSession = &media.Session{Codec: "PCMU", TelephoneEventPT: 101}
	u.calls.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		sent, emitted int
		err           error
	}
	done := make(chan result, 1)
	go func() {
		sent, emitted, err := u.SendDTMF(ctx, "d1", "123", session.DTMFModeRFC2833, 100, 50)
		done <- result{sent, emitted, err}
	}()

	waitFor(t, func() bool { return ml.eventTX() != nil })
	cancel()

	select {
	case res := <-done:
		if apierr.CodeOf(res.err) != apierr.CodeCancelled {
			t.Fatalf("code=%v want cancelled", apierr.CodeOf(res.err))
		}
		if res.sent != 0 {
			t.Fatalf("digits_sent=%d want 0 — nothing is known to have reached the wire", res.sent)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendDTMF(rfc2833) did not return within 2s of ctx cancellation — it is still " +
			"blocked on ev.Done()/ml.done, neither of which this test ever triggers (B13)")
	}
	if ml.eventTX() != nil {
		t.Fatal("the event slot must be free after a ctx-cancelled SendDTMF(rfc2833)")
	}
	// The slot is PROVABLY free: a subsequent claim on the same loop succeeds.
	ev2, err := newDTMFEventTX(101, "9", 100, 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ml.claimEventTX(ev2) {
		t.Fatal("claimEventTX after a ctx-cancelled SendDTMF(rfc2833) should succeed — the slot must be provably free")
	}
}

func TestSendDTMFRefusesAnUnansweredCall(t *testing.T) {
	u := &UA{cfg: Config{DTMFMode: "inband"}}
	u.register(&dialog{id: "d1", phase: phaseRinging})
	_, _, err := u.SendDTMF(context.Background(), "d1", "1", session.DTMFModeInband, 100, 50)
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("code=%v want precondition_failed", apierr.CodeOf(err))
	}
}

func TestDTMFModeReportsTheEffectivePerCallMode(t *testing.T) {
	u, _, _ := dtmfHarness(t, "inband")
	mode, ok := u.DTMFMode("d1")
	if !ok || mode != "inband" {
		t.Fatalf("mode=%q ok=%v want inband/true", mode, ok)
	}
	if _, ok := u.DTMFMode("nope"); ok {
		t.Fatal("an unknown dialog must report ok=false")
	}
}

// TestSendDTMFInbandAcceptsDurationAtTheWireSafeMax covers correction 4's fix:
// unlike Task 12's rfc2833 sender (newDTMFEventTX, which already rejects
// anything over dtmfMaxDurationMs), the brief's inband arm as written had NO
// upper bound on duration_ms — codec.NewDTMFSource would pre-render an
// unbounded number of frames (verified: a 60s-per-digit, 20-digit request
// allocates ~22MB and blocks for 20 minutes uninterruptibly). Both modes must
// accept the same range of requests; the reject case is covered separately by
// TestSendDTMFInbandRejectsDurationAboveTheWireSafeMax.
func TestSendDTMFInbandAcceptsDurationAtTheWireSafeMax(t *testing.T) {
	u, _, ml := dtmfHarness(t, "inband")
	pumpTX(t, ml)
	if _, _, err := u.SendDTMF(context.Background(), "d1", "1", session.DTMFModeInband, dtmfMaxDurationMs, 0); err != nil {
		t.Fatalf("SendDTMF at the max (%d ms) must succeed: %v", dtmfMaxDurationMs, err)
	}
}

// TestSendDTMFInbandRejectsDurationAboveTheWireSafeMax runs SendDTMF with no
// pumpTX draining the source, so if the duration_ms cap ever regresses, the
// call reaches sendDTMFInband's blocking select with nothing to unblock it —
// exactly what was observed during Task 13 review's mutation test of this
// cap (the call hung for the full 10-minute go test timeout instead of
// failing). The bounded wait below turns that failure mode into a clear
// one-line diagnosis instead of a suite-wide hang.
func TestSendDTMFInbandRejectsDurationAboveTheWireSafeMax(t *testing.T) {
	u, _, _ := dtmfHarness(t, "inband")
	done := make(chan error, 1)
	go func() {
		_, _, err := u.SendDTMF(context.Background(), "d1", "1", session.DTMFModeInband, dtmfMaxDurationMs+1, 0)
		done <- err
	}()
	select {
	case err := <-done:
		if apierr.CodeOf(err) != apierr.CodeInvalidArgument {
			t.Fatalf("code=%v want invalid_argument for duration_ms above the wire-safe max", apierr.CodeOf(err))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SendDTMF did not return within 5s — the duration_ms cap has likely regressed, " +
			"leaving SendDTMF blocked in sendDTMFInband's select with nothing draining the source")
	}
}

func TestSendDTMFRFC2833IsNotSupportedWhenTelephoneEventWasNotNegotiated(t *testing.T) {
	u, d, _ := dtmfHarness(t, "rfc2833")
	u.calls.mu.Lock()
	d.mediaSession = &media.Session{Codec: "PCMU", TelephoneEventPT: 0}
	u.calls.mu.Unlock()
	_, _, err := u.SendDTMF(context.Background(), "d1", "1", session.DTMFModeRFC2833, 100, 50)
	if apierr.CodeOf(err) != apierr.CodeNotSupported {
		t.Fatalf("code=%v want not_supported — rfc2833 is REPORTED, never silently downgraded", apierr.CodeOf(err))
	}
}

// TestSendDTMFRFC2833RejectsAnOutOfRangePayloadType covers correction 6: a
// negotiated TelephoneEventPT outside the valid RTP payload-type range (0-127)
// must be rejected as not_supported, exactly like an unnegotiated (0) one — not
// silently truncated to some other, wrong PT number by the uint8 conversion.
// Both bounds are pinned: a peer's SDP can produce EITHER a too-high value
// (128) or a negative one (-1, e.g. via parseSDP's strconv.Atoi-based PT
// parsing, which accepts negative numbers) — a guard that only rejected one
// side would still let uint8(-1) silently wrap to 255 on the wire, which is
// exactly what a task-review pass caught here (verified: `TelephoneEventPT ==
// 0 || > 127` alone let -1 straight through).
func TestSendDTMFRFC2833RejectsAnOutOfRangePayloadType(t *testing.T) {
	for _, pt := range []int{128, -1} {
		t.Run(fmt.Sprintf("pt=%d", pt), func(t *testing.T) {
			u, d, _ := dtmfHarness(t, "rfc2833")
			u.calls.mu.Lock()
			d.mediaSession = &media.Session{Codec: "PCMU", TelephoneEventPT: pt}
			u.calls.mu.Unlock()
			_, _, err := u.SendDTMF(context.Background(), "d1", "1", session.DTMFModeRFC2833, 100, 50)
			if apierr.CodeOf(err) != apierr.CodeNotSupported {
				t.Fatalf("code=%v want not_supported — an out-of-range payload type must never be silently truncated", apierr.CodeOf(err))
			}
		})
	}
}

func TestSendDTMFRFC2833CoexistsWithAnActivePlay(t *testing.T) {
	u, d, ml := dtmfHarness(t, "rfc2833")
	u.calls.mu.Lock()
	d.mediaSession = &media.Session{Codec: "PCMU", TelephoneEventPT: 101}
	u.calls.mu.Unlock()
	if !ml.claimOp(opPlay, nil) {
		t.Fatal("claimOp(opPlay)")
	}

	type result struct{ sent, emitted int }
	done := make(chan result, 1)
	go func() {
		sent, emitted, err := u.SendDTMF(context.Background(), "d1", "12", session.DTMFModeRFC2833, 40, 20)
		if err != nil {
			t.Errorf("SendDTMF(rfc2833): %v", err)
		}
		done <- result{sent, emitted}
	}()

	// Drive the sender the way runTX would: pull every tick. The event
	// self-releases via its finish() hook when it completes (Task 12's
	// claimEventTX compare-and-clear release), so this loop does NOT call
	// releaseEventTX itself.
	deadline := time.After(5 * time.Second)
	for {
		if ev := ml.eventTX(); ev != nil {
			ev.next()
		}
		select {
		case res := <-done:
			if res.sent != 2 {
				t.Fatalf("digits_sent=%d want 2", res.sent)
			}
			// 40ms is two whole ticks, so the emitted per-digit duration is the
			// requested one here — the rounding case is covered by
			// TestSendDTMFRFC2833ReportsTheEMITTEDDuration below.
			if res.emitted != 40 {
				t.Fatalf("emitted duration_ms=%d want 40", res.emitted)
			}
			if ml.currentOp() != opPlay {
				t.Fatal("an rfc2833 send must NOT touch the media slot (§2.2)")
			}
			return
		case <-deadline:
			t.Fatal("SendDTMF(rfc2833) never returned")
		default:
			// B-M11 (D20, W2): YIELD. A bare default: here spins the scheduler
			// flat out for up to this test's 5 s deadline, burning a whole core
			// — which on this 4-core sandbox is enough to make CONCURRENT tests
			// miss their own short deadlines. pumpTX in this package already
			// learned this; these two had not.
			runtime.Gosched()
		}
	}
}

// TestSendDTMFRFC2833ReportsTheEMITTEDDuration is the rfc2833 half of §4's
// "duration_ms is a fact" contract. newDTMFEventTX rounds each digit up to whole
// 20 ms ticks exactly as codec.DTMFSource does, so a 50 ms request emits 60 ms —
// and reports 60, not 50.
func TestSendDTMFRFC2833ReportsTheEMITTEDDuration(t *testing.T) {
	u, d, ml := dtmfHarness(t, "rfc2833")
	u.calls.mu.Lock()
	d.mediaSession = &media.Session{Codec: "PCMU", TelephoneEventPT: 101}
	u.calls.mu.Unlock()

	type result struct{ sent, emitted int }
	done := make(chan result, 1)
	go func() {
		sent, emitted, err := u.SendDTMF(context.Background(), "d1", "1", session.DTMFModeRFC2833, 50, 0)
		if err != nil {
			t.Errorf("SendDTMF(rfc2833): %v", err)
		}
		done <- result{sent, emitted}
	}()
	deadline := time.After(5 * time.Second)
	for {
		if ev := ml.eventTX(); ev != nil {
			ev.next()
		}
		select {
		case res := <-done:
			if res.emitted != 60 {
				t.Fatalf("emitted duration_ms=%d want 60 (three 20ms ticks for a 50ms request)",
					res.emitted)
			}
			return
		case <-deadline:
			t.Fatal("SendDTMF(rfc2833) never returned")
		default:
			// B-M11 (D20, W2): YIELD. A bare default: here spins the scheduler
			// flat out for up to this test's 5 s deadline, burning a whole core
			// — which on this 4-core sandbox is enough to make CONCURRENT tests
			// miss their own short deadlines. pumpTX in this package already
			// learned this; these two had not.
			runtime.Gosched()
		}
	}
}

func TestSendDTMFRFC2833SecondConcurrentSendIsPreconditionFailed(t *testing.T) {
	u, d, ml := dtmfHarness(t, "rfc2833")
	u.calls.mu.Lock()
	d.mediaSession = &media.Session{Codec: "PCMU", TelephoneEventPT: 101}
	u.calls.mu.Unlock()
	first, _ := newDTMFEventTX(101, "9", 100, 50, nil)
	if !ml.claimEventTX(first) {
		t.Fatal("claimEventTX")
	}
	_, _, err := u.SendDTMF(context.Background(), "d1", "1", session.DTMFModeRFC2833, 100, 50)
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("code=%v want precondition_failed", apierr.CodeOf(err))
	}
}

// TestSendDTMFRFC2833ReturnsAnErrorWhenTheCallEndsMidSend is the rfc2833
// mirror of TestSendDTMFInbandReturnsAnErrorWhenTheCallEndsMidSend, covering
// corrections 2 and 3's fix: the brief's <-ml.done teardown arm released the
// event slot but then fell through to reporting len(digits) regardless of
// whether a single tick had actually gone out (verified: tearing the call down
// before any tick is consumed still reported all digits as "sent" with no
// error). SendDTMF's own doc comment promises digits_sent is a FACT, not an
// intention, so a teardown mid-send must report an honest failure instead —
// and the event slot must end up clear so a subsequent send on a still-open
// call is not wedged.
func TestSendDTMFRFC2833ReturnsAnErrorWhenTheCallEndsMidSend(t *testing.T) {
	u, d, ml := dtmfHarness(t, "rfc2833")
	u.calls.mu.Lock()
	d.mediaSession = &media.Session{Codec: "PCMU", TelephoneEventPT: 101}
	u.calls.mu.Unlock()

	type result struct {
		sent, emitted int
		err           error
	}
	done := make(chan result, 1)
	go func() {
		sent, emitted, err := u.SendDTMF(context.Background(), "d1", "123", session.DTMFModeRFC2833, 100, 50)
		done <- result{sent, emitted, err}
	}()

	// Tear the call down before a single tick is consumed — no packet is known
	// to have reached the wire.
	waitFor(t, func() bool { return ml.eventTX() != nil })
	close(ml.done)

	res := <-done
	if res.err == nil {
		t.Fatal("SendDTMF must report an error when the call ends before the digits are sent, " +
			"not a fabricated success count")
	}
	if apierr.CodeOf(res.err) != apierr.CodePreconditionFailed {
		t.Fatalf("code=%v want precondition_failed", apierr.CodeOf(res.err))
	}
	if res.sent != 0 {
		t.Fatalf("digits_sent=%d want 0 — nothing is known to have reached the wire", res.sent)
	}
	if res.emitted != 0 {
		t.Fatalf("emitted duration_ms=%d want 0 — nothing is known to have reached the wire", res.emitted)
	}
	if ml.eventTX() != nil {
		t.Fatal("the event slot must be released when the call ends mid-send")
	}
}

// TestSendDTMFInbandAndRFC2833AreMutuallyExclusive is F1's inband∥rfc2833
// cross-mode pair — the actual corruption scenario the bug describes.
// Before F1, inband was single-flighted only against itself
// (claimOp(opDTMFInband)) and rfc2833 only against itself (claimEventTX,
// deliberately independent of st.op per medialoop.go's own doc comment), so
// nothing excluded the TWO of them from running concurrently on the same
// dialog — letting an rfc2833 event steal a tick out from under an inband
// DTMFSource's continuous-phase assumption (medialoop.go's runTX skips
// pulling currentSrc().Frame() whenever an event is active, RFC 4733
// §2.5.2.2). SendDTMF's dialog-level dtmfSendInFlight claim closes that at
// the dispatch level.
func TestSendDTMFInbandAndRFC2833AreMutuallyExclusive(t *testing.T) {
	u, d, ml := dtmfHarness(t, "inband")
	u.calls.mu.Lock()
	d.mediaSession = &media.Session{Codec: "PCMU", TelephoneEventPT: 101}
	u.calls.mu.Unlock()

	type result struct {
		sent int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		sent, _, err := u.SendDTMF(context.Background(), "d1", "12", session.DTMFModeInband, 100, 50)
		done <- result{sent, err}
	}()
	waitFor(t, func() bool { return ml.currentOp() == opDTMFInband })

	if _, _, err := u.SendDTMF(context.Background(), "d1", "9", session.DTMFModeRFC2833, 100, 0); apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("rfc2833 concurrent with an in-flight inband send: code=%v want precondition_failed", apierr.CodeOf(err))
	}

	pumpTX(t, ml) // drain the remainder so the inband send completes
	first := <-done
	if first.err != nil || first.sent != 2 {
		t.Fatalf("inband send = %+v, want sent=2 err=nil", first)
	}

	// Once inband has released the dialog-level claim, rfc2833 must succeed.
	done2 := make(chan result, 1)
	go func() {
		sent, _, err := u.SendDTMF(context.Background(), "d1", "5", session.DTMFModeRFC2833, 40, 0)
		done2 <- result{sent, err}
	}()
	deadline := time.After(5 * time.Second)
	for {
		if ev := ml.eventTX(); ev != nil {
			ev.next()
		}
		select {
		case r := <-done2:
			if r.err != nil || r.sent != 1 {
				t.Fatalf("rfc2833 after inband released the claim = %+v, want sent=1 err=nil", r)
			}
			return
		case <-deadline:
			t.Fatal("rfc2833 send never returned after inband released the claim")
		default:
			// B-M11 (D20, W2): YIELD, same defect as the other two bare
			// default: loops in this file (the row's triage cited two; this
			// third instance has the identical shape and was found during
			// re-verification, so it is fixed here too rather than left
			// burning a core for no principled reason).
			runtime.Gosched()
		}
	}
}

// sessionWithPeerEvents sets the dialog's negotiated media session to PCMU with
// telephone-event 101 and the given peer events list (nil = absent).
func sessionWithPeerEvents(u *UA, d *dialog, events map[uint8]bool) {
	u.calls.mu.Lock()
	d.mediaSession = &media.Session{Codec: "PCMU", TelephoneEventPT: 101, PeerEvents: events}
	u.calls.mu.Unlock()
}

func peerList(lo, hi uint8) map[uint8]bool {
	m := map[uint8]bool{}
	for c := lo; c <= hi; c++ {
		m[c] = true
	}
	return m
}

func TestSendDTMFInvalidDigitKeepsItsExistingError(t *testing.T) {
	u, d, _ := dtmfHarness(t, "rfc2833")
	sessionWithPeerEvents(u, d, peerList(0, 9))
	_, _, err := u.SendDTMF(context.Background(), "d1", "1x", session.DTMFModeRFC2833, 100, 0)
	if apierr.CodeOf(err) != apierr.CodeInvalidArgument || !strings.Contains(err.Error(), "must be non-empty and drawn from") {
		t.Fatalf("err = %v, want newDTMFEventTX's invalid_argument wording", err)
	}
}

func TestSendDTMFRefusesAMultiDigitStringWithAnExcludedEventBeforeSending(t *testing.T) {
	u, d, ml := dtmfHarness(t, "rfc2833")
	sessionWithPeerEvents(u, d, peerList(0, 9))
	_, _, err := u.SendDTMF(context.Background(), "d1", "12#", session.DTMFModeRFC2833, 100, 0)
	if apierr.CodeOf(err) != apierr.CodeInvalidArgument || !strings.Contains(err.Error(), `"#"`) || !strings.Contains(err.Error(), "event 11") ||
		!strings.Contains(err.Error(), "0-9") {
		t.Fatalf("err = %v, want invalid_argument naming # / event 11 / the list 0-9", err)
	}
	if ml.eventTX() != nil {
		t.Fatal("the event slot was claimed although the string was refused")
	}
}

func TestSendDTMFOnACallThatDoesNotSendIsPreconditionFailed(t *testing.T) {
	for _, mode := range []string{"rfc2833", "inband"} {
		t.Run(mode, func(t *testing.T) {
			u, d, ml := dtmfHarness(t, mode)
			sessionWithPeerEvents(u, d, nil)
			ml.txOff = true
			dm := session.DTMFModeRFC2833
			if mode == "inband" {
				dm = session.DTMFModeInband
			}
			_, _, err := u.SendDTMF(context.Background(), "d1", "1", dm, 100, 0)
			if apierr.CodeOf(err) != apierr.CodePreconditionFailed || !strings.Contains(err.Error(), "does not send") {
				t.Fatalf("err = %v, want precondition_failed (does not send)", err)
			}
		})
	}
	t.Run("info is not refused by txOff", func(t *testing.T) {
		u, d, ml := dtmfHarness(t, "info")
		sessionWithPeerEvents(u, d, nil)
		ml.txOff = true
		_, _, err := u.SendDTMF(context.Background(), "d1", "1", session.DTMFModeInfo, 100, 0)
		if err != nil && strings.Contains(err.Error(), "does not send") {
			t.Fatalf("info mode refused by the txOff check: %v", err)
		}
	})
}
