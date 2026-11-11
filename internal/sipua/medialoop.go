package sipua

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/pion/rtp"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/quality"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// mediaLoop owns a single answered call's RTP: a TX ticker goroutine and an RX
// read-plus-playout goroutine over the one dialog UDP socket. internal/media and
// its subpackages stay pure; this is where the sockets and goroutines live
// (§3.1). The accumulator carries its own lock, the jitter buffer is
// single-affine to runRX, and dest is guarded by destMu. The RX
// goroutine MAY take u.calls.mu — onDigit's call to UA.handleDigit takes it
// via u.emit when reporting a detected digit, and again (separately) to read
// d.dtmfWaiter before offering the digit to a parked wait_dtmf waiter, with
// offer itself called outside that lock — but must NEVER take it while
// already holding ml.st.mu — lock order is always u.calls.mu -> ml.st.mu,
// never the reverse.
type mediaLoop struct {
	conn        *net.UDPConn
	codecName   string
	payloadType uint8
	transform   media.FrameTransform
	jb          *media.JitterBuffer
	plc         *media.PLC
	acc         *quality.Accumulator
	// st is the per-call media state machine (§2.2): the single exclusion slot,
	// the TX source, the RX recorder tap and the terminal stopped flag, all
	// under one mutex. It replaces W5's four independent atomics.
	st   mediaState
	ssrc uint32
	// C-M5 (D20, W2): the fourth test-only seam. See call.go's block above
	// ringBudgetOverride for the invariant these four share (no t.Parallel() under
	// internal/sipua) and parallel_invariant_test.go, which enforces it.
	//
	// seq0 is the RTP sequence number runTX starts from. assemble() randomises
	// it like ssrc; the field exists so a test can seed a value close to the
	// uint16 wrap boundary without waiting ~22 minutes for a random start to
	// reach it (R8, Task 33). No caller sets it outside tests.
	seq0           uint16
	jitterBufferMS int
	logger         *slog.Logger
	// clock is the time source runRX's playout drain loop reads instead of
	// calling time.Now() directly (Task 9), so a test can inject an
	// accelerated fake clock. Defaults to media.RealClock{} in assemble().
	clock media.Clock
	// writeTo is the datagram write runTX uses. Defaulted to conn.WriteToUDP in
	// assemble() (the clock/logger pattern); a test substitutes it to inject
	// send errors.
	writeTo func([]byte, *net.UDPAddr) (int, error)

	// detector is the inband DTMF Goertzel tap, fed every decoded RX frame. It
	// is nil unless the profile selected dtmf_mode: inband (see
	// UA.inbandDetectionEnabled): running Goertzel on every frame of every call
	// would spend CPU no other mode needs and expose every call to talk-off for
	// no benefit. It is SINGLE-GOROUTINE-AFFINE to runRX, like jb and plc, and
	// carries no lock.
	detector *codec.DTMFDetector

	// recvPTs maps every audio payload type we accept to its codec (RFC 3264
	// 5.1: an offerer must receive every answered codec at either side's
	// number); defaulted in assemble() to {payloadType: codecName}. Immutable
	// after launch().
	recvPTs map[uint8]string
	// txOff stops runTX writing audio or events: the negotiated direction does
	// not send, or the peer rejected the stream or gave an unspecified address
	// (RFC 3264 6, 8.4). Immutable after launch().
	txOff bool

	// recvEventPTs holds the NEGOTIATED RFC 4733 telephone-event payload types
	// we accept, empty when telephone-event was not negotiated. Unlike the inband detector this tap is
	// UNCONDITIONAL when the type was negotiated: it costs one payload-type
	// comparison per packet, and a peer that negotiated telephone-event will send
	// it whether or not our own dtmf_mode is rfc2833.
	recvEventPTs map[uint8]bool

	// rxEvent is the telephone-event reassembly state: which digit is in
	// progress and whether it has been reported. SINGLE-GOROUTINE-AFFINE to
	// runRX, like detector.
	rxEvent rxEventState

	// onDigit receives every detected digit, from either detection mode, and is
	// the ONE funnel §2.2 describes: startMediaLoop wires it to
	// UA.handleDigit, which emits UAEventDTMF (via u.emit, which is where it
	// takes u.calls.mu — see the struct's own doc comment above) and then
	// offers the digit to a parked wait_dtmf waiter, if d.dtmfWaiter is set. It
	// is a closure rather than a *dialog method because mediaLoop deliberately
	// holds no *dialog and no *UA. nil disables both taps' reporting (unit
	// harnesses that only exercise the audio path).
	onDigit func(digit byte, mode string, durationMs int)

	// eventTS is the RTP timestamp latched at the start of the current
	// telephone-event (RFC 4733: every packet of one event carries the event's
	// START timestamp while its duration field grows). TOUCHED ONLY BY runTX,
	// which is why it lives here and not in the mutex-guarded state block.
	eventTS uint32

	destMu sync.Mutex
	// dest is the signalled address for the whole call (RFC 3550 11: a source
	// port is never assumed to be a destination port). It is also the only
	// source RX accepts (CF-179); any other source is rogue.
	dest *net.UDPAddr

	// emit + identity for the media_start event and tx_underrun error event.
	emit      func(session.UAEvent)
	dialogID  string
	callID    string
	direction session.Direction

	done     chan struct{}
	wg       sync.WaitGroup
	stopOnce sync.Once
}

// mediaOp names which single exclusive TX/RX media operation a call is running.
// It replaces W5's `busy atomic.Bool` with an explicit state (§2.2): the slot
// now says WHAT is running, not merely that something is, which is what lets
// the DTMF paths report a precise precondition_failed and lets stop()'s
// finalize reason about an in-flight RecordStart without a 12-line comment.
type mediaOp uint8

const (
	opNone mediaOp = iota
	opPlay
	opRecord
	opDTMFInband
)

// mediaState is the ONE mutex-guarded block replacing W5's four independent
// atomics (src, rec, busy, stopped), each of which was a retrofit for a race
// found after the fact (§2.2). The TX ticker takes this lock once per 20 ms
// tick, which is free at that rate.
//
// EVERY FIELD IS GUARDED BY mu, AND EVERY TRANSITION HAPPENS UNDER IT, once
// the loop is running — the check and the act are never separated (§6.3). The
// pre-launch initialization in assemble/startMediaLoop writes ml.st.src
// directly, without taking mu: both run single-goroutine, before launch()
// starts the TX/RX goroutines that are the only other readers/writers, so no
// lock is needed there. `stopped` is terminal and absorbing: once set, every
// claim fails forever.
type mediaState struct {
	mu      sync.Mutex
	op      mediaOp            // the single exclusion slot (W5 semantics preserved)
	src     codec.AudioSource  // active TX source
	prior   codec.AudioSource  // restored when op returns to opNone
	rec     *codec.WAVRecorder // RX tap, non-nil iff a recording is installed
	stopped bool

	// rtpEvent is the RFC 2833/4733 telephone-event sender, and it is
	// DELIBERATELY INDEPENDENT OF `op` (spec §2.2, §7): telephone-event packets
	// ride their own payload type and RFC 4733 permits them alongside audio, so
	// dtmf_send(mode="rfc2833") succeeds during an active play or record. It is
	// single-flight against ITSELF — two concurrent rfc2833 sends on one call
	// resolve to one winner and one precondition_failed.
	rtpEvent *dtmfEventTX
}

// claimOp claims the single play-or-record-or-inband-DTMF slot and, when src is
// non-nil, installs it as the TX source (saving the prior one for releaseOp).
// It returns false when another op holds the slot or the loop has stopped —
// which every caller turns into precondition_failed, unchanged from W5.
//
// Deliberate narrowing versus pre-Task-7 behavior, though not for the reason
// a bare reading suggests: old claimMediaOp had NO stopped check of any kind
// — a claim on an already-obtained ml always succeeded whenever busy was
// free, with no regard to whether stop() had already run on it. What bounded
// this in practice was reached through the DIALOG, not the claim: Play/
// RecordStart look up ml via d.mediaLoop under u.calls.mu, and every teardown
// path nils d.mediaLoop under that same lock before calling stop(), so a call
// that looks the dialog up AFTER teardown sees ml == nil and never reaches
// claimMediaOp at all. The actual gap was a goroutine that already held a
// reference to ml (obtained before teardown nil'd d.mediaLoop) calling
// claimMediaOp after stop() had completed on it — claimMediaOp would still
// let that through. claimOp closes this directly at the claim itself,
// independent of whatever the caller's dialog lookup did or didn't observe.
func (ml *mediaLoop) claimOp(op mediaOp, src codec.AudioSource) bool {
	ml.st.mu.Lock()
	defer ml.st.mu.Unlock()
	if ml.st.stopped || ml.st.op != opNone {
		return false
	}
	ml.st.op = op
	if src != nil {
		ml.st.prior, ml.st.src = ml.st.src, src
	}
	return true
}

// releaseOp returns the slot to opNone and restores the source that was active
// before the claim. It is idempotent: releasing an already-free slot restores
// nothing and is not an error (Play's mid-play teardown path relies on this).
func (ml *mediaLoop) releaseOp() {
	ml.st.mu.Lock()
	defer ml.st.mu.Unlock()
	if ml.st.op == opNone {
		return
	}
	ml.st.op = opNone
	if ml.st.prior != nil {
		ml.st.src, ml.st.prior = ml.st.prior, nil
	}
}

// releaseOpFor is releaseOp's instance-scoped, compare-and-clear counterpart
// (B12): it releases the slot ONLY if it is still claimed for src specifically,
// a no-op otherwise. It exists for a source's OWN release hook (a
// PromptSource's or DTMFSource's onExhaust, and the ml.done teardown arm that
// backs it up), where an unconditional releaseOp() has a stale-release hazard
// releaseEventTX already avoids for the independent event slot: source A
// finishes and releases (op -> opNone, prior restored); a NEW claim for source
// B lands in the same slot; A's release hook fires a SECOND time (the
// ml.done/ctx.Done() tie-break arm racing A's own onExhaust) and, with a bare
// releaseOp(), would clobber B's claim out from under it. Scoping the release
// to the specific source it was claimed for makes a stale second release a
// safe no-op instead.
//
// This is deliberately NOT an ordering reversal (release-after-close instead
// of release-before-close): closing release-before-close would let a caller
// doing two sequential Plays hit a spurious precondition_failed if the second
// claim races the first release. releaseOp() itself is untouched and stays
// the record path's release (claimOp(opRecord, nil) installs no source, so
// there is nothing to compare against there).
func (ml *mediaLoop) releaseOpFor(src codec.AudioSource) {
	ml.st.mu.Lock()
	defer ml.st.mu.Unlock()
	if ml.st.src != src {
		return
	}
	ml.st.op = opNone
	if ml.st.prior != nil {
		ml.st.src, ml.st.prior = ml.st.prior, nil
	}
}

// currentSrc is the TX source runTX pulls a frame from each tick.
func (ml *mediaLoop) currentSrc() codec.AudioSource {
	ml.st.mu.Lock()
	defer ml.st.mu.Unlock()
	return ml.st.src
}

// installRecorder installs the RX recorder tap, reporting false when the loop
// has ALREADY stopped. This single in-critical-section read replaces W5 Task
// 6's install-then-recheck dance: RecordStart's Artifacts.Create/
// NewWAVRecorder run with u.calls.mu released, so a concurrent Hangup/onBye can
// run stop() to completion while they are in flight. Under the old atomics the
// store and the recheck were two separate operations and the comment reasoning
// about their interleaving ran to twelve lines. Here the decision is made once,
// under the same lock stop() takes, so a false return means "stop() already
// won; finalize your own recorder" with no interleaving left to reason about.
//
// Deliberate, safe narrowing versus pre-Task-7 behavior: an install landing
// just before the stop flag flips now returns success, with stop()'s
// markStopped() cleanly finalizing the recorder either way — no dangling
// recorder is possible in either outcome.
//
// rec must be non-nil against a live (non-stopped) loop: unlike claimOp's src
// (nil there means "leave the current source alone"), installRecorder always
// stores its argument verbatim, so a nil rec against a live loop silently
// clears the tap — and orphans (without finalizing) any recorder already
// installed. No current caller passes nil here; that is caller discipline,
// not something this method enforces.
func (ml *mediaLoop) installRecorder(rec *codec.WAVRecorder) bool {
	ml.st.mu.Lock()
	defer ml.st.mu.Unlock()
	if ml.st.stopped {
		return false
	}
	ml.st.rec = rec
	return true
}

// takeRecorder is THE claim on an active recording, and its atomicity is
// load-bearing: two concurrent RecordStops (or a RecordStop racing stop()'s
// teardown finalize) must resolve to EXACTLY ONE WINNER (§6.3). The loser
// observes nil and returns precondition_failed.
func (ml *mediaLoop) takeRecorder() *codec.WAVRecorder {
	ml.st.mu.Lock()
	defer ml.st.mu.Unlock()
	rec := ml.st.rec
	ml.st.rec = nil
	return rec
}

// recorder is runRX's per-frame read of the tap.
func (ml *mediaLoop) recorder() *codec.WAVRecorder {
	ml.st.mu.Lock()
	defer ml.st.mu.Unlock()
	return ml.st.rec
}

// claimEventTX installs the telephone-event sender, reporting false when one is
// already in flight or the loop has stopped. It does NOT consult st.op. On
// success it arms e's release hook to a compare-and-clear closure over this
// exact instance, so finish() can release the slot itself once the event is
// done (see releaseEventTX and dtmfEventTX.finish's doc comments).
func (ml *mediaLoop) claimEventTX(e *dtmfEventTX) bool {
	ml.st.mu.Lock()
	defer ml.st.mu.Unlock()
	if ml.st.stopped || ml.st.rtpEvent != nil {
		return false
	}
	ml.st.rtpEvent = e
	e.release = func() { ml.releaseEventTX(e) }
	return true
}

// releaseEventTX clears the sender, but ONLY if the slot currently holds
// exactly this instance (compare-and-clear). This is deliberate, not a
// no-argument "clear whatever is there": dtmfEventTX.finish() calls this
// itself, from the same callback that closes Done(), so a caller that wakes
// on Done() and immediately starts a new event can race finish()'s release
// against its own claim. An unconditional clear would risk the OLD event's
// delayed release clobbering a NEWER event that had already been claimed in
// that window, hanging the newer event's Done() forever. Comparing the
// instance makes releasing a stale event a safe no-op. Idempotent.
func (ml *mediaLoop) releaseEventTX(e *dtmfEventTX) {
	ml.st.mu.Lock()
	defer ml.st.mu.Unlock()
	if ml.st.rtpEvent == e {
		ml.st.rtpEvent = nil
	}
}

// eventTX is runTX's per-tick read of the sender; nil when none is in flight.
func (ml *mediaLoop) eventTX() *dtmfEventTX {
	ml.st.mu.Lock()
	defer ml.st.mu.Unlock()
	return ml.st.rtpEvent
}

// isStopped reports the terminal state.
func (ml *mediaLoop) isStopped() bool {
	ml.st.mu.Lock()
	defer ml.st.mu.Unlock()
	return ml.st.stopped
}

// currentOp reports which media op holds the slot; opNone when it is free.
func (ml *mediaLoop) currentOp() mediaOp {
	ml.st.mu.Lock()
	defer ml.st.mu.Unlock()
	return ml.st.op
}

// markStopped enters the terminal absorbing state and hands back any installed
// recorder in the SAME critical section, so no concurrent installRecorder can
// slip one in between the two.
func (ml *mediaLoop) markStopped() *codec.WAVRecorder {
	ml.st.mu.Lock()
	defer ml.st.mu.Unlock()
	ml.st.stopped = true
	rec := ml.st.rec
	ml.st.rec = nil
	return rec
}

// assemble wires the pure media components onto an already-built loop. transform
// is nil for a plain-RTP call (an identity transform is installed). It is split
// from launch so tests can inspect the assembled loop without goroutines.
func (ml *mediaLoop) assemble(transform media.FrameTransform, signalled *net.UDPAddr) {
	if transform != nil {
		ml.transform = transform
	}
	if ml.transform == nil {
		ml.transform = media.NewIdentityTransform()
	}
	depth := ml.jitterBufferMS / 20
	if depth < 1 {
		depth = 1
	}
	ml.jb = media.NewJitterBuffer(depth)
	ml.plc = media.NewPLC(codec.SamplesPerFrame)
	if ml.acc == nil {
		ml.acc = quality.New()
	}
	if ml.st.src == nil {
		ml.st.src = codec.NewSilenceSource()
	}
	ml.ssrc = rand.Uint32()
	ml.seq0 = uint16(rand.Uint32())
	ml.dest = signalled
	if ml.recvPTs == nil {
		ml.recvPTs = map[uint8]string{ml.payloadType: ml.codecName}
	}
	ml.done = make(chan struct{})
	if ml.clock == nil {
		ml.clock = media.RealClock{}
	}
	// Optional collaborators are defaulted-if-nil here, not nil-guarded at
	// each call site — the same pattern as acc/src/clock above. Every
	// directly-constructed mediaLoop literal in this plan's own tests leaves
	// logger nil, and Task 9's RX drop paths (SRTP auth failure, decode
	// failure) are exactly the kind of place a future logger.Warn would
	// naturally get added — defaulting here means that never nil-derefs.
	if ml.logger == nil {
		ml.logger = slog.Default()
	}
	if ml.writeTo == nil {
		ml.writeTo = ml.conn.WriteToUDP
	}
}

// launch starts the two goroutines. Their bodies are filled by later tasks; the
// scaffold blocks on done so lifecycle is testable now.
func (ml *mediaLoop) launch() {
	ml.wg.Add(2)
	go func() { defer ml.wg.Done(); ml.runTX() }()
	go func() { defer ml.wg.Done(); ml.runRX() }()
}

// stop is idempotent: it closes done (signalling runTX), closes the conn
// (unblocking runRX's ReadFromUDP), and joins.
//
// MUST be called WITHOUT holding u.calls.mu. Both goroutines call ml.emit,
// which is wired to u.emit (call.go) — and u.emit itself briefly acquires
// u.calls.mu to read the registered event callback. A caller that held
// u.calls.mu across stop()'s wg.Wait() would deadlock against a goroutine
// parked inside emit() waiting for that same lock. Every current call site
// (teardownDialog, Hangup, onBye) already releases the lock before calling
// stop() — that release MUST be preserved by any future caller too.
func (ml *mediaLoop) stop() {
	ml.stopOnce.Do(func() {
		// markStopped enters the terminal state AND claims any installed
		// recorder in one critical section, so an installRecorder racing this
		// teardown either lands before (and is claimed here) or is refused.
		//
		// C-M4 (D20, W2): THE CODE IS CORRECT, THE OLD REASONING WAS NOT. This
		// comment used to justify the early markStopped() by WAVRecorder.Write being
		// a no-op after Close — but Close() runs AFTER wg.Wait(), so runRX has already
		// returned and can never observe a closed recorder. That guarantee was never
		// load-bearing here.
		//
		// The real reason markStopped() comes first: it is what makes the stop
		// IDEMPOTENT, so a second stop() (from a racing teardown) returns without
		// re-running the teardown below. Nothing about the recorder's lifetime is
		// involved.
		rec := ml.markStopped()
		close(ml.done)
		if ml.conn != nil {
			_ = ml.conn.Close()
		}
		ml.wg.Wait()
		// An active recording never explicitly stopped (call ended mid-record,
		// discrete tool or plan-driven) is finalized here rather than left with
		// a corrupt placeholder header.
		if rec != nil {
			_, _ = rec.Close()
		}
	})
}

func (ml *mediaLoop) snapshot() quality.Snapshot {
	return ml.acc.Snapshot(ml.neg().codecName, 0, ml.jitterBufferMS)
}

// negotiated is the part of a loop that a peer re-offer can change (RFC 3261
// 14.2): the codec and its payload type, the payload types we accept, whether
// our TX is off (hold, rejection or an unspecified address) and the peer's
// signalled address. The SRTP transform is NOT part of it: a re-offer that
// would change the keys is refused (D-10), so it is fixed for the loop's life.
type negotiated struct {
	codecName    string
	payloadType  uint8
	recvPTs      map[uint8]string
	recvEventPTs map[uint8]bool
	txOff        bool
	dest         *net.UDPAddr
}

// newNegotiated derives the loop state from a negotiated Session, resolving
// the peer's address. A hand-built Session (tests) keeps the static PT for its
// codec. Call it with no lock held.
func newNegotiated(sess *media.Session) (*negotiated, error) {
	pt, _ := codec.PayloadType(sess.Codec)
	var recvPTs map[uint8]string
	if len(sess.RecvPTs) > 0 {
		pt, recvPTs = uint8(sess.SendPT), sess.RecvPTs
	}
	remote, err := net.ResolveUDPAddr("udp", sess.RemoteAddr)
	if err != nil {
		return nil, err
	}
	return &negotiated{
		codecName: sess.Codec, payloadType: pt, recvPTs: recvPTs,
		recvEventPTs: negotiatedEventPTs(sess), txOff: !sess.SendsMedia(), dest: remote,
	}, nil
}

// neg returns the loop's current negotiated state, read under destMu. Each unit
// of work (a TX tick, an RX packet) loads it once, so a concurrent swap is seen
// whole or not at all.
func (ml *mediaLoop) neg() negotiated {
	ml.destMu.Lock()
	defer ml.destMu.Unlock()
	return negotiated{ml.codecName, ml.payloadType, ml.recvPTs, ml.recvEventPTs, ml.txOff, ml.dest}
}

// swap installs a re-offer's negotiated state under destMu. The maps in n are
// never mutated after construction, so readers holding the old ones stay valid.
func (ml *mediaLoop) swap(n *negotiated) {
	ml.destMu.Lock()
	defer ml.destMu.Unlock()
	ml.codecName, ml.payloadType, ml.recvPTs = n.codecName, n.payloadType, n.recvPTs
	if ml.recvPTs == nil {
		ml.recvPTs = map[uint8]string{n.payloadType: n.codecName}
	}
	ml.recvEventPTs, ml.txOff, ml.dest = n.recvEventPTs, n.txOff, n.dest
}

// observedRemote reports the destination TX is using, which is the signalled
// address; the second result is always false (TX never latches, CF-159).
func (ml *mediaLoop) observedRemote() (string, bool) {
	ml.destMu.Lock()
	defer ml.destMu.Unlock()
	if ml.dest == nil {
		return "", false
	}
	return ml.dest.String(), false
}

// runTX is the per-call TX ticker (§6.5.2/§3.4): every 20 ms it pulls a frame
// from the audio source, encodes it with the negotiated codec, builds the RTP
// packet (seq++, ts0 + n*160), protects it through the frame transform, and
// writes it to the signalled destination. It schedules against
// absolute deadlines from media.TXTicker, never an accumulating time.Ticker, so
// drift is bounded. A stall of more than 3 frames resyncs by skipping (never
// bursting), counts the skip in tx_underruns, and emits one tx_underrun error.
func (ml *mediaLoop) runTX() {
	seq := ml.seq0
	firstWriteTried := false
	tk := media.NewTXTicker(time.Now(), rand.Uint32())
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(time.Until(tk.Deadline()))
		select {
		case <-ml.done:
			return
		case <-timer.C:
		}

		if skipped := tk.Resync(time.Now()); skipped > 0 {
			ml.acc.RecordTXUnderrun(int(skipped))
			seq += uint16(skipped)
			ml.emitTXUnderrun(int(skipped))
		}

		// A telephone-event send takes this tick INSTEAD of the audio frame
		// (RFC 4733 §2.5.2.2's audio suppression), so runTX remains the single
		// writer of this socket and the seq/SSRC/SRTP contexts stay coherent.
		// A terminal tick's release of the claimed-event slot happens inside
		// ev.next() itself (dtmfEventTX.finish(), driven by claimEventTX's
		// compare-and-clear release hook), not here — see releaseEventTX's
		// doc comment for why that matters.
		//
		// F1 (Phase 4 W1): this interleave is left UNCHANGED on purpose. The
		// currentSrc().Frame() pull below is still skipped on any tick an
		// event is active, which means a PromptSource/silence source (media_play,
		// or ordinary call audio) can still be preempted by an rfc2833 event
		// mid-tick — that is the deliberate, documented audio suppression above,
		// and it is harmless for those sources. It is NOT the corruption bug F1
		// fixed: that bug was a codec.DTMFSource's continuous-phase assumption
		// being violated by a stolen tick, and it is closed at the DISPATCH
		// level (SendDTMF's dialog-level dtmfSendInFlight claim, dtmf.go),
		// which now refuses to let an inband send and an rfc2833 send run
		// concurrently on the same dialog in the first place — so this tick
		// interleave can no longer steal a tick out from under a DTMFSource at
		// all, and needed no change here.
		n := ml.neg() // once per tick: a re-offer's swap is seen whole
		payloadType, payload := n.payloadType, []byte(nil)
		marker := false
		timestamp := tk.Timestamp()
		if ev := ml.eventTX(); ev != nil {
			evPayload, evMarker, newTS, more := ev.next()
			if more && evPayload != nil {
				if newTS {
					ml.eventTS = tk.Timestamp()
				}
				payloadType, payload, marker = ev.pt, evPayload, evMarker
				timestamp = ml.eventTS
			}
		}
		if payload == nil {
			pcm := ml.currentSrc().Frame()
			enc, err := codec.Encode(n.codecName, pcm)
			if err != nil {
				ml.logger.Error("tx encode", "err", err)
				// B11: a bare return here exits runTX leaving ml.done open and
				// every blocking caller (Play, sendDTMFInband,
				// sendDTMFRFC2833) parked forever. stop() cannot be called
				// INLINE — it does ml.wg.Wait() and runTX is one of the two
				// goroutines wg tracks, so an inline call self-joins and
				// deadlocks. Running it on its own goroutine lets THIS
				// goroutine return (satisfying wg.Done() via launch()'s
				// defer) while stop() waits for it from the outside; stop()
				// is stopOnce-guarded, so a concurrent teardown
				// (teardownDialog/Hangup/onBye) racing this exit is safe.
				go ml.stop()
				return
			}
			payload = enc
		}
		pkt := &rtp.Packet{
			Header: rtp.Header{
				Version: 2, PayloadType: payloadType, Marker: marker,
				SequenceNumber: seq, Timestamp: timestamp, SSRC: ml.ssrc,
			},
			Payload: payload,
		}
		marshaled, err := pkt.Marshal()
		if err != nil {
			ml.logger.Error("tx marshal", "err", err)
			// B11: the identical defect as the encode-error return above, 12
			// lines up — see its comment for why stop() must run on its own
			// goroutine rather than inline.
			go ml.stop()
			return
		}
		// No pre-sizing needed here: Protect (Task 5) owns a reusable scratch
		// buffer sized for clear+SRTPAuthTagLen internally, so §15.1's
		// no-reallocation requirement is satisfied inside the transform, not
		// by anything the caller does to clear itself.
		wire, err := ml.transform.Protect(marshaled)
		if err != nil {
			// A Protect error is an internal fault: drop the frame, emit a
			// tx_underrun-style error, and keep the cadence (§15.1).
			ml.emitTXUnderrun(1)
			ml.acc.RecordTXUnderrun(1)
		} else {
			dst := n.dest
			if dst != nil && !n.txOff {
				_, werr := ml.writeTo(wire, dst)
				if !firstWriteTried {
					// CF-053: on kernels before 6.12 with a NAT table, the
					// stream's first datagram can fail with EPERM (conntrack
					// reverse-clash, CF-036).
					// One immediate retry succeeds; later frames, and every
					// other error, are written once as before.
					firstWriteTried = true
					if errors.Is(werr, syscall.EPERM) {
						_, werr = ml.writeTo(wire, dst)
					}
				}
				if werr == nil {
					ml.acc.RecordSent()
				}
			}
		}
		seq++
		tk.Advance()
	}
}

// emitTXUnderrun appends one §6.5.2 error event with detail.kind == "tx_underrun".
func (ml *mediaLoop) emitTXUnderrun(frames int) {
	if ml.emit == nil {
		return
	}
	ml.emit(session.UAEvent{
		Kind: session.UAEventMediaError, DialogID: ml.dialogID, CallID: ml.callID,
		Direction: ml.direction,
		Detail:    map[string]any{"kind": "tx_underrun", "frames_skipped": frames},
	})
}

// runRX is the per-call read-plus-playout loop (§3.5). It reads from the socket,
// accepts only the signalled source (fromSignalled), Unprotects the frame (dropping and
// counting srtp_auth_failures on error), decodes it, places it in the jitter
// buffer by sequence slot, and at each 20 ms playout tick pulls the due slot or
// runs PLC, recording a burst_gaps entry (§10.10) for every run of 2+
// consecutive empty slots. Decoded PCM is discarded once accounted for (W5
// taps this point for media_record). It is single-goroutine-affine: it alone
// touches jb, plc and the RX SRTP context, so none of them needs a lock.
func (ml *mediaLoop) runRX() {
	buf := make([]byte, 1500)
	// playout is constructed lazily, anchored at the FIRST real packet's
	// arrival (startedAt) rather than at goroutine launch. Anchoring at launch
	// would leave playout.Deadline() stuck at the launch-time t0: once the
	// first packet finally arrives, every 20ms tick between launch and that
	// moment (a real SIP/RTP-setup gap, not silence on an active stream) would
	// then be "due" all at once and drain synchronously as spurious
	// PLC-concealed losses (RecordConcealed → packets_lost) before real
	// playout catches up.
	//
	// Frame 0's deadline is OFFSET by jitterBufferMS past startedAt, not equal
	// to it. This is the buffer's actual reorder tolerance (§6.5.1): the first
	// packet is pushed to the jitter buffer immediately on arrival, but is not
	// POPPED for playout until jitterBufferMS later — during that window,
	// packets 1, 2, ... that arrive out of order still land in their correct
	// slot and get played in sequence, exactly the "at least 60ms of reorder
	// tolerance" the master spec's jitter buffer promises. Anchoring frame 0
	// AT startedAt (no offset) would pop it in the very same instant it
	// arrives, giving the buffer zero playout delay — a reordered packet
	// arriving even a few ms "late" (but well inside the nominal 60ms depth)
	// would already have missed its slot's playout deadline and get
	// mis-classified late/lost instead of tolerated.
	var playout *media.TXTicker
	started := false
	var startedAt time.Time
	// burstRun/burstStartMs track a run of consecutive empty playout slots
	// (§10.10 burst_gaps): a run of 2+ consecutive missing frames is a burst,
	// recorded once the run ends (a present frame arrives) or never recorded
	// at all if the run never reaches length 2 (a single isolated miss is
	// packets_lost only, per spec, never a burst_gaps entry).
	var burstRun int
	var burstStartMs int64

	for {
		select {
		case <-ml.done:
			return
		default:
		}
		_ = ml.conn.SetReadDeadline(time.Now().Add(media.FrameDuration))
		n, src, err := ml.conn.ReadFromUDP(buf)
		if err == nil {
			wasStarted := started
			ml.handleInbound(buf[:n], src, &started, &startedAt)
			if !wasStarted && started {
				// Frame 0 is due jitterBufferMS AFTER startedAt, not at
				// startedAt itself — this offset IS the buffer's reorder
				// tolerance window (see the runRX doc comment above).
				delay := time.Duration(ml.jitterBufferMS) * time.Millisecond
				playout = media.NewTXTicker(startedAt.Add(delay), 0)
			}
		}
		// Playout: drain every due frame (deadline reached), running PLC on gaps.
		// Reads ml.clock, NOT bare time.Now() — a test-injected fake clock must
		// govern this comparison so drain cadence can be advanced deterministically
		// instead of gated by real wall-clock sleeps (see Clock's doc comment,
		// Task 4).
		for playout != nil && !ml.clock.Now().Before(playout.Deadline()) {
			frame, present := ml.jb.Pop()
			if present {
				ml.plc.Observe(frame)
				if burstRun >= 2 {
					ml.acc.RecordBurstGap(burstStartMs, burstRun)
				}
				burstRun = 0
			} else {
				ml.plc.Conceal()
				ml.acc.RecordConcealed()
				if burstRun == 0 {
					burstStartMs = ml.clock.Now().Sub(startedAt).Milliseconds()
				}
				burstRun++
			}
			playout.Advance()
		}
		select {
		case <-ml.done:
			return
		default:
		}
	}
}

// tapRX feeds one decoded 20 ms PCM frame to the inband DTMF detector and
// reports any digit it accepts. It is a no-op when no detector is installed or
// no funnel is wired, so the audio-only path costs one nil check per frame.
func (ml *mediaLoop) tapRX(pcm []int16) {
	if ml.detector == nil || ml.onDigit == nil {
		return
	}
	if digit, durationMs, ok := ml.detector.Feed(pcm); ok {
		ml.onDigit(digit, "inband", durationMs)
	}
}

// rxEventState reassembles one inbound RFC 4733 event, keyed on its RTP
// timestamp (RFC 4733 2.5.2). SINGLE-GOROUTINE-AFFINE to runRX.
type rxEventState struct {
	inFlight   bool
	code       uint8
	ts         uint32 // RTP timestamp of the current segment
	durationTS uint16 // largest duration seen in the current segment
	priorTS    uint32 // summed duration of the earlier segments of a long event
	ended      bool   // endedCode/endedTS name the last event that ended
	endedCode  uint8
	endedTS    uint32
}

// reportEventDigit decodes code via codec.DTMFDigitForEventCode and reports it
// through onDigit at durationTS (RTP timestamp units, converted to ms). It is
// the ONE funnel both handleTelephoneEvent report sites (the normal end-packet
// report and the lost-end recovery report) go through.
func (ml *mediaLoop) reportEventDigit(code uint8, durationTS uint32) {
	// codec.DTMFDigitForEventCode, NEVER codec.DTMFAlphabet[code]: the
	// alphabet's order is not RFC 4733's code order, so an index would decode
	// '*' (code 10) as 'A' and mangle every non-decimal digit (Task 8).
	if digit, ok := codec.DTMFDigitForEventCode(code); ok {
		// RFC 4733 durations are in RTP timestamp units; at 8 kHz that is 8
		// per millisecond.
		ml.onDigit(digit, "rfc2833", int(durationTS)/8)
	}
}

// handleTelephoneEvent reassembles an inbound telephone-event and reports its
// digit EXACTLY ONCE. An event is identified by (event code, RTP timestamp);
// the marker bit is not consulted (CF-158, CF-162, RFC 4733 2.5.2.2-2.5.2.3):
//
//   - a packet of an event that already ended (end retransmits, late
//     intermediates) is ignored;
//   - a packet whose timestamp is exactly the previous segment's plus 0xFFFF
//     continues a long event, and the segment durations add up;
//   - anything else starts a new event, and one still in flight (all its end
//     packets lost) is reported at its last duration first.
func (ml *mediaLoop) handleTelephoneEvent(pkt *rtp.Packet) {
	if ml.onDigit == nil || len(pkt.Payload) < 4 {
		return
	}
	code := pkt.Payload[0]
	end := pkt.Payload[1]&0x80 != 0
	dur := binary.BigEndian.Uint16(pkt.Payload[2:4])
	ts := pkt.Timestamp
	st := &ml.rxEvent

	// A packet of an event that already ended is late: ignore it (2.5.2.2).
	if st.ended && code == st.endedCode && ts == st.endedTS {
		return
	}
	// A late packet of the previous segment of the long event in flight.
	if st.inFlight && st.priorTS > 0 && code == st.code && ts == st.ts-0xFFFF {
		return
	}
	switch {
	case st.inFlight && code == st.code && ts == st.ts:
		// Same segment of the event in flight.
	case st.inFlight && code == st.code && ts == st.ts+0xFFFF:
		// Next segment of a long event (2.5.2.3 compares timestamps only):
		// no gap, one event, even if the segment's own 0xFFFF packet was lost.
		st.priorTS += 0xFFFF
		st.ts, st.durationTS = ts, 0
	default:
		// A new event. One still in flight lost all its end packets: report
		// it at its last duration and remember it as ended.
		if st.inFlight {
			ml.reportEventDigit(st.code, st.priorTS+uint32(st.durationTS))
			st.ended, st.endedCode, st.endedTS = true, st.code, st.ts
		}
		*st = rxEventState{inFlight: true, code: code, ts: ts,
			ended: st.ended, endedCode: st.endedCode, endedTS: st.endedTS}
	}
	if dur > st.durationTS {
		st.durationTS = dur
	}
	if end {
		ml.reportEventDigit(code, st.priorTS+uint32(st.durationTS))
		st.inFlight = false
		st.ended, st.endedCode, st.endedTS = true, code, ts
	}
}

func (ml *mediaLoop) handleInbound(wire []byte, src *net.UDPAddr, started *bool, startedAt *time.Time) {
	// CF-179: RTP is accepted only from the peer's signalled address; any other
	// source is dropped and counted rogue, BEFORE Unprotect (the source is
	// known up front, so an SRTP packet from elsewhere is a rogue packet, not
	// an authentication failure).
	// One negotiation snapshot per packet: the source check, the event demux and
	// the codec lookup all read it, so a re-offer's swap between them cannot
	// make a packet from the old peer be classified with the new types.
	n := ml.neg()
	if rxSnapshotHook != nil {
		rxSnapshotHook()
	}
	if !ml.fromSignalled(n.dest, src) {
		return
	}
	decrypted, err := ml.transform.Unprotect(wire)
	if err != nil {
		ml.acc.RecordSRTPAuthFailure() // NOT packets_lost (§15.1 O2)
		return
	}
	var pkt rtp.Packet
	if err := pkt.Unmarshal(decrypted); err != nil {
		return
	}
	// Telephone-event demux (§2.2). It comes BEFORE the audio payload-type
	// check, because an event packet's PT is by definition not the audio PT and
	// the existing check would drop it as "not our negotiated stream". The
	// source check above already kept other sources from injecting digits. It
	// returns without touching the jitter buffer, the PLC or the quality
	// accumulator: an event packet is not audio, and counting it as a received
	// audio packet would corrupt loss, jitter and burst-gap accounting (§10.10).
	if n.recvEventPTs[pkt.PayloadType] {
		ml.handleTelephoneEvent(&pkt)
		return
	}
	rxCodec, ok := n.recvPTs[pkt.PayloadType]
	if !ok {
		return // not our negotiated stream
	}
	if !*started {
		*started, *startedAt = true, ml.clock.Now()
		ml.emitMediaStart()
	}
	pcm, derr := codec.Decode(rxCodec, pkt.Payload)
	if derr != nil {
		return
	}
	// W5 media_record tap: if a recorder is installed, write the decoded PCM
	// before it is placed in the jitter buffer and (eventually) discarded. The
	// pointer is loaded per frame; RecordStop clears it (Store(nil)).
	if r := ml.recorder(); r != nil {
		_ = r.Write(pcm)
	}
	// Inband DTMF detection tap (§2.2). It runs AFTER the recorder so a
	// recording still contains the tones — the artifact is the received audio,
	// not a DTMF-stripped version of it.
	ml.tapRX(pcm)
	switch ml.jb.Push(pkt.SequenceNumber, pcm) {
	case media.OutcomePlaced:
		ml.acc.RecordReceived()
	case media.OutcomeReorder:
		ml.acc.RecordReceived()
		ml.acc.RecordOutOfOrder()
	case media.OutcomeDuplicate:
		ml.acc.RecordDuplicate()
	case media.OutcomeLate:
		ml.acc.RecordLateDiscard()
	}
	// Interarrival jitter (RFC 3550): transit = arrival_ms - rtp_ts/8. Uses
	// ml.clock, not time.Since, for the same reason as the drain loop above.
	transit := float64(ml.clock.Now().Sub(*startedAt).Milliseconds()) - float64(pkt.Timestamp)/8.0
	ml.acc.RecordJitterSample(transit)
}

// rxSnapshotHook is a TEST-ONLY seam, nil in production: handleInbound calls it
// right after loading the packet's negotiation snapshot, so a test can land a
// swap between the snapshot and the packet's classification.
var rxSnapshotHook func()

// fromSignalled reports whether src is the peer's signalled media address (dest,
// taken from the packet's negotiation snapshot). Any other source is rogue: rogue_source_packets is incremented
// and the packet is to be dropped. It never changes dest (RFC 3550 11, CF-159).
// A nil dest (only hand-built test loops) accepts nothing. The accumulator is
// called after destMu is released.
func (ml *mediaLoop) fromSignalled(dest, src *net.UDPAddr) bool {
	ok := udpAddrEqual(dest, src)
	if !ok {
		ml.acc.RecordRogueSource()
	}
	return ok
}

func (ml *mediaLoop) emitMediaStart() {
	if ml.emit == nil {
		return
	}
	addr, latched := ml.observedRemote()
	ml.emit(session.UAEvent{
		Kind: session.UAEventMediaStart, DialogID: ml.dialogID, CallID: ml.callID,
		Direction: ml.direction, RemoteMediaAddr: addr, MediaLatched: latched,
	})
}

func udpAddrEqual(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.IP.Equal(b.IP) && a.Port == b.Port
}

// negotiatedEventPT returns pt as a payload type, or 0 (not negotiated) when it
// is out of the valid RTP payload-type range — mirrors sendDTMFRFC2833's guard
// against uint8's silent wraparound (dtmf.go): a peer's SDP can produce a
// TelephoneEventPT outside 1-127, and converting that straight to uint8 would
// silently wrap to some other, wrong PT — e.g. uint8(264) == 8, colliding with
// PCMA's payload type and misrouting every audio packet on a PCMA call as a
// telephone-event, dropping all audio.
func negotiatedEventPT(pt int) uint8 {
	if pt < 1 || pt > 127 {
		return 0
	}
	return uint8(pt)
}

// negotiatedEventPTs is the set of telephone-event PTs the loop accepts: the
// session's RecvEventPTs, or for a hand-built session (nil) its single
// TelephoneEventPT, each through negotiatedEventPT's 1-127 guard.
func negotiatedEventPTs(sess *media.Session) map[uint8]bool {
	out := map[uint8]bool{}
	if sess.RecvEventPTs == nil {
		if pt := negotiatedEventPT(sess.TelephoneEventPT); pt != 0 {
			out[pt] = true
		}
		return out
	}
	for pt := range sess.RecvEventPTs {
		if g := negotiatedEventPT(int(pt)); g != 0 {
			out[g] = true
		}
	}
	return out
}

// mediaLoopBuiltHook is a TEST-ONLY seam, nil in production (the
// dialAnsweringHook style): startMediaLoop calls it after the loop is built and
// before the publish-and-launch section, so a test can land a re-offer there.
var mediaLoopBuiltHook func()

// startMediaLoop builds and launches the media loop for a dialog that has just
// reached phaseAnswered. It reads the negotiated session and the bound socket
// (captured by the caller under u.calls.mu) and installs the loop on the dialog.
func (u *UA) startMediaLoop(d *dialog) {
	u.calls.mu.Lock()
	sess, conn, awaiting := d.mediaSession, d.mediaConn, d.mediaAwaitingAnswer
	u.calls.mu.Unlock()
	if sess == nil || conn == nil {
		return // nothing negotiated (should not happen at phaseAnswered)
	}
	if awaiting {
		return // CF-145: our offer is not answered yet (applyAckAnswer starts it)
	}

	// A Session from BuildAnswer/ParseAnswer carries the negotiated PTs; a
	// hand-built one (tests) keeps the static PT for its codec.
	neg, err := newNegotiated(sess)
	if err != nil {
		// C6: u.log() is the package's one nil-safe Logger accessor (see its
		// doc comment, keepalive.go). startMediaLoop runs on a *UA method
		// before the media loop exists, so it is the only viable accessor
		// here — a peer-supplied malformed sess.RemoteAddr reached this SIGSEGV
		// (raw u.cfg.Logger.Warn against a nil Config.Logger) directly.
		u.log().Warn("media loop: bad remote addr", "addr", sess.RemoteAddr, "err", err)
		return
	}

	var transform media.FrameTransform
	if sess.LocalCrypto != nil && sess.RemoteCrypto != nil {
		w := media.ReplayWindowFor(u.jitterBufferMS())
		if aerr := media.AssertReplayWindow(w, u.jitterBufferMS()); aerr != nil {
			u.log().Error("media loop: replay-window invariant", "err", aerr)
			return
		}
		t, terr := media.NewSRTPTransform(*sess.LocalCrypto, *sess.RemoteCrypto, w)
		if terr != nil {
			u.log().Error("media loop: srtp transform", "err", terr)
			return
		}
		transform = t
	}
	if transform == nil && sess.SRTPPolicy() == media.SRTPRequired {
		// Fail closed: a required session never runs as plain RTP.
		u.log().Error("media loop: srtp required but no transform; not starting media", "dialog_id", d.id)
		return
	}

	ml := &mediaLoop{
		conn: conn, codecName: neg.codecName, payloadType: neg.payloadType, recvPTs: neg.recvPTs, txOff: neg.txOff,
		jitterBufferMS: u.jitterBufferMS(), logger: u.cfg.Logger,
		emit: u.emit, dialogID: d.id, callID: d.callID, direction: d.direction,
		onDigit:      func(digit byte, mode string, durationMs int) { u.handleDigit(d, digit, mode, durationMs) },
		recvEventPTs: neg.recvEventPTs,
	}
	if u.inbandDetectionEnabled() {
		ml.detector = codec.NewDTMFDetector()
	}
	ml.st.src = u.txAudioSource()
	ml.assemble(transform, neg.dest)
	if mediaLoopBuiltHook != nil {
		mediaLoopBuiltHook()
	}

	// Publish-and-launch is ONE critical section, re-checking phaseAnswered,
	// not two. teardownDialog/Hangup/onBye each set d.phase = phaseDone and
	// capture+nil d.mediaLoop/d.mediaConn under this SAME lock, in that order,
	// before this function ever runs. If teardown already won that race
	// (phase no longer phaseAnswered — a peer BYE arriving right after ACK is
	// a real, common case, not just theoretical), d.mediaConn is ALREADY
	// closed by that teardown's `else if conn != nil` branch (mediaLoop was
	// still nil then). Launching ml onto that dead, forgotten dialog would
	// orphan its goroutines forever: nothing would ever hold a reference to
	// call ml.stop(), so runTX ticks forever onto a closed conn and runRX's
	// ReadFromUDP spins at 100% CPU returning the closed-conn error
	// immediately with nothing to block on. So: check first, launch only if
	// still answered, and never launch at all otherwise. ml.launch() itself
	// only starts the two goroutines and returns immediately — it does not
	// block and does not itself touch u.calls.mu, so calling it while holding
	// the lock is safe (unlike ml.stop(), which DOES eventually touch
	// u.calls.mu transitively via emit() and must never be called under it —
	// see stop()'s doc comment, this same task).
	u.calls.mu.Lock()
	if d.phase != phaseAnswered {
		u.calls.mu.Unlock()
		return
	}
	if d.mediaSession != sess {
		// A peer re-offer (answerInDialogOffer) replaced the Session after the
		// snapshot at the top: this loop was built from the old one and has
		// launched nothing (the socket is the dialog's and stays open), so drop
		// it and build from the current Session. Each retry needs a newer
		// published Session, so this ends.
		u.calls.mu.Unlock()
		u.startMediaLoop(d)
		return
	}
	d.mediaLoop = ml
	ml.launch()
	if len(d.mediaPlanSteps) > 0 {
		u.launchMediaPlan(d, ml, d.mediaPlanSteps)
	}
	u.calls.mu.Unlock()
}

// jitterBufferMS is the configured RX buffer depth in ms, defaulting to 60.
func (u *UA) jitterBufferMS() int {
	if u.cfg.JitterBufferMS >= 20 && u.cfg.JitterBufferMS <= 200 {
		return u.cfg.JitterBufferMS
	}
	return 60
}

// txAudioSource is the production TX source (silence) unless the hidden TXToneHz
// diagnostic knob is set — the e2e gate's tone generator (locked decision 3).
// It is NEVER selectable through any MCP tool.
func (u *UA) txAudioSource() codec.AudioSource {
	if u.cfg.TXToneHz > 0 {
		return codec.NewSineSource(u.cfg.TXToneHz)
	}
	return codec.NewSilenceSource()
}
