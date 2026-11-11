package sipua

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/artifact"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// testCallHandle stands in for the session-level call handle ToolService
// resolves and passes explicitly as RecordStart/RecordStop's callHandle
// parameter (the same value CaptureStart already keys artifacts under,
// string(c.Handle())) — sipua never derives this itself.
const testCallHandle = "call-handle-1"

// recordHarness builds a UA with a real artifact store rooted in a temp dir and
// one answered dialog with a live mediaLoop (goroutines not started; we feed the
// recorder tap by hand through handleInbound's write path).
func recordHarness(t *testing.T) (*UA, *mediaLoop, *artifact.Store) {
	t.Helper()
	store := artifact.New(t.TempDir(), clock.System())
	u := &UA{cfg: Config{Artifacts: store}}
	ml := &mediaLoop{emit: func(session.UAEvent) {}}
	ml.assemble(nil, nil)
	d := &dialog{id: "d1", callID: "call-abc", phase: phaseAnswered, mediaLoop: ml}
	u.register(d)
	if err := store.OpenCallDir(context.Background(), testCallHandle); err != nil {
		t.Fatal(err)
	}
	return u, ml, store
}

func TestRecordStartStopRoundTrip(t *testing.T) {
	u, ml, _ := recordHarness(t)
	ctx := context.Background()

	name, err := u.RecordStart(ctx, "d1", testCallHandle, "")
	if err != nil {
		t.Fatalf("RecordStart: %v", err)
	}
	if name != "recording.wav" {
		t.Fatalf("default name=%q want recording.wav", name)
	}
	// The recorder tap is installed; simulate two received 20ms frames.
	if r := ml.recorder(); r == nil {
		t.Fatal("RecordStart did not install the recorder tap")
	} else {
		_ = r.Write(make([]int16, codec.SamplesPerFrame))
		_ = r.Write(make([]int16, codec.SamplesPerFrame))
	}

	info, dur, err := u.RecordStop(ctx, "d1", testCallHandle, "")
	if err != nil {
		t.Fatalf("RecordStop: %v", err)
	}
	if dur != int64(2*20) {
		t.Fatalf("duration=%d want 40", dur)
	}
	if info.Bytes != int64(44+2*codec.SamplesPerFrame*2) {
		t.Fatalf("bytes=%d want %d", info.Bytes, 44+2*codec.SamplesPerFrame*2)
	}
	if ml.recorder() != nil {
		t.Fatal("RecordStop did not clear the recorder tap")
	}
	if ml.currentOp() != opNone {
		t.Fatal("RecordStop did not release the play-or-record slot")
	}
}

func TestRecordSecondStartWhileActiveIsPreconditionFailed(t *testing.T) {
	u, _, _ := recordHarness(t)
	ctx := context.Background()
	if _, err := u.RecordStart(ctx, "d1", testCallHandle, ""); err != nil {
		t.Fatalf("first RecordStart: %v", err)
	}
	if _, err := u.RecordStart(ctx, "d1", testCallHandle, ""); apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("second RecordStart code=%v want precondition_failed", apierr.CodeOf(err))
	}
}

func TestRecordDefaultNamesDoNotCollideSequentially(t *testing.T) {
	u, ml, _ := recordHarness(t)
	ctx := context.Background()

	n1, err := u.RecordStart(ctx, "d1", testCallHandle, "")
	if err != nil {
		t.Fatal(err)
	}
	_ = ml.recorder().Write(make([]int16, codec.SamplesPerFrame))
	if _, _, err := u.RecordStop(ctx, "d1", testCallHandle, ""); err != nil {
		t.Fatal(err)
	}
	n2, err := u.RecordStart(ctx, "d1", testCallHandle, "")
	if err != nil {
		t.Fatalf("second RecordStart after stop: %v", err)
	}
	if n1 != "recording.wav" || n2 != "recording-2.wav" {
		t.Fatalf("names=%q,%q want recording.wav,recording-2.wav", n1, n2)
	}
}

// TestConcurrentRecordStopHasExactlyOneWinner: RecordStop's Swap(nil) claim
// must resolve two concurrent stops to exactly one winner (governing spec
// §6.0's concurrent-tool-call invariant), matching the same guarantee
// TestRecordSecondStartWhileActiveIsPreconditionFailed asserts for starts.
func TestConcurrentRecordStopHasExactlyOneWinner(t *testing.T) {
	u, ml, _ := recordHarness(t)
	ctx := context.Background()
	if _, err := u.RecordStart(ctx, "d1", testCallHandle, ""); err != nil {
		t.Fatal(err)
	}
	_ = ml.recorder().Write(make([]int16, codec.SamplesPerFrame))

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = u.RecordStop(ctx, "d1", testCallHandle, "")
		}(i)
	}
	wg.Wait()

	var oks, failed int
	for _, err := range errs {
		switch {
		case err == nil:
			oks++
		case apierr.CodeOf(err) == apierr.CodePreconditionFailed:
			failed++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if oks != 1 || failed != 1 {
		t.Fatalf("oks=%d failed=%d want 1,1", oks, failed)
	}
}

// stopDuringCreate wraps a session.ArtifactStore so that Create can trigger a
// hook right after the real Create returns (and before RecordStart proceeds to
// NewWAVRecorder/installRecorder), simulating a concurrent teardown landing in
// the middle of RecordStart's real I/O window. The returned writer is wrapped
// with a closeCountingWriter so the test can prove the self-reclaim branch's
// rec.Close() genuinely ran, rather than merely checking the artifact file
// exists on disk: store.Resolve is a bare os.Stat + os.Open
// (internal/artifact/store.go:123-141) that never parses the WAV, so it
// cannot tell a properly finalized file from an unfinalized placeholder —
// deleting the self-reclaim's rec.Close() call entirely still leaves a
// stat-able, openable file on disk (NewWAVRecorder already wrote the
// placeholder header before Close would ever run), which is exactly why that
// check alone was provably vacuous under mutation testing.
type stopDuringCreate struct {
	session.ArtifactStore
	hook   func()
	closes *int
}

func (s stopDuringCreate) Create(ctx context.Context, callHandle, name string) (io.WriteCloser, error) {
	w, err := s.ArtifactStore.Create(ctx, callHandle, name)
	s.hook()
	if err != nil {
		return w, err
	}
	at, ok := w.(io.WriterAt)
	if !ok {
		return w, err // NewWAVRecorder will itself reject a non-WriterAt sink
	}
	return &closeCountingWriter{WriteCloser: w, at: at, closes: s.closes}, nil
}

// closeCountingWriter wraps the artifact writer WAVRecorder holds, counting
// Close calls. On the self-reclaim path under test, WAVRecorder.Close is the
// ONLY thing that ever closes this writer, so closes == 1 afterward is a
// direct, content-independent proof that the finalize genuinely executed.
type closeCountingWriter struct {
	io.WriteCloser
	at     io.WriterAt
	closes *int
}

func (c *closeCountingWriter) WriteAt(p []byte, off int64) (int, error) { return c.at.WriteAt(p, off) }

func (c *closeCountingWriter) Close() error {
	*c.closes++
	return c.WriteCloser.Close()
}

// TestRecordStartSelfReclaimsIfTeardownWonRace is a DETERMINISTIC regression
// test for the RecordStart-races-Hangup/onBye window: Artifacts.Create and
// NewWAVRecorder are real I/O performed with u.calls.mu released, so a
// concurrent call teardown can forget the dialog and run mediaLoop.stop() to
// completion (including its own recorder finalize) while RecordStart is still
// in that window, before it ever reaches installRecorder.
//
// Under claimOp/installRecorder, setting the stopped flag BEFORE calling
// RecordStart would make claimOp refuse the claim immediately — RecordStart
// would short-circuit before creating any artifact, so the disk-artifact
// assertions below would never be exercised and this test would silently stop
// covering the real §6.3 install-races-teardown race window. Instead, the
// stopDuringCreate wrapper flips the stopped state DURING artifact creation
// (via ml.markStopped(), mirroring what a concurrent stop() actually does),
// simulating the race actually happening mid-flight rather than simulating it
// having already happened — reproducing deterministically every run instead
// of only occasionally under -race.
//
// Nothing is ever written to the orphaned recorder on this path: installing
// the tap fails BEFORE any RX frame could ever reach it (that IS the point
// under test), so the correct expectation is a decoded sample count of 0, not
// a non-empty one — matching TestStopFinalizesOrphanedRecorder's sibling
// pattern of decoding the resulting WAV to prove the header was genuinely
// patched, rather than merely asserting the file is resolvable.
func TestRecordStartSelfReclaimsIfTeardownWonRace(t *testing.T) {
	u, ml, store := recordHarness(t)
	ctx := context.Background()

	var closes int
	u.cfg.Artifacts = stopDuringCreate{ArtifactStore: store, hook: func() { ml.markStopped() }, closes: &closes}

	name, err := u.RecordStart(ctx, "d1", testCallHandle, "")
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("RecordStart racing a completed stop() code=%v want precondition_failed", apierr.CodeOf(err))
	}
	if name != "" {
		t.Fatalf("name=%q want empty on self-reclaim", name)
	}
	if ml.currentOp() != opNone {
		t.Fatal("RecordStart did not release the play-or-record slot on self-reclaim")
	}
	// The self-reclaim branch's rec.Close() must have genuinely run. (A check
	// that ml.recorder() == nil here would be vacuous: installRecorder returns
	// false and never assigns ml.st.rec on this path in the first place, so
	// nothing was ever installed to "self-reclaim" from ml's point of view —
	// the surrounding assertions already cover that installRecorder correctly
	// refused. What actually needs proving is that RecordStart's own local
	// `rec` — the one it created and then had to finalize itself — was
	// genuinely closed.)
	if closes != 1 {
		t.Fatalf("artifact writer Close calls=%d want 1 — self-reclaim did not finalize the recorder", closes)
	}
	// And the resulting file genuinely parses as a valid canonical WAV (not a
	// truncated or corrupt write), with the decoded sample count matching what
	// was actually written on this path: nothing.
	_, rc, err := store.Resolve(ctx, store.URI(testCallHandle, "recording.wav"))
	if err != nil {
		t.Fatalf("Resolve after self-reclaim: %v", err)
	}
	defer func() { _ = rc.Close() }()
	back, err := codec.ReadWAV(rc)
	if err != nil {
		t.Fatalf("ReadWAV after self-reclaim: %v", err)
	}
	if len(back) != 0 {
		t.Fatalf("decoded samples=%d want 0 (no frame ever reached the orphaned recorder)", len(back))
	}
}

func TestRecordStartIsRefusedDuringAControlOp(t *testing.T) {
	u, _, _ := recordHarness(t)
	u.calls.mu.Lock()
	u.calls.byID["d1"].phase = phaseControlOp
	u.calls.mu.Unlock()
	_, err := u.RecordStart(context.Background(), "d1", testCallHandle, "")
	if err == nil || apierr.CodeOf(err) != apierr.CodePreconditionFailed ||
		!strings.Contains(err.Error(), "control operation is in progress") {
		t.Fatalf("RecordStart during a control op err=%v want precondition_failed", err)
	}
}

func TestRecordStopIsRefusedDuringAControlOp(t *testing.T) {
	u, _, _ := recordHarness(t)
	ctx := context.Background()
	if _, err := u.RecordStart(ctx, "d1", testCallHandle, ""); err != nil {
		t.Fatalf("RecordStart: %v", err)
	}
	u.calls.mu.Lock()
	u.calls.byID["d1"].phase = phaseControlOp
	u.calls.mu.Unlock()
	_, _, err := u.RecordStop(ctx, "d1", testCallHandle, "")
	if err == nil || apierr.CodeOf(err) != apierr.CodePreconditionFailed ||
		!strings.Contains(err.Error(), "control operation is in progress") {
		t.Fatalf("RecordStop during a control op err=%v want precondition_failed", err)
	}
}
