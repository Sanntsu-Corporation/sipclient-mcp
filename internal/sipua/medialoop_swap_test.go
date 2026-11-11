package sipua

import (
	"bytes"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
)

func TestMediaLoopSourceSwapIsAtomic(t *testing.T) {
	ml := &mediaLoop{}
	ml.assemble(nil, nil)

	// Default source after assemble is silence.
	if _, ok := ml.currentSrc().(interface{ Frame() []int16 }); !ok {
		t.Fatal("assemble left no default source")
	}
	first := ml.currentSrc().Frame()
	if len(first) != codec.SamplesPerFrame {
		t.Fatalf("default frame len=%d", len(first))
	}

	// Swap to a prompt source and confirm currentSrc observes it.
	ps := codec.NewPromptSource([][]int16{fill160(7)}, 1, nil)
	var swapped codec.AudioSource = ps
	if !ml.claimOp(opPlay, swapped) {
		t.Fatal("claimOp failed to install the swapped source")
	}
	if ml.currentSrc().Frame()[0] != 7 {
		t.Fatal("claimOp/currentSrc did not round-trip the prompt source")
	}
}

// TestReleaseOpForIsInstanceScopedCompareAndClear is B12's mutation proof.
// releaseOp() is unconditional: it always frees the slot and restores prior,
// which has a stale-release hazard for a source's OWN release hook (onExhaust,
// and the ml.done/ctx.Done() tie-break arms that back it up) — a source that
// already released once (e.g. via onExhaust) can have its hook fire a SECOND
// time (the tie-break arm racing it) after a NEWER source has already claimed
// the slot, and a bare releaseOp() would clobber that newer claim.
// releaseOpFor(src) closes this by only releasing when the slot is still
// claimed for THAT EXACT instance — a stale second release becomes a safe
// no-op, mirroring releaseEventTX's existing compare-and-clear for the
// independent event slot.
func TestReleaseOpForIsInstanceScopedCompareAndClear(t *testing.T) {
	ml := &mediaLoop{}
	ml.assemble(nil, nil)

	srcA := codec.NewPromptSource([][]int16{fill160(1)}, 1, nil)
	if !ml.claimOp(opPlay, srcA) {
		t.Fatal("claimOp(A)")
	}
	// A's own release (e.g. its onExhaust firing on genuine exhaustion).
	ml.releaseOpFor(srcA)
	if ml.currentOp() != opNone {
		t.Fatal("releaseOpFor(A) did not free the slot")
	}

	srcB := codec.NewPromptSource([][]int16{fill160(2)}, 1, nil)
	if !ml.claimOp(opPlay, srcB) {
		t.Fatal("claimOp(B) after A's release")
	}

	// STALE RELEASE: A's hook fires a SECOND time, simulating a delayed
	// ml.done/ctx.Done() tie-break arm racing A's own onExhaust. B's claim
	// must survive.
	ml.releaseOpFor(srcA)

	if ml.currentOp() != opPlay {
		t.Fatal("B's claim was cleared by A's stale second release — releaseOpFor must be a no-op " +
			"for an instance no longer holding the slot")
	}
	if ml.currentSrc() != srcB {
		t.Fatal("B's installed source was clobbered by A's stale second release")
	}
}

func TestMediaLoopBusyClaimIsExclusive(t *testing.T) {
	ml := &mediaLoop{}
	ml.assemble(nil, nil)
	if !ml.claimOp(opPlay, nil) {
		t.Fatal("first claim failed")
	}
	if ml.claimOp(opRecord, nil) {
		t.Fatal("second claim succeeded while busy")
	}
	ml.releaseOp()
	if !ml.claimOp(opPlay, nil) {
		t.Fatal("claim failed after release")
	}
}

func fill160(v int16) []int16 {
	f := make([]int16, codec.SamplesPerFrame)
	for i := range f {
		f[i] = v
	}
	return f
}

func TestStopFinalizesOrphanedRecorder(t *testing.T) {
	ml := &mediaLoop{}
	ml.assemble(nil, nil)
	// launch() is deliberately NOT called: ml.conn is nil in this unit harness
	// (no real socket), and this test targets stop()'s post-wg.Wait() finalize
	// specifically, not the runTX/runRX goroutine lifecycle (covered
	// elsewhere). An un-Add()ed WaitGroup's Wait() returns immediately, so
	// stop() reaches the finalize step the same as it would after a real
	// wg.Wait() drains two already-exited goroutines.

	mf := &memWriteCloserAt{}
	rec, err := codec.NewWAVRecorder(mf)
	if err != nil {
		t.Fatalf("NewWAVRecorder: %v", err)
	}
	_ = rec.Write(make([]int16, codec.SamplesPerFrame))
	if !ml.installRecorder(rec) {
		t.Fatal("installRecorder")
	}

	ml.stop() // simulates call teardown with an active, never-stopped recording

	// A never-patched placeholder header (data size 0) still parses via
	// ReadWAV as a valid, empty file — this assertion alone would not catch a
	// regression that skipped the finalize. Assert the DECODED SAMPLE COUNT
	// matches what was actually written, which only holds if Close() really
	// ran and patched the header's data size.
	back, err := codec.ReadWAV(bytes.NewReader(mf.buf))
	if err != nil {
		t.Fatalf("ReadWAV after stop(): %v", err)
	}
	if len(back) != codec.SamplesPerFrame {
		t.Fatalf("decoded samples=%d want %d — header was never finalized", len(back), codec.SamplesPerFrame)
	}
	if ml.recorder() != nil {
		t.Fatal("stop() did not clear the recorder tap")
	}
}

// memWriteCloserAt is the minimal io.WriteCloser + io.WriterAt WAVRecorder
// needs, without pulling in a real file for this unit test.
type memWriteCloserAt struct{ buf []byte }

func (m *memWriteCloserAt) Write(p []byte) (int, error) {
	m.buf = append(m.buf, p...)
	return len(p), nil
}
func (m *memWriteCloserAt) WriteAt(p []byte, off int64) (int, error) {
	end := int(off) + len(p)
	if end > len(m.buf) {
		m.buf = append(m.buf, make([]byte, end-len(m.buf))...)
	}
	copy(m.buf[off:end], p)
	return len(p), nil
}
func (m *memWriteCloserAt) Close() error { return nil }
