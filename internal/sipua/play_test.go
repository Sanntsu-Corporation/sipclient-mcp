package sipua

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// writePromptWAV writes a canonical 8k/mono/16-bit WAV of `frames` 20ms frames
// of constant value v and returns its path.
func writePromptWAV(t *testing.T, dir string, frames int, v int16) string {
	t.Helper()
	pcm := make([]int16, frames*codec.SamplesPerFrame)
	for i := range pcm {
		pcm[i] = v
	}
	dataLen := len(pcm) * 2
	var b bytes.Buffer
	b.WriteString("RIFF")
	_ = binary.Write(&b, binary.LittleEndian, uint32(36+dataLen))
	b.WriteString("WAVE")
	b.WriteString("fmt ")
	_ = binary.Write(&b, binary.LittleEndian, uint32(16))
	_ = binary.Write(&b, binary.LittleEndian, uint16(1))
	_ = binary.Write(&b, binary.LittleEndian, uint16(1))
	_ = binary.Write(&b, binary.LittleEndian, uint32(8000))
	_ = binary.Write(&b, binary.LittleEndian, uint32(16000))
	_ = binary.Write(&b, binary.LittleEndian, uint16(2))
	_ = binary.Write(&b, binary.LittleEndian, uint16(16))
	b.WriteString("data")
	_ = binary.Write(&b, binary.LittleEndian, uint32(dataLen))
	for _, s := range pcm {
		_ = binary.Write(&b, binary.LittleEndian, s)
	}
	path := filepath.Join(dir, "p.wav")
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// playHarness builds a UA with one answered dialog carrying a live mediaLoop
// whose TX goroutine is NOT started (we drive Frame() by hand), so Play's swap
// and completion logic is tested deterministically.
func playHarness(t *testing.T, promptPath string) (*UA, *dialog, *mediaLoop) {
	t.Helper()
	u := &UA{cfg: Config{Prompts: map[string]string{"prompt-1": promptPath}}}
	ml := &mediaLoop{emit: func(session.UAEvent) {}}
	ml.assemble(nil, nil)
	d := &dialog{id: "d1", phase: phaseAnswered, mediaLoop: ml}
	u.register(d)
	return u, d, ml
}

func TestPlayUnregisteredPromptIsInvalidArgument(t *testing.T) {
	u, _, _ := playHarness(t, writePromptWAV(t, t.TempDir(), 1, 1))
	_, err := u.Play(context.Background(), "d1", "no-such-prompt", 1, true)
	if code := apierr.CodeOf(err); code != apierr.CodeInvalidArgument {
		t.Fatalf("code=%v want invalid_argument", code)
	}
}

func TestPlaySwapsSourceAndComputesDuration(t *testing.T) {
	u, _, ml := playHarness(t, writePromptWAV(t, t.TempDir(), 3, 42)) // 3 frames

	// wait_complete=false returns immediately with the deterministic duration.
	dur, err := u.Play(context.Background(), "d1", "prompt-1", 2, false)
	if err != nil {
		t.Fatalf("Play: %v", err)
	}
	if dur != int64(3*2*20) {
		t.Fatalf("duration=%d want %d", dur, 3*2*20)
	}
	// The TX source is now the prompt.
	if ml.currentSrc().Frame()[0] != 42 {
		t.Fatal("Play did not swap TX to the prompt source")
	}
	// A second Play while the first is active fails precondition.
	if _, err := u.Play(context.Background(), "d1", "prompt-1", 1, false); apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("second Play code=%v want precondition_failed", apierr.CodeOf(err))
	}
}

// TestPlayCtxCancellationUnblocksAndFreesTheSlot is B13's Play-side mutation
// proof. Before the fix, Play discarded its ctx parameter (`_
// context.Context`) entirely: a caller cancelling mid-wait had no effect and
// Play stayed blocked in its select until ps.Done() (never, since this test
// deliberately never drives Frame()) or ml.done (never, since the loop is
// never stopped) — i.e. forever. The fix adds a third `case <-ctx.Done():`
// arm that frees the slot and returns a classifiable cancelled error.
func TestPlayCtxCancellationUnblocksAndFreesTheSlot(t *testing.T) {
	// 5 frames: plenty that this test's own bounded wait will never exhaust it
	// by accident (nothing here calls Frame()).
	u, _, ml := playHarness(t, writePromptWAV(t, t.TempDir(), 5, 7))
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	var playErr error
	go func() {
		_, playErr = u.Play(ctx, "d1", "prompt-1", 1, true)
		close(done)
	}()

	// Wait for Play to actually claim the slot (i.e. reach its blocking
	// select) before cancelling, so cancel() cannot race ahead of the claim.
	waitFor(t, func() bool { return ml.currentOp() == opPlay })
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Play did not return within 2s of ctx cancellation — it is still blocked on " +
			"ps.Done()/ml.done, neither of which this test ever triggers (B13)")
	}
	if apierr.CodeOf(playErr) != apierr.CodeCancelled {
		t.Fatalf("code=%v want cancelled", apierr.CodeOf(playErr))
	}
	if ml.currentOp() != opNone {
		t.Fatal("the media slot must be free after a ctx-cancelled Play")
	}
	// The slot is PROVABLY free: a subsequent claim on the same loop succeeds.
	if !ml.claimOp(opPlay, nil) {
		t.Fatal("claimOp after a ctx-cancelled Play should succeed — the slot must be provably free")
	}
}

// TestPlayCtxCancelReleaseIsInstanceScopedNotBareRelease is a Rule 9 fix-round
// mutation proof (a fresh verifier subagent found this after B11/B13/B12
// landed): Play's ctx.Done() arm called the bare, unconditional releaseOp()
// instead of the instance-scoped releaseOpFor(ps) its OWN ml.done arm — and
// B12's whole point — already uses. DTMFSource/PromptSource.finish() call
// onExhaust (which correctly releases via releaseOpFor) BEFORE closing
// Done(), so there is a real window where A's slot has already been freed and
// re-claimed by a newer op (B) by the time A's ctx.Done() arm actually runs
// (ps.Done() and ctx.Done() can both end up ready near-simultaneously, and
// select does not prefer one over the other) — a bare releaseOp() there
// clobbers B's claim exactly like the ml.done arm's would have, pre-B12.
//
// This drives the exact scenario deterministically rather than racing the
// select: A's own release is simulated directly via releaseOpFor (the same
// call finish() itself would make), which frees the slot WITHOUT closing
// ps.Done() — so A's own Play call is still parked in its select with only
// ctx.Done() live to fire once cancelled, no non-determinism required.
func TestPlayCtxCancelReleaseIsInstanceScopedNotBareRelease(t *testing.T) {
	u, _, ml := playHarness(t, writePromptWAV(t, t.TempDir(), 5, 1))
	ctxA, cancelA := context.WithCancel(context.Background())

	doneA := make(chan struct{})
	go func() {
		_, _ = u.Play(ctxA, "d1", "prompt-1", 1, true)
		close(doneA)
	}()
	waitFor(t, func() bool { return ml.currentOp() == opPlay })
	srcA := ml.currentSrc()

	// Simulate A's onExhaust having ALREADY fired legitimately (as if the
	// prompt had actually finished playing) — the same release call
	// PromptSource.finish() itself makes. A's ps.Done() is deliberately NOT
	// closed here, so A's own Play goroutine stays parked in its select.
	ml.releaseOpFor(srcA)
	if ml.currentOp() != opNone {
		t.Fatal("releaseOpFor(A) did not free the slot")
	}

	// A NEWER op (B) claims the now-free slot.
	if _, err := u.Play(context.Background(), "d1", "prompt-1", 1, false); err != nil {
		t.Fatalf("second Play (B): %v", err)
	}
	if ml.currentOp() != opPlay {
		t.Fatal("B's claim did not land")
	}
	srcB := ml.currentSrc()

	// NOW cancel A's ORIGINAL ctx. A's select has only ctx.Done() ready
	// (ps.Done() was never closed, ml.done was never closed), so this
	// deterministically drives A's ctx.Done() arm.
	cancelA()
	select {
	case <-doneA:
	case <-time.After(2 * time.Second):
		t.Fatal("Play(A) did not return within 2s of its own ctx cancellation")
	}

	// B's claim MUST survive: A's now-stale release must be a no-op.
	if ml.currentOp() != opPlay {
		t.Fatal("B's claim was cleared by A's stale ctx-cancellation release — Play's ctx.Done() " +
			"arm must use releaseOpFor(ps), not the bare releaseOp()")
	}
	if ml.currentSrc() != srcB {
		t.Fatal("B's installed source was clobbered by A's stale ctx-cancellation release")
	}
}

func TestPlayWaitCompleteBlocksUntilExhaustionAndRestores(t *testing.T) {
	u, _, ml := playHarness(t, writePromptWAV(t, t.TempDir(), 1, 9)) // 1 frame
	prior := ml.currentSrc()

	done := make(chan int64, 1)
	go func() {
		dur, err := u.Play(context.Background(), "d1", "prompt-1", 1, true)
		if err != nil {
			t.Errorf("Play: %v", err)
		}
		done <- dur
	}()

	// Drive the source like the TX ticker would: pull frames until the prompt
	// exhausts, which restores `prior`, closes the completion channel and
	// unblocks Play.
	deadline := time.After(2 * time.Second)
	for {
		src := ml.currentSrc()
		src.Frame()
		select {
		case dur := <-done:
			if dur != 20 {
				t.Fatalf("duration=%d want 20", dur)
			}
			if ml.currentSrc() != prior {
				t.Fatal("Play did not restore the prior source on exhaustion")
			}
			if ml.currentOp() != opNone {
				t.Fatal("busy not released after exhaustion")
			}
			return
		case <-deadline:
			t.Fatal("Play(wait_complete) did not return")
		default:
		}
	}
}
