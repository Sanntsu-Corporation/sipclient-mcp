package codec

import (
	"testing"
)

func TestFramesFromPCMPadsFinalFrame(t *testing.T) {
	pcm := make([]int16, SamplesPerFrame+5) // 1 full frame + 5 samples
	for i := range pcm {
		pcm[i] = int16(i + 1)
	}
	frames := FramesFromPCM(pcm)
	if len(frames) != 2 {
		t.Fatalf("frames=%d want 2", len(frames))
	}
	if len(frames[1]) != SamplesPerFrame {
		t.Fatalf("padded frame len=%d want %d", len(frames[1]), SamplesPerFrame)
	}
	if frames[1][5] != 0 {
		t.Fatalf("pad sample = %d want 0", frames[1][5])
	}
	if frames[1][4] != pcm[SamplesPerFrame+4] {
		t.Fatalf("frame content not preserved")
	}
}

func TestPromptSourcePlaysThenSilencesAndSignals(t *testing.T) {
	frames := [][]int16{
		fillFrame(1), fillFrame(2), // 2 frames, repeat 2 => 4 real frames
	}
	var exhausted bool
	p := NewPromptSource(frames, 2, func() { exhausted = true })

	if p.DurationMs() != int64(4*20) {
		t.Fatalf("DurationMs=%d want %d", p.DurationMs(), 4*20)
	}

	seq := []int{1, 2, 1, 2} // repeat cycles through the frames
	for i, want := range seq {
		f := p.Frame()
		if f[0] != int16(want) {
			t.Fatalf("frame %d first sample=%d want %d", i, f[0], want)
		}
		select {
		case <-p.Done():
			t.Fatalf("Done() closed after only %d frames", i+1)
		default:
		}
	}
	// The next Frame() is past the end: it returns silence, fires onExhaust,
	// and closes Done().
	f := p.Frame()
	for _, s := range f {
		if s != 0 {
			t.Fatal("post-exhaustion frame is not silence")
		}
	}
	if !exhausted {
		t.Fatal("onExhaust did not fire")
	}
	select {
	case <-p.Done():
	default:
		t.Fatal("Done() not closed after exhaustion")
	}
	// Exhaustion is idempotent: further Frame() calls stay silent and do not panic.
	_ = p.Frame()
}

func fillFrame(v int16) []int16 {
	f := make([]int16, SamplesPerFrame)
	for i := range f {
		f[i] = v
	}
	return f
}
