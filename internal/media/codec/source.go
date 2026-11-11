package codec

import "math"

// AudioSource yields one 20 ms (160-sample) PCM frame per call. The TX ticker
// pulls a frame each tick and hands it to Encode. Production TX uses a silence
// source (no media_play until W5); the e2e gate uses a SineSource.
type AudioSource interface {
	Frame() []int16
}

type silenceSource struct{}

// NewSilenceSource returns comfort-silence frames — real RTP is still sent,
// exercising the full jitter/PLC/quality/SRTP pipeline on the peer's RX.
func NewSilenceSource() AudioSource { return silenceSource{} }

func (silenceSource) Frame() []int16 { return make([]int16, SamplesPerFrame) }

// SineSource generates a continuous sine tone as 160-sample PCM frames. Ported
// from the vendored engine's generateSinePCMU math (calltester/audio.go), but
// yielding int16 PCM (not pre-encoded PCMU) so the TX path runs the real codec.
// INTERNAL ONLY: never exposed through any MCP tool (locked decision 3).
type SineSource struct {
	freqHz float64
	n      int64 // absolute sample index, so phase is continuous across frames
}

// NewSineSource builds a SineSource generating a tone at freqHz.
func NewSineSource(freqHz float64) *SineSource { return &SineSource{freqHz: freqHz} }

// Frame returns the next 160-sample PCM frame.
func (s *SineSource) Frame() []int16 {
	const sampleRate = 8000.0
	out := make([]int16, SamplesPerFrame)
	for i := range out {
		t := float64(s.n) / sampleRate
		out[i] = int16(math.Sin(2.0*math.Pi*s.freqHz*t) * 32767.0)
		s.n++
	}
	return out
}

// FramesFromPCM chunks PCM into SamplesPerFrame-sized frames, zero-padding the
// final partial frame so every frame the TX ticker pulls is exactly one 20 ms
// G.711 frame.
func FramesFromPCM(pcm []int16) [][]int16 {
	if len(pcm) == 0 {
		return nil
	}
	n := (len(pcm) + SamplesPerFrame - 1) / SamplesPerFrame
	frames := make([][]int16, n)
	for i := 0; i < n; i++ {
		frame := make([]int16, SamplesPerFrame)
		copy(frame, pcm[i*SamplesPerFrame:min((i+1)*SamplesPerFrame, len(pcm))])
		frames[i] = frame
	}
	return frames
}

// PromptSource is an AudioSource over pre-decoded prompt PCM (media_play, §3.3).
// It serves repeat×len(frames) prompt frames and then silence forever; the TX
// ticker's `pcm := src.Frame()` call is unchanged. On exhaustion it fires
// onExhaust once (the caller restores the prior source there) and closes Done().
//
// It is single-consumer-affine to the TX goroutine, which is the only caller of
// Frame(); the once-guard and the done channel are the only shared state, and
// Done() is a plain receive from another goroutine — no lock is needed because
// the channel close happens-before the receive.
type PromptSource struct {
	frames    [][]int16
	total     int // repeat * len(frames)
	idx       int
	onExhaust func()
	doneCh    chan struct{}
}

// NewPromptSource builds a prompt source. repeat < 1 is treated as 1. onExhaust
// may be nil.
func NewPromptSource(frames [][]int16, repeat int, onExhaust func()) *PromptSource {
	if repeat < 1 {
		repeat = 1
	}
	return &PromptSource{
		frames:    frames,
		total:     repeat * len(frames),
		onExhaust: onExhaust,
		doneCh:    make(chan struct{}),
	}
}

// Frame returns the next prompt frame, or silence once exhausted. The first call
// past the end fires onExhaust and closes Done().
func (p *PromptSource) Frame() []int16 {
	if p.idx >= p.total {
		p.finish()
		return make([]int16, SamplesPerFrame)
	}
	f := p.frames[p.idx%len(p.frames)]
	p.idx++
	// This was the final real frame; the NEXT call will be silence, but we
	// only signal completion once, on that next call, so the last real
	// frame is guaranteed to have been pulled before the caller unblocks.
	return f
}

func (p *PromptSource) finish() {
	select {
	case <-p.doneCh:
		return // already finished
	default:
	}
	// Release-before-close is INTENTIONAL, not something to reverse (B12):
	// releasing the media-loop slot after Close() would let a caller doing
	// two sequential Plays hit a spurious precondition_failed if the second
	// claim raced the first release. The remaining hazard — a stale onExhaust
	// firing a second time and clobbering a NEWER claim — is closed on the
	// internal/sipua side, by scoping the release to the specific source it
	// was claimed for (mediaLoop.releaseOpFor), not by reordering these two
	// calls.
	if p.onExhaust != nil {
		p.onExhaust()
	}
	close(p.doneCh)
}

// Done is closed once the prompt is exhausted.
func (p *PromptSource) Done() <-chan struct{} { return p.doneCh }

// DurationMs is the deterministic playback length: total frames × 20 ms.
func (p *PromptSource) DurationMs() int64 { return int64(p.total) * 20 }
