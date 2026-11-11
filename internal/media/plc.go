package media

// PLC is the §6.5.1 packet-loss concealer: it replays the last decoded frame
// attenuated 6 dB (×0.5) per successive concealed frame, going to hard silence
// after 4 consecutive concealments. It NEVER touches the passive counters —
// concealment improves what a recording sounds like, not what tier-1 metrics
// report. Single-goroutine-affine to the RX loop; no lock.
type PLC struct {
	frameSamples int
	last         []int16
	consecutive  int
}

// NewPLC builds a PLC concealer for a frameSamples-sample frame size.
func NewPLC(frameSamples int) *PLC {
	if frameSamples < 1 {
		frameSamples = 1
	}
	return &PLC{frameSamples: frameSamples}
}

// Observe records a real decoded frame and resets the decay counter.
func (p *PLC) Observe(frame []int16) {
	p.last = append(p.last[:0], frame...)
	p.consecutive = 0
}

// Conceal produces one concealed frame. The Nth consecutive concealed frame is
// the last real frame scaled by 0.5^N, and is hard silence at N >= 4.
func (p *PLC) Conceal() []int16 {
	p.consecutive++
	out := make([]int16, p.frameSamples)
	if p.consecutive >= 4 || len(p.last) == 0 {
		return out // silence
	}
	shift := uint(p.consecutive) // 0.5^N via arithmetic right shift
	for i := 0; i < p.frameSamples && i < len(p.last); i++ {
		out[i] = p.last[i] >> shift
	}
	return out
}
