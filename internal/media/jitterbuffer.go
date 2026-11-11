package media

// SeqDelta is the 16-bit modular signed distance a-b, in [-32768, 32767]. It is
// the ONLY sequence comparison the RX path uses (§6.5.1): a plain unsigned `>`
// mis-scores a reorder across the uint16 wrap as tens of thousands of packets,
// which is the vendored engine's documented bug (§14.2).
func SeqDelta(a, b uint16) int { return int(int16(a - b)) }

// PushOutcome classifies how a received frame was placed relative to the
// playout cursor. The RX loop maps each to exactly one quality counter.
type PushOutcome int

// PushOutcome values classify a JitterBuffer.Push result.
const (
	OutcomePlaced    PushOutcome = iota // in order at the front of the window
	OutcomeReorder                      // in window but behind the highest seen (out_of_order)
	OutcomeDuplicate                    // a slot at/after the cursor was already filled
	OutcomeLate                         // slot already played out (late_discards)
)

// JitterBuffer is the §6.5.1 fixed-delay RX buffer: a sequence-indexed slot map
// with a monotonic playout cursor. It is PURE and single-goroutine-affine to the
// RX read loop; it carries no lock because nothing else touches it.
type JitterBuffer struct {
	depth   int
	slots   map[uint16][]int16
	nextPop uint16
	highest uint16
	started bool
}

// NewJitterBuffer builds a JitterBuffer holding depthPackets packets.
func NewJitterBuffer(depthPackets int) *JitterBuffer {
	if depthPackets < 1 {
		depthPackets = 1
	}
	return &JitterBuffer{depth: depthPackets, slots: map[uint16][]int16{}}
}

// Depth returns the buffer's configured depth in packets.
func (jb *JitterBuffer) Depth() int { return jb.depth }

// Buffered returns the number of packets currently held.
func (jb *JitterBuffer) Buffered() int { return len(jb.slots) }

// Push places a decoded frame into its sequence slot and classifies it.
func (jb *JitterBuffer) Push(seq uint16, frame []int16) PushOutcome {
	if !jb.started {
		jb.started, jb.nextPop, jb.highest = true, seq, seq
		jb.slots[seq] = frame
		return OutcomePlaced
	}
	// Already played out: seq strictly before the playout cursor.
	if SeqDelta(seq, jb.nextPop) < 0 {
		return OutcomeLate
	}
	if _, filled := jb.slots[seq]; filled {
		return OutcomeDuplicate
	}
	jb.slots[seq] = frame
	if SeqDelta(seq, jb.highest) > 0 {
		jb.highest = seq
		return OutcomePlaced
	}
	return OutcomeReorder
}

// Pop returns the frame at the playout cursor and advances it by one slot.
// present == false is an empty slot: the RX loop conceals it via PLC and counts
// it in packets_lost (§6.5.1).
func (jb *JitterBuffer) Pop() (frame []int16, present bool) {
	f, ok := jb.slots[jb.nextPop]
	if ok {
		delete(jb.slots, jb.nextPop)
	}
	jb.nextPop++
	return f, ok
}
