package quality

import (
	"math"
	"sync"
)

// BurstGap is one §10.10 burst: a run of >= 2 consecutive missing sequence
// numbers, at the playout offset of its first missing packet.
type BurstGap struct {
	AtMs    int64 `json:"at_ms"`
	Packets int   `json:"packets"`
}

// Snapshot is the tier-1 §10.10 quality readout. tier is always 1 and the
// tier-2 fields (mos_lqo, pesq_raw, reference) are always null this wave.
type Snapshot struct {
	Tier               int        `json:"tier"`
	Codec              string     `json:"codec"`
	DurationMs         int64      `json:"duration_ms"`
	PacketsSent        int64      `json:"packets_sent"`
	PacketsReceived    int64      `json:"packets_received"`
	PacketsLost        int64      `json:"packets_lost"`
	LossPct            float64    `json:"loss_pct"`
	OutOfOrder         int64      `json:"out_of_order"`
	Duplicates         int64      `json:"duplicates"`
	LateDiscards       int64      `json:"late_discards"`
	RogueSourcePackets int64      `json:"rogue_source_packets"`
	TXUnderruns        int64      `json:"tx_underruns"`
	SRTPAuthFailures   int64      `json:"srtp_auth_failures"`
	BurstGaps          []BurstGap `json:"burst_gaps"`
	JitterMsAvg        float64    `json:"jitter_ms_avg"`
	JitterMsPeak       float64    `json:"jitter_ms_peak"`
	RFactor            float64    `json:"r_factor"`
	MOSEstimate        float64    `json:"mos_estimate"`
	MOSLQO             *float64   `json:"mos_lqo"`
	PESQRaw            *float64   `json:"pesq_raw"`
	Reference          *string    `json:"reference"`
}

// Accumulator holds one call's passive counters. It is written by the TX ticker
// goroutine (RecordSent/RecordTXUnderrun) and the RX read loop (everything
// else), and read by quality_get from a third goroutine, so it carries its own
// mutex — unlike the single-affine jitter buffer and SRTP contexts.
type Accumulator struct {
	mu               sync.Mutex
	sent             int64
	received         int64
	lost             int64
	outOfOrder       int64
	duplicates       int64
	lateDiscards     int64
	rogueSource      int64
	txUnderruns      int64
	srtpAuthFailures int64
	burstGaps        []BurstGap
	jitter           float64 // EWMA J
	jitterPeak       float64
	lastTransit      float64
	haveTransit      bool
}

// New builds an empty Accumulator.
func New() *Accumulator { return &Accumulator{} }

// RecordSent counts one packet sent.
func (a *Accumulator) RecordSent() { a.mu.Lock(); a.sent++; a.mu.Unlock() }

// RecordReceived counts one packet received.
func (a *Accumulator) RecordReceived() { a.mu.Lock(); a.received++; a.mu.Unlock() }

// RecordOutOfOrder counts one packet received out of sequence order.
func (a *Accumulator) RecordOutOfOrder() { a.mu.Lock(); a.outOfOrder++; a.mu.Unlock() }

// RecordDuplicate counts one duplicate packet.
func (a *Accumulator) RecordDuplicate() { a.mu.Lock(); a.duplicates++; a.mu.Unlock() }

// RecordLateDiscard counts one packet discarded as arriving too late to play out.
func (a *Accumulator) RecordLateDiscard() { a.mu.Lock(); a.lateDiscards++; a.mu.Unlock() }

// RecordSRTPAuthFailure counts one SRTP authentication failure.
func (a *Accumulator) RecordSRTPAuthFailure() { a.mu.Lock(); a.srtpAuthFailures++; a.mu.Unlock() }

// RecordRogueSource counts one packet rejected as coming from an unlatched source.
func (a *Accumulator) RecordRogueSource() { a.mu.Lock(); a.rogueSource++; a.mu.Unlock() }

// RecordConcealed counts a PLC-concealed empty slot: it is a lost packet (§6.5.1)
// even though PLC hid it from the recording.
func (a *Accumulator) RecordConcealed() { a.mu.Lock(); a.lost++; a.mu.Unlock() }

// RecordTXUnderrun counts frames of TX underrun.
func (a *Accumulator) RecordTXUnderrun(frames int) {
	a.mu.Lock()
	a.txUnderruns += int64(frames)
	a.mu.Unlock()
}

// RecordBurstGap records one §10.10 burst gap.
func (a *Accumulator) RecordBurstGap(atMs int64, packets int) {
	a.mu.Lock()
	a.burstGaps = append(a.burstGaps, BurstGap{AtMs: atMs, Packets: packets})
	a.mu.Unlock()
}

// RecordJitterSample updates the RFC 3550 interarrival jitter EWMA
// J += (|D| - J)/16 from consecutive packet transit times, tracking the peak.
func (a *Accumulator) RecordJitterSample(transitMs float64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.haveTransit {
		d := math.Abs(transitMs - a.lastTransit)
		a.jitter += (d - a.jitter) / 16.0
		if a.jitter > a.jitterPeak {
			a.jitterPeak = a.jitter
		}
	}
	a.lastTransit, a.haveTransit = transitMs, true
}

// Snapshot folds the counters through the E-model into r_factor and
// mos_estimate. srtp_auth_failures are deliberately absent from the loss inputs
// (§15.1 O2).
func (a *Accumulator) Snapshot(codecName string, durationMs int64, jitterBufferMS int) Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	total := a.received + a.lost
	lossPct := 0.0
	if total > 0 {
		lossPct = 100.0 * float64(a.lost) / float64(total)
	}
	r := RFactor(lossPct, a.jitter, codecName, jitterBufferMS)
	gaps := append([]BurstGap(nil), a.burstGaps...)
	return Snapshot{
		Tier: 1, Codec: codecName, DurationMs: durationMs,
		PacketsSent: a.sent, PacketsReceived: a.received, PacketsLost: a.lost,
		LossPct:            math.Round(lossPct*100) / 100,
		OutOfOrder:         a.outOfOrder,
		Duplicates:         a.duplicates,
		LateDiscards:       a.lateDiscards,
		RogueSourcePackets: a.rogueSource,
		TXUnderruns:        a.txUnderruns,
		SRTPAuthFailures:   a.srtpAuthFailures,
		BurstGaps:          gaps,
		JitterMsAvg:        math.Round(a.jitter*100) / 100,
		JitterMsPeak:       math.Round(a.jitterPeak*100) / 100,
		RFactor:            math.Round(r*100) / 100,
		MOSEstimate:        math.Round(RToMOS(r)*100) / 100,
		MOSLQO:             nil, PESQRaw: nil, Reference: nil,
	}
}
