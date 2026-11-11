// Package quality is the passive tier-1 voice-quality accumulator and the
// simplified ITU-T G.107 E-model. It is PURE: the RX/TX goroutines in
// internal/sipua feed it counters and read a Snapshot; it owns no I/O.
package quality

import "math"

// G.711 (PCMU/PCMA) E-model impairment constants (ITU-T G.113 Appendix I):
// equipment impairment factor Ie = 0 and packet-loss robustness Bpl = 25.1.
// Both G.711 laws share them.
const (
	g711Ie  = 0.0
	g711Bpl = 25.1
	// R0 is the default basic signal-to-noise ratio (ITU-T G.107); Is and A are
	// held at 0 in this simplified model (no quantization/loudness impairments,
	// no advantage factor on a wired path).
	emodelR0 = 93.2
)

func ieBplFor(codecName string) (ie, bpl float64) {
	switch codecName {
	case "PCMU", "PCMA":
		return g711Ie, g711Bpl
	default:
		return g711Ie, g711Bpl // only G.711 exists this wave
	}
}

// RFactor folds loss and jitter through the simplified E-model. Ie_eff is the
// standard effective equipment impairment for random loss:
//
//	Ie_eff = Ie + (95 - Ie) * Ppl/(Ppl + Bpl)
//
// and Id is the standard delay impairment for a mean one-way delay Ta built from
// packetisation (20 ms), the fixed jitter buffer depth, and twice the observed
// mean jitter. R = R0 - Id - Ie_eff.
func RFactor(lossPct, jitterAvgMs float64, codecName string, jitterBufferMS int) float64 {
	ie, bpl := ieBplFor(codecName)
	ppl := lossPct
	if ppl < 0 {
		ppl = 0
	}
	ieEff := ie + (95.0-ie)*ppl/(ppl+bpl)
	ta := 20.0 + float64(jitterBufferMS) + 2.0*jitterAvgMs
	id := delayImpairment(ta)
	r := emodelR0 - id - ieEff
	if r < 0 {
		return 0
	}
	if r > 100 {
		return 100
	}
	return r
}

// delayImpairment is the ITU-T G.107 simplified delay term. Below 100 ms the
// contribution is negligible; above it, it grows per the standard piecewise
// approximation.
func delayImpairment(ta float64) float64 {
	if ta < 100 {
		return 0
	}
	x := math.Log(ta/100) / math.Log(2)
	return 25 * (math.Pow(1+math.Pow(x, 6), 1.0/6) -
		3*math.Pow(1+math.Pow(x/3, 6), 1.0/6) + 2)
}

// RToMOS is the ITU-T G.107 Annex B R-factor-to-MOS mapping.
func RToMOS(r float64) float64 {
	if r <= 0 {
		return 1.0
	}
	if r >= 100 {
		return 4.5
	}
	mos := 1.0 + 0.035*r + r*(r-60.0)*(100.0-r)*7.0e-6
	if mos < 1.0 {
		return 1.0
	}
	if mos > 4.5 {
		return 4.5
	}
	return mos
}
