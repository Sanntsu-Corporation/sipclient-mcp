package codec

import "math"

// Q.24 acceptance parameters. Both are REQUIREMENTS of the recommendation, not
// tuning knobs:
//
//   - dtmfMinToneMs: a tone shorter than 40 ms MUST NOT be accepted.
//   - dtmfQ24TwistDB: a digit whose two tones differ in level by up to 8 dB
//     MUST be accepted, in either direction.
const (
	dtmfMinToneMs  = 40
	dtmfQ24TwistDB = 8.0
)

// dtmfTwistBiasDB is how far the gate classify() applies must sit ABOVE Q.24's
// 8 dB limit, and it is not slack. The gate is applied to the ratio of two
// Goertzel bin magnitudes, which is a BIASED estimate of the tones' true level
// ratio; the gate must therefore be Q.24's limit widened by a bound on that
// bias over the SAME acceptance window Q.24 fixes — both tones anywhere within
// ±1.5 % of nominal, twist up to ±8 dB.
//
// The bias has exactly two sources. Each is bounded by measuring the ESTIMATOR
// (see TestTwistGateBudgetCoversTheEstimatorsMeasuredBias, which recomputes
// both from goertzelMag), never by measuring how many digits a candidate gate
// happens to let through:
//
//   - BIN ROLL-OFF, 3.84 dB. goertzelMag evaluates an unwindowed 160-sample
//     transform AT the nominal frequency, so a tone δ Hz off it measures low by
//     the Dirichlet roll-off |sin(πNδ/fs) / (N·sin(πδ/fs))|². The worst case
//     over Q.24's ±1.5 % is at the highest grid tone, where 1.5 % of 1633 Hz =
//     24.5 Hz is half a bin width: 3.84 dB measured, 3.75 dB analytically, the
//     0.09 dB difference being the tone's own negative-frequency image
//     rippling with frame phase. When one tone sits at that corner and its
//     partner is on grid, the entire 3.84 dB lands on the measured ratio.
//   - PARTNER-TONE LEAKAGE, 1.07 dB. Each bin also collects the other tone's
//     skirt, with a sign set by their relative phase. Measured over all 16
//     digits at Q.24's 8 dB limit with both tones ON grid, so that roll-off
//     contributes nothing, the worst perturbation of the measured ratio is
//     1.07 dB, at 941/1209 Hz — the closest grid pair. This is the same effect
//     testdata/dtmf/README.md records as "roughly 1-1.2 dB", and it is why the
//     spec-correct p8db vector measures 9.15 dB at a true 8.0 dB.
//
// 3.84 + 1.07 = 4.91, rounded UP to 5.0. Rounding a must-accept bound upward is
// always safe; rounding it down is a conformance failure. The two worst cases
// occur at different digits and so cannot coincide, which is why the bound is
// slightly loose: the worst ratio actually measured anywhere in the must-accept
// region is 12.74 dB against the resulting 13.0 dB gate.
//
// WHY THE PREVIOUS 10.0 dB WAS WRONG. It covered only the leakage term, because
// it was derived from the pinned Q.23 vectors — whose tones are all exactly on
// grid, making the roll-off term identically zero on every frame of every one
// of them, so it could not be seen there. Measured over Q.24's must-accept
// region (16 digits x both tones ±1.5 % at 0.25 % x twist ±8 dB at 2 dB x 10
// frame phases = 243,360 frames), a 10.0 dB gate rejected 4131 frames Q.24
// requires be accepted, every one of them attributed to this gate; at 13.0 the
// count is 0. The mandatory REJECT side does not pay for it: sweeping
// 500-1100 x 1050-1800 Hz at 1 Hz resolution for pairs more than 3.5 % from
// every grid tone, 0 of 133,125 decode at 10.0 dB and 0 at 13.0 dB — twist is
// not the gate that rejects them (purity and the frequency probes are), so
// widening it buys the acceptance side at no cost to the rejection side.
const dtmfTwistBiasDB = 5.0

// dtmfTwistDB is the level-ratio gate classify() applies: Q.24's requirement
// plus this estimator's worst-case bias over Q.24's own acceptance window.
const dtmfTwistDB = dtmfQ24TwistDB + dtmfTwistBiasDB // 13.0 dB

// dtmfEnergyFloor is the minimum per-tone Goertzel magnitude, normalised by
// frame length, below which a frame is treated as silence.
//
// THE NORMALISATION IS REAL AND classify() PERFORMS IT. goertzelMag returns
// |X|², which for an amplitude-A sine over N samples scales as (A*N/2)² — so
// the raw magnitude depends on the frame length and is NOT a level. Dividing
// by N² removes that dependence and leaves A²/4, a pure amplitude measure.
// (An earlier revision of this comment claimed the normalisation while the
// code compared raw |X|² against the constant, which made the floor about six
// orders of magnitude too permissive: a full-scale tone measures ~4.2e11 raw
// and the smallest tone that cleared every gate was amplitude 8, i.e. −72
// dBFS. The floor did no work at all.)
//
// The constant is therefore a LEVEL: 1.0e5 == A²/4 == peak amplitude 632,
// which is 20*log10(632/32768) = −34.3 dBFS ≈ −31 dBm0 for G.711 (digital
// full-scale sine = +3.14 dBm0). That is below the quietest tone Q.24's
// receiver dynamic range requires be recognised (about −25 dBm0 per
// frequency), so no tone the recommendation requires us to accept is cut off,
// while line noise and residual echo are.
//
// THE OPERATIVE MARGIN IS 1.44 dB, NOT 6. An earlier revision of this comment
// claimed "roughly 6 dB", which is the margin for an ON-GRID, ZERO-TWIST tone
// only — measured 6.30 dB. At the corner of the acceptance region Q.24
// actually mandates (both tones ±1.5 % off grid, 8 dB of twist, weaker tone at
// −25 dBm0) bin roll-off and leakage take most of it back: the worst
// normalised per-tone energy there is 1.394e5 against this 1.0e5 floor, i.e.
// 1.44 dB. Still conformant — sweeping that whole region with the weaker tone
// pinned at −25 dBm0 produces zero misses — but the headroom is a decibel and
// a half, so this floor is one of the two gates (with dtmfTwistDB) that a
// change to SamplesPerFrame would put straight into non-conformance.
//
// Measured margin on the pinned vectors, which are far louder: the worst
// normalised per-tone energy over every tone frame of all five files is 2.66e6
// on q23-16digit-p8db.pcm — 26x above this floor.
const dtmfEnergyFloor = 1.0e5

// dtmfMinPurity is the fraction of a frame's total energy that the two winning
// bins must together account for. Together with dtmfFreqProbeTol below it
// replaces what used to be missing entirely: an ABSOLUTE frequency check.
// relativeThreshold further down enforces only a relative, in-group one, which
// a tone 28 % off every grid frequency still passes.
//
// THE TWO GATES DO DIFFERENT JOBS AND NEITHER SUBSUMES THE OTHER. This one is
// an energy-accounting test: it rejects a frame whose energy is mostly
// somewhere other than the two bins that won, which is the case for gross
// off-grid tones and for broadband content such as speech and music (the
// talk-off risk that makes this Critical under dtmf_mode: inband). It is weak
// exactly where the other is strong: when ONE tone is exactly on grid, that
// tone alone contributes ~0.5 to purity, so no purity threshold compatible
// with Q.24's acceptance requirement can reject a partner tone that is merely
// 4 % off. dtmfFreqProbeTol handles that case per-tone.
//
// The measure is
//
//	purity = (lowBest + highBest) / ((N/2) * Σx[n]²)
//
// which is 1.0 for an ideal on-grid pair (each bin's |X|² = (A*N/2)² and each
// tone's share of Σx[n]² is A²N/2) and falls off as the input moves away from
// the bin centre, because an unwindowed 160-sample Goertzel is a narrow filter
// and off-centre energy leaks out of it into the frame total.
//
// WHERE 0.35 COMES FROM. Q.24 fixes both edges of the window and the threshold
// must fall between the two measured extremes:
//
//   - MUST ACCEPT: every digit with both tones anywhere within ±1.5 % of
//     nominal and up to Q.24's ±8 dB of twist. Swept at 0.25 % / 2 dB / 10
//     frame-phase resolution over all 16 digits, the minimum purity is 0.4475
//     ('D' = 941/1633, low +1.5 %, high −1.5 %, twist +8 dB — the worst case
//     because 1.5 % of 1633 Hz is half a bin width).
//   - MUST REJECT: any pair more than 3.5 % from every grid tone. Swept at
//     1 Hz over 500–1100 x 1050–1800 Hz with ±8 dB of twist, the maximum
//     purity among the pairs that pass the other gates is 0.2528 (672/1280).
//
// 0.35 is near the geometric midpoint of [0.2528, 0.4475]: 28 % of margin
// below the quietest signal we must accept and 38 % above the purest signal we
// must reject. The pinned Q.23 vectors' worst frame is 0.9473, and ordinary
// voiced-speech formant pairs — the phantom-digit risk this gate exists for,
// e.g. 500/1094 Hz, which used to decode '4' — measure 0.008 to 0.058, two
// orders of magnitude below the gate.
//
// NOT covered, deliberately: a tone in Q.24's UNDEFINED band, more than 1.5 %
// but at most 3.5 % off a grid tone (e.g. 745.79 Hz, which is 3.15 % below
// 770 Hz), may be accepted or rejected as the implementation likes.
const dtmfMinPurity = 0.35

// dtmfFreqProbeTol is the per-tone absolute frequency gate: the winning grid
// bin must out-measure two probe bins placed this far either side of it. If a
// probe wins, the energy that lit the bin is not actually AT the bin, and the
// frame is not that digit.
//
// WHY A PROBE PAIR RATHER THAN A THRESHOLD. A Goertzel bin's magnitude alone
// cannot say how far off centre its input is — a loud tone 4 % away and a
// quiet one dead centre measure the same. Comparing against probes at
// f0*(1±tol) removes the level dependence entirely: whichever of the three
// evaluation points is nearest the true frequency wins, so the test reduces to
// "is the tone nearer the grid than it is to the probes", i.e. |δ| < tol/2.
// This is what makes the gate a frequency test rather than another energy one,
// and it is why it costs four extra Goertzel evaluations per frame (12 bins,
// not 8) — see goertzelMag's note on the per-frame budget.
//
// WHERE 0.055 COMES FROM. The crossover sits at tol/2, which must land inside
// Q.24's UNDEFINED band — above the 1.5 % that must be accepted and below the
// 3.5 % beyond which rejection is mandatory. That alone bounds tol to
// (0.03, 0.07); leakage from the partner tone narrows it, so the plateau was
// measured rather than assumed. Over all 16 digits, both tones swept ±1.5 % at
// 0.25 %, twist ±8 dB at 2 dB, 8 frame phases, against both reject bands
// (one tone exact and its partner >3.5 % off; and both tones >3.5 % off, swept
// at 2 Hz over 500-1100 x 1050-1800 Hz):
//
//	tol     must-accept misses    reject-band leaks
//	0.030        28946                    0
//	0.035         1164                    0
//	0.040           55                    0
//	0.045            0                    0
//	0.050            0                    0
//	0.055            0                    0   <- chosen, mid-plateau
//	0.060            0                    0
//	0.065            0                    0
//
// 0.055 is the middle of the measured [0.045, 0.065] plateau.
//
// THE CROSSOVER IS A RANGE, NOT A POINT. An earlier revision of this comment
// gave it as "2.50-2.55 %", generalising from the 697 Hz row alone. Swept at
// 0.05 % over 8 frame phases in both directions, the deviation out to which
// acceptance is still total is 2.55 % off 697 Hz, 2.65-2.70 % off 941 and
// 1209 Hz, and only 2.25-2.40 % off 1633 Hz — the lowest, because 1.5 % of
// 1633 Hz is already half a bin width. Rejection is total by 2.55-2.95 %. So
// the spread is 2.25-2.70 %, and the margin above Q.24's 1.5 % acceptance
// bound is 0.75 points at 1633 Hz, not "about a point". Conformance is
// unaffected: every crossover still sits strictly inside Q.24's undefined
// (1.5 %, 3.5 %) band, so both bounds remain Q.24's and neither is tuning.
const dtmfFreqProbeTol = 0.055

// relativeThreshold is how far the winning bin must exceed the strongest OTHER
// bin in its own group. This is NOT a blanket enforcement of Q.24's ±1.5 %
// frequency tolerance — a tone measurably off that tolerance can still win
// this check (e.g. +4.0% off grid dominates its runner-up by ~24x). What it
// actually rejects is a frequency sitting near the MIDPOINT between two
// adjacent bins, where neither bin dominates because the tone's energy leaks
// into both roughly equally.
const relativeThreshold = 4.0

// DTMFDetector detects DTMF digits in a stream of 20 ms PCM frames using the
// Goertzel algorithm over the eight Q.23 bins.
//
// IT IS SINGLE-GOROUTINE-AFFINE and carries NO LOCK: runRX is its only caller,
// exactly as the jitter buffer and the PLC are (medialoop.go's runRX doc
// comment). Do not add a mutex; add a second detector instead if a second
// consumer ever appears.
//
// Reporting is once per tone, AT THE TONE'S END: a validated digit (Q.24's
// 40 ms floor, twist, purity, bin-dominance and absolute-frequency gates all
// still apply — they decide whether a run ever counts as a digit at all) keeps
// accumulating silently while it holds, and is only handed to the caller on
// the frame where classification changes — to a different digit, or to
// silence. durationMs at that point is the tone's TRUE elapsed length (20 ms
// frame-quantized), not a fixed floor value: this is what lets DurationMs mean
// the same thing for inband as it does for RFC 2833 (design spec §8 R2). A
// tone still sounding when Feed stops being called (e.g. the call ends
// mid-tone) is never reported — it was never observed to completion.
type DTMFDetector struct {
	// held is the digit currently accumulating (0 when none); runFrames is how
	// many consecutive frames it has been present. Because reporting happens at
	// the END of the run rather than as soon as the Q.24 floor is crossed,
	// runFrames at report time already IS the tone's true duration — no
	// separate "already reported" flag is needed.
	held      byte
	runFrames int
}

// NewDTMFDetector returns a detector with no tone in progress.
func NewDTMFDetector() *DTMFDetector { return &DTMFDetector{} }

// goertzelMag returns the squared magnitude of freq in frame. It is the
// textbook second-order recurrence: one multiply-add per sample per bin, eight
// grid bins per 20 ms frame plus up to four dtmfFreqProbeTol probes — at most
// 1920 multiply-adds per frame, which is why this can run inline on the RX
// goroutine. The probes are evaluated last in classify, so a frame that fails
// an earlier gate never pays for them.
func goertzelMag(frame []int16, freq float64) float64 {
	k := 2 * math.Cos(2*math.Pi*freq/dtmfSampleRate)
	var s1, s2 float64
	for _, v := range frame {
		s := float64(v) + k*s1 - s2
		s2, s1 = s1, s
	}
	return s1*s1 + s2*s2 - k*s1*s2
}

// strongestBin returns the index and magnitude of the largest bin, plus the
// largest magnitude among the others.
func strongestBin(frame []int16, freqs []float64) (idx int, best, runnerUp float64) {
	idx = -1
	for i, f := range freqs {
		m := goertzelMag(frame, f)
		switch {
		case m > best:
			idx, best, runnerUp = i, m, best
		case m > runnerUp:
			runnerUp = m
		}
	}
	return idx, best, runnerUp
}

// toneIsCentred reports whether the energy that won grid bin f0 with magnitude
// best is genuinely centred on f0, by checking it against probe bins
// dtmfFreqProbeTol either side. A tone nearer a probe than the grid frequency
// loses, whatever its level.
func toneIsCentred(frame []int16, f0, best float64) bool {
	return best > goertzelMag(frame, f0*(1-dtmfFreqProbeTol)) &&
		best > goertzelMag(frame, f0*(1+dtmfFreqProbeTol))
}

// classify decides which digit (if any) a single frame carries.
func classify(frame []int16) byte {
	lowIdx, lowBest, lowRunner := strongestBin(frame, dtmfLowFreqs[:])
	highIdx, highBest, highRunner := strongestBin(frame, dtmfHighFreqs[:])
	if lowIdx < 0 || highIdx < 0 {
		return 0
	}
	// Energy floor: silence and low-level noise are not tones. n2 is the frame
	// length squared — the normalisation dtmfEnergyFloor's derivation assumes,
	// which turns |X|² into the level A²/4.
	n2 := float64(len(frame)) * float64(len(frame))
	if lowBest/n2 < dtmfEnergyFloor || highBest/n2 < dtmfEnergyFloor {
		return 0
	}
	// Tone purity: the two winning bins must account for most of the frame's
	// energy, which is what enforces Q.24's absolute frequency tolerance (see
	// dtmfMinPurity). frameEnergy is > 0 here because the floor above passed.
	var frameEnergy float64
	for _, v := range frame {
		frameEnergy += float64(v) * float64(v)
	}
	if (lowBest+highBest)/(float64(len(frame))/2) < dtmfMinPurity*frameEnergy {
		return 0
	}
	// Bin dominance: rejects a frequency near the midpoint between two
	// adjacent bins, where no single bin dominates (see relativeThreshold).
	if lowRunner > 0 && lowBest < lowRunner*relativeThreshold {
		return 0
	}
	if highRunner > 0 && highBest < highRunner*relativeThreshold {
		return 0
	}
	// Q.24 twist: the two tones may differ by at most dtmfTwistDB. Magnitudes
	// are SQUARED, so the power ratio is the magnitude ratio and the dB figure
	// is 10*log10, not 20*log10.
	ratioDB := 10 * math.Log10(highBest/lowBest)
	if math.Abs(ratioDB) > dtmfTwistDB {
		return 0
	}
	// Absolute frequency tolerance, per tone: the energy that won each bin must
	// actually sit AT that bin and not merely nearest it. Last because it is the
	// only gate that costs further Goertzel evaluations (see dtmfFreqProbeTol).
	if !toneIsCentred(frame, dtmfLowFreqs[lowIdx], lowBest) ||
		!toneIsCentred(frame, dtmfHighFreqs[highIdx], highBest) {
		return 0
	}
	for digit, rc := range dtmfGrid {
		if rc[0] == lowIdx && rc[1] == highIdx {
			return digit
		}
	}
	return 0
}

// Feed consumes exactly one 20 ms frame. ok is true on the frame at which a
// held tone ENDS — classify() returns a different digit, or silence — and
// that tone met Q.24's 40 ms minimum somewhere during its run; durationMs is
// its TRUE elapsed length (runFrames * 20 ms), not merely proof the floor was
// crossed. Two presses of the same digit with an intervening gap still report
// as two separate digits, because the gap flushes the first run's report
// before the second run starts accumulating. A frame of the wrong length is
// ignored rather than panicking — runRX's decode always yields
// SamplesPerFrame, so a short frame means a caller bug, not a wire condition.
func (d *DTMFDetector) Feed(frame []int16) (byte, int, bool) {
	if len(frame) != SamplesPerFrame {
		return 0, 0, false
	}
	digit := classify(frame)
	if digit == d.held {
		// Run continues (including silence continuing as silence): keep
		// accumulating, nothing to report yet.
		if digit != 0 {
			d.runFrames++
		}
		return 0, 0, false
	}
	// Classification changed: the previous run, if any, just ended. Flush its
	// report only if it ever met the Q.24 minimum duration.
	var reportDigit byte
	var reportMs int
	var ok bool
	if d.held != 0 && d.runFrames*dtmfFrameMs >= dtmfMinToneMs {
		reportDigit, reportMs, ok = d.held, d.runFrames*dtmfFrameMs, true
	}
	d.held = digit
	if digit != 0 {
		d.runFrames = 1
	} else {
		d.runFrames = 0
	}
	return reportDigit, reportMs, ok
}
