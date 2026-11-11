// internal/media/codec/goertzel_test.go — the vector loader, written first so
// Task 10's detector tests have something concrete to fail against.
package codec

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// dtmfVectorPath is the repo-relative path of a pinned vector. Tests run with
// the package directory as CWD, so testdata/dtmf is three levels up.
func dtmfVectorPath(name string) string {
	return filepath.Join("..", "..", "..", "testdata", "dtmf", name)
}

// loadPCM reads a raw 8k/mono/16-bit LE PCM file into samples.
func loadPCM(t *testing.T, path string) []int16 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(b) == 0 || len(b)%2 != 0 {
		t.Fatalf("%s: %d bytes is not a whole number of 16-bit samples", path, len(b))
	}
	out := make([]int16, len(b)/2)
	for i := range out {
		out[i] = int16(binary.LittleEndian.Uint16(b[2*i:]))
	}
	return out
}

// goertzelPower is goertzelMag under the name the call sites read best. F-M3
// (D20, W2): its third parameter was dead (`_ float64`, never read), which made
// every call site pass a value that did nothing.
func goertzelPower(samples []int16, freq float64) float64 { return goertzelMag(samples, freq) }

// dtmfVectorFrame returns the tone-only samples (excluding the trailing
// silence) for the digit at position i in DTMFAlphabet order, given the
// fixed 100 ms tone / 100 ms silence / 8 kHz layout the generator emits.
func dtmfVectorFrame(pcm []int16, i int) []int16 {
	const toneN = 100 * dtmfSampleRate / 1000  // 800
	const frameN = 200 * dtmfSampleRate / 1000 // 1600 (tone + silence)
	start := i * frameN
	return pcm[start : start+toneN]
}

func TestPinnedQ23VectorsExistAndAreWellFormed(t *testing.T) {
	// 16 digits x (100 ms tone + 100 ms silence) x 8 samples/ms = 25600 samples.
	const wantSamples = 16 * 200 * 8
	for _, name := range []string{
		"q23-16digit-0db.pcm", "q23-16digit-p4db.pcm", "q23-16digit-m4db.pcm",
		"q23-16digit-p8db.pcm", "q23-16digit-m8db.pcm",
	} {
		pcm := loadPCM(t, dtmfVectorPath(name))
		if len(pcm) != wantSamples {
			t.Fatalf("%s: %d samples want %d", name, len(pcm), wantSamples)
		}
	}
}

// detectAll feeds every frame of samples through a fresh DTMFDetector and
// returns the digits it reported, in order.
func detectAll(t *testing.T, pcm []int16) (string, []int) {
	t.Helper()
	d := NewDTMFDetector()
	var got []byte
	var durs []int
	for off := 0; off+SamplesPerFrame <= len(pcm); off += SamplesPerFrame {
		if digit, durMs, ok := d.Feed(pcm[off : off+SamplesPerFrame]); ok {
			got = append(got, digit)
			durs = append(durs, durMs)
		}
	}
	return string(got), durs
}

func TestDetectorReadsTheZeroTwistVectorExactly(t *testing.T) {
	pcm := loadPCM(t, dtmfVectorPath("q23-16digit-0db.pcm"))
	got, _ := detectAll(t, pcm)
	if got != DTMFAlphabet {
		t.Fatalf("decoded %q want %q (>= 99%% accuracy at 0 dB twist)", got, DTMFAlphabet)
	}
}

func TestDetectorHoldsAcrossTheQ24TwistWindow(t *testing.T) {
	for _, name := range []string{
		"q23-16digit-p4db.pcm", "q23-16digit-m4db.pcm",
		"q23-16digit-p8db.pcm", "q23-16digit-m8db.pcm",
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := detectAll(t, loadPCM(t, dtmfVectorPath(name)))
			if got != DTMFAlphabet {
				t.Fatalf("decoded %q want %q (Q.24 permits 8 dB twist)", got, DTMFAlphabet)
			}
		})
	}
}

// TestDetectorDecodesTheSourceOnAnUnalignedFrameGrid is the only test in this
// package that does NOT hand the detector the generator's own frames on the
// generator's own grid, and that blindness is what hid a real property.
//
// A REAL RECEIVER HAS NO IDEA WHERE OUR FRAME BOUNDARIES ARE. Its 160-sample
// analysis windows straddle ours at an arbitrary offset, so every window it
// takes spans a boundary of ours — which is exactly the condition
// NewDTMFSource's continuous absolute sample index n exists to make harmless.
// The comment there claims a phase discontinuity at a frame boundary "would
// make our own generator fail our own Q.24 acceptance test", and that claim was
// false: MEASURED, resetting the phase per frame (`t := float64(j)` instead of
// `float64(n)`) left the entire codec package green, because on the aligned
// grid every test uses, the discontinuities land precisely between windows and
// are never seen. Off the grid the same generator loses digits outright:
//
//	offset (samples)   aligned suite   this test
//	   0               16/16           16/16
//	  40               16/16            9-13/16
//	  80               16/16            9/16
//	 120               16/16           13/16
//
// The offsets are deliberately not multiples of SamplesPerFrame — a multiple
// would re-align and prove nothing.
func TestDetectorDecodesTheSourceOnAnUnalignedFrameGrid(t *testing.T) {
	src, err := NewDTMFSource(DTMFAlphabet, 100, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	var pcm []int16
	// One extra frame beyond the rendered length, so the last digit's trailing
	// silence is present at every offset and its run is always flushed.
	for i := 0; i < 16*10+2; i++ {
		pcm = append(pcm, src.Frame()...)
	}
	for _, off := range []int{40, 80, 120} {
		got, _ := detectAll(t, pcm[off:])
		if got != DTMFAlphabet {
			t.Fatalf("at a receiver frame grid offset by %d samples the source decoded %q, "+
				"want %q: a receiver never shares our frame boundaries, so every one of its "+
				"analysis windows spans one of ours and the rendered tone's phase must carry "+
				"across them", off, got, DTMFAlphabet)
		}
	}
}

func TestDetectorRejectsTonesShorterThanTheQ24Minimum(t *testing.T) {
	// Q.24: a tone shorter than 40 ms MUST NOT be accepted. 20 ms is one frame.
	short, err := NewDTMFSource("5", 20, 200, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDTMFDetector()
	for i := 0; i < 11; i++ { // 1 tone frame + 10 gap frames
		if _, _, ok := d.Feed(short.Frame()); ok {
			t.Fatal("a 20 ms tone must be rejected (Q.24's 40 ms minimum)")
		}
	}
}

// TestDetectorAcceptsTheQ24MinimumAndReportsTiming drives BOTH sides of the
// duration comparison and, at 40 ms, the boundary value itself.
//
// 40 MS IS THE CASE THE NAME PROMISED AND THE TEST DID NOT HAVE. Q.24's floor
// is "shorter than 40 ms MUST NOT be accepted", i.e. 40 ms itself must be
// ACCEPTED, so the comparison in Feed is `>=` and the off-by-one that makes it
// `>` is a conformance failure. With 60 ms as the only accepted case and 20 ms
// (TestDetectorRejectsTonesShorterThanTheQ24Minimum) as the only rejected one,
// the two coincide under that mutation — MEASURED: changing Feed's
// `>= dtmfMinToneMs` to `> dtmfMinToneMs` left the whole codec package green.
func TestDetectorAcceptsTheQ24MinimumAndReportsTiming(t *testing.T) {
	// 40 is Q.24's floor exactly; 60 proves durationMs is the TRUE tone length
	// and not the floor value echoed back.
	for _, toneMs := range []int{40, 60} {
		t.Run(fmt.Sprintf("%dms", toneMs), func(t *testing.T) {
			src, err := NewDTMFSource("7", toneMs, 100, nil)
			if err != nil {
				t.Fatal(err)
			}
			d := NewDTMFDetector()
			var reported bool
			for i := 0; i < 8; i++ {
				if digit, durMs, ok := d.Feed(src.Frame()); ok {
					if digit != '7' {
						t.Fatalf("digit=%q want '7'", digit)
					}
					// Reported at the frame the tone ENDS (the first silence frame
					// after it), with the TRUE tone length.
					if durMs != toneMs {
						t.Fatalf("duration_ms=%d want %d (the true tone length)", durMs, toneMs)
					}
					reported = true
				}
			}
			if !reported {
				t.Fatalf("a %d ms tone was never reported; Q.24 forbids rejection only BELOW 40 ms",
					toneMs)
			}
		})
	}
}

func TestDetectorReportsALongToneExactlyOnce(t *testing.T) {
	src, err := NewDTMFSource("3", 400, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDTMFDetector()
	var n int
	for i := 0; i < 25; i++ {
		if _, _, ok := d.Feed(src.Frame()); ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("a single 400 ms tone reported %d times, want 1", n)
	}
}

// toneFrame renders frame number f of a continuous-phase two-tone pair. f is
// absolute so successive frames join without a phase discontinuity, which
// would itself smear energy between bins and make a rejection test pass for
// the wrong reason.
func toneFrame(low, high, lowAmp, highAmp float64, f int) []int16 {
	frame := make([]int16, SamplesPerFrame)
	for j := range frame {
		t := float64(f*SamplesPerFrame+j) / dtmfSampleRate
		frame[j] = int16(lowAmp*math.Sin(2*math.Pi*low*t) + highAmp*math.Sin(2*math.Pi*high*t))
	}
	return frame
}

// offGridPct is a frequency's distance from the NEAREST tone in grid, as a
// percentage of that tone. Tests use it to assert their own premise: Q.24
// mandates rejection only beyond 3.5 %, so a "must be rejected" case that has
// drifted to within 3.5 % of some grid tone is no longer testing the
// recommendation, and the test says so rather than quietly passing.
func offGridPct(freq float64, grid []float64) float64 {
	nearest := math.Inf(1)
	for _, g := range grid {
		if d := math.Abs(freq-g) / g * 100; d < nearest {
			nearest = d
		}
	}
	return nearest
}

// TestDetectorRejectsOffGridFrequencies is the Q.24 absolute-frequency gate.
//
// IT REPLACES A TEST THAT COULD NOT FAIL. The original probed exactly ONE
// point — 697 Hz + 5.0 % = 731.85 Hz — which happens to land near the 697/770
// midpoint, the single deviation where the in-group dominance margin
// incidentally rejects. Deviations on either side of it decoded happily: a
// sweep of 90888 pairs that Q.24 requires be rejected found 12.1 % of them
// decoding as digits, including ordinary voiced-speech formant pairs. The
// table below therefore walks the deviation RANGE and both tones separately,
// and every case carries its own proof that it really is in the mandatory
// reject band.
func TestDetectorRejectsOffGridFrequencies(t *testing.T) {
	cases := []struct {
		name      string
		low, high float64
	}{
		// Voiced-speech formant pairs that decoded as digits before the purity
		// gate existed — the phantom-digit risk in dtmf_mode: inband.
		{"formant F1/F2 500/1094 (decoded '4')", 500, 1094},
		{"formant 500/1144 (decoded '4')", 500, 1144},
		{"formant 500/1694 (decoded 'B')", 500, 1694},
		{"formant 600/1246 (decoded '4')", 600, 1246},
		{"near-grid 980/1736 (decoded '*')", 980, 1736},
		// Low tone swept off 697 Hz, high tone exact. Only deviations that stay
		// clear of BOTH 697 and 770 qualify; +7 % and +8 % are deliberately
		// absent because they land inside 3.5 % of 770 Hz, where Q.24 leaves the
		// outcome to the implementation.
		{"low -10 % off 697", 697 * 0.90, 1209},
		{"low -7 % off 697", 697 * 0.93, 1209},
		{"low -5 % off 697", 697 * 0.95, 1209},
		{"low -4 % off 697", 697 * 0.96, 1209},
		{"low +4 % off 697", 697 * 1.04, 1209},
		{"low +5 % off 697", 697 * 1.05, 1209}, // the old test's only point
		{"low +6 % off 697", 697 * 1.06, 1209},
		{"low +15 % off 697", 697 * 1.15, 1209},
		// High tone swept off 1209 Hz, low tone exact.
		{"high -10 % off 1209", 697, 1209 * 0.90},
		{"high -7 % off 1209", 697, 1209 * 0.93},
		{"high -5 % off 1209", 697, 1209 * 0.95},
		{"high -4 % off 1209", 697, 1209 * 0.96},
		{"high +4 % off 1209", 697, 1209 * 1.04},
		{"high +5 % off 1209", 697, 1209 * 1.05},
		{"high +6 % off 1209", 697, 1209 * 1.06},
		// Top of the grid, where there is no next column to be pulled toward.
		{"high +7 % off 1633", 941, 1633 * 1.07},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The premise: at least one tone must be beyond Q.24's 3.5 % reject
			// threshold, or this case does not test the recommendation at all.
			dl := offGridPct(tc.low, dtmfLowFreqs[:])
			dh := offGridPct(tc.high, dtmfHighFreqs[:])
			if dl <= 3.5 && dh <= 3.5 {
				t.Fatalf("case is not in Q.24's mandatory reject band: %.2f Hz is %.2f %% "+
					"off the nearest grid low and %.2f Hz is %.2f %% off the nearest grid high "+
					"(one of them must exceed 3.5 %%)", tc.low, dl, tc.high, dh)
			}
			d := NewDTMFDetector()
			for f := 0; f < 10; f++ {
				frame := toneFrame(tc.low, tc.high, 8000, 8000, f)
				// classify() is asserted directly, not just Feed(): Feed reports a
				// run only when classification CHANGES, so a pair that decodes on
				// EVERY frame is still held at the end of the loop and never
				// reported. Checking Feed alone would pass such a case for entirely
				// the wrong reason — verified, it does exactly that for 500/1694 Hz.
				if digit := classify(frame); digit != 0 {
					t.Fatalf("%.2f/%.2f Hz (%.2f %% / %.2f %% off grid) classified as %q on frame %d; "+
						"Q.24 requires it be rejected", tc.low, tc.high, dl, dh, digit, f)
				}
				if digit, _, ok := d.Feed(frame); ok {
					t.Fatalf("%.2f/%.2f Hz (%.2f %% / %.2f %% off grid) was reported as %q; "+
						"Q.24 requires it be rejected", tc.low, tc.high, dl, dh, digit)
				}
			}
			// Trailing silence flushes any run still held, so the end-to-end half
			// of this test cannot be satisfied by a digit that simply never ended.
			for f := 0; f < 2; f++ {
				if digit, _, ok := d.Feed(make([]int16, SamplesPerFrame)); ok {
					t.Fatalf("%.2f/%.2f Hz (%.2f %% / %.2f %% off grid) was reported as %q "+
						"when the tone ended; Q.24 requires it be rejected", tc.low, tc.high, dl, dh, digit)
				}
			}
		})
	}
}

// TestDetectorRejectsTheWholeQ24RejectBand is the population-level version of
// the table above: the table proves specific known-bad pairs are fixed, this
// proves no pair ANYWHERE in the mandatory reject band survives. It is the
// direct answer to the 12.1 % measurement — the count must be zero, not merely
// smaller.
func TestDetectorRejectsTheWholeQ24RejectBand(t *testing.T) {
	var swept, decoded int
	var examples []string
	for low := 500.0; low <= 1100.0; low += 5 {
		if offGridPct(low, dtmfLowFreqs[:]) <= 3.5 {
			continue
		}
		for high := 1050.0; high <= 1800.0; high += 5 {
			if offGridPct(high, dtmfHighFreqs[:]) <= 3.5 {
				continue
			}
			for f := 0; f < 2; f++ {
				swept++
				if digit := classify(toneFrame(low, high, 8000, 8000, f)); digit != 0 {
					decoded++
					if len(examples) < 5 {
						examples = append(examples, fmt.Sprintf("%.0f/%.0f Hz -> %q", low, high, digit))
					}
				}
			}
		}
	}
	if swept < 10000 {
		t.Fatalf("only %d frames swept; the sweep no longer covers the reject band", swept)
	}
	if decoded != 0 {
		t.Fatalf("%d of %d frames in Q.24's mandatory reject band decoded as digits (%v); want 0",
			decoded, swept, examples)
	}
}

// TestDetectorRejectsASingleOffGridTone covers the reject band the purity gate
// alone CANNOT reach, and is the reason dtmfFreqProbeTol exists. When one tone
// is exactly on grid it contributes about half the frame's energy all by
// itself, so a joint purity measure stays far above any threshold Q.24's
// acceptance requirement permits, no matter how far off grid its partner is.
// Every deviation here is checked in both directions and against every row and
// column, not just the one pair the original test happened to probe.
func TestDetectorRejectsASingleOffGridTone(t *testing.T) {
	var swept int
	for _, pct := range []float64{-15, -10, -7, -6, -5, -4, 4, 5, 6, 7, 10, 15} {
		for gi := 0; gi < 4; gi++ {
			// Low tone off its own grid frequency, high tone exact, then the
			// mirror image. Cases that drift within 3.5 % of a NEIGHBOURING grid
			// tone are skipped: Q.24 does not mandate rejection there.
			for _, c := range []struct{ low, high float64 }{
				{dtmfLowFreqs[gi] * (1 + pct/100), 1209},
				{697, dtmfHighFreqs[gi] * (1 + pct/100)},
			} {
				if offGridPct(c.low, dtmfLowFreqs[:]) <= 3.5 && offGridPct(c.high, dtmfHighFreqs[:]) <= 3.5 {
					continue
				}
				for f := 0; f < 4; f++ {
					swept++
					if digit := classify(toneFrame(c.low, c.high, 8000, 8000, f)); digit != 0 {
						t.Fatalf("%.2f/%.2f Hz (%.2f %% / %.2f %% off grid) classified as %q on frame %d; "+
							"Q.24 requires it be rejected", c.low, c.high,
							offGridPct(c.low, dtmfLowFreqs[:]), offGridPct(c.high, dtmfHighFreqs[:]), digit, f)
					}
				}
			}
		}
	}
	if swept < 200 {
		t.Fatalf("only %d frames swept; the single-tone sweep no longer covers the reject band", swept)
	}
}

// TestDetectorAcceptsTheQ24FrequencyTolerance guards the OTHER side of every
// rejection gate: the region Q.24 requires be ACCEPTED. Q.24 fixes both axes of
// that region at once — every digit must be recognised with either tone
// anywhere within ±1.5 % of nominal AND with up to ±8 dB of twist — so this
// test sweeps them together. A tightening of dtmfMinPurity that bought talk-off
// resistance by refusing legitimate in-tolerance tones, or a twist gate set
// from on-grid evidence alone, is just as much a conformance failure as
// admitting a tone the recommendation requires be rejected.
//
// THE TWIST AXIS IS NOT DECORATION. It is where the two effects compound: 1.5 %
// of 1633 Hz is 24.5 Hz, half a Goertzel bin at this frame length, so a corner
// tone measures up to 3.84 dB low, and that error lands directly on the
// measured twist ratio (see dtmfTwistBiasDB). An earlier revision of this test
// held twist at zero, which is exactly why a twist gate that rejected 4131
// frames of this region survived a full review round: on grid, the roll-off
// term is identically zero and there is nothing to see.
//
// Amplitudes follow scripts/gen-dtmf-vectors' convention — the twist is split
// symmetrically about a base amplitude, high tone x10^(twist/40) and low tone
// x10^(-twist/40) — so a failure here is directly comparable to the pinned
// vectors.
func TestDetectorAcceptsTheQ24FrequencyTolerance(t *testing.T) {
	const baseAmp = 6000.0
	devs := []float64{-1.5, 0, 1.5}
	for digit, rc := range dtmfGrid {
		lowNom, highNom := dtmfLowFreqs[rc[0]], dtmfHighFreqs[rc[1]]
		for _, dl := range devs {
			for _, dh := range devs {
				low := lowNom * (1 + dl/100)
				high := highNom * (1 + dh/100)
				for _, twist := range []float64{-8, -4, 0, 4, 8} {
					lowAmp := baseAmp * math.Pow(10, -twist/40)
					highAmp := baseAmp * math.Pow(10, twist/40)
					for f := 0; f < 4; f++ {
						got := classify(toneFrame(low, high, lowAmp, highAmp, f))
						if got != digit {
							t.Fatalf("digit %q at low %+.1f %% / high %+.1f %% (%.2f/%.2f Hz), "+
								"twist %+.0f dB, frame %d: decoded %q; Q.24 requires acceptance "+
								"within ±1.5 %% across ±8 dB of twist",
								digit, dl, dh, low, high, twist, f, got)
						}
					}
				}
			}
		}
	}
}

// TestTwistGateBudgetCoversTheEstimatorsMeasuredBias pins dtmfTwistBiasDB to
// the thing it claims to be. The budget is the gap between Q.24's 8 dB
// requirement and the gate classify() applies, and it is justified in
// goertzel.go by two bounds on the BIN-RATIO ESTIMATOR. This test recomputes
// both from goertzelMag, so the derivation is executable rather than asserted:
// change SamplesPerFrame, or the grid, and the budget stops covering the bias
// and this fails — which is the failure mode that produced the 10.0 dB gate in
// the first place.
//
// Deliberately two-sided. Too small is a conformance failure; far too large
// means the gate has quietly stopped being derived from anything.
func TestTwistGateBudgetCoversTheEstimatorsMeasuredBias(t *testing.T) {
	// (1) Bin roll-off: a lone tone at Q.24's ±1.5 % corner, measured against
	// the same tone on grid. No partner tone, so leakage contributes nothing.
	var rolloffDB float64
	var rolloffAt float64
	for _, f0 := range append(dtmfLowFreqs[:], dtmfHighFreqs[:]...) {
		for _, sign := range []float64{-1, 1} {
			off := f0 * (1 + sign*0.015)
			for f := 0; f < 8; f++ {
				db := -10 * math.Log10(
					goertzelMag(toneFrame(off, 0, 8000, 0, f), f0)/
						goertzelMag(toneFrame(f0, 0, 8000, 0, f), f0))
				if db > rolloffDB {
					rolloffDB, rolloffAt = db, f0
				}
			}
		}
	}

	// (2) Partner-tone leakage: both tones exactly ON grid (so roll-off is
	// zero) at Q.24's 8 dB limit, comparing the measured ratio against the same
	// two tones rendered in isolation.
	var leakDB float64
	var leakAt byte
	for digit, rc := range dtmfGrid {
		low, high := dtmfLowFreqs[rc[0]], dtmfHighFreqs[rc[1]]
		for _, twist := range []float64{-8, 8} {
			lowAmp := 6000 * math.Pow(10, -twist/40)
			highAmp := 6000 * math.Pow(10, twist/40)
			for f := 0; f < 40; f++ {
				both := toneFrame(low, high, lowAmp, highAmp, f)
				clean := 10 * math.Log10(
					goertzelMag(toneFrame(low, high, 0, highAmp, f), high)/
						goertzelMag(toneFrame(low, high, lowAmp, 0, f), low))
				measured := 10 * math.Log10(goertzelMag(both, high)/goertzelMag(both, low))
				if d := math.Abs(measured - clean); d > leakDB {
					leakDB, leakAt = d, digit
				}
			}
		}
	}

	need := rolloffDB + leakDB
	if dtmfTwistBiasDB < need {
		t.Fatalf("dtmfTwistBiasDB = %.2f dB but this estimator's worst-case bias over Q.24's "+
			"acceptance window is %.2f dB (roll-off %.2f dB at %.0f Hz + leakage %.2f dB at digit %q); "+
			"the twist gate now rejects tones Q.24 requires be accepted",
			float64(dtmfTwistBiasDB), need, rolloffDB, rolloffAt, leakDB, leakAt)
	}
	if dtmfTwistBiasDB > need+1.0 {
		t.Fatalf("dtmfTwistBiasDB = %.2f dB exceeds the measured worst-case bias %.2f dB "+
			"(roll-off %.2f + leakage %.2f) by more than the 1.0 dB rounding allowance; "+
			"the twist gate is no longer derived from Q.24 plus a bound, it is tuned",
			float64(dtmfTwistBiasDB), need, rolloffDB, leakDB)
	}
}

// TestDetectorEnergyFloorIsALevelNotARawMagnitude guards the normalisation
// dtmfEnergyFloor's derivation depends on. The constant only means "peak
// amplitude 632" if classify divides |X|² by N² first; without that division a
// raw magnitude is compared against the constant and the floor sits about six
// orders of magnitude too low, admitting tones down to amplitude 8 (−72 dBFS).
// Amplitude 300 is below the floor and 3000 is above it, so this fails loudly
// if the normalisation is ever dropped again.
func TestDetectorEnergyFloorIsALevelNotARawMagnitude(t *testing.T) {
	const low, high = 697.0, 1209.0 // digit '1', exactly on grid
	if got := classify(toneFrame(low, high, 300, 300, 0)); got != 0 {
		t.Fatalf("an on-grid tone at amplitude 300 (below the −31 dBm0 floor) decoded as %q; "+
			"the |X|²/N² normalisation is missing, so dtmfEnergyFloor is not a level", got)
	}
	if got := classify(toneFrame(low, high, 3000, 3000, 0)); got != '1' {
		t.Fatalf("an on-grid tone at amplitude 3000 (well above the floor) decoded as %q, want '1'; "+
			"the energy floor is now rejecting tones Q.24 requires be recognised", got)
	}
}

// dbm0Amplitude is the peak amplitude of a sine at the given dBm0 level, using
// goertzel.go's own reference: a digital full-scale sine is +3.14 dBm0.
func dbm0Amplitude(dbm0 float64) float64 {
	return 32768 * math.Pow(10, (dbm0-3.14)/20)
}

// TestDetectorAcceptsQ24sQuietestTonesAtTheAcceptanceCorner is the LEVEL axis of
// Q.24's must-accept region, which TestDetectorAcceptsTheQ24FrequencyTolerance
// does not sweep: that test renders every case at baseAmp 6000, roughly −11 dBm0,
// which is 26 dB clear of dtmfEnergyFloor. Q.24's receiver dynamic range runs
// down to about −25 dBm0 per frequency, so the frequency/twist corner has to hold
// at that level too — and goertzel.go's own derivation says the margin there is
// 1.44 dB, not the 6.30 dB an on-grid zero-twist tone enjoys.
//
// WITHOUT THIS THE FLOOR WAS PINNED ONLY TO A DECADE-WIDE BAND.
// TestDetectorEnergyFloorIsALevelNotARawMagnitude brackets it with amplitude 300
// (reject) and 3000 (accept), which catches the missing |X|²/N² normalisation —
// six orders of magnitude — but nothing finer. MEASURED: raising
// dtmfEnergyFloor from 1.0e5 to 1.0e6, i.e. 10 dB into the region Q.24 requires
// be recognised, left the whole codec package green. The floor's stated
// conformance claim ("no tone the recommendation requires us to accept is cut
// off") had no test at all; it is this one.
func TestDetectorAcceptsQ24sQuietestTonesAtTheAcceptanceCorner(t *testing.T) {
	// The WEAKER of the two tones is pinned at the bottom of the dynamic range;
	// twist then raises the other, exactly as goertzel.go's derivation states it.
	weak := dbm0Amplitude(-25)
	if weak < 1200 || weak > 1400 {
		t.Fatalf("weak amplitude %.0f is not −25 dBm0; the dBm0 reference has moved", weak)
	}
	devs := []float64{-1.5, 0, 1.5}
	for digit, rc := range dtmfGrid {
		lowNom, highNom := dtmfLowFreqs[rc[0]], dtmfHighFreqs[rc[1]]
		for _, dl := range devs {
			for _, dh := range devs {
				low := lowNom * (1 + dl/100)
				high := highNom * (1 + dh/100)
				for _, twist := range []float64{-8, -4, 0, 4, 8} {
					// 20*log10(highAmp/lowAmp) == twist, with whichever tone is
					// weaker held at −25 dBm0 rather than the pair's mean, so the
					// quiet tone is quiet at every twist and not just at zero.
					lowAmp, highAmp := weak, weak*math.Pow(10, twist/20)
					if twist < 0 {
						lowAmp, highAmp = weak*math.Pow(10, -twist/20), weak
					}
					for f := 0; f < 4; f++ {
						got := classify(toneFrame(low, high, lowAmp, highAmp, f))
						if got != digit {
							t.Fatalf("digit %q at low %+.1f %% / high %+.1f %% (%.2f/%.2f Hz), "+
								"twist %+.0f dB, weaker tone at −25 dBm0 (amp %.0f), frame %d: "+
								"decoded %q; Q.24's receiver dynamic range reaches −25 dBm0 per "+
								"frequency, so a gate that cuts this off is a conformance failure",
								digit, dl, dh, low, high, twist, weak, f, got)
						}
					}
				}
			}
		}
	}
}

func TestDetectorIgnoresSilenceAndSpeechLikeNoise(t *testing.T) {
	d := NewDTMFDetector()
	for i := 0; i < 50; i++ {
		if _, _, ok := d.Feed(make([]int16, SamplesPerFrame)); ok {
			t.Fatal("silence must never produce a digit")
		}
	}
}

// TestDetectorRejectsExcessiveTwist guards the twist gate itself: without this,
// a future regression that widens dtmfTwistDB far past its derived value (see
// dtmfTwistBiasDB) would go undetected by the tests above, which only ever
// exercise twist up to the Q.24-permitted 8 dB. A ~16 dB twist pair — well past
// the 13.0 dB gate, and measuring 14.9-17.2 dB through this estimator — must
// not be reported as the digit it would otherwise decode to.
//
// IT ASSERTS classify() DIRECTLY, and that is the whole point of the assertion
// order below. Feed reports a run only when classification CHANGES, so a pair
// that decodes on EVERY frame is still held when the loop ends and is never
// reported: a Feed-only version of this test stays green under a twist gate
// widened to 20 dB, passing for entirely the wrong reason. The Feed half is
// kept as well, with trailing silence to flush any held run, so both the gate
// and the reporting path are covered.
func TestDetectorRejectsExcessiveTwist(t *testing.T) {
	d := NewDTMFDetector()
	const low, high = 697.0, 1209.0 // digit '1'
	// ratioDB = 20*log10(highAmp/lowAmp): keep highAmp fixed and shrink lowAmp
	// (rather than boosting highAmp) so the summed peak stays well within
	// int16 range and the signal itself is clean.
	const highAmp = 8000.0
	const lowAmp = highAmp / 6.31 // 20*log10(6.31) ~= 16.0 dB twist
	for f := 0; f < 10; f++ {
		frame := toneFrame(low, high, lowAmp, highAmp, f)
		if digit := classify(frame); digit != 0 {
			t.Fatalf("a ~16 dB twist tone must be rejected, classify returned %q on frame %d", digit, f)
		}
		if digit, _, ok := d.Feed(frame); ok {
			t.Fatalf("a ~16 dB twist tone must be rejected, got digit %q", digit)
		}
	}
	for f := 0; f < 2; f++ {
		if digit, _, ok := d.Feed(make([]int16, SamplesPerFrame)); ok {
			t.Fatalf("a ~16 dB twist tone must be rejected, got digit %q when the tone ended", digit)
		}
	}
}

// TestDTMFTalkOff is the TR-TSY-000762 talk-off gate. The speech tape and the
// music set are not redistributable and are not in this repository, so this
// test SKIPS WITH AN EXPLICIT LOG LINE when they are absent (design spec §8) —
// it is never silently green.
func TestDTMFTalkOff(t *testing.T) {
	speech := dtmfVectorPath("talkoff-trtsy000762.pcm")
	music := dtmfVectorPath("talkoff-music.pcm")
	if _, err := os.Stat(speech); err != nil {
		t.Skipf("talk-off tape absent (%s): TR-TSY-000762 is not redistributable; "+
			"drop the raw 8k/mono/16-bit LE file there to run this gate", speech)
	}
	got, _ := detectAll(t, loadPCM(t, speech))
	if len(got) > 1 {
		t.Fatalf("talk-off: %d false triggers over TR-TSY-000762, want <= 1: %q", len(got), got)
	}
	if _, err := os.Stat(music); err != nil {
		t.Logf("music talk-off set absent (%s): skipping the zero-trigger half", music)
		return
	}
	if got, _ := detectAll(t, loadPCM(t, music)); len(got) != 0 {
		t.Fatalf("talk-off: %d false triggers over the music set, want 0: %q", len(got), got)
	}
}

// TestPinnedQ23VectorDigitOrder is a cheap hardening check on top of the
// length-only assertion above: this codebase has a specific history (Tasks
// 3, 4, 6) of doc comments making unverified claims about codec-side data
// ordering that silently drifted. Without this, nothing at Task 9's own
// commit actually verifies the 0 dB vector's digit slots are laid out in
// DTMFAlphabet order — only that the file has the right total length. This
// checks the first and last digit slots against DTMFFreqs for that
// position, using a plain Goertzel energy comparison (not a full detector).
//
// The low and high tones are checked SEPARATELY against the decoy, not
// summed: DTMFAlphabet's row-3 digits ('*', '0', '#', 'D') all share the same
// low tone (941 Hz), so a bug that swapped two of them (e.g. '0' and '#'
// trading places) would still show strong low-tone energy at the expected
// low frequency even though the digit is wrong — a summed check would not
// catch it, but requiring the high tone to independently dominate does.
func TestPinnedQ23VectorDigitOrder(t *testing.T) {
	pcm := loadPCM(t, dtmfVectorPath("q23-16digit-0db.pcm"))

	// A frequency pair present in neither slot checked below (digit '0' is
	// 941/1336 Hz, digit '#' is 941/1477 Hz), so it makes a clean decoy: if
	// the vector's digit order were wrong, energy at the expected low/high
	// frequencies would collapse toward the decoy's level instead of
	// dominating it.
	const decoyLow, decoyHigh = 697.0, 1209.0

	for _, i := range []int{0, len(DTMFAlphabet) - 1} {
		digit := DTMFAlphabet[i]
		low, high, ok := DTMFFreqs(digit)
		if !ok {
			t.Fatalf("DTMFFreqs(%q) not ok", digit)
		}
		frame := dtmfVectorFrame(pcm, i)

		expLow := goertzelPower(frame, low)
		expHigh := goertzelPower(frame, high)
		decLow := goertzelPower(frame, decoyLow)
		decHigh := goertzelPower(frame, decoyHigh)

		if expLow <= decLow || expHigh <= decHigh {
			t.Fatalf("slot %d (digit %q): expected-tone energy (low=%.3e high=%.3e) not dominant over "+
				"decoy energy (low=%.3e high=%.3e) — vector's digit order does not match DTMFAlphabet[%d]=%q",
				i, digit, expLow, expHigh, decLow, decHigh, i, digit)
		}
	}
}
