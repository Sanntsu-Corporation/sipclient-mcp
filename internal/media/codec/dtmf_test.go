package codec

import (
	"math"
	"testing"
)

func TestDTMFAlphabetAndFreqTable(t *testing.T) {
	if len(DTMFAlphabet) != 16 {
		t.Fatalf("alphabet %q has %d entries, want 16", DTMFAlphabet, len(DTMFAlphabet))
	}
	// Pin the exact literal and its order. Task 9 generates pinned test
	// vectors "in DTMFAlphabet order" and Task 10 decodes them in that same
	// order; a future silent reorder of this constant would misalign those
	// vectors against the detector with nothing else here to catch it.
	if DTMFAlphabet != "0123456789ABCD*#" {
		t.Fatalf("DTMFAlphabet = %q, want the exact pinned literal %q", DTMFAlphabet, "0123456789ABCD*#")
	}
	for i := 0; i < len(DTMFAlphabet); i++ {
		low, high, ok := DTMFFreqs(DTMFAlphabet[i])
		if !ok || low <= 0 || high <= low {
			t.Fatalf("digit %q: low=%v high=%v ok=%v", DTMFAlphabet[i], low, high, ok)
		}
	}
	if _, _, ok := DTMFFreqs('X'); ok {
		t.Fatal("DTMFFreqs accepted a digit outside the alphabet")
	}
	// ITU Q.23 spot checks.
	if low, high, _ := DTMFFreqs('1'); low != 697 || high != 1209 {
		t.Fatalf("'1' = %v/%v want 697/1209", low, high)
	}
	if low, high, _ := DTMFFreqs('D'); low != 941 || high != 1633 {
		t.Fatalf("'D' = %v/%v want 941/1633", low, high)
	}
}

func TestValidDTMFDigits(t *testing.T) {
	if !ValidDTMFDigits("0123456789ABCD*#") {
		t.Fatal("the whole alphabet must validate")
	}
	for _, bad := range []string{"", "12x", "1 2", "e"} {
		if ValidDTMFDigits(bad) {
			t.Fatalf("%q must not validate", bad)
		}
	}
}

func TestDTMFEventCodeMatchesRFC4733(t *testing.T) {
	want := map[byte]uint8{'0': 0, '1': 1, '9': 9, '*': 10, '#': 11, 'A': 12, 'D': 15}
	for d, code := range want {
		got, ok := DTMFEventCode(d)
		if !ok || got != code {
			t.Fatalf("digit %q => %d (ok=%v) want %d", d, got, ok, code)
		}
	}
}

// TestDTMFDigitForEventCodeIsTheExactInverse pins the direction that a naive
// implementation gets WRONG. RFC 4733's code assignment is NOT DTMFAlphabet's
// own index order: code 10 is '*' but DTMFAlphabet[10] is 'A', code 11 is '#'
// but DTMFAlphabet[11] is 'B', and codes 12-15 are 'A'-'D' where the alphabet
// has 'C', 'D', '*', '#'. Every one of the six non-decimal digits is corrupted
// by an alphabet index, and only by an alphabet index — which is why the six are
// asserted explicitly here as well as through the round trip.
func TestDTMFDigitForEventCodeIsTheExactInverse(t *testing.T) {
	for i := 0; i < len(DTMFAlphabet); i++ {
		digit := DTMFAlphabet[i]
		code, ok := DTMFEventCode(digit)
		if !ok {
			t.Fatalf("digit %q has no event code", digit)
		}
		back, ok := DTMFDigitForEventCode(code)
		if !ok || back != digit {
			t.Fatalf("code %d => %q (ok=%v), want %q", code, back, ok, digit)
		}
	}
	// The six the alphabet-index bug corrupts, spelled out.
	for code, want := range map[uint8]byte{10: '*', 11: '#', 12: 'A', 13: 'B', 14: 'C', 15: 'D'} {
		got, ok := DTMFDigitForEventCode(code)
		if !ok || got != want {
			t.Fatalf("code %d => %q (ok=%v), want %q — DTMFAlphabet[%d] is %q, "+
				"which is exactly the wrong answer an index table gives",
				code, got, ok, want, code, DTMFAlphabet[code])
		}
	}
	// RFC 4733 also defines non-DTMF events above 15 (flash hook, tones); they
	// are not digits and must be reported absent, not clamped.
	for _, code := range []uint8{16, 17, 100, 255} {
		if _, ok := DTMFDigitForEventCode(code); ok {
			t.Fatalf("event code %d must not decode to a DTMF digit", code)
		}
	}
}

func TestDTMFSourceFrameCountAndDuration(t *testing.T) {
	// 2 digits x (100 ms tone + 60 ms gap), EXCEPT the last digit has no
	// trailing gap (B-M9): digit 1 = 5 tone + 3 gap = 8 frames, digit 2
	// (last) = 5 tone only = 5 frames; 13 frames total.
	s, err := NewDTMFSource("12", 100, 60, nil)
	if err != nil {
		t.Fatalf("NewDTMFSource: %v", err)
	}
	if s.DurationMs() != 260 {
		t.Fatalf("DurationMs=%d want 260", s.DurationMs())
	}
	if s.EmittedDurationMs() != 100 {
		t.Fatalf("EmittedDurationMs=%d want 100", s.EmittedDurationMs())
	}
	// Mirrors promptsource_test.go's TestPromptSourcePlaysThenSilencesAndSignals
	// idiom: Frame() only closes Done() on the call PAST the last real frame,
	// not on the last real frame itself, so the 13 real frames are pulled
	// first (asserting Done() is not yet closed after each), and only the
	// 14th call is expected to return silence with Done() closed.
	const wantFrames = 13
	for i := 0; i < wantFrames; i++ {
		f := s.Frame()
		if len(f) != SamplesPerFrame {
			t.Fatalf("frame %d len=%d want %d", i, len(f), SamplesPerFrame)
		}
		select {
		case <-s.Done():
			t.Fatalf("Done() closed after only %d frames", i+1)
		default:
		}
	}
	// The next Frame() is past the end: it returns silence and closes Done().
	f := s.Frame()
	if len(f) != SamplesPerFrame {
		t.Fatalf("post-exhaustion frame len=%d want %d", len(f), SamplesPerFrame)
	}
	for _, v := range f {
		if v != 0 {
			t.Fatal("post-exhaustion frame is not silence")
		}
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("Done() not closed after exhaustion")
	}
}

// TestDTMFSourceRoundsThePerDigitDurationUpAndReportsIt pins what dtmf_send's
// duration_ms is allowed to say: 50 ms is not a whole number of 20 ms frames, so
// three frames are rendered and 60 is the emitted per-digit duration.
func TestDTMFSourceRoundsThePerDigitDurationUpAndReportsIt(t *testing.T) {
	s, err := NewDTMFSource("12", 50, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.EmittedDurationMs() != 60 {
		t.Fatalf("EmittedDurationMs=%d want 60 — a 50ms request renders three 20ms frames",
			s.EmittedDurationMs())
	}
	// gap_ms 0 means NO GAP: two digits x three tone frames and nothing else.
	if s.DurationMs() != 120 {
		t.Fatalf("DurationMs=%d want 120 (no gap frames at gap_ms=0)", s.DurationMs())
	}
	// THE GAP IS ROUNDED UP TOO, and nothing pinned that: every other gap in
	// this package is 0, 20 or 60 ms — all whole frames, where rounding up and
	// truncating give the same answer. MEASURED: changing gapFrames to
	// `gapMs / dtmfFrameMs` left the whole codec package green. 50 ms of gap is
	// three frames — but B-M9: only the FIRST digit gets a gap (there is no
	// second digit to separate the LAST one from), so this two-digit send is
	// 3 tone + 3 gap (digit 1) + 3 tone only (digit 2, last) = 180 ms, not 240.
	g, err := NewDTMFSource("12", 50, 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	if g.DurationMs() != 180 {
		t.Fatalf("DurationMs=%d want 180 — a 50 ms gap rounds UP to three 20 ms frames after "+
			"digit 1, and the last digit gets no trailing gap (B-M9)", g.DurationMs())
	}
	// 50 ms ONLY SEPARATES ROUNDING UP FROM TRUNCATING, because 50 is past the
	// midpoint of its frame: rounding to NEAREST gives the same three frames, and
	// measured, `(gapMs+dtmfFrameMs/2)/dtmfFrameMs` left the whole codec package
	// green. 21 ms is the discriminating value — up is 2 frames, nearest and
	// truncation are both 1 — so digit 1 (1 tone + 2 gap frames) plus digit 2's
	// tone-only frame (B-M9: no trailing gap on the last digit) renders 80 ms;
	// rounding to nearest or truncating the gap to 1 frame would instead render
	// 60 ms (1 tone + 1 gap + 1 tone), so 80 still discriminates round-up from
	// the alternatives.
	n, err := NewDTMFSource("12", 20, 21, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n.DurationMs() != 80 {
		t.Fatalf("DurationMs=%d want 80 — a 21 ms gap rounds UP to two 20 ms frames after digit "+
			"1, and digit 2 (last) gets no trailing gap (B-M9)", n.DurationMs())
	}
}

func TestDTMFSourceFiresOnExhaustExactlyOnce(t *testing.T) {
	var fired int
	s, err := NewDTMFSource("1", 20, 0, func() { fired++ })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		s.Frame()
	}
	if fired != 1 {
		t.Fatalf("onExhaust fired %d times, want exactly 1", fired)
	}
}

func TestDTMFSourceRendersTheToneThenSilentGap(t *testing.T) {
	// 20 ms tone, 20 ms gap: frame 0 is tone, frame 1 is digital silence.
	s, err := NewDTMFSource("5", 20, 20, nil)
	if err != nil {
		t.Fatal(err)
	}
	tone := s.Frame()
	var energy float64
	for _, v := range tone {
		energy += float64(v) * float64(v)
	}
	if math.Sqrt(energy/float64(len(tone))) < 1000 {
		t.Fatal("the tone frame carries no energy")
	}
	gap := s.Frame()
	for _, v := range gap {
		if v != 0 {
			t.Fatal("the gap frame must be digital silence")
		}
	}
}

func TestNewDTMFSourceRejectsIllegalInput(t *testing.T) {
	for _, tc := range []struct {
		digits   string
		dur, gap int
	}{
		{"", 100, 50},
		{"1X", 100, 50},
		{"1", 0, 50},
		{"1", 100, -1},
	} {
		if _, err := NewDTMFSource(tc.digits, tc.dur, tc.gap, nil); err == nil {
			t.Fatalf("NewDTMFSource(%q, %d, %d) must error", tc.digits, tc.dur, tc.gap)
		}
	}
}
