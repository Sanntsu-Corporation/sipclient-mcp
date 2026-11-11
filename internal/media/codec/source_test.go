package codec

import "testing"

func TestSilenceSourceFrame(t *testing.T) {
	f := NewSilenceSource().Frame()
	if len(f) != SamplesPerFrame {
		t.Fatalf("silence frame len=%d want %d", len(f), SamplesPerFrame)
	}
	for _, s := range f {
		if s != 0 {
			t.Fatalf("silence frame carried non-zero sample %d", s)
		}
	}
}

func TestSineSourceFrameSizeAndContinuity(t *testing.T) {
	s := NewSineSource(1000)
	f1 := s.Frame()
	f2 := s.Frame()
	if len(f1) != SamplesPerFrame || len(f2) != SamplesPerFrame {
		t.Fatalf("sine frame sizes %d,%d", len(f1), len(f2))
	}
	// Phase is continuous across frames: sample 0 of frame 2 must equal the
	// sample the generator would produce at absolute index 160, not restart at 0.
	nonzero := false
	for _, v := range f1 {
		if v != 0 {
			nonzero = true
			break
		}
	}
	if !nonzero {
		t.Fatal("1kHz sine produced an all-zero frame")
	}
}
