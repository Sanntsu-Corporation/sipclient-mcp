package media

import "testing"

// §6.5.1 acceptance: a 4-frame gap decays to silence — the fourth concealed
// frame's peak amplitude is 0, and each earlier concealed frame is the previous
// decoded frame attenuated 6 dB (halved) per successive concealment.
func TestPLCDecayToSilence(t *testing.T) {
	p := NewPLC(1)
	p.Observe([]int16{1000})
	c1 := p.Conceal()
	c2 := p.Conceal()
	c3 := p.Conceal()
	c4 := p.Conceal()
	if c1[0] != 500 || c2[0] != 250 || c3[0] != 125 {
		t.Fatalf("decay wrong: %d,%d,%d want 500,250,125", c1[0], c2[0], c3[0])
	}
	if c4[0] != 0 {
		t.Fatalf("fourth concealed frame peak=%d want 0 (silence)", c4[0])
	}
}

func TestPLCResetsOnObserve(t *testing.T) {
	p := NewPLC(1)
	p.Observe([]int16{800})
	if p.Conceal()[0] != 400 {
		t.Fatal("first conceal must be half")
	}
	p.Observe([]int16{800}) // a real frame arrived; decay counter resets
	if p.Conceal()[0] != 400 {
		t.Fatal("conceal after Observe must restart the decay at half")
	}
}
