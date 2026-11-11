package quality

import "testing"

// D5 / R4 acceptance shape: 5% loss lowers mos_estimate by at least 0.3 vs the
// lossless run, and a lossless PCMU path scores a high MOS.
func TestEModelLossDropsMOS(t *testing.T) {
	clean := RToMOS(RFactor(0, 2, "PCMU", 60))
	lossy := RToMOS(RFactor(5.0, 2, "PCMU", 60))
	if clean < 4.0 {
		t.Fatalf("lossless PCMU mos_estimate=%.3f, want >= 4.0", clean)
	}
	if clean-lossy < 0.3 {
		t.Fatalf("5%% loss dropped mos_estimate by only %.3f, want >= 0.3", clean-lossy)
	}
}

func TestRToMOSBounds(t *testing.T) {
	if RToMOS(-5) != 1.0 {
		t.Fatal("R<=0 must give MOS 1.0")
	}
	if RToMOS(120) != 4.5 {
		t.Fatal("R>=100 must clamp MOS to 4.5")
	}
}

func TestPCMUAndPCMASameImpairment(t *testing.T) {
	// Both are G.711: identical Ie/Bpl, so identical R for identical inputs.
	if RFactor(3, 1, "PCMU", 60) != RFactor(3, 1, "PCMA", 60) {
		t.Fatal("PCMU and PCMA must share G.711 impairment constants")
	}
}
