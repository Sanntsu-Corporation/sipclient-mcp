package codec

import "testing"

// A small ITU-flavoured spot-check table: known linear samples and their
// canonical G.711 codewords. µ-law of digital silence (0) is 0xFF; A-law of 0
// is 0xD5. These are fixed reference points; the round-trip test below covers
// the full range within G.711's quantisation error.
func TestPCMUReferencePoints(t *testing.T) {
	// µ-law has distinct +0/-0 codewords (0xFF/0x7F); -1 is negative, so it
	// lands in the negative near-zero codeword, not positive zero's 0xFF.
	cases := []struct {
		in   int16
		want byte
	}{
		{0, 0xFF},
		{-1, 0x7F},
		{32767, 0x80},
		{-32768, 0x00},
	}
	for _, c := range cases {
		got := EncodePCMU([]int16{c.in})[0]
		if got != c.want {
			t.Fatalf("EncodePCMU(%d)=0x%02X want 0x%02X", c.in, got, c.want)
		}
	}
}

func TestPCMAReferencePoints(t *testing.T) {
	if got := EncodePCMA([]int16{0})[0]; got != 0xD5 {
		t.Fatalf("EncodePCMA(0)=0x%02X want 0xD5", got)
	}
}

// G.711 is lossy; a decode(encode(x)) round-trip must land within one
// quantisation step of x across the whole 8-bit codeword space. Iterating the
// 256 codewords (not raw PCM) makes the bound exact: decode is the inverse of a
// surjection, so encode(decode(cw)) == cw for every legal codeword — EXCEPT
// µ-law's one genuine exception, 0x7F ("negative zero"): it decodes to the
// same linear 0 as 0xFF ("positive zero"), and encoding linear 0 always
// canonically produces 0xFF, never 0x7F. This is standard µ-law (two
// codewords, one linear value), not a defect — skip that single codeword
// rather than assert codeword identity for it.
func TestPCMUCodewordStable(t *testing.T) {
	for cw := 0; cw < 256; cw++ {
		if cw == 0x7F {
			continue // negative zero: decodes to 0, re-encodes to 0xFF, not 0x7F
		}
		pcm := DecodePCMU([]byte{byte(cw)})
		if got := EncodePCMU(pcm)[0]; got != byte(cw) {
			t.Fatalf("codeword 0x%02X: encode(decode)=0x%02X", cw, got)
		}
	}
}

func TestPCMACodewordStable(t *testing.T) {
	for cw := 0; cw < 256; cw++ {
		pcm := DecodePCMA([]byte{byte(cw)})
		if got := EncodePCMA(pcm)[0]; got != byte(cw) {
			t.Fatalf("codeword 0x%02X: encode(decode)=0x%02X", cw, got)
		}
	}
}

func TestEncodeDecodeDispatchAndPT(t *testing.T) {
	if _, err := Encode("opus", []int16{0}); err == nil {
		t.Fatal("Encode must reject an unsupported codec")
	}
	b, err := Encode("PCMA", []int16{0})
	if err != nil || len(b) != 1 || b[0] != 0xD5 {
		t.Fatalf("Encode(PCMA,0)=%v,%v", b, err)
	}
	if pt, ok := PayloadType("PCMU"); !ok || pt != 0 {
		t.Fatalf("PayloadType(PCMU)=%d,%v", pt, ok)
	}
	if pt, ok := PayloadType("PCMA"); !ok || pt != 8 {
		t.Fatalf("PayloadType(PCMA)=%d,%v", pt, ok)
	}
	if _, ok := PayloadType("opus"); ok {
		t.Fatal("PayloadType must reject opus")
	}
}
