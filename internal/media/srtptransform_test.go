package media

import (
	"bytes"
	"testing"

	"github.com/pion/rtp"
)

func rtpBytes(t *testing.T, seq uint16, ts uint32, payload []byte) []byte {
	t.Helper()
	p := &rtp.Packet{
		Header:  rtp.Header{Version: 2, PayloadType: 0, SequenceNumber: seq, Timestamp: ts, SSRC: 0x1234},
		Payload: payload,
	}
	raw, err := p.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func TestIdentityTransformRoundTrip(t *testing.T) {
	tr := NewIdentityTransform()
	in := rtpBytes(t, 1, 160, []byte{0xFF, 0xFE})
	out, err := tr.Protect(in)
	if err != nil || !bytes.Equal(out, in) {
		t.Fatalf("identity Protect changed bytes: %v %v", out, err)
	}
	back, err := tr.Unprotect(out)
	if err != nil || !bytes.Equal(back, in) {
		t.Fatalf("identity Unprotect changed bytes: %v %v", back, err)
	}
}

// The construction-time invariant, including the OMITTED-option case: a window
// of 0 (what a caller who forgot SRTPReplayProtection would supply) MUST fail
// construction rather than silently defaulting to CreateContext's zero-window.
func TestSRTPTransformRejectsZeroReplayWindow(t *testing.T) {
	lk, _, _ := GenerateCryptoAttr()
	rk, _, _ := GenerateCryptoAttr()
	if _, err := NewSRTPTransform(lk, rk, 0); err == nil {
		t.Fatal("NewSRTPTransform with replayWindow 0 must fail (zero replay protection)")
	}
	if err := AssertReplayWindow(0, 60); err == nil {
		t.Fatal("AssertReplayWindow(0,60) must fail")
	}
	if err := AssertReplayWindow(2, 200); err == nil {
		t.Fatal("AssertReplayWindow(2,200) must fail: window 2 < 200/20 = 10")
	}
	if err := AssertReplayWindow(64, 60); err != nil {
		t.Fatalf("AssertReplayWindow(64,60) must pass, got %v", err)
	}
	if got := ReplayWindowFor(60); got != 64 {
		t.Fatalf("ReplayWindowFor(60)=%d want 64", got)
	}
}

// Real AES_CM_128_HMAC_SHA1_80 encrypt/decrypt: two contexts keyed as a call
// would be (our key for TX, peer key for RX), wired crosswise so the RX context
// of one side decrypts the TX output of the other.
func TestSRTPTransformEncryptDecryptRoundTrip(t *testing.T) {
	aKey, _, _ := GenerateCryptoAttr()
	bKey, _, _ := GenerateCryptoAttr()
	// Side A: TX with aKey, RX with bKey. Side B: TX with bKey, RX with aKey.
	aSide, err := NewSRTPTransform(aKey, bKey, 64)
	if err != nil {
		t.Fatalf("aSide: %v", err)
	}
	bSide, err := NewSRTPTransform(bKey, aKey, 64)
	if err != nil {
		t.Fatalf("bSide: %v", err)
	}
	plaintext := rtpBytes(t, 7, 1120, []byte{0x01, 0x02, 0x03})
	wire, err := aSide.Protect(plaintext)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	if len(wire) != len(plaintext)+SRTPAuthTagLen {
		t.Fatalf("wire grew by %d, want %d (auth tag)", len(wire)-len(plaintext), SRTPAuthTagLen)
	}
	back, err := bSide.Unprotect(wire)
	if err != nil {
		t.Fatalf("Unprotect: %v", err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Fatalf("round-trip lost data: %v vs %v", back, plaintext)
	}
	// A tampered auth tag fails authentication (routine, not misuse).
	tampered := append([]byte(nil), wire...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := bSide.Unprotect(tampered); err == nil {
		t.Fatal("Unprotect must reject a tampered auth tag")
	}
}

// TestProtectReusesScratchBufferAfterFirstCall is §15.1's no-reallocation
// acceptance: once txScratch has grown to accommodate a packet's size, calling
// Protect again with a same-or-smaller packet must reuse that same backing
// array rather than allocating a new one.
func TestProtectReusesScratchBufferAfterFirstCall(t *testing.T) {
	lk, _, err := GenerateCryptoAttr()
	if err != nil {
		t.Fatalf("GenerateCryptoAttr (local): %v", err)
	}
	rk, _, err := GenerateCryptoAttr()
	if err != nil {
		t.Fatalf("GenerateCryptoAttr (remote): %v", err)
	}
	transform, err := NewSRTPTransform(lk, rk, DefaultReplayWindow)
	if err != nil {
		t.Fatalf("NewSRTPTransform: %v", err)
	}
	st := transform.(*srtpTransform)

	plaintext := make([]byte, 172) // a representative marshalled RTP packet size
	if _, err := st.Protect(plaintext); err != nil {
		t.Fatalf("first Protect: %v", err)
	}
	grownCap := cap(st.txScratch)
	if grownCap < len(plaintext)+SRTPAuthTagLen {
		t.Fatalf("txScratch cap = %d after first call, want >= %d", grownCap, len(plaintext)+SRTPAuthTagLen)
	}

	if _, err := st.Protect(plaintext); err != nil {
		t.Fatalf("second Protect: %v", err)
	}
	if cap(st.txScratch) != grownCap {
		t.Fatalf("txScratch cap changed from %d to %d on a same-size second call — reallocated instead of reused",
			grownCap, cap(st.txScratch))
	}
}
