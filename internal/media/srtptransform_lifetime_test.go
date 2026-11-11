package media

import "testing"

// lifetimeRig returns a sender context keyed with K and a transform whose
// remote key is K with the given lifetime.
func lifetimeRig(t *testing.T, lifetime uint64) (send, recv FrameTransform) {
	t.Helper()
	k, other := keyOf(t), keyOf(t)
	send, err := NewSRTPTransform(k, other, 64)
	if err != nil {
		t.Fatal(err)
	}
	k.Lifetime = lifetime
	recv, err = NewSRTPTransform(other, k, 64)
	if err != nil {
		t.Fatal(err)
	}
	return send, recv
}

func TestSRTPTransformObeysTheKeyLifetime(t *testing.T) {
	send, recv := lifetimeRig(t, 4)
	wire := func(seq uint16) []byte {
		w, err := send.Protect(rtpBytes(t, seq, uint32(seq)*160, []byte{1, 2}))
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), w...)
	}
	for seq := uint16(1); seq <= 2; seq++ {
		if _, err := recv.Unprotect(wire(seq)); err != nil {
			t.Fatalf("packet %d refused: %v", seq, err)
		}
	}
	bad := wire(9)
	bad[len(bad)-1] ^= 0xFF
	if _, err := recv.Unprotect(bad); err == nil {
		t.Fatal("a broken auth tag was accepted")
	}
	if _, err := recv.Unprotect(wire(3)); err != nil {
		t.Fatalf("packet 3 refused after a forged packet (it must not count): %v", err)
	}
	for seq := uint16(4); seq <= 6; seq++ {
		if _, err := recv.Unprotect(wire(seq)); err == nil {
			t.Fatalf("packet %d accepted at or past the lifetime", seq)
		}
	}
}

func TestSRTPTransformWithoutALifetimeUsesTheSuiteMaximum(t *testing.T) {
	send, recv := lifetimeRig(t, 0)
	for seq := 1; seq <= 1000; seq++ {
		w, err := send.Protect(rtpBytes(t, uint16(seq), uint32(seq)*160, []byte{1}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := recv.Unprotect(w); err != nil {
			t.Fatalf("packet %d refused: %v", seq, err)
		}
	}
}

func TestNewSRTPTransformLifetimeLimit(t *testing.T) {
	for _, tc := range []struct{ in, want uint64 }{{0, maxKeyLifetime}, {4, 4}, {maxKeyLifetime, maxKeyLifetime}} {
		_, recv := lifetimeRig(t, tc.in)
		if got := recv.(*srtpTransform).rxLimit; got != tc.want {
			t.Errorf("Lifetime %d: rxLimit %d, want %d", tc.in, got, tc.want)
		}
	}
}
