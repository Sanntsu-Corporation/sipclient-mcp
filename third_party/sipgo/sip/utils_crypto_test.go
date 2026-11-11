package sip

import (
	mrand "math/rand"
	"strings"
	"testing"
)

// TestGeneratorsIgnoreTheMathRandSeed (CF-073): RFC 3261 19.3 requires tags and
// branches to be cryptographically random, so reseeding math/rand must not make
// the generators repeat.
func TestGeneratorsIgnoreTheMathRandSeed(t *testing.T) {
	t.Setenv("GODEBUG", "randseednop=0")
	gens := map[string]func() string{
		"GenerateTagN":    func() string { return GenerateTagN(16) },
		"GenerateBranchN": func() string { return GenerateBranchN(16) },
		"RandString":      func() string { return RandString(10) },
	}
	for name, gen := range gens {
		mrand.Seed(7) //nolint:staticcheck // the deterministic seed is the point of the test
		a := gen()
		mrand.Seed(7) //nolint:staticcheck
		b := gen()
		if a == b {
			t.Errorf("%s returned %q twice for one math/rand seed", name, a)
		}
	}
}

// TestGeneratorsKeepTheirFormat guards the identifier format across CF-073.
func TestGeneratorsKeepTheirFormat(t *testing.T) {
	inAlphabet := func(s string) bool {
		for _, c := range s {
			if !strings.ContainsRune(letterBytes, c) {
				return false
			}
		}
		return true
	}
	for i := 0; i < 50; i++ {
		tag := GenerateTagN(8)
		if len(tag) != 8 || !inAlphabet(tag) {
			t.Fatalf("tag %q: want 8 characters of the alphabet", tag)
		}
		branch := GenerateBranchN(10)
		if !strings.HasPrefix(branch, "z9hG4bK.") || len(branch) != len("z9hG4bK.")+10 || !inAlphabet(branch[len("z9hG4bK."):]) {
			t.Fatalf("branch %q: want z9hG4bK. plus 10 characters of the alphabet", branch)
		}
		rs := RandString(10)
		if len(rs) != 10 || !inAlphabet(rs) {
			t.Fatalf("RandString %q: want 10 characters of the alphabet", rs)
		}
	}
}
