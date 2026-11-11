package session_test

// dtmf_defaults_test.go — E-M6's fix (D20, P4-W2-01, Phase 4 W2).
//
// The spec fixes DTMF's default tone duration at 100 ms and inter-digit gap at
// 50 ms. Every existing assertion derived its expectation FROM THOSE CONSTANTS
// rather than from the literals, so both could be changed together — by a
// well-meaning "tune the defaults" commit — and the whole suite would stay green
// while the shipped product silently stopped matching its own specification.
//
// A LITERAL PIN IS THE POINT. It is deliberately not DRY with the constants: the
// duplication IS the test. If these numbers must change, the spec changes first
// and this test is updated in the same commit, with the spec section cited.

import (
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

func TestDTMFTimingDefaultsAreTheSpecsLiterals(t *testing.T) {
	if got := session.DefaultDTMFDurationMs; got != 100 {
		t.Errorf("DefaultDTMFDurationMs = %d, want the spec's literal 100 — if the default is "+
			"genuinely changing, update the spec and this literal in the same commit; every other "+
			"assertion in the tree derives from this constant and cannot notice the drift", got)
	}
	if got := session.DefaultDTMFGapMs; got != 50 {
		t.Errorf("DefaultDTMFGapMs = %d, want the spec's literal 50 — see the duration case above "+
			"for why this is pinned against a literal rather than against the constant", got)
	}
}
