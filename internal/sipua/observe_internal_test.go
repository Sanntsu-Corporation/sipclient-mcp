package sipua

import (
	"testing"

	"github.com/emiago/sipgo/sip"
)

// TestHeaderValueHasMinimalAllocationsAndIsCorrect is C-M3's mutation proof.
// headerValue used to delegate to headerValues (Rule 16 reuse, Correction
// 13), which regressed its allocation count (AllocsPerRun) on this
// observability hot path — every observed SIP message walks it — from 1/call
// to 2/call (measured; see the allocs assertion below for why 1, not a
// literal 0, is the correct floor through the sip.Message interface).
// C-M3 reverts to a direct single-value walk over msg.GetHeaders(name),
// returning the first value's .Value() or "" if none exist — matching the
// original, pre-Correction-13 implementation exactly (git history).
func TestHeaderValueHasMinimalAllocationsAndIsCorrect(t *testing.T) {
	req := sip.NewRequest(sip.INVITE, sip.Uri{Host: "example"})
	req.AppendHeader(sip.NewHeader("Call-ID", "c-1"))
	req.AppendHeader(sip.NewHeader("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1"))
	req.AppendHeader(sip.NewHeader("Via", "SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK-2"))

	t.Run("absent header returns empty string", func(t *testing.T) {
		if got := headerValue(req, "X-Nope"); got != "" {
			t.Fatalf("headerValue(absent)=%q want empty", got)
		}
	})
	t.Run("multi-value header returns the FIRST value", func(t *testing.T) {
		if got := headerValue(req, "Via"); got != "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1" {
			t.Fatalf("headerValue(Via)=%q want the first Via value", got)
		}
	})
	t.Run("single-value header returns it", func(t *testing.T) {
		if got := headerValue(req, "Call-ID"); got != "c-1" {
			t.Fatalf("headerValue(Call-ID)=%q want %q", got, "c-1")
		}
	})

	// 1, not 0: msg.GetHeaders(name) is sip.Message's ONLY interface method
	// for a named-header lookup (observe.go's own doc comment explains why —
	// the concrete *headers struct's singular GetHeader is not promoted
	// through the interface), and the vendored sipgo's GetHeaders always
	// builds a fresh []Header via append even for a single match
	// (third_party/sipgo/sip/headers.go) — that ONE allocation is inherent to
	// crossing the interface boundary and is not something headerValue's own
	// body can avoid. This is what the ORIGINAL, pre-regression
	// implementation (`hs := msg.GetHeaders(name); return hs[0].Value()`,
	// git history) measured at too — verified directly, both before this fix
	// and against headerValues' 2-allocation delegated path (its own extra
	// `out` slice on top of the same GetHeaders call). The fix's job is
	// eliminating headerValues' EXTRA allocation on top of the unavoidable
	// one, not chasing an unreachable literal zero.
	allocs := testing.AllocsPerRun(1000, func() {
		_ = headerValue(req, "Call-ID")
	})
	if allocs != 1 {
		t.Fatalf("headerValue allocs/op = %v, want 1 (matching the original pre-regression "+
			"implementation — see comment above for why 0 is not reachable through the "+
			"sip.Message interface)", allocs)
	}
}
