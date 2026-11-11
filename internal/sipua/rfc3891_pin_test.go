package sipua_test

// Lane B (rfc-sweep-b) pin for the B-RPL / B-RPS areas (RFC 3891). It passes
// today and must be inverted when its NEW-B finding is fixed. No test here calls t.Parallel
// (parallel_invariant_test.go). It reuses the transfer helpers of
// transfer_test.go (startTransferPeer, dialAnswered, mustTransfer).

import (
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestRFC3891_AttendedReferBodyIsEmpty_AcceptedDeviation pins NEW-B-5 (B-RPL-14,
// RFC 3891 8: "Use of end-to-end security mechanisms to encrypt this information
// is also RECOMMENDED." rfc3891.txt:661-662). Evidence:
// evidence/xfer-attended-udp/excerpt.txt frame 15 and evidence/rpl-attended/excerpt.txt
// frame 8 (the REFER whose Refer-To carries the dialog information has no body,
// Content-Length 0). The only part of the deviation a test can observe is the
// absent body.
//
// The pin only detects a body on by default; an opt-in option or a documented
// reliance on TLS leaves it green (retire it then, do not invert it).
//
// ACCEPTED DEVIATION (rfc-fix-1, D-112):
// a tripwire, not a to-do. Hop-by-hop TLS is the protection; S/MIME would need a
// new dependency (Rule 17) and no peer could decrypt it.
func TestRFC3891_AttendedReferBodyIsEmpty_AcceptedDeviation(t *testing.T) {
	p := startTransferPeer(t, peer.Behaviour{ReferStatus: 202})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	consult := dialAnswered(t, ua, p, events)
	callA := dialAnswered(t, ua, p, events)
	out := mustTransfer(t, ua, session.TransferRequest{
		DialogID: callA.DialogID, Mode: session.TransferAttended, ConsultDialogID: consult.DialogID})
	if !out.Accepted {
		t.Fatalf("result=%+v, want an accepted attended REFER (the pin's precondition)", out)
	}
	if got := p.LastRequestHeader("REFER", "Refer-To"); got == "" {
		t.Fatal("the REFER reached the peer without a Refer-To (the pin's precondition)")
	}
	if b := p.LastRequestBody("REFER"); b != "" {
		t.Errorf("the attended REFER now carries a body %q: the accepted deviation D-112 (REFER dialog information not end-to-end protected) changed; see the design spec section 18", b)
	}
}
