package loopback_test

import (
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// TestCallDialHeaderInjectionNeverReachesTheWire is HIGH-1's wire assertion —
// the point of the finding: a Route header smuggled through call_dial's
// headers map must be rejected BEFORE anything is dialled, not merely
// rejected in some other way that still lets an INVITE leave the process.
//
// sipgo v0.24.1's Request.Destination() prefers a Route header over the
// Request-URI when resolving the real next hop (sip/request.go:191-200), and
// getHeader matches by LOWERCASED name across any header type
// (sip/headers.go:236-244), so an unvalidated "Route" header would redirect
// the INVITE to attacker.test regardless of what to_uri and
// policy.CheckDestination already approved. h.Peer() is the harness's
// canonical far-end peer (contract §2.10); InviteCount() is its existing
// per-method counter (Rule 16 reuse — no new mechanism invented here).
func TestCallDialHeaderInjectionNeverReachesTheWire(t *testing.T) {
	h := loopback.New(t)
	defer h.Close()

	s := h.NewSession(t)
	ua := s.MustCreateUA(t, "direct")

	before := h.Peer().InviteCount()

	_, err := s.CallTool("call_dial", map[string]any{
		"ua": ua, "to_uri": h.PeerURI(),
		"headers": map[string]any{"Route": "sip:evil@attacker.test"},
	})
	if got := loopback.ErrorCode(err); got != "invalid_argument" {
		t.Fatalf("call_dial with an injected Route header returned code %q, want invalid_argument", got)
	}

	// THE POINT OF THE FINDING: the far end saw NOTHING. A check that
	// rejects the tool call but only after an INVITE has already been built
	// and sent (or sent to the wrong host) is not this fix.
	if got := h.Peer().InviteCount() - before; got != 0 {
		t.Fatalf("peer saw %d INVITE(s) after a call_dial that should have been rejected "+
			"at the input boundary, want 0 — the INVITE must never be built, let alone sent", got)
	}
}
