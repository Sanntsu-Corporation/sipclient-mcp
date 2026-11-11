package loopback_test

import (
	"strings"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// TestCallDialRejectsAMediaPlanStepOverMaxStepDurationS is Phase 4 W1 M2's
// D7 loopback coverage (D7/P4-P07): it exercises Inputs §4 (RN-1)'s new
// max_step_duration_s ceiling through the REAL Manager/UA/MCP-server stack —
// call_dial's tools/call JSON-RPC handler, not validateMediaPlan called
// directly — so a wiring regression between the tool surface and the
// validator (a field renamed or dropped before validation runs) would be
// caught here even if internal/session's own unit tests still passed.
//
// WithPolicyOverride, not TripDurationCap: this module raised
// max_call_duration_s's default 24x (300s -> 7200s), which would have made
// TripDurationCap's fake-clock advance jump the same 24x if this test used
// it — and TripDurationCap has zero live callers in the tree today, so
// bounding the cap explicitly (as durationcap_test.go already does for
// max_call_duration_s) is both the established pattern and the one that
// keeps this test's runtime independent of that default.
func TestCallDialRejectsAMediaPlanStepOverMaxStepDurationS(t *testing.T) {
	h := loopback.New(t, loopback.WithPolicyOverride("limits.max_step_duration_s", 5))
	defer h.Close()

	ua := h.MustCreateUA(t, "direct")

	_, err := h.CallTool("call_dial", map[string]any{
		"ua": ua, "to_uri": h.PeerURI(),
		"media_plan": []map[string]any{
			{"op": "wait", "duration_ms": float64(5001)},
		},
	})
	if err == nil {
		t.Fatal("call_dial accepted a wait step over the configured 5s max_step_duration_s ceiling")
	}
	if !strings.Contains(err.Error(), "max_step_duration_s") {
		t.Fatalf("error %q does not name max_step_duration_s", err)
	}

	// The accept side, at exactly the ceiling: a guard that rejected every
	// wait step would pass the case above too. Reuses `ua` — the rejected
	// call above never reached CreateUA/CreateCall, so this session's
	// STRICT one-UA-per-session slot (Phase 1, owner-locked decision) is
	// still free.
	env := h.MustCallTool(t, "call_dial", map[string]any{
		"ua": ua, "to_uri": h.PeerURI(),
		"media_plan": []map[string]any{
			{"op": "wait", "duration_ms": float64(5000)},
		},
	})
	if _, ok := env["call_handle"].(string); !ok {
		t.Fatalf("call_dial at the ceiling did not return a call_handle: %+v", env)
	}
}
