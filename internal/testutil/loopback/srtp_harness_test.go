package loopback_test

import (
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// CF-170: the harness used to drop ua_create's srtp, so a UA created with
// srtp "required" ran plain RTP. Two harness UAs with srtp required negotiate
// SRTP and call_status reports it.
func TestHarnessThreadsSRTPToTheUA(t *testing.T) {
	h := loopback.New(t)
	defer h.Close()
	args := map[string]any{"mode": "direct", "srtp": "required", "allow_cleartext_sdes": true}
	callee := h.MustCreateUAWithArgs(t, args)
	s1 := h.NewSession(t)
	caller := s1.MustCallTool(t, "ua_create", mergeTransport(args))["ua_handle"].(string)

	c1 := s1.MustDial(t, caller, h.UAContactURI(t, callee))
	c2 := h.MustWaitForInboundCall(t, 5*time.Second)
	if err := h.Answer(c2); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	s1.MustWait(t, c1, "answered", 5000)
	for _, st := range []map[string]any{
		s1.MustCallTool(t, "call_status", map[string]any{"call": c1}),
		h.MustCallTool(t, "call_status", map[string]any{"call": c2}),
	} {
		if st["srtp"] != true {
			t.Fatalf("call_status srtp = %v, want true: %v", st["srtp"], st)
		}
	}
}

func mergeTransport(args map[string]any) map[string]any {
	out := map[string]any{"transport": "udp"}
	for k, v := range args {
		out[k] = v
	}
	return out
}
