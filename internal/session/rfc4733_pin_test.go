package session

// Lane D (rfc-sweep-d) pin for the ua_create default (6a D11), kept as an
// accepted-deviation tripwire (D-135). It uses the NewManager NewUA capture seam of
// TestUACreateThreadsInlineDTMFAndTimerKeys (toolservice_test.go), which pins
// the DTMFMode default the same way.

import (
	"context"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// TestRFC4733_NEWD4_UACreateDefaultsToDisabledSRTP_AcceptedDeviation pins
// NEW-D-4 (D-TSEC-01, RFC 4733 6: "Thus, message integrity MUST be provided
// for the telephone-event payload type." rfc4733.txt:2090-2091). Evidence:
// evidence/rg-echo/excerpt.txt frame 4 (product-default offer m=audio ...
// RTP/AVP, telephone-event 101 with no a=crypto) and evidence/rg-echo/rtp.txt
// (PT 101 packets in the clear). Locus: internal/session/toolservice.go:UACreate
// (defaultStr(in.SRTP, "disabled")), bytes emitted via
// internal/media/sdp.go:BuildOffer's RTP/AVP line.
//
// ACCEPTED DEVIATION (decision D-135, CF-135): events are integrity-protected
// only with srtp "required" over TLS. No in-scope option protects them on the
// UDP default without cleartext SDES keys (CF-134). This pin is a tripwire:
// if the default changes, revisit D-135.
func TestRFC4733_NEWD4_UACreateDefaultsToDisabledSRTP_AcceptedDeviation(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var got UAConfig
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc,
		Policy: policy.NewStaticStore(policy.Defaults(), fc, testLogger()),
		Logger: testLogger(),
		NewUA: func(_ context.Context, cfg UAConfig) (UserAgent, error) {
			got = cfg
			return nopAgent{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := NewToolService(m).UACreate(ctx, "s1", UACreateInput{Mode: "direct", Transport: string(TransportUDP)}); err != nil {
		t.Fatalf("UACreate(direct, srtp omitted): %v", err)
	}
	if got.SRTP != "disabled" {
		t.Fatalf("UAConfig.SRTP default = %q: decision D-135 (accepted deviation, CF-135) no longer holds: revisit it", got.SRTP)
	}
}
