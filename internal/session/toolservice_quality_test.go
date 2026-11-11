package session_test

import (
	"context"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

// media_start is appended to the call log when the UA emits UAEventMediaStart,
// carrying the negotiated addresses and the latch flag.
func TestMediaStartAppendsEvent(t *testing.T) {
	ua := fakes.NewUserAgent()
	ua.MediaViewOK = true
	ua.MediaViewResult = session.MediaView{Codec: "PCMU"}

	m, ts, ctx, uaHandle := newFixture(t, fakes.NewArtifactStore(), fakes.NewTap(),
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return ua, nil })
	callHandle, call := mustDial(t, m, ts, "s1", uaHandle, nil)

	m.HandleUAEventForTest(ctx, session.Handle(uaHandle), session.UAEvent{
		Kind: session.UAEventMediaStart, DialogID: call.DialogID(),
		LocalMediaAddr: "192.0.2.7:16384", RemoteMediaAddr: "198.51.100.1:5555", MediaLatched: true,
	})

	evs, _, _ := call.Events(0)
	found := false
	for _, e := range evs {
		if e.Type == session.EventMediaStart {
			found = true
			if e.Detail["media_latched"] != true {
				t.Fatalf("media_start detail media_latched=%v", e.Detail["media_latched"])
			}
			if e.Detail["remote_media_addr"] != "198.51.100.1:5555" {
				t.Fatalf("media_start remote_media_addr=%v", e.Detail["remote_media_addr"])
			}
		}
	}
	if !found {
		t.Fatal("no media_start event appended")
	}
	_ = callHandle
}

// quality_get returns the §10.10 tier-1 shape with tier 1 and mos_lqo null.
func TestQualityGetTier1Shape(t *testing.T) {
	ua := fakes.NewUserAgent()
	ua.QualityViewOK = true
	ua.QualityViewResult = session.QualityView{
		Tier: 1, PacketsSent: 120, PacketsReceived: 100, PacketsLost: 1, RFactor: 90, MOSEstimate: 4.2,
	}

	m, ts, ctx, uaHandle := newFixture(t, fakes.NewArtifactStore(), fakes.NewTap(),
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return ua, nil })
	callHandle, _ := mustDial(t, m, ts, "s1", uaHandle, nil)

	out, err := ts.QualityGet(ctx, "s1", session.QualityGetInput{Call: callHandle})
	if err != nil {
		t.Fatalf("QualityGet: %v", err)
	}
	om := out.(map[string]any)
	if om["tier"] != 1 {
		t.Fatalf("tier=%v want 1", om["tier"])
	}
	if v, ok := om["mos_lqo"]; !ok || v != nil {
		t.Fatalf("mos_lqo must be present and null, got (%v,%v)", v, ok)
	}
	for _, k := range []string{"packets_sent", "packets_received", "packets_lost", "loss_pct", "jitter_ms_avg",
		"out_of_order", "burst_gaps", "r_factor", "mos_estimate", "rogue_source_packets",
		"tx_underruns", "srtp_auth_failures"} {
		if _, ok := om[k]; !ok {
			t.Fatalf("quality_get missing field %q", k)
		}
	}

	// D26 (P4-W2-06): TX-side packets_sent had ZERO behavioral assertions
	// anywhere — absent from this key list, unset in the fixture above, and
	// unread by the one e2e scenario that calls quality_get. Key presence is not
	// enough: it would survive packets_sent being wired to PacketsReceived, which
	// is exactly the plumbing mistake a copy-paste in toolservice.go would make.
	// This asserts the VALUE, which requires the two fixture numbers to differ.
	if got := om["packets_sent"]; got != int64(120) {
		t.Fatalf("packets_sent = %v (%T), want int64(120) from QualityView.PacketsSent — a value "+
			"of 100 means it is wired to PacketsReceived", got, got)
	}
}
