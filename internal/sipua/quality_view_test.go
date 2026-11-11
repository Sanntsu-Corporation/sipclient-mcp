package sipua

import (
	"net"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/quality"
)

func TestQualityViewReflectsAccumulator(t *testing.T) {
	conn := loopbackUDP(t)
	acc := quality.New()
	for i := 0; i < 7; i++ {
		acc.RecordSent()
		acc.RecordReceived()
	}
	ml := &mediaLoop{
		conn: conn, codecName: "PCMU", jitterBufferMS: 60,
		transform: media.NewIdentityTransform(), acc: acc,
	}
	ml.assemble(nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000})
	defer ml.stop()

	qv := qualityViewFromLoop(ml) // helper under test (see impl)
	if qv.PacketsSent != 7 || qv.PacketsReceived != 7 {
		t.Fatalf("qv sent/received = %d/%d want 7/7", qv.PacketsSent, qv.PacketsReceived)
	}
	if qv.Tier != 1 || qv.MOSLQO != nil {
		t.Fatalf("tier=%d mos_lqo=%v want 1/nil", qv.Tier, qv.MOSLQO)
	}
}
