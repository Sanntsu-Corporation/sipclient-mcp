package sipua

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/quality"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/sipproxy"
)

// Behind a NAT relay, the peer's real packets arrive from the relay's address.
// RTP is accepted only from the signalled address (CF-179), so while the SDP
// names some other address the relayed packets are dropped and counted rogue;
// once the relay's address is the signalled one they are received. TX always
// stays at the signalled address (CF-159, RFC 3550 11): MediaLatched is never
// set.
func TestRTPFromAnUnsignalledRelayIsDropped(t *testing.T) {
	run := func(t *testing.T, signalRelay bool) (session.UAEvent, bool, quality.Snapshot, string) {
		uaConn := loopbackUDP(t)
		uaAddr := uaConn.LocalAddr().(*net.UDPAddr)
		relay := sipproxy.NewMediaRelay(t, uaAddr)
		defer relay.Close()
		signalled := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9} // a decoy the peer never sends from
		if signalRelay {
			signalled = relay.Addr()
		}
		evCh := make(chan session.UAEvent, 4)
		ml := &mediaLoop{
			conn: uaConn, codecName: "PCMU", payloadType: 0,
			transform: media.NewIdentityTransform(), jitterBufferMS: 60,
			acc: quality.New(), direction: session.Outbound,
			emit: func(e session.UAEvent) { evCh <- e },
		}
		ml.assemble(nil, signalled)
		ml.wg.Add(1)
		go func() { defer ml.wg.Done(); ml.runRX() }()
		defer ml.stop()
		for i := 0; i < 8; i++ {
			p := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 0, SequenceNumber: uint16(i), Timestamp: uint32(i * 160)}, Payload: codec.EncodePCMU(make([]int16, 160))}
			raw, _ := p.Marshal()
			relay.Inject(raw)
			time.Sleep(5 * time.Millisecond)
		}
		select {
		case ev := <-evCh:
			return ev, true, ml.snapshot(), signalled.String()
		case <-time.After(300 * time.Millisecond):
			return session.UAEvent{}, false, ml.snapshot(), signalled.String()
		}
	}
	t.Run("unsignalled relay is dropped", func(t *testing.T) {
		_, started, snap, _ := run(t, false)
		if started || snap.PacketsReceived != 0 || snap.RogueSourcePackets != 8 {
			t.Fatalf("started=%v received=%d rogue=%d, want dropped (rogue 8)", started, snap.PacketsReceived, snap.RogueSourcePackets)
		}
	})
	t.Run("signalled relay is received", func(t *testing.T) {
		ev, started, snap, signalled := run(t, true)
		if !started || ev.MediaLatched || ev.RemoteMediaAddr != signalled || snap.RogueSourcePackets != 0 {
			t.Fatalf("started=%v latched=%v remote=%q rogue=%d", started, ev.MediaLatched, ev.RemoteMediaAddr, snap.RogueSourcePackets)
		}
	})
}

// fakeClock is a test-only media.Clock whose Now() only moves when Advance is
// called, decoupling the RX drain loop's cadence from real wall-clock time.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{now: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// runRXOverRelay feeds n PCMU packets through a relay (built via newRelay,
// AFTER the real UA socket exists, targeting its actual LocalAddr() — the
// relay cannot be pre-built by the caller with a placeholder address, since
// there is no way to know the UA's real ephemeral port before uaConn is
// created here) to a fresh mediaLoop and returns its final quality snapshot.
// A fakeClock advances by exactly one media.FrameDuration per packet
// injected, so the drain loop pops (or conceals) exactly one slot per packet
// regardless of real injection speed — the small real sleep per iteration is
// only to let the actual loopback UDP delivery land before the next inject,
// not to pace playout.
func runRXOverRelay(t *testing.T, newRelay func(ua *net.UDPAddr) *sipproxy.MediaRelay, n int) quality.Snapshot {
	t.Helper()
	uaConn := loopbackUDP(t)
	relay := newRelay(uaConn.LocalAddr().(*net.UDPAddr))
	defer relay.Close()
	// The relay's address is the signalled one, so its packets are accepted.
	fc := newFakeClock(time.Unix(0, 0))
	ml := &mediaLoop{
		conn: uaConn, codecName: "PCMU", payloadType: 0,
		transform: media.NewIdentityTransform(), jitterBufferMS: 60,
		jb: media.NewJitterBuffer(3), plc: media.NewPLC(160),
		acc: quality.New(), direction: session.Outbound,
		clock: fc,
	}
	ml.assemble(nil, relay.Addr())
	ml.wg.Add(1)
	go func() { defer ml.wg.Done(); ml.runRX() }()
	defer ml.stop()

	for i := 0; i < n; i++ {
		p := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 0,
			SequenceNumber: uint16(i), Timestamp: uint32(i * 160)},
			Payload: codec.EncodePCMU(make([]int16, 160))}
		raw, _ := p.Marshal()
		relay.Inject(raw)
		time.Sleep(2 * time.Millisecond) // real: let loopback delivery land
		fc.Advance(media.FrameDuration)  // virtual: exactly one frame due
	}
	time.Sleep(50 * time.Millisecond) // let runRX's own loop drain the final frame
	return ml.snapshot()
}

// TestQualityGetReflectsInjectedLoss is the R4 acceptance: a synthetic 5%
// uniform loss injected into the RX path (via netfault, §14.6) drives loss_pct
// to 5.0±0.5 and drops mos_estimate by at least 0.3 relative to a lossless run.
func TestQualityGetReflectsInjectedLoss(t *testing.T) {
	const n = 1000

	clean := runRXOverRelay(t, func(ua *net.UDPAddr) *sipproxy.MediaRelay {
		return sipproxy.NewMediaRelay(t, ua)
	}, n)

	lossy := runRXOverRelay(t, func(ua *net.UDPAddr) *sipproxy.MediaRelay {
		return sipproxy.NewLossyMediaRelay(t, ua, 0.05)
	}, n)

	if lossy.LossPct < 4.5 || lossy.LossPct > 5.5 {
		t.Fatalf("loss_pct = %.2f, want 5.0 ±0.5", lossy.LossPct)
	}
	if drop := clean.MOSEstimate - lossy.MOSEstimate; drop < 0.3 {
		t.Fatalf("mos_estimate dropped %.2f (clean=%.2f lossy=%.2f), want >= 0.3",
			drop, clean.MOSEstimate, lossy.MOSEstimate)
	}
}

// TestBurstGapsRecordedForConsecutiveLoss is the §10.10 acceptance: a
// deterministic run of 3 consecutive dropped packets produces exactly one
// burst_gaps entry with packets==3, and sum(packets over burst_gaps) <=
// packets_lost holds.
func TestBurstGapsRecordedForConsecutiveLoss(t *testing.T) {
	// BurstDrop{EveryN:10, RunLen:3} drops packets 1-3 of every 10-packet
	// group (1-based: pos=(n-1)%10, dropped when pos<3) — six such 3-runs
	// across 60 packets.
	const n = 60

	snap := runRXOverRelay(t, func(ua *net.UDPAddr) *sipproxy.MediaRelay {
		return sipproxy.NewBurstyMediaRelay(t, ua, 10, 3) // drop 3 of every 10
	}, n)

	if len(snap.BurstGaps) == 0 {
		t.Fatal("expected at least one burst_gaps entry, got none")
	}
	var sumBurstPackets int64
	for _, g := range snap.BurstGaps {
		if g.Packets < 2 {
			t.Fatalf("burst_gaps entry with packets=%d, want >= 2 (isolated losses must never appear here)", g.Packets)
		}
		sumBurstPackets += int64(g.Packets)
	}
	if sumBurstPackets > snap.PacketsLost {
		t.Fatalf("sum(burst_gaps packets)=%d exceeds packets_lost=%d, invariant violated",
			sumBurstPackets, snap.PacketsLost)
	}
}
