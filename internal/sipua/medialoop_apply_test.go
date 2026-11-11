package sipua

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtp"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/quality"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// collectRTP records (payload type) of every datagram sock receives.
func collectRTP(t *testing.T, sock *net.UDPConn) (get func() []uint8) {
	t.Helper()
	var mu sync.Mutex
	var pts []uint8
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := sock.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var p rtp.Packet
			if p.Unmarshal(buf[:n]) == nil {
				mu.Lock()
				pts = append(pts, p.PayloadType)
				mu.Unlock()
			}
		}
	}()
	return func() []uint8 {
		mu.Lock()
		defer mu.Unlock()
		return append([]uint8(nil), pts...)
	}
}

func txLoop(t *testing.T, dest *net.UDPAddr) *mediaLoop {
	t.Helper()
	ml := &mediaLoop{
		conn: loopbackUDP(t), codecName: "PCMU", payloadType: 0,
		transform: media.NewIdentityTransform(), jitterBufferMS: 60, acc: quality.New(),
	}
	ml.assemble(nil, dest)
	ml.launch()
	t.Cleanup(ml.stop)
	return ml
}

// I7: a swap is seen whole. Every packet sent while two states alternate
// belongs to one of them: (socket A, PT 0) or (socket B, PT 8). Run under -race.
func TestApplySwapIsAtomic(t *testing.T) {
	a, b := loopbackUDP(t), loopbackUDP(t)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	gotA, gotB := collectRTP(t, a), collectRTP(t, b)
	na := &negotiated{codecName: "PCMU", payloadType: 0, recvPTs: map[uint8]string{0: "PCMU"}, dest: a.LocalAddr().(*net.UDPAddr)}
	nb := &negotiated{codecName: "PCMA", payloadType: 8, recvPTs: map[uint8]string{8: "PCMA"}, dest: b.LocalAddr().(*net.UDPAddr)}
	ml := txLoop(t, na.dest)
	for i := 0; i < 1000; i++ {
		if i%2 == 0 {
			ml.swap(nb)
		} else {
			ml.swap(na)
		}
		if i%100 == 0 {
			time.Sleep(25 * time.Millisecond)
		}
	}
	time.Sleep(60 * time.Millisecond)
	for _, pt := range gotA() {
		if pt != 0 {
			t.Fatalf("a packet at A carried PT %d, want 0", pt)
		}
	}
	for _, pt := range gotB() {
		if pt != 8 {
			t.Fatalf("a packet at B carried PT %d, want 8", pt)
		}
	}
	if len(gotA())+len(gotB()) == 0 {
		t.Fatal("no RTP sent")
	}
}

// A swap re-targets the loop without restarting it: the TX source (a prompt in
// flight) keeps running and the packets after the swap go to the new address.
func TestApplyKeepsAnInFlightPlay(t *testing.T) {
	a, b := loopbackUDP(t), loopbackUDP(t)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	gotA, gotB := collectRTP(t, a), collectRTP(t, b)
	ml := txLoop(t, a.LocalAddr().(*net.UDPAddr))
	srcBefore := ml.currentSrc()
	time.Sleep(100 * time.Millisecond)
	ml.swap(&negotiated{codecName: "PCMU", payloadType: 0, recvPTs: map[uint8]string{0: "PCMU"}, dest: b.LocalAddr().(*net.UDPAddr)})
	nA := len(gotA())
	time.Sleep(200 * time.Millisecond)
	if ml.currentSrc() != srcBefore {
		t.Error("the swap replaced the TX source")
	}
	if len(gotB()) == 0 {
		t.Error("no RTP reached the new address after the swap")
	}
	if extra := len(gotA()) - nA; extra > 2 { // a tick already in flight
		t.Errorf("%d packets still went to the old address after the swap", extra)
	}
}

func TestNegotiatedFollowsHold(t *testing.T) {
	sess := &media.Session{LocalAddr: "127.0.0.1:1", RemoteAddr: "127.0.0.1:2000", Codec: "PCMU", Direction: media.DirRecvOnly}
	n, err := newNegotiated(sess)
	if err != nil || !n.txOff {
		t.Fatalf("recvonly: txOff=%v err=%v, want TX off", n != nil && n.txOff, err)
	}
	sess.Direction = media.DirSendRecv
	if n, _ = newNegotiated(sess); n.txOff {
		t.Error("sendrecv: TX still off")
	}
}

// An RX packet is classified with ONE negotiation snapshot: a swap that lands
// after the snapshot (here, inside rxSnapshotHook) must not make a packet from
// the old peer be judged with the new peer's payload types.
func TestRXPacketUsesOneNegotiationSnapshot(t *testing.T) {
	peerA, peerB := loopbackUDP(t), loopbackUDP(t)
	t.Cleanup(func() { _ = peerA.Close(); _ = peerB.Close() })
	na := &negotiated{codecName: "PCMU", payloadType: 0, recvPTs: map[uint8]string{0: "PCMU"}, dest: peerA.LocalAddr().(*net.UDPAddr)}
	nb := &negotiated{codecName: "PCMA", payloadType: 8, recvPTs: map[uint8]string{8: "PCMA"}, dest: peerB.LocalAddr().(*net.UDPAddr)}
	ml := &mediaLoop{
		conn: loopbackUDP(t), codecName: "PCMU", payloadType: 0,
		transform: media.NewIdentityTransform(), jitterBufferMS: 60, acc: quality.New(),
		emit: func(session.UAEvent) {},
	}
	ml.assemble(nil, na.dest)
	rxSnapshotHook = func() { ml.swap(nb) }
	t.Cleanup(func() { rxSnapshotHook = nil })

	p := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 0, SequenceNumber: 1, Timestamp: 160, SSRC: 9},
		Payload: codec.EncodePCMU(make([]int16, 160))}
	raw, _ := p.Marshal()
	started, at := false, time.Time{}
	ml.clock = clock.System()
	ml.handleInbound(raw, na.dest, &started, &at)
	if snap := ml.acc.Snapshot("PCMU", 0, 60); snap.PacketsReceived != 1 || snap.RogueSourcePackets != 0 {
		t.Fatalf("received=%d rogue=%d, want 1 and 0: the packet from the old peer must be judged by the snapshot it was checked against",
			snap.PacketsReceived, snap.RogueSourcePackets)
	}
}
