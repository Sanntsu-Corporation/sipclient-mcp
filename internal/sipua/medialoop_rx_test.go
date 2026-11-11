package sipua

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/quality"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

func sendRTP(t *testing.T, from *net.UDPConn, to *net.UDPAddr, seq uint16, ts uint32) {
	t.Helper()
	payload := codec.EncodePCMU(make([]int16, 160))
	p := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 0, SequenceNumber: seq, Timestamp: ts, SSRC: 9}, Payload: payload}
	raw, _ := p.Marshal()
	if _, err := from.WriteToUDP(raw, to); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// RX accepts RTP only from the signalled address (CF-179): packets from any
// other source are dropped before they are decrypted or decoded and counted in
// rogue_source_packets; no media_start is emitted.
func TestRunRXDropsAnUnsignalledSource(t *testing.T) {
	uaConn := loopbackUDP(t)
	peer := loopbackUDP(t)
	defer func() { _ = peer.Close() }()

	decoy := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9} // signalled but never used

	evCh := make(chan session.UAEvent, 4)
	ml := &mediaLoop{
		conn: uaConn, codecName: "PCMU", payloadType: 0,
		transform: media.NewIdentityTransform(), jitterBufferMS: 60,
		acc: quality.New(), direction: session.Inbound,
		emit: func(ev session.UAEvent) { evCh <- ev },
	}
	ml.assemble(nil, decoy)
	ml.wg.Add(1)
	go func() { defer ml.wg.Done(); ml.runRX() }()
	defer ml.stop()

	uaAddr := uaConn.LocalAddr().(*net.UDPAddr)
	for i := 0; i < 10; i++ {
		sendRTP(t, peer, uaAddr, uint16(i), uint32(i*160))
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case ev := <-evCh:
		t.Fatalf("unexpected event from an unsignalled source: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}
	snap := ml.acc.Snapshot("PCMU", 0, 60)
	if snap.PacketsReceived != 0 || snap.RogueSourcePackets != 10 {
		t.Fatalf("received=%d rogue=%d, want 0 and 10", snap.PacketsReceived, snap.RogueSourcePackets)
	}
}

// fromSignalled compares IP and port with the signalled address.
func TestFromSignalledComparesIPAndPort(t *testing.T) {
	at := func(ip string, port int) *net.UDPAddr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: port} }
	for _, c := range []struct {
		name      string
		dest, src *net.UDPAddr
		want      bool
	}{
		{"same", at("127.0.0.1", 5000), at("127.0.0.1", 5000), true},
		{"other port", at("127.0.0.1", 5000), at("127.0.0.1", 5002), false},
		{"other ip", at("127.0.0.1", 5000), at("127.0.0.2", 5000), false},
		{"zero address", at("0.0.0.0", 5000), at("127.0.0.1", 5000), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ml := &mediaLoop{acc: quality.New()}
			ml.dest = c.dest
			if got := ml.fromSignalled(ml.neg().dest, c.src); got != c.want {
				t.Fatalf("fromSignalled = %v, want %v", got, c.want)
			}
			if rogue := ml.acc.Snapshot("PCMU", 0, 60).RogueSourcePackets; (rogue == 0) != c.want {
				t.Fatalf("rogue count %d for want=%v", rogue, c.want)
			}
		})
	}
}

// A real gap between runRX launching and the first packet arriving (a SIP/RTP
// setup delay on an answered call, not silence on an already-flowing stream)
// must NOT be charged against packets_lost. playout is anchored at the first
// packet's arrival, not at goroutine launch — this regression-tests that: a
// deliberate ~150ms pre-packet gap (7+ frame periods) followed by ONE real
// packet must show zero concealed/lost frames, since nothing was due before
// media genuinely started.
func TestRunRXDoesNotChargeStartupGapAsLoss(t *testing.T) {
	uaConn := loopbackUDP(t)
	peer := loopbackUDP(t)
	defer func() { _ = peer.Close() }()

	ml := &mediaLoop{
		conn: uaConn, codecName: "PCMU", payloadType: 0,
		transform: media.NewIdentityTransform(), jitterBufferMS: 60,
		acc: quality.New(), direction: session.Inbound,
		emit: func(session.UAEvent) {},
	}
	ml.assemble(nil, peer.LocalAddr().(*net.UDPAddr))
	ml.wg.Add(1)
	go func() { defer ml.wg.Done(); ml.runRX() }()
	defer ml.stop()

	// Simulate the real-world SIP/RTP setup gap: runRX has been polling for
	// ~150ms (7+ 20ms frame periods) before any media arrives.
	time.Sleep(150 * time.Millisecond)

	uaAddr := uaConn.LocalAddr().(*net.UDPAddr)
	sendRTP(t, peer, uaAddr, 0, 0)
	time.Sleep(50 * time.Millisecond) // let the single packet play out

	snap := ml.acc.Snapshot("PCMU", 0, 60)
	if snap.PacketsLost != 0 {
		t.Fatalf("packets_lost = %d, want 0 (pre-media gap must not be charged as loss)", snap.PacketsLost)
	}
	if snap.PacketsReceived != 1 {
		t.Fatalf("packets_received = %d, want 1", snap.PacketsReceived)
	}
}

// The jitter buffer's whole purpose is to tolerate a reorder arriving within
// its configured depth WITHOUT counting it as late/lost (§6.5.1: "a 3-packet
// reorder is fully corrected... out_of_order==3, packets_lost==0"). This is
// the integrated-loop regression for that: seq 0 arrives on time, seq 2
// arrives on time, and seq 1 arrives ~25ms after seq 0 (reordered, but well
// inside the 60ms jitterBufferMS window) — it must land in its own slot via
// jb.Push's OutcomeReorder path (recorded as out_of_order), NOT get evaluated
// against an already-advanced playout cursor as late/lost. Before frame 0's
// deadline was offset by jitterBufferMS (rather than equal to startedAt), this
// would have failed: frame 0 popped in the very same instant it arrived, so by
// the time the reordered seq 1 showed up 25ms later the cursor would already
// be past it.
//
// The stream keeps flowing (seq 3-8 sent right behind the reorder, all well
// ahead of their own due times) rather than going quiet after seq 2. Per
// §6.5.1, "a concealed frame still counts in packets_lost" UNCONDITIONALLY —
// there is no separate "the peer paused" case in this design's model (RTP
// here is assumed continuous, no DTX); a real gap in an active stream is
// genuinely indistinguishable from loss and correctly charged as such. So
// this test must never let real silence reach a frame's due time, or it would
// assert the reorder-tolerance behavior against noise from an unrelated
// (and, for this design, correct) accounting: an artificial pause the test
// itself introduced, not a jitter-buffer defect.
func TestRunRXTolerateReorderWithinJitterBufferWindow(t *testing.T) {
	uaConn := loopbackUDP(t)
	peer := loopbackUDP(t)
	defer func() { _ = peer.Close() }()

	ml := &mediaLoop{
		conn: uaConn, codecName: "PCMU", payloadType: 0,
		transform: media.NewIdentityTransform(), jitterBufferMS: 60,
		acc: quality.New(), direction: session.Inbound,
		emit: func(session.UAEvent) {},
	}
	ml.assemble(nil, peer.LocalAddr().(*net.UDPAddr))
	ml.wg.Add(1)
	go func() { defer ml.wg.Done(); ml.runRX() }()
	defer ml.stop()

	uaAddr := uaConn.LocalAddr().(*net.UDPAddr)
	sendRTP(t, peer, uaAddr, 0, 0)
	time.Sleep(5 * time.Millisecond)
	sendRTP(t, peer, uaAddr, 2, 320) // seq 1 skipped for now
	time.Sleep(5 * time.Millisecond)
	sendRTP(t, peer, uaAddr, 1, 160) // arrives ~10ms after seq 0: reordered
	// Keep the stream flowing: seq 3-8, all delivered within ~25ms of real
	// time, comfortably ahead of every frame's own 60ms+ due time below.
	for seq := uint16(3); seq <= 8; seq++ {
		time.Sleep(5 * time.Millisecond)
		sendRTP(t, peer, uaAddr, seq, uint32(seq)*160)
	}

	// All 9 packets (0-8) are pushed by ~t=40ms real time. Frame k is due at
	// startedAt+60ms+k*20ms, so frames 0-9 are due at 60..240ms. Snapshotting
	// at ~t=140ms evaluates frames 0-4 (due 60/80/100/120/140ms) — all
	// present, since packets 0-4 were pushed ~100ms+ before their own due
	// times — while frame 5 (due 160ms) stays safely unreached with a 20ms
	// margin against real-clock scheduling jitter.
	time.Sleep(100 * time.Millisecond)

	snap := ml.acc.Snapshot("PCMU", 0, 60)
	if snap.LateDiscards != 0 {
		t.Fatalf("late_discards = %d, want 0 (a 10ms reorder is well inside the 60ms window)", snap.LateDiscards)
	}
	if snap.PacketsLost != 0 {
		t.Fatalf("packets_lost = %d, want 0", snap.PacketsLost)
	}
	if snap.OutOfOrder != 1 {
		t.Fatalf("out_of_order = %d, want 1 (seq 1 arriving after seq 2)", snap.OutOfOrder)
	}
	if snap.PacketsReceived != 9 {
		t.Fatalf("packets_received = %d, want 9", snap.PacketsReceived)
	}
}

// Every packet from a source other than the signalled one counts in
// rogue_source_packets, whether or not the signalled peer has already sent. (The
// TX dest never follows an RX source since CF-159; medialoop_symmetric_test.go
// pins that, so this test guards only the counter.)
func TestRunRXCountsEveryUnsignalledPacketAsRogue(t *testing.T) {
	uaConn := loopbackUDP(t)
	peer := loopbackUDP(t)
	rogue := loopbackUDP(t)
	defer func() { _ = peer.Close() }()
	defer func() { _ = rogue.Close() }()

	ml := &mediaLoop{
		conn: uaConn, codecName: "PCMU", payloadType: 0,
		transform: media.NewIdentityTransform(), jitterBufferMS: 60,
		acc: quality.New(), direction: session.Inbound,
		emit: func(session.UAEvent) {},
	}
	ml.assemble(nil, peer.LocalAddr().(*net.UDPAddr)) // the first peer is the signalled one
	ml.wg.Add(1)
	go func() { defer ml.wg.Done(); ml.runRX() }()
	defer ml.stop()

	uaAddr := uaConn.LocalAddr().(*net.UDPAddr)
	sendRTP(t, peer, uaAddr, 0, 0)
	time.Sleep(20 * time.Millisecond)
	for i := 1; i <= 3; i++ {
		sendRTP(t, rogue, uaAddr, uint16(i), uint32(i*160))
		time.Sleep(10 * time.Millisecond)
	}
	snap := ml.acc.Snapshot("PCMU", 0, 60)
	if snap.RogueSourcePackets != 3 || snap.PacketsReceived != 1 {
		t.Fatalf("rogue=%d received=%d, want 3 and 1", snap.RogueSourcePackets, snap.PacketsReceived)
	}
}

// S4b/S4c: the source check runs BEFORE Unprotect. A packet that fails SRTP
// authentication from an unsignalled source is a rogue packet, not an
// authentication failure; the same packet from the signalled source is an
// authentication failure.
func TestRunRXCountsAnUnsignalledSRTPPacketAsRogueNotAuthFailure(t *testing.T) {
	cpA, _, errA := media.GenerateCryptoAttr()
	cpB, _, errB := media.GenerateCryptoAttr()
	cpC, _, errC := media.GenerateCryptoAttr()
	if errA != nil || errB != nil || errC != nil {
		t.Fatal(errA, errB, errC)
	}
	win := media.ReplayWindowFor(60)
	rx, err := media.NewSRTPTransform(cpA, cpB, win) // decrypts with B
	if err != nil {
		t.Fatal(err)
	}
	bad, err := media.NewSRTPTransform(cpC, cpA, win) // protects with C: fails auth at rx
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := (&rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 0, SequenceNumber: 1, SSRC: 7}, Payload: make([]byte, 160)}).Marshal()
	wire, err := bad.Protect(plain)
	if err != nil {
		t.Fatal(err)
	}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000}
	other := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5001}
	mk := func() *mediaLoop {
		ml := &mediaLoop{conn: loopbackUDP(t), codecName: "PCMU", payloadType: 0, transform: rx, jitterBufferMS: 60, acc: quality.New()}
		ml.assemble(rx, peer)
		return ml
	}
	ml := mk()
	defer func() { _ = ml.conn.Close() }()
	ml.handleInbound(append([]byte(nil), wire...), other, new(bool), new(time.Time))
	snap := ml.acc.Snapshot("PCMU", 0, 60)
	if snap.RogueSourcePackets != 1 || snap.SRTPAuthFailures != 0 {
		t.Fatalf("unsignalled: rogue=%d auth=%d, want 1 and 0", snap.RogueSourcePackets, snap.SRTPAuthFailures)
	}
	ml.handleInbound(append([]byte(nil), wire...), peer, new(bool), new(time.Time))
	snap = ml.acc.Snapshot("PCMU", 0, 60)
	if snap.RogueSourcePackets != 1 || snap.SRTPAuthFailures != 1 {
		t.Fatalf("signalled: rogue=%d auth=%d, want 1 and 1", snap.RogueSourcePackets, snap.SRTPAuthFailures)
	}
}

// Each accepted payload type is decoded with its own codec (RFC 3264 5.1: an
// offerer receives every answered codec; CF-155).
func TestHandleInboundDecodesEachPayloadTypeWithItsOwnCodec(t *testing.T) {
	ml := &mediaLoop{
		conn: loopbackUDP(t), codecName: "PCMU", payloadType: 0,
		recvPTs:   map[uint8]string{0: "PCMU", 8: "PCMA"},
		transform: media.NewIdentityTransform(), jitterBufferMS: 20,
		acc: quality.New(),
	}
	ml.assemble(nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000})
	defer func() { _ = ml.conn.Close() }()
	pcm := make([]int16, 160)
	for i := range pcm {
		pcm[i] = int16(i * 150)
	}
	payload := codec.EncodePCMA(pcm)
	wire, err := (&rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 8, SequenceNumber: 1}, Payload: payload}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000} // the signalled address
	ml.handleInbound(wire, src, new(bool), new(time.Time))
	got, ok := ml.jb.Pop()
	if !ok {
		t.Fatal("no frame buffered")
	}
	wantA, _ := codec.Decode("PCMA", payload)
	wantU, _ := codec.Decode("PCMU", payload)
	if !reflect.DeepEqual(got, wantA) || reflect.DeepEqual(got, wantU) {
		t.Fatal("frame at PT 8 was not decoded as PCMA")
	}
}
