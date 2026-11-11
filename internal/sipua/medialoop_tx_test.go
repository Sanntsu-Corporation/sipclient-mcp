package sipua

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/quality"
)

// TestRunTXEncodeErrorStopsTheLoopInsteadOfHanging is B11's producer-side
// mutation proof for the encode-error bare return (medialoop.go, the
// `codec.Encode` error branch inside runTX). Before the fix, this branch's
// bare `return` exited the goroutine leaving ml.done open forever — every
// blocking caller (Play, sendDTMFInband, sendDTMFRFC2833) parked forever, and
// ml.stop() could never be called inline to close it (stop()'s own
// ml.wg.Wait() would self-join against the very goroutine calling it).
//
// codecName is set to an unsupported value so codec.Encode fails
// deterministically on the very first tick that has no DTMF event in flight —
// no fault injection or mocking needed, this is a genuinely reachable
// production input (a negotiated codec name codec.Encode/Decode does not
// recognize).
//
// This does NOT go through Play/SendDTMF (those are B13's concern in
// play_test.go/dtmf_test.go) — it pins runTX's OWN exit behavior directly: a
// goroutine parked on ml.done unblocks within a bounded deadline, and stop()
// — called concurrently, exactly as a racing teardownDialog/Hangup/onBye
// would — returns without deadlocking.
func TestRunTXEncodeErrorStopsTheLoopInsteadOfHanging(t *testing.T) {
	peer := loopbackUDP(t)
	defer func() { _ = peer.Close() }()
	txConn := loopbackUDP(t)

	ml := &mediaLoop{
		conn: txConn, codecName: "BOGUS-UNSUPPORTED-CODEC", payloadType: 0,
		transform: media.NewIdentityTransform(), jitterBufferMS: 60,
		acc: quality.New(),
	}
	ml.assemble(nil, peer.LocalAddr().(*net.UDPAddr))
	ml.wg.Add(1)
	go func() { defer ml.wg.Done(); ml.runTX() }()

	// A goroutine parked on ml.done, exactly like Play/sendDTMFInband/
	// sendDTMFRFC2833's blocking selects.
	unblocked := make(chan struct{})
	go func() {
		<-ml.done
		close(unblocked)
	}()

	select {
	case <-unblocked:
	case <-time.After(2 * time.Second):
		t.Fatal("ml.done did not close within 2s after a tx encode error — " +
			"runTX's bare return leaves it open forever (B11)")
	}

	// stop() must complete without an inline self-join deadlock: runTX's own
	// exit already ran `go ml.stop()`, and this concurrent call races it,
	// exactly like teardownDialog/Hangup/onBye would.
	stopped := make(chan struct{})
	go func() { ml.stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("ml.stop() did not return within 2s after a tx encode error — possible deadlock (B11)")
	}
}

// The TX goroutine sends real RTP to the signalled dest at ~50 pps, with the
// negotiated payload type and monotonically increasing sequence numbers spaced
// by 160 in RTP timestamp.
func TestRunTXSendsPacedRTP(t *testing.T) {
	peer := loopbackUDP(t)
	defer func() { _ = peer.Close() }()
	txConn := loopbackUDP(t)

	ml := &mediaLoop{
		conn: txConn, codecName: "PCMU", payloadType: 0,
		transform: media.NewIdentityTransform(), jitterBufferMS: 60,
		acc: quality.New(),
	}
	ml.assemble(nil, peer.LocalAddr().(*net.UDPAddr))
	ml.wg.Add(1)
	go func() { defer ml.wg.Done(); ml.runTX() }()
	defer ml.stop()

	buf := make([]byte, 1500)
	var firstTS uint32
	var lastSeq uint16
	seen := 0
	deadline := time.Now().Add(300 * time.Millisecond)
	_ = peer.SetReadDeadline(deadline)
	for {
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			break
		}
		var p rtp.Packet
		if err := p.Unmarshal(buf[:n]); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if p.PayloadType != 0 {
			t.Fatalf("payload type=%d want 0", p.PayloadType)
		}
		if seen == 0 {
			firstTS, lastSeq = p.Timestamp, p.SequenceNumber
		} else {
			if p.SequenceNumber != lastSeq+1 {
				t.Fatalf("seq gap: %d after %d", p.SequenceNumber, lastSeq)
			}
			if p.Timestamp != firstTS+uint32(seen*160) {
				t.Fatalf("ts=%d want %d", p.Timestamp, firstTS+uint32(seen*160))
			}
			lastSeq = p.SequenceNumber
		}
		seen++
	}
	// ~250ms of the 300ms window => roughly 10-15 packets; assert a sane floor.
	if seen < 8 {
		t.Fatalf("received %d RTP packets in ~250ms, want >= 8 (~50pps)", seen)
	}
	if ml.acc.Snapshot("PCMU", 0, 60).PacketsSent < 8 {
		t.Fatal("accumulator did not record sent packets")
	}
}

// TestRunTXEventPacketsCarryFixedTimestampAndSoleMarker exercises the actual
// wire output of an RFC 4733 send through a real runTX goroutine (the same
// packet-capture harness as TestRunTXSendsPacedRTP), not just dtmfEventTX's
// generator in isolation. dtmf_test.go's unit tests never touch runTX's
// integration branch (around the `if ev := ml.eventTX(); ev != nil` block in
// medialoop.go), so a regression there — e.g. swapping `timestamp =
// ml.eventTS` back for `tk.Timestamp()` — would leave all of dtmf_test.go's
// tests green while shipping a packet stream many gateways reject or
// misparse. This asserts, on the real captured RTP packets: every packet of
// one event (including its end retransmits) carries the IDENTICAL RTP
// timestamp; the marker bit is set on the event's first packet only; and the
// sequence number increments by exactly 1 across event, gap, and audio
// packets alike, with no gap and no duplicate.
func TestRunTXEventPacketsCarryFixedTimestampAndSoleMarker(t *testing.T) {
	peer := loopbackUDP(t)
	defer func() { _ = peer.Close() }()
	txConn := loopbackUDP(t)

	ml := &mediaLoop{
		conn: txConn, codecName: "PCMU", payloadType: 0,
		transform: media.NewIdentityTransform(), jitterBufferMS: 60,
		acc: quality.New(),
	}
	ml.assemble(nil, peer.LocalAddr().(*net.UDPAddr))

	const eventPT = 101
	// 40ms tone => 2 tone ticks + 3 end retransmits = 5 event packets, no gap
	// (gapMs=0), so the packets right after are ordinary audio again.
	ev, err := newDTMFEventTX(eventPT, "1", 40, 0, nil)
	if err != nil {
		t.Fatalf("newDTMFEventTX: %v", err)
	}
	if !ml.claimEventTX(ev) {
		t.Fatal("claimEventTX")
	}

	ml.wg.Add(1)
	go func() { defer ml.wg.Done(); ml.runTX() }()
	defer ml.stop()

	type seenPkt struct {
		pt     uint8
		ts     uint32
		seq    uint16
		marker bool
	}
	var seen []seenPkt
	buf := make([]byte, 1500)
	deadline := time.Now().Add(300 * time.Millisecond)
	_ = peer.SetReadDeadline(deadline)
	for {
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			break
		}
		var p rtp.Packet
		if err := p.Unmarshal(buf[:n]); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		seen = append(seen, seenPkt{pt: p.PayloadType, ts: p.Timestamp, seq: p.SequenceNumber, marker: p.Marker})
	}
	if len(seen) < 8 {
		t.Fatalf("captured %d packets in ~250ms, want >= 8 (5 event + trailing audio)", len(seen))
	}

	// Sequence must increment by exactly 1 across the WHOLE capture — event
	// and audio packets share one sequence-number space with no gap and no
	// duplicate (RFC 4733 §2.2).
	for i := 1; i < len(seen); i++ {
		if seen[i].seq != seen[i-1].seq+1 {
			t.Fatalf("seq[%d]=%d after seq[%d]=%d: want exactly +1 across event/audio ticks", i, seen[i].seq, i-1, seen[i-1].seq)
		}
	}

	var eventPkts []seenPkt
	for _, p := range seen {
		if p.pt == eventPT {
			eventPkts = append(eventPkts, p)
		}
	}
	if len(eventPkts) != 5 {
		t.Fatalf("captured %d event-PT packets, want exactly 5 (2 tone + 3 end retransmits)", len(eventPkts))
	}
	for i, p := range eventPkts {
		if p.ts != eventPkts[0].ts {
			t.Fatalf("event packet %d ts=%d want the identical %d across the whole event, including the end retransmits", i, p.ts, eventPkts[0].ts)
		}
		wantMarker := i == 0
		if p.marker != wantMarker {
			t.Fatalf("event packet %d marker=%v want %v (marker set ONLY on the event's first packet)", i, p.marker, wantMarker)
		}
	}
	if seen[len(seen)-1].pt == eventPT {
		t.Fatal("capture window ended still inside the event; want it to extend into a following audio tick so the seq-continuity check above spans the event->audio transition")
	}
}

// txAttemptLog is a mediaLoop.writeTo stand-in: it records the RTP sequence
// number of every write attempt, fails the attempts failWith selects, and
// signals each attempt so a test reads a fixed number of them without sleeping.
type txAttemptLog struct {
	mu       sync.Mutex
	seqs     []uint16
	okCount  int
	failWith func(attempt int, seq uint16, base uint16) error
	signal   chan struct{}
}

func newTXAttemptLog(failWith func(attempt int, seq uint16, base uint16) error) *txAttemptLog {
	return &txAttemptLog{failWith: failWith, signal: make(chan struct{}, 256)}
}

func (l *txAttemptLog) write(b []byte, _ *net.UDPAddr) (int, error) {
	var pkt rtp.Packet
	if err := pkt.Unmarshal(b); err != nil {
		panic(err)
	}
	l.mu.Lock()
	attempt := len(l.seqs)
	l.seqs = append(l.seqs, pkt.SequenceNumber)
	err := l.failWith(attempt, pkt.SequenceNumber, l.seqs[0])
	if err == nil {
		l.okCount++
	}
	l.mu.Unlock()
	l.signal <- struct{}{}
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// run drives runTX against the log until n attempts were made, stops the loop
// and returns the attempted sequence numbers, the accumulator's sent count and
// the successful-attempt count.
func (l *txAttemptLog) run(t *testing.T, n int) (seqs []uint16, sent int64, ok int) {
	t.Helper()
	peer := loopbackUDP(t)
	defer func() { _ = peer.Close() }()
	ml := &mediaLoop{
		conn: loopbackUDP(t), codecName: "PCMU", payloadType: 0,
		transform: media.NewIdentityTransform(), jitterBufferMS: 60,
		acc: quality.New(), writeTo: l.write,
	}
	ml.assemble(nil, peer.LocalAddr().(*net.UDPAddr))
	ml.wg.Add(1)
	go func() { defer ml.wg.Done(); ml.runTX() }()
	deadline := time.After(time.Duration(n)*20*time.Millisecond + 2*time.Second)
	for i := 0; i < n; i++ {
		select {
		case <-l.signal:
		case <-deadline:
			ml.stop()
			t.Fatalf("only %d of %d write attempts within the bound", i, n)
		}
	}
	ml.stop()
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]uint16(nil), l.seqs...), ml.acc.Snapshot("PCMU", 0, 60).PacketsSent, l.okCount
}

// epermAsTheKernelDelivers is the shape a conntrack reverse-clash drop reaches
// the daemon in: *net.OpError -> *os.SyscallError -> syscall.EPERM.
func epermAsTheKernelDelivers() error {
	return &net.OpError{Op: "write", Err: os.NewSyscallError("sendto", syscall.EPERM)}
}

func countSeq(seqs []uint16, v uint16) int {
	n := 0
	for _, s := range seqs {
		if s == v {
			n++
		}
	}
	return n
}

// strictlyIncreasing reports whether every seqs[i] for i >= from is later than
// seqs[i-1] (uint16 wrap aware). Exact s0+k arithmetic is NOT used: runTX skips
// sequence numbers after a stall of more than 60 ms (seq += skipped), which a
// loaded box can cause.
func strictlyIncreasing(seqs []uint16, from int) bool {
	for i := from; i < len(seqs); i++ {
		if int16(seqs[i]-seqs[i-1]) <= 0 {
			return false
		}
	}
	return true
}

// CF-053: the first write of the stream is retried once on EPERM and that
// retry delivers the frame.
func TestRunTXRetriesTheFirstFrameOnceAfterEPERM(t *testing.T) {
	l := newTXAttemptLog(func(attempt int, _, _ uint16) error {
		if attempt == 0 {
			return epermAsTheKernelDelivers()
		}
		return nil
	})
	seqs, sent, _ := l.run(t, 8)
	if seqs[1] != seqs[0] {
		t.Fatalf("attempts = %v, want the first frame written twice (the retry)", seqs)
	}
	if !strictlyIncreasing(seqs, 2) {
		t.Fatalf("attempts after the retry = %v, want strictly increasing frames", seqs)
	}
	if frames := int64(len(seqs) - 1); sent != frames {
		t.Fatalf("sent = %d, want %d (every frame delivered, the first one by the retry)", sent, frames)
	}
}

// A first frame that fails twice is lost, not retried a third time, and the
// stream keeps its 20 ms cadence.
func TestRunTXPersistentFirstFrameEPERMDoesNotStallTheStream(t *testing.T) {
	l := newTXAttemptLog(func(attempt int, _, _ uint16) error {
		if attempt <= 1 {
			return epermAsTheKernelDelivers()
		}
		return nil
	})
	start := time.Now()
	seqs, sent, _ := l.run(t, 11)
	if elapsed, bound := time.Since(start), 10*20*time.Millisecond+time.Second; elapsed > bound {
		t.Fatalf("11 attempts took %v, want within %v", elapsed, bound)
	}
	if seqs[1] != seqs[0] {
		t.Fatalf("attempts = %v, want the first frame written twice", seqs)
	}
	if n := countSeq(seqs, seqs[0]); n != 2 {
		t.Fatalf("first frame attempted %d times, want exactly 2 (one retry): %v", n, seqs)
	}
	if !strictlyIncreasing(seqs, 2) {
		t.Fatalf("attempts after the retry = %v, want strictly increasing frames", seqs)
	}
	if want := int64(len(seqs) - 2); sent != want {
		t.Fatalf("sent = %d, want %d (the first frame is lost)", sent, want)
	}
}

// Only the first write of the stream is retried: a later EPERM is a lost frame.
func TestRunTXRetriesOnlyTheFirstFrame(t *testing.T) {
	l := newTXAttemptLog(func(attempt int, _, _ uint16) error {
		if attempt == 2 { // the third write: a later frame, not the first
			return epermAsTheKernelDelivers()
		}
		return nil
	})
	seqs, sent, _ := l.run(t, 8)
	if n := countSeq(seqs, seqs[2]); n != 1 {
		t.Fatalf("the failed later frame %d attempted %d times, want 1 (no retry after the first frame): %v", seqs[2], n, seqs)
	}
	if !strictlyIncreasing(seqs, 1) {
		t.Fatalf("attempts = %v, want strictly increasing frames, no repeats", seqs)
	}
	if want := int64(len(seqs) - 1); sent != want {
		t.Fatalf("sent = %d, want %d (one frame lost)", sent, want)
	}
}

// Only EPERM is retried: any other first-write error is one lost frame.
func TestRunTXDoesNotRetryANonEPERMFirstFrameError(t *testing.T) {
	l := newTXAttemptLog(func(attempt int, _, _ uint16) error {
		if attempt == 0 {
			return &net.OpError{Op: "write", Err: net.ErrClosed}
		}
		return nil
	})
	seqs, _, _ := l.run(t, 6)
	if n := countSeq(seqs, seqs[0]); n != 1 {
		t.Fatalf("first frame attempted %d times, want exactly 1 (a non-EPERM error is not retried): %v", n, seqs)
	}
	if !strictlyIncreasing(seqs, 1) {
		t.Fatalf("attempts = %v, want the stream to keep flowing with increasing frames", seqs)
	}
}

// With txOff the TX ticks run but nothing is written and nothing counts as sent.
func TestRunTXWritesNothingWhileTxOff(t *testing.T) {
	for _, off := range []bool{true, false} {
		var writes atomic.Int32
		peer := loopbackUDP(t)
		ml := &mediaLoop{
			conn: loopbackUDP(t), codecName: "PCMU", payloadType: 0, txOff: off,
			transform: media.NewIdentityTransform(), jitterBufferMS: 60,
			acc:     quality.New(),
			writeTo: func([]byte, *net.UDPAddr) (int, error) { writes.Add(1); return 0, nil },
		}
		ml.assemble(nil, peer.LocalAddr().(*net.UDPAddr))
		ml.wg.Add(1)
		go func() { defer ml.wg.Done(); ml.runTX() }()
		time.Sleep(150 * time.Millisecond)
		ml.stop()
		_ = peer.Close()
		if got := writes.Load(); off && got != 0 || !off && got < 1 {
			t.Fatalf("txOff=%v: %d writes", off, got)
		}
		if off && ml.acc.Snapshot("PCMU", 0, 60).PacketsSent != 0 {
			t.Fatal("txOff: packets counted as sent")
		}
	}
}
