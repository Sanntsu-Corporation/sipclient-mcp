package sipua

// Task 33 (R8, governing spec line 1614, deferred to P3): heap-diff and
// sequence-wrap assertions, driven through the REAL runTX goroutine rather
// than a bare audio source or a hand-rolled local variable (see the doc
// comments on each test below for why the naive versions are vacuous).
//
// package sipua, not sipua_test: newAcceptanceLoop builds a *mediaLoop
// directly (in-package state), the same pattern medialoop_tx_test.go already
// uses for TestRunTXSendsPacedRTP.

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/pion/rtp"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/quality"
)

// newAcceptanceLoop assembles a mediaLoop with a DTMFSource claimed as its
// current op, so the measured TX path (runTX -> currentSrc().Frame() ->
// codec.Encode -> rtp.Packet -> conn.WriteTo) is the same one a real dtmf_send
// exercises, not silence.
func newAcceptanceLoop(t *testing.T) *mediaLoop {
	t.Helper()
	txConn := loopbackUDP(t)
	ml := &mediaLoop{
		conn: txConn, codecName: "PCMU", payloadType: 0,
		transform: media.NewIdentityTransform(), jitterBufferMS: 60,
		acc: quality.New(),
	}
	ml.assemble(nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000})
	src, err := codec.NewDTMFSource("123*#", 100, 60, func() { ml.releaseOp() })
	if err != nil {
		t.Fatalf("NewDTMFSource: %v", err)
	}
	if !ml.claimOp(opDTMFInband, src) {
		t.Fatal("claimOp")
	}
	return ml
}

// heapAfterGC reports the live heap in bytes.
//
// runtime.GC() IS CALLED TWICE ON PURPOSE, and this is the whole reason the
// pre-fix version of the test below could not fail (C/I1). One cycle does not
// return the heap to its live set: objects that only became unreachable
// during that cycle survive it and are collected by the NEXT one. Measured on
// this test, that single-GC residue is ~38 KB and — because the residue is
// larger at the first sample than the second, the warm-up having just freed
// the DTMF render — it enters the diff as a CONSTANT -38 KB OFFSET. The old
// assertion was `grew > 128 KiB` against that offset, so the real trip point
// was ~166 KiB, i.e. ~830 B per frame. The reviewer's reference leak retains
// 320 B/frame, moved the number from -38 KB to +38 KB, and stayed green.
//
// With the second cycle the offset disappears: the steady-state path measures
// ~2 B/frame, so a leak no longer has to out-shout a 38 KB artifact.
func heapAfterGC() int64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return int64(ms.HeapAlloc)
}

// maxRetainedBytesPerTXFrame is the per-frame heap-retention budget for a
// steady-state TX path. The path is meant to retain nothing.
//
// THE MEASUREMENT NOISE IS ABSOLUTE, NOT PER-FRAME, and that is what sets this
// number (Cycle 4 / C4-A). With heapAfterGC's double cycle the residual
// warm-up transient landing inside the window is ~0.4-2.0 KB *in total*,
// independent of how many frames the window covers — measured 400/784/1376 B
// over 200 frames and 992/1968 B over 600. So the per-frame floor is bought
// directly with window length (~6 B/frame at 200 frames, ~1-3 at 600), and the
// budget is not a free parameter: it is the noise floor times a safety factor.
//
// Calibrated by injecting a fixed per-frame retention into runTX and finding
// the trip point (C4-A mutation sweep, 4-CPU box):
//
//	600-frame window   16 B/frame leak -> reads 19, PASS
//	                   24 B/frame leak -> reads 25, FAIL
//
// so the gate fires at ~20 B/frame against a declared 24 — it is honest about
// its own sensitivity rather than a number widened until a run passed. Against
// the worst observed noise at the 450-frame floor (2.0 KB / 450 = 4.4 B/frame)
// that leaves ~5x margin, which is what keeps it green under contention on a
// shared box.
//
// For scale: the reference leak — retaining every PCM frame in runTX, one
// SamplesPerFrame []int16 per tick — is 320 B/frame and reads 329. The
// smallest object runTX itself allocates per tick is the ~112 B rtp.Packet
// header, so every leak shape *native to this loop* trips this budget by 5x or
// more. 24 rather than that 112 buys the shape that is NOT a retained loop
// object: an accumulating slice or map entry a few bytes wide per packet (a
// stats history that never trims), which is the leak a 64 B/frame budget — the
// pre-Cycle-4 value, real trip point ~56 — would have shipped green.
const maxRetainedBytesPerTXFrame = 24

// TestR8LongHeldCallDoesNotGrowTheHeap (governing spec line 1614, deferred to
// P3): a long-held call must not grow the heap. Measured across the REAL
// runTX goroutine — encode, RTP marshal, Protect and socket write — because
// that, not the audio source alone, is the path that could retain per-frame
// allocations (a naive version measuring ml.currentSrc().Frame() directly
// never enters runTX at all and stays green under a real per-frame leak
// injected into runTX itself — this is what C1/B1 of the task-33 brief
// correction found). HeapAlloc is read after GC at both ends, so this measures
// RETENTION, not churn.
//
// THE ASSERTION IS A PER-FRAME RATE, NOT A TOTAL. A total has to be chosen
// against an assumed frame count and an assumed noise floor, and the pre-fix
// version got both wrong at once; a rate divides out the frame count the run
// actually achieved and is compared against a floor that was measured (see
// maxRetainedBytesPerTXFrame). Retention is linear in frames while the
// measurement's own noise is not, so the rate is also what a longer window
// would sharpen.
func TestR8LongHeldCallDoesNotGrowTheHeap(t *testing.T) {
	ml := newAcceptanceLoop(t)
	ml.wg.Add(1)
	go func() { defer ml.wg.Done(); ml.runTX() }()
	defer ml.stop()

	// Warm up PAST the one-time transients, not merely into them: the DTMF
	// source renders 40 frames and is exhausted 0.8 s in, and both that render
	// and releaseOp's free of it must land before the first sample rather than
	// inside the window, where they would read as retention (or mask it).
	time.Sleep(2 * time.Second)
	before := heapAfterGC()
	sent0 := ml.acc.Snapshot("PCMU", 0, 60).PacketsSent

	// 12 s, not 4: the noise this measurement fights is a fixed ~0.4-2.0 KB of
	// warm-up residue (see maxRetainedBytesPerTXFrame), so the per-frame floor
	// falls as 1/frames while a leak stays flat. Window length IS the
	// sensitivity knob, and the 4 s version was paying ~6 B/frame of floor for
	// it. 12 s buys ~1-3 B/frame — the whole reason the budget below can be 24
	// rather than 64 — for 8 s of a package that already runs ~112 s.
	time.Sleep(12 * time.Second) // ~600 more frames
	after := heapAfterGC()
	frames := ml.acc.Snapshot("PCMU", 0, 60).PacketsSent - sent0
	if frames < 450 {
		t.Fatalf("only %d frames sent in 4s; runTX is not pacing", frames)
	}

	grew := after - before
	perFrame := grew / int64(frames)
	t.Logf("HEAPDIFF grew=%d bytes over %d TX frames (%d B/frame, budget %d B/frame)",
		grew, frames, perFrame, maxRetainedBytesPerTXFrame)
	if perFrame > maxRetainedBytesPerTXFrame {
		t.Fatalf("the TX path retained %d B/frame (%d bytes across %d TX frames), over the %d B/frame budget; "+
			"a steady-state TX path must retain none of them", perFrame, grew, frames, maxRetainedBytesPerTXFrame)
	}
}

// TestR8RTPSequenceNumberWrapsCleanly: the RTP sequence number on the WIRE,
// out of the real runTX goroutine, must wrap 65535 -> 0 with no gap and no
// duplicate. A naive version asserting a bare local uint16 variable's own
// arithmetic tests Go, not the SUT (medialoop.go:431 makes seq a function
// local with no field to seed) — hence the seq0 seam (RULING 1): ml.seq0
// lets this test seed a start value close to the wrap boundary instead of
// waiting on a random start to reach it.
func TestR8RTPSequenceNumberWrapsCleanly(t *testing.T) {
	rxPeer := loopbackUDP(t)
	defer func() { _ = rxPeer.Close() }()
	txConn := loopbackUDP(t)

	ml := &mediaLoop{
		conn: txConn, codecName: "PCMU", payloadType: 0,
		transform: media.NewIdentityTransform(), jitterBufferMS: 60,
		acc: quality.New(),
	}
	ml.assemble(nil, rxPeer.LocalAddr().(*net.UDPAddr))
	ml.seq0 = 65533
	ml.wg.Add(1)
	go func() { defer ml.wg.Done(); ml.runTX() }()
	defer ml.stop()

	want := []uint16{65533, 65534, 65535, 0, 1, 2}
	var seen []uint16
	buf := make([]byte, 1500)
	_ = rxPeer.SetReadDeadline(time.Now().Add(5 * time.Second))
	for len(seen) < len(want) {
		n, _, err := rxPeer.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read %d/%d packets: %v (seen=%v)", len(seen), len(want), err, seen)
		}
		var p rtp.Packet
		if err := p.Unmarshal(buf[:n]); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		seen = append(seen, p.SequenceNumber)
	}
	t.Logf("SEQ seen=%v", seen)
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("wire sequence %v want %v", seen, want)
		}
	}
}
