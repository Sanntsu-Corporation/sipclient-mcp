// internal/sipua/dtmf_detect_test.go — Task 17: inband DTMF detection on the
// RX path.
//
// TestInbandDetectionIsOffUnlessTheProfileSelectsIt, TestRXDetectsInbandDigitsAndEmitsUAEventDTMF
// and TestRXDoesNotDetectWhenNoDetectorIsInstalled exercise mediaLoop.tapRX and
// UA.inbandDetectionEnabled directly, by hand-building a mediaLoop and calling
// tapRX. That is deliberately NOT the whole story: neither the real RX entry
// point (handleInbound, reached only through runRX reading real wire packets)
// nor startMediaLoop's conditional detector install is exercised by those
// three alone — deleting both the ml.tapRX(pcm) call inside handleInbound and
// the detector-installation block inside startMediaLoop still leaves them
// green. TestHandleInboundDetectsInbandDTMFThroughRealRTP and
// TestStartMediaLoopInstallsDetectorOnlyForInbandMode close that gap by
// driving the real production entry points.
package sipua

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/quality"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

type digitSink struct {
	mu   sync.Mutex
	seen []session.UAEvent
}

func (s *digitSink) emit(ev session.UAEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, ev)
}

func (s *digitSink) digits() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []byte
	for _, ev := range s.seen {
		if ev.Kind == session.UAEventDTMF {
			out = append(out, ev.Digit...)
		}
	}
	return string(out)
}

func TestInbandDetectionIsOffUnlessTheProfileSelectsIt(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want bool
	}{
		{"", false}, {"rfc2833", false}, {"info", false}, {"inband", true},
	} {
		u := &UA{cfg: Config{DTMFMode: tc.mode}}
		if got := u.inbandDetectionEnabled(); got != tc.want {
			t.Fatalf("dtmf_mode=%q => inband detection %v, want %v", tc.mode, got, tc.want)
		}
	}
}

func TestRXDetectsInbandDigitsAndEmitsUAEventDTMF(t *testing.T) {
	sink := &digitSink{}
	ml := &mediaLoop{
		emit: sink.emit, dialogID: "d1", callID: "call-abc",
		direction: session.Outbound, detector: codec.NewDTMFDetector(),
	}
	ml.assemble(nil, nil)
	ml.onDigit = func(digit byte, mode string, durationMs int) {
		ml.emit(session.UAEvent{
			Kind: session.UAEventDTMF, DialogID: ml.dialogID, CallID: ml.callID,
			Direction: ml.direction, Digit: string(digit), DTMFMode: mode, DurationMs: durationMs,
		})
	}

	// Feed the RX tap the PCM a peer sending "42" inband would produce.
	src, err := codec.NewDTMFSource("42", 100, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		ml.tapRX(src.Frame())
	}
	if got := sink.digits(); got != "42" {
		t.Fatalf("detected %q want \"42\"", got)
	}
	for _, ev := range sink.seen {
		if ev.Kind == session.UAEventDTMF && ev.DTMFMode != "inband" {
			t.Fatalf("mode=%q want inband", ev.DTMFMode)
		}
	}
}

func TestRXDoesNotDetectWhenNoDetectorIsInstalled(t *testing.T) {
	sink := &digitSink{}
	ml := &mediaLoop{emit: sink.emit, dialogID: "d1"}
	ml.assemble(nil, nil)
	ml.onDigit = func(byte, string, int) { t.Fatal("onDigit must not fire with no detector") }
	src, _ := codec.NewDTMFSource("9", 100, 0, nil)
	for i := 0; i < 6; i++ {
		ml.tapRX(src.Frame())
	}
}

// TestHandleInboundDetectsInbandDTMFThroughRealRTP is the coverage-gap closer:
// it never calls tapRX directly. Instead it opens two real loopback UDP
// sockets, marshals real RTP packets carrying REAL G.711 mu-law-encoded DTMF
// tone audio (the exact bytes a peer sending inband DTMF would put on the
// wire), and drives them into runRX's real ReadFromUDP loop, which reaches
// tapRX only via handleInbound's post-decode call. If that call (or the
// detector field it reads) were ever deleted, this test would hang until its
// timeout and fail — unlike the three tests above, which construct a
// mediaLoop and call tapRX by hand and so would stay green either way.
func TestHandleInboundDetectsInbandDTMFThroughRealRTP(t *testing.T) {
	uaConn := loopbackUDP(t)
	peer := loopbackUDP(t)
	defer func() { _ = peer.Close() }()

	evCh := make(chan session.UAEvent, 8)
	ml := &mediaLoop{
		conn: uaConn, codecName: "PCMU", payloadType: 0,
		transform: media.NewIdentityTransform(), jitterBufferMS: 60,
		acc: quality.New(), direction: session.Inbound,
		detector: codec.NewDTMFDetector(),
		emit:     func(ev session.UAEvent) { evCh <- ev },
	}
	ml.onDigit = func(digit byte, mode string, durationMs int) {
		ml.emit(session.UAEvent{
			Kind: session.UAEventDTMF, Digit: string(digit), DTMFMode: mode, DurationMs: durationMs,
		})
	}
	ml.assemble(nil, peer.LocalAddr().(*net.UDPAddr))
	ml.wg.Add(1)
	go func() { defer ml.wg.Done(); ml.runRX() }()
	defer ml.stop()

	uaAddr := uaConn.LocalAddr().(*net.UDPAddr)
	src, err := codec.NewDTMFSource("5", 100, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	seq := uint16(0)
	for i := 0; i < 10; i++ { // 5 tone frames + 5 silence frames, matching the source's own layout
		pcm := src.Frame()
		payload := codec.EncodePCMU(pcm)
		p := &rtp.Packet{Header: rtp.Header{
			Version: 2, PayloadType: 0, SequenceNumber: seq, Timestamp: uint32(seq) * 160, SSRC: 9,
		}, Payload: payload}
		raw, merr := p.Marshal()
		if merr != nil {
			t.Fatalf("marshal: %v", merr)
		}
		if _, werr := peer.WriteToUDP(raw, uaAddr); werr != nil {
			t.Fatalf("send: %v", werr)
		}
		seq++
		time.Sleep(5 * time.Millisecond)
	}

	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-evCh:
			if ev.Kind != session.UAEventDTMF {
				continue // e.g. media_start, emitted on the first authenticated packet
			}
			if ev.DTMFMode != "inband" {
				t.Fatalf("mode=%q want inband", ev.DTMFMode)
			}
			if ev.Digit != "5" {
				t.Fatalf("digit=%q want %q", ev.Digit, "5")
			}
			return
		case <-deadline:
			t.Fatal("no dtmf event observed through the real RTP -> decode -> tapRX pipeline")
		}
	}
}

// TestStartMediaLoopInstallsDetectorOnlyForInbandMode is the second
// coverage-gap closer: it drives the real startMediaLoop entry point (not a
// hand-built mediaLoop literal), so deleting startMediaLoop's
// `if u.inbandDetectionEnabled() { ml.detector = ... }` block would leave this
// test failing where the three original tests would not notice at all.
func TestStartMediaLoopInstallsDetectorOnlyForInbandMode(t *testing.T) {
	for _, tc := range []struct {
		mode         string
		wantDetector bool
	}{
		{"inband", true}, {"rfc2833", false}, {"info", false}, {"", false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			u := newTestUAWithDaemonCtx(context.Background(), t)
			u.cfg.DTMFMode = tc.mode
			conn := loopbackUDP(t)
			defer func() { _ = conn.Close() }()

			d := &dialog{
				id: newDialogID(), phase: phaseAnswered,
				mediaConn:    conn,
				mediaSession: &media.Session{Codec: "PCMU", RemoteAddr: "127.0.0.1:5004"},
			}
			u.startMediaLoop(d)
			if d.mediaLoop == nil {
				t.Fatal("startMediaLoop did not publish a media loop")
			}
			defer d.mediaLoop.stop()

			if got := d.mediaLoop.detector != nil; got != tc.wantDetector {
				t.Fatalf("dtmf_mode=%q detector installed=%v want %v", tc.mode, got, tc.wantDetector)
			}
		})
	}
}

// Task 18: RFC 4733 telephone-event detection on the RX path.

func TestRXDetectsTelephoneEventOncePerDigit(t *testing.T) {
	sink := &digitSink{}
	ml := &mediaLoop{
		emit: sink.emit, dialogID: "d1", callID: "call-abc",
		direction: session.Inbound, recvEventPTs: map[uint8]bool{101: true},
	}
	ml.assemble(nil, nil)
	ml.onDigit = func(digit byte, mode string, durationMs int) {
		ml.emit(session.UAEvent{
			Kind: session.UAEventDTMF, DialogID: ml.dialogID, CallID: ml.callID,
			Digit: string(digit), DTMFMode: mode, DurationMs: durationMs,
		})
	}

	// Four digits, each rendered exactly as our own sender renders them.
	//
	// THE DIGIT CHOICE IS THE POINT, not incidental coverage. '7' is a decimal
	// digit, which every plausible decode gets right. '*' (code 10), '#' (code 11)
	// and 'B' (code 13) are the ones a codec.DTMFAlphabet[code] index CORRUPTS —
	// it would report 'A', 'B' and 'D' respectively.
	//
	// B-M5 (D20, W2): SCOPE CORRECTION. This is a ROUND TRIP through the real TX and
	// RX paths, which is what makes it valuable — but a round trip cannot isolate the
	// decode inverse: an encoder and decoder that agreed on the WRONG mapping would
	// pass it. The isolated pin of codec.DTMFDigitForEventCode against the alphabet
	// index lives in internal/media/codec's own tests, not here.
	const want = "7*#B"
	var ts uint32
	ev, err := newDTMFEventTX(101, want, 60, 20, nil)
	if err != nil {
		t.Fatal(err)
	}
	for {
		payload, marker, newTS, more := ev.next()
		if !more {
			break
		}
		if payload == nil {
			continue
		}
		if newTS { // a fresh RTP timestamp per event, as the real sender does
			ts += 1600
		}
		ml.handleTelephoneEvent(&rtp.Packet{
			Header:  rtp.Header{PayloadType: 101, Marker: marker, Timestamp: ts},
			Payload: payload,
		})
	}
	if got := sink.digits(); got != want {
		t.Fatalf("detected %q want %q — an alphabet-indexed decode reports \"7ABD\"", got, want)
	}
	for _, e := range sink.seen {
		if e.Kind != session.UAEventDTMF {
			continue
		}
		if e.DTMFMode != "rfc2833" {
			t.Fatalf("mode=%q want rfc2833", e.DTMFMode)
		}
		if e.DurationMs != 60 {
			t.Fatalf("duration_ms=%d want 60 (480 timestamp units / 8)", e.DurationMs)
		}
	}
}

func TestRXIgnoresTelephoneEventWhenNotNegotiated(t *testing.T) {
	sink := &digitSink{}
	ml := &mediaLoop{emit: sink.emit, dialogID: "d1", payloadType: 0} // recvEventPTs stays empty
	// A signalled source, and the packet comes from it: only the event-PT gate
	// can drop this packet (CF-179 would drop it first with no dest).
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	ml.assemble(nil, src)
	ml.onDigit = func(byte, string, int) { t.Fatal("must not report a digit when no event PT is negotiated") }
	ml.handleInbound(mustMarshalRTP(t, 101, dtmfEventPayload(1, true, 480)), src, new(bool), new(time.Time))
}

func TestTelephoneEventPacketsAreNotFedToTheJitterBuffer(t *testing.T) {
	sink := &digitSink{}
	ml := &mediaLoop{emit: sink.emit, dialogID: "d1", payloadType: 0, recvEventPTs: map[uint8]bool{101: true}}
	ml.assemble(nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	var digits int
	ml.onDigit = func(byte, string, int) { digits++ }
	started, startedAt := false, time.Time{}
	ml.handleInbound(mustMarshalRTP(t, 101, dtmfEventPayload(1, true, 480)),
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, &started, &startedAt)
	if digits != 1 {
		t.Fatalf("digits=%d want 1", digits)
	}
	if s := ml.snapshot(); s.PacketsReceived != 0 {
		t.Fatalf("packets_received=%d — a telephone-event packet is not audio and must not "+
			"count toward loss/jitter accounting", s.PacketsReceived)
	}
}

// TestRXReportsADigitWhoseEndPacketsWereAllLost closes the gap between the
// brief's own doc comment ("a new event's marker also closes any previous
// event that never delivered its end packet ... so a lost end cannot swallow
// a digit") and code that would otherwise just overwrite the state and drop
// the orphaned digit silently: only non-end packets arrive for one digit (its
// end packet and all 3 retransmits are lost), then a new digit's first
// (marker) packet arrives. The orphaned digit must still be reported, at the
// last duration seen before the new event began.
func TestRXReportsADigitWhoseEndPacketsWereAllLost(t *testing.T) {
	sink := &digitSink{}
	ml := &mediaLoop{
		emit: sink.emit, dialogID: "d1", callID: "call-abc",
		direction: session.Inbound, recvEventPTs: map[uint8]bool{101: true},
	}
	ml.assemble(nil, nil)
	ml.onDigit = func(digit byte, mode string, durationMs int) {
		ml.emit(session.UAEvent{
			Kind: session.UAEventDTMF, DialogID: ml.dialogID, CallID: ml.callID,
			Digit: string(digit), DTMFMode: mode, DurationMs: durationMs,
		})
	}

	// Digit '7' (code 7): only non-end packets, growing duration; its end
	// packet (and all 3 retransmits) never arrive.
	ml.handleTelephoneEvent(&rtp.Packet{
		Header: rtp.Header{PayloadType: 101, Marker: true}, Payload: dtmfEventPayload(7, false, 160),
	})
	ml.handleTelephoneEvent(&rtp.Packet{
		Header: rtp.Header{PayloadType: 101, Marker: false}, Payload: dtmfEventPayload(7, false, 320),
	})
	ml.handleTelephoneEvent(&rtp.Packet{
		Header: rtp.Header{PayloadType: 101, Marker: false}, Payload: dtmfEventPayload(7, false, 480),
	})

	// Digit '8's first packet: must recover the orphaned '7' before tracking '8'.
	ml.handleTelephoneEvent(&rtp.Packet{
		Header: rtp.Header{PayloadType: 101, Marker: true}, Payload: dtmfEventPayload(8, false, 160),
	})

	if got := sink.digits(); got != "7" {
		t.Fatalf("detected %q want %q (recovered digit whose end packets were all lost)", got, "7")
	}
	for _, e := range sink.seen {
		if e.Kind != session.UAEventDTMF {
			continue
		}
		if e.DurationMs != 60 {
			t.Fatalf("duration_ms=%d want 60 (480 timestamp units / 8, the last duration seen)", e.DurationMs)
		}
	}
}

// TestRXIgnoresTelephoneEventFromARogueSource is Task 18's Correction 5: once
// RX has latched onto a source, a telephone-event packet from any OTHER
// source must be dropped — not reported as a digit — exactly like the audio
// path drops and counts a rogue source. Without this gate a plain-RTP call
// would have an unauthenticated DTMF-injection path into
// wait_dtmf/plan-driven logic.
func TestRXIgnoresTelephoneEventFromARogueSource(t *testing.T) {
	sink := &digitSink{}
	ml := &mediaLoop{
		emit: sink.emit, dialogID: "d1", callID: "call-abc",
		direction: session.Inbound, recvEventPTs: map[uint8]bool{101: true},
	}
	latched := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000} // the signalled address
	ml.assemble(nil, latched)
	ml.onDigit = func(digit byte, mode string, durationMs int) {
		ml.emit(session.UAEvent{
			Kind: session.UAEventDTMF, DialogID: ml.dialogID, CallID: ml.callID,
			Digit: string(digit), DTMFMode: mode, DurationMs: durationMs,
		})
	}

	rogue := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5001}
	started, startedAt := false, time.Time{}

	// First digit, from the source that latches: reported.
	ml.handleInbound(mustMarshalRTP(t, 101, dtmfEventPayload(1, true, 480)), latched, &started, &startedAt)
	if got := sink.digits(); got != "1" {
		t.Fatalf("digits=%q want %q (latched source)", got, "1")
	}

	// Second digit, from a different source after the latch: dropped, not
	// reported, and counted as a rogue source packet.
	ml.handleInbound(mustMarshalRTP(t, 101, dtmfEventPayload(2, true, 480)), rogue, &started, &startedAt)
	if got := sink.digits(); got != "1" {
		t.Fatalf("digits=%q want %q — a rogue source must not report a digit", got, "1")
	}
	if s := ml.snapshot(); s.RogueSourcePackets == 0 {
		t.Fatal("rogue source telephone-event packet not counted")
	}
}

// TestStartMediaLoopInstallsTheNegotiatedTelephoneEventPT is Task 18's
// Correction 4 coverage-gap closer, modeled on Task 17's
// TestStartMediaLoopInstallsDetectorOnlyForInbandMode: it drives the real
// startMediaLoop entry point, so deleting startMediaLoop's `recvEventPTs:` line
// (or its negotiatedEventPT range guard) would leave this test failing where
// TestRXDetectsTelephoneEventOncePerDigit and friends — which all hand-build
// a mediaLoop literal with recvEventPTs set directly — would not notice at all.
func TestStartMediaLoopInstallsTheNegotiatedTelephoneEventPT(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  map[uint8]bool
		want map[uint8]bool
	}{
		{"101 installed", map[uint8]bool{101: true}, map[uint8]bool{101: true}},
		{"two installed", map[uint8]bool{101: true, 96: true}, map[uint8]bool{101: true, 96: true}},
		{"none", map[uint8]bool{}, map[uint8]bool{}},
		{"out of range keys dropped", map[uint8]bool{0: true, 128: true, 255: true, 101: true}, map[uint8]bool{101: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newTestUAWithDaemonCtx(context.Background(), t)
			conn := loopbackUDP(t)
			defer func() { _ = conn.Close() }()

			d := &dialog{
				id: newDialogID(), phase: phaseAnswered,
				mediaConn: conn,
				mediaSession: &media.Session{
					Codec: "PCMU", RemoteAddr: "127.0.0.1:5004", RecvEventPTs: tc.set,
				},
			}
			u.startMediaLoop(d)
			if d.mediaLoop == nil {
				t.Fatal("startMediaLoop did not publish a media loop")
			}
			defer d.mediaLoop.stop()

			if got := d.mediaLoop.recvEventPTs; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("RecvEventPTs=%v => recvEventPTs=%v want %v", tc.set, got, tc.want)
			}
		})
	}
	t.Run("hand-built session falls back to TelephoneEventPT", func(t *testing.T) {
		u := newTestUAWithDaemonCtx(context.Background(), t)
		conn := loopbackUDP(t)
		defer func() { _ = conn.Close() }()
		d := &dialog{id: newDialogID(), phase: phaseAnswered, mediaConn: conn,
			mediaSession: &media.Session{Codec: "PCMU", RemoteAddr: "127.0.0.1:5004", TelephoneEventPT: 264}}
		u.startMediaLoop(d)
		defer d.mediaLoop.stop()
		if len(d.mediaLoop.recvEventPTs) != 0 {
			t.Fatalf("out-of-range TelephoneEventPT installed: %v", d.mediaLoop.recvEventPTs)
		}
	})
}

func mustMarshalRTP(t *testing.T, pt uint8, payload []byte) []byte {
	t.Helper()
	pkt := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: pt}, Payload: payload}
	b, err := pkt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestHandleDigitViaRealOnDigitEmitsUAEventDTMF closes the OTHER half of the
// coverage gap the two tests above still left open: every test in this file
// installs its OWN onDigit closure (matching the brief's original three) or
// never calls onDigit at all, so none of them ever runs UA.handleDigit's
// actual logic — a wrong Kind, a dropped DTMFMode, or swapped
// DialogID/CallID there would ship silently. This test drives startMediaLoop
// for real, then invokes the REAL onDigit closure startMediaLoop's own
// literal installs (`d.mediaLoop.onDigit`, wired to u.handleDigit) — not a
// test substitute — and asserts the UAEventDTMF that reaches a real
// UA.OnEvent handler carries the right dialog/call identity, digit, mode and
// duration. Deleting the `onDigit:` line from startMediaLoop's literal leaves
// every other test in this file green; this one fails immediately (onDigit
// is nil).
func TestHandleDigitViaRealOnDigitEmitsUAEventDTMF(t *testing.T) {
	u := newTestUAWithDaemonCtx(context.Background(), t)
	u.cfg.DTMFMode = "inband"
	conn := loopbackUDP(t)
	defer func() { _ = conn.Close() }()

	var got session.UAEvent
	var gotN int
	u.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) {
		got = ev
		gotN++
	})

	d := &dialog{
		id: newDialogID(), callID: "call-real-ondigit", direction: session.Inbound,
		phase: phaseAnswered, mediaConn: conn,
		mediaSession: &media.Session{Codec: "PCMU", RemoteAddr: "127.0.0.1:5004"},
	}
	u.startMediaLoop(d)
	if d.mediaLoop == nil {
		t.Fatal("startMediaLoop did not publish a media loop")
	}
	defer d.mediaLoop.stop()
	if d.mediaLoop.onDigit == nil {
		t.Fatal("startMediaLoop did not install onDigit")
	}

	// The REAL production closure, not a test-substituted one: this is
	// startMediaLoop's own `onDigit: func(digit byte, mode string, durationMs int) { u.handleDigit(d, digit, mode, durationMs) }`.
	//
	// The mode argument is deliberately "rfc2833" while u.cfg.DTMFMode is
	// "inband": handleDigit must report the mode the DETECTOR observed, not the
	// UA's configured default. Passing "inband" here — as this test originally
	// did — made the two coincide, and hardcoding `DTMFMode: "inband"` in
	// handleDigit's event literal left the whole internal/sipua package green.
	// This is the only test that drives the real onDigit closure and asserts
	// DTMFMode at all; every other mode assertion in this file goes through a
	// test-installed closure that builds the event itself.
	d.mediaLoop.onDigit('5', "rfc2833", 100)

	if gotN != 1 {
		t.Fatalf("emit called %d times, want 1", gotN)
	}
	if got.Kind != session.UAEventDTMF {
		t.Fatalf("Kind=%q want %q", got.Kind, session.UAEventDTMF)
	}
	if got.DialogID != d.id {
		t.Fatalf("DialogID=%q want %q", got.DialogID, d.id)
	}
	if got.CallID != d.callID {
		t.Fatalf("CallID=%q want %q", got.CallID, d.callID)
	}
	if got.Direction != d.direction {
		t.Fatalf("Direction=%v want %v", got.Direction, d.direction)
	}
	if got.Digit != "5" {
		t.Fatalf("Digit=%q want %q", got.Digit, "5")
	}
	if got.DTMFMode != "rfc2833" {
		t.Fatalf("DTMFMode=%q want %q — the DETECTOR's mode, not u.cfg.DTMFMode (%q)",
			got.DTMFMode, "rfc2833", u.cfg.DTMFMode)
	}
	if got.DurationMs != 100 {
		t.Fatalf("DurationMs=%d want 100", got.DurationMs)
	}
}

// rxUnitLoop is a mediaLoop whose digit reports are collected as "<digit>@<ms>".
func rxUnitLoop() (*mediaLoop, *[]string) {
	var got []string
	ml := &mediaLoop{recvEventPTs: map[uint8]bool{101: true}}
	ml.assemble(nil, nil)
	ml.onDigit = func(d byte, _ string, ms int) { got = append(got, fmt.Sprintf("%c@%d", d, ms)) }
	return ml, &got
}

// rxEv feeds one telephone-event packet straight to handleTelephoneEvent.
func rxEv(ml *mediaLoop, code byte, ts uint32, dur uint16, end bool) {
	b := byte(10)
	if end {
		b |= 0x80
	}
	ml.handleTelephoneEvent(&rtp.Packet{Header: rtp.Header{PayloadType: 101, Timestamp: ts},
		Payload: []byte{code, b, byte(dur >> 8), byte(dur)}})
}

func wantReports(t *testing.T, got *[]string, want ...string) {
	t.Helper()
	if len(*got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(*got, append([]string(nil), want...)) {
		t.Fatalf("reports %v, want %v", *got, want)
	}
}

func TestRXIgnoresEndRetransmitsAndLateIntermediates(t *testing.T) {
	ml, got := rxUnitLoop()
	rxEv(ml, 5, 4000, 160, false)
	rxEv(ml, 5, 4000, 480, false)
	for i := 0; i < 3; i++ {
		rxEv(ml, 5, 4000, 480, true)
	}
	rxEv(ml, 5, 4000, 320, false) // late intermediate of the ended event
	wantReports(t, got, "5@60")
}

func TestRXRepeatedDigitWithANewTimestampIsReportedAgain(t *testing.T) {
	ml, got := rxUnitLoop()
	rxEv(ml, 5, 100, 480, true)
	rxEv(ml, 5, 900, 480, true)
	wantReports(t, got, "5@60", "5@60")
}

func TestRXLongEventContinuationRequiresExactTimestamp(t *testing.T) {
	for _, next := range []uint32{1000 + 0xFFFE, 1000 + 0x10000} {
		ml, got := rxUnitLoop()
		rxEv(ml, 8, 1000, 0xFFFF, false)
		rxEv(ml, 8, next, 160, false)
		wantReports(t, got, "8@8191")
	}
}

func TestRXLongEventContinuationAcrossTimestampWrap(t *testing.T) {
	ml, got := rxUnitLoop()
	start := uint32(0xFFFFFFF0)
	rxEv(ml, 6, start, 0xFFFF, false)
	next := start + 0xFFFF // wraps
	rxEv(ml, 6, next, 100, false)
	rxEv(ml, 6, next, 200, true)
	wantReports(t, got, "6@8216")
}

func TestRXLongEventSurvivesALostSegmentEndPacket(t *testing.T) {
	ml, got := rxUnitLoop()
	rxEv(ml, 8, 1000, 160, false)
	rxEv(ml, 8, 1000, 65000, false) // the 0xFFFF packet is lost
	rxEv(ml, 8, 1000+0xFFFF, 160, false)
	for i := 0; i < 3; i++ {
		rxEv(ml, 8, 1000+0xFFFF, 320, true)
	}
	wantReports(t, got, "8@8231")
}

func TestRXLatePacketOfThePreviousSegmentIsIgnored(t *testing.T) {
	ml, got := rxUnitLoop()
	rxEv(ml, 8, 2000, 0xFFFF, false)
	rxEv(ml, 8, 2000+0xFFFF, 160, false)
	rxEv(ml, 8, 2000, 0xFFFF, false) // late packet of the first segment
	for i := 0; i < 3; i++ {
		rxEv(ml, 8, 2000+0xFFFF, 320, true)
	}
	wantReports(t, got, "8@8231")
}

func TestRXLatePacketOfARecoveredEventIsIgnored(t *testing.T) {
	ml, got := rxUnitLoop()
	rxEv(ml, 7, 10, 160, false)
	rxEv(ml, 8, 20, 160, false) // 7 lost every end packet: reported on 8's arrival
	rxEv(ml, 7, 10, 320, false) // late packet of 7
	rxEv(ml, 8, 20, 320, true)
	wantReports(t, got, "7@20", "8@40")
}
