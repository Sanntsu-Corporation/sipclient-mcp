package codec

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// memFile is an in-memory io.WriteCloser + io.WriterAt, the two things
// WAVRecorder needs from the artifact store's *os.File. It lets these tests
// stay pure (no temp files) while exercising the real header-patch path.
type memFile struct {
	buf    []byte
	closed bool
}

func (m *memFile) Write(p []byte) (int, error) {
	m.buf = append(m.buf, p...)
	return len(p), nil
}

func (m *memFile) WriteAt(p []byte, off int64) (int, error) {
	end := int(off) + len(p)
	if end > len(m.buf) {
		m.buf = append(m.buf, make([]byte, end-len(m.buf))...)
	}
	copy(m.buf[off:end], p)
	return len(p), nil
}

func (m *memFile) Close() error { m.closed = true; return nil }

// buildWAV synthesises a canonical 8k/mono/16-bit WAV around the given samples.
func buildWAV(sampleRate uint32, channels uint16, bits uint16, samples []int16) []byte {
	dataLen := len(samples) * 2
	var b bytes.Buffer
	b.WriteString("RIFF")
	_ = binary.Write(&b, binary.LittleEndian, uint32(36+dataLen))
	b.WriteString("WAVE")
	b.WriteString("fmt ")
	_ = binary.Write(&b, binary.LittleEndian, uint32(16))
	_ = binary.Write(&b, binary.LittleEndian, uint16(1)) // PCM
	_ = binary.Write(&b, binary.LittleEndian, channels)
	_ = binary.Write(&b, binary.LittleEndian, sampleRate)
	_ = binary.Write(&b, binary.LittleEndian, sampleRate*uint32(channels)*uint32(bits)/8) // byteRate
	_ = binary.Write(&b, binary.LittleEndian, uint16(channels*bits/8))                    // blockAlign
	_ = binary.Write(&b, binary.LittleEndian, bits)
	b.WriteString("data")
	_ = binary.Write(&b, binary.LittleEndian, uint32(dataLen))
	for _, s := range samples {
		_ = binary.Write(&b, binary.LittleEndian, s)
	}
	return b.Bytes()
}

func TestReadWAVAccepts8kMono16(t *testing.T) {
	want := []int16{0, 1, -1, 32767, -32768, 100}
	got, err := ReadWAV(bytes.NewReader(buildWAV(8000, 1, 16, want)))
	if err != nil {
		t.Fatalf("ReadWAV: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sample %d = %d want %d", i, got[i], want[i])
		}
	}
}

func TestReadWAVRejectsWrongFormat(t *testing.T) {
	cases := []struct {
		name           string
		rate           uint32
		channels, bits uint16
		wantSubstr     string
	}{
		{"stereo", 8000, 2, 16, "channels"},
		{"16k", 16000, 1, 16, "sample rate"},
		{"8bit", 8000, 1, 8, "bits"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ReadWAV(bytes.NewReader(buildWAV(c.rate, c.channels, c.bits, []int16{0})))
			if err == nil {
				t.Fatalf("ReadWAV accepted %s, want error naming %q", c.name, c.wantSubstr)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(c.wantSubstr)) {
				t.Fatalf("error %q does not name %q", err.Error(), c.wantSubstr)
			}
		})
	}
}

func TestReadWAVRejectsTruncated(t *testing.T) {
	if _, err := ReadWAV(bytes.NewReader([]byte("RIF"))); err == nil {
		t.Fatal("ReadWAV accepted a 3-byte input")
	}
}

func TestWAVRecorderRoundTrips(t *testing.T) {
	mf := &memFile{}
	rec, err := NewWAVRecorder(mf)
	if err != nil {
		t.Fatalf("NewWAVRecorder: %v", err)
	}
	// header written eagerly
	if len(mf.buf) != 44 {
		t.Fatalf("placeholder header = %d bytes, want 44", len(mf.buf))
	}
	frame := make([]int16, SamplesPerFrame)
	for i := range frame {
		frame[i] = int16(i)
	}
	if err := rec.Write(frame); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := rec.Write(frame); err != nil {
		t.Fatalf("Write 2: %v", err)
	}
	if rec.Samples() != 2*SamplesPerFrame {
		t.Fatalf("Samples()=%d want %d", rec.Samples(), 2*SamplesPerFrame)
	}
	n, err := rec.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n != 2*SamplesPerFrame {
		t.Fatalf("Close samples=%d want %d", n, 2*SamplesPerFrame)
	}
	if !mf.closed {
		t.Fatal("Close did not close the underlying writer")
	}
	// The finalised bytes must round-trip through ReadWAV to the samples we wrote.
	back, err := ReadWAV(bytes.NewReader(mf.buf))
	if err != nil {
		t.Fatalf("ReadWAV(recorded): %v", err)
	}
	if len(back) != 2*SamplesPerFrame {
		t.Fatalf("recorded sample count=%d want %d", len(back), 2*SamplesPerFrame)
	}
	for i := 0; i < SamplesPerFrame; i++ {
		if back[i] != int16(i) {
			t.Fatalf("recorded sample %d=%d want %d", i, back[i], i)
		}
	}
}

func TestNewWAVRecorderRejectsNonSeekableSink(t *testing.T) {
	// A plain io.WriteCloser with no WriterAt cannot be finalised.
	if _, err := NewWAVRecorder(struct {
		io.Writer
		io.Closer
	}{io.Discard, io.NopCloser(nil)}); err == nil {
		t.Fatal("NewWAVRecorder accepted a sink without WriterAt")
	}
}

// TestWAVRecorderCloseIsIdempotent: a second Close (two racing finalizers —
// mediaLoop.stop's teardown finalize racing an in-flight RecordStop, or two
// concurrent RecordStops) must not re-patch the header or double-close w.
func TestWAVRecorderCloseIsIdempotent(t *testing.T) {
	mf := &memFile{}
	rec, err := NewWAVRecorder(mf)
	if err != nil {
		t.Fatalf("NewWAVRecorder: %v", err)
	}
	_ = rec.Write(make([]int16, SamplesPerFrame))
	n1, err1 := rec.Close()
	n2, err2 := rec.Close()
	if err1 != nil || err2 != nil {
		t.Fatalf("Close errs: %v, %v", err1, err2)
	}
	if n1 != n2 {
		t.Fatalf("Close sample counts differ: %d vs %d", n1, n2)
	}
}

// TestWAVRecorderWriteAfterCloseIsSafeNoOp: runRX may hold a *WAVRecorder it
// Loaded just before a concurrent RecordStop cleared the atomic pointer and
// called Close — that one in-flight Write must not corrupt the finalised file.
func TestWAVRecorderWriteAfterCloseIsSafeNoOp(t *testing.T) {
	mf := &memFile{}
	rec, err := NewWAVRecorder(mf)
	if err != nil {
		t.Fatalf("NewWAVRecorder: %v", err)
	}
	_ = rec.Write(make([]int16, SamplesPerFrame))
	if _, err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	closedLen := len(mf.buf)
	if err := rec.Write(make([]int16, SamplesPerFrame)); err != nil {
		t.Fatalf("Write after Close returned an error, want silent no-op: %v", err)
	}
	if len(mf.buf) != closedLen {
		t.Fatal("Write after Close appended bytes to the finalised file")
	}
}

// TestWAVRecorderConcurrentWriteAndCloseRace exercises the real hazard under
// -race: one goroutine simulating runRX writing frames, another simulating
// RecordStop closing mid-stream. Must be race-free and leave a parseable WAV.
func TestWAVRecorderConcurrentWriteAndCloseRace(t *testing.T) {
	mf := &memFile{}
	rec, err := NewWAVRecorder(mf)
	if err != nil {
		t.Fatalf("NewWAVRecorder: %v", err)
	}
	frame := make([]int16, SamplesPerFrame)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			_ = rec.Write(frame)
		}
	}()
	_, _ = rec.Close()
	<-done
	if _, err := ReadWAV(bytes.NewReader(mf.buf)); err != nil {
		t.Fatalf("ReadWAV(recorded) after concurrent write/close: %v", err)
	}
}
