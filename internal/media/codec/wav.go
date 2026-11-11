package codec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Canonical WAV parameters for this harness (§10.9): 8000 Hz, mono, 16-bit PCM.
// Prompts must already be this; recordings are always produced as this.
const (
	wavSampleRate = 8000
	wavChannels   = 1
	wavBits       = 16
)

// ReadWAV parses a canonical PCM WAV and returns its mono 16-bit samples. It is
// deliberately strict: a prompt that is not 8000 Hz / mono / 16-bit is rejected
// here (§10.9 "reject anything else at load time, not silently resample"),
// naming the offending field so an operator can fix the file.
func ReadWAV(r io.Reader) ([]int16, error) {
	all, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("wav: read: %w", err)
	}
	if len(all) < 44 {
		return nil, errors.New("wav: too short to contain a header")
	}
	if string(all[0:4]) != "RIFF" || string(all[8:12]) != "WAVE" {
		return nil, errors.New("wav: not a RIFF/WAVE file")
	}
	// Walk chunks after the 12-byte RIFF header to find fmt and data.
	var (
		haveFmt, haveData bool
		channels, bits    uint16
		sampleRate        uint32
		data              []byte
	)
	off := 12
	for off+8 <= len(all) {
		id := string(all[off : off+4])
		size := int(binary.LittleEndian.Uint32(all[off+4 : off+8]))
		body := off + 8
		if body+size > len(all) {
			size = len(all) - body // tolerate a data size that overruns EOF
		}
		switch id {
		case "fmt ":
			if size < 16 {
				return nil, errors.New("wav: fmt chunk too small")
			}
			format := binary.LittleEndian.Uint16(all[body : body+2])
			if format != 1 {
				return nil, fmt.Errorf("wav: not PCM (format tag %d)", format)
			}
			channels = binary.LittleEndian.Uint16(all[body+2 : body+4])
			sampleRate = binary.LittleEndian.Uint32(all[body+4 : body+8])
			bits = binary.LittleEndian.Uint16(all[body+14 : body+16])
			haveFmt = true
		case "data":
			data = all[body : body+size]
			haveData = true
		}
		off = body + size
		if size%2 == 1 {
			off++ // chunks are word-aligned
		}
	}
	if !haveFmt {
		return nil, errors.New("wav: no fmt chunk")
	}
	if !haveData {
		return nil, errors.New("wav: no data chunk")
	}
	if sampleRate != wavSampleRate {
		return nil, fmt.Errorf("wav: sample rate %d Hz, only %d Hz is accepted", sampleRate, wavSampleRate)
	}
	if channels != wavChannels {
		return nil, fmt.Errorf("wav: %d channels, only mono (%d) is accepted", channels, wavChannels)
	}
	if bits != wavBits {
		return nil, fmt.Errorf("wav: %d bits per sample, only %d-bit is accepted", bits, wavBits)
	}
	out := make([]int16, len(data)/2)
	for i := range out {
		out[i] = int16(binary.LittleEndian.Uint16(data[i*2 : i*2+2]))
	}
	return out, nil
}

// WAVRecorder is a streaming canonical-WAV writer over the io.WriteCloser the
// artifact store hands back. It writes a placeholder 44-byte header up front and
// patches the two size fields on Close — the same size-unknown-up-front shape
// internal/trace's pcap writer uses.
//
// IT IS SAFE FOR ONE CONCURRENT Write CALLER RACING ONE Close CALLER, AND THAT
// IS NOT INCIDENTAL. The RX goroutine (runRX) calls Write on every decoded
// frame for as long as mediaLoop.rec is installed; RecordStop/mediaLoop.stop
// call Close from a DIFFERENT goroutine, and atomic.Pointer's Store/Swap only
// stops FUTURE Load calls from observing this recorder — a frame that already
// Loaded it before the clear is still in flight. Without internal locking, that
// frame's Write() (append + rec.samples++) can interleave with Close()'s
// WriteAt(header, 0) + rec.w.Close(), corrupting the header or double-closing
// the fd. mu serializes every Write/Close against every other; closed makes
// Write a safe no-op once Close has started, and Close itself is idempotent
// (a second Close, from two racing stop paths, returns the same result rather
// than double-patching or double-closing).
type WAVRecorder struct {
	mu      sync.Mutex
	w       io.WriteCloser
	at      io.WriterAt
	samples int
	closed  bool
}

// NewWAVRecorder writes the placeholder header immediately. w must also satisfy
// io.WriterAt (the artifact store opens files O_RDWR, so its *os.File does); a
// sink that cannot be patched is rejected rather than producing a WAV with a
// zero data size.
func NewWAVRecorder(w io.WriteCloser) (*WAVRecorder, error) {
	at, ok := w.(io.WriterAt)
	if !ok {
		return nil, errors.New("wav: recorder sink does not support WriterAt (cannot finalise header)")
	}
	rec := &WAVRecorder{w: w, at: at}
	if _, err := w.Write(wavHeader(0)); err != nil {
		return nil, fmt.Errorf("wav: write header: %w", err)
	}
	return rec, nil
}

// Write appends samples as little-endian 16-bit PCM. A no-op once Close has
// been called (the recorder may still be reachable for one in-flight frame
// after a concurrent RecordStop/mediaLoop.stop clears the atomic pointer).
func (rec *WAVRecorder) Write(pcm []int16) error {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.closed {
		return nil
	}
	buf := make([]byte, len(pcm)*2)
	for i, s := range pcm {
		binary.LittleEndian.PutUint16(buf[i*2:i*2+2], uint16(s))
	}
	if _, err := rec.w.Write(buf); err != nil {
		return err
	}
	rec.samples += len(pcm)
	return nil
}

// Samples reports how many samples have been written so far.
func (rec *WAVRecorder) Samples() int {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return rec.samples
}

// Close patches the RIFF and data sizes at offset 0 and closes the sink.
// Idempotent: a second call (two racing finalizers) returns the same sample
// count and nil, doing no further I/O.
func (rec *WAVRecorder) Close() (int, error) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.closed {
		return rec.samples, nil
	}
	rec.closed = true
	if _, err := rec.at.WriteAt(wavHeader(rec.samples*2), 0); err != nil {
		_ = rec.w.Close()
		return rec.samples, fmt.Errorf("wav: patch header: %w", err)
	}
	if err := rec.w.Close(); err != nil {
		return rec.samples, err
	}
	return rec.samples, nil
}

// wavHeader builds the 44-byte canonical header for a data section of dataLen
// bytes (dataLen 0 for the placeholder).
func wavHeader(dataLen int) []byte {
	h := make([]byte, 44)
	copy(h[0:4], "RIFF")
	binary.LittleEndian.PutUint32(h[4:8], uint32(36+dataLen))
	copy(h[8:12], "WAVE")
	copy(h[12:16], "fmt ")
	binary.LittleEndian.PutUint32(h[16:20], 16)
	binary.LittleEndian.PutUint16(h[20:22], 1) // PCM
	binary.LittleEndian.PutUint16(h[22:24], wavChannels)
	binary.LittleEndian.PutUint32(h[24:28], wavSampleRate)
	binary.LittleEndian.PutUint32(h[28:32], wavSampleRate*wavChannels*wavBits/8) // byteRate
	binary.LittleEndian.PutUint16(h[32:34], wavChannels*wavBits/8)               // blockAlign
	binary.LittleEndian.PutUint16(h[34:36], wavBits)
	copy(h[36:40], "data")
	binary.LittleEndian.PutUint32(h[40:44], uint32(dataLen))
	return h
}
