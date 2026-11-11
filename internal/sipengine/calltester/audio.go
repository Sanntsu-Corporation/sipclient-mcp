package calltester

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
)

type AudioReader interface {
	ReadChunk(size int) []byte
}

type dummyReader struct{}

func (d *dummyReader) ReadChunk(size int) []byte {
	return make([]byte, size)
}

type memoryBufferReader struct {
	buffer []byte
	pos    int
	mu     sync.Mutex
}

func (m *memoryBufferReader) ReadChunk(size int) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	chunk := make([]byte, size)
	for i := 0; i < size; i++ {
		chunk[i] = m.buffer[m.pos]
		m.pos = (m.pos + 1) % len(m.buffer)
	}
	return chunk
}

// linearToUlaw converts a 16-bit linear PCM sample to 8-bit PCMU (G.711 mu-law)
func linearToUlaw(sample int16) byte {
	const BIAS = 0x84
	const CLIP = 32635
	sign := (sample >> 8) & 0x80
	if sign != 0 {
		sample = -sample
	}
	if sample > CLIP {
		sample = CLIP
	}
	sample += BIAS
	exponent := 7
	for mask := int16(0x4000); (sample & mask) == 0; mask >>= 1 {
		exponent--
	}
	mantissa := (sample >> (exponent + 3)) & 0x0F
	ulaw := byte(sign | (int16(exponent) << 4) | mantissa)
	return ^ulaw
}

func ulawToLinear(value byte) int16 {
	ulaw := ^value
	sign := ulaw & 0x80
	exponent := (ulaw >> 4) & 0x07
	mantissa := ulaw & 0x0F

	sample := ((int(mantissa) << 3) + 0x84) << exponent
	sample -= 0x84
	if sign != 0 {
		sample = -sample
	}
	return int16(sample)
}

func decodePCMUToPCM16(buffer []byte) []int16 {
	samples := make([]int16, len(buffer))
	for i, value := range buffer {
		samples[i] = ulawToLinear(value)
	}
	return samples
}

// generateSinePCMU generates 1 second of PCMU audio for a given frequency
func generateSinePCMU(freqHz float64) []byte {
	const sampleRate = 8000
	buffer := make([]byte, sampleRate)
	for i := 0; i < sampleRate; i++ {
		t := float64(i) / float64(sampleRate)
		sample := math.Sin(2.0*math.Pi*freqHz*t) * 32767.0
		buffer[i] = linearToUlaw(int16(sample))
	}
	return buffer
}

// NewAudioReader creates an AudioReader based on the source specification.
// Format:
//   - "sine:1000" -> produces a 1000Hz sine wave tone
//   - "file:/path/to/file.raw" -> loops a raw PCMU file
//   - "" -> produces silence (dummy payload)
func NewAudioReader(source string) (AudioReader, error) {
	if source == "" {
		return &dummyReader{}, nil
	}

	if strings.HasPrefix(source, "sine:") {
		freqStr := strings.TrimPrefix(source, "sine:")
		freq, err := strconv.ParseFloat(freqStr, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid sine frequency %q: %w", freqStr, err)
		}
		buf := generateSinePCMU(freq)
		return &memoryBufferReader{buffer: buf}, nil
	}

	if strings.HasPrefix(source, "file:") {
		path := strings.TrimPrefix(source, "file:")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read audio file %q: %w", path, err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("audio file is empty")
		}
		return &memoryBufferReader{buffer: data}, nil
	}

	return nil, fmt.Errorf("unsupported audio source format: %s", source)
}
