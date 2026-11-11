// Package codec implements the two G.711 codecs this harness speaks (PCMU and
// PCMA) plus internal-only PCM audio sources for the TX path. It is PURE: no
// sockets, no goroutines, no clock — internal/sipua's goroutines call into it.
//
// The µ-law encode/decode is ported (Rule 16 reuse) from the vendored engine's
// internal/sipengine/calltester/audio.go bit-exact tables; A-law is the
// standard ITU-T G.711 algorithm added alongside it.
package codec

// SamplesPerFrame is the 20 ms G.711 frame at 8 kHz (§6.5.2).
const SamplesPerFrame = 160

// ---- µ-law (PCMU, payload type 0) ------------------------------------------

// linearToUlaw ports the vendored engine's algorithm (Rule 16 reuse), with one
// deliberate deviation: sample is promoted to int BEFORE negation, matching
// linearToAlaw's own pattern below. The vendored source negates while still
// int16 (internal/sipengine/calltester/audio.go:45), which overflows for the
// single value -32768 (int16's most-negative value has no positive
// counterpart in two's complement, so -(-32768) wraps back to -32768 instead
// of 32768) — silently producing the wrong codeword for exactly that one
// sample rather than the correct max-negative codeword. This never surfaces
// via that file's own callers today (no caller feeds it exactly -32768), but
// this is new code, not a modification of that file, and R7's acceptance
// criterion is bit-exact correctness against the ITU reference, not
// reproducing an incidental legacy quirk.
func linearToUlaw(sample int16) byte {
	const bias = 0x84
	const clip = 32635
	s := int(sample)
	sign := 0
	if s < 0 {
		sign = 0x80
		s = -s
	}
	if s > clip {
		s = clip
	}
	s += bias
	exponent := 7
	for mask := 0x4000; (s&mask) == 0 && exponent > 0; mask >>= 1 {
		exponent--
	}
	mantissa := (s >> (exponent + 3)) & 0x0F
	return ^byte(sign | (exponent << 4) | mantissa)
}

func ulawToLinear(value byte) int16 {
	u := ^value
	sign := u & 0x80
	exponent := (u >> 4) & 0x07
	mantissa := u & 0x0F
	sample := ((int(mantissa) << 3) + 0x84) << exponent
	sample -= 0x84
	if sign != 0 {
		sample = -sample
	}
	return int16(sample)
}

// ---- A-law (PCMA, payload type 8) — standard ITU-T G.711 -------------------

func linearToAlaw(sample int16) byte {
	const clip = 32635
	sign := byte(0x55) // A-law inverts even bits; start from the toggle mask
	s := int(sample)
	compressed := byte(0)
	if s >= 0 {
		sign = 0xD5
	} else {
		s = -s - 1
		if s < 0 {
			s = 0
		}
	}
	if s > clip {
		s = clip
	}
	if s < 256 {
		compressed = byte(s >> 4)
	} else {
		exponent := 7
		for mask := 0x4000; (s&mask) == 0 && exponent > 1; mask >>= 1 {
			exponent--
		}
		mantissa := (s >> (exponent + 3)) & 0x0F
		compressed = byte((exponent << 4) | mantissa)
	}
	return compressed ^ sign
}

func alawToLinear(value byte) int16 {
	v := value ^ 0x55
	sign := v & 0x80
	exponent := (v >> 4) & 0x07
	mantissa := v & 0x0F
	sample := (int(mantissa) << 4) + 0x08
	if exponent > 0 {
		sample += 0x100
		sample <<= (exponent - 1)
	}
	if sign == 0 {
		sample = -sample
	}
	return int16(sample)
}

// ---- vectorised wrappers ---------------------------------------------------

// EncodePCMU encodes linear PCM samples to G.711 μ-law.
func EncodePCMU(pcm []int16) []byte {
	out := make([]byte, len(pcm))
	for i, s := range pcm {
		out[i] = linearToUlaw(s)
	}
	return out
}

// DecodePCMU decodes G.711 μ-law to linear PCM samples.
func DecodePCMU(payload []byte) []int16 {
	out := make([]int16, len(payload))
	for i, b := range payload {
		out[i] = ulawToLinear(b)
	}
	return out
}

// EncodePCMA encodes linear PCM samples to G.711 A-law.
func EncodePCMA(pcm []int16) []byte {
	out := make([]byte, len(pcm))
	for i, s := range pcm {
		out[i] = linearToAlaw(s)
	}
	return out
}

// DecodePCMA decodes G.711 A-law to linear PCM samples.
func DecodePCMA(payload []byte) []int16 {
	out := make([]int16, len(payload))
	for i, b := range payload {
		out[i] = alawToLinear(b)
	}
	return out
}

var codecPT = map[string]uint8{"PCMU": 0, "PCMA": 8}

// PayloadType maps a negotiated codec name to its static RTP payload type.
func PayloadType(codecName string) (uint8, bool) { pt, ok := codecPT[codecName]; return pt, ok }

// Encode dispatches on the negotiated codec name (media.Session.Codec).
func Encode(codecName string, pcm []int16) ([]byte, error) {
	switch codecName {
	case "PCMU":
		return EncodePCMU(pcm), nil
	case "PCMA":
		return EncodePCMA(pcm), nil
	default:
		return nil, &unsupportedCodecError{codecName}
	}
}

// Decode dispatches on the negotiated codec name.
func Decode(codecName string, payload []byte) ([]int16, error) {
	switch codecName {
	case "PCMU":
		return DecodePCMU(payload), nil
	case "PCMA":
		return DecodePCMA(payload), nil
	default:
		return nil, &unsupportedCodecError{codecName}
	}
}

type unsupportedCodecError struct{ name string }

func (e *unsupportedCodecError) Error() string { return "codec: unsupported codec " + e.name }
