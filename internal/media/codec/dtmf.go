package codec

import (
	"errors"
	"fmt"
	"math"
)

// DTMFAlphabet is §10.8's digit set. It has exactly TWO jobs: VALIDATING a
// caller's digit string (ValidDTMFDigits) and fixing the EMISSION ORDER of the
// pinned test vectors. internal/session states the same 16 characters
// independently (mediaplan_validate.go) because §14.2's import boundary keeps
// this package below session; dtmf_test.go and mediaplan_validate_test.go each
// pin their own copy, so the two cannot diverge silently.
//
// NEVER INDEX IT BY AN RFC 4733 EVENT CODE. Its order is not the event-code
// order: DTMFAlphabet[10] is 'A', but code 10 is '*'; DTMFAlphabet[11] is 'B',
// but code 11 is '#'; codes 12-15 are 'A'-'D' where the alphabet has 'C', 'D',
// '*', '#'. An index table therefore corrupts all six non-decimal digits and
// only those, so it passes any test that exercises 0-9 alone. The event-code
// mapping lives in dtmfEventCodes and its inverse dtmfCodeToDigit below; use
// DTMFEventCode / DTMFDigitForEventCode and nothing else.
const DTMFAlphabet = "0123456789ABCD*#"

// DTMFPayloadType is the dynamic RTP payload type this UA OFFERS for
// telephone-event (RFC 4733 §2.1 leaves it to negotiation; 101 is the de-facto
// choice every interop target we test against uses). The type actually put on
// the wire is the negotiated RTP payload type for telephone-event, established
// during SDP negotiation, never this constant — this is only what BuildOffer
// proposes.
const DTMFPayloadType uint8 = 101

// F-M4 / D25 (D20, W2): NO PRODUCTION CONSUMER. internal/media duplicates this
// value locally as telephoneEventOfferPT rather than importing it, even though
// the import is legal here (unlike internal/session's dtmfAlphabet, which
// importguard genuinely blocks — see internal/session/mediaplan_validate.go).
// The two are kept in step by a sync-test (internal/media/sdp_offer_test.go),
// which is real protection but weaker than one constant would be.
//
// NOT UNIFIED HERE: pointing internal/media at this constant changes an SDP
// offer's construction, which is behavior W2 has no charter to touch. It is the
// cheapest available follow-up when a wave does own that path.

// dtmfSampleRate is G.711's 8 kHz; this package speaks no other rate. It is
// the single definition used everywhere this file needs the sample rate, so
// it cannot drift from itself.
const dtmfSampleRate = 8000.0

// dtmfFrameMs is this file's one definition of the 20 ms frame duration,
// used both to round a caller's requested duration up to a whole frame count
// (NewDTMFSource) and to convert a frame count back to milliseconds
// (DurationMs), so the two computations cannot drift apart.
const dtmfFrameMs = 20

// dtmfLowFreqs/dtmfHighFreqs are ITU-T Q.23's tone pairs. The keypad is a
// 4x4 grid: rows carry the low tone, columns the high tone.
var dtmfLowFreqs = [4]float64{697, 770, 852, 941}
var dtmfHighFreqs = [4]float64{1209, 1336, 1477, 1633}

// dtmfGrid maps each digit to its (row, col) in the Q.23 keypad.
var dtmfGrid = map[byte][2]int{
	'1': {0, 0}, '2': {0, 1}, '3': {0, 2}, 'A': {0, 3},
	'4': {1, 0}, '5': {1, 1}, '6': {1, 2}, 'B': {1, 3},
	'7': {2, 0}, '8': {2, 1}, '9': {2, 2}, 'C': {2, 3},
	'*': {3, 0}, '0': {3, 1}, '#': {3, 2}, 'D': {3, 3},
}

// dtmfEventCodes is RFC 4733 §3.10's event-code table: 0-9 are 0-9, * is 10,
// # is 11, A-D are 12-15. It is the ONE place this mapping is written down —
// note that it is NOT DTMFAlphabet's index order, which is the whole reason the
// inverse below is derived from this table rather than from the alphabet.
var dtmfEventCodes = map[byte]uint8{
	'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
	'*': 10, '#': 11, 'A': 12, 'B': 13, 'C': 14, 'D': 15,
}

// dtmfCodeToDigit is dtmfEventCodes INVERTED, and it is computed from that table
// rather than transcribed, so the two directions cannot drift apart. Deriving it
// this way is also what keeps DTMFAlphabet out of the decode path entirely: an
// alphabet index silently maps code 10 to 'A' instead of '*'.
var dtmfCodeToDigit = func() map[uint8]byte {
	out := make(map[uint8]byte, len(dtmfEventCodes))
	for digit, code := range dtmfEventCodes {
		out[code] = digit
	}
	return out
}()

// DTMFFreqs returns the Q.23 low/high tone pair for a digit.
func DTMFFreqs(digit byte) (low, high float64, ok bool) {
	rc, ok := dtmfGrid[digit]
	if !ok {
		return 0, 0, false
	}
	return dtmfLowFreqs[rc[0]], dtmfHighFreqs[rc[1]], true
}

// DTMFEventCode returns a digit's RFC 4733 telephone-event code.
func DTMFEventCode(digit byte) (uint8, bool) {
	c, ok := dtmfEventCodes[digit]
	return c, ok
}

// DTMFDigitForEventCode is DTMFEventCode's exact inverse: it turns a received
// RFC 4733 event code back into its digit. ok is false for the non-DTMF events
// RFC 4733 also defines above 15 (flash hook, tones), which are ignored rather
// than clamped into the digit space.
//
// IT IS THE ONLY CORRECT WAY TO DECODE A RECEIVED EVENT CODE. `DTMFAlphabet[code]`
// looks equivalent and is not — see DTMFAlphabet's own comment. The RX demux in
// internal/sipua calls this function; it does not carry its own table.
func DTMFDigitForEventCode(code uint8) (byte, bool) {
	d, ok := dtmfCodeToDigit[code]
	return d, ok
}

// ValidDTMFDigits reports whether every character of s is in DTMFAlphabet. The
// empty string is NOT valid — "send no digits" is a caller error, not a no-op.
func ValidDTMFDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if _, ok := dtmfGrid[s[i]]; !ok {
			return false
		}
	}
	return true
}

// dtmfAmplitude is each tone's peak amplitude. The two summed tones reach
// 2*8000 = 16000, half of int16 full scale, leaving 6 dB of headroom so the
// sum never clips and the pair is at 0 dB twist by construction.
const dtmfAmplitude = 8000.0

// DTMFSource renders a digit string as 20 ms PCM frames: durationMs of dual
// tone followed by gapMs of digital silence, per digit, in order. It is an
// AudioSource, so the TX ticker's `pcm := src.Frame()` call is unchanged.
//
// ITS CONTRACT IS PromptSource's, DELIBERATELY (spec §2.2): it is
// single-consumer-affine to the TX goroutine, which is the only caller of
// Frame(); on exhaustion it fires onExhaust ONCE (the caller releases the media
// slot there) and closes Done(), then serves silence forever. Reusing that
// exact shape is what lets mediaLoop.claimOp treat a play and an inband DTMF
// identically.
type DTMFSource struct {
	frames    [][]int16
	idx       int
	onExhaust func()
	doneCh    chan struct{}
	// toneMs is the PER-DIGIT tone length actually rendered, after rounding the
	// request up to whole 20 ms frames. It is what dtmf_send reports as
	// duration_ms, so the report is a fact about the wire and not an echo of the
	// request (§4).
	toneMs int
}

// NewDTMFSource pre-renders every frame. digits must be non-empty and drawn
// from DTMFAlphabet; durationMs must be > 0 and gapMs >= 0. Both are rounded UP
// to a whole 20 ms frame, so the rendered length is deterministic and
// DurationMs reports exactly what will be sent.
func NewDTMFSource(digits string, durationMs, gapMs int, onExhaust func()) (*DTMFSource, error) {
	if !ValidDTMFDigits(digits) {
		return nil, fmt.Errorf("dtmf: digits %q must be non-empty and drawn from %s", digits, DTMFAlphabet)
	}
	if durationMs <= 0 {
		return nil, errors.New("dtmf: duration_ms must be > 0")
	}
	if gapMs < 0 {
		return nil, errors.New("dtmf: gap_ms must be >= 0")
	}
	toneFrames := (durationMs + dtmfFrameMs - 1) / dtmfFrameMs
	gapFrames := (gapMs + dtmfFrameMs - 1) / dtmfFrameMs

	s := &DTMFSource{
		onExhaust: onExhaust,
		doneCh:    make(chan struct{}),
		toneMs:    toneFrames * dtmfFrameMs,
	}
	for i := 0; i < len(digits); i++ {
		low, high, _ := DTMFFreqs(digits[i])
		// n is the ABSOLUTE sample index within this digit's tone, so phase is
		// continuous across the digit's frames (a phase discontinuity at a frame
		// boundary spreads energy into neighbouring Goertzel bins and would make
		// our own generator fail our own Q.24 acceptance test).
		n := 0
		for f := 0; f < toneFrames; f++ {
			frame := make([]int16, SamplesPerFrame)
			for j := range frame {
				t := float64(n) / dtmfSampleRate
				v := dtmfAmplitude*math.Sin(2*math.Pi*low*t) +
					dtmfAmplitude*math.Sin(2*math.Pi*high*t)
				frame[j] = int16(v)
				n++
			}
			s.frames = append(s.frames, frame)
		}
		// B-M9: no gap after the FINAL digit — there is no successor tone to
		// separate it from, so appending one here only inflates the total
		// hold time on the claimed media slot (and, on the wire, sends extra
		// silence frames) for no signalling purpose.
		if i+1 < len(digits) {
			for f := 0; f < gapFrames; f++ {
				s.frames = append(s.frames, make([]int16, SamplesPerFrame))
			}
		}
	}
	return s, nil
}

// Frame returns the next rendered frame, or silence once exhausted. The first
// call past the end fires onExhaust and closes Done(), so the last real frame
// is guaranteed to have been pulled before any waiter unblocks — the same
// ordering PromptSource guarantees.
func (s *DTMFSource) Frame() []int16 {
	if s.idx >= len(s.frames) {
		s.finish()
		return make([]int16, SamplesPerFrame)
	}
	f := s.frames[s.idx]
	s.idx++
	return f
}

func (s *DTMFSource) finish() {
	select {
	case <-s.doneCh:
		return // already finished
	default:
	}
	// Release-before-close is INTENTIONAL, not something to reverse (B12):
	// releasing the media-loop slot after Close() would let a caller doing
	// two sequential Plays hit a spurious precondition_failed if the second
	// claim raced the first release. The remaining hazard — a stale onExhaust
	// firing a second time and clobbering a NEWER claim — is closed on the
	// internal/sipua side, by scoping the release to the specific source it
	// was claimed for (mediaLoop.releaseOpFor), not by reordering these two
	// calls.
	if s.onExhaust != nil {
		s.onExhaust()
	}
	close(s.doneCh)
}

// Done is closed once every rendered frame has been served.
func (s *DTMFSource) Done() <-chan struct{} { return s.doneCh }

// DurationMs is the deterministic length of the whole digit string: total
// frames x 20 ms, gaps included.
func (s *DTMFSource) DurationMs() int64 { return int64(len(s.frames)) * dtmfFrameMs }

// EmittedDurationMs is the PER-DIGIT tone length this source actually renders,
// which is the request rounded UP to whole 20 ms frames: 50 ms in, 60 ms out.
// dtmf_send reports THIS, never its own input (§4).
func (s *DTMFSource) EmittedDurationMs() int { return s.toneMs }
