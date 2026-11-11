package media

import (
	"errors"
	"fmt"

	"github.com/pion/srtp/v3"
)

// DefaultReplayWindow is the SRTP replay window this design configures (§6.5.1).
// It is at least the jitter buffer's depth in packets across the whole
// 20-200 ms range (1-10 packets) and never smaller.
const DefaultReplayWindow = 64

// SRTPAuthTagLen is the AES_CM_128_HMAC_SHA1_80 RTP auth-tag length. Protect
// grows every frame by exactly this, and the TX buffer is sized for it (§15.1).
const SRTPAuthTagLen = 10

// FrameTransform is O2's frozen seam (§15.1): it sits between RTP packetisation
// and the socket on TX, and between the socket and the jitter buffer on RX. The
// error returns are mandatory — Unprotect fails in normal operation on an
// auth-tag mismatch or a replay-window rejection.
type FrameTransform interface {
	Protect(plaintext []byte) ([]byte, error) // TX: marshalled RTP in, wire bytes out
	Unprotect(wire []byte) ([]byte, error)    // RX: wire bytes in, marshalled RTP out
}

// identityTransform is the plain-RTP seam: it returns its input unchanged. Used
// on every unencrypted call so the TX/RX call sites are identical to the SRTP
// path — the seam is genuinely load-bearing, not conditional plumbing.
type identityTransform struct{}

// NewIdentityTransform builds the plain-RTP (no encryption) FrameTransform.
func NewIdentityTransform() FrameTransform { return identityTransform{} }

func (identityTransform) Protect(plaintext []byte) ([]byte, error) { return plaintext, nil }
func (identityTransform) Unprotect(wire []byte) ([]byte, error)    { return wire, nil }

var errKeyLifetimeExpired = errors.New("srtp: peer key lifetime exhausted")

// srtpTransform holds two independently keyed, single-goroutine-affine
// srtp.Context values: tx is used ONLY by the TX ticker goroutine and rx ONLY by
// the RX read loop, so no lock is required (§15.1). srtp.Context carries no mutex
// and mutates ROC/replay state on every call; the affinity is the
// synchronisation.
type srtpTransform struct {
	tx *srtp.Context
	rx *srtp.Context
	// txScratch is Protect's reusable output buffer (§15.1: "P2 sizes its TX
	// buffers... so P4 introduces no reallocation on the TX hot path"). It is
	// touched ONLY by Protect, which is called ONLY from the TX goroutine
	// (never Unprotect/RX) — single-goroutine-affine like tx/rx, no lock.
	txScratch []byte
	// rxLimit and rxCount enforce the peer key's lifetime (RFC 4568 6.1): rxCount
	// counts authenticated packets, touched only by Unprotect (the RX goroutine).
	rxLimit, rxCount uint64
}

// ReplayWindowFor returns the replay window to configure for a jitter buffer of
// jitterBufferMS: the design's DefaultReplayWindow (64), never below the buffer
// depth in packets.
func ReplayWindowFor(jitterBufferMS int) int {
	w := jitterBufferMS / 20
	if w < DefaultReplayWindow {
		w = DefaultReplayWindow
	}
	return w
}

// AssertReplayWindow is the §6.5.1 construction-time invariant. It reads the
// window ACTUALLY configured (never an assumed default): a window of 0 — what a
// caller who omitted SRTPReplayProtection would pass — fails, as does any window
// below jitterBufferMS/20.
func AssertReplayWindow(replayWindow, jitterBufferMS int) error {
	if replayWindow <= 0 {
		return fmt.Errorf("srtp replay window is %d: SRTPReplayProtection must be set explicitly "+
			"(CreateContext defaults to zero replay protection)", replayWindow)
	}
	if minWindow := jitterBufferMS / 20; replayWindow < minWindow {
		return fmt.Errorf("srtp replay window %d < jitter_buffer_ms/20 = %d", replayWindow, minWindow)
	}
	return nil
}

// NewSRTPTransform builds the TX/RX contexts for one call. localKey encrypts
// what WE send (the peer decrypts it with our key); remoteKey decrypts what the
// PEER sends. The explicit SRTPReplayProtection(replayWindow) is load-bearing:
// omitting it ships silent zero replay protection (§6.5.1). replayWindow <= 0 is
// rejected here so the omission cannot pass.
func NewSRTPTransform(localKey, remoteKey CryptoParams, replayWindow int) (FrameTransform, error) {
	if replayWindow <= 0 {
		return nil, fmt.Errorf("srtp replay window is %d: must be > 0", replayWindow)
	}
	tx, err := srtp.CreateContext(localKey.MasterKey[:], localKey.MasterSalt[:],
		srtp.ProtectionProfileAes128CmHmacSha1_80, srtp.SRTPReplayProtection(uint(replayWindow)))
	if err != nil {
		return nil, fmt.Errorf("srtp tx context: %w", err)
	}
	rx, err := srtp.CreateContext(remoteKey.MasterKey[:], remoteKey.MasterSalt[:],
		srtp.ProtectionProfileAes128CmHmacSha1_80, srtp.SRTPReplayProtection(uint(replayWindow)))
	if err != nil {
		return nil, fmt.Errorf("srtp rx context: %w", err)
	}
	limit := remoteKey.Lifetime
	if limit == 0 {
		limit = maxKeyLifetime
	}
	return &srtpTransform{tx: tx, rx: rx, rxLimit: limit}, nil
}

// Protect encrypts a marshalled RTP packet. Passing a nil header makes pion
// unmarshal the header from the packet itself, which is exactly the socket
// boundary O2 places the seam at.
//
// Writes into t.txScratch (grown once, on the first call whose packet exceeds
// its current capacity, then reused every call after) rather than passing pion
// a nil dst — EncryptRTP allocates its OWN output slice whenever dst is nil,
// which would silently defeat any buffer sizing a caller did, regardless of
// how carefully it pre-sized its OWN slice before calling Protect (that slice
// is only ever read here, as `clear`, never passed to pion as `dst`). Sizing
// happens INSIDE Protect, at the one place that actually owns the buffer
// EncryptRTP writes into.
func (t *srtpTransform) Protect(plaintext []byte) ([]byte, error) {
	if cap(t.txScratch) < len(plaintext)+SRTPAuthTagLen {
		t.txScratch = make([]byte, 0, len(plaintext)+SRTPAuthTagLen)
	}
	wire, err := t.tx.EncryptRTP(t.txScratch[:0], plaintext, nil)
	if err != nil {
		return nil, err
	}
	t.txScratch = wire
	return wire, nil
}

// Unprotect decrypts and authenticates a wire packet. An auth-tag mismatch or a
// replay-window rejection is returned as an error; the RX loop drops the frame
// and counts srtp_auth_failures, never packets_lost.
func (t *srtpTransform) Unprotect(wire []byte) ([]byte, error) {
	// RFC 4568 6.1: the SRTP packets under a key must be fewer than its lifetime;
	// a packet that would reach it is refused like one with a bad auth tag.
	if t.rxCount+1 >= t.rxLimit {
		return nil, errKeyLifetimeExpired
	}
	out, err := t.rx.DecryptRTP(nil, wire, nil)
	if err == nil {
		t.rxCount++ // a forged or replayed packet does not use up the key
	}
	return out, err
}
