package fakes

import (
	"context"
	"io"
	"sync"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

var _ session.Tap = (*Tap)(nil)

// Tap is a hand-written fake of session.Tap — all SEVEN methods (U7's six
// plus U18's Retain), every per-call one keyed by SIP Call-ID. It
// accumulates the records session
// installs into sipua and media, so a session test can assert on the ORDER
// and CONTENT of what was tapped without a renderer.
type Tap struct {
	mu sync.Mutex

	LadderResult session.Ladder
	LadderErr    error
	// ArmErr/DisarmErr default to apierr.NotSupported, matching trace.Sink's
	// P1 behaviour (D9b): PCAP arrives at P2. A test that wants the P2 shape
	// sets them to nil explicitly, so it cannot get P2 semantics by accident.
	ArmErr       error
	DisarmResult session.CaptureResult
	DisarmErr    error

	SIPRecords   []session.SIPRecord
	MediaRecords []session.MediaRecord
	LadderCalls  []LadderCall
	Armed        []ArmCall
	DisarmCalls  []string
	Evicted      []string
	// Retained records every Retain call in order (U18), so a caller's test
	// can assert that the live call's ladder was actually protected rather
	// than left as the LRU's first victim.
	Retained []string
}

// LadderCall is one recorded Ladder call.
type LadderCall struct {
	UAHandle string
	CallID   string
	Format   session.LadderFormat
}

// ArmCall is one recorded ArmCapture call.
type ArmCall struct {
	UAHandle string
	CallID   string
	Config   session.CaptureConfig
}

// NewTap returns a Tap fake whose capture methods default to
// apierr.NotSupported, matching trace.Sink's P1 behaviour (D9b).
func NewTap() *Tap {
	return &Tap{
		ArmErr:    apierr.NotSupported("capture is not supported at P1"),
		DisarmErr: apierr.NotSupported("capture is not supported at P1"),
	}
}

// SIPMessage records a tapped SIP message. D9a: unconditional, no arming.
func (t *Tap) SIPMessage(_ context.Context, rec session.SIPRecord) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.SIPRecords = append(t.SIPRecords, rec)
}

// MediaFrame records a tapped media frame.
func (t *Tap) MediaFrame(_ context.Context, rec session.MediaRecord) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.MediaRecords = append(t.MediaRecords, rec)
}

// Ladder returns the scripted Ladder for (uaHandle, callID) (HIGH-3).
func (t *Tap) Ladder(_ context.Context, uaHandle, callID string, format session.LadderFormat) (session.Ladder, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.LadderCalls = append(t.LadderCalls, LadderCall{UAHandle: uaHandle, CallID: callID, Format: format})
	return t.LadderResult, t.LadderErr
}

// Retain marks a live call's ladder as never-evictable (U18). P1b Task 8
// calls it at dialog establishment, holding no lock. The fake records the
// call so a caller's test can assert the live call's ring was actually
// protected — without Retain the LRU evicts LIVE calls' ladders in
// preference to dead keepalive rings, and call_ladder answers not_found for
// a live, owned handle.
func (t *Tap) Retain(_ context.Context, _ /*uaHandle*/, callID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Retained = append(t.Retained, callID)
}

// Evict drops a call's ladder AND RELEASES THE RETENTION ON IT (U7, U18).
// Task 10's janitor calls it during registry eviction; the fake records the
// call so a retention test can assert the ring was released promptly rather
// than left for the LRU. (Prompt release is what Evict buys for an unretained
// ring; §N3's bound is limits.max_ladders + LRU over the UNRETAINED rings —
// U15 as amended by U18. For a RETAINED ring, Evict is the only release.)
//
// Both Retained and Evicted are APPEND-ONLY CALL LOGS, matching every other
// recorder on this fake: the fake does not model the store, so a caller
// asserts the release as the PAIRING of a Retain and a later Evict on the
// same callID. The store-level property — that Evict really drops the
// retention and the ring rejoins the LRU's candidate set — is asserted
// against the real trace.Sink via DebugRetainedCount in P1c Task 16, which
// is where it belongs and where it can actually fail.
func (t *Tap) Evict(_ context.Context, _ /*uaHandle*/, callID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Evicted = append(t.Evicted, callID)
}

// ArmCapture records the request and defaults to apierr.NotSupported (D9b).
func (t *Tap) ArmCapture(_ context.Context, uaHandle, callID string, _ io.WriteCloser, cfg session.CaptureConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Armed = append(t.Armed, ArmCall{UAHandle: uaHandle, CallID: callID, Config: cfg})
	return t.ArmErr
}

// DisarmCapture records the request and defaults to apierr.NotSupported (D9b).
func (t *Tap) DisarmCapture(_ context.Context, _, callID string) (session.CaptureResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.DisarmCalls = append(t.DisarmCalls, callID)
	return t.DisarmResult, t.DisarmErr
}

// SIPRecordsSnapshot returns a copy of the tapped SIP records, safe to read
// while other goroutines are still tapping.
func (t *Tap) SIPRecordsSnapshot() []session.SIPRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]session.SIPRecord, len(t.SIPRecords))
	copy(out, t.SIPRecords)
	return out
}

// ArmedSnapshot returns a copy of the recorded ArmCapture calls, safe to read
// while another goroutine (e.g. CallDial's dial-time OnDialogBound closure,
// D9b) may still be arming — mirrors SIPRecordsSnapshot above.
func (t *Tap) ArmedSnapshot() []ArmCall {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]ArmCall, len(t.Armed))
	copy(out, t.Armed)
	return out
}
