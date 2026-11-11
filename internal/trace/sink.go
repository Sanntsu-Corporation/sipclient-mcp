// Package trace holds the SIP tap sink, the bounded per-call ladder ring
// buffer, and the three ladder renderers.
//
// THE LADDER IS UNCONDITIONAL (D9a): always on, NO ARMING CHECK ANYWHERE on
// the SIPMessage/Ladder path, because it stores metadata and message text
// into a bounded buffer evicted with the call and costs nothing worth
// optimising.
//
// ArmCapture/DisarmCapture are NOT in conflict with that: they are a
// DIFFERENT SWITCH, governing PCAP, which D9b makes opt-in and which arrives
// at P2. session.Tap declares them at P1 so P2 EXTENDS rather than rewrites
// the interface (§15.1 O1/O2). At P1 both return apierr.NotSupported and
// record nothing — deliberately NOT a silent nil, because a silent no-op is
// indistinguishable from a working capture.
//
// ROADMAP CORRECTION (handoff §6b items 6, 8 and 9): the roadmap annotates
// P1.9 "(D9d canonical form)", its §4 constraint table row 4 forbids claiming
// byte-identical signalling capture, and risk R-1 calls sipgo v1.4.3's
// SIPTracer the only route to it. All three are STALE. Under U1/D9d, UDP is
// BYTE-EXACT and UDP is P1's only transport. §8 D9d, §10.11 and §18.10 of the
// spec are the source of truth; the roadmap is non-normative.
//
// LAYERING (§6.2, contract Part 1.3): trace and sipua are PEERS and never
// call each other, and this package proves it by importing NEITHER sipua NOR
// sipgo. It is a PURE RENDERER over session.SIPRecord — sipua extracts every
// scalar at the socket seam, so nothing here parses SIP. That is what makes
// the three renderers testable against hand-built records.
// internal/importguard asserts both directions.
//
// Rule 16 reuse: NONE FOUND in internal/sipengine. The vendored engine has no
// trace, ladder, ring-buffer or rendering code of any kind — §7.1 enumerates
// four packages (digest, siptest, calltester, config) and none of them
// records or renders a message history.
package trace

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// DefaultLadderSize bounds each ladder's DEPTH.
const DefaultLadderSize = 512

// DefaultMaxLadders bounds the NUMBER OF UNRETAINED LADDERS (U15 as amended
// by U18). It matches policy.Limits.MaxLadders's default, for the same reason.
const DefaultMaxLadders = 512

// There is NO trace.Format and NO trace.Rendered. The format is
// session.LadderFormat and the result is session.Ladder, because session.Tap
// names both and a local duplicate would stop Sink satisfying it (Rule 18).

// tapKey namespaces a ladder ring by its owning UA handle AND its SIP Call-ID
// (HIGH-3). Inbound Call-IDs are peer-chosen verbatim, so a single peer can
// hand two UAs in different sessions the SAME Call-ID; keying on Call-ID alone
// then merges their rings and lets one session read the other's traffic
// through its own legitimately-owned handle. The UA handle is what keeps the
// two rings distinct. A record from a tap with no UA identity carries ua ""
// — which reproduces the pre-existing per-Call-ID keying exactly, so no
// non-UA path changes behaviour.
type tapKey struct {
	ua     string
	callID string
}

type ring struct {
	buf       []session.SIPRecord
	next      int
	filled    bool
	truncated bool
	// lastWrite is the Sink's write counter at this ring's most recent append.
	// It orders the LRU (U15) and is touched ONLY on write, never on render.
	lastWrite uint64
	// retained marks this ring as belonging to a REGISTRY-RESIDENT call (U18,
	// narrowed by U21 — NOT merely a live one: a terminated call keeps its
	// retention until the registry evicts it, so releasing on "no longer live"
	// would evict the ladder early and reintroduce B2). A retained
	// ring is NEVER an eviction candidate and NEVER counts against maxLadders.
	// It lives on the ring rather than in a second map deliberately: deleting
	// the map entry then IS the release, so Evict cannot free the ring and
	// forget the retention (Rule 15 — one place, not two that must agree).
	retained bool
}

func (r *ring) append(rec session.SIPRecord) {
	if len(r.buf) == 0 {
		return
	}
	if r.filled {
		r.truncated = true
	}
	r.buf[r.next] = rec
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.filled = true
	}
}

// ordered returns a COPY of the records, oldest-first. It must copy: the
// caller renders outside the sink's lock while the socket goroutines keep
// appending.
func (r *ring) ordered() []session.SIPRecord {
	if !r.filled && !r.truncated {
		out := make([]session.SIPRecord, r.next)
		copy(out, r.buf[:r.next])
		return out
	}
	out := make([]session.SIPRecord, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	out = append(out, r.buf[:r.next]...)
	return out
}

// Sink holds TWO bounds, and both are required (U15):
//   - size       bounds each ladder's DEPTH   (records per Call-ID)
//   - maxLadders bounds the NUMBER OF UNRETAINED LADDERS (U18 amends U15)
//
// Only the second closes §N3. Tap.Evict reaches only Call-IDs the session
// registry knows about, and ObservingConn taps the SOCKET, not the dialog — so
// REGISTER, OPTIONS keepalives, failed dials and pre-registration inbound
// rejections all create ladders no Evict can ever reach. See the U15 note
// above for why each of those four is guaranteed rather than hypothetical.
//
// THE LRU's CANDIDATE SET IS THE UNRETAINED RINGS ONLY (U18). Without that
// exclusion the ordering is exactly backwards: a live call writes nothing to
// its ladder between the ACK and the BYE, so it is the least-recently-written
// object in the store, while keepalive OPTIONS refreshes its own recency on
// every write — so pure LRW evicts live calls in preference to dead keepalive
// traffic, and call_ladder on a live, owned handle answers not_found. See the
// U18 note above.
//
// THE STORE IS STILL BOUNDED (U21): at most maxLadders unretained rings plus
// one retained ring per REGISTRY-RESIDENT call — live, bounded by
// limits.max_concurrent_calls_total (50), plus terminated-but-still-retained,
// bounded by limits.max_terminated_calls_per_session per session and by
// limits.registry_retention in time. "512 + 50" is withdrawn.
type Sink struct {
	size       int
	maxLadders int
	mu         sync.Mutex
	calls      map[tapKey]*ring
	// seq is a monotonic write counter. Each ring records the seq of its last
	// APPEND, which is what "least recently written" is ordered on. A plain
	// counter rather than a clock: it needs no injected clock.Clock, it cannot
	// go backwards, and ties are impossible under the mutex.
	seq uint64
	// captures holds one *capture per armed call (D9b). Nil until the first
	// ArmCapture. s.mu guards ONLY lookup/insert/delete of the map entry (a
	// pointer copy) — never the capture's own file I/O; see capture.mu below
	// and the doc comment on ArmCapture/DisarmCapture.
	captures map[tapKey]*capture
}

// New returns a Sink holding at most maxLadders UNRETAINED bounded per-call
// rings, plus one retained ring per registry-resident call (live, bounded by
// max_concurrent_calls_total; plus terminated-but-still-retained, bounded by
// max_terminated_calls_per_session and by registry_retention in time — U21).
// size <= 0 uses DefaultLadderSize; maxLadders <= 0 uses DefaultMaxLadders.
// The value comes from policy.Limits.MaxLadders; P1d wires it and P1e's
// harness passes it.
//
// EVICTION IS LEAST-RECENTLY-WRITTEN, ON INSERT, OVER THE UNRETAINED RINGS
// ONLY (U18 amends U15). A RETAINED RING IS NEVER EVICTED BY THE LRU AND
// NEVER COUNTS AGAINST maxLadders. Without that exclusion the policy is
// exactly backwards — see the U18 note above.
func New(size, maxLadders int) *Sink {
	if size <= 0 {
		size = DefaultLadderSize
	}
	if maxLadders <= 0 {
		maxLadders = DefaultMaxLadders
	}
	return &Sink{size: size, maxLadders: maxLadders, calls: map[tapKey]*ring{}}
}

// SIPMessage implements session.Tap. THERE IS NO ARMING CHECK ON THE LADDER
// PATH: D9a makes the ladder unconditional, and adding one here is a defect.
//
// The D9b pcap tee is a DIFFERENT SWITCH, wired below. It runs OUTSIDE s.mu
// (finding NEW-1 / D7): s.mu guards the ladder ring for EVERY call, so a
// slow/blocking pcap Write held under it would stall every other call's
// tapping and ladder rendering (registry.go:57: no lock across an artifact
// write). The armed handle is looked up under s.mu (a pointer copy), the lock
// is released, and only then is the frame written, serialized per-call by the
// capture's own mutex.
func (s *Sink) SIPMessage(_ context.Context, rec session.SIPRecord) {
	if rec.CallID == "" {
		return
	}
	key := tapKey{ua: rec.UAHandle, callID: rec.CallID}
	s.mu.Lock()
	// HIGH-3: key by (UAHandle, CallID), not Call-ID alone. rec.UAHandle is
	// stamped by the per-UA producer (ObservingConn); it is "" on any tap with
	// no UA identity, which reproduces the old per-Call-ID keying exactly.
	r, ok := s.calls[key]
	if !ok {
		// Make room BEFORE inserting, so the map never momentarily exceeds the
		// bound (§N3 is a bound on held memory, not on average held memory).
		s.evictLRWLocked()
		r = &ring{buf: make([]session.SIPRecord, s.size)}
		s.calls[key] = r
	}
	s.seq++
	r.lastWrite = s.seq
	r.append(rec)
	var capt *capture
	if s.captures != nil {
		capt = s.captures[key] // pointer copy under s.mu; may be nil
	}
	s.mu.Unlock()
	// D9b pcap tee — OUTSIDE s.mu. A blocking disk write here stalls only THIS
	// call's capture, never another call's tapping/ladder.
	if capt != nil {
		capt.writeFrame(rec)
	}
}

// evictLRWLocked drops least-recently-WRITTEN UNRETAINED ladders until
// inserting one more fits within maxLadders. Called with s.mu held.
//
// RETAINED RINGS ARE SKIPPED ENTIRELY (U18): they are neither counted against
// maxLadders nor eligible to be dropped. The insert that triggered this can
// never be blocked, because the ring being inserted is itself unretained until
// a Retain arrives — so whenever the unretained count reaches the cap, an
// unretained candidate exists by construction.
//
// WRITTEN, not read. A ladder nobody has RENDERED is not stale — an agent may
// legitimately call call_ladder long after a call ended, and evicting on read
// recency would reclaim exactly the ladders a slow agent is about to ask for.
// A ladder nobody has TAPPED in a while is the best available proxy for a dead
// dialog, which is what we actually want to reclaim.
//
// The linear scan is deliberate at this size: maxLadders defaults to 512 and
// the scan runs only on the insert of a genuinely new Call-ID, so a heap or an
// intrusive list would be a data structure carried for no measured benefit
// (Rule 15). If P2's media frames make inserts hot, revisit it then. Contract
// §2.7 no longer claims this path is O(1) (U18): what is normative is WHICH
// ring is chosen, not the structure that finds it. Counting the unretained
// rings in the same pass is why no separate counter is carried.
func (s *Sink) evictLRWLocked() {
	for {
		var oldestKey tapKey
		var oldestSeq uint64
		unretained := 0
		found := false
		for k, r := range s.calls {
			if r.retained {
				continue
			}
			unretained++
			if !found || r.lastWrite < oldestSeq {
				oldestKey, oldestSeq, found = k, r.lastWrite, true
			}
		}
		if unretained < s.maxLadders {
			return
		}
		// unretained >= maxLadders >= 1, so found is true here.
		delete(s.calls, oldestKey)
	}
}

// DebugLadderCount reports how many ladders the Sink currently holds, retained
// and unretained together. DEBUG-ONLY: the LRU bound is otherwise unobservable,
// and a bound nothing can observe is a bound nothing can test.
func (s *Sink) DebugLadderCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// Retain marks callID's ring as belonging to a LIVE CALL (U18): it is excluded
// from the LRU's candidate set and from the maxLadders count until Evict
// releases it. If no ring exists yet an EMPTY RETAINED ONE IS CREATED —
// session retains on the DialResult's Call-ID with no ordering guarantee
// against the tap's first write, so a no-op here would leave the live call's
// opening messages evictable for exactly the window the retention exists to
// cover.
//
// NO evictLRWLocked CALL: the ring created here is retained, so it does not
// count against maxLadders and makes no room necessary.
//
// session.Manager calls this holding NO LOCK, immediately after the
// unexported Call-ID setter returns (contract §2.5.3, §6.0b INV-2) — so it
// adds no edge to §6.3's hierarchy. That call site is P1b Task 8's, not this
// task's.
func (s *Sink) Retain(_ context.Context, uaHandle, callID string) {
	if callID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tapKey{ua: uaHandle, callID: callID}
	r, ok := s.calls[key]
	if !ok {
		r = &ring{buf: make([]session.SIPRecord, s.size)}
		s.calls[key] = r
	}
	r.retained = true
}

// DebugRetainedCount reports how many rings are currently retained. DEBUG-ONLY,
// for the same reason DebugLadderCount is: U18's bound must be asserted rather
// than assumed, and U15 shipped an inverted policy precisely because its
// acceptance could not observe this.
func (s *Sink) DebugRetainedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.calls {
		if r.retained {
			n++
		}
	}
	return n
}

// MediaFrame is a no-op at P1: no media flows (§15's R14 split). It is
// declared because session.Tap requires it and P2 must EXTEND rather than
// rewrite the interface. [P2]
func (s *Sink) MediaFrame(_ context.Context, _ session.MediaRecord) {}

// Evict drops a call's ladder promptly, ahead of the LRU's pressure, when the
// janitor evicts the owning session.Call (U7).
//
// IT IS AN OPTIMISATION FOR UNRETAINED RINGS AND THE ONLY RELEASE FOR RETAINED
// ONES (U15 as amended by U18). For an unretained ring it reaches only Call-IDs
// the session registry knows about, and ObservingConn taps the socket rather
// than the dialog — so REGISTER, OPTIONS keepalives, failed dials and inbound
// INVITEs rejected before a Call record exists all create ladders no Evict can
// ever name; evictLRWLocked is what bounds those. For a RETAINED ring this is
// the ONLY thing that ever frees it, because the LRU will not consider it.
// RecordTermination MUST NOT call Evict (U21): the release stays at
// evictCallLocked, at REGISTRY EVICTION, which every terminated call reaches
// — by limits.registry_retention if not sooner by the per-session terminated
// cap — so contract §6.0b INV-1's unconditional bookkeeping still closes the
// loop, one lifecycle stage later, on every path including error and
// cancellation paths (P1b Task 10).
//
// THE RELEASE NEEDS NO EXTRA STATEMENT: `retained` lives on the ring, so
// deleting the map entry frees the ring AND the retention together. That is
// the whole reason the flag is not a second map (Rule 15) — there is no way to
// free one and forget the other. TestEvictReleasesTheRetention asserts it.
//
// The ladder RENDER is written as an artifact at call close in P2; P1 does
// not, because P1 has no artifact store.
func (s *Sink) Evict(_ context.Context, uaHandle, callID string) {
	key := tapKey{ua: uaHandle, callID: callID}
	s.mu.Lock()
	capt := s.captures[key]
	delete(s.captures, key)
	delete(s.calls, key)
	s.mu.Unlock()
	if capt != nil {
		_ = capt.close() // idempotent; OUTSIDE s.mu (D7)
	}
}

// Ladder renders callID's tapped messages in format f ("" defaults to
// session.LadderText). It returns apierr.NotFound if callID has no ring.
func (s *Sink) Ladder(_ context.Context, uaHandle, callID string, f session.LadderFormat) (session.Ladder, error) {
	s.mu.Lock()
	r, ok := s.calls[tapKey{ua: uaHandle, callID: callID}]
	if !ok {
		s.mu.Unlock()
		return session.Ladder{}, apierr.NotFound(
			fmt.Sprintf("no ladder for call-id %s", callID))
	}
	recs := r.ordered()
	truncated := r.truncated
	s.mu.Unlock()

	body, err := render(recs, f)
	if err != nil {
		return session.Ladder{}, err
	}
	if f == "" {
		f = session.LadderText
	}
	return session.Ladder{Format: f, Rendered: body, Messages: len(recs), Truncated: truncated}, nil
}

// capture is one armed call's streaming pcap (D9b). c.mu — NOT the Sink's
// daemon-wide s.mu — serializes this call's frame writes and its close, so a
// slow/blocking pcap disk write stalls only THIS capture, never other calls'
// SIPMessage/ladder (registry.go:57: no lock across an artifact write).
type capture struct {
	mu        sync.Mutex
	w         io.WriteCloser
	maxBytes  int64
	written   int64
	packets   int64
	started   bool // pcap global header written (lazy, first frame)
	truncated bool
	closed    bool                  // fd closed; writeFrame is a no-op afterwards
	result    session.CaptureResult // cached at first close, returned idempotently
	// enc is the stateful pcap framer (Rule 6a D1), one per armed capture, so
	// a tcp/tls call's synthesised seq/ack stays consistent across the whole
	// stream — the same encoder TYPE Pcap (batch) constructs per call,
	// keeping batch and stream on one framing path (Rule 18).
	enc *streamSeqEncoder
	// transports records which transport label(s) this capture actually
	// framed a record for, so close() can report the OBSERVED transport(s) in
	// CaptureResult.CaptureFidelity (D2) instead of a hardcoded "udp".
	transports map[string]bool
}

// writeFrame renders and appends rec under c.mu (NEVER s.mu). It writes the
// pcap global header lazily on the first frame, enforces MaxBytes->truncated,
// and no-ops once closed — which closes the "SIPMessage grabbed the handle,
// then DisarmCapture closed it" race, since both take c.mu.
func (c *capture) writeFrame(rec session.SIPRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.truncated {
		return
	}
	frame, err := c.enc.frame(rec)
	if err != nil {
		return // a record whose 5-tuple will not synthesise is dropped, not fatal
	}
	if c.transports == nil {
		c.transports = map[string]bool{}
	}
	c.transports[pcapFidelityTransport(rec)] = true
	if !c.started {
		header := PcapFileHeader() // len 24 <= maxBytes by the arm-time floor, so it fits
		if _, err := c.w.Write(header); err != nil {
			c.truncated = true
			return
		}
		c.written = int64(len(header))
		c.started = true
	}
	if c.maxBytes > 0 && c.written+int64(len(frame)) > c.maxBytes {
		c.truncated = true // §12.3 byte cap reached; stop appending
		return
	}
	if _, err := c.w.Write(frame); err != nil {
		c.truncated = true
		return
	}
	c.written += int64(len(frame))
	c.packets++
}

// close finalizes under c.mu (NEVER s.mu): writes the header if no frame ever
// arrived (a valid empty pcap), closes the fd, caches the result. Idempotent
// and double-close safe — a later close (the other of {terminal,
// capture_stop, Evict}) returns the cached result.
func (c *capture) close() session.CaptureResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.result
	}
	if !c.started {
		if _, err := c.w.Write(PcapFileHeader()); err == nil {
			c.written = int64(len(PcapFileHeader()))
		}
		c.started = true
	}
	_ = c.w.Close()
	c.closed = true
	fidelity := make(map[string]string, len(c.transports))
	for t := range c.transports {
		fidelity[t] = "byte_exact" // every transport this wave frames is byte-exact (D2)
	}
	c.result = session.CaptureResult{
		Name:                "capture.pcap",
		Bytes:               c.written,
		Packets:             c.packets,
		Truncated:           c.truncated,
		SignalingCiphertext: "not_requested", // plaintext-only this wave (design §7)
		CaptureFidelity:     fidelity,        // the ACTUAL transport(s) observed (D2), not hardcoded
	}
	return c.result
}

// pcapFidelityTransport labels rec for CaptureResult.CaptureFidelity (D2):
// tcp/tls get their own label, everything else (including the zero-value ""
// that predates per-record transport stamping) reports "udp" — matching the
// UDP framing streamSeqEncoder actually applies to those records.
func pcapFidelityTransport(rec session.SIPRecord) string {
	switch rec.Transport {
	case session.TransportTCP:
		return "tcp"
	case session.TransportTLS:
		return "tls"
	default:
		return "udp"
	}
}

// ArmCapture and DisarmCapture govern PCAP (D9b, W2): opt-in per-call
// streaming capture, keyed by (uaHandle, callID) like the five other per-call
// Tap methods (HIGH-3). scope is signaling-only and payload_mode is
// plaintext-only this wave — media capture and ciphertext both report
// apierr.NotSupported, DELIBERATELY NOT A SILENT NIL: a silent no-op is
// indistinguishable from a working capture, and not_supported is §11.2's
// exact code for "capability unavailable in this build".
//
// LOCK DISCIPLINE (D7 / finding NEW-1): ArmCapture does NO file I/O — the
// pcap header is written lazily on the first frame — so registering the
// handle under s.mu is a pure map operation with no I/O in the critical
// section.
//
// Their existence does NOT weaken D9a: the ladder path above has no arming
// check of any kind, and these two touch nothing it reads.
func (s *Sink) ArmCapture(_ context.Context, uaHandle, callID string, w io.WriteCloser, cfg session.CaptureConfig) error {
	if cfg.Scope != "" && cfg.Scope != "signaling" {
		return apierr.NotSupported("pcap scope " + cfg.Scope + " arrives with the RTP path in W4; W2 captures signaling only")
	}
	if cfg.PayloadMode == "ciphertext" {
		return apierr.NotSupported("ciphertext capture is P4; W2 captures plaintext only")
	}
	if callID == "" {
		return apierr.InvalidArgument("capture requires a call-id")
	}
	if cfg.MaxBytes > 0 && cfg.MaxBytes < int64(len(PcapFileHeader())) {
		return apierr.InvalidArgument("capture max_bytes must be at least the pcap header size (24 bytes)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.captures == nil {
		s.captures = map[tapKey]*capture{}
	}
	key := tapKey{ua: uaHandle, callID: callID}
	if _, dup := s.captures[key]; dup {
		return apierr.PreconditionFailed("a capture is already armed for this call")
	}
	s.captures[key] = &capture{w: w, maxBytes: cfg.MaxBytes, enc: newStreamSeqEncoder()} // NO I/O here — header is lazy
	return nil
}

// DisarmCapture is ArmCapture's companion; see its doc comment above. The
// entry is NOT deleted here (finding 1b): it lingers (closed) until Evict, so
// a capture_stop after the call terminated still returns the cached
// counters. The close runs under cap.mu, OUTSIDE s.mu (D7).
func (s *Sink) DisarmCapture(_ context.Context, uaHandle, callID string) (session.CaptureResult, error) {
	s.mu.Lock()
	capt := s.captures[tapKey{ua: uaHandle, callID: callID}]
	s.mu.Unlock()
	if capt == nil {
		return session.CaptureResult{}, apierr.NotFound("no armed capture for this call")
	}
	return capt.close(), nil // close + result-cache under cap.mu, OUTSIDE s.mu; idempotent
}
