package trace_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/trace"
)

// writeCloserBuf is a bytes.Buffer with a no-op Close, satisfying
// io.WriteCloser for capture tests that want to inspect the written bytes.
type writeCloserBuf struct {
	bytes.Buffer
}

func (writeCloserBuf) Close() error { return nil }

// blockingWriteCloser blocks inside Write until unblock is closed, so
// TestBlockingCaptureDoesNotStallOtherCalls can hold cap.mu without ever
// touching s.mu.
type blockingWriteCloser struct {
	unblock <-chan struct{}
}

func (b blockingWriteCloser) Write(p []byte) (int, error) {
	<-b.unblock
	return len(p), nil
}

func (blockingWriteCloser) Close() error { return nil }

// NOTE THE ABSENCE OF sipgo. internal/trace is a pure renderer over
// session.SIPRecord, so its tests build records BY HAND — scalars in, rendered
// text out — instead of parsing fixtures. That is the whole payoff of moving
// ObservingConn to internal/sipua (contract Part 1.3): the renderer is now
// testable without a socket, a parser or a live UA.
//
// inviteRaw is retained as the SERIALIZED field's value, because the ladder's
// job is to reproduce the observed octets verbatim.

// rec builds a request record with the scalars a renderer reads.
func rec(at time.Time, dir session.Direction, callID, method, raw string) session.SIPRecord {
	return session.SIPRecord{
		At: at, Direction: dir, Transport: session.TransportUDP,
		LocalAddr: "127.0.0.1:5066", RemoteAddr: "192.0.2.10:5060",
		CallID: callID, CSeq: "1 " + method, Method: method,
		FromURI: "sip:alice@example", ToURI: "sip:bob@example",
		SDPCodecs:  []string{"PCMU"},
		Serialized: raw, Raw: []byte(raw), Fidelity: "byte_exact",
	}
}

const inviteRaw = "INVITE sip:bob@192.0.2.10:5060 SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-1;rport\r\n" +
	"From: <sip:alice@example>;tag=t1\r\n" +
	"To: <sip:bob@example>\r\n" +
	"Call-ID: c-1\r\n" +
	"CSeq: 1 INVITE\r\n" +
	"Max-Forwards: 70\r\n" +
	"Contact: <sip:alice@127.0.0.1:5066>\r\n" +
	"Content-Type: application/sdp\r\n" +
	"Content-Length: 145\r\n\r\n" +
	"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=sipclient-mcp\r\nc=IN IP4 127.0.0.1\r\n" +
	"t=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"

func TestSinkRingBufferIsBoundedAndEvictedWithTheCall(t *testing.T) {
	cases := []struct {
		name          string
		size          int
		appended      int
		wantMessages  int
		wantTruncated bool
	}{
		{"under the bound", 8, 5, 5, false},
		{"exactly at the bound", 8, 8, 8, false},
		{"over the bound evicts oldest", 8, 20, 8, true},
		{"far over the bound", 4, 1000, 4, true},
		{"zero size uses the default", 0, 3, 3, false},
	}
	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := trace.New(tc.size, 0)
			base := time.Unix(0, 0)
			for i := 0; i < tc.appended; i++ {
				s.SIPMessage(ctx, rec(base.Add(time.Duration(i)*time.Millisecond),
					session.Outbound, "c-1", "INVITE", inviteRaw))
			}
			got, err := s.Ladder(ctx, "", "c-1", session.LadderJSON)
			if err != nil {
				t.Fatalf("Ladder: %v", err)
			}
			if got.Format != session.LadderJSON {
				t.Errorf("Ladder.Format = %q, want %q — the result echoes the format it rendered", got.Format, session.LadderJSON)
			}
			if got.Messages != tc.wantMessages {
				t.Errorf("Messages = %d, want %d", got.Messages, tc.wantMessages)
			}
			if got.Truncated != tc.wantTruncated {
				t.Errorf("Truncated = %v, want %v", got.Truncated, tc.wantTruncated)
			}
			// The ring buffer is EVICTED WITH THE CALL: the janitor calls
			// Evict as part of registry eviction (U7), which returns the
			// memory promptly. It is an OPTIMISATION, not §N3's bound — the
			// LRU is, and TestLadderCountIsBoundedByMaxLadders covers that.
			s.Evict(ctx, "", "c-1")
			if _, err := s.Ladder(ctx, "", "c-1", session.LadderJSON); err == nil {
				t.Error("Ladder on an evicted call succeeded; want not_found")
			}
		})
	}
}

func TestSinkIsolatesCallsAndIgnoresRecordsWithNoCallID(t *testing.T) {
	ctx := context.Background()
	s := trace.New(0, 0)
	for _, cid := range []string{"a", "a", "b", ""} {
		s.SIPMessage(ctx, rec(time.Unix(0, 0), session.Outbound, cid, "INVITE", inviteRaw))
	}
	a, err := s.Ladder(ctx, "", "a", session.LadderJSON)
	if err != nil {
		t.Fatalf("Ladder(a): %v", err)
	}
	if a.Messages != 2 {
		t.Errorf("call a has %d messages, want 2", a.Messages)
	}
	b, err := s.Ladder(ctx, "", "b", session.LadderJSON)
	if err != nil {
		t.Fatalf("Ladder(b): %v", err)
	}
	if b.Messages != 1 {
		t.Errorf("call b has %d messages, want 1", b.Messages)
	}
	if _, err := s.Ladder(ctx, "", "", session.LadderJSON); err == nil {
		t.Error("a record with no Call-ID created a ladder; it must be dropped")
	}
}

// TestSinkKeysByUAHandleNotCallIDAlone is HIGH-3's discriminator. Inbound
// Call-IDs are peer-chosen verbatim, so a single peer can hand two UAs in
// DIFFERENT sessions the SAME Call-ID. If the sink keyed on Call-ID alone,
// their rings would merge and session A would read session B's traffic through
// its own legitimately-owned handle. Keying by (UAHandle, CallID) keeps the
// two rings separate: each UA's Ladder sees only its own message.
//
// This FAILS on the pre-fix sink: with a Call-ID-only key both records land in
// one ring, so each Ladder reports 2 messages and A's ladder leaks B's octets.
func TestSinkKeysByUAHandleNotCallIDAlone(t *testing.T) {
	ctx := context.Background()
	s := trace.New(0, 0)

	const sharedCallID = "collide@peer" // the peer sends the SAME Call-ID to both UAs

	recA := rec(time.Unix(0, 1), session.Outbound, sharedCallID, "INVITE", inviteRaw)
	recA.UAHandle = "ua_aaaaaaaaaaaaaaaa"
	recA.Serialized, recA.Raw = "SECRET-A-INVITE", []byte("SECRET-A-INVITE")

	recB := rec(time.Unix(0, 2), session.Outbound, sharedCallID, "BYE", inviteRaw)
	recB.UAHandle = "ua_bbbbbbbbbbbbbbbb"
	recB.Serialized, recB.Raw = "SECRET-B-BYE", []byte("SECRET-B-BYE")

	s.SIPMessage(ctx, recA)
	s.SIPMessage(ctx, recB)

	ladderA, err := s.Ladder(ctx, "ua_aaaaaaaaaaaaaaaa", sharedCallID, session.LadderJSON)
	if err != nil {
		t.Fatalf("Ladder(uaA): %v", err)
	}
	ladderB, err := s.Ladder(ctx, "ua_bbbbbbbbbbbbbbbb", sharedCallID, session.LadderJSON)
	if err != nil {
		t.Fatalf("Ladder(uaB): %v", err)
	}

	// Each UA sees exactly its OWN one message — not the two-message merge a
	// shared ring would produce.
	if ladderA.Messages != 1 {
		t.Errorf("uaA ladder has %d messages, want 1 (its own only); a merge would show 2", ladderA.Messages)
	}
	if ladderB.Messages != 1 {
		t.Errorf("uaB ladder has %d messages, want 1 (its own only); a merge would show 2", ladderB.Messages)
	}
	// The load-bearing disclosure assertion: A's ladder must NOT contain B's
	// octets, and vice versa. This is what fails when the rings collide.
	if strings.Contains(ladderA.Rendered, "SECRET-B-BYE") {
		t.Errorf("uaA's ladder leaked uaB's traffic (cross-session disclosure):\n%s", ladderA.Rendered)
	}
	if strings.Contains(ladderB.Rendered, "SECRET-A-INVITE") {
		t.Errorf("uaB's ladder leaked uaA's traffic (cross-session disclosure):\n%s", ladderB.Rendered)
	}
	// And each still sees its own, so the namespacing did not lose data.
	if !strings.Contains(ladderA.Rendered, "SECRET-A-INVITE") {
		t.Errorf("uaA lost its own traffic:\n%s", ladderA.Rendered)
	}
	if !strings.Contains(ladderB.Rendered, "SECRET-B-BYE") {
		t.Errorf("uaB lost its own traffic:\n%s", ladderB.Rendered)
	}
}

func TestDefaultLadderSizeIs512(t *testing.T) {
	if trace.DefaultLadderSize != 512 {
		t.Errorf("DefaultLadderSize = %d, want 512", trace.DefaultLadderSize)
	}
	if trace.DefaultMaxLadders != 512 {
		t.Errorf("DefaultMaxLadders = %d, want 512", trace.DefaultMaxLadders)
	}
}

// U15: the NUMBER OF LADDERS is bounded, not just each ladder's depth.
//
// THIS TEST GENUINELY OVERFLOWS. maxLadders is 4 and it taps 40 distinct
// Call-IDs, so the cap is crossed ten times over. A test that stayed under the
// cap would pass against a Sink with no LRU at all — which is exactly how the
// unbounded map survived the first review.
func TestLadderCountIsBoundedByMaxLadders(t *testing.T) {
	ctx := context.Background()
	const maxLadders = 4
	s := trace.New(8, maxLadders)

	for i := 0; i < 40; i++ {
		s.SIPMessage(ctx, rec(time.Unix(0, int64(i)), session.Outbound,
			fmt.Sprintf("call-%02d", i), "INVITE", inviteRaw))
		// The bound holds AT EVERY POINT, not merely at the end: §N3 bounds
		// held memory, not average held memory.
		if got := s.DebugLadderCount(); got > maxLadders {
			t.Fatalf("after %d Call-IDs the Sink holds %d ladders, want <= %d", i+1, got, maxLadders)
		}
	}

	if got := s.DebugLadderCount(); got != maxLadders {
		t.Errorf("Sink holds %d ladders after 40 distinct Call-IDs, want exactly %d", got, maxLadders)
	}
	// The OLDEST-WRITTEN is gone...
	if _, err := s.Ladder(ctx, "", "call-00", session.LadderJSON); err == nil {
		t.Error("the least-recently-written ladder survived; the LRU did not evict")
	}
	// ...and the NEWEST is present. Both halves are needed: a Sink that evicted
	// the wrong end would pass the first assertion alone.
	if _, err := s.Ladder(ctx, "", "call-39", session.LadderJSON); err != nil {
		t.Errorf("the most-recently-written ladder was evicted: %v", err)
	}
}

// Least-recently-WRITTEN, not least-recently-READ. Rendering a ladder must not
// protect it: an agent may call call_ladder long after a call ended, and
// read-recency eviction would reclaim exactly the ladders a slow agent is
// about to ask for.
func TestLRUOrdersOnWritesNotReads(t *testing.T) {
	ctx := context.Background()
	s := trace.New(8, 2)

	s.SIPMessage(ctx, rec(time.Unix(0, 1), session.Outbound, "old", "INVITE", inviteRaw))
	s.SIPMessage(ctx, rec(time.Unix(0, 2), session.Outbound, "new", "INVITE", inviteRaw))

	// Read "old" repeatedly. If reads counted, this would make it the freshest.
	for i := 0; i < 5; i++ {
		if _, err := s.Ladder(ctx, "", "old", session.LadderJSON); err != nil {
			t.Fatalf("Ladder(old): %v", err)
		}
	}
	// Now write a third Call-ID, forcing one eviction.
	s.SIPMessage(ctx, rec(time.Unix(0, 3), session.Outbound, "third", "INVITE", inviteRaw))

	if _, err := s.Ladder(ctx, "", "old", session.LadderJSON); err == nil {
		t.Error("reading a ladder protected it from eviction; the LRU must order on WRITES")
	}
}

// THE DEFECT U15 EXISTS FOR, in one test.
//
// ObservingConn taps the SOCKET, not the dialog, so a REGISTER's Call-ID gets a
// ladder even though no session.Call will ever bear it — §14.2's D9d test in
// fact REQUIRES the first outbound REGISTER to be tapped. The janitor only ever
// calls Evict with Call-IDs the session registry knows, so no Evict can reach
// these. Before U15 they accumulated forever on a daemon doing repeated
// ua_create/ua_destroy and failed dials — precisely §N3's stated workload.
func TestUntrackedCallIDsAreReclaimedByTheLRU(t *testing.T) {
	ctx := context.Background()
	const maxLadders = 3
	s := trace.New(8, maxLadders)

	// Call-IDs of the four classes no Evict can ever name: a REGISTER, an
	// OPTIONS keepalive (R10), a dial that errored before returning a
	// DialResult, and an inbound INVITE rejected before a Call record existed.
	untracked := []string{"reg-1", "opt-1", "faileddial-1", "earlyreject-1"}
	for i, cid := range untracked {
		s.SIPMessage(ctx, rec(time.Unix(0, int64(i)), session.Outbound, cid, "REGISTER", inviteRaw))
	}

	// Evict is powerless here: session never learned any of these Call-IDs, so
	// nothing would ever call it with them. Calling it anyway is a no-op, which
	// is the point — it is not the bound.
	for _, cid := range untracked {
		s.Evict(ctx, "", cid)
	}
	// Re-tap them, since the explicit Evicts above did remove them; the real
	// scenario is that those calls never happen at all.
	for i, cid := range untracked {
		s.SIPMessage(ctx, rec(time.Unix(0, int64(i)), session.Outbound, cid, "REGISTER", inviteRaw))
	}

	// The LRU reclaims them regardless. THAT is §N3's bound.
	if got := s.DebugLadderCount(); got != maxLadders {
		t.Errorf("Sink holds %d ladders for %d untrackable Call-IDs, want the cap %d — "+
			"without the LRU these accumulate forever, because no Evict can name them",
			got, len(untracked), maxLadders)
	}
	if _, err := s.Ladder(ctx, "", untracked[0], session.LadderJSON); err == nil {
		t.Error("the oldest untrackable ladder survived the cap; §N3's bound does not hold")
	}
}

// ---- U18: the LRU's candidate set is the UNRETAINED rings only ------------
//
// EVERY Call-ID in the five tests above is UNRETAINED. That is exactly why
// U15's inversion survived U15's own gate: the acceptance could not see the
// one ordering property that mattered. These four cross that gap.

// U18 case 1: a retained ring survives a flood that crosses the cap many
// times over, and does not count against the cap while it does.
func TestRetainedLadderSurvivesTheFlood(t *testing.T) {
	ctx := context.Background()
	const maxLadders = 3
	s := trace.New(4, maxLadders)

	s.SIPMessage(ctx, rec(time.Unix(0, 1), session.Outbound, "L", "ACK", inviteRaw))
	s.Retain(ctx, "", "L")
	if got := s.DebugRetainedCount(); got != 1 {
		t.Fatalf("DebugRetainedCount = %d after one Retain, want 1", got)
	}

	for i := 0; i < maxLadders+10; i++ {
		s.SIPMessage(ctx, rec(time.Unix(0, int64(100+i)), session.Outbound,
			fmt.Sprintf("flood-%02d", i), "OPTIONS", inviteRaw))
	}

	got, err := s.Ladder(ctx, "", "L", session.LadderJSON)
	if err != nil {
		t.Fatalf("Ladder(L) after %d unrelated insertions: %v — a retained ring is "+
			"never an eviction candidate (U18)", maxLadders+10, err)
	}
	if got.Messages != 1 {
		t.Errorf("retained ladder L has %d messages, want the 1 recorded ACK", got.Messages)
	}
	if n := s.DebugRetainedCount(); n != 1 {
		t.Errorf("DebugRetainedCount = %d after the flood, want 1", n)
	}
	// The retained ring does not COUNT against maxLadders either, so the cap
	// still admits a full complement of unretained rings alongside it.
	if n := s.DebugLadderCount(); n != maxLadders+1 {
		t.Errorf("DebugLadderCount = %d, want %d (%d unretained + 1 retained)",
			n, maxLadders+1, maxLadders)
	}
}

// U18 case 2: THE DIRECT INVERSION — the test that would have FAILED on U15 as
// shipped, and the reason U18 exists.
//
// "L" is a live call. At P1 it writes NOTHING to its ladder between the ACK and
// the BYE (no media per §15's R14 split, no session timers, no re-INVITEs), so
// its last write is the oldest in the store. "K" is keepalive OPTIONS traffic,
// which mints rings and refreshes its own recency on every write. Under pure
// least-recently-written eviction L is dropped FIRST and K outlives it —
// exactly backwards — and call_ladder on a live, owned handle then answers
// not_found, which is outside §10.11's error set and §13.5's distinction.
func TestLiveCallLadderOutlivesKeepaliveTraffic(t *testing.T) {
	ctx := context.Background()
	const maxLadders = 3
	s := trace.New(8, maxLadders)

	// The live call's last write is the ACK, at the OLDEST timestamp here.
	s.SIPMessage(ctx, rec(time.Unix(0, 1), session.Outbound, "L", "ACK", inviteRaw))
	s.Retain(ctx, "", "L")

	// Keepalive traffic: written repeatedly, so K is strictly the MOST recently
	// written ring at the moment the flood begins and L strictly the least.
	for i := 0; i < 5; i++ {
		s.SIPMessage(ctx, rec(time.Unix(0, int64(10+i)), session.Outbound,
			"K", "OPTIONS", inviteRaw))
	}

	for i := 0; i < maxLadders+10; i++ {
		s.SIPMessage(ctx, rec(time.Unix(0, int64(100+i)), session.Outbound,
			fmt.Sprintf("flood-%02d", i), "OPTIONS", inviteRaw))
	}

	if _, err := s.Ladder(ctx, "", "L", session.LadderJSON); err != nil {
		t.Errorf("the LIVE call's ladder was evicted (%v) — this is precisely U15's "+
			"inversion: a held call is the least-recently-written object in the store", err)
	}
	if _, err := s.Ladder(ctx, "", "K", session.LadderJSON); err == nil {
		t.Error("the keepalive ring survived the flood; it is unretained and must be " +
			"an eviction candidate like any other unretained ring")
	}
}

// U18 case 3: Evict is the ONLY release, and it must actually release. A
// retention Evict leaves behind is PERMANENT — the LRU can never reclaim a
// retained ring — which is a worse leak than the one U15 closed.
func TestEvictReleasesTheRetention(t *testing.T) {
	ctx := context.Background()
	const maxLadders = 3
	s := trace.New(4, maxLadders)

	s.SIPMessage(ctx, rec(time.Unix(0, 1), session.Outbound, "L", "ACK", inviteRaw))
	s.Retain(ctx, "", "L")
	s.Evict(ctx, "", "L")

	if got := s.DebugRetainedCount(); got != 0 {
		t.Fatalf("DebugRetainedCount = %d after Evict, want 0", got)
	}
	if _, err := s.Ladder(ctx, "", "L", session.LadderJSON); err == nil {
		t.Error("Ladder on an evicted call succeeded; want not_found")
	}

	for i := 0; i < maxLadders+10; i++ {
		s.SIPMessage(ctx, rec(time.Unix(0, int64(100+i)), session.Outbound,
			fmt.Sprintf("flood-%02d", i), "OPTIONS", inviteRaw))
	}
	if got := s.DebugLadderCount(); got != maxLadders {
		t.Errorf("DebugLadderCount = %d after the release and a flood, want exactly %d — "+
			"anything higher means a retained ring leaked past Evict", got, maxLadders)
	}
}

// U18 case 4: Retain may arrive BEFORE any message on that Call-ID. session
// retains on the DialResult's Call-ID, which reaches it with no ordering
// guarantee against the tap's first write, so Retain MUST create an empty
// retained ring rather than no-op — a no-op would leave the live call's first
// messages evictable for exactly the window the retention exists to cover.
func TestRetainBeforeAnyMessageRetainsTheRing(t *testing.T) {
	ctx := context.Background()
	const maxLadders = 3
	s := trace.New(4, maxLadders)

	s.Retain(ctx, "", "M")
	if got := s.DebugRetainedCount(); got != 1 {
		t.Fatalf("DebugRetainedCount = %d after Retain on an unknown Call-ID, want 1 — "+
			"Retain must create an empty retained ring, not no-op", got)
	}

	for i := 0; i < maxLadders+10; i++ {
		s.SIPMessage(ctx, rec(time.Unix(0, int64(100+i)), session.Outbound,
			fmt.Sprintf("flood-%02d", i), "OPTIONS", inviteRaw))
	}

	s.SIPMessage(ctx, rec(time.Unix(0, 200), session.Outbound, "M", "INVITE", inviteRaw))

	got, err := s.Ladder(ctx, "", "M", session.LadderJSON)
	if err != nil {
		t.Fatalf("Ladder(M) after the flood: %v — the ring retained before its first "+
			"message must still be there when the message arrives", err)
	}
	if got.Messages != 1 {
		t.Errorf("ladder M has %d messages, want the 1 recorded INVITE", got.Messages)
	}
}

// §6.3 gives every call its own goroutines: the ladder is written from the
// socket goroutines while call_ladder renders from an HTTP handler goroutine.
func TestSinkConcurrentAppendAndRender(t *testing.T) {
	ctx := context.Background()
	s := trace.New(64, 0)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				s.SIPMessage(ctx, rec(time.Unix(0, int64(i)), session.Outbound,
					fmt.Sprintf("c-%d", w%3), "INVITE", inviteRaw))
			}
		}(w)
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				for _, f := range []session.LadderFormat{session.LadderText, session.LadderMermaid, session.LadderJSON} {
					_, _ = s.Ladder(ctx, "", "c-0", f)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			s.Evict(ctx, "", "c-2")
		}
	}()
	wg.Wait()

	got, err := s.Ladder(ctx, "", "c-0", session.LadderJSON)
	if err != nil {
		t.Fatalf("Ladder: %v", err)
	}
	if got.Messages != 64 {
		t.Errorf("Messages = %d, want 64 (the ring bound)", got.Messages)
	}
	if !got.Truncated {
		t.Error("Truncated = false after overflowing the ring")
	}
}

// ---- D9b: opt-in per-call pcap capture engine ------------------------------

func TestCaptureStreamsPerCallScoped(t *testing.T) {
	s := trace.New(0, 0)
	var buf writeCloserBuf // bytes.Buffer + no-op Close, test helper
	cfg := session.CaptureConfig{Scope: "signaling", PayloadMode: "plaintext", MaxBytes: 1 << 20}
	if err := s.ArmCapture(context.Background(), "ua_1", "call-A", &buf, cfg); err != nil {
		t.Fatalf("ArmCapture: %v", err)
	}
	// A record for the armed call, and one for a DIFFERENT call on the same UA.
	s.SIPMessage(context.Background(), session.SIPRecord{
		UAHandle: "ua_1", CallID: "call-A", At: time.Unix(1, 0),
		Direction: session.Outbound, LocalAddr: "127.0.0.1:5060",
		RemoteAddr: "127.0.0.1:5062", Method: "INVITE",
		Raw: []byte("INVITE sip:a SIP/2.0\r\n\r\n")})
	s.SIPMessage(context.Background(), session.SIPRecord{
		UAHandle: "ua_1", CallID: "call-B", At: time.Unix(2, 0),
		Direction: session.Outbound, LocalAddr: "127.0.0.1:5060",
		RemoteAddr: "127.0.0.1:5064", Method: "INVITE",
		Raw: []byte("INVITE sip:b SIP/2.0\r\n\r\n")})
	res, err := s.DisarmCapture(context.Background(), "ua_1", "call-A")
	if err != nil {
		t.Fatalf("DisarmCapture: %v", err)
	}
	if res.Name != "capture.pcap" || res.Packets != 1 {
		t.Fatalf("want name=capture.pcap packets=1, got %+v", res)
	}
	if res.CaptureFidelity["udp"] != "byte_exact" {
		t.Fatalf("capture_fidelity = %v, want {udp:byte_exact}", res.CaptureFidelity)
	}
	if res.SignalingCiphertext != "not_requested" {
		t.Fatalf("signaling_ciphertext = %q, want not_requested", res.SignalingCiphertext)
	}
	if bytes.Contains(buf.Bytes(), []byte("sip:b")) {
		t.Fatal("capture leaked call-B's INVITE into call-A's pcap")
	}
	if !bytes.Contains(buf.Bytes(), []byte("sip:a")) {
		t.Fatal("capture missing call-A's INVITE")
	}
}

// TestCaptureMaxBytesTruncates asserts the §12.3 byte cap: arm with MaxBytes
// smaller than the header plus one frame, push several records, and confirm
// the result reports Truncated and the written bytes never exceed MaxBytes.
func TestCaptureMaxBytesTruncates(t *testing.T) {
	ctx := context.Background()
	s := trace.New(0, 0)
	var buf writeCloserBuf
	// One frame from this fixture is well over 24 + a few bytes, so a cap of
	// header-size + 10 admits the header but truncates on the first frame.
	const maxBytes = int64(24 + 10)
	cfg := session.CaptureConfig{Scope: "signaling", MaxBytes: maxBytes}
	if err := s.ArmCapture(ctx, "ua_1", "call-A", &buf, cfg); err != nil {
		t.Fatalf("ArmCapture: %v", err)
	}
	for i := 0; i < 5; i++ {
		s.SIPMessage(ctx, session.SIPRecord{
			UAHandle: "ua_1", CallID: "call-A", At: time.Unix(int64(i), 0),
			Direction: session.Outbound, LocalAddr: "127.0.0.1:5060",
			RemoteAddr: "127.0.0.1:5062", Method: "INVITE",
			Raw: []byte(inviteRaw)})
		if int64(buf.Len()) > maxBytes {
			t.Fatalf("after record %d, written %d bytes exceeds MaxBytes %d", i, buf.Len(), maxBytes)
		}
	}
	res, err := s.DisarmCapture(ctx, "ua_1", "call-A")
	if err != nil {
		t.Fatalf("DisarmCapture: %v", err)
	}
	if !res.Truncated {
		t.Error("Truncated = false, want true — MaxBytes was crossed")
	}
	if res.Bytes > maxBytes {
		t.Errorf("res.Bytes = %d, exceeds MaxBytes %d", res.Bytes, maxBytes)
	}
	if int64(buf.Len()) > maxBytes {
		t.Errorf("buf holds %d bytes, exceeds MaxBytes %d", buf.Len(), maxBytes)
	}
}

// hasCode reports whether err is an *apierr.Error with the given code.
func hasCode(err error, want apierr.Code) bool {
	var ae *apierr.Error
	return errors.As(err, &ae) && ae.Code == want
}

// TestArmCaptureAlreadyArmedPreconditionFailed is D9's already-armed gate at the
// ENGINE layer (B1a): arming the SAME (uaHandle, callID) twice returns an
// *apierr.Error with code precondition_failed.
func TestArmCaptureAlreadyArmedPreconditionFailed(t *testing.T) {
	ctx := context.Background()
	s := trace.New(0, 0)
	var buf1, buf2 writeCloserBuf
	cfg := session.CaptureConfig{Scope: "signaling"}
	if err := s.ArmCapture(ctx, "ua_1", "call-A", &buf1, cfg); err != nil {
		t.Fatalf("first ArmCapture: %v", err)
	}
	err := s.ArmCapture(ctx, "ua_1", "call-A", &buf2, cfg)
	if !hasCode(err, apierr.CodePreconditionFailed) {
		t.Fatalf("second ArmCapture err = %v, want precondition_failed (already armed)", err)
	}
}

// TestArmCaptureSubHeaderMaxBytesInvalidArgument is D9's MaxBytes>0 && <24 gate
// at the ENGINE layer (B2a): a positive MaxBytes below the 24-byte pcap header
// is rejected invalid_argument, since such a cap could not even admit the header.
func TestArmCaptureSubHeaderMaxBytesInvalidArgument(t *testing.T) {
	ctx := context.Background()
	s := trace.New(0, 0)
	var buf writeCloserBuf
	cfg := session.CaptureConfig{Scope: "signaling", MaxBytes: 12} // 0 < 12 < 24
	err := s.ArmCapture(ctx, "ua_1", "call-A", &buf, cfg)
	if !hasCode(err, apierr.CodeInvalidArgument) {
		t.Fatalf("ArmCapture with sub-24 MaxBytes err = %v, want invalid_argument", err)
	}
}

// TestCaptureSilentlyDropsNonSynthesisableRecord is the pcap 5-tuple failure
// path at the engine layer (B3): a record whose 5-tuple will not synthesise
// (here a non-IPv4 address) is SILENTLY DROPPED by writeFrame — no panic, the
// capture continues, and the packet count is unchanged. One good IPv4 record
// plus one non-IPv4 record yields exactly one counted packet.
func TestCaptureSilentlyDropsNonSynthesisableRecord(t *testing.T) {
	ctx := context.Background()
	s := trace.New(0, 0)
	var buf writeCloserBuf
	if err := s.ArmCapture(ctx, "ua_1", "call-A", &buf, session.CaptureConfig{Scope: "signaling"}); err != nil {
		t.Fatalf("ArmCapture: %v", err)
	}
	good := session.SIPRecord{
		UAHandle: "ua_1", CallID: "call-A", At: time.Unix(1, 0),
		Direction: session.Outbound, LocalAddr: "127.0.0.1:5060",
		RemoteAddr: "127.0.0.1:5062", Method: "INVITE", Raw: []byte(inviteRaw),
	}
	nonIPv4 := session.SIPRecord{
		UAHandle: "ua_1", CallID: "call-A", At: time.Unix(2, 0),
		Direction: session.Outbound, LocalAddr: "[::1]:5060",
		RemoteAddr: "[::1]:5062", Method: "INVITE", Raw: []byte(inviteRaw),
	}
	s.SIPMessage(ctx, good)
	s.SIPMessage(ctx, nonIPv4) // dropped: no IPv4 5-tuple to synthesise

	res, err := s.DisarmCapture(ctx, "ua_1", "call-A")
	if err != nil {
		t.Fatalf("DisarmCapture: %v", err)
	}
	if res.Packets != 1 {
		t.Fatalf("res.Packets = %d, want 1 — the non-IPv4 record must be dropped, not counted or fatal", res.Packets)
	}
}

// TestDisarmCaptureIsIdempotent: arm, push a record, DisarmCapture twice ->
// the same non-zero-Packets result and no panic; then Evict, and confirm no
// double-close panic.
func TestDisarmCaptureIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := trace.New(0, 0)
	var buf writeCloserBuf
	if err := s.ArmCapture(ctx, "ua_1", "call-A", &buf, session.CaptureConfig{Scope: "signaling"}); err != nil {
		t.Fatalf("ArmCapture: %v", err)
	}
	s.SIPMessage(ctx, session.SIPRecord{
		UAHandle: "ua_1", CallID: "call-A", At: time.Unix(1, 0),
		Direction: session.Outbound, LocalAddr: "127.0.0.1:5060",
		RemoteAddr: "127.0.0.1:5062", Method: "INVITE",
		Raw: []byte(inviteRaw)})

	res1, err := s.DisarmCapture(ctx, "ua_1", "call-A")
	if err != nil {
		t.Fatalf("first DisarmCapture: %v", err)
	}
	if res1.Packets == 0 {
		t.Fatalf("first DisarmCapture: Packets = 0, want > 0")
	}
	res2, err := s.DisarmCapture(ctx, "ua_1", "call-A")
	if err != nil {
		t.Fatalf("second DisarmCapture: %v", err)
	}
	if res2.Name != res1.Name || res2.Bytes != res1.Bytes || res2.Packets != res1.Packets ||
		res2.Truncated != res1.Truncated || res2.SignalingCiphertext != res1.SignalingCiphertext {
		t.Errorf("second DisarmCapture = %+v, want the cached %+v", res2, res1)
	}

	// Evict must not double-close-panic on an already-closed capture.
	s.Evict(ctx, "ua_1", "call-A")
}

// TestArmCaptureReportsTCPFidelityAndProtocol6 is the ONLY test in this file
// (or pcap_tcp_test.go) that exercises the tcp/tls capture-fidelity path
// through the ACTUAL Sink API (ArmCapture -> SIPMessage -> DisarmCapture).
// Every capture test above uses Transport-unset records (defaulting to udp
// fidelity), and pcap_tcp_test.go's TestPcapFrameTCPUsesProtocol6 drives
// streamSeqEncoder.frame directly (package trace, not trace_test) — bypassing
// Sink entirely. Neither would catch a regression that reverted
// CaptureResult.CaptureFidelity to a hardcoded {"udp":"byte_exact"} (D2), or
// that broke ArmCapture's streaming path's wiring to streamSeqEncoder for
// non-udp transports — exactly the path cmd/sipclient-mcpd/run.go wires the
// real daemon's capture through.
//
// TLS is not given its own test here: pcapFidelityTransport and
// streamSeqEncoder both switch on rec.Transport with tcp and tls sharing the
// identical framing arm (only the reported label differs — sink.go's
// pcapFidelityTransport), so a second test would duplicate this one's
// assertions without covering new code (Rule 15).
func TestArmCaptureReportsTCPFidelityAndProtocol6(t *testing.T) {
	ctx := context.Background()
	s := trace.New(0, 0)
	var buf writeCloserBuf
	if err := s.ArmCapture(ctx, "ua_1", "call-A", &buf, session.CaptureConfig{Scope: "signaling"}); err != nil {
		t.Fatalf("ArmCapture: %v", err)
	}
	s.SIPMessage(ctx, session.SIPRecord{
		UAHandle: "ua_1", CallID: "call-A", At: time.Unix(1, 0),
		Direction: session.Outbound, Transport: session.TransportTCP,
		LocalAddr: "127.0.0.1:5060", RemoteAddr: "127.0.0.1:5062",
		Method: "INVITE", Raw: []byte(inviteRaw)})

	res, err := s.DisarmCapture(ctx, "ua_1", "call-A")
	if err != nil {
		t.Fatalf("DisarmCapture: %v", err)
	}
	if res.CaptureFidelity["tcp"] != "byte_exact" {
		t.Fatalf("capture_fidelity = %v, want {tcp:byte_exact} — CaptureFidelity must report "+
			"the OBSERVED transport, not a hardcoded udp", res.CaptureFidelity)
	}

	// Confirm the STREAMING Sink path actually reaches streamSeqEncoder's tcp
	// framing, not just that the label says so: PcapFileHeader() is the
	// 24-byte global header (ArmCapture's doc comment), then the first
	// record is a 16-byte pcap-record header followed by the IP header,
	// whose byte 9 is the protocol (see pcap_tcp_test.go's
	// TestPcapFrameTCPUsesProtocol6 for the identical offset pattern).
	got := buf.Bytes()
	const ipProtocolOffset = 24 + 16 + 9
	if len(got) <= ipProtocolOffset {
		t.Fatalf("captured pcap is only %d bytes, want more than %d", len(got), ipProtocolOffset)
	}
	if got[ipProtocolOffset] != 6 {
		t.Fatalf("IP protocol byte = %d, want 6 (TCP) — the streaming Sink path is not "+
			"reaching the tcp arm of streamSeqEncoder", got[ipProtocolOffset])
	}
}

// TestBlockingCaptureDoesNotStallOtherCalls is the D7 assertion (finding
// NEW-1): a blocking pcap Write on call A must hold only cap.mu, never s.mu,
// so an UNRELATED call B's SIPMessage and Ladder proceed promptly while A is
// stuck. Run with -race and a test timeout so a lock-discipline regression
// surfaces as a hang, not a silent pass.
func TestBlockingCaptureDoesNotStallOtherCalls(t *testing.T) {
	ctx := context.Background()
	s := trace.New(0, 0)
	unblock := make(chan struct{})
	bw := blockingWriteCloser{unblock: unblock}
	if err := s.ArmCapture(ctx, "ua_1", "call-A", bw, session.CaptureConfig{Scope: "signaling"}); err != nil {
		t.Fatalf("ArmCapture: %v", err)
	}

	recA := session.SIPRecord{
		UAHandle: "ua_1", CallID: "call-A", At: time.Unix(1, 0),
		Direction: session.Outbound, LocalAddr: "127.0.0.1:5060",
		RemoteAddr: "127.0.0.1:5062", Method: "INVITE",
		Raw: []byte(inviteRaw),
	}
	aStarted := make(chan struct{})
	aDone := make(chan struct{})
	go func() {
		close(aStarted)
		s.SIPMessage(ctx, recA) // blocks inside cap.writeFrame, holding only cap.mu
		close(aDone)
	}()
	<-aStarted
	// Give the goroutine a moment to actually enter the blocking Write before
	// asserting the rest of the Sink is unaffected.
	time.Sleep(20 * time.Millisecond)

	recB := session.SIPRecord{
		UAHandle: "ua_1", CallID: "call-B", At: time.Unix(2, 0),
		Direction: session.Outbound, LocalAddr: "127.0.0.1:5060",
		RemoteAddr: "127.0.0.1:5064", Method: "INVITE",
		Raw: []byte(inviteRaw),
	}
	bDone := make(chan struct{})
	go func() {
		s.SIPMessage(ctx, recB)
		close(bDone)
	}()
	select {
	case <-bDone:
	case <-time.After(2 * time.Second):
		t.Fatal("SIPMessage for unrelated call B did not return promptly; s.mu is held across A's blocking pcap write")
	}

	ladderDone := make(chan struct{})
	go func() {
		_, _ = s.Ladder(ctx, "", "call-B", session.LadderJSON)
		close(ladderDone)
	}()
	select {
	case <-ladderDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Ladder for unrelated call B did not return promptly; s.mu is held across A's blocking pcap write")
	}

	close(unblock)
	select {
	case <-aDone:
	case <-time.After(2 * time.Second):
		t.Fatal("call A's SIPMessage never returned after unblocking")
	}
}
