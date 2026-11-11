package netfault

import (
	"errors"
	"math/rand"
	"net"
	"testing"
	"time"
)

var testAddr net.Addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060}

// errNoPacket is returned by memConn.ReadFrom when its buffer is drained. It
// must NOT block: TestDropPatternDelivers950Of1000 calls ReadFrom exactly
// 1000 times against 1000 pre-loaded packets, and relies on the trailing
// calls (past exhaustion) failing immediately rather than hanging.
var errNoPacket = errors.New("memConn: no packet available")

type packet struct {
	data []byte
	addr net.Addr
}

// memConn is a chan-backed net.PacketConn used only by this package's own
// tests, so ReadFrom/WriteTo ordering is fully deterministic — no real
// socket, no OS scheduling jitter.
type memConn struct{ ch chan packet }

func newMemConn(capacity int) *memConn {
	if capacity < 1 {
		capacity = 1
	}
	return &memConn{ch: make(chan packet, capacity)}
}

// push pre-loads a packet for a future ReadFrom to deliver.
func (m *memConn) push(data []byte, addr net.Addr) { m.ch <- packet{data: data, addr: addr} }

func (m *memConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-m.ch:
		return copy(p, pkt.data), pkt.addr, nil
	default:
		return 0, nil, errNoPacket
	}
}

func (m *memConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	m.push(append([]byte(nil), p...), addr)
	return len(p), nil
}

// drained pops every packet currently queued in m.ch, in FIFO order, without
// blocking. WriteTo pushes onto m.ch, so for the tx-direction tests below
// this doubles as the record of what the inner PacketConn actually received
// "on the wire" — including duplicates (pushed twice) and excluding drops
// (never pushed).
func (m *memConn) drained() []packet {
	var out []packet
	for {
		select {
		case pkt := <-m.ch:
			out = append(out, pkt)
		default:
			return out
		}
	}
}

func (m *memConn) Close() error                       { return nil }
func (m *memConn) LocalAddr() net.Addr                { return testAddr }
func (m *memConn) SetDeadline(_ time.Time) error      { return nil }
func (m *memConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m *memConn) SetWriteDeadline(_ time.Time) error { return nil }

// TestDropPatternDelivers950Of1000 is the §14.6 unit acceptance: a length-20
// pattern with exactly one drop is 1-in-20, so 1000 rx packets deliver
// exactly 950.
func TestDropPatternDelivers950Of1000(t *testing.T) {
	// pattern of length 20 with exactly one drop => 1 in 20 => 50 of 1000 dropped.
	pattern := make([]bool, 20)
	pattern[0] = true // drop the 1st of every 20
	inner := newMemConn(1000)
	c := New(inner, Config{RX: []Impairment{Drop{Pattern: pattern}}})
	for i := 0; i < 1000; i++ {
		inner.push([]byte{byte(i)}, testAddr) // pre-load 1000 rx packets
	}
	delivered := 0
	buf := make([]byte, 8)
	for i := 0; i < 1000; i++ {
		if _, _, err := c.ReadFrom(buf); err == nil {
			delivered++
		}
	}
	if delivered != 950 {
		t.Fatalf("delivered %d of 1000, want exactly 950", delivered)
	}
}

// TestBurstDropEveryN: EveryN=4, RunLen=1 drops the 1st packet of every
// 4-cycle. 8 pushed packets (2 cycles) deliver exactly 6; the trailing reads
// (channel drained) fail rather than block.
func TestBurstDropEveryN(t *testing.T) {
	inner := newMemConn(8)
	c := New(inner, Config{RX: []Impairment{BurstDrop{EveryN: 4, RunLen: 1}}})
	for i := 0; i < 8; i++ {
		inner.push([]byte{byte(i)}, testAddr)
	}
	delivered := 0
	buf := make([]byte, 8)
	for i := 0; i < 8; i++ {
		if _, _, err := c.ReadFrom(buf); err == nil {
			delivered++
		}
	}
	if delivered != 6 {
		t.Fatalf("delivered %d of 8, want exactly 6 (2 dropped, one per 4-cycle)", delivered)
	}
}

// TestDuplicateEveryN: EveryN=3 delivers the 3rd and 6th packets twice, back
// to back, of a 6-packet stream.
func TestDuplicateEveryN(t *testing.T) {
	inner := newMemConn(6)
	c := New(inner, Config{RX: []Impairment{Duplicate{EveryN: 3}}})
	for i := 0; i < 6; i++ {
		inner.push([]byte{byte(i)}, testAddr)
	}
	buf := make([]byte, 8)
	var got []byte
	for i := 0; i < 8; i++ {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read %d: unexpected error %v", i, err)
		}
		got = append(got, buf[:n]...)
	}
	want := []byte{0, 1, 2, 2, 3, 4, 5, 5}
	if string(got) != string(want) {
		t.Fatalf("got %v, want %v (3rd and 6th packets each delivered twice)", got, want)
	}
}

// TestRewriteSourceAfterN: AfterN=2 leaves the first two packets' source
// address untouched and rewrites every packet after that to Addr.
func TestRewriteSourceAfterN(t *testing.T) {
	rewriteAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 6000}
	inner := newMemConn(4)
	c := New(inner, Config{RX: []Impairment{RewriteSource{Addr: rewriteAddr, AfterN: 2}}})
	for i := 0; i < 4; i++ {
		inner.push([]byte{byte(i)}, testAddr)
	}
	buf := make([]byte, 8)
	wantAddr := []net.Addr{testAddr, testAddr, rewriteAddr, rewriteAddr}
	for i := 0; i < 4; i++ {
		_, addr, err := c.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read %d: unexpected error %v", i, err)
		}
		if addr != wantAddr[i] {
			t.Fatalf("packet %d: addr = %v, want %v", i+1, addr, wantAddr[i])
		}
	}
}

// TestReorderHoldsAndReleases: EveryN=3, DelayN=2 holds the 3rd packet of a
// 5-packet stream and releases it 2 packets later than it would otherwise
// have been delivered, on the rx path. 5 packets (not 6) so the single hold
// triggered (n=3) has a release point (n=5) that is actually reached within
// the stream — a 2nd trigger (n=6) would hold forever with no n=8 to release
// it.
func TestReorderHoldsAndReleases(t *testing.T) {
	inner := newMemConn(5)
	c := New(inner, Config{RX: []Impairment{Reorder{EveryN: 3, DelayN: 2}}})
	for i := 0; i < 5; i++ {
		inner.push([]byte{byte(i)}, testAddr)
	}
	buf := make([]byte, 8)
	var got []byte
	for i := 0; i < 5; i++ {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read %d: unexpected error %v", i, err)
		}
		got = append(got, buf[:n]...)
	}
	// packet index 2 (0-based, the 3rd packet) is held and released 2
	// packet-positions later: 0,1,3,4,2.
	want := []byte{0, 1, 3, 4, 2}
	if string(got) != string(want) {
		t.Fatalf("got %v, want %v (3rd packet released 2 positions later)", got, want)
	}
}

// TestDelaySeededJitterIsReproducible asserts reproducibility, not
// wall-clock precision: two independently seeded rngs with the SAME seed
// produce the SAME sequence of computed delay durations for Delay.
func TestDelaySeededJitterIsReproducible(t *testing.T) {
	d := Delay{FixedMS: 5, JitterMS: 10}
	rng1 := rand.New(rand.NewSource(42))
	rng2 := rand.New(rand.NewSource(42))
	for n := int64(1); n <= 20; n++ {
		v1 := d.verdict(n, rng1, testAddr)
		v2 := d.verdict(n, rng2, testAddr)
		if v1.delay != v2.delay {
			t.Fatalf("packet %d: delay mismatch with same seed: %v vs %v", n, v1.delay, v2.delay)
		}
	}
}

// TestTxDropSuppressesSend is the tx-direction counterpart of
// TestDropPatternDelivers950Of1000: a dropped tx packet must be
// "pretend-sent" (WriteTo still returns len(p), nil) WITHOUT forwarding to
// the inner conn. Before this test, no test exercised the tx DROP branch, so
// a bug that forwarded the packet anyway (defeating the drop) would pass
// every existing test.
func TestTxDropSuppressesSend(t *testing.T) {
	inner := newMemConn(8)
	// Pattern of length 3: drop the 1st of every 3 packets sent.
	c := New(inner, Config{TX: []Impairment{Drop{Pattern: []bool{true, false, false}}}})
	for i := 0; i < 3; i++ {
		n, err := c.WriteTo([]byte{byte(i)}, testAddr)
		if err != nil {
			t.Fatalf("WriteTo %d: unexpected error %v", i, err)
		}
		if n != 1 {
			t.Fatalf("WriteTo %d: n = %d, want 1 (pretend-sent even when dropped)", i, n)
		}
	}
	got := inner.drained()
	if len(got) != 2 {
		t.Fatalf("inner received %d packets, want exactly 2 (packet 0 dropped, never reaching the wire): %v", len(got), got)
	}
	if got[0].data[0] != 1 || got[1].data[0] != 2 {
		t.Fatalf("inner received packets %v, want [1 2] in order (packet 0 dropped)", got)
	}
}

// TestTxDuplicateDoubleWrites is the tx-direction counterpart of
// TestDuplicateEveryN: a duplicated tx packet must reach the inner conn via
// TWO separate WriteTo calls, not merely be reported as sent twice by the
// wrapper.
func TestTxDuplicateDoubleWrites(t *testing.T) {
	inner := newMemConn(8)
	c := New(inner, Config{TX: []Impairment{Duplicate{EveryN: 3}}})
	for i := 0; i < 3; i++ {
		if _, err := c.WriteTo([]byte{byte(i)}, testAddr); err != nil {
			t.Fatalf("WriteTo %d: unexpected error %v", i, err)
		}
	}
	got := inner.drained()
	want := []byte{0, 1, 2, 2}
	if len(got) != len(want) {
		t.Fatalf("inner received %d packets, want %d (3rd packet written twice): %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].data[0] != w {
			t.Fatalf("packet %d: inner received %v, want %v", i, got[i].data, want)
		}
	}
}

// TestDelayProducesExpectedDelay closes the blind spot in
// TestDelaySeededJitterIsReproducible: reproducibility alone would still
// pass even if verdict always returned a zero delay. This asserts the actual
// computed delay VALUE.
func TestDelayProducesExpectedDelay(t *testing.T) {
	// No jitter: the rng is never consulted (JitterMS == 0 skips Intn), so
	// the delay is exactly FixedMS regardless of seed.
	d := Delay{FixedMS: 5, JitterMS: 0}
	v := d.verdict(1, rand.New(rand.NewSource(1)), testAddr)
	if v.delay != 5*time.Millisecond {
		t.Fatalf("delay = %v, want exactly 5ms (FixedMS with no jitter)", v.delay)
	}

	// With jitter: assert against an independently-seeded rng performing the
	// same documented computation (FixedMS + Intn(JitterMS+1)) for seed 42,
	// packet 1 — an exact value check, not just self-reproducibility.
	dj := Delay{FixedMS: 5, JitterMS: 10}
	want := time.Duration(5+rand.New(rand.NewSource(42)).Intn(11)) * time.Millisecond
	got := dj.verdict(1, rand.New(rand.NewSource(42)), testAddr)
	if got.delay != want {
		t.Fatalf("delay = %v, want %v (FixedMS=5 + seeded jitter, seed 42, packet 1)", got.delay, want)
	}
}

// TestTxReorderPanics is the fail-loud acceptance (finding 3): Reorder is
// rx-only, and New must panic at construction time if placed in Config.TX
// rather than silently doing nothing.
func TestTxReorderPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New with a tx-side Reorder must panic; a silently-inert tx reorder " +
				"would let W4 get no reordering with no signal")
		}
	}()
	New(newMemConn(0), Config{TX: []Impairment{Reorder{EveryN: 3, DelayN: 1}}})
}
