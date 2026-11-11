// Package netfault is a TEST-ONLY deterministic UDP fault injector (§14.6). It
// wraps a net.PacketConn and applies per-direction impairments. It is NOT an MCP
// tool and MUST NEVER become one — a tool that could inject loss would let an
// agent manufacture a quality result. It lives under internal/testutil, which §9
// forbids the daemon from importing (asserted by importguard).
package netfault

import (
	"math/rand"
	"net"
	"sync"
	"time"
)

// Impairment decides, per packet in its direction, what happens to it.
type Impairment interface {
	// verdict is consulted with the 1-based packet index n for this direction
	// and the direction's seeded rng. Impairments needing cross-packet state
	// (reorder, burst_drop) keep it internally; they are single-direction and
	// single-goroutine under the pipeline mutex.
	verdict(n int64, rng *rand.Rand, raddr net.Addr) verdict
}

type verdict struct {
	drop        bool
	duplicate   bool          // deliver/send twice
	delay       time.Duration // hold before delivery
	rewriteTo   net.Addr      // non-nil overrides the source addr (rx only)
	holdRelease int64         // >0: hold this packet, release it this many packets later (reorder)
}

// Drop discards packets, by seeded rate OR by deterministic cycled pattern.
type Drop struct {
	Rate    float64 // 0..1; used when Pattern is nil
	Pattern []bool  // cycled; true = drop (exactly deterministic)
}

func (d Drop) verdict(n int64, rng *rand.Rand, _ net.Addr) verdict {
	if len(d.Pattern) > 0 {
		return verdict{drop: d.Pattern[(n-1)%int64(len(d.Pattern))]}
	}
	return verdict{drop: rng.Float64() < d.Rate}
}

// BurstDrop drops RunLen consecutive packets every EveryN packets.
type BurstDrop struct{ EveryN, RunLen int64 }

func (b BurstDrop) verdict(n int64, _ *rand.Rand, _ net.Addr) verdict {
	pos := (n - 1) % b.EveryN
	return verdict{drop: pos < b.RunLen}
}

// Duplicate delivers every EveryN-th packet twice.
type Duplicate struct{ EveryN int64 }

func (d Duplicate) verdict(n int64, _ *rand.Rand, _ net.Addr) verdict {
	return verdict{duplicate: n%d.EveryN == 0}
}

// Delay holds each packet FixedMS plus seeded uniform JitterMS.
//
// LIMITATION (Cycle-5 #4): the hold is a time.Sleep performed by ReadFrom/WriteTo
// while they hold the direction mutex, so Delay is HEAD-OF-LINE blocking, not
// independent per-packet jitter — a delayed packet stalls every packet behind
// it in the same direction. Use Reorder for genuine out-of-order delivery; Delay
// models a uniform latency floor, not a jitter distribution.
type Delay struct{ FixedMS, JitterMS int }

func (d Delay) verdict(_ int64, rng *rand.Rand, _ net.Addr) verdict {
	ms := d.FixedMS
	if d.JitterMS > 0 {
		ms += rng.Intn(d.JitterMS + 1)
	}
	return verdict{delay: time.Duration(ms) * time.Millisecond}
}

// RewriteSource delivers from Addr after AfterN packets (rx; R10 latching).
type RewriteSource struct {
	Addr   net.Addr
	AfterN int64
}

func (r RewriteSource) verdict(n int64, _ *rand.Rand, _ net.Addr) verdict {
	if n > r.AfterN {
		return verdict{rewriteTo: r.Addr}
	}
	return verdict{}
}

// Reorder holds every EveryN-th packet and signals the pipeline to release it
// DelayN packets later. The buffering itself lives in the pipeline (which
// owns the payload and the read loop); Reorder is a pure per-packet decider
// like the other five, so it participates through combine() and compiles as
// an Impairment. Reorder is RX-ONLY: New panics if placed in Config.TX (its
// only consumer is the W4 rx jitter buffer).
//
// LIMITATION (Cycle-5 #2): a reorder that lands within the last DelayN packets
// of a stream STRANDS the held packet — its release index is never reached by a
// subsequent ReadFrom, so it is silently dropped rather than reordered. This is
// acceptable for the seeded W4 rx-jitter fixtures (which always read past the
// release point); a full flush-on-close is deferred to W4 if it ever matters.
type Reorder struct{ EveryN, DelayN int64 }

func (r Reorder) verdict(n int64, _ *rand.Rand, _ net.Addr) verdict {
	if r.EveryN > 0 && n%r.EveryN == 0 {
		return verdict{holdRelease: r.DelayN}
	}
	return verdict{}
}

// Config names the per-direction impairment pipelines and their seeds.
type Config struct {
	RX, TX []Impairment
	RXSeed int64
	TXSeed int64
}

type pipeline struct {
	mu   sync.Mutex
	imps []Impairment
	rng  *rand.Rand
	n    int64
	// pending holds duplicate/released-reorder copies to emit on the next
	// ReadFrom (FIFO).
	pending [][]byte
	// held holds reordered payloads keyed by their release packet-index
	// (Reorder).
	held map[int64][]byte
	// lastAddr is the source addr to report for a pending-queue emission (rx
	// only — ReadFrom is the only consumer; duplicates/reordered releases
	// carry the address of the packet they were derived from).
	//
	// LIMITATION (Cycle-5 #3 / Cycle-3 #5): the whole pending queue shares this
	// ONE lastAddr, so a queued duplicate/reordered release reports the source
	// of the MOST RECENT holding packet, not its own. This is exact for the
	// single-peer W4 RTP path (one remote address throughout) but imprecise for
	// a multi-peer stream, where a release could be attributed to the wrong peer.
	lastAddr net.Addr
}

// Conn wraps a net.PacketConn, applying independent rx/tx impairment
// pipelines to ReadFrom/WriteTo.
type Conn struct {
	net.PacketConn
	rx, tx *pipeline
}

// New wraps inner with cfg's per-direction impairments.
//
// It panics if cfg.TX contains a Reorder: Reorder is rx-only (its only
// consumer is the W4 rx jitter buffer), and a tx-side hold/release has no
// consumer to drain it. A silently-inert tx reorder would let W4 get no
// reordering with no signal, so this is rejected at construction rather than
// ignored (finding 3) — this is test-only code, so a construction-time panic
// is the correct fail-loud: a misconfigured injector must not run.
func New(inner net.PacketConn, cfg Config) *Conn {
	for _, imp := range cfg.TX {
		if _, isReorder := imp.(Reorder); isReorder {
			panic("netfault: Reorder is rx-only (its consumer is the W4 rx jitter buffer); " +
				"place it in Config.RX, not Config.TX")
		}
	}
	return &Conn{
		PacketConn: inner,
		rx:         &pipeline{imps: cfg.RX, rng: rand.New(rand.NewSource(cfg.RXSeed))},
		tx:         &pipeline{imps: cfg.TX, rng: rand.New(rand.NewSource(cfg.TXSeed))},
	}
}

// ReadFrom applies the rx pipeline. A dropped packet is skipped (the loop reads
// again); a duplicated packet's copy is queued in pending; delay sleeps;
// rewriteTo substitutes the returned source address.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.rx.mu.Lock()
	defer c.rx.mu.Unlock()
	for {
		if len(c.rx.pending) > 0 {
			buf := c.rx.pending[0]
			c.rx.pending = c.rx.pending[1:]
			return copy(p, buf), c.rx.lastAddr, nil
		}
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		c.rx.n++
		v := combine(c.rx.imps, c.rx.n, c.rx.rng, addr)
		if v.drop {
			continue
		}
		// Reorder: stash this packet for release DelayN packets later, and read on.
		if v.holdRelease > 0 {
			if c.rx.held == nil {
				c.rx.held = map[int64][]byte{}
			}
			stash := make([]byte, n)
			copy(stash, p[:n])
			c.rx.held[c.rx.n+v.holdRelease] = stash
			c.rx.lastAddr = addr
			continue
		}
		if v.delay > 0 {
			time.Sleep(v.delay)
		}
		if v.rewriteTo != nil {
			addr = v.rewriteTo
		}
		if v.duplicate {
			dup := make([]byte, n)
			copy(dup, p[:n])
			c.rx.pending = append(c.rx.pending, dup)
			c.rx.lastAddr = addr
		}
		// A held packet now due (reorder release) is emitted before this one's
		// successor is read, so it lands DelayN positions later in the stream.
		if held, ok := c.rx.held[c.rx.n]; ok {
			delete(c.rx.held, c.rx.n)
			c.rx.pending = append(c.rx.pending, held)
		}
		return n, addr, nil
	}
}

// WriteTo applies the tx pipeline: drop/duplicate/delay. rewriteTo is rx-only
// (it alters an inbound source address, meaningless outbound). A tx-side Reorder
// is REJECTED AT CONSTRUCTION (New panics), so holdRelease never reaches here
// on the tx path; it is not silently ignored. The other four impairments are
// genuinely per-direction.
func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.tx.mu.Lock()
	defer c.tx.mu.Unlock()
	c.tx.n++
	v := combine(c.tx.imps, c.tx.n, c.tx.rng, addr)
	if v.drop {
		return len(p), nil // pretend-sent; the wire never sees it
	}
	if v.delay > 0 {
		time.Sleep(v.delay)
	}
	n, err := c.PacketConn.WriteTo(p, addr)
	if err == nil && v.duplicate {
		_, _ = c.PacketConn.WriteTo(p, addr)
	}
	return n, err
}

// combine folds the ordered impairments into one verdict (drop short-circuits).
func combine(imps []Impairment, n int64, rng *rand.Rand, addr net.Addr) verdict {
	var out verdict
	for _, imp := range imps {
		v := imp.verdict(n, rng, addr)
		if v.drop {
			return verdict{drop: true}
		}
		if v.duplicate {
			out.duplicate = true
		}
		if v.delay > out.delay {
			out.delay = v.delay
		}
		if v.rewriteTo != nil {
			out.rewriteTo = v.rewriteTo
		}
		if v.holdRelease > out.holdRelease {
			out.holdRelease = v.holdRelease
		}
	}
	return out
}
