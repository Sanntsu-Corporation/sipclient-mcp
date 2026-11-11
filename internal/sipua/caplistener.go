package sipua

import (
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Every UA's TCP listener (the UDP UA's, CF-076, and the tcp/tls UAs', CF-189)
// is bounded, so a peer cannot pin unlimited goroutines and buffers on it
// (sipgo's accept loop has no cap and its reader no deadline). At the cap the
// least recently active connection is closed to admit a new one when it has
// been silent for the RFC 3261 18 keep-open floor (inboundTCPEvictIdle), else
// the new one is refused: our own tcp/tls UAs leak one connection per request
// they send (CF-080), so refusing outright would turn that leak into failing
// calls (D6C-8).
const (
	// maxInboundTCPConns equals the default limits.max_concurrent_calls_total
	// (internal/policy/policy.go): a connection per concurrent call is the most
	// a healthy deployment needs.
	maxInboundTCPConns = 50

	// inboundTCPIdleTimeout is the longest legitimate silence on a connection:
	// the largest session-timer interval a peer may negotiate with us
	// (maxAcceptableSessionIntervalS); it also exceeds the 60 s ring timeout, so
	// a pending INVITE's answer is never written to a connection closed for
	// idleness. The deadline is raised above a configured ring timeout longer
	// than that (inboundTCPIdle). Residual (recorded for the owner): a timerless
	// inbound dialog silent for longer than this loses its connection; the peer
	// reconnects to our listener and we dial its Contact for our own requests.
	inboundTCPIdleTimeout = time.Duration(maxAcceptableSessionIntervalS) * time.Second
)

// inboundTCPIdle is the idle read deadline for a UA: inboundTCPIdleTimeout, or
// the configured ring timeout plus a minute when that is longer, so a pending
// INVITE's answer is never written to a connection closed for idleness.
func inboundTCPIdle(ringTimeout time.Duration) time.Duration {
	if d := ringTimeout + time.Minute; d > inboundTCPIdleTimeout {
		return d
	}
	return inboundTCPIdleTimeout
}

// inboundTCPEvictIdle is the silence after which a connection may be closed to
// make room at the cap: the effective ring timeout plus 64*T1, the longest a
// transaction on it can run (RFC 3261 18: keep a connection open at least that
// long). evictIdleOverride (tests) replaces it.
func inboundTCPEvictIdle(ringTimeout time.Duration) time.Duration {
	if evictIdleOverride != 0 {
		return evictIdleOverride
	}
	return effectiveInboundRingTimeout(ringTimeout) + 64*500*time.Millisecond
}

// evictIdleOverride is a TEST-ONLY seam (0 in production); see the C-M5 comment
// in call.go.
var evictIdleOverride time.Duration

// capListener limits the connections an inner listener holds open at once and
// gives each an idle read deadline. A connection over the cap evicts the least
// recently active one silent for evictIdle, else is closed at accept; Accept
// itself never blocks on the cap.
type capListener struct {
	net.Listener
	slots     chan struct{}
	idle      time.Duration
	evictIdle time.Duration

	// now and base time activity as a monotonic offset, so a wall-clock step
	// cannot make every connection look idle. now is replaced by tests.
	now  func() time.Time
	base time.Time

	mu    sync.Mutex
	conns []*capConn // open conns in accept order
}

func newCapListener(ln net.Listener, maxConns int, idle, evictIdle time.Duration) *capListener {
	return &capListener{Listener: ln, slots: make(chan struct{}, maxConns), idle: idle,
		evictIdle: evictIdle, now: time.Now, base: time.Now()}
}

func (l *capListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		cc := &capConn{Conn: c, l: l}
		if l.admit(cc) {
			return cc, nil
		}
		_ = c.Close()
	}
}

// admit gives c a slot, evicting the idlest connection when none is free.
func (l *capListener) admit(c *capConn) bool {
	if l.take(c) {
		return true
	}
	if v := l.idlest(); v != nil {
		_ = v.Close() // releases v's slot before returning (Once)
	}
	return l.take(c)
}

func (l *capListener) take(c *capConn) bool {
	select {
	case l.slots <- struct{}{}:
	default:
		return false
	}
	c.touch()
	l.mu.Lock()
	l.conns = append(l.conns, c)
	l.mu.Unlock()
	return true
}

// idlest returns the open connection with the oldest activity if it has been
// silent for evictIdle; ties go to the earliest accepted.
func (l *capListener) idlest() *capConn {
	l.mu.Lock()
	defer l.mu.Unlock()
	var best *capConn
	for _, c := range l.conns {
		if best == nil || c.last.Load() < best.last.Load() {
			best = c
		}
	}
	if best != nil && l.now().Sub(l.base)-time.Duration(best.last.Load()) >= l.evictIdle {
		return best
	}
	return nil
}

type capConn struct {
	net.Conn
	l    *capListener
	once sync.Once
	last atomic.Int64 // last activity, offset from l.base
}

func (c *capConn) touch() { c.last.Store(int64(c.l.now().Sub(c.l.base))) }

// Read arms the idle deadline before each read.
func (c *capConn) Read(b []byte) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(c.l.idle))
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *capConn) Write(b []byte) (int, error) {
	c.touch()
	return c.Conn.Write(b)
}

// Close releases the connection's slot exactly once.
func (c *capConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.l.mu.Lock()
		if i := slices.Index(c.l.conns, c); i >= 0 {
			c.l.conns = slices.Delete(c.l.conns, i, i+1)
		}
		c.l.mu.Unlock()
		<-c.l.slots
	})
	return err
}
