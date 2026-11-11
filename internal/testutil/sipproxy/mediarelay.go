package sipproxy

import (
	"net"
	"sync"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/netfault"
)

// MediaRelay emulates a symmetric NAT for RTP: it holds its own UDP socket and
// forwards every Inject'ed packet to the UA from THAT socket's address, so the
// UA sees a source distinct from any SDP-signalled address; the UA drops it
// unless the relay's address is the one signalled (CF-179, R10, §3.7). It is a
// test helper only — the Asterisk lab rig has no NAT relay.
//
// conn is net.PacketConn, not the concrete *net.UDPConn, ONLY so
// NewLossyMediaRelay below can wrap it in a netfault.Conn (which implements
// net.PacketConn's generic ReadFrom/WriteTo but not net.UDPConn's typed
// ReadFromUDP/WriteToUDP); Inject therefore calls the generic WriteTo.
type MediaRelay struct {
	conn net.PacketConn
	ua   *net.UDPAddr
	t    *testing.T

	mu     sync.Mutex
	closed bool
}

// NewMediaRelay binds a relay socket on loopback and targets ua.
func NewMediaRelay(t *testing.T, ua *net.UDPAddr) *MediaRelay {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("media relay listen: %v", err)
	}
	return &MediaRelay{conn: c, ua: ua, t: t}
}

// NewLossyMediaRelay is NewMediaRelay wrapped in netfault's TX-direction Drop
// impairment (§14.6), so every Inject'ed packet has an independent lossRate
// chance of never reaching ua — the R4 acceptance's "synthetic uniform loss
// injected into the RX path" (master spec R4), reusing the existing test-only
// fault injector rather than re-implementing loss dropping here (Rule 16).
func NewLossyMediaRelay(t *testing.T, ua *net.UDPAddr, lossRate float64) *MediaRelay {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("lossy media relay listen: %v", err)
	}
	wrapped := netfault.New(c, netfault.Config{
		TX:     []netfault.Impairment{netfault.Drop{Rate: lossRate}},
		TXSeed: 1,
	})
	return &MediaRelay{conn: wrapped, ua: ua, t: t}
}

// NewBurstyMediaRelay is NewMediaRelay wrapped in netfault's TX-direction
// BurstDrop impairment: it drops runLen consecutive packets every everyN
// packets, producing the DETERMINISTIC consecutive-loss runs §10.10's
// burst_gaps requires (a single isolated loss is never a burst — runLen must
// be >= 2 for the caller to observe any burst_gaps entries at all).
func NewBurstyMediaRelay(t *testing.T, ua *net.UDPAddr, everyN, runLen int64) *MediaRelay {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("bursty media relay listen: %v", err)
	}
	wrapped := netfault.New(c, netfault.Config{
		TX: []netfault.Impairment{netfault.BurstDrop{EveryN: everyN, RunLen: runLen}},
	})
	return &MediaRelay{conn: wrapped, ua: ua, t: t}
}

// Addr is the relay's own source address — the source address the UA sees.
func (r *MediaRelay) Addr() *net.UDPAddr { return r.conn.LocalAddr().(*net.UDPAddr) }

// Inject forwards one RTP packet to the UA from the relay's socket. Uses the
// generic net.PacketConn.WriteTo (not net.UDPConn.WriteToUDP) so a
// netfault-wrapped conn (NewLossyMediaRelay) works identically to a plain one.
func (r *MediaRelay) Inject(rtp []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if _, err := r.conn.WriteTo(rtp, r.ua); err != nil {
		r.t.Logf("media relay inject: %v", err)
	}
}

// Close stops the relay; a second call is a no-op.
func (r *MediaRelay) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		_ = r.conn.Close()
	}
}
