package sipua_test

// Lane D (rfc-sweep-d) pins for RFC 3550 deviations seen on an answered
// outbound call (6a D11), built on laneDOutbound (rfc3264_pin_test.go). Each
// pin passes today and must be inverted when its finding is fixed. No t.Parallel.

import (
	"net"
	"testing"
	"time"

	"github.com/pion/rtp"
)

// TestRFC3550_NEWD28_OurRTPStaysAtTheSignalledAddress is the fixed NEW-D-28 (L20,
// D-RTCP-05, RFC 3550 11: "A participant MUST NOT assume that the source port of
// the incoming RTP or RTCP packet can be used as the destination port for
// outgoing RTP or RTCP packets." rfc3550.txt:3794-3796; RFC 4961's definition of
// symmetric RTP is by our own ports, rfc4961.txt:125-126). It was
// the NEW-D-28 pin (renamed by this fix): our RTP followed the first
// source received. Locus: internal/sipua/medialoop.go (CF-159, D-159).
// Design: R10 in the design spec; the
// inverted unit tests are TestRTPThroughRelayIsReceivedWithoutLatching
// (renamed TestRTPFromAnUnsignalledRelayIsDropped by CF-179,
// internal/sipua/medialoop_symmetric_test.go) and
// TestRunRXDropsAnUnsignalledSource. Control: our RTP reaches
// the answer's port before the second source speaks and after it.
func TestRFC3550_NEWD28_OurRTPStaysAtTheSignalledAddress(t *testing.T) {
	c := laneDOutbound(t, []string{"PCMU"}, laneDBaseAnswer)
	other, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("second source: %v", err)
	}
	t.Cleanup(func() { _ = other.Close() })
	for i := 0; i < 25; i++ {
		c.sendFrom(t, other, 0, false, uint16(1+i), uint32(160*i), 0x0a0b0c0d, make([]byte, 160))
		time.Sleep(2 * time.Millisecond)
	}
	got := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, rerr := other.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			if (&rtp.Packet{}).Unmarshal(buf[:n]) == nil {
				got <- struct{}{}
				return
			}
		}
	}()
	select {
	case <-got:
		t.Fatal("our RTP followed the second source (RFC 3550 11, CF-159)")
	case <-time.After(2 * time.Second):
	}
	for len(c.pkts) > 0 { // drain what arrived before and during the second source
		<-c.pkts
	}
	select {
	case <-c.pkts: // our RTP kept going to the signalled address
	case <-time.After(2 * time.Second):
		t.Fatal("our RTP no longer reaches the signalled address")
	}
}

// TestRFC3550Pin_NEWD29_NothingListensAtRTCPPort pins NEW-D-29 (L21, D-RTCP-01
// and D-ATT-06, RFC 3550 6: "Functions 1-3 SHOULD be used in all environments,
// but particularly in the IP multicast environment." rfc3550.txt:1111-1112;
// RFC 4566 6: "Note that an RTP-based system SHOULD still send RTCP, even if
// started inactive." rfc4566.txt:1519-1520). Evidence: evidence/u-rx/rtp.txt
// (an RTCP receiver report sent to our media port plus 1 draws an ICMP port
// unreachable; the UA sends no RTCP in any corpus capture). Locus:
// internal/sipua/mediaport.go:bindMediaPort (binds one even port, nothing at
// port+1). Control: binding the media port itself fails with EADDRINUSE.
//
// PIN OF A DEVIATION: invert this assertion when NEW-D-29 is fixed.
func TestRFC3550Pin_NEWD29_NothingListensAtRTCPPort(t *testing.T) {
	c := laneDOutbound(t, []string{"PCMU"}, laneDBaseAnswer)
	if l, err := net.ListenUDP("udp", c.uaMedia); err == nil {
		_ = l.Close()
		t.Fatalf("control failed: the media port %v was free to bind", c.uaMedia)
	}
	rtcp := &net.UDPAddr{IP: c.uaMedia.IP, Port: c.uaMedia.Port + 1}
	l, err := net.ListenUDP("udp", rtcp)
	if err != nil {
		t.Fatalf("RTCP port %v is bound (%v): NEW-D-29 is fixed, invert this pin", rtcp, err)
	}
	_ = l.Close()
}

// TestRFC3550_CF179_RTPFromAnUnsignalledSourceIsDropped (CF-179, owner ruling:
// RTP is accepted only from the IP:port in the peer's SDP): ten packets from a
// second socket are dropped and counted rogue; then five from the answer's own
// socket are received.
func TestRFC3550_CF179_RTPFromAnUnsignalledSourceIsDropped(t *testing.T) {
	c := laneDOutbound(t, []string{"PCMU"}, laneDBaseAnswer)
	other, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("second source: %v", err)
	}
	t.Cleanup(func() { _ = other.Close() })
	for i := 0; i < 10; i++ {
		c.sendFrom(t, other, 0, false, uint16(1+i), uint32(160*i), 0x0a0b0c0d, make([]byte, 160))
	}
	waitForCond(t, func() bool { q, _ := c.ua.QualityView(c.dlg); return q.RogueSourcePackets == 10 })
	if q, _ := c.ua.QualityView(c.dlg); q.PacketsReceived != 0 {
		t.Fatalf("packets_received %d after unsignalled packets, want 0", q.PacketsReceived)
	}
	for i := 0; i < 5; i++ {
		c.send(t, 0, false, uint16(100+i), uint32(160*(100+i)), make([]byte, 160))
	}
	waitForCond(t, func() bool { q, _ := c.ua.QualityView(c.dlg); return q.PacketsReceived == 5 })
}
