package sipua

import (
	"context"
	"fmt"
	"net"
)

// bindMediaPort binds a UDP socket on ip to an EVEN port drawn from the UA's
// configured media.port_range (§6.5.3). It holds the socket so the SDP c=/m=
// can never advertise a port the server does not yet own; W4 attaches RTP to
// this same conn. No RTP is sent this wave (M3). The conn is closed by
// teardownDialog / Hangup when the dialog ends. SO_BROADCAST is cleared (Go sets
// it on every datagram socket) so the kernel refuses a send to any broadcast
// address a peer's c= might name (CF-201).
func (u *UA) bindMediaPort(ip net.IP) (*net.UDPConn, int, error) {
	lo, hi := u.cfg.MediaPortRange[0], u.cfg.MediaPortRange[1]
	if lo == 0 && hi == 0 {
		lo, hi = 16384, 32767
	}
	if lo%2 != 0 {
		lo++
	}
	lc := net.ListenConfig{Control: clearBroadcast}
	for port := lo; port <= hi; port += 2 {
		pc, err := lc.ListenPacket(context.Background(), "udp", (&net.UDPAddr{IP: ip, Port: port}).String())
		if err == nil {
			return pc.(*net.UDPConn), port, nil
		}
	}
	return nil, 0, fmt.Errorf("no free even media port in range %d-%d on %s", lo, hi, ip)
}
