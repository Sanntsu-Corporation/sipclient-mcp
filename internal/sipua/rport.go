package sipua

import (
	"net"
	"net/netip"
	"sync"

	"github.com/emiago/sipgo/sip"
)

type publicAddr struct {
	mu    sync.Mutex
	addr  netip.AddrPort
	known bool
}

func (p *publicAddr) Set(ap netip.AddrPort) { p.mu.Lock(); p.addr, p.known = ap, true; p.mu.Unlock() }
func (p *publicAddr) Get() (netip.AddrPort, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addr, p.known
}

// learnPublicAddr reads the top Via's received + rport params off a response
// (RFC 3261 §18.2.1 / RFC 3581). Both must be present and parse as an IP and a
// port to learn a public address.
func learnPublicAddr(resp *sip.Response) (netip.AddrPort, bool) {
	via := resp.Via() // top Via — verified sipgo v0.24.1 returns the first/top Via
	if via == nil || via.Params == nil {
		return netip.AddrPort{}, false
	}
	recv, ok1 := via.Params.Get("received")
	rport, ok2 := via.Params.Get("rport")
	if !ok1 || !ok2 || recv == "" || rport == "" {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(net.JoinHostPort(recv, rport))
	if err != nil {
		return netip.AddrPort{}, false
	}
	// A learned address is emitted verbatim in Answer's 200 OK Contact, so it
	// must clear the same D9d address-sanity rejections the bound-address path
	// (localaddr.go) applies before it can be trusted as a Via/Contact host. A
	// hostile or misconfigured registrar could otherwise drive an unsafe
	// received/rport (wildcard, link-local, multicast, zoned or port 0) into
	// the Contact. usableRouteResult covers the IP-class checks; zone and port
	// are not IP properties, so they are checked here.
	if !usableRouteResult(net.IP(ap.Addr().AsSlice())) || ap.Addr().Zone() != "" || ap.Port() == 0 {
		return netip.AddrPort{}, false
	}
	return ap, true
}
