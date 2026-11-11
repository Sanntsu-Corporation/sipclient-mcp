package sipua_test

import (
	"net"
	"strconv"
	"strings"
	"sync"
)

// countingConn is a net.PacketConn decorator that counts SIP datagrams by
// request method and response code. It is installed through Task 13's
// Config.WrapConn seam — the same seam the production ObservingConn uses
// (Task 16) — and exists here only to assert the exact message sequence R1
// names without depending on the trace package.
type countingConn struct {
	net.PacketConn
	mu   sync.Mutex
	sent []string
	recv []string
}

func (c *countingConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.sent = append(c.sent, firstLine(b))
	c.mu.Unlock()
	return c.PacketConn.WriteTo(b, addr)
}

func (c *countingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil && n > 0 {
		c.mu.Lock()
		c.recv = append(c.recv, firstLine(b[:n]))
		c.mu.Unlock()
	}
	return n, addr, err
}

func firstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexByte(s, '\r'); i >= 0 {
		return s[:i]
	}
	return s
}

func (c *countingConn) Sent(method string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, l := range c.sent {
		if strings.HasPrefix(l, method+" ") {
			n++
		}
	}
	return n
}

func (c *countingConn) Received(code int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	prefix := "SIP/2.0 " + strconv.Itoa(code) + " "
	n := 0
	for _, l := range c.recv {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}
