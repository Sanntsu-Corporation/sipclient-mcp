//go:build unix

package sipua

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestMediaSocketCannotBroadcast(t *testing.T) {
	u := &UA{}
	u.cfg.MediaPortRange = [2]int{21100, 21200}
	c, _, err := u.bindMediaPort(net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4bcast, Port: 9}); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("broadcast write err=%v, want EACCES", err)
	}
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if _, err := c.WriteTo([]byte("x"), l.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = l.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := l.ReadFrom(make([]byte, 8)); err != nil {
		t.Fatalf("unicast datagram not received: %v", err)
	}
}
