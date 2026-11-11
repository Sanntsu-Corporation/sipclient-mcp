package sip

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// udpSizeFixture returns a listener-type UDPConnection (the Conn == nil
// branch) and a loopback receiver the message is addressed to.
func udpSizeFixture(t *testing.T) (*UDPConnection, net.PacketConn) {
	t.Helper()
	rx, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = rx.Close() })
	tx, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Close() })
	return &UDPConnection{PacketConn: tx, PacketAddr: tx.LocalAddr().String(), Listener: true}, rx
}

// sizedResponse returns a response whose serialisation is exactly size bytes.
func sizedResponse(t *testing.T, dst string, size int) *Response {
	t.Helper()
	body := 0
	for i := 0; i < 8; i++ {
		res := NewResponse(StatusOK, "OK")
		res.SetBody([]byte(strings.Repeat("a", body)))
		got := len(res.String())
		if got == size {
			res.SetDestination(dst)
			return res
		}
		body += size - got
		require.GreaterOrEqual(t, body, 0)
	}
	t.Fatalf("cannot size a response to %d bytes", size)
	return nil
}

func udpSizedRequest(t *testing.T, dst string, size int) *Request {
	t.Helper()
	body := 0
	for i := 0; i < 8; i++ {
		req := NewRequest(OPTIONS, Uri{Host: "127.0.0.1", Port: 5060})
		req.SetBody([]byte(strings.Repeat("a", body)))
		got := len(req.String())
		if got == size {
			req.SetDestination(dst)
			return req
		}
		body += size - got
		require.GreaterOrEqual(t, body, 0)
	}
	t.Fatalf("cannot size a request to %d bytes", size)
	return nil
}

func expectDatagram(t *testing.T, rx net.PacketConn, want int) {
	t.Helper()
	_ = rx.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 70000)
	n, _, err := rx.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, want, n)
}

func expectNoDatagram(t *testing.T, rx net.PacketConn) {
	t.Helper()
	_ = rx.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 70000)
	_, _, err := rx.ReadFrom(buf)
	require.Error(t, err, "no datagram expected")
}

func TestUDPWriteMsgSendsAResponseOver1300Bytes(t *testing.T) {
	c, rx := udpSizeFixture(t)
	res := sizedResponse(t, rx.LocalAddr().String(), 1400)
	require.NoError(t, c.WriteMsg(res))
	expectDatagram(t, rx, 1400)
}

func TestUDPWriteMsgResponseLimitIsTheDatagramMaximum(t *testing.T) {
	c, rx := udpSizeFixture(t)
	require.NoError(t, c.WriteMsg(sizedResponse(t, rx.LocalAddr().String(), 65507)))
	expectDatagram(t, rx, 65507)

	err := c.WriteMsg(sizedResponse(t, rx.LocalAddr().String(), 65508))
	require.ErrorIs(t, err, ErrUDPMTUCongestion)
	expectNoDatagram(t, rx)
}

func TestUDPWriteMsgStillRefusesARequestOver1300Bytes(t *testing.T) {
	c, rx := udpSizeFixture(t)
	require.NoError(t, c.WriteMsg(udpSizedRequest(t, rx.LocalAddr().String(), 1300)))
	expectDatagram(t, rx, 1300)

	err := c.WriteMsg(udpSizedRequest(t, rx.LocalAddr().String(), 1301))
	require.ErrorIs(t, err, ErrUDPMTUCongestion)
	expectNoDatagram(t, rx)
}
