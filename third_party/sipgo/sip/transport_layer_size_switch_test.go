package sip

import (
	"context"
	"net"
	"strings"
	"testing"
)

// CF-106 (RFC 3261 18.1.1): a request larger than 1300 bytes (path MTU
// unknown) MUST go over a congestion-controlled transport, and the top Via
// MUST then name it. ClientRequestConnection switches an oversize UDP
// request to TCP.

// sizedRequest builds an OPTIONS to dst over transport whose serialised
// length is exactly size bytes.
func sizedRequest(t *testing.T, transport string, dst *net.TCPAddr, size int) *Request {
	t.Helper()
	req := viaReuseRequest(transport, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 45060}, dst)
	pad := NewHeader("X-Pad", "")
	req.AppendHeader(pad)
	pad = NewHeader("X-Pad", strings.Repeat("a", size-len(req.String())))
	req.headers.ReplaceHeader(pad)
	if got := len(req.String()); got != size {
		t.Fatalf("sizedRequest: built %d bytes, want %d", got, size)
	}
	return req
}

func TestClientRequestConnectionSwitchesAnOversizeUDPRequestToTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	dst := ln.Addr().(*net.TCPAddr)

	newTP := func(t *testing.T) *TransportLayer {
		tp := NewTransportLayer(net.DefaultResolver, NewParser(), nil, true, nil)
		t.Cleanup(func() { tp.Close() })
		return tp
	}

	t.Run("1301 bytes goes over TCP with a TCP top Via", func(t *testing.T) {
		req := sizedRequest(t, "udp", dst, 1301)
		branch, _ := req.Via().Params.Get("branch")
		c, err := newTP(t).ClientRequestConnection(context.Background(), req)
		if err != nil {
			t.Fatalf("ClientRequestConnection: %v", err)
		}
		defer c.TryClose()
		if _, ok := c.(*TCPConnection); !ok {
			t.Fatalf("got %T, want *TCPConnection", c)
		}
		if got := req.Via().Transport; got != "TCP" {
			t.Errorf("top Via transport = %q, want TCP", got)
		}
		if got := req.Transport(); got != "TCP" {
			t.Errorf("req.Transport() = %q, want TCP", got)
		}
		if got, _ := req.Via().Params.Get("branch"); got != branch {
			t.Errorf("branch changed from %q to %q", branch, got)
		}
	})

	t.Run("exactly 1300 bytes stays UDP", func(t *testing.T) {
		req := sizedRequest(t, "udp", dst, 1300)
		c, err := newTP(t).ClientRequestConnection(context.Background(), req)
		if err != nil {
			t.Fatalf("ClientRequestConnection: %v", err)
		}
		defer c.TryClose()
		if _, ok := c.(*UDPConnection); !ok {
			t.Fatalf("got %T, want *UDPConnection", c)
		}
		if got := req.Via().Transport; got != "UDP" {
			t.Errorf("top Via transport = %q, want UDP", got)
		}
	})

	t.Run("an oversize TCP request is untouched", func(t *testing.T) {
		req := sizedRequest(t, "tcp", dst, 1400)
		c, err := newTP(t).ClientRequestConnection(context.Background(), req)
		if err != nil {
			t.Fatalf("ClientRequestConnection: %v", err)
		}
		defer c.TryClose()
		if _, ok := c.(*TCPConnection); !ok {
			t.Fatalf("got %T, want *TCPConnection", c)
		}
		if got := req.Via().Transport; got != "TCP" {
			t.Errorf("top Via transport = %q, want TCP", got)
		}
	})
}
