package sipua_test

// CF-190: a UDP UA's TCP traffic (its TCP listener, CF-076, and the TCP dials
// of CF-106 oversize requests) reaches the capture tap. No t.Parallel here.

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

func newTappedUDPUA(t *testing.T, tap session.Tap) *sipua.UA {
	t.Helper()
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		WrapListener: func(ln net.Listener) net.Listener {
			return sipua.ObservingListener(ln, tap, session.TransportTCP, nil, "ua-u")
		},
		WrapDialConn: func(c net.Conn) net.Conn {
			return sipua.ObservingStreamConn(c, tap, session.TransportTCP, nil, "ua-u")
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua
}

func awaitRecords(t *testing.T, tap *fakes.Tap, ok func([]session.SIPRecord) bool) []session.SIPRecord {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		recs := tap.SIPRecordsSnapshot()
		if ok(recs) {
			return recs
		}
		if time.Now().After(deadline) {
			t.Fatalf("the tap never held the expected records; got %d: %+v", len(recs), recs)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUDPUATCPInboundIsObserved(t *testing.T) {
	tap := fakes.NewTap()
	ua := newTappedUDPUA(t, tap)
	c, err := net.DialTimeout("tcp", ua.BoundAddr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte(tcpOptions(c.LocalAddr().String(), ua.BoundAddr().String(), "z9hG4bKcf190a")))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readStreamMsg(bufio.NewReader(c)); err != nil {
		t.Fatalf("no response on the TCP connection: %v", err)
	}
	recs := awaitRecords(t, tap, func(rs []session.SIPRecord) bool {
		var in, out bool
		for _, r := range rs {
			in = in || (r.Direction == session.Inbound && r.Method == "OPTIONS")
			out = out || (r.Direction == session.Outbound && r.StatusCode == 200)
		}
		return in && out
	})
	for _, r := range recs {
		if r.Transport != session.TransportTCP || r.UAHandle != "ua-u" {
			t.Errorf("record transport/handle = %q/%q, want tcp/ua-u", r.Transport, r.UAHandle)
		}
	}
}

func TestUDPUAOversizeDialIsObservedOverTCP(t *testing.T) {
	tap := fakes.NewTap()
	ua := newTappedUDPUA(t, tap)
	_ = collect(t, ua)
	addr, _ := tcpInviteSink(t)
	if _, err := ua.Dial(context.Background(), session.DialRequest{
		ToURI: "sip:bob@" + addr, Headers: oversizeHeaders,
	}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	recs := awaitRecords(t, tap, func(rs []session.SIPRecord) bool {
		for _, r := range rs {
			if r.Direction == session.Outbound && r.Method == "INVITE" && strings.Contains(string(r.Raw), "X-Rfcfix1-Pad") {
				return true
			}
		}
		return false
	})
	for _, r := range recs {
		if r.Method == "INVITE" && r.Transport != session.TransportTCP {
			t.Errorf("INVITE record transport = %q, want tcp", r.Transport)
		}
	}
}
