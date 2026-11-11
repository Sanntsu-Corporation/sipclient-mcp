package sip

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// startFakeDNS serves a tiny stdlib-only authoritative DNS over UDP on
// 127.0.0.1:0 and returns a Go-resolver pointed at it plus a function that
// returns the "name/TYPE" of every query in arrival order.
//
// zone maps "name/TYPE" (TYPE one of A, AAAA, SRV) to answers: an IP for A and
// AAAA, "priority weight port target" for SRV. A name with no record of any
// type draws NXDOMAIN; a known name without the asked type draws NOERROR with
// no answer.
func startFakeDNS(t *testing.T, zone map[string][]string) (*net.Resolver, func() []string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	known := map[string]bool{}
	for k := range zone {
		known[k[:strings.LastIndex(k, "/")]] = true
	}
	var mu sync.Mutex
	var log []string

	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			q := append([]byte(nil), buf[:n]...)
			// question: labels, then qtype and qclass
			i := 12
			var labels []string
			for i < n && q[i] != 0 {
				l := int(q[i])
				labels = append(labels, string(q[i+1:i+1+l]))
				i += 1 + l
			}
			i++ // root
			qtype := binary.BigEndian.Uint16(q[i : i+2])
			qend := i + 4
			name := strings.ToLower(strings.Join(labels, "."))
			tname := map[uint16]string{1: "A", 28: "AAAA", 33: "SRV"}[qtype]
			mu.Lock()
			log = append(log, name+"/"+tname)
			mu.Unlock()

			var answers []byte
			count := 0
			for _, v := range zone[name+"/"+tname] {
				var rdata []byte
				switch qtype {
				case 1:
					rdata = net.ParseIP(v).To4()
				case 28:
					rdata = net.ParseIP(v).To16()
				case 33:
					f := strings.Fields(v)
					pr, _ := strconv.Atoi(f[0])
					wt, _ := strconv.Atoi(f[1])
					po, _ := strconv.Atoi(f[2])
					rdata = []byte{byte(pr >> 8), byte(pr), byte(wt >> 8), byte(wt), byte(po >> 8), byte(po)}
					for _, lab := range strings.Split(strings.TrimSuffix(f[3], "."), ".") {
						rdata = append(rdata, byte(len(lab)))
						rdata = append(rdata, lab...)
					}
					rdata = append(rdata, 0)
				}
				rr := []byte{0xC0, 0x0C, byte(qtype >> 8), byte(qtype), 0, 1, 0, 0, 0, 30, byte(len(rdata) >> 8), byte(len(rdata))}
				answers = append(answers, rr...)
				answers = append(answers, rdata...)
				count++
			}
			rcode := byte(0)
			if count == 0 && !known[name] {
				rcode = 3
			}
			resp := append([]byte(nil), q[:2]...)
			resp = append(resp, 0x81, 0x80|rcode, 0, 1, byte(count>>8), byte(count), 0, 0, 0, 0)
			resp = append(resp, q[12:qend]...)
			resp = append(resp, answers...)
			_, _ = pc.WriteTo(resp, from)
		}
	}()

	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", pc.LocalAddr().String())
	}}
	return r, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), log...)
	}
}

func dnsTestLayer(t *testing.T, r *net.Resolver) *TransportLayer {
	t.Helper()
	l := NewTransportLayer(r, NewParser(), nil, false, nil)
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func indexOf(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

// udpClientRequest returns a request to sip:bob@host[:port] whose Via names a
// served UDP listener, so ClientRequestConnection returns that listener after
// resolving the destination.
func udpClientRequest(t *testing.T, l *TransportLayer, host string, port int) *Request {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	go func() { _ = l.ServeUDP(pc) }()
	la := pc.LocalAddr().(*net.UDPAddr)
	require.Eventually(t, func() bool {
		c, _ := l.GetConnection("udp", la.String())
		return c != nil
	}, 2*time.Second, 5*time.Millisecond)
	req := viaReuseRequest("udp", &net.TCPAddr{IP: la.IP, Port: la.Port}, &net.TCPAddr{IP: la.IP, Port: 1})
	req.Recipient = Uri{Host: host, Port: port}
	return req
}

func TestRFC3261_NEWA11_SRVBeforeAForAHostWithoutAPort(t *testing.T) {
	r, queries := startFakeDNS(t, map[string][]string{
		"_sip._udp.example.test/SRV": {"10 10 15601 target.example.test"},
		"target.example.test/A":      {"127.0.0.7"},
		"example.test/A":             {"127.0.0.8"},
	})
	l := dnsTestLayer(t, r)
	req := udpClientRequest(t, l, "example.test", 0)
	_, err := l.ClientRequestConnection(context.Background(), req)
	require.NoError(t, err)
	q := queries()
	require.NotEmpty(t, q)
	require.Equal(t, "_sip._udp.example.test/SRV", q[0])
	require.Equal(t, "127.0.0.7:15601", req.Destination())
	require.Equal(t, -1, indexOf(q, "example.test/A"))
	require.Equal(t, -1, indexOf(q, "example.test/AAAA"))
}

func TestResolveUsesOnlyAWhenTheURIHasAPort(t *testing.T) {
	r, queries := startFakeDNS(t, map[string][]string{
		"_sip._udp.example.test/SRV": {"10 10 15601 target.example.test"},
		"target.example.test/A":      {"127.0.0.7"},
		"example.test/A":             {"127.0.0.8"},
	})
	l := dnsTestLayer(t, r)
	req := udpClientRequest(t, l, "example.test", 5070)
	_, err := l.ClientRequestConnection(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.8:5070", req.Destination())
	for _, q := range queries() {
		require.False(t, strings.HasSuffix(q, "/SRV"), "no SRV query for a URI with a port: %v", queries())
	}
}

func TestResolveFallsBackToAWhenNoSRVRecordExists(t *testing.T) {
	r, queries := startFakeDNS(t, map[string][]string{
		"nosrv.test/A": {"127.0.0.9"},
	})
	l := dnsTestLayer(t, r)
	req := udpClientRequest(t, l, "nosrv.test", 0)
	_, err := l.ClientRequestConnection(context.Background(), req)
	require.NoError(t, err)
	q := queries()
	require.Equal(t, "_sip._udp.nosrv.test/SRV", q[0])
	require.GreaterOrEqual(t, indexOf(q, "nosrv.test/A"), 1)
	require.Equal(t, "127.0.0.9:5060", req.Destination())
}

func TestResolveTLSUsesTheSipsService(t *testing.T) {
	r, queries := startFakeDNS(t, map[string][]string{
		"_sips._tcp.example.test/SRV": {"10 10 15602 target.example.test"},
		"target.example.test/A":       {"127.0.0.7"},
	})
	l := dnsTestLayer(t, r)
	var a Addr
	require.NoError(t, l.resolveAddr(context.Background(), "tls", "example.test", &a, false))
	require.Equal(t, "_sips._tcp.example.test/SRV", queries()[0])
	require.Equal(t, "127.0.0.7", a.IP.String())
	require.Equal(t, 15602, a.Port)
}

func TestResolveSRVTargetPrefersIPv4(t *testing.T) {
	r, _ := startFakeDNS(t, map[string][]string{
		"_sip._udp.example.test/SRV": {"10 10 15603 target.example.test"},
		"target.example.test/AAAA":   {"::1"},
		"target.example.test/A":      {"127.0.0.7"},
	})
	l := dnsTestLayer(t, r)
	var a Addr
	require.NoError(t, l.resolveAddr(context.Background(), "udp", "example.test", &a, false))
	require.Equal(t, "127.0.0.7", a.IP.String())
	require.Equal(t, 15603, a.Port)
}

func TestResolveFallsBackToAWhenTheSRVTargetHasNoAddress(t *testing.T) {
	r, _ := startFakeDNS(t, map[string][]string{
		"_sip._udp.example.test/SRV": {"10 10 15604 ghost.example.test"},
		"example.test/A":             {"127.0.0.8"},
	})
	l := dnsTestLayer(t, r)
	var a Addr
	require.NoError(t, l.resolveAddr(context.Background(), "udp", "example.test", &a, false))
	require.Equal(t, "127.0.0.8", a.IP.String())
	require.Equal(t, 0, a.Port, "the caller's default port stays")
}

func TestNewTransportLayerPrefersSRV(t *testing.T) {
	l := NewTransportLayer(net.DefaultResolver, NewParser(), nil, false, nil)
	t.Cleanup(func() { _ = l.Close() })
	require.True(t, l.DNSPreferSRV)
}

func TestResolveWithoutPreferSRVKeepsUpstreamOrder(t *testing.T) {
	r, queries := startFakeDNS(t, map[string][]string{
		"_sip._udp.example.test/SRV": {"10 10 15601 target.example.test"},
		"target.example.test/A":      {"127.0.0.7"},
		"example.test/A":             {"127.0.0.8"},
	})
	l := dnsTestLayer(t, r)
	l.DNSPreferSRV = false
	var a Addr
	require.NoError(t, l.resolveAddr(context.Background(), "udp", "example.test", &a, false))
	require.Equal(t, "127.0.0.8", a.IP.String())
	for _, q := range queries() {
		require.False(t, strings.HasSuffix(q, "/SRV"), "A first, no SRV needed: %v", queries())
	}
}

func TestUriPortGiven(t *testing.T) {
	route := func(host string, port int) *RouteHeader {
		return &RouteHeader{Address: Uri{Host: host, Port: port}}
	}
	cases := []struct {
		name string
		mk   func() *Request
		want bool
	}{
		{"recipient without port", func() *Request { return NewRequest(OPTIONS, Uri{Host: "h"}) }, false},
		{"recipient with port", func() *Request { return NewRequest(OPTIONS, Uri{Host: "h", Port: 5070}) }, true},
		{"route with port", func() *Request {
			r := NewRequest(OPTIONS, Uri{Host: "h"})
			r.AppendHeader(route("p", 5080))
			return r
		}, true},
		{"route without port wins over recipient port", func() *Request {
			r := NewRequest(OPTIONS, Uri{Host: "h", Port: 5070})
			r.AppendHeader(route("p", 0))
			return r
		}, false},
		{"explicit destination with port", func() *Request {
			r := NewRequest(OPTIONS, Uri{Host: "h"})
			r.SetDestination("h:5070")
			return r
		}, true},
		{"explicit destination port 0", func() *Request {
			r := NewRequest(OPTIONS, Uri{Host: "h"})
			r.SetDestination("h:0")
			return r
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, uriPortGiven(tc.mk()))
		})
	}
}
