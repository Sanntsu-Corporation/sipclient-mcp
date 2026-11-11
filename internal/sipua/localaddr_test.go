package sipua

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// fixedAddrs installs a deterministic interface-address set for the duration of
// the test. The seam exists because the rule-4 "no usable address" case is
// unreachable on any host that has one, and §15's P1 row requires that case to
// be asserted.
func fixedAddrs(t *testing.T, cidrs ...string) {
	t.Helper()
	prev := interfaceAddrs
	t.Cleanup(func() { interfaceAddrs = prev })
	interfaceAddrs = func() ([]net.Addr, error) {
		out := make([]net.Addr, 0, len(cidrs))
		for _, c := range cidrs {
			ip, ipnet, err := net.ParseCIDR(c)
			if err != nil {
				t.Fatalf("bad fixture CIDR %q: %v", c, err)
			}
			out = append(out, &net.IPNet{IP: ip, Mask: ipnet.Mask})
		}
		return out, nil
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(new(bytes.Buffer), nil))
}

// fakeConn is a minimal net.Conn double that reports a caller-chosen local
// address. routeLookup only calls LocalAddr and Close; the embedded nil
// net.Conn satisfies the rest of the interface without implementing it,
// since those methods are never invoked on this path.
type fakeConn struct {
	net.Conn
	local net.Addr
}

func (f *fakeConn) LocalAddr() net.Addr { return f.local }
func (f *fakeConn) Close() error        { return nil }

// fakeDial installs a fake dialUDP for the duration of the test, returning
// local as the kernel-selected local address. The seam exists because rule
// 3's zone/usability rejection in routeLookup can only be driven by a real
// kernel route lookup; no fixture can force net.Dial to return a zoned,
// link-local, multicast or unspecified result, so dialUDP substitutes for
// net.Dial exactly as interfaceAddrs substitutes for net.InterfaceAddrs.
func fakeDial(t *testing.T, local net.Addr) {
	t.Helper()
	prev := dialUDP
	t.Cleanup(func() { dialUDP = prev })
	dialUDP = func(_, _ string) (net.Conn, error) {
		return &fakeConn{local: local}, nil
	}
}

func TestResolveLocalIPRule4Fallback(t *testing.T) {
	tests := []struct {
		name    string
		addrs   []string
		want    string
		wantErr bool
	}{
		{
			name:  "skips loopback, takes first routable unicast",
			addrs: []string{"127.0.0.1/8", "192.168.8.244/24", "10.0.0.5/8"},
			want:  "192.168.8.244",
		},
		{
			name:  "skips IPv6 link-local so no zone can ever reach a Via",
			addrs: []string{"fe80::1/64", "2001:db8::5/64"},
			want:  "2001:db8::5",
		},
		{
			name:  "skips IPv4 link-local (169.254/16)",
			addrs: []string{"169.254.1.9/16", "192.168.8.244/24"},
			want:  "192.168.8.244",
		},
		{
			name:    "loopback and link-local only is unresolvable",
			addrs:   []string{"127.0.0.1/8", "fe80::1/64", "169.254.1.9/16"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixedAddrs(t, tt.addrs...)
			got, err := ResolveLocalIP("", discardLogger())
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveLocalIP: %v", err)
			}
			if got.String() != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestResolveLocalIPRule4LogsWarnNamingTheChosenAddress(t *testing.T) {
	fixedAddrs(t, "127.0.0.1/8", "192.168.8.244/24")

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	got, err := ResolveLocalIP("", logger)
	if err != nil {
		t.Fatalf("ResolveLocalIP: %v", err)
	}

	var rec struct {
		Level   string `json:"level"`
		LocalIP string `json:"local_ip"`
		Rule    string `json:"rule"`
	}
	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("rule 4 emitted no log line")
	}
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("log line is not JSON: %q: %v", line, err)
	}
	if rec.Level != "WARN" {
		t.Fatalf("level = %q, want WARN", rec.Level)
	}
	if rec.Rule != "6.5.3-rule-4" {
		t.Fatalf("rule = %q, want 6.5.3-rule-4", rec.Rule)
	}
	if rec.LocalIP != got.String() {
		t.Fatalf("WARN names %q but resolution returned %q", rec.LocalIP, got)
	}
}

// TestRouteLookupRejectsUnusableKernelResult pins rule 3's zone/usability
// guard (routeLookup): a kernel-selected local address that could not
// legally reach a Via must fall through to rule 4, not be returned as-is.
// Without this test the guard can be deleted with the suite staying green,
// since no real interface can be relied on to produce a zoned or link-local
// route result.
func TestRouteLookupRejectsUnusableKernelResult(t *testing.T) {
	tests := []struct {
		name  string
		local *net.UDPAddr
	}{
		{
			name:  "zoned address falls through to rule 4",
			local: &net.UDPAddr{IP: net.ParseIP("2001:db8::5"), Zone: "eth0"},
		},
		{
			name:  "IPv4 link-local unicast falls through to rule 4",
			local: &net.UDPAddr{IP: net.ParseIP("169.254.1.9")},
		},
		{
			name:  "link-local multicast falls through to rule 4",
			local: &net.UDPAddr{IP: net.ParseIP("224.0.0.251")},
		},
		{
			name:  "administratively-scoped multicast falls through to rule 4",
			local: &net.UDPAddr{IP: net.ParseIP("239.1.2.3")},
		},
		{
			name:  "unspecified address falls through to rule 4",
			local: &net.UDPAddr{IP: net.ParseIP("0.0.0.0")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeDial(t, tt.local)
			fixedAddrs(t, "192.168.8.244/24")
			got, err := ResolveLocalIP("127.0.0.1:5060", discardLogger())
			if err != nil {
				t.Fatalf("ResolveLocalIP: %v", err)
			}
			if got.String() != "192.168.8.244" {
				t.Fatalf("rule 3 kernel result %v should have been rejected by routeLookup, "+
					"falling through to rule 4; got %s instead", tt.local, got)
			}
		})
	}
}

// TestRouteLookupAcceptsUsableKernelResult is the positive counterpart: a
// legitimate, unzoned kernel-selected address is returned by rule 3 and
// rule 4 is never reached.
func TestRouteLookupAcceptsUsableKernelResult(t *testing.T) {
	fakeDial(t, &net.UDPAddr{IP: net.ParseIP("203.0.113.9")})
	fixedAddrs(t, "192.168.8.244/24") // present but must not be chosen

	got, err := ResolveLocalIP("198.51.100.1:5060", discardLogger())
	if err != nil {
		t.Fatalf("ResolveLocalIP: %v", err)
	}
	if got.String() != "203.0.113.9" {
		t.Fatalf("got %s, want rule 3's kernel-selected 203.0.113.9", got)
	}
}

func TestPreferredPort(t *testing.T) {
	if got := preferredPort("udp"); got != "5060" {
		t.Errorf("preferredPort(udp) = %q, want 5060", got)
	}
}

func TestResolveBindAddr_PrefersStandardPortWhenUnspecified(t *testing.T) {
	addr, explicit, err := ResolveBindAddr("192.0.2.10", "", "udp", slog.Default())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if addr != "192.0.2.10:5060" {
		t.Errorf("addr = %q, want 192.0.2.10:5060", addr)
	}
	if explicit {
		t.Error("portExplicit = true, want false for an unspecified port")
	}
}

func TestResolveBindAddr_ExplicitPortIsMarkedExplicit(t *testing.T) {
	addr, explicit, err := ResolveBindAddr("192.0.2.10:5080", "", "udp", slog.Default())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if addr != "192.0.2.10:5080" || !explicit {
		t.Errorf("got (%q, explicit=%v), want (192.0.2.10:5080, true)", addr, explicit)
	}
}

func TestResolveBindAddr(t *testing.T) {
	tests := []struct {
		name      string
		localAddr string
		remote    string
		addrs     []string
		want      string
		wantCode  apierr.Code
		wantMsg   string
	}{
		{
			name:      "omitted in direct mode falls to rule 4, kernel picks the port",
			localAddr: "",
			remote:    "",
			addrs:     []string{"127.0.0.1/8", "192.168.8.244/24"},
			want:      "192.168.8.244:5060",
		},
		{
			name:      "omitted in register mode resolves by rule 3 against the registrar",
			localAddr: "",
			remote:    "127.0.0.1:5060",
			addrs:     []string{"127.0.0.1/8"},
			want:      "127.0.0.1:5060",
		},
		{
			name:      "IPv4 wildcard keeps the supplied port",
			localAddr: "0.0.0.0:5060",
			remote:    "",
			addrs:     []string{"127.0.0.1/8", "192.168.8.244/24"},
			want:      "192.168.8.244:5060",
		},
		{
			name:      "IPv6 wildcard keeps the supplied port",
			localAddr: "[::]:5060",
			remote:    "",
			addrs:     []string{"fe80::1/64", "2001:db8::5/64"},
			want:      "[2001:db8::5]:5060",
		},
		{
			name:      "bare port keeps the port and resolves the host",
			localAddr: "5060",
			remote:    "",
			addrs:     []string{"192.168.8.244/24"},
			want:      "192.168.8.244:5060",
		},
		{
			name:      "colon-prefixed bare port is the same case",
			localAddr: ":5060",
			remote:    "",
			addrs:     []string{"192.168.8.244/24"},
			want:      "192.168.8.244:5060",
		},
		{
			name:      "concrete address passes through untouched",
			localAddr: "192.168.8.244:5070",
			remote:    "",
			addrs:     []string{"10.0.0.5/8"},
			want:      "192.168.8.244:5070",
		},
		{
			name:      "explicit IPv6 link-local host is rejected",
			localAddr: "[fe80::1]:5060",
			remote:    "",
			addrs:     []string{"192.168.8.244/24"},
			wantCode:  apierr.CodeInvalidArgument,
		},
		{
			name:      "explicit IPv4 link-local host is rejected",
			localAddr: "169.254.1.9:5060",
			remote:    "",
			addrs:     []string{"192.168.8.244/24"},
			wantCode:  apierr.CodeInvalidArgument,
		},
		{
			name:      "explicit zoned IPv6 literal is rejected",
			localAddr: "[fe80::1%eth0]:5060",
			remote:    "",
			addrs:     []string{"192.168.8.244/24"},
			wantCode:  apierr.CodeInvalidArgument,
			wantMsg:   "zone",
		},
		{
			name:      "zoned non-link-local literal is rejected too",
			localAddr: "[2001:db8::5%eth0]:5060",
			remote:    "",
			addrs:     []string{"192.168.8.244/24"},
			wantCode:  apierr.CodeInvalidArgument,
			wantMsg:   "zone",
		},
		{
			name:      "unresolvable host yields invalid_argument",
			localAddr: "0.0.0.0:5060",
			remote:    "",
			addrs:     []string{"127.0.0.1/8", "fe80::1/64"},
			wantCode:  apierr.CodeInvalidArgument,
		},
		{
			name:      "non-IP host is rejected rather than resolved by DNS",
			localAddr: "example.com:5060",
			remote:    "",
			addrs:     []string{"192.168.8.244/24"},
			wantCode:  apierr.CodeInvalidArgument,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixedAddrs(t, tt.addrs...)
			got, _, err := ResolveBindAddr(tt.localAddr, tt.remote, "udp", discardLogger())
			if tt.wantCode != "" {
				var ae *apierr.Error
				if !errors.As(err, &ae) {
					t.Fatalf("want *apierr.Error, got %T (%v), result %q", err, err, got)
				}
				if ae.Code != tt.wantCode {
					t.Fatalf("code = %q, want %q", ae.Code, tt.wantCode)
				}
				if tt.wantMsg != "" && !strings.Contains(ae.Message, tt.wantMsg) {
					t.Fatalf("message %q does not mention %q", ae.Message, tt.wantMsg)
				}
				if got != "" {
					t.Fatalf("failed resolution returned an address %q; no UA may be created", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveBindAddr: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
