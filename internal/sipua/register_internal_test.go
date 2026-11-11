package sipua

// Internal (package sipua) unit tests for the two helpers contactExpires uses
// to decide WHICH listed Contact is our binding. Both encode wire-grammar
// rules — case-insensitive parameter names (RFC 3261 §7.3.1) and the
// scheme-default port in URI equivalence (§19.1.4) — that a registrar double
// echoing back exactly what we sent can never produce, so they are pinned
// here rather than through the peer.

import (
	"context"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

func TestParamFoldIsCaseInsensitive(t *testing.T) {
	cases := []struct {
		name   string
		params sip.HeaderParams
		want   string
		wantOK bool
	}{
		{name: "lowercase, the common form", params: sip.HeaderParams{"expires": "60"}, want: "60", wantOK: true},
		{name: "capitalised on the wire", params: sip.HeaderParams{"Expires": "60"}, want: "60", wantOK: true},
		{name: "shouting", params: sip.HeaderParams{"EXPIRES": "60"}, want: "60", wantOK: true},
		{name: "absent", params: sip.HeaderParams{"q": "0.5"}, wantOK: false},
		{name: "nil params", params: nil, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := paramFold(tc.params, "expires")
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("paramFold = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestSameBindingComparesUserHostAndPort(t *testing.T) {
	sent := sip.Uri{Scheme: "sip", User: "alice", Host: "192.0.2.7", Port: 5060}
	cases := []struct {
		name   string
		listed sip.Uri
		want   bool
	}{
		{name: "identical", listed: sent, want: true},
		{
			// Registrars routinely normalise the default port away when they
			// echo a binding back; that is still our binding.
			name:   "our port omitted, defaulting to 5060",
			listed: sip.Uri{Scheme: "sip", User: "alice", Host: "192.0.2.7"},
			want:   true,
		},
		{
			// THE MULTI-BINDING CASE: same AOR, another device.
			name:   "another device on a different port",
			listed: sip.Uri{Scheme: "sip", User: "alice", Host: "192.0.2.7", Port: 5080},
			want:   false,
		},
		{
			name:   "another device on a different host",
			listed: sip.Uri{Scheme: "sip", User: "alice", Host: "192.0.2.8", Port: 5060},
			want:   false,
		},
		{
			name:   "a different user entirely",
			listed: sip.Uri{Scheme: "sip", User: "bob", Host: "192.0.2.7", Port: 5060},
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameBinding(tc.listed, sent); got != tc.want {
				t.Fatalf("sameBinding(%s, %s) = %v, want %v", tc.listed.String(), sent.String(), got, tc.want)
			}
		})
	}
}

func TestSameBindingIgnoresHostCase(t *testing.T) {
	// Hostnames are case-insensitive; the user part is not.
	a := sip.Uri{Scheme: "sip", User: "alice", Host: "PBX.Example", Port: 5060}
	b := sip.Uri{Scheme: "sip", User: "alice", Host: "pbx.example", Port: 5060}
	if !sameBinding(a, b) {
		t.Fatal("host comparison must be case-insensitive")
	}
	if sameBinding(sip.Uri{Scheme: "sip", User: "Alice", Host: "pbx.example", Port: 5060}, b) {
		t.Fatal("the user part is case-SENSITIVE (RFC 3261 §19.1.4)")
	}
}

func TestSameBindingDefaultsTheSipsPort(t *testing.T) {
	withPort := sip.Uri{Scheme: "sips", User: "alice", Host: "pbx.example", Port: 5061}
	without := sip.Uri{Scheme: "sips", User: "alice", Host: "pbx.example"}
	if !sameBinding(without, withPort) {
		t.Fatal("a sips URI with no port must default to 5061, not 5060")
	}
}

// TestSameBindingTellsTransportsApart pins the URI-parameter half of RFC 3261
// §19.1.4. siptest.contactURI puts `;transport=tcp|tls` on our REGISTER Contact
// for every non-UDP transport, and the project's own rig shares ONE AOR name
// between e2e-uac-register and e2e-uac-register-tls, so two bindings at the
// same host:port differing only by transport are a shape that really occurs —
// and comparing them equal lets contactExpires adopt the wrong binding's
// expiry.
func TestSameBindingTellsTransportsApart(t *testing.T) {
	sent := sip.Uri{Scheme: "sip", User: "alice", Host: "192.0.2.7", Port: 5060,
		UriParams: sip.HeaderParams{"transport": "tcp"}}
	cases := []struct {
		name   string
		listed sip.Uri
		want   bool
	}{
		{
			// THE DEFECT: another device on the same host:port over a DIFFERENT
			// transport is a different binding.
			name: "same host:port, different transport",
			listed: sip.Uri{Scheme: "sip", User: "alice", Host: "192.0.2.7", Port: 5060,
				UriParams: sip.HeaderParams{"transport": "tls"}},
			want: false,
		},
		{
			// Parameter values are case-insensitive (§19.1.4).
			name: "same transport, shouted",
			listed: sip.Uri{Scheme: "sip", User: "alice", Host: "192.0.2.7", Port: 5060,
				UriParams: sip.HeaderParams{"Transport": "TCP"}},
			want: true,
		},
		{
			// B9: transport is NOT one of the parameters §19.1.4's "present in
			// only one URI is IGNORED" rule folds away — it identifies a
			// DIFFERENT wire path (UDP vs TCP vs TLS), unlike a parameter that
			// is genuinely decoration. Before B9 this compared equal, the same
			// class of leniency uriPort still extends to a normalised-away
			// PORT; a registrar that echoes the binding back without the
			// transport param it was sent is NOT necessarily echoing ours.
			name:   "transport dropped by the registrar's echo",
			listed: sip.Uri{Scheme: "sip", User: "alice", Host: "192.0.2.7", Port: 5060},
			want:   false,
		},
		{
			// §19.1.4: maddr present in only one URI never matches.
			name: "maddr on only one side",
			listed: sip.Uri{Scheme: "sip", User: "alice", Host: "192.0.2.7", Port: 5060,
				UriParams: sip.HeaderParams{"transport": "tcp", "maddr": "239.255.255.1"}},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameBinding(tc.listed, sent); got != tc.want {
				t.Fatalf("sameBinding(%s, %s) = %v, want %v", tc.listed.String(), sent.String(), got, tc.want)
			}
		})
	}
}

// TestSameBindingRequiresTheSameScheme is B8: sip: and sips: identify
// DIFFERENT bindings (RFC 3261 §19.1.4 URI equivalence requires the scheme to
// match), not the same one spelled two ways. Everything else about the two
// URIs below is identical.
func TestSameBindingRequiresTheSameScheme(t *testing.T) {
	sipURI := sip.Uri{Scheme: "sip", User: "alice", Host: "192.0.2.7", Port: 5061}
	sipsURI := sip.Uri{Scheme: "sips", User: "alice", Host: "192.0.2.7", Port: 5061}
	if sameBinding(sipURI, sipsURI) {
		t.Fatal("sip: and sips: must not compare equal (B8)")
	}
	if !sameBinding(sipURI, sipURI) {
		t.Fatal("a URI must still match an identical copy of itself")
	}
	// The scheme comparison is itself case-insensitive, same as every other
	// wire-grammar comparison in this file.
	shouted := sip.Uri{Scheme: "SIP", User: "alice", Host: "192.0.2.7", Port: 5061}
	if !sameBinding(sipURI, shouted) {
		t.Fatal("scheme comparison must be case-insensitive")
	}
}

// TestSetExpiresClampsRatherThanNarrowingSilently is B4: sip.ExpiresHeader is
// a uint32, and a seconds value outside its range narrows SILENTLY
// (9999999999 mod 2^32 = 1410065407) rather than erroring. The policy-side
// load-time ceiling is the primary defence; this pins the belt-and-suspenders
// clamp at the point of narrowing itself.
func TestSetExpiresClampsRatherThanNarrowingSilently(t *testing.T) {
	cases := []struct {
		name    string
		seconds int
		want    uint32
	}{
		{name: "an ordinary value passes through unchanged", seconds: 300, want: 300},
		{name: "zero passes through unchanged (Unregister)", seconds: 0, want: 0},
		{
			name:    "a value that would narrow to 1410065407 clamps instead",
			seconds: 9999999999,
			want:    math.MaxUint32,
		},
		{name: "a negative value clamps to zero, not a huge unsigned wrap", seconds: -1, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &sip.Request{}
			setExpires(req, tc.seconds)
			h := req.GetHeader("Expires")
			if h == nil {
				t.Fatal("setExpires did not set an Expires header")
			}
			got, err := strconv.ParseUint(strings.TrimSpace(h.Value()), 10, 32)
			if err != nil {
				t.Fatalf("Expires value %q did not parse as a uint32: %v", h.Value(), err)
			}
			if uint32(got) != tc.want {
				t.Fatalf("setExpires(%d) => Expires=%d, want %d", tc.seconds, got, tc.want)
			}
		})
	}
}

// TestUriPortDefaultsByTransportNotJustScheme pins §19.1.1's default port
// table: 5061 is the default for TLS, and our own TLS Contact is a `sip:` URI
// carrying `;transport=tls` (siptest.contactURI), which a scheme-only default
// reads as port 5060 — mistaking it for a plaintext binding on the same host.
func TestUriPortDefaultsByTransportNotJustScheme(t *testing.T) {
	tls := sip.Uri{Scheme: "sip", User: "alice", Host: "pbx.example",
		UriParams: sip.HeaderParams{"transport": "tls"}}
	if got := uriPort(tls); got != 5061 {
		t.Fatalf("uriPort(%s) = %d, want 5061", tls.String(), got)
	}
	explicit := sip.Uri{Scheme: "sip", User: "alice", Host: "pbx.example", Port: 5061,
		UriParams: sip.HeaderParams{"transport": "tls"}}
	if !sameBinding(tls, explicit) {
		t.Fatal("a sip: URI over TLS with no port must default to 5061")
	}
	plain := sip.Uri{Scheme: "sip", User: "alice", Host: "pbx.example", Port: 5060}
	if sameBinding(tls, plain) {
		t.Fatal("a TLS binding must not be read as the plaintext binding on 5060")
	}
}

// TestBuildRegisterDoesNotOverrideContactOnTCP is the Rule 13 Cycle 3 fix
// for buildRegister's Contact-override block: on UDP, the RFC 3581 learned
// address genuinely reflects a NAT mapping (the same socket sends every
// REGISTER), but over TCP/TLS the source port sipgo's buildVia stamps is
// ALWAYS a fresh connection's OS-assigned ephemeral port — never the
// listening port — so overriding Contact with it would advertise a port
// nothing listens on. This is a white-box (package sipua) unit test rather
// than an extension of rport_integration_test.go's UDP scenario because
// internal/testutil/sipproxy (the sole stimulus oracle, Rule 6a-D1) has no
// TCP listener support — buildRegister needs no live registrar exchange to
// exercise, only a populated learnedPublic, which this test sets directly.
func TestBuildRegisterDoesNotOverrideContactOnTCP(t *testing.T) {
	ua, err := New(context.Background(), Config{
		Transport: "tcp",
		Mode:      "register",
		AOR:       "sip:alice@example",
		Registrar: "sip:registrar.example:5060",
		AuthUser:  "alice",
		AuthPass:  "s3cr3t",
		ExpiresS:  300,
		Timeout:   2 * time.Second,
		LocalAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("New(tcp): %v", err)
	}
	defer func() { _ = ua.Close(context.Background()) }()

	// A learned address IS known -- exactly the state that fires the
	// override on UDP -- so this test proves the transport gate, not an
	// empty-learnedPublic no-op.
	observed := netip.MustParseAddrPort("198.51.100.9:40000")
	ua.learnedPublic.Set(observed)

	req := ua.buildRegister(300)
	c := req.Contact()
	if c == nil {
		t.Fatal("buildRegister produced a REGISTER with no Contact header")
	}

	bound := ua.BoundAddr()
	if c.Address.Host != bound.IP.String() || c.Address.Port != bound.Port {
		t.Fatalf("TCP REGISTER Contact = %s:%d, want the BOUND address %s:%d "+
			"(the RFC 3581 learned address must not override Contact on TCP/TLS)",
			c.Address.Host, c.Address.Port, bound.IP.String(), bound.Port)
	}
	if c.Address.Host == observed.Addr().String() && c.Address.Port == int(observed.Port()) {
		t.Fatal("TCP REGISTER Contact was overridden with the learned (NAT) address")
	}
}
