package sipua

import "testing"

// TestDigestHostAllowed pins CF-046's host-match rule (D-C, D-C0..D-C5): the
// INVITE target host must equal the registrar host (register mode) or the AOR
// host, compared exactly after normalisation, unless AuthAnyHost is set.
//
// The IPv6 rows are pure-function rows only: Dial rejects an IPv6-literal
// to_uri up front (TestDialRejectsIPv6ToURI), so no IPv6 target reaches
// runDial's guard. They stay because norm must be right if that is lifted.
func TestDigestHostAllowed(t *testing.T) {
	reg := func(registrar string) Config { return Config{Mode: "register", Registrar: registrar} }
	direct := func(aor string) Config { return Config{Mode: "direct", AOR: aor} }

	tests := []struct {
		name   string
		cfg    Config
		target string
		want   bool
	}{
		{"case-insensitive host", reg("sip:pbx.example.com:5060"), "PBX.Example.com", true},
		{"one trailing dot on the target", reg("sip:pbx.example.com"), "pbx.example.com.", true},
		{"IPv6 canonical text", reg("sip:[2001:DB8:0::1]:5070"), "[2001:db8::1]", true},
		{"registrar port does not reach the host compare", reg("sip:pbx.example.com:5060"), "pbx.example.com", true},
		{"upper-case scheme on the registrar", reg("SIP:pbx.example.com:5060"), "pbx.example.com", true},
		{"mixed-case sips scheme on the AOR", direct("Sips:u@carrier.example"), "carrier.example", true},
		{"bare host:port registrar (no scheme)", reg("pbx.example.com:5060"), "pbx.example.com", true},
		{"registrar params cut", reg("sip:pbx:5060;transport=tcp"), "pbx", true},
		{"direct AOR anchors (D-C1 (2))", direct("sip:u@carrier.example"), "carrier.example", true},
		{"direct AOR with port and params", direct("sip:u@carrier.example:5070;x=1"), "carrier.example", true},
		{"AuthAnyHost allows any target", Config{Mode: "direct", AuthAnyHost: true}, "anything.example", true},
		{"AuthAnyHost allows an empty target", Config{Mode: "direct", AuthAnyHost: true}, "", true},

		{"two trailing dots", reg("sip:pbx.example.com"), "pbx.example.com..", false},
		{"different IPv6", reg("sip:[2001:DB8:0::1]:5070"), "2001:db8::2", false},
		{"no DNS: IP literal vs name", reg("sip:pbx.lab"), "192.168.8.232", false},
		{"no suffix match", reg("sip:example.com"), "evil.example.com", false},
		{"no prefix match", reg("sip:pbx.example.com"), "pbx.example.com.evil", false},
		{"empty target", reg("sip:pbx.example.com"), "", false},
		{"unparsable registrar port fails closed", reg("sip:host:abc"), "host", false},
		{"double @ in the AOR does not anchor the part after the last @", direct("sip:u@h@evil.example"), "evil.example", false},
		{"direct without AOR nor override (proxy direct-account shape)", direct(""), "carrier.example", false},
		{"register mode with empty registrar and no AOR", reg(""), "", false},
		{"registrar ignored in direct mode", Config{Mode: "direct", Registrar: "sip:pbx.example.com"}, "pbx.example.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := digestHostAllowed(tc.cfg, tc.target); got != tc.want {
				t.Errorf("digestHostAllowed(mode=%q registrar=%q aor=%q any=%v, %q) = %v, want %v",
					tc.cfg.Mode, tc.cfg.Registrar, tc.cfg.AOR, tc.cfg.AuthAnyHost, tc.target, got, tc.want)
			}
		})
	}
}
