package sip

import "testing"

// CF-172: a sips: request with no transport signal defaults to TLS, never UDP.
func TestTransportOfASipsRequestWithoutATransportSignalIsTLS(t *testing.T) {
	cases := []struct {
		name      string
		recipient string
		route     string
		via       string
		pin       string
		want      string
	}{
		{"sips no signal", "sips:bob@h", "", "", "", "TLS"},
		{"sips route, sip recipient", "sip:bob@h", "<sips:proxy;lr>", "", "", "TLS"},
		{"sip no signal", "sip:bob@h", "", "", "", "UDP"},
		{"sips with UDP via", "sips:bob@h", "", "SIP/2.0/UDP 10.0.0.9;branch=z9hG4bKx", "", "UDP"},
		{"sips transport=tcp", "sips:bob@h;transport=tcp", "", "", "", "TLS"},
		{"sips transport=udp", "sips:bob@h;transport=udp", "", "", "", "UDP"},
		{"sips pinned TCP", "sips:bob@h", "", "", "TCP", "TCP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var uri Uri
			if err := ParseUri(tc.recipient, &uri); err != nil {
				t.Fatal(err)
			}
			req := NewRequest(INVITE, uri)
			if tc.route != "" {
				req.AppendHeader(NewHeader("Route", tc.route))
			}
			if tc.via != "" {
				req.AppendHeader(NewHeader("Via", tc.via))
			}
			if tc.pin != "" {
				req.SetTransport(tc.pin)
			}
			if got := req.Transport(); got != tc.want {
				t.Errorf("Transport() = %q, want %q", got, tc.want)
			}
		})
	}
}
