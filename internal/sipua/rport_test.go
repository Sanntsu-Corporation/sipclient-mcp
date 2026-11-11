package sipua

import (
	"testing"

	"github.com/emiago/sipgo/sip"
)

func TestLearnPublicAddr_ReadsTopViaReceivedRport(t *testing.T) {
	resp := sip.NewResponse(200, "OK")
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: "10.0.0.5", Port: 5060, Params: sip.NewParams()}
	via.Params.Add("branch", "z9hG4bKtest")
	via.Params.Add("received", "203.0.113.7")
	via.Params.Add("rport", "44321")
	resp.PrependHeader(via)

	ap, ok := learnPublicAddr(resp)
	if !ok || ap.String() != "203.0.113.7:44321" {
		t.Fatalf("learnPublicAddr = (%v,%v), want 203.0.113.7:44321,true", ap, ok)
	}
}

func TestLearnPublicAddr_AbsentWhenNoRport(t *testing.T) {
	resp := sip.NewResponse(200, "OK")
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: "10.0.0.5", Port: 5060, Params: sip.NewParams()}
	via.Params.Add("branch", "z9hG4bKtest")
	resp.PrependHeader(via)
	if _, ok := learnPublicAddr(resp); ok {
		t.Error("expected no learned addr when received/rport absent")
	}
}

// TestLearnPublicAddr_RejectsUnsafeAddr covers the D9d parity guard: a learned
// received/rport is emitted verbatim in Answer's 200 OK Contact, so it must
// clear the same address-sanity rejections the bound-address path
// (localaddr.go) applies. Each case here is unsafe and must NOT be learned.
func TestLearnPublicAddr_RejectsUnsafeAddr(t *testing.T) {
	cases := []struct {
		name     string
		received string
		rport    string
	}{
		{"wildcard", "0.0.0.0", "5060"},
		{"link-local-unicast", "fe80::1", "5060"},
		{"multicast", "224.0.0.1", "5060"},
		{"zoned-link-local", "fe80::1%eth0", "5060"},
		{"zero-port", "203.0.113.7", "0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := sip.NewResponse(200, "OK")
			via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
				Host: "10.0.0.5", Port: 5060, Params: sip.NewParams()}
			via.Params.Add("branch", "z9hG4bKtest")
			via.Params.Add("received", tc.received)
			via.Params.Add("rport", tc.rport)
			resp.PrependHeader(via)

			if ap, ok := learnPublicAddr(resp); ok {
				t.Errorf("learnPublicAddr(received=%q, rport=%q) = (%v, true), want ok=false (unsafe address must not be learned)",
					tc.received, tc.rport, ap)
			}
		})
	}
}
