package session

import (
	"strings"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// CF-185 (RFC 3261 8.1.2, 19.1; CF-172): a sips: registrar must be reached over
// TLS, so ua_create refuses it on a udp or tcp UA instead of downgrading.
func TestUACreateRefusesASipsRegistrarOnANonTLSUA(t *testing.T) {
	for _, tr := range []struct{ in, effective string }{{"", "udp"}, {"udp", "udp"}, {"tcp", "tcp"}} {
		for _, reg := range []string{"sips:reg.example.test", "SIPS:reg.example.test:5061", "Sips:reg.example.test", " sips:reg.example.test"} {
			t.Run(tr.in+"/"+reg, func(t *testing.T) {
				ts, ctx, created := newModeValidationManager(t)
				_, err := ts.UACreate(ctx, "s1", UACreateInput{
					Mode: "register", AOR: "sip:alice@example.test", Registrar: reg, Transport: tr.in,
				})
				if err == nil {
					t.Fatal("UACreate = nil error, want invalid_argument")
				}
				assertCode(t, err, apierr.CodeInvalidArgument)
				for _, want := range []string{reg, "sips:", `"` + tr.effective + `"`, `transport "tls"`} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not contain %q", err.Error(), want)
					}
				}
				if *created {
					t.Error("a UA was built before the refusal")
				}
			})
		}
	}
}

func TestUACreateAcceptsASipsRegistrarOnATLSUA(t *testing.T) {
	ts, ctx, created := newModeValidationManager(t)
	if _, err := ts.UACreate(ctx, "s1", UACreateInput{
		Mode: "register", AOR: "sip:alice@example.test", Registrar: "sips:reg.example.test", Transport: "tls",
	}); err != nil {
		t.Fatalf("UACreate = %v, want ok", err)
	}
	if !*created {
		t.Error("no UA was built")
	}
}

func TestUACreateAcceptsASipRegistrarOnEveryTransport(t *testing.T) {
	for _, tr := range []string{"udp", "tcp", "tls"} {
		for _, reg := range []string{"sip:reg.example.test", "reg.example.test:5060"} {
			t.Run(tr+"/"+reg, func(t *testing.T) {
				ts, ctx, created := newModeValidationManager(t)
				if _, err := ts.UACreate(ctx, "s1", UACreateInput{
					Mode: "register", AOR: "sip:alice@example.test", Registrar: reg, Transport: tr,
				}); err != nil {
					t.Fatalf("UACreate = %v, want ok", err)
				}
				if !*created {
					t.Error("no UA was built")
				}
			})
		}
	}
}
