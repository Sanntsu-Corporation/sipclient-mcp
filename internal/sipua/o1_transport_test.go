package sipua_test

import (
	"strings"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/siptest"
)

// O1's exit gate (§15.1). No TCP or TLS listener is wired up anywhere in this
// test — that is the point: it proves the transport token is a parameter and
// not a renamed constant.
func TestO1ViaAndContactTransportAreDerivedFromTheParameter(t *testing.T) {
	cfg := config.Config{
		LocalAddr:  "192.168.8.244:5060",
		TargetURI:  "sip:pbx.example.net",
		FromUser:   "alice",
		FromDomain: "example.net",
		ToUser:     "bob",
		ToDomain:   "example.net",
	}

	tests := []struct {
		transport   string
		wantVia     string
		wantContact string // "" means the transport param must be absent
	}{
		{transport: "udp", wantVia: "SIP/2.0/UDP", wantContact: ""},
		{transport: "tcp", wantVia: "SIP/2.0/TCP", wantContact: ";transport=tcp"},
		{transport: "tls", wantVia: "SIP/2.0/TLS", wantContact: ";transport=tls"},
	}

	for _, tt := range tests {
		t.Run("register/"+tt.transport, func(t *testing.T) {
			req := siptest.BuildRegister(cfg, tt.transport)
			assertViaAndContact(t, req.String(), tt.wantVia, tt.wantContact)
		})
		t.Run("invite/"+tt.transport, func(t *testing.T) {
			req := siptest.BuildInvite(cfg, tt.transport, []byte("v=0\r\n"))
			assertViaAndContact(t, req.String(), tt.wantVia, tt.wantContact)
		})
	}
}

func assertViaAndContact(t *testing.T, msg, wantVia, wantContact string) {
	t.Helper()
	if !strings.Contains(msg, wantVia) {
		t.Fatalf("Via does not carry %q:\n%s", wantVia, msg)
	}
	var contact string
	for _, line := range strings.Split(msg, "\r\n") {
		if strings.HasPrefix(line, "Contact:") {
			contact = line
		}
	}
	if contact == "" {
		t.Fatalf("no Contact header:\n%s", msg)
	}
	if wantContact == "" {
		if strings.Contains(strings.ToLower(contact), "transport=") {
			t.Fatalf("Contact carries a transport param for UDP, which is the "+
				"RFC 3261 default and must be omitted: %q", contact)
		}
		return
	}
	if !strings.Contains(strings.ToLower(contact), wantContact) {
		t.Fatalf("Contact = %q, want it to carry %q", contact, wantContact)
	}
}
