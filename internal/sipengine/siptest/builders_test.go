package siptest

import (
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
)

func TestBuildRegisterUsesAuthUserForRegisterIdentity(t *testing.T) {
	t.Parallel()

	req := BuildRegister(config.Config{
		TargetURI:   "sip:192.168.8.231:5060",
		LocalAddr:   "192.168.1.120:0",
		FromUser:    "0312345678",
		FromDomain:  "192.168.8.231",
		AuthUser:    "10674002660",
		AuthPass:    "P@ssword654321",
	}, "udp")

	from := req.From()
	if from == nil || from.Address.User != "10674002660" {
		t.Fatalf("expected REGISTER From user to use auth user, got %#v", from)
	}

	to := req.To()
	if to == nil || to.Address.User != "10674002660" {
		t.Fatalf("expected REGISTER To user to use auth user, got %#v", to)
	}

	contact := req.Contact()
	if contact == nil || contact.Address.User != "10674002660" {
		t.Fatalf("expected REGISTER Contact user to use auth user, got %#v", contact)
	}
}

func TestBuildInviteKeepsInviteCallerIdentity(t *testing.T) {
	t.Parallel()

	req := BuildInvite(config.Config{
		TargetURI:   "sip:192.168.8.231:5060",
		LocalAddr:   "192.168.1.120:0",
		FromUser:    "0312345678",
		FromDomain:  "192.168.8.231",
		ToUser:      "05012345678",
		ToDomain:    "192.168.8.231",
		AuthUser:    "10674002660",
		AuthPass:    "P@ssword654321",
	}, "udp", []byte("v=0\r\n"))

	from := req.From()
	if from == nil || from.Address.User != "0312345678" {
		t.Fatalf("expected INVITE From user to keep sample caller, got %#v", from)
	}
}
