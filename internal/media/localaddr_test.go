package media

import (
	"io"
	"log/slog"
	"net"
	"testing"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestResolveMediaAddrRule1ExplicitIP(t *testing.T) {
	SetRouteResolver(func(string, *slog.Logger) (net.IP, error) {
		t.Fatal("rule 3/4 must not run when local_addr carries an explicit IP")
		return nil, nil
	})
	ip, err := ResolveMediaAddr("192.0.2.7:5060", "203.0.113.9", "198.51.100.1:5060", discard())
	if err != nil {
		t.Fatalf("ResolveMediaAddr: %v", err)
	}
	if ip.String() != "192.0.2.7" {
		t.Fatalf("rule 1 co-location failed: got %s", ip)
	}
}

func TestResolveMediaAddrRule2PolicyOverride(t *testing.T) {
	SetRouteResolver(func(string, *slog.Logger) (net.IP, error) {
		t.Fatal("rule 3/4 must not run when policy media_ip is set")
		return nil, nil
	})
	// local_addr omitted / wildcard -> rule 1 does not apply -> rule 2 wins.
	ip, err := ResolveMediaAddr("0.0.0.0:5060", "203.0.113.9", "198.51.100.1:5060", discard())
	if err != nil {
		t.Fatalf("ResolveMediaAddr: %v", err)
	}
	if ip.String() != "203.0.113.9" {
		t.Fatalf("rule 2 override failed: got %s", ip)
	}
}

func TestResolveMediaAddrRule34Fallthrough(t *testing.T) {
	called := false
	SetRouteResolver(func(remote string, _ *slog.Logger) (net.IP, error) {
		called = true
		if remote != "198.51.100.1:5060" {
			t.Fatalf("remote passed through wrong: %q", remote)
		}
		return net.ParseIP("198.51.100.2"), nil
	})
	ip, err := ResolveMediaAddr("", "", "198.51.100.1:5060", discard())
	if err != nil {
		t.Fatalf("ResolveMediaAddr: %v", err)
	}
	if !called {
		t.Fatal("rules 3/4 resolver was not consulted")
	}
	if ip.String() != "198.51.100.2" {
		t.Fatalf("fallthrough ip=%s", ip)
	}
}

func TestResolveMediaAddrBarePortDoesNotTriggerRule1(t *testing.T) {
	SetRouteResolver(func(string, *slog.Logger) (net.IP, error) {
		return net.ParseIP("198.51.100.2"), nil
	})
	ip, err := ResolveMediaAddr("5060", "", "198.51.100.1:5060", discard())
	if err != nil {
		t.Fatalf("ResolveMediaAddr: %v", err)
	}
	if ip.String() != "198.51.100.2" {
		t.Fatalf("a bare port must not be treated as an explicit IP: got %s", ip)
	}
}
