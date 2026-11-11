package session

import (
	"context"
	"errors"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// TestMaxUAsPerSessionBoundary is the multi-UA-per-session wave's cap-
// enforcement proof at a configured N > 1: the Nth ua_create on a session
// succeeds, the (N+1)th is denied naming max_uas_per_session. Mirrors
// caps_test.go's existing max_uas_total denial-shape assertions.
func TestMaxUAsPerSessionBoundary(t *testing.T) {
	m, _ := newManagerWith(t, func(l *policy.Limits) { l.MaxUAsPerSession = 3 })
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP}); err != nil {
			t.Fatalf("CreateUA #%d: %v", i+1, err)
		}
	}
	_, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err == nil {
		t.Fatal("4th CreateUA succeeded past max_uas_per_session=3, want a denial")
	}
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("4th CreateUA error is not *apierr.Error: %v", err)
	}
	if ae.Code != apierr.CodeDenied {
		t.Errorf("denial code = %q, want %q", ae.Code, apierr.CodeDenied)
	}
	if ae.Rule != "max_uas_per_session" {
		t.Errorf("denial rule = %q, want %q", ae.Rule, "max_uas_per_session")
	}
	if ae.Limit == nil || *ae.Limit != 3 {
		t.Errorf("denial limit = %v, want 3", ae.Limit)
	}
}

// TestTwoUAsInOneSessionDialIndependently is the FR's headline scenario: one
// session creates a caller UA and a callee UA (different accounts), and
// both are independently addressable by their own ua handle for call_dial.
func TestTwoUAsInOneSessionDialIndependently(t *testing.T) {
	m, _ := newManagerWith(t, func(l *policy.Limits) { l.MaxUAsPerSession = 4 })
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	caller, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA caller: %v", err)
	}
	callee, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA callee: %v", err)
	}
	if caller.Handle() == callee.Handle() {
		t.Fatal("caller and callee minted the same handle")
	}

	c1, err := m.CreateCall(ctx, "s1", caller.Handle(), Outbound, StateDialing)
	if err != nil {
		t.Fatalf("CreateCall on caller: %v", err)
	}
	c2, err := m.CreateCall(ctx, "s1", callee.Handle(), Outbound, StateDialing)
	if err != nil {
		t.Fatalf("CreateCall on callee: %v", err)
	}
	if c1.UAHandle() != caller.Handle() {
		t.Errorf("c1.UAHandle() = %s, want %s", c1.UAHandle(), caller.Handle())
	}
	if c2.UAHandle() != callee.Handle() {
		t.Errorf("c2.UAHandle() = %s, want %s", c2.UAHandle(), callee.Handle())
	}
}
