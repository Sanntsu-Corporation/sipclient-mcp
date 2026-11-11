package session_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

func TestCallDialPassesTheRedirectBudget(t *testing.T) {
	agent := fakes.NewUserAgent()
	m, ts, uaHandle := newLiveLimitsFixture(t, agent, 3, 5)

	mustDial(t, m, ts, "s1", uaHandle, nil)
	if got := agent.Dials[0].MaxRedirects; got != 3 {
		t.Fatalf("default MaxRedirects = %d, want 3", got)
	}
	if _, err := ts.ConfigSet(context.Background(), "s1", session.ConfigSetInput{
		Key: "limits.max_redirects", Value: float64(0),
	}); err != nil {
		t.Fatalf("ConfigSet: %v", err)
	}
	mustDial(t, m, ts, "s1", uaHandle, nil)
	if got := agent.Dials[1].MaxRedirects; got != 0 {
		t.Fatalf("MaxRedirects after config_set 0 = %d, want 0", got)
	}
}

func TestCallDialRedirectCheckAppliesToURIRules(t *testing.T) {
	agent := fakes.NewUserAgent()
	m, ts, uaHandle := newLiveLimitsFixture(t, agent, 3, 5)
	mustDial(t, m, ts, "s1", uaHandle, nil)
	check := agent.Dials[0].CheckRedirect
	if check == nil {
		t.Fatal("DialRequest.CheckRedirect is nil")
	}
	got, err := check("sip:ok@example.net")
	if err != nil || got != "sip:ok@example.net" {
		t.Errorf("check(sip:ok@example.net) = %q, %v", got, err)
	}
	for _, bad := range []string{"sips:x@example.net", "sip:x@example.net;transport=tcp"} {
		_, err := check(bad)
		var ae *apierr.Error
		if err == nil || !errors.As(err, &ae) || ae.Code != apierr.CodeInvalidArgument {
			t.Errorf("check(%q) err = %v, want invalid_argument", bad, err)
		}
	}
	// The live policy applies: a deny added after the dial was placed.
	if _, err := ts.ConfigSet(context.Background(), "s1", session.ConfigSetInput{
		Key: "destinations.deny", Value: []any{`^sip:.*@denied\.example$`},
	}); err != nil {
		t.Fatalf("ConfigSet: %v", err)
	}
	if _, err := check("sip:x@denied.example"); err == nil {
		t.Error("a destination denied after the dial was placed was accepted")
	}
}
