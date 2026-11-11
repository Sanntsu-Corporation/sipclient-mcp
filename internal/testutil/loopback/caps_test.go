package loopback_test

import (
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// assertDenied asserts that err is a DENIED naming exactly the policy key
// that bound, with that key's own limit and current. §12.2.2's acceptance
// requires the DENIAL TO NAME THE BOUND — an agent starved by the server-wide
// cap while under its own must be able to tell which one stopped it.
//
// The code is "denied" (apierr.CodeDenied), not "resource_limit":
// internal/session/caps.go builds every §12.2.2 concurrency-cap refusal via
// apierr.DeniedLimit, confirmed against internal/session/caps_test.go's own
// assertDenied, which asserts exactly ae.Code == apierr.CodeDenied for this
// same class of denial. "resource_limit" (apierr.CodeResourceLimit) is a
// DIFFERENT code, used for waiter caps and UA caps, not concurrency caps.
//
// Declared here, its sole consumer, rather than in the shared fixture file
// (D348): assertDenied is used only by this file's two tests.
func assertDenied(t *testing.T, err error, rule string, limit, current int) {
	t.Helper()
	if err == nil {
		t.Fatalf("want a denial naming %q, got success", rule)
	}
	if code := loopback.ErrorCode(err); code != "denied" {
		t.Fatalf("code = %q, want denied", code)
	}
	if got := loopback.ErrorRule(err); got != rule {
		t.Fatalf("rule = %q, want %q — the denial must name the exact key that bound "+
			"(§12.2.2, U3)", got, rule)
	}
	gotLimit, gotCurrent := loopback.ErrorLimits(err)
	if gotLimit != limit || gotCurrent != current {
		t.Fatalf("limit/current = %d/%d, want %d/%d — both come from the key that bound",
			gotLimit, gotCurrent, limit, current)
	}
}

// §12.2.2's acceptance, verbatim: independent per-session and server-wide
// bounds, first-come-first-served contention, and a `denied` naming the exact
// key that bound.
func TestTwoIndependentConcurrencyCaps(t *testing.T) {
	h := loopback.New(t,
		loopback.WithPolicyOverride("limits.max_concurrent_calls_per_session", 2),
		loopback.WithPolicyOverride("limits.max_concurrent_calls_total", 3),
		loopback.WithPolicyOverride("limits.registry_retention", "1h"))
	defer h.Close()

	s1, s2 := h.NewSession(t), h.NewSession(t)
	ua1, ua2 := s1.MustCreateUA(t, "direct"), s2.MustCreateUA(t, "direct")

	c1 := s1.MustDial(t, ua1, h.PeerURI())
	c2 := s1.MustDial(t, ua1, h.PeerURI())

	_, err := s1.CallTool("call_dial", map[string]any{"ua": ua1, "to_uri": h.PeerURI()})
	assertDenied(t, err, "max_concurrent_calls_per_session", 2, 2)

	// Independence: S1's exhaustion does not consume S2's allowance.
	if _, err := s2.CallTool("call_dial", map[string]any{"ua": ua2, "to_uri": h.PeerURI()}); err != nil {
		t.Fatalf("S2's first dial failed while S1 was at its own cap: %v", err)
	}

	// First-come-first-served: S2 is denied on the TOTAL holding only one call.
	_, err = s2.CallTool("call_dial", map[string]any{"ua": ua2, "to_uri": h.PeerURI()})
	assertDenied(t, err, "max_concurrent_calls_total", 3, 3)

	// A slot freed by S1 is immediately available to S2; no reservation held.
	s1.MustHangup(t, c1)
	deadline := time.Now().Add(100 * time.Millisecond)
	for {
		if _, err := s2.CallTool("call_dial", map[string]any{"ua": ua2, "to_uri": h.PeerURI()}); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("S2's dial did not succeed within 100ms of S1 hanging up")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// A terminated call stops counting at TERMINATION, not at eviction —
	// registry_retention is 1h, so eviction cannot be what freed the slot.
	s1.MustHangup(t, c2)
	if _, err := s1.CallTool("call_dial", map[string]any{"ua": ua1, "to_uri": h.PeerURI()}); err != nil {
		t.Fatalf("dial after hangup failed with registry_retention=1h: %v — a terminated "+
			"call must stop counting immediately on termination (§12.2.2)", err)
	}
}

// Check order: per-session first, so an agent over both bounds is told about
// its own first.
func TestCapCheckOrderIsPerSessionFirst(t *testing.T) {
	h := loopback.New(t,
		loopback.WithPolicyOverride("limits.max_concurrent_calls_per_session", 1),
		loopback.WithPolicyOverride("limits.max_concurrent_calls_total", 1))
	defer h.Close()

	s := h.NewSession(t)
	ua := s.MustCreateUA(t, "direct")
	s.MustDial(t, ua, h.PeerURI())

	_, err := s.CallTool("call_dial", map[string]any{"ua": ua, "to_uri": h.PeerURI()})
	assertDenied(t, err, "max_concurrent_calls_per_session", 1, 1)
}
