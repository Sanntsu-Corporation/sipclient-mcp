package sipua

import (
	"context"
	"strings"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// This file pins a coupling that Rule 13's wave-level review flagged once
// already: two numeric ceilings — one guarding a session's own refresh
// interval, one guarding a registration's expiry — are each written TWICE,
// independently, in two packages that do not import each other for this
// purpose.
//
//   - internal/session's validateInlineAccount (toolservice.go) rejects
//     ua_create's session_expires_s above 7200, with a comment explaining the
//     7200 is "not a fresh number": it is a copy of
//     maxAcceptableSessionIntervalS (sessiontimer.go), repeated as a literal
//     because session cannot import sipua (contract Part 1 — and sipua imports
//     session, so the edge would be a cycle).
//   - the same function rejects expires_s outside 30..86400, where the 86400
//     is a copy of maxAcceptableRegisterExpiresS (register.go) — deliberately
//     a SEPARATE number from the 7200, because it bounds a different thing (a
//     registrar binding, not a call).
//
// The ORIGINAL version of this file pinned the same two constants against
// policy.validate()'s profile bounds. Phase 1 deleted policy.Profile, the
// bounds moved into validateInlineAccount, and this file was deleted with the
// code it referenced — leaving validateInlineAccount's comment claiming "this
// cross-reference is what keeps the two from drifting unnoticed" while the
// mechanism that actually caught drift was gone and only the prose remained.
// Either ceiling could then move on one side alone: sipua would go on refusing
// a peer-demanded session interval, or clamping a registrar-granted expiry, at
// its own ceiling while ua_create quietly accepted a higher value and put it on
// the wire.
//
// The check runs from THIS package because the two constants are unexported
// here, and it reaches session's ceiling through the exported ua_create
// surface, which is the only place that ceiling is applied.

// uaCreateErrorAt runs ua_create with one numeric field set to value and
// returns the error text.
//
// mode is left EMPTY on purpose. validateInlineAccount runs before UACreate's
// mode switch, so a value it accepts falls through to `mode "" is not
// "register" or "direct"` — an error that never mentions the field under test.
// The two outcomes are therefore cleanly distinguishable without a live UA,
// a listener or a fake agent: either the message names the field (the bound
// rejected the value) or it does not (the bound let it through).
func uaCreateErrorAt(t *testing.T, apply func(*session.UACreateInput)) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	clk := clock.System()
	store := policy.NewStaticStore(policy.Defaults(), clk, discardLogger())
	m, err := session.NewManager(session.ManagerConfig{
		Ctx: ctx, Clock: clk, Policy: store, Logger: discardLogger(),
		NewUA: func(context.Context, session.UAConfig) (session.UserAgent, error) {
			t.Error("ua_create reached the UA factory; validation was supposed to stop it first")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("session.NewManager: %v", err)
	}

	var in session.UACreateInput
	apply(&in)
	out, err := session.NewToolService(m).UACreate(ctx, "s1", in)
	if err == nil {
		t.Fatalf("ua_create(%+v) succeeded; it should have stopped at the empty mode (out=%+v)", in, out)
	}
	return err.Error()
}

// TestSessionExpiresCeilingMatchesUACreateValidation pins ua_create's
// session_expires_s ceiling against sipua's own maxAcceptableSessionIntervalS
// — the peer-facing ceiling sipua refuses to exceed when negotiating a session
// interval (sessiontimer.go).
func TestSessionExpiresCeilingMatchesUACreateValidation(t *testing.T) {
	const field = "session_expires_s"

	at := uaCreateErrorAt(t, func(in *session.UACreateInput) {
		in.SessionExpiresS = maxAcceptableSessionIntervalS
	})
	if strings.Contains(at, field) {
		t.Fatalf("ua_create rejected %s=%d, sipua's own maxAcceptableSessionIntervalS ceiling — "+
			"ua_create's ceiling has drifted BELOW sipua's, so a UA that exactly matches what sipua "+
			"would accept from a peer can no longer be created: %s",
			field, maxAcceptableSessionIntervalS, at)
	}

	past := uaCreateErrorAt(t, func(in *session.UACreateInput) {
		in.SessionExpiresS = maxAcceptableSessionIntervalS + 1
	})
	if !strings.Contains(past, field) {
		t.Fatalf("ua_create accepted %s=%d, one past sipua's maxAcceptableSessionIntervalS=%d ceiling — "+
			"ua_create's ceiling has drifted ABOVE sipua's, so a UA can now offer a session interval "+
			"sipua would refuse from a peer (error was %q)",
			field, maxAcceptableSessionIntervalS+1, maxAcceptableSessionIntervalS, past)
	}
}

// TestRegisterExpiresCeilingMatchesUACreateValidation pins ua_create's
// expires_s ceiling against sipua's own maxAcceptableRegisterExpiresS — the
// registrar-facing ceiling sipua clamps a granted registration expiry to
// (register.go).
func TestRegisterExpiresCeilingMatchesUACreateValidation(t *testing.T) {
	const field = "expires_s"

	at := uaCreateErrorAt(t, func(in *session.UACreateInput) {
		in.ExpiresS = maxAcceptableRegisterExpiresS
	})
	if strings.Contains(at, field) {
		t.Fatalf("ua_create rejected %s=%d, sipua's own maxAcceptableRegisterExpiresS ceiling — "+
			"ua_create's ceiling has drifted BELOW sipua's, so a UA that exactly matches what sipua "+
			"would accept from a registrar can no longer be created: %s",
			field, maxAcceptableRegisterExpiresS, at)
	}

	past := uaCreateErrorAt(t, func(in *session.UACreateInput) {
		in.ExpiresS = maxAcceptableRegisterExpiresS + 1
	})
	if !strings.Contains(past, field) {
		t.Fatalf("ua_create accepted %s=%d, one past sipua's maxAcceptableRegisterExpiresS=%d ceiling — "+
			"ua_create's ceiling has drifted ABOVE sipua's, so a UA can now request a registration "+
			"expiry sipua would clamp down from a registrar (error was %q)",
			field, maxAcceptableRegisterExpiresS+1, maxAcceptableRegisterExpiresS, past)
	}
}
