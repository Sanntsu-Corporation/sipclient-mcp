package loopback_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// §12.7's WIRE half. Task 19 asserts the HTTP surface — token separation,
// 404-when-unset, response shape, audit lines, no call_handle in any payload.
// This half asserts what actually goes out on the wire and what the counters
// do. NEITHER HALF ALONE DISCHARGES §12.7's ACCEPTANCE.
func TestAdminDeleteOnTheWire(t *testing.T) {
	h := loopback.New(t, loopback.WithAdminToken("admin-secret"),
		loopback.WithAccounts(loopback.TestAccount("carrier-a", "s3cr3t-auth-pass")))
	defer h.Close()

	// Phase 1's STRICT one-UA-per-session model (owner-locked decision): the
	// register-mode and direct-mode UAs go on their OWN sessions — neither
	// this test nor active_uas/isolation accounting below cares which
	// session owns which handle.
	s1 := h.NewSession(t)
	uaReg := s1.MustCreateUAWithAccount(t, "carrier-a")
	s1b := h.NewSession(t)
	uaDirect := s1b.MustCreateUA(t, "direct")
	call := s1b.MustDial(t, uaDirect, h.PeerURI())
	s1b.MustWait(t, call, "answered", 2000)
	s1.AbandonSessionID(t) // the agent crashes; the id is gone forever
	s1b.AbandonSessionID(t)

	before := h.MustMetrics(t)
	byeBefore := h.Peer().ByeCount()
	unregBefore := h.Registrar().UnregisterCount("testuser")

	res := h.MustAdminDelete(t, uaDirect)
	if res.Unregistered {
		t.Fatalf("direct-mode UA reported unregistered=true, want false")
	}
	if res.CallsTerminated != 1 {
		t.Fatalf("calls_terminated = %d, want 1", res.CallsTerminated)
	}
	if got := h.Peer().ByeCount() - byeBefore; got != 1 {
		t.Fatalf("far end observed %d BYE, want exactly 1", got)
	}

	res = h.MustAdminDelete(t, uaReg)
	if !res.Unregistered {
		t.Fatal("register-mode UA reported unregistered=false, want true")
	}
	if got := h.Registrar().UnregisterCount("testuser") - unregBefore; got != 1 {
		t.Fatalf("registrar observed %d REGISTER Expires:0, want exactly 1", got)
	}

	// D11 point 4 ("an INVITE to the destroyed UA's AOR now gets 404 Not
	// Found") is asserted separately, on the registrar-routed path, by
	// TestAdminDeleteRegisterModeAORGets404 below — see that test's docstring
	// for why the proxy fix (internal/testutil/sipproxy) this needed was out
	// of an earlier task's scope.

	after := h.MustMetrics(t)
	if d := before["active_uas"] - after["active_uas"]; d != 2 {
		t.Fatalf("active_uas decremented by %d, want 2 (one per DELETE)", d)
	}
	const reasonKey = `calls_by_termination_reason{reason="local_hangup"}`
	if d := after[reasonKey] - before[reasonKey]; d != 1 {
		t.Fatalf("calls_by_termination_reason{local_hangup} incremented by %d, want "+
			"exactly 1 — an admin teardown is a locally-initiated BYE and introduces "+
			"no new enum value (§12.7, §11.4)", d)
	}
}

// D11 point 4: once a register-mode UA is admin-destroyed, a subsequent
// INVITE routed via the registrar to its AOR gets 404 Not Found — the far
// end must no longer be able to reach it.
//
// Routed via the REGISTRAR (h.Registrar().Addr()), not the direct UA socket:
// Task 23b established that the direct-socket path gets no response at all
// once destroyUA closes the socket, which is a different (and already-known)
// symptom, not this one. This test's target is the registrar's routing
// table: internal/testutil/sipproxy's handleRegister used to record
// unregisters[user]++ on an accepted Expires:0 REGISTER but never clear
// p.contacts[user], so forwardRequest kept finding the stale contact and
// forwarding to it — the proxy's own explicit 404 branch was unreachable via
// deregistration. Fixed by clearing the contact on the accepted Expires:0
// path (internal/testutil/sipproxy/proxy.go, VENDOR.md-tracked).
func TestAdminDeleteRegisterModeAORGets404(t *testing.T) {
	h := loopback.New(t, loopback.WithAdminToken("admin-secret"),
		loopback.WithAccounts(loopback.TestAccount("carrier-a", "s3cr3t-auth-pass")))
	defer h.Close()

	s1 := h.NewSession(t)
	uaReg := s1.MustCreateUAWithAccount(t, "carrier-a")

	res := h.MustAdminDelete(t, uaReg)
	if !res.Unregistered {
		t.Fatal("register-mode UA reported unregistered=false, want true")
	}

	status := h.Peer().DialExpectingStatus(t, "sip:testuser@"+h.Registrar().Addr())
	if status != 404 {
		t.Fatalf("INVITE to the destroyed UA's AOR via the registrar = %d, want 404 (D11 point 4)", status)
	}
}

// The exhaustion-recovery case: the state the design previously could not exit.
func TestAdminDeleteRecoversFromUAExhaustion(t *testing.T) {
	h := loopback.New(t, loopback.WithAdminToken("admin-secret"),
		loopback.WithPolicyOverride("limits.max_uas_total", 2))
	defer h.Close()

	// Phase 1's STRICT one-UA-per-session model (owner-locked decision): the
	// two stranded UAs need their OWN sessions — max_uas_total is
	// SERVER-WIDE, so exhaustion (and its recovery) is unaffected by which
	// session owns which handle.
	stranded1 := h.NewSession(t)
	ua1 := stranded1.MustCreateUA(t, "direct")
	stranded2 := h.NewSession(t)
	ua2 := stranded2.MustCreateUA(t, "direct")
	stranded1.AbandonSessionID(t)
	stranded2.AbandonSessionID(t)

	fresh := h.NewSession(t)
	_, err := fresh.CallTool("ua_create", map[string]any{"mode": "direct", "transport": "udp"})
	// "denied" (apierr.CodeDenied), not "resource_limit": max_uas_total is
	// enforced via apierr.DeniedLimit (internal/session/caps.go), the same
	// code family as §12.2.2's concurrency caps — see caps_test.go's
	// assertDenied for the same finding, confirmed against
	// internal/session/caps_test.go's own assertion.
	if code := loopback.ErrorCode(err); code != "denied" {
		t.Fatalf("ua_create with both slots stranded = %q, want denied", code)
	}
	if rule := loopback.ErrorRule(err); rule != "max_uas_total" {
		t.Fatalf("resource_limit rule = %q, want max_uas_total", rule)
	}

	h.MustAdminDelete(t, ua1)
	h.MustAdminDelete(t, ua2)

	if _, err := fresh.CallTool("ua_create", map[string]any{"mode": "direct", "transport": "udp"}); err != nil {
		t.Fatalf("ua_create after reclaiming both stranded UAs: %v — this is the state "+
			"the design previously could not exit (§12.7)", err)
	}
}

// §12.7's registry-lock constraint, asserted on the wire: with the grace period
// at its default and a far end that never answers the BYE, an unrelated live
// session's call_status must return within N2's budget rather than blocking.
func TestAdminDeleteDoesNotHoldTheRegistryLockAcrossTheByeWait(t *testing.T) {
	h := loopback.New(t, loopback.WithAdminToken("admin-secret"),
		loopback.WithPolicyOverride("limits.shutdown_grace_period", "10s"),
		loopback.WithPeerBehaviour(loopback.PeerBehaviour{AnswerAfter: 0, SwallowBye: true}))
	defer h.Close()

	s1 := h.NewSession(t)
	ua := s1.MustCreateUA(t, "direct")
	s1.MustWait(t, s1.MustDial(t, ua, h.PeerURI()), "answered", 2000)
	s1.AbandonSessionID(t)

	s2 := h.NewSession(t)
	ua2 := s2.MustCreateUA(t, "direct")
	c2 := s2.MustDial(t, ua2, h.PeerURI())
	s2.MustWait(t, c2, "answered", 2000)

	deleteDone := make(chan time.Duration, 1)
	start := time.Now()
	go func() {
		h.MustAdminDelete(t, ua)
		deleteDone <- time.Since(start)
	}()
	h.Peer().WaitForBye(t, 2*time.Second) // the DELETE is now inside the grace period

	statusStart := time.Now()
	s2.MustCallStatus(t, c2)
	if d := time.Since(statusStart); d > 500*time.Millisecond {
		t.Fatalf("an unrelated session's call_status took %v while an admin DELETE was "+
			"in its BYE wait; the registry lock is held across the wait (§12.7)", d)
	}

	if d := <-deleteDone; d < 9*time.Second {
		t.Fatalf("admin DELETE returned after %v, want it to occupy the full 10s grace "+
			"period against a far end that never answers", d)
	}
}

// §12.7's ISOLATION clause, and §15's "R11 isolation is unchanged by it".
//
// The admin plane destroys a UA belonging to S1. The question this test answers
// is whether that operation widens what a DIFFERENT live session can see —
// before it, during its effects, and after it. The answer must be "not at all,
// at any point".
//
// WHY `not_found` AND NEVER `gone`, both before and after: `gone` means "existed
// but has been reclaimed" (§11.2, §13.5) and is the correct answer to the OWNING
// session for an evicted handle. To a FOREIGN session it would disclose that the
// handle once existed, which is exactly what §12.2's not_found-rather-than-denied
// posture exists to prevent — an agent must not learn that another session's
// handle is real. §13.5's gone/not_found distinction is scoped to the owner;
// cross-session, `not_found` is the only answer, and the admin DELETE must not
// turn one into the other.
func TestAdminDeleteLeavesR11IsolationIntact(t *testing.T) {
	h := loopback.New(t, loopback.WithAdminToken("admin-secret"),
		loopback.WithAccounts(loopback.TestAccount("carrier-a", "s3cr3t-auth-pass")))
	defer h.Close()

	// Same scenario as TestAdminDeleteOnTheWire: "S1" holds a register-mode UA
	// and a direct-mode UA with one answered call, then abandons its session
	// id(s). Phase 1's STRICT one-UA-per-session model (owner-locked
	// decision) splits them across s1/s1b — R11 isolation from s2 does not
	// depend on which of S1's own sessions owns which handle.
	s1 := h.NewSession(t)
	uaReg := s1.MustCreateUAWithAccount(t, "carrier-a")
	s1b := h.NewSession(t)
	uaDirect := s1b.MustCreateUA(t, "direct")
	call := s1b.MustDial(t, uaDirect, h.PeerURI())
	s1b.MustWait(t, call, "answered", 2000)
	s1.AbandonSessionID(t) // the agent crashes; the id is gone forever
	s1b.AbandonSessionID(t)

	// S2 is a DIFFERENT live logical session — a fresh initialize on the SAME
	// bearer token, therefore a new session id (§12.6). Sharing the token must
	// not merge the two, which is the property that makes this test meaningful:
	// if it did, S2 would legitimately see S1's handles and the DELETE would be
	// irrelevant either way.
	s2 := h.NewSession(t)
	if s2.ID() == s1.ID() {
		t.Fatal("S2 was issued S1's session id; a fresh initialize must mint a new one")
	}

	// assertIsolated is run THREE times against the same handles: before the
	// DELETE, between the two DELETEs, and after both. Identical expectations
	// each time — that invariance across the operation IS the criterion.
	assertIsolated := func(when string) {
		t.Helper()
		for _, tc := range []struct {
			tool   string
			args   map[string]any
			handle string
		}{
			{"call_status", map[string]any{"call": call}, call},
			{"ua_status", map[string]any{"ua": uaDirect}, uaDirect},
			{"ua_status", map[string]any{"ua": uaReg}, uaReg},
		} {
			_, err := s2.CallTool(tc.tool, tc.args)
			code := loopback.ErrorCode(err)
			if code == "gone" {
				t.Fatalf("%s: S2 got `gone` from %s on S1's handle %s — `gone` discloses "+
					"that the handle once existed, which §12.2's "+
					"not_found-rather-than-denied posture exists to prevent for a "+
					"foreign session (§12.7, R11)", when, tc.tool, tc.handle)
			}
			if code != "not_found" {
				t.Fatalf("%s: S2 got %q from %s on S1's handle %s, want not_found "+
					"(R11, §12.6, §12.7)", when, code, tc.tool, tc.handle)
			}
		}
		// call_list is the enumeration surface, and it must not leak either.
		for _, c := range s2.MustCallList(t) {
			if c.CallHandle == call {
				t.Fatalf("%s: S2's call_list enumerates S1's call %s", when, call)
			}
		}
	}

	assertIsolated("before the admin DELETE")

	// The admin DELETE runs and returns 200. Its BODY is checked over the RAW
	// JSON, not the decoded struct: a decode into AdminDestroyed would silently
	// drop an unexpected key, and "no admin response body contains a
	// call_handle" is a statement about the bytes on the wire.
	status, body := h.AdminDeleteRaw(t, uaDirect)
	if status != 200 {
		t.Fatalf("admin DELETE status = %d, want 200", status)
	}
	assertNoCallHandleInBody(t, body, call)

	assertIsolated("between the two admin DELETEs")

	status, body = h.AdminDeleteRaw(t, uaReg)
	if status != 200 {
		t.Fatalf("admin DELETE status = %d, want 200", status)
	}
	assertNoCallHandleInBody(t, body, call)

	// The GET listing is an admin response body too, and it is the one that
	// enumerates — so it is the likeliest place for a call_handle to appear.
	listBody := h.AdminListUAsRaw(t)
	assertNoCallHandleInBody(t, listBody, call)

	assertIsolated("after both admin DELETEs")

	// And the destroyed handles are still not_found — never gone — to S2 even
	// though they are now genuinely reclaimed. This is the half that would
	// regress first: the natural implementation of "reclaimed" answers `gone`
	// to everyone, and the owner check has to come first.
	assertIsolated("after the UAs were reclaimed")
}

// assertNoCallHandleInBody enforces §12.7's response-shape rule over the raw
// bytes: no `call_handle` KEY anywhere in the JSON, and no occurrence of the
// live call's handle VALUE. Both, because the key could be renamed and the
// value could still leak, or the key could appear carrying something else.
//
// Declared here, its sole consumer.
func assertNoCallHandleInBody(t *testing.T, body string, callHandle string) {
	t.Helper()
	if strings.Contains(body, "call_handle") {
		t.Fatalf("admin response body contains a call_handle key — R11 must not regress "+
			"through this surface (§12.7): %s", body)
	}
	if callHandle != "" && strings.Contains(body, callHandle) {
		t.Fatalf("admin response body discloses call handle %s: %s", callHandle, body)
	}
}
