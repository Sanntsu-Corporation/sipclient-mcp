package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

// testToken and adminToken are declared in policy_testhelper_test.go (Task 17
// Step 17.5) — once for the package, not once per test file (Rule 18).

// assertAuditLine scans logBuf for a JSON line with "event":"admin_action"
// matching method, path and uaHandle, then asserts its level, result and
// calls_terminated, plus the presence of source and at. D238: unspecified by
// the plan text; this signature and body are Rule 6b's mandate.
func assertAuditLine(t *testing.T, logBuf *bytes.Buffer, level, method, path, uaHandle, result string, callsTerminated int) {
	t.Helper()
	for _, line := range bytes.Split(logBuf.Bytes(), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if rec["event"] != "admin_action" {
			continue
		}
		if rec["method"] != method || rec["path"] != path || rec["ua_handle"] != uaHandle {
			continue
		}
		if lvl, _ := rec["level"].(string); lvl != level {
			t.Errorf("admin_action level = %v, want %q: %s", rec["level"], level, line)
		}
		if rec["result"] != result {
			t.Errorf("admin_action result = %v, want %q: %s", rec["result"], result, line)
		}
		if ct, ok := rec["calls_terminated"].(float64); !ok || int(ct) != callsTerminated {
			t.Errorf("admin_action calls_terminated = %v, want %d: %s", rec["calls_terminated"], callsTerminated, line)
		}
		if _, ok := rec["source"]; !ok {
			t.Errorf("admin_action line missing source: %s", line)
		}
		if _, ok := rec["at"]; !ok {
			t.Errorf("admin_action line missing at: %s", line)
		}
		return
	}
	t.Fatalf("no admin_action line found for method=%s path=%s ua_handle=%s: %s", method, path, uaHandle, logBuf.String())
}

// TestAdminPlaneAbsentWhenUnconfigured: §12.7 requires that with
// auth.admin_token_file unset the plane is NOT REGISTERED AT ALL — both paths
// return 404 with any token. "Not registered" rather than "401 to everyone",
// so a deployment that does not want the plane does not have it.
//
// D239: newTestServer's Config carries no Admin at all, so
// registerAdminRoutes' `s.cfg.Admin == nil` short-circuit returns early
// regardless of the AdminEnabled() token gate — that shape would pass with
// the guard deleted, proving nothing. Task 20's daemon always supplies a real
// *session.Manager, so the configuration that matters is Admin CONFIGURED and
// the token unset; the server below is built inline with a real
// fakes.NewAdmin() and admin == "" so this test actually exercises
// AdminEnabled() rather than the nil-Admin short-circuit.
func TestAdminPlaneAbsentWhenUnconfigured(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	store, _ := testPolicyStore(t, clk, testToken, "") // admin_token_file UNSET
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour),
		Tools:    fakes.NewTools(),
		Admin:    fakes.NewAdmin(),
		Policy:   store,
		Log:      discardLogger(),
		Clock:    clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	tests := []struct {
		name   string
		method string
		path   string
		token  string
	}{
		{"GET with the admin token", "GET", "/admin/uas", adminToken},
		{"GET with the MCP token", "GET", "/admin/uas", testToken},
		{"GET with no token", "GET", "/admin/uas", ""},
		{"DELETE with the admin token", "DELETE", "/admin/uas/ua_7f2a", adminToken},
		{"DELETE with the MCP token", "DELETE", "/admin/uas/ua_7f2a", testToken},
		{"DELETE with no token", "DELETE", "/admin/uas/ua_7f2a", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := do(t, hs, tc.method, tc.path, tc.token, nil)
			if code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (the plane must be absent, not merely refusing)", code)
			}
		})
	}
}

// newAdminServer is newTestServer's CONFIGURED-admin variant: testPolicyStore
// is given a real admin token, so auth.admin_token_file is set and
// AdminEnabled() is true.
func newAdminServer(t *testing.T, clk clock.Clock) (*httptest.Server, *fakes.Admin, *bytes.Buffer) {
	t.Helper()
	var logBuf bytes.Buffer
	adm := fakes.NewAdmin()
	store, _ := testPolicyStore(t, clk, testToken, adminToken)
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour),
		Tools:    fakes.NewTools(),
		Admin:    adm,
		Policy:   store,
		Log:      slog.New(slog.NewJSONHandler(&logBuf, nil)),
		Clock:    clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs, adm, &logBuf
}

// TestAdminTokenSeparation: the MCP bearer token is REJECTED 401. That token is
// shared across agents by design (§12.6), and an admin plane on it would let
// any agent enumerate and destroy every other agent's UAs — converting §12.2's
// isolation control into a convention.
func TestAdminTokenSeparation(t *testing.T) {
	hs, adm, _ := newAdminServer(t, fakeclock.New(time.Unix(1_700_000_000, 0)))
	adm.AddUA(fakes.UA{UAHandle: "ua_7f2a", Session: "44b1c0de", Registered: true, ActiveCalls: 1})

	tests := []struct {
		name     string
		method   string
		path     string
		token    string
		wantCode int
	}{
		{"GET with the admin token", "GET", "/admin/uas", adminToken, http.StatusOK},
		{"GET with the MCP bearer token", "GET", "/admin/uas", testToken, http.StatusUnauthorized},
		{"GET with no token", "GET", "/admin/uas", "", http.StatusUnauthorized},
		{"GET with a wrong token", "GET", "/admin/uas", "nope", http.StatusUnauthorized},
		{"DELETE with the admin token", "DELETE", "/admin/uas/ua_7f2a", adminToken, http.StatusOK},
		{"DELETE with the MCP bearer token", "DELETE", "/admin/uas/ua_7f2a", testToken, http.StatusUnauthorized},
		{"DELETE with no token", "DELETE", "/admin/uas/ua_7f2a", "", http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := do(t, hs, tc.method, tc.path, tc.token, nil)
			if code != tc.wantCode {
				t.Fatalf("status = %d, want %d", code, tc.wantCode)
			}
		})
	}
}

func TestAdminListShape(t *testing.T) {
	hs, adm, logBuf := newAdminServer(t, fakeclock.New(time.Unix(1_700_000_000, 0)))
	adm.AddUA(fakes.UA{
		UAHandle: "ua_7f2a", Session: "44b1c0de", Mode: "register",
		AOR: "sip:testuser@carrier-a.example", Transport: "udp", Registered: true,
		ActiveCalls: 1, SessionConnected: false,
	})

	code, body := do(t, hs, "GET", "/admin/uas", adminToken, nil)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	var got struct {
		UAs         []map[string]any `json:"uas"`
		Count       int              `json:"count"`
		MaxUAsTotal int              `json:"max_uas_total"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, body)
	}
	if got.Count != 1 || len(got.UAs) != 1 {
		t.Fatalf("count = %d, uas = %d, want 1 and 1", got.Count, len(got.UAs))
	}
	// max_uas_total must come from the LIVE policy (default 200), not a zero
	// value nothing populated — proves the field is read from
	// s.cfg.Policy.Current().Limits.MaxUAsTotal rather than a struct literal
	// that happens to zero-marshal the same key.
	if got.MaxUAsTotal != 200 {
		t.Fatalf("max_uas_total = %d, want 200 (the policy default; proves the field is read live, not a zero value)", got.MaxUAsTotal)
	}
	for _, key := range []string{"ua_handle", "session", "mode", "aor", "transport",
		"registered", "active_calls", "created_at", "session_connected", "session_last_seen_at"} {
		if _, ok := got.UAs[0][key]; !ok {
			t.Errorf("admin UA entry is missing %q", key)
		}
	}
	if got.UAs[0]["session"] != "44b1c0de" {
		t.Errorf("session = %v; §12.7 states the FULL session id is carried DELIBERATELY "+
			"and is not redacted — the operator must be able to correlate", got.UAs[0]["session"])
	}
	// R11 is untouched: the admin plane exposes no call handle and no call content.
	if bytes.Contains(body, []byte("call_handle")) {
		t.Fatalf("admin response contains a call_handle; §12.7 widens NO agent-visible handle scope: %s", body)
	}
	// Audit: INFO for GET.
	assertAuditLine(t, logBuf, "INFO", "GET", "/admin/uas", "", "ok", 0)

	// D243: fakes.Admin.destroyedUA is a write-only field — LiveUAs never
	// reads it, so a handle recorded via AddDestroyedUA cannot be listed by
	// ANY implementation and asserting "must not be listed" against it proves
	// nothing (a false stated reason; the write-only field is pre-existing
	// Task 7a code, reported not fixed, per Rule 19). The real, checkable
	// property of a destroyed handle is that DELETE 404s and runs no
	// teardown.
	adm.AddDestroyedUA("ua_dead")
	if code, _ := do(t, hs, "DELETE", "/admin/uas/ua_dead", adminToken, nil); code != http.StatusNotFound {
		t.Fatalf("DELETE on a destroyed handle: status = %d, want 404", code)
	}
	if n := adm.TeardownCalls("ua_dead"); n != 0 {
		t.Fatalf("TeardownCalls(ua_dead) = %d, want 0 — a 404 must run no teardown", n)
	}
}

func TestAdminDeleteUA(t *testing.T) {
	hs, adm, logBuf := newAdminServer(t, fakeclock.New(time.Unix(1_700_000_000, 0)))
	adm.AddUA(fakes.UA{UAHandle: "ua_7f2a", Session: "44b1c0de", Registered: true, ActiveCalls: 1})

	code, body := do(t, hs, "DELETE", "/admin/uas/ua_7f2a", adminToken, nil)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", code, body)
	}
	var got struct {
		UAHandle        string `json:"ua_handle"`
		Unregistered    bool   `json:"unregistered"`
		CallsTerminated int    `json:"calls_terminated"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, body)
	}
	if got.UAHandle != "ua_7f2a" || !got.Unregistered || got.CallsTerminated != 1 {
		t.Fatalf("body = %+v, want {ua_7f2a true 1}", got)
	}

	// ADD: AdminDestroyed.Session is json:"-" precisely so the owning session
	// id — a §12.6 credential factor — never reaches the DELETE response
	// body, even though §12.7 requires it in the audit line. Assert both
	// halves; the plan text asserted neither.
	if bytes.Contains(body, []byte("44b1c0de")) {
		t.Fatalf("DELETE response body contains the session id; AdminDestroyed.Session "+
			"is json:\"-\" precisely so it does not: %s", body)
	}

	// Rule 16: exactly ua_destroy's teardown, on ua_destroy's implementation.
	if n := adm.TeardownCalls("ua_7f2a"); n != 1 {
		t.Fatalf("teardown ran %d times, want exactly 1 — a second teardown path "+
			"would be a second set of bugs", n)
	}
	if reason := adm.TerminationReason("ua_7f2a"); reason != "local_hangup" {
		t.Fatalf("termination_reason = %q, want local_hangup — §12.7 introduces NO new enum value", reason)
	}

	// WARN, because it destroys another party's live objects.
	assertAuditLine(t, logBuf, "WARN", "DELETE", "/admin/uas/ua_7f2a", "ua_7f2a", "ok", 1)

	// The audit line DOES carry the full session id — the other half of the
	// same clause the body assertion above pins.
	if !bytes.Contains(logBuf.Bytes(), []byte("44b1c0de")) {
		t.Fatalf("audit log does not carry the owning session id; §12.7 requires the "+
			"DELETE audit line to carry it, even though the response body must not: %s", logBuf.Bytes())
	}

	// Repeating returns 404: no LIVE UA bears the handle, including one already
	// destroyed. The §N3 terminated entry is left behind and is NOT listed here.
	if code, _ := do(t, hs, "DELETE", "/admin/uas/ua_7f2a", adminToken, nil); code != http.StatusNotFound {
		t.Fatalf("repeat DELETE status = %d, want 404", code)
	}
	if code, _ := do(t, hs, "DELETE", "/admin/uas/ua_neverexisted", adminToken, nil); code != http.StatusNotFound {
		t.Fatalf("unknown handle status = %d, want 404", code)
	}
}

// TestAdminDeleteDoesNotStallTools is the TRANSPORT HALF of §12.7's
// registry-lock assertion. It drives fakes.Admin, so it proves exactly one
// thing: THE TRANSPORT HANDLER ADDS NO SERIALIZATION OF ITS OWN while a DELETE
// occupies the grace period.
//
// It does NOT prove that session.Manager releases the registry lock before the
// BYE wait — a fake manager holds no such lock. That property is implemented
// and unit-tested in P1b Task 11a and asserted on the wire in P1e Task 23.
// Neither half alone discharges §12.7's acceptance.
//
// D244: the plan drives this DELETE through do(), which calls t.Fatalf on
// request errors — a testing API violation off the test goroutine (the D195
// pattern) once do() runs inside `go func(){...}()`. The request is built and
// issued inline below instead, so any error is sent over deleteDone and
// asserted on the TEST goroutine only.
func TestAdminDeleteDoesNotStallTools(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	tools := fakes.NewTools()
	tools.SetPayload("call_status", map[string]any{"state": "answered"})
	adm := fakes.NewAdmin()
	adm.AddUA(fakes.UA{UAHandle: "ua_slow", Session: "44b1c0de", Registered: true, ActiveCalls: 1})
	// The far end never answers the BYE, so teardown occupies the whole period.
	adm.SetTeardownDelay("ua_slow", 10*time.Second)

	store, _ := testPolicyStore(t, clk, testToken, adminToken)
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour), Tools: tools, Admin: adm,
		Policy: store, Log: discardLogger(), Clock: clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	s2 := initSession(t, hs, testToken) // an unrelated live session

	type deleteResult struct {
		code int
		err  error
	}
	deleteDone := make(chan deleteResult, 1)
	go func() {
		req, err := http.NewRequest(http.MethodDelete, hs.URL+"/admin/uas/ua_slow", nil)
		if err != nil {
			deleteDone <- deleteResult{err: err}
			return
		}
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := hs.Client().Do(req)
		if err != nil {
			deleteDone <- deleteResult{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		deleteDone <- deleteResult{code: resp.StatusCode}
	}()

	// Give the DELETE time to enter the grace period.
	time.Sleep(200 * time.Millisecond)

	body := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"call_status","arguments":{"call":"call_1"}}}`
	start := time.Now()
	if code, _ := post(t, hs, testToken, s2, body); code != http.StatusOK {
		t.Fatalf("call_status status = %d, want 200", code)
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("call_status took %v while a DELETE occupied the grace period; N2's "+
			"budget is < 50ms. The TRANSPORT is serialising admin DELETEs against tool "+
			"calls — a package-level mutex, a shared single-worker queue, or a handler "+
			"that blocks the mux. (The SESSION-layer registry-lock property is P1b Task "+
			"11a's and P1e Task 23's; this test cannot see it.)", d)
	}

	select {
	case res := <-deleteDone:
		if res.err != nil {
			t.Fatalf("DELETE request: %v", res.err)
		}
		if res.code != http.StatusOK {
			t.Fatalf("DELETE status = %d, want 200 after the grace period", res.code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("DELETE did not return after the grace period")
	}
}

// TestAdminExhaustionRecovery is §12.7's end-to-end justification: an agent
// that crashes strands its UAs permanently, because ua_destroy needs the owning
// session id, ownership is immutable with no adoption path, the owning record
// never ages out while it owns a live UA, and no MCP client persists its
// Mcp-Session-Id across its own process restart. Without this plane the only
// remedy is a daemon restart that kills every other session's live calls.
func TestAdminExhaustionRecovery(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	tools := fakes.NewTools()
	adm := fakes.NewAdmin()
	// limits.max_uas_total: 2, both slots held by a session that never returns.
	adm.SetMaxUAsTotal(2)
	adm.AddUA(fakes.UA{UAHandle: "ua_1", Session: "44b1c0de", Registered: true, ActiveCalls: 1})
	adm.AddUA(fakes.UA{UAHandle: "ua_2", Session: "44b1c0de", Mode: "direct"})
	tools.BindUALimit(adm) // ua_create returns resource_limit while adm is full

	// max_uas_total reaches the GET body from the POLICY, not from a Config
	// field — there is no Config.MaxUAsTotal.
	store, _ := testPolicyStoreWithLimits(t, clk, testToken, adminToken,
		"  max_uas_total: 2\n")
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour), Tools: tools, Admin: adm,
		Policy: store, Log: discardLogger(), Clock: clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	fresh := initSession(t, hs, testToken)
	createBody := `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":` +
		`{"name":"ua_create","arguments":{"mode":"direct","transport":"udp"}}}`

	if code, _ := post(t, hs, testToken, fresh, createBody); code != http.StatusOK {
		t.Fatalf("ua_create transport status = %d, want 200", code)
	}
	if code := tools.LastEnvelopeCode("ua_create"); code != "resource_limit" {
		t.Fatalf("ua_create code = %q, want resource_limit naming max_uas_total", code)
	}
	if rule := tools.LastEnvelopeRule("ua_create"); rule != "max_uas_total" {
		t.Fatalf("denial rule = %q, want max_uas_total", rule)
	}

	for _, h := range []string{"ua_1", "ua_2"} {
		if code, _ := do(t, hs, "DELETE", "/admin/uas/"+h, adminToken, nil); code != http.StatusOK {
			t.Fatalf("DELETE %s status = %d, want 200", h, code)
		}
	}

	if code, _ := post(t, hs, testToken, fresh, createBody); code != http.StatusOK {
		t.Fatalf("ua_create after reclamation status = %d, want 200", code)
	}
	if code := tools.LastEnvelopeCode("ua_create"); code != "" {
		t.Fatalf("ua_create still returned %q after both UAs were reclaimed; the "+
			"max_uas_total slots were not freed", code)
	}
}

// TestAdminNonGoals pins the four boundaries §12.7 states as locked decisions,
// each because each is easy to erode.
func TestAdminNonGoals(t *testing.T) {
	// NOTE on the first subtest: it asserts the RESPONSE-SHAPE half of §12.7's
	// R11 clause only — that no admin body discloses a call handle. The other
	// half, that a live session S2 still gets not_found (never gone) on S1's
	// handles BEFORE AND AFTER the DELETE, needs two real sessions against a
	// real session.Manager and is P1e Task 23's
	// TestAdminDeleteLeavesR11IsolationIntact (contract Part 4.3). This subtest
	// does not discharge it.
	t.Run("R11 untouched: no call_handle and no call content in any admin body", func(t *testing.T) {
		hs, adm, _ := newAdminServer(t, fakeclock.New(time.Unix(1_700_000_000, 0)))
		adm.AddUA(fakes.UA{UAHandle: "ua_7f2a", Session: "44b1c0de", ActiveCalls: 3})
		_, list := do(t, hs, "GET", "/admin/uas", adminToken, nil)
		_, del := do(t, hs, "DELETE", "/admin/uas/ua_7f2a", adminToken, nil)
		for _, body := range [][]byte{list, del} {
			for _, forbidden := range []string{"call_handle", "ladder", "events", "quality", "artifacts", "to_uri"} {
				if bytes.Contains(body, []byte(forbidden)) {
					t.Errorf("admin body contains %q: %s", forbidden, body)
				}
			}
		}
	})

	t.Run("D11 point 5 untouched: no time-based destruction trigger", func(t *testing.T) {
		clk := fakeclock.New(time.Unix(1_700_000_000, 0))
		hs, adm, _ := newAdminServer(t, clk)
		adm.AddUA(fakes.UA{UAHandle: "ua_7f2a", Session: "44b1c0de", SessionConnected: false})
		clk.Advance(72 * time.Hour)
		_, body := do(t, hs, "GET", "/admin/uas", adminToken, nil)
		if !bytes.Contains(body, []byte("ua_7f2a")) {
			t.Fatalf("a live UA disappeared after 72h with no DELETE; the admin plane "+
				"adds NO time-based destruction trigger — a human decides, one UA at a time: %s", body)
		}
	})

	t.Run("§12.6 untouched: DELETE destroys, never transfers", func(t *testing.T) {
		hs, adm, _ := newAdminServer(t, fakeclock.New(time.Unix(1_700_000_000, 0)))
		adm.AddUA(fakes.UA{UAHandle: "ua_7f2a", Session: "44b1c0de"})
		if _, _ = do(t, hs, "DELETE", "/admin/uas/ua_7f2a", adminToken, nil); adm.OwnerOf("ua_7f2a") != "44b1c0de" {
			t.Fatal("DELETE moved the UA's ownership; §12.7 is NOT an adoption path")
		}
		if adm.Live("ua_7f2a") {
			t.Fatal("DELETE left the UA live; it destroys")
		}
	})

	t.Run("not an MCP tool: §14.6 passes unchanged in both configurations", func(t *testing.T) {
		// Configured.
		hs, _, _ := newAdminServer(t, fakeclock.New(time.Unix(1_700_000_000, 0)))
		id := initSession(t, hs, testToken)
		configured := listToolNames(t, hs, testToken, id)
		// Unset.
		hs2, _, _ := newTestServer(t, fakeclock.New(time.Unix(1_700_000_000, 0)), time.Hour)
		id2 := initSession(t, hs2, testToken)
		unset := listToolNames(t, hs2, testToken, id2)
		if !slices.Equal(configured, unset) {
			t.Fatalf("tool surface differs with the admin plane configured (%v) and unset (%v); "+
				"§12.7 registers NO tool", configured, unset)
		}
		want := append([]string(nil), P1Tools...)
		want = append(want, P2Tools...)
		want = append(want, P3Tools...)
		want = append(want, P4Tools...)
		sort.Strings(want)
		if !slices.Equal(configured, want) {
			t.Fatalf("tool surface = %v, want P1Tools + P2Tools + P3Tools + P4Tools = %v", configured, want)
		}
	})
}

// TestAdminAuditCarriesNoCredential: per D6 and §12.2, no bearer token, admin
// token or profile credential appears in an admin_action line. The full session
// id DOES appear, and that is §12.7's stated, deliberate exception.
func TestAdminAuditCarriesNoCredential(t *testing.T) {
	hs, adm, logBuf := newAdminServer(t, fakeclock.New(time.Unix(1_700_000_000, 0)))
	adm.AddUA(fakes.UA{UAHandle: "ua_7f2a", Session: "44b1c0de", Registered: true, ActiveCalls: 2})

	_, _ = do(t, hs, "GET", "/admin/uas", adminToken, nil)
	_, _ = do(t, hs, "DELETE", "/admin/uas/ua_7f2a", adminToken, nil)

	logged := logBuf.Bytes()
	for _, secret := range []string{adminToken, testToken} {
		if bytes.Contains(logged, []byte(secret)) {
			t.Fatalf("audit log contains a token: %s", logged)
		}
	}
	if !bytes.Contains(logged, []byte("44b1c0de")) {
		t.Fatal("audit log does not carry the full session id; §12.7 requires it " +
			"UNREDACTED so an operator can correlate a stranded UA with the session that stranded it")
	}
}
