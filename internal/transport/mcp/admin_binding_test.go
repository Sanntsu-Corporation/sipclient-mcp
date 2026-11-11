package mcp

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

// TestAdminScopedToolsWiredAndGated (P2-T8): config_get, config_set and
// admin_token_rotate each reach their OWN handler (not each other's — the
// three-way fake-Tools call count is the same "wired to the right method"
// assertion TestP3ToolsAreCallableAndReachTheirOwnHandler makes for
// dtmf_send/dtmf_received) when called with the admin token, and are
// DENIED — not a protocol error, a §11.2 `denied` envelope — when called
// with the ordinary bearer token.
func TestAdminScopedToolsWiredAndGated(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	tools := fakes.NewTools()
	store, _ := testPolicyStore(t, clk, testToken, adminToken)
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour), Tools: tools,
		Policy: store, Log: discardLogger(), Clock: clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	adminID := initSession(t, hs, adminToken)
	bearerID := initSession(t, hs, testToken)

	cases := []struct {
		name string
		args string
	}{
		{"config_get", "{}"},
		{"config_set", `{"key":"limits.max_uas_total","value":5}`},
		{"admin_token_rotate", "{}"},
	}
	for _, tc := range cases {
		if isErr, text := callTool(t, hs, adminToken, adminID, tc.name, tc.args); isErr {
			t.Fatalf("%s with the admin token: protocol error: %s", tc.name, text)
		} else if strings.Contains(text, `"ok":false`) {
			t.Fatalf("%s with the admin token: got an error envelope, want success: %s", tc.name, text)
		}
		if calls := tools.CallsFor(tc.name); len(calls) != 1 {
			t.Fatalf("%s: called %d times via the admin session, want exactly 1 -- not wired to its own handler",
				tc.name, len(calls))
		}

		if isErr, text := callTool(t, hs, testToken, bearerID, tc.name, tc.args); isErr {
			t.Fatalf("%s with the bearer token: protocol error: %s", tc.name, text)
		} else if !strings.Contains(text, `"code":"denied"`) {
			t.Fatalf("%s with the bearer token: want a denied envelope, got: %s", tc.name, text)
		}
		// The denial must never have reached the fake handler a second time.
		if calls := tools.CallsFor(tc.name); len(calls) != 1 {
			t.Fatalf("%s: called %d times total, want the bearer-token call to have been gated BEFORE the handler", tc.name, len(calls))
		}
	}
}

// TestIdentityStoreIsAdmin (P2-T5, white-box): bind's admin flag is what
// isAdmin reports back, and an unknown or forgotten id reports false -- the
// SAME single-unknown-id non-disclosure rule matches already applies.
func TestIdentityStoreIsAdmin(t *testing.T) {
	s := newIdentityStore()
	adminID := newSessionID()
	bearerID := newSessionID()

	s.bind(adminID, []byte("admin-tok"), true)
	s.bind(bearerID, []byte("bearer-tok"), false)

	if !s.isAdmin(adminID) {
		t.Error("isAdmin(adminID) = false, want true")
	}
	if s.isAdmin(bearerID) {
		t.Error("isAdmin(bearerID) = true, want false")
	}
	if s.isAdmin(newSessionID()) {
		t.Error("isAdmin(unknown id) = true, want false")
	}
	if s.isAdmin("") {
		t.Error("isAdmin(\"\") = true, want false")
	}

	s.forget(adminID)
	if s.isAdmin(adminID) {
		t.Error("isAdmin(adminID) = true after forget, want false")
	}
}

// TestSessionBoundToAdminTokenReportsIsAdminTrue (P2-T5): a real MCP
// initialize with the admin token binds admin=true; one with the ordinary
// bearer token binds admin=false; one with an unrecognised token gets no
// session at all (bearerAuth still rejects it, §2.4's "accepts EITHER
// token" only widens the set to two, not to "any token").
func TestSessionBoundToAdminTokenReportsIsAdminTrue(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	store, _ := testPolicyStore(t, clk, testToken, adminToken)
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour),
		Tools:    fakes.NewTools(),
		Policy:   store,
		Log:      discardLogger(),
		Clock:    clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	_, adminID := post(t, hs, adminToken, "", initBody)
	if adminID == "" {
		t.Fatal("initialize with the admin token issued no session id")
	}
	if !srv.identity.isAdmin(adminID) {
		t.Error("session initialized with the admin token: isAdmin = false, want true")
	}

	_, bearerID := post(t, hs, testToken, "", initBody)
	if bearerID == "" {
		t.Fatal("initialize with the bearer token issued no session id")
	}
	if srv.identity.isAdmin(bearerID) {
		t.Error("session initialized with the bearer token: isAdmin = true, want false")
	}

	code, wrongID := post(t, hs, "totally-wrong-token", "", initBody)
	if wrongID != "" {
		t.Errorf("initialize with an unrecognised token issued a session id %q, want none", wrongID)
	}
	if code != 401 {
		t.Errorf("initialize with an unrecognised token: status = %d, want 401", code)
	}
}

// TestAdminBindingDroppedWhenSessionDies (P2-T5): resolve's existing forget
// path (server.go) drops a dead id's ordinary binding; this asserts the
// SAME drop removes the admin flag too, since binding is one struct, not
// two independent maps that could desync.
func TestAdminBindingDroppedWhenSessionDies(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	sess := fakes.NewSessions(clk, time.Hour)
	store, _ := testPolicyStore(t, clk, testToken, adminToken)
	srv, err := NewServer(Config{
		Sessions: sess,
		Tools:    fakes.NewTools(),
		Policy:   store,
		Log:      discardLogger(),
		Clock:    clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	id := newSessionID()
	srv.identity.bind(id, []byte(adminToken), true)
	if !srv.identity.isAdmin(id) {
		t.Fatal("precondition: isAdmin must be true right after bind")
	}

	// The fake Sessions never had Open(id) called, so Alive(id) is false and
	// resolve() takes the forget branch.
	if srv.resolve(id, []byte(adminToken)) {
		t.Fatal("resolve() on a never-opened id must be false")
	}
	if srv.identity.isAdmin(id) {
		t.Error("isAdmin still true after resolve() dropped a dead id's binding")
	}
}

// TestAdminTokenRotationRaceLeavesBindingsConsistent (P2-T5, -race): a
// stream of admin-token initializes races a concurrent rotation of the
// admin token FILE's contents (what admin_token_rotate does internally,
// exercised here directly against the Store so this test does not need the
// session package's tool wiring). Every request that actually authenticated
// (got a non-empty session id back) must be bound admin=true: bearerAuth
// reads exactly ONE Policy.Current() snapshot per request and
// sessionIDMiddleware binds from that SAME snapshot's decision
// (adminFromContext), so which generation of the token was live at
// authentication time is irrelevant -- the request is bound to what it was
// actually authenticated against.
//
// Mutation (per the plan): recompute MatchesAdminToken inside onIssue
// instead of reading adminFromContext, and this reddens, because onIssue's
// independent Policy.Current() read can observe a DIFFERENT (later-rotated)
// policy than the one bearerAuth authenticated the request against.
func TestAdminTokenRotationRaceLeavesBindingsConsistent(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	store, policyPath := testPolicyStore(t, clk, testToken, adminToken)
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour),
		Tools:    fakes.NewTools(),
		Policy:   store,
		Log:      discardLogger(),
		Clock:    clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	adminFile := filepath.Join(filepath.Dir(policyPath), "admin.token")

	type result struct {
		id    string
		admin bool
	}
	fire := func(out *result) {
		_, id := post(t, hs, adminToken, "", initBody)
		out.id = id
		if id != "" {
			out.admin = srv.identity.isAdmin(id)
		}
	}

	// Phase A: a batch of admin-token initializes run to completion BEFORE
	// any rotation starts, so this test always has at least one guaranteed
	// authenticated data point regardless of how the scheduler interleaves
	// phase B below -- the assertion is never vacuously true because
	// everything happened to get rejected.
	const preN = 10
	pre := make([]result, preN)
	{
		var wg sync.WaitGroup
		wg.Add(preN)
		for i := 0; i < preN; i++ {
			go func(i int) { defer wg.Done(); fire(&pre[i]) }(i)
		}
		wg.Wait()
	}

	// Phase B: a second batch races a concurrent rotation of the admin
	// token FILE's contents -- writing a fresh value and reloading, the
	// same two operations admin_token_rotate performs inside Store.Mutate.
	// Once rotated, the ORIGINAL adminToken stops authenticating, so
	// requests still presenting it increasingly 401 (empty id) as the
	// rotations land -- expected, and why the assertion below only checks
	// requests that actually got a session id.
	const raceN = 30
	race := make([]result, raceN)
	var wg sync.WaitGroup
	wg.Add(raceN)
	for i := 0; i < raceN; i++ {
		go func(i int) { defer wg.Done(); fire(&race[i]) }(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			newTok, err := policy.GenerateToken()
			if err != nil {
				t.Errorf("GenerateToken: %v", err)
				return
			}
			if err := policy.WriteSecretFile(adminFile, newTok); err != nil {
				t.Errorf("WriteSecretFile: %v", err)
				return
			}
			if err := store.Reload(); err != nil {
				t.Errorf("Reload: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	authenticated := 0
	for _, r := range append(pre, race...) {
		if r.id == "" {
			continue // rejected by a rotation that had already landed; not this test's concern
		}
		authenticated++
		if !r.admin {
			t.Errorf("request (id %s): isAdmin = false, want true (it presented the admin token and got a session)", r.id)
		}
	}
	if authenticated == 0 {
		t.Fatal("every request was rejected -- the race window never actually overlapped a valid admin request; test is not exercising anything")
	}
}

// TestAdminTokenRotateRebindsTheCallingSession is SEC-2's regression pin.
//
// THE BUG IT PINS — identityStore.bind records sha256(the token presented at
// initialize) and nothing rewrote it. After a successful admin_token_rotate
// the caller's id was still bound to the OLD token's digest, so the caller
// had no working credential left at all: the old token is rejected outright
// by bearerAuth (the digest was recomputed from the rotated file) and the new
// one authenticates but does not match the binding, so resolve() calls the id
// unknown and the very next tool call 404s with nothing explaining why.
// Rotating your admin token silently killed the session that rotated it.
//
// IT DRIVES THE REGISTERED TOOL OVER HTTP, NOT rebindAfterRotate DIRECTLY.
// The earlier version of this test built `rebindAfterRotate(srv,
// srv.cfg.Tools.AdminTokenRotate)` by hand and called it, which made its own
// claim of catching an unwired wrapper FALSE: deleting the rebindAfterRotate
// call from registerTools left the whole suite green, because the test
// reconstructed the wrapper it was supposed to be checking was installed.
// Going through initialize + tools/call means the ONLY admin_token_rotate
// that runs is the one registerTools actually registered.
//
// Mutation check (verified): drop the s.identity.rebind call from
// rebindAfterRotate, or unwrap t.AdminTokenRotate in registerTools, and this
// test reddens.
func TestAdminTokenRotateRebindsTheCallingSession(t *testing.T) {
	const newToken = "the-freshly-minted-admin-token"
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	tools := fakes.NewTools()
	tools.SetPayload("admin_token_rotate", map[string]any{"admin_token": newToken})
	store, _ := testPolicyStore(t, clk, testToken, adminToken)
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour), Tools: tools,
		Policy: store, Log: discardLogger(), Clock: clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	id := initSession(t, hs, adminToken)
	if !srv.identity.matches(id, []byte(adminToken)) {
		t.Fatal("precondition: initialize must bind the session to the token it presented")
	}

	if isErr, text := callTool(t, hs, adminToken, id, "admin_token_rotate", "{}"); isErr {
		t.Fatalf("admin_token_rotate: protocol error: %s", text)
	} else if strings.Contains(text, `"ok":false`) {
		t.Fatalf("admin_token_rotate returned an error envelope, want success: %s", text)
	}

	if !srv.identity.matches(id, []byte(newToken)) {
		t.Error("after admin_token_rotate the calling session is NOT bound to the new token: " +
			"its next request 404s under §12.6's unknown-id rule, so rotating locks the rotator out")
	}
	if srv.identity.matches(id, []byte(adminToken)) {
		t.Error("after admin_token_rotate the calling session still matches the OLD token, " +
			"which bearerAuth now rejects outright")
	}
	// The capability decided at bind time is NOT what rotation rewrites.
	if !srv.identity.isAdmin(id) {
		t.Error("rebinding cleared the session's admin flag; only the token digest may change")
	}
}

// TestRebindLeavesAnUnboundIDAlone: binding is initialize's job. A rotate
// arriving on an id that was never bound must not conjure one — that would
// hand a session to a caller that never authenticated.
func TestRebindLeavesAnUnboundIDAlone(t *testing.T) {
	s := newIdentityStore()
	id := newSessionID()
	s.rebind(id, []byte("some-token"))
	if s.matches(id, []byte("some-token")) {
		t.Error("rebind created a binding for an id that was never bound")
	}
}

// TestAdminTokenRotateDoesNotRebindOnFailure: a rotation that errored
// changed no token file, so the caller's binding must be left exactly as it
// was. Re-binding on the error path would break the session over a rotation
// that never happened.
func TestAdminTokenRotateDoesNotRebindOnFailure(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	tools := fakes.NewTools()
	tools.SetErr("admin_token_rotate", apierr.Internal("", "rotation failed"))
	store, _ := testPolicyStore(t, clk, testToken, adminToken)
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour), Tools: tools,
		Policy: store, Log: discardLogger(), Clock: clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	id := newSessionID()
	srv.identity.bind(id, []byte(adminToken), true)

	rotate := rebindAfterRotate(srv, srv.cfg.Tools.AdminTokenRotate)
	if _, err := rotate(context.Background(), id, session.AdminTokenRotateInput{}); err == nil {
		t.Fatal("scripted admin_token_rotate failure returned no error")
	}
	if !srv.identity.matches(id, []byte(adminToken)) {
		t.Error("a FAILED rotation re-bound the session away from the token it still holds")
	}
}
