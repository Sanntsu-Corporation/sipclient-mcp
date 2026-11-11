package mcp

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

// newTestServer is THE test-server constructor for this package (Rule 18 — there
// is no newTestHandler and no newTestEnv). It returns the running httptest
// server, the fake session registry and the *Server, so a test can reach
// StopAccepting, the identity store or the policy store directly.
//
// The admin plane is UNCONFIGURED here: testPolicyStore is given admin == "",
// so AdminEnabled() is false and /admin/* is not registered. Task 19's
// newAdminServer is the configured variant.
func newTestServer(t *testing.T, clk clock.Clock, window time.Duration) (*httptest.Server, *fakes.Sessions, *Server) {
	t.Helper()
	sess := fakes.NewSessions(clk, window)
	store, _ := testPolicyStore(t, clk, testToken, "")
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
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs, sess, srv
}

// post issues one JSON-RPC request and returns the status and the
// Mcp-Session-Id response header.
//
// D195: this helper is called from non-test goroutines by
// TestConcurrentReconnectUnderOneIdentity, so it MUST NOT call t.Fatalf —
// t.Fatalf calls runtime.Goexit, which is a testing API violation off the
// test goroutine. Errors report via t.Errorf and return zero values instead.
func post(t *testing.T, hs *httptest.Server, token, sessionID, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, hs.URL+"/mcp", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Errorf("NewRequest: %v", err)
		return 0, ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if sessionID != "" {
		req.Header.Set(sessionIDHeader, sessionID)
	}
	resp, err := hs.Client().Do(req)
	if err != nil {
		t.Errorf("Do: %v", err)
		return 0, ""
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header.Get(sessionIDHeader)
}

// do issues a plain HTTP request and returns the status and the whole body.
func do(t *testing.T, hs *httptest.Server, method, path, token string, body io.Reader) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, hs.URL+path, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hs.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return resp.StatusCode, out
}

const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":` +
	`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`

const nonInitBody = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`

// initSession performs an initialize and returns the issued session id.
func initSession(t *testing.T, hs *httptest.Server, token string) string {
	t.Helper()
	code, id := post(t, hs, token, "", initBody)
	if code != http.StatusOK {
		t.Fatalf("initialize status = %d, want 200", code)
	}
	if len(id) != 32 {
		t.Fatalf("issued Mcp-Session-Id = %q, want 32 hex chars", id)
	}
	return id
}

// TestSessionIdentityMatrix is §12.6's acceptance and §14.2's requirement that
// the matrix be run twice, so the SINGLE unknown-id rule is pinned in both
// halves: on an initialize an unknown id is IGNORED and a fresh session is
// issued; on any non-initialize request the server returns 404.
func TestSessionIdentityMatrix(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	hs, _, _ := newTestServer(t, clk, time.Hour)

	known := initSession(t, hs, testToken)
	fabricated := newSessionID()

	tests := []struct {
		name string
		id   string
		// wantInitStatus is the status for the same case sent as an initialize.
		wantInitStatus int
		// wantInitFresh is whether the initialize must issue an id different
		// from the one presented.
		wantInitFresh bool
		// wantNonInitStatus is the status for the same case sent as a
		// non-initialize request.
		wantNonInitStatus int
	}{
		{"same token, same id", known, http.StatusOK, true, http.StatusOK},
		{"same token, absent id", "", http.StatusOK, true, http.StatusNotFound},
		{"same token, fabricated id", fabricated, http.StatusOK, true, http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name+"/initialize", func(t *testing.T) {
			code, issued := post(t, hs, testToken, tc.id, initBody)
			if code != tc.wantInitStatus {
				t.Fatalf("status = %d, want %d", code, tc.wantInitStatus)
			}
			if issued == "" {
				t.Fatal("initialize issued no Mcp-Session-Id")
			}
			if tc.wantInitFresh && issued == tc.id {
				t.Fatalf("initialize returned the presented id %q; §12.6 requires a FRESH session", issued)
			}
		})
		t.Run(tc.name+"/non-initialize", func(t *testing.T) {
			code, _ := post(t, hs, testToken, tc.id, nonInitBody)
			if code != tc.wantNonInitStatus {
				t.Fatalf("status = %d, want %d", code, tc.wantNonInitStatus)
			}
		})
	}
}

// TestSharedTokenDoesNotMergeSessions is the §12.6 consequence that keeps
// §12.2's isolation meaningful when one operator token serves several agents.
func TestSharedTokenDoesNotMergeSessions(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	hs, _, _ := newTestServer(t, clk, time.Hour)

	a := initSession(t, hs, testToken)
	b := initSession(t, hs, testToken)
	if a == b {
		t.Fatalf("two initialize calls on one bearer token returned the same id %q; "+
			"§12.6 requires DIFFERENT logical sessions", a)
	}
}

// TestStopAcceptingRefusesNewMCPRequestsOnly is §11.4 step 1. It is asserted
// HERE, at the transport layer, because the daemon (Task 20) reaches
// StopAccepting through the CONCRETE *mcp.Server — with a handler-only API
// the daemon would have to type-assert its own return value back to reach it.
func TestStopAcceptingRefusesNewMCPRequestsOnly(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	hs, _, srv := newTestServer(t, clk, time.Hour)

	id := initSession(t, hs, testToken)
	if code, _ := post(t, hs, testToken, id, nonInitBody); code != http.StatusOK {
		t.Fatalf("before StopAccepting: status = %d, want 200", code)
	}

	srv.StopAccepting()

	if code, _ := post(t, hs, testToken, id, nonInitBody); code != http.StatusServiceUnavailable {
		t.Fatalf("after StopAccepting: status = %d, want 503", code)
	}
	// The observability surface keeps answering so an orchestrator can watch
	// the drain complete.
	if code, body := do(t, hs, "GET", "/healthz", "", nil); code != http.StatusOK || string(body) != "ok" {
		t.Fatalf("GET /healthz during drain = %d %q, want 200 \"ok\"", code, body)
	}
}

// TestDifferentTokenSameID: a session id presented with a token it was NOT
// issued to is treated as UNKNOWN (§12.6), which means the same single rule
// applies — fresh session on initialize, 404 on anything else. A leaked
// session id transfers nothing on its own.
func TestDifferentTokenSameID(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	hs, _, srv := newTestServer(t, clk, time.Hour)

	id := initSession(t, hs, testToken)

	// Model a deployment where one bearer-token file holds several valid
	// tokens: the id is known to internal/session, but its BINDING names a
	// different token from the one presented.
	srv.identity.bind(id, []byte("a-different-token"), false)

	if code, _ := post(t, hs, testToken, id, nonInitBody); code != http.StatusNotFound {
		t.Fatalf("non-initialize with a mismatched binding: status = %d, want 404", code)
	}
	code, issued := post(t, hs, testToken, id, initBody)
	if code != http.StatusOK {
		t.Fatalf("initialize with a mismatched binding: status = %d, want 200", code)
	}
	if issued == id {
		t.Fatalf("initialize returned the presented id %q; a fresh session was required", issued)
	}
}

// TestResumeWindowOnlyAgesEmptySessions is §12.6's lifetime rule, driven by the
// FAKE CLOCK per §14.2's determinism requirement.
func TestResumeWindowOnlyAgesEmptySessions(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	hs, sess, _ := newTestServer(t, clk, 5*time.Second)

	empty := initSession(t, hs, testToken)
	live := initSession(t, hs, testToken)
	sess.AddLiveObject(live) // models ua_create

	clk.Advance(10 * time.Second)

	if code, _ := post(t, hs, testToken, empty, nonInitBody); code != http.StatusNotFound {
		t.Fatalf("empty session past the resume window: status = %d, want 404", code)
	}
	if code, _ := post(t, hs, testToken, live, nonInitBody); code != http.StatusOK {
		t.Fatalf("session owning a live UA: status = %d, want 200 — the window "+
			"must NEVER apply to a session with live objects", code)
	}

	clk.Advance(60 * time.Second)
	if code, _ := post(t, hs, testToken, live, nonInitBody); code != http.StatusOK {
		t.Fatalf("session owning a live UA after 70s: status = %d, want 200 (no deadline)", code)
	}

	sess.DropLiveObject(live) // models ua_destroy
	clk.Advance(10 * time.Second)
	if code, _ := post(t, hs, testToken, live, nonInitBody); code != http.StatusNotFound {
		t.Fatalf("now-empty session past the window: status = %d, want 404", code)
	}
}

// TestConcurrentReconnectUnderOneIdentity is §12.6's -race acceptance, at the
// transport layer. "Inbound INVITE" is modelled by the fake appending a live
// object to the session, because §6.2 forbids this package from importing
// internal/sipua. The wire-level half of this acceptance belongs to the
// loopback-harness task (P1e Task 23); NEITHER half alone discharges §12.6.
//
// D194: the "foreign" assertion below deliberately posts against the REAL
// second session id, bound to a DIFFERENT bearer token — not a fabricated
// string. A fabricated id would make this loop redundant with the fabricated
// case already exercised in TestSessionIdentityMatrix, and would pass with
// identityStore deleted entirely, proving nothing about binding.
//
// Beyond-D19x defect found while running this test: the SDK multiplexes every
// concurrent HTTP POST that names the SAME Mcp-Session-Id onto ONE shared
// jsonrpc2.Connection per session, which correlates a response to its request
// SOLELY by the JSON-RPC "id" field (github.com/modelcontextprotocol/go-sdk
// v1.6.1 streamable.go's per-session requestStreams map). A literal, repeated
// JSON-RPC id — such as the package's nonInitBody, which is fine for every
// OTHER (sequential) test in this file — collides across concurrently
// in-flight requests against the SAME session id: two overlapping "id":2
// calls overwrite each other's stream registration, and the loser's HTTP
// response never arrives, hanging that goroutine forever. Reproduced directly
// (not reasoned about): with the shared literal id, a 2-goroutine version of
// this test hung on roughly 1 run in 5; with a unique id per request, 10/10
// runs passed. Every request against the "id" session below therefore carries
// a unique JSON-RPC id. Requests against "foreign" keep the shared
// nonInitBody: they never reach the SDK at all (§12.6 404s them in
// sessionIDMiddleware before next.ServeHTTP), so no collision is possible.
func TestConcurrentReconnectUnderOneIdentity(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	hs, sess, srv := newTestServer(t, clk, time.Hour)

	id := initSession(t, hs, testToken)
	sess.AddLiveObject(id) // the session owns a live UA throughout

	// foreign is a REAL, alive session id, issued through the same public
	// initialize path as id — but then REBOUND to a different bearer token,
	// exactly as TestDifferentTokenSameID does, so it is genuinely unknown to
	// id's token (§12.6) rather than a fabricated string that never resolved
	// to anything. The test server accepts only testToken, so this is the
	// only way to construct a same-server "different token" case through a
	// real session id.
	foreign := initSession(t, hs, testToken)
	sess.AddLiveObject(foreign)
	srv.identity.bind(foreign, []byte("a-different-token"), false)

	var wg sync.WaitGroup
	start := make(chan struct{})
	const iterations = 50

	for i := 0; i < 20; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				// A unique JSON-RPC id per request — see the defect note
				// above. i and j together are unique across all 20*iterations
				// concurrently issued calls against the "id" session.
				body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`, i*iterations+j+1)
				if code, _ := post(t, hs, testToken, id, body); code != http.StatusOK {
					t.Errorf("reconnect: status = %d, want 200", code)
					return
				}
				// foreign is alive, but was never bound to testToken: this
				// session must never resolve it. Never reaches the SDK, so
				// the shared nonInitBody id cannot collide here.
				if code, _ := post(t, hs, testToken, foreign, nonInitBody); code != http.StatusNotFound {
					t.Errorf("foreign session id under testToken: status = %d, want 404", code)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for j := 0; j < iterations; j++ {
			sess.AddLiveObject(id) // inbound INVITE creates a call
			sess.DropLiveObject(id)
		}
	}()

	close(start)
	wg.Wait()
}

// TestNoAdoptionPath: §12.6 denies any mechanism by which one logical session
// acquires another's handles. This asserts the absence structurally — the
// registered tool set is pinned by this task's tool-surface test, and this
// test pins the names that would BE an adoption path if they ever appeared.
//
// D224: P1Tools must have exactly the 12 entries §10 defines for this phase
// (13 minus profile_list, removed in the session-scoped UA lifecycle wave —
// D1, owner-locked decision). Without this guard, an empty or accidentally-
// shortened P1Tools would make the loop below iterate zero times and pass
// vacuously — exactly how this test ran in isolation before TestToolSurface
// existed to cross-check P1Tools against a live tools/list round trip.
func TestNoAdoptionPath(t *testing.T) {
	if len(P1Tools) != 12 {
		t.Fatalf("P1Tools has %d entries, want 12; an empty or short list makes the loop below assert nothing", len(P1Tools))
	}
	for _, forbidden := range []string{"session_attach", "session_resume", "ua_adopt", "session_transfer"} {
		for _, name := range P1Tools {
			if name == forbidden {
				t.Fatalf("tool %q is registered; §12.6 exists to deny exactly this "+
					"adoption surface — ownership is assigned at ua_create and is IMMUTABLE", name)
			}
		}
	}
}

// TestInitializeFailsClosedWhenSessionOpenFails is the production-hardening
// spec's Task 3, transport-layer half: Manager.Open (internal/session) can
// now fail (the max_sessions_total cap), and server.go's issueRecorder
// already has fail-closed handling for that — this proves it actually
// works end to end, not just that the comment describing it is correct.
// The initialize itself still returns 200 with an id (issueRecorder learns
// of the failure only after the SDK has already set the response header —
// a known, accepted UX quirk), but the id is never bound to the caller's
// token, so the very next request using it must 404, exactly like a
// completely unknown id under §12.6's single disclose-nothing rule.
func TestInitializeFailsClosedWhenSessionOpenFails(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	hs, sess, _ := newTestServer(t, clk, time.Hour)
	sess.OpenErr = fmt.Errorf("session cap exceeded")

	code, id := post(t, hs, testToken, "", initBody)
	if code != http.StatusOK {
		t.Fatalf("initialize status = %d, want 200 (the SDK already committed before onIssue saw the Open failure)", code)
	}
	if id == "" {
		t.Fatal("initialize returned no Mcp-Session-Id; the test needs one to prove it's unusable")
	}

	code2, _ := post(t, hs, testToken, id, nonInitBody)
	if code2 != http.StatusNotFound {
		t.Fatalf("follow-up request with the failed-to-open id = %d, want 404 (fail closed: an id whose Open failed must never resolve)", code2)
	}
}
