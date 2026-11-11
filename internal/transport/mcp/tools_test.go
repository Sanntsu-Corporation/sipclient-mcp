package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

// extractEnvelope pulls the single JSON envelope out of a CallToolResult.
func extractEnvelope(t *testing.T, res *sdk.CallToolResult) map[string]any {
	t.Helper()
	if res == nil {
		t.Fatal("CallToolResult is nil")
	}
	if res.IsError {
		t.Fatal("CallToolResult.IsError is true; §11.1/§11.2 errors are the " +
			"ENVELOPE's ok:false, never an MCP protocol error — otherwise a denied " +
			"becomes indistinguishable from a transport fault")
	}
	if len(res.Content) != 1 {
		t.Fatalf("len(Content) = %d, want 1", len(res.Content))
	}
	txt, ok := res.Content[0].(*sdk.TextContent)
	if !ok {
		t.Fatalf("Content[0] is %T, want *sdk.TextContent", res.Content[0])
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(txt.Text), &out); err != nil {
		t.Fatalf("content is not JSON: %v (%s)", err, txt.Text)
	}
	return out
}

func TestToolAdapterEnvelopes(t *testing.T) {
	type in struct {
		Call string `json:"call"`
	}
	tests := []struct {
		name     string
		payload  any
		err      error
		wantOK   bool
		wantCode string
	}{
		{"success", map[string]any{"call_handle": "call_1"}, nil, true, ""},
		{"apierr", nil, apierr.NotFound("unknown"), false, "not_found"},
		{"unexpected", nil, errUnexpectedForTest, false, "internal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var sawSession string
			var sawInput in
			h := toolHandler(func(_ context.Context, sess string, i in) (any, error) {
				sawSession = sess
				sawInput = i
				return tc.payload, tc.err
			}, fixedCorrelation, discardLogger())

			// A zero-value CallToolRequest carries no Session. The adapter must
			// TOLERATE that and yield "" rather than panicking; the real
			// req.Session.ID() path is covered end to end in
			// TestToolCallCarriesTheLogicalSessionID.
			res, _, err := h(context.Background(), &sdk.CallToolRequest{}, in{Call: "call_1"})
			if err != nil {
				t.Fatalf("handler returned a Go error: %v — the envelope is the "+
					"only channel; a Go error here becomes an MCP protocol error", err)
			}
			if sawSession != "" {
				t.Fatalf("session id = %q, want \"\" for a request with no Session", sawSession)
			}
			if sawInput.Call != "call_1" {
				t.Fatalf("input not passed through: %+v", sawInput)
			}
			env := extractEnvelope(t, res)
			if env["ok"] != tc.wantOK {
				t.Fatalf("ok = %v, want %v", env["ok"], tc.wantOK)
			}
			if tc.wantCode != "" && env["code"] != tc.wantCode {
				t.Fatalf("code = %v, want %v", env["code"], tc.wantCode)
			}
		})
	}
}

func TestToolCallCarriesTheLogicalSessionID(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	tools := fakes.NewTools()
	sess := fakes.NewSessions(clk, time.Hour)
	store, _ := testPolicyStore(t, clk, testToken, "")
	srv, err := NewServer(Config{
		Sessions: sess, Tools: tools, Policy: store,
		Log: discardLogger(), Clock: clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	id := initSession(t, hs, testToken)
	tools.SetPayload("call_list", map[string]any{"calls": []any{}})

	code, _ := post(t, hs, testToken, id,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"call_list","arguments":{}}}`)
	if code != http.StatusOK {
		t.Fatalf("tools/call status = %d, want 200", code)
	}
	got := tools.LastSession("call_list")
	if got != id {
		t.Fatalf("tool saw session %q, want the issued §12.6 id %q — the tool "+
			"layer must scope handles by the logical session, not the connection", got, id)
	}
}

// n2ToolArgs supplies SCHEMA-VALID arguments for every P1 tool. D218/D219: the
// SDK validates arguments against the generated JSON schema BEFORE invoking
// the handler, and every *Input struct field without `omitempty` is marked
// required — so `{}` is rejected before the tool ever runs for every tool
// with at least one required field, and only session_keepalive, ua_status and
// call_list (which have none) reach the handler with empty arguments. A test
// that posts `{}` uniformly measures the SDK's validator, not the tool path.
var n2ToolArgs = map[string]string{
	"session_keepalive": `{}`,
	"ua_create":         `{"mode":"direct"}`,
	"ua_status":         `{}`,
	"ua_destroy":        `{"ua":"ua_1"}`,
	"call_dial":         `{"ua":"ua_1","to_uri":"sip:test@example.com"}`,
	"call_answer":       `{"call":"call_1"}`,
	"call_reject":       `{"call":"call_1"}`,
	"call_hangup":       `{"call":"call_1"}`,
	"call_status":       `{"call":"call_1"}`,
	"call_list":         `{}`,
	"call_events":       `{"call":"call_1"}`,
	"call_ladder":       `{"call":"call_1"}`,
	"call_wait":         `{"call":"call_1","until":"answered","timeout_ms":1000}`,
}

func TestN2LatencyBudget(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	tools := fakes.NewTools()
	// call_wait is the ONLY tool permitted to block (D2, N2, §10.5).
	tools.SetDelay("call_wait", 300*time.Millisecond)

	store, _ := testPolicyStore(t, clk, testToken, "")
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour), Tools: tools,
		Policy: store, Log: discardLogger(), Clock: clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	id := initSession(t, hs, testToken)

	// Warm the HTTP path ONCE, untimed: the first request pays connection setup and
	// SDK handler warm-up that would otherwise be charged to whichever non-blocking
	// subtest runs first (observed as ua_status flaking the 50ms N2 budget). This
	// does NOT relax the budget — every subtest below is still asserted < 50ms.
	tools.SetPayload("call_list", map[string]any{})
	_, _ = post(t, hs, testToken, id,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_list","arguments":{}}}`)

	nonBlocking := []string{
		"session_keepalive", "ua_create", "ua_status", "ua_destroy",
		"call_dial", "call_answer", "call_reject", "call_hangup",
		"call_status", "call_list", "call_events", "call_ladder",
	}
	for _, name := range nonBlocking {
		t.Run(name, func(t *testing.T) {
			tools.SetPayload(name, map[string]any{})
			body := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"` +
				name + `","arguments":` + n2ToolArgs[name] + `}}`
			start := time.Now()
			if code, _ := post(t, hs, testToken, id, body); code != http.StatusOK {
				t.Fatalf("status = %d, want 200", code)
			}
			if len(tools.CallsFor(name)) == 0 {
				t.Fatalf("%s: SDK rejected the arguments before the handler ran; this subtest measured the validator, not the tool path", name)
			}
			if d := time.Since(start); d > 50*time.Millisecond {
				t.Fatalf("%s took %v, N2 budget is < 50ms", name, d)
			}
		})
	}

	t.Run("call_wait blocks", func(t *testing.T) {
		tools.SetPayload("call_wait", map[string]any{"timed_out": true})
		body := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"call_wait","arguments":` +
			n2ToolArgs["call_wait"] + `}}`
		start := time.Now()
		if code, _ := post(t, hs, testToken, id, body); code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		if len(tools.CallsFor("call_wait")) == 0 {
			t.Fatalf("call_wait: SDK rejected the arguments before the handler ran; this subtest measured the validator, not the tool path")
		}
		if d := time.Since(start); d < 250*time.Millisecond {
			t.Fatalf("call_wait returned in %v; it is the one tool that blocks", d)
		}
	})
}

// listToolNames issues a tools/list JSON-RPC request and returns the sorted
// tool names.
//
// D221: this needs its own request rather than the package's `post` helper,
// which discards the response body. The streamable HTTP transport frames a
// JSON-RPC response as SSE — "event: message\ndata: {...}\n\n" — observed
// directly against the real SDK, not assumed from the spec's JSON-RPC
// examples, so the data line is located by its "data: " prefix and the rest
// of the frame is decoded as the JSON-RPC envelope.
func listToolNames(t *testing.T, hs *httptest.Server, token, sessionID string) []string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, hs.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":6,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(sessionIDHeader, sessionID)

	resp, err := hs.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list status = %d, want 200: %s", resp.StatusCode, raw)
	}

	const dataPrefix = "data: "
	var data []byte
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, dataPrefix) {
			data = []byte(strings.TrimPrefix(line, dataPrefix))
			break
		}
	}
	if data == nil {
		t.Fatalf("tools/list response carries no SSE \"data: \" line: %s", raw)
	}

	var parsed struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("tools/list data is not JSON: %v (%s)", err, data)
	}
	names := make([]string, 0, len(parsed.Result.Tools))
	for _, tl := range parsed.Result.Tools {
		names = append(names, tl.Name)
	}
	sort.Strings(names)
	return names
}

// TestToolSurface is §14.6's enumeration test.
//
// §14.6 as written requires the registered set to equal "the §10 list exactly".
// AT P1 THAT IS UNSATISFIABLE: media_*, dtmf_*, quality_get, capture_* and
// session_webhook_set have no implementation at this phase, and registering
// them would advertise capabilities that can only fail. This is a genuine
// spec-vs-phase conflict, resolved — and recorded in the P1 closeout — by
// asserting against a phase-declared set PLUS two assertions that preserve the
// property §14.6 exists for: nothing can be added or dropped without failing.
func TestToolSurface(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	store, _ := testPolicyStore(t, clk, testToken, "")
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour),
		Tools:    fakes.NewTools(), Policy: store,
		Log: discardLogger(), Clock: clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	id := initSession(t, hs, testToken)

	registered := listToolNames(t, hs, testToken, id) // tools/list, sorted

	want := append([]string(nil), P1Tools...)
	want = append(want, P2Tools...)
	want = append(want, P3Tools...)
	want = append(want, P4Tools...)
	sort.Strings(want)
	if !slices.Equal(registered, want) {
		t.Fatalf("registered tools = %v, want P1Tools + P2Tools + P3Tools + P4Tools = %v", registered, want)
	}

	// (1) Union pins the §10 list: a §10 tool can be neither dropped nor
	//     invented without failing here.
	union := append([]string(nil), P1Tools...)
	union = append(union, P2Tools...)
	union = append(union, P3Tools...)
	union = append(union, P4Tools...)
	for name := range DeferredTools {
		union = append(union, name)
	}
	sort.Strings(union)
	full := append([]string(nil), Section10ToolNames...)
	sort.Strings(full)
	if !slices.Equal(union, full) {
		t.Fatalf("P1Tools + P2Tools + P3Tools + P4Tools + DeferredTools = %v, want the §10 list %v", union, full)
	}

	// (2) The four sets are pairwise disjoint: a tool cannot be registered
	//     under more than one of P1Tools, P2Tools, P3Tools, P4Tools and
	//     DeferredTools.
	for _, name := range append(append(append(append([]string(nil), P1Tools...), P2Tools...), P3Tools...), P4Tools...) {
		if phase, dup := DeferredTools[name]; dup {
			t.Fatalf("%q is registered AND declared deferred to %s", name, phase)
		}
	}
	for _, name := range P2Tools {
		if slices.Contains(P1Tools, name) {
			t.Fatalf("%q is in both P1Tools and P2Tools", name)
		}
	}
	for _, name := range P3Tools {
		if slices.Contains(P1Tools, name) || slices.Contains(P2Tools, name) {
			t.Fatalf("%q is in P3Tools and also in P1Tools or P2Tools", name)
		}
	}
	for _, name := range P4Tools {
		if slices.Contains(P1Tools, name) || slices.Contains(P2Tools, name) || slices.Contains(P3Tools, name) {
			t.Fatalf("%q is in P4Tools and also in P1Tools, P2Tools or P3Tools", name)
		}
	}

	// (3) The §12.7 HTTP admin plane (/admin/uas, DELETE /admin/uas/{h}) is
	// NOT a tool and appears in NEITHER list. admin_token_rotate is a
	// DELIBERATE, NAMED EXCEPTION (Phase 2 §2.2 item 5, §2.4a): it is an
	// admin-SCOPED MCP tool (gated by identityStore.isAdmin, not an
	// unauthenticated or bearer-token-reachable route), not the HTTP admin
	// plane this check exists to keep off the tool surface. A future
	// "admin_*" name other than this one still trips the check below.
	for _, name := range append(union, registered...) {
		if name == "admin_token_rotate" {
			continue
		}
		if strings.HasPrefix(name, "admin") || strings.Contains(name, "/admin") {
			t.Fatalf("%q looks like the §12.7 admin plane; it registers no tool "+
				"and never appears in the §10 tool surface", name)
		}
	}
}

func TestMediaToolsAreRegisteredNotDeferred(t *testing.T) {
	for _, name := range []string{"media_play", "media_record_start", "media_record_stop"} {
		if _, deferred := DeferredTools[name]; deferred {
			t.Fatalf("%s is still in DeferredTools", name)
		}
		found := false
		for _, p := range P2Tools {
			if p == name {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s not in P2Tools", name)
		}
	}
}

func TestP3ToolsAreRegisteredAndNoLongerDeferred(t *testing.T) {
	for _, name := range P3Tools {
		if phase, deferred := DeferredTools[name]; deferred {
			t.Fatalf("%s is registered by P3Tools but still deferred to %s", name, phase)
		}
	}
	want := map[string]bool{"dtmf_send": true, "dtmf_received": true}
	got := map[string]bool{}
	for _, n := range P3Tools {
		got[n] = true
	}
	if len(got) != len(want) {
		t.Fatalf("P3Tools = %v want exactly dtmf_send and dtmf_received", P3Tools)
	}
	for n := range want {
		if !got[n] {
			t.Fatalf("P3Tools is missing %s", n)
		}
	}
}

func TestEveryToolInSection10IsEitherRegisteredOrDeferred(t *testing.T) {
	registered := map[string]bool{}
	for _, set := range [][]string{P1Tools, P2Tools, P3Tools, P4Tools} {
		for _, n := range set {
			if registered[n] {
				t.Fatalf("%s is registered by two phase sets", n)
			}
			registered[n] = true
		}
	}
	for _, n := range Section10ToolNames {
		_, deferred := DeferredTools[n]
		if registered[n] == deferred {
			t.Fatalf("%s: registered=%v deferred=%v — every §10 tool must be exactly one of the two",
				n, registered[n], deferred)
		}
	}
	for n := range DeferredTools {
		if !slices.Contains(Section10ToolNames, n) {
			t.Fatalf("DeferredTools names %s, which is not a §10 tool", n)
		}
	}
	for n := range registered {
		if !slices.Contains(Section10ToolNames, n) {
			t.Fatalf("%s is registered but is not a §10 tool", n)
		}
	}
}

// callTool issues one tools/call and returns the decoded JSON-RPC result. It
// reuses listToolNames' SSE-framing discovery (D221); the package's `post`
// helper cannot serve here because it discards the body, and a SCHEMA
// REJECTION is an HTTP 200 whose result carries isError — invisible to a
// status-code-only assertion.
func callTool(t *testing.T, hs *httptest.Server, token, sessionID, name, args string) (isError bool, text string) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
	req, err := http.NewRequest(http.MethodPost, hs.URL+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(sessionIDHeader, sessionID)
	resp, err := hs.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	var data []byte
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "data: ") {
			data = []byte(strings.TrimPrefix(line, "data: "))
			break
		}
	}
	if data == nil {
		t.Fatalf("tools/call response carries no SSE \"data: \" line: %s", raw)
	}
	var parsed struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("tools/call data is not JSON: %v (%s)", err, data)
	}
	if len(parsed.Result.Content) != 1 {
		t.Fatalf("len(content) = %d, want 1: %s", len(parsed.Result.Content), data)
	}
	return parsed.Result.IsError, parsed.Result.Content[0].Text
}

// TestP3ToolsAreCallableAndReachTheirOwnHandler is the assertion that a
// name-only registration test cannot make: that `dtmf_send` is wired to
// DTMFSend and `dtmf_received` to DTMFReceived. Both handlers satisfy
// registerTool's generic signature, so swapping them COMPILES and passes every
// set-membership test — the schema published under each name and the input
// struct the handler decodes are the only observable difference.
func TestP3ToolsAreCallableAndReachTheirOwnHandler(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	tools := fakes.NewTools()
	store, _ := testPolicyStore(t, clk, testToken, "")
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour), Tools: tools,
		Policy: store, Log: discardLogger(), Clock: clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	id := initSession(t, hs, testToken)

	// gap_ms: 0 is the discriminating argument. It is NOT the zero value of
	// the decoded field — DTMFSendInput.GapMs is *int, so an explicit 0 must
	// arrive as a non-nil pointer to 0 and an omitted gap_ms as nil. A plain
	// int would make this assertion vacuous.
	if isErr, text := callTool(t, hs, testToken, id, "dtmf_send",
		`{"call":"call_1","digits":"123*#","mode":"info","duration_ms":120,"gap_ms":0}`); isErr {
		t.Fatalf("dtmf_send rejected its own §10.8 arguments: %s", text)
	}
	calls := tools.CallsFor("dtmf_send")
	if len(calls) != 1 {
		t.Fatalf("DTMFSend was called %d times, want 1 — dtmf_send is wired to another handler", len(calls))
	}
	in, ok := calls[0].In.(session.DTMFSendInput)
	if !ok {
		t.Fatalf("dtmf_send decoded a %T, want session.DTMFSendInput", calls[0].In)
	}
	if in.Call != "call_1" || in.Digits != "123*#" || in.Mode != "info" || in.DurationMs != 120 {
		t.Fatalf("dtmf_send decoded %+v, want call_1/123*#/info/120", in)
	}
	if in.GapMs == nil || *in.GapMs != 0 {
		t.Fatalf("gap_ms = %v, want a non-nil pointer to 0 — an explicit \"no gap\" must not collapse into absent", in.GapMs)
	}
	if isErr, text := callTool(t, hs, testToken, id, "dtmf_send",
		`{"call":"call_1","digits":"1"}`); isErr {
		t.Fatalf("dtmf_send rejected an omitted gap_ms: %s", text)
	}
	if in := tools.CallsFor("dtmf_send")[1].In.(session.DTMFSendInput); in.GapMs != nil {
		t.Fatalf("an omitted gap_ms decoded as %v, want nil", *in.GapMs)
	}
	// The third tri-state leg (Cycle 4 / C4-A, item A3). The two above pin
	// absent-vs-explicit-zero, which is the interesting half; without this one
	// nothing at THIS boundary shows the pointer ever carries a value other
	// than the zero it was compared against, so a decoder that returned a
	// pointer-to-zero for every present gap_ms would satisfy both of them.
	// (session.DTMFSendInput is pinned for a positive value in
	// toolservice_media_test.go, but as a Go struct — never through the MCP
	// JSON-schema decode this test exists to cover.)
	if isErr, text := callTool(t, hs, testToken, id, "dtmf_send",
		`{"call":"call_1","digits":"1","gap_ms":40}`); isErr {
		t.Fatalf("dtmf_send rejected an explicit positive gap_ms: %s", text)
	}
	switch in := tools.CallsFor("dtmf_send")[2].In.(session.DTMFSendInput); {
	case in.GapMs == nil:
		t.Fatal("an explicit gap_ms of 40 decoded as nil, want a non-nil pointer to 40")
	case *in.GapMs != 40:
		t.Fatalf("an explicit gap_ms of 40 decoded as %d, want 40", *in.GapMs)
	}

	if isErr, text := callTool(t, hs, testToken, id, "dtmf_received",
		`{"call":"call_1","since":9}`); isErr {
		t.Fatalf("dtmf_received rejected its own §10.8 arguments: %s", text)
	}
	rcv := tools.CallsFor("dtmf_received")
	if len(rcv) != 1 {
		t.Fatalf("DTMFReceived was called %d times, want 1 — dtmf_received is wired to another handler", len(rcv))
	}
	rin, ok := rcv[0].In.(session.DTMFReceivedInput)
	if !ok {
		t.Fatalf("dtmf_received decoded a %T, want session.DTMFReceivedInput", rcv[0].In)
	}
	// since: 9, not 0 — 0 is both the default and the zero value.
	if rin.Call != "call_1" || rin.Since != 9 {
		t.Fatalf("dtmf_received decoded %+v, want call_1/9", rin)
	}
}

func TestServerAdvertisesTheP3Tools(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	hs, _, _ := newTestServer(t, clk, time.Hour)
	id := initSession(t, hs, testToken)
	names := listToolNames(t, hs, testToken, id)
	for _, want := range P3Tools {
		if !slices.Contains(names, want) {
			t.Fatalf("the server does not advertise %s: %v", want, names)
		}
	}
}

// TestDTMFSendSchemaAdvertisesItsBounds is the schema half of the dtmf_send
// bounds fix. checkDTMFSendBounds (internal/session/toolservice.go) ENFORCES
// them; a model only learns they exist from the published inputSchema, and a
// tool whose arguments are silently range-checked is a tool a model mis-scales.
//
// The assertion is on the DESCRIPTIONS, not on `maximum` keywords, and that is
// deliberate: the render budget is limits.max_call_duration_s, which SIGHUP can
// change under a running daemon, so a numeric maximum baked into the schema
// would be a second copy of a value that moves.
func TestDTMFSendSchemaAdvertisesItsBounds(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	store, _ := testPolicyStore(t, clk, testToken, "")
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour), Tools: fakes.NewTools(),
		Policy: store, Log: discardLogger(), Clock: clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	id := initSession(t, hs, testToken)

	props := toolInputProperties(t, hs, testToken, id, "dtmf_send")
	for _, field := range []string{"digits", "duration_ms", "gap_ms"} {
		p, ok := props[field].(map[string]any)
		if !ok {
			t.Fatalf("dtmf_send inputSchema has no %q property: %v", field, props)
		}
		desc, _ := p["description"].(string)
		if !strings.Contains(desc, "max_call_duration_s") {
			t.Fatalf("dtmf_send.%s description = %q — it must tell the model the "+
				"argument is bounded, or the bound is invisible until the call fails", field, desc)
		}
	}
	for _, field := range []string{"duration_ms", "gap_ms"} {
		desc, _ := props[field].(map[string]any)["description"].(string)
		if !strings.Contains(desc, "never defaulted") {
			t.Fatalf("dtmf_send.%s description = %q — it must say a negative value is "+
				"REJECTED rather than silently defaulted, which is the contract the "+
				"media_plan dtmf step already publishes", field, desc)
		}
	}
}

// toolInputProperties issues a tools/list and returns one tool's inputSchema
// "properties" object. It repeats listToolNames' SSE-framing discovery (D221)
// rather than widening it, matching how callTool already does the same.
func toolInputProperties(t *testing.T, hs *httptest.Server, token, sessionID, name string) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, hs.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":8,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(sessionIDHeader, sessionID)
	resp, err := hs.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	var data []byte
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "data: ") {
			data = []byte(strings.TrimPrefix(line, "data: "))
			break
		}
	}
	if data == nil {
		t.Fatalf("tools/list response carries no SSE \"data: \" line: %s", raw)
	}
	var parsed struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				InputSchema struct {
					Properties map[string]any `json:"properties"`
				} `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("tools/list data is not JSON: %v (%s)", err, data)
	}
	for _, tl := range parsed.Result.Tools {
		if tl.Name == name {
			return tl.InputSchema.Properties
		}
	}
	t.Fatalf("tools/list published no tool named %q", name)
	return nil
}

// TestCallTransferIsRegisteredAndReachesItsOwnHandler is the name-to-handler
// wiring assertion TestP3ToolsAreCallableAndReachTheirOwnHandler makes for the
// P3 tools: set membership alone cannot tell call_transfer apart from any other
// handler with a compatible generic signature.
func TestCallTransferIsRegisteredAndReachesItsOwnHandler(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	tools := fakes.NewTools()
	store, _ := testPolicyStore(t, clk, testToken, "")
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour), Tools: tools,
		Policy: store, Log: discardLogger(), Clock: clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	id := initSession(t, hs, testToken)

	if !slices.Contains(listToolNames(t, hs, testToken, id), "call_transfer") {
		t.Fatal("call_transfer is not advertised")
	}
	if isErr, text := callTool(t, hs, testToken, id, "call_transfer",
		`{"call":"call_1","mode":"attended","consult_call":"call_2"}`); isErr {
		t.Fatalf("call_transfer rejected its own arguments: %s", text)
	}
	if isErr, text := callTool(t, hs, testToken, id, "call_transfer",
		`{"call":"call_1","mode":"blind","target":"sip:carol@example.com"}`); isErr {
		t.Fatalf("call_transfer rejected a blind request: %s", text)
	}
	calls := tools.CallsFor("call_transfer")
	if len(calls) != 2 {
		t.Fatalf("CallTransfer was called %d times, want 2", len(calls))
	}
	if in, ok := calls[0].In.(session.CallTransferInput); !ok ||
		in != (session.CallTransferInput{Call: "call_1", Mode: "attended", ConsultCall: "call_2"}) {
		t.Fatalf("attended decoded %#v", calls[0].In)
	}
	if in, ok := calls[1].In.(session.CallTransferInput); !ok ||
		in != (session.CallTransferInput{Call: "call_1", Mode: "blind", Target: "sip:carol@example.com"}) {
		t.Fatalf("blind decoded %#v", calls[1].In)
	}
}
