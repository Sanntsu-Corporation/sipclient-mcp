package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/mcpdaemon"
)

const (
	relayPassword  = `Rp@ss"w\ord<&>é-UNIQUE`
	relayPassword2 = `Second<&>pw"-UNIQUE2`
)

func relayAccounts() map[string]Account {
	return map[string]Account{
		"sbc-lab":   {Mode: "register", SIPServer: "10.1.2.3", Port: 5070, Transport: "tcp", Username: "1001", Password: relayPassword},
		"carrier-x": {Mode: "direct", Transport: "tls", Username: "acme", Password: relayPassword2},
	}
}

func writeRaw(path, body string) error { return os.WriteFile(path, []byte(body), 0o600) }

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type harness struct {
	d       *mcpdaemon.Daemon
	cfgPath string
	cs      *sdk.ClientSession
	logBuf  *syncBuf
	runErr  chan error
	r       *Relay
}

func writeCfg(t *testing.T, upstream, token string, accts map[string]Account) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sipclient-proxy.json")
	if err := Save(p, &Config{Upstream: upstream, Token: token, Accounts: accts}); err != nil {
		t.Fatal(err)
	}
	return p
}

// startRelay runs a Relay against d and returns a client connected to the proxy.
func startRelay(t *testing.T, d *mcpdaemon.Daemon, accts map[string]Account) *harness {
	t.Helper()
	return startRelayWithConfig(t, d, writeCfg(t, d.URL, d.Token, accts))
}

func startRelayWithConfig(t *testing.T, d *mcpdaemon.Daemon, cfgPath string) *harness {
	t.Helper()
	return startRelayOpts(t, d, cfgPath, Options{})
}

// startRelayOpts is startRelayWithConfig with extra Options (ConfigPath, Version
// and Log are set here).
func startRelayOpts(t *testing.T, d *mcpdaemon.Daemon, cfgPath string, o Options) *harness {
	t.Helper()
	h := &harness{d: d, cfgPath: cfgPath, logBuf: &syncBuf{}, runErr: make(chan error, 1)}
	o.ConfigPath, o.Version = h.cfgPath, "test"
	o.Log = slog.New(slog.NewTextHandler(h.logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.r = New(o)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ct, st := sdk.NewInMemoryTransports()
	go func() { h.runErr <- h.r.Run(ctx, st) }()
	// Connect blocks on the in-memory pipe if Run already gave up (bad token, bad
	// config), so race it against Run's result and report why instead of hanging.
	type connected struct {
		cs  *sdk.ClientSession
		err error
	}
	done := make(chan connected, 1)
	go func() {
		cs, err := sdk.NewClient(&sdk.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
		done <- connected{cs, err}
	}()
	var cs *sdk.ClientSession
	select {
	case c := <-done:
		if c.err != nil {
			t.Fatalf("connect to proxy: %v", c.err)
		}
		cs = c.cs
	case runErr := <-h.runErr:
		t.Fatalf("relay Run failed: %v", runErr)
	case <-time.After(20 * time.Second):
		t.Fatal("timed out connecting to the proxy")
	}
	t.Cleanup(func() { _ = cs.Close() })
	h.cs = cs
	return h
}

func (h *harness) tryCall(name, args string) (*sdk.CallToolResult, error) {
	var a any
	if args != "" {
		a = json.RawMessage(args)
	}
	return h.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: name, Arguments: a})
}

func (h *harness) call(t *testing.T, name, args string) *sdk.CallToolResult {
	t.Helper()
	res, err := h.tryCall(name, args)
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	return res
}

func text(res *sdk.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func directClient(t *testing.T, d *mcpdaemon.Daemon) *sdk.ClientSession {
	t.Helper()
	tr := &sdk.StreamableClientTransport{Endpoint: d.URL, HTTPClient: newHTTPClient(d.URL, d.Token, 0), DisableStandaloneSSE: true}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "direct", Version: "0"}, nil).Connect(context.Background(), tr, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func toolMap(t *testing.T, cs *sdk.ClientSession) map[string]*sdk.Tool {
	t.Helper()
	m := map[string]*sdk.Tool{}
	for tool, err := range cs.Tools(context.Background(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		m[tool.Name] = tool
	}
	return m
}

func contains(v any, s string) bool {
	l, _ := v.([]any)
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func lastUACreate(t *testing.T, d *mcpdaemon.Daemon) session.UACreateInput {
	t.Helper()
	calls := d.Tools.CallsFor("ua_create")
	if len(calls) == 0 {
		t.Fatal("daemon saw no ua_create")
	}
	return calls[len(calls)-1].In.(session.UACreateInput)
}

// ---- stub upstream: a plain SDK server behind the same bearer check -------

// stubUpstream is an SDK MCP server whose tools and replies the test scripts.
// The relay tests that need exact control of what the upstream sends (raw
// argument bytes, non-text blocks, notifications) use it instead of the daemon.
type stubUpstream struct {
	Srv   *sdk.Server
	HS    *httptest.Server
	Token string

	mu   sync.Mutex
	args map[string][]byte // arguments of the last call to each stub tool

	// gets counts the standalone-stream GET requests the stub has seen; getHook,
	// when set BEFORE the relay starts, may answer such a GET itself (true = handled).
	// Both exist for the Task 6 bridge tests.
	gets    atomic.Int32
	getHook func(w http.ResponseWriter, r *http.Request) bool

	// CF-206: sessions answering HTTP 404 (what the daemon does once a session
	// expired or after a restart). expire kills every session seen so far; with
	// expireOnCall set, every tools/call kills the session it arrives on.
	seen, dead   map[string]bool // guarded by mu
	expireOnCall atomic.Bool

	// stall makes the stub a daemon that accepts connections but never answers
	// an initialize or a DELETE (other requests are answered); stalled counts
	// such requests still waiting and maxStalled the most at once.
	stall, stalled, maxStalled atomic.Int32
	unstall                    chan struct{} // closed at cleanup, before the server closes
	// stallCancel stalls every notifications/cancelled POST the same way.
	stallCancel atomic.Bool
	// rejectNextCall answers the next tools/call with HTTP 503: the SDK reports
	// it without breaking the connection, so the session stays alive.
	rejectNextCall atomic.Bool
}

func (s *stubUpstream) rejects(r *http.Request) bool {
	if r.Method != http.MethodPost || !s.rejectNextCall.Load() {
		return false
	}
	b, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(b))
	return bytes.Contains(b, []byte(`"tools/call"`)) && s.rejectNextCall.CompareAndSwap(true, false)
}

// stalls holds r until its client gives up, if r must be stalled.
func (s *stubUpstream) stalls(r *http.Request) bool {
	stallAll := s.stall.Load() != 0
	switch {
	case r.Method == http.MethodDelete:
		if !stallAll {
			return false
		}
	case r.Method == http.MethodPost && (stallAll || s.stallCancel.Load()):
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		initialize := stallAll && r.Header.Get("Mcp-Session-Id") == "" && bytes.Contains(b, []byte(`"initialize"`))
		cancel := s.stallCancel.Load() && bytes.Contains(b, []byte(`"notifications/cancelled"`))
		if !initialize && !cancel {
			return false
		}
	default:
		return false
	}
	n := s.stalled.Add(1)
	for m := s.maxStalled.Load(); n > m; m = s.maxStalled.Load() {
		if s.maxStalled.CompareAndSwap(m, n) {
			break
		}
	}
	select {
	case <-r.Context().Done():
	case <-s.unstall:
	}
	s.stalled.Add(-1)
	return true
}

// expire makes every session the stub has seen answer HTTP 404 from now on.
func (s *stubUpstream) expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.seen {
		s.dead[id] = true
	}
}

// gone reports whether r must be answered HTTP 404 "session not found".
func (s *stubUpstream) gone(r *http.Request) bool {
	id := r.Header.Get("Mcp-Session-Id")
	if id == "" {
		return false
	}
	kill := false
	if s.expireOnCall.Load() && r.Method == http.MethodPost {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		kill = bytes.Contains(b, []byte(`"tools/call"`))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[id] = true
	if kill {
		s.dead[id] = true
	}
	return s.dead[id]
}

func newStub(t *testing.T, token string, reply func() *sdk.CallToolResult) *stubUpstream {
	t.Helper()
	return newStubWithInstructions(t, token, reply, "stub-instructions")
}

func newStubWithInstructions(t *testing.T, token string, reply func() *sdk.CallToolResult, instructions string) *stubUpstream {
	t.Helper()
	s := &stubUpstream{Token: token, args: map[string][]byte{}, seen: map[string]bool{}, dead: map[string]bool{}, unstall: make(chan struct{})}
	s.Srv = sdk.NewServer(&sdk.Implementation{Name: "stub", Version: "0"}, &sdk.ServerOptions{Instructions: instructions})
	record := func(name string, req *sdk.CallToolRequest) {
		s.mu.Lock()
		s.args[name] = append([]byte(nil), req.Params.Arguments...)
		s.mu.Unlock()
	}
	s.Srv.AddTool(&sdk.Tool{Name: "ua_create", Description: "stub", InputSchema: map[string]any{
		"type": "object", "required": []any{"mode"}, "properties": map[string]any{"mode": map[string]any{"type": "string"}},
	}}, func(_ context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		record("ua_create", req)
		if reply != nil {
			return reply(), nil
		}
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "ok"}}}, nil
	})
	s.Srv.AddTool(&sdk.Tool{Name: "noargs", Description: "records what it receives", InputSchema: map[string]any{"type": "object"}},
		func(_ context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			record("noargs", req)
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "ok"}}}, nil
		})
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s.Srv }, nil)
	s.HS = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if s.gone(r) {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		if s.stalls(r) {
			return
		}
		if s.rejects(r) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodGet {
			s.gets.Add(1)
			if hook := s.getHook; hook != nil && hook(w, r) {
				return
			}
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(s.HS.Close)
	t.Cleanup(func() { close(s.unstall) }) // runs first: a stalled request must not block Close
	return s
}

func (s *stubUpstream) daemon() *mcpdaemon.Daemon {
	return &mcpdaemon.Daemon{URL: s.HS.URL, Token: s.Token}
}

func (s *stubUpstream) lastArgs() []byte { return s.lastArgsOf("ua_create") }

func (s *stubUpstream) lastArgsOf(tool string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.args[tool]...)
}

// ---- tests against the daemon's real handler ------------------------------

func TestRelayMirrorsUpstreamTools(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	up, px := toolMap(t, directClient(t, d)), toolMap(t, h.cs)
	if _, ok := px["account_list"]; !ok {
		t.Fatal("account_list missing")
	}
	var upNames, pxNames []string
	for n := range up {
		upNames = append(upNames, n)
	}
	for n := range px {
		if n != "account_list" {
			pxNames = append(pxNames, n)
		}
	}
	sort.Strings(upNames)
	sort.Strings(pxNames)
	if strings.Join(upNames, ",") != strings.Join(pxNames, ",") {
		t.Fatalf("tool sets differ:\nup=%v\npx=%v", upNames, pxNames)
	}
	for n, tool := range up {
		if n != "ua_create" && px[n].Description != tool.Description {
			t.Errorf("%s description changed", n)
		}
	}
}

func TestUACreateSchemaRewritten(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	sch := func(cs *sdk.ClientSession) map[string]any {
		b, _ := json.Marshal(toolMap(t, cs)["ua_create"].InputSchema)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	up, px := sch(directClient(t, d)), sch(h.cs)
	if !contains(up["required"], "mode") {
		t.Fatalf("premise broken: daemon ua_create must require mode: %v", up["required"])
	}
	if _, ok := up["properties"].(map[string]any)["account"]; ok {
		t.Fatal("premise broken: daemon must not know account")
	}
	if contains(px["required"], "mode") {
		t.Fatal("proxy must not require mode")
	}
	if _, ok := px["properties"].(map[string]any)["account"]; !ok {
		t.Fatal("proxy schema lacks account")
	}
	if !strings.Contains(toolMap(t, h.cs)["ua_create"].Description, "account_list") {
		t.Fatal("ua_create description should point at account_list")
	}
}

func TestUACreateByAccount(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())

	res := h.call(t, "ua_create", `{"account":"sbc-lab","dtmf_mode":"rfc2833"}`)
	if res.IsError {
		t.Fatalf("unexpected error: %s", text(res))
	}
	want := session.UACreateInput{Mode: "register", Transport: "tcp", AuthUser: "1001", AuthPass: relayPassword,
		Registrar: "sip:10.1.2.3:5070", AOR: "sip:1001@10.1.2.3", DTMFMode: "rfc2833"}
	if got := lastUACreate(t, d); got.Mode != want.Mode || got.Transport != want.Transport || got.AuthUser != want.AuthUser ||
		got.AuthPass != want.AuthPass || got.Registrar != want.Registrar || got.AOR != want.AOR || got.DTMFMode != want.DTMFMode {
		t.Fatalf("daemon saw %+v, want %+v", got, want)
	}

	h.call(t, "ua_create", `{"account":"carrier-x"}`)
	got := lastUACreate(t, d)
	if got.Mode != "direct" || got.Transport != "tls" || got.Registrar != "" || got.AOR != "" || got.AuthPass != relayPassword2 {
		t.Fatalf("direct account mapped wrongly: %+v", got)
	}
}

func TestUACreateConflictSendsNothingUpstream(t *testing.T) {
	for _, f := range []string{"mode", "registrar", "aor", "auth_user", "auth_pass", "transport", "auth_any_host"} {
		t.Run(f, func(t *testing.T) {
			d := mcpdaemon.Start(t)
			h := startRelay(t, d, relayAccounts())
			res := h.call(t, "ua_create", `{"account":"sbc-lab","`+f+`":"x"}`)
			if !res.IsError || !strings.Contains(text(res), `combined with "`+f+`"`) {
				t.Fatalf("want IsError naming %q, got IsError=%v %q", f, res.IsError, text(res))
			}
			if n := len(d.Tools.CallsFor("ua_create")); n != 0 {
				t.Fatalf("daemon received %d ua_create calls; a conflict must send nothing", n)
			}
			if strings.Contains(text(res), relayPassword) {
				t.Fatal("password leaked in conflict error")
			}
		})
	}
}

// TestProxyDirectAccountDigestNeedsAuthAnyHost pins D-C2/D-C3 at the proxy: a
// direct account's UA gets no anchor (no aor, no registrar), so it answers no
// digest challenge unless the ENTRY sets auth_any_host. The daemon here is
// fake-backed, so the refusal itself is proven by sipua's
// TestDirectAccountShapeWithoutAORWithholdsCredentials on this exact shape.
func TestProxyDirectAccountDigestNeedsAuthAnyHost(t *testing.T) {
	t.Run("entry without the override forwards no anchor and no override", func(t *testing.T) {
		d := mcpdaemon.Start(t)
		h := startRelay(t, d, relayAccounts())
		if res := h.call(t, "ua_create", `{"account":"carrier-x"}`); res.IsError {
			t.Fatalf("unexpected error: %s", text(res))
		}
		got := lastUACreate(t, d)
		if got.Mode != "direct" || got.AOR != "" || got.Registrar != "" || got.AuthAnyHost {
			t.Fatalf("direct account forwarded %+v, want mode direct, empty aor/registrar, auth_any_host false", got)
		}
	})
	t.Run("entry with the override forwards it", func(t *testing.T) {
		d := mcpdaemon.Start(t)
		accts := relayAccounts()
		a := accts["carrier-x"]
		a.AuthAnyHost = true
		accts["carrier-x"] = a
		h := startRelay(t, d, accts)
		if res := h.call(t, "ua_create", `{"account":"carrier-x"}`); res.IsError {
			t.Fatalf("unexpected error: %s", text(res))
		}
		got := lastUACreate(t, d)
		if !got.AuthAnyHost || got.AOR != "" || got.Registrar != "" {
			t.Fatalf("direct account with override forwarded %+v, want auth_any_host true and still no anchor", got)
		}
	})
	t.Run("a model-supplied override is rejected locally", func(t *testing.T) {
		d := mcpdaemon.Start(t)
		h := startRelay(t, d, relayAccounts())
		for _, extra := range []string{`"auth_any_host":true`, `"AUTH_ANY_HOST":true`, `"auth_any_host":false`, `"auth_any_host":null`} {
			res := h.call(t, "ua_create", `{"account":"carrier-x",`+extra+`}`)
			if !res.IsError || !strings.Contains(text(res), `combined with "auth_any_host"`) {
				t.Errorf("%s: want IsError naming auth_any_host, got IsError=%v %q", extra, res.IsError, text(res))
			}
		}
		if n := len(d.Tools.CallsFor("ua_create")); n != 0 {
			t.Fatalf("daemon received %d ua_create calls; a conflict must send nothing", n)
		}
	})
}

func TestUACreateEmptyOwnedFieldIsAConflict(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	res := h.call(t, "ua_create", `{"account":"sbc-lab","mode":""}`)
	if !res.IsError || !strings.Contains(text(res), `combined with "mode"`) {
		t.Fatalf("got IsError=%v %q", res.IsError, text(res))
	}
	if len(d.Tools.CallsFor("ua_create")) != 0 {
		t.Fatal("nothing may reach the daemon")
	}
}

// N2: Go's JSON decoder matches keys case-insensitively, so "Registrar" next to
// "account" must be a conflict like "registrar" (D7, presence not spelling) and
// nothing may be sent. The daemon's closed input schema is a second layer that
// rejects the variant too; the premise is asserted, but the proxy does not rely on it.
func TestUACreateCaseVariantOfOwnedFieldIsAConflict(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	for key, want := range map[string]string{"Registrar": "registrar", "tran\u017Fport": "transport", "AUTH_PASS": "auth_pass"} {
		res := h.call(t, "ua_create", `{"account":"sbc-lab","`+key+`":"sip:evil.example:5060"}`)
		if !res.IsError || !strings.Contains(text(res), `combined with "`+want+`"`) {
			t.Errorf("key %q: want a conflict naming %q, got IsError=%v %q", key, want, res.IsError, text(res))
		}
	}
	if n := len(d.Tools.CallsFor("ua_create")); n != 0 {
		t.Fatalf("daemon received %d ua_create calls; a conflict must send nothing", n)
	}
	// Premise: without the proxy, the daemon itself refuses the variant.
	res, err := directClient(t, d).CallTool(context.Background(), &sdk.CallToolParams{Name: "ua_create",
		Arguments: json.RawMessage(`{"mode":"direct","auth_user":"u","auth_pass":"p","Registrar":"sip:evil.example:5060"}`)})
	if err == nil && !res.IsError {
		t.Fatal("premise broken: the daemon accepted a case variant of an owned field")
	}
	if n := len(d.Tools.CallsFor("ua_create")); n != 0 {
		t.Fatalf("premise: the daemon executed a call with a case-variant key (%d calls)", n)
	}
}

func TestUACreateUnknownAccountListsNames(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	res := h.call(t, "ua_create", `{"account":"nope"}`)
	if !res.IsError || !strings.Contains(text(res), "carrier-x, sbc-lab") {
		t.Fatalf("got IsError=%v %q", res.IsError, text(res))
	}
	if len(d.Tools.CallsFor("ua_create")) != 0 {
		t.Fatal("unknown account must not reach the daemon")
	}
}

func TestUACreateWithoutAccountIsUntouched(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	h.call(t, "ua_create", `{"mode":"direct","auth_pass":"explicit-pw","transport":"udp"}`)
	got := lastUACreate(t, d)
	if got.Mode != "direct" || got.AuthPass != "explicit-pw" || got.Transport != "udp" {
		t.Fatalf("explicit call altered: %+v", got)
	}
}

func TestRelayForwardsCallWithoutArguments(t *testing.T) {
	d := mcpdaemon.Start(t)
	d.Tools.SetPayload("call_list", map[string]any{"calls": []any{}})
	h := startRelay(t, d, relayAccounts())
	res := h.call(t, "call_list", "")
	if res.IsError || !strings.Contains(text(res), `"calls"`) {
		t.Fatalf("got %v %q", res.IsError, text(res))
	}
	if len(d.Tools.CallsFor("call_list")) != 1 {
		t.Fatal("call_list did not reach the daemon")
	}
}

// ua_create, session_keepalive and call_list all take no required arguments
// here, so the daemon records each one; the test first proves every tool was
// actually recorded (an empty session id on both sides must not pass as equal).
func TestRelayUsesOneUpstreamSession(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	h.call(t, "ua_create", `{"account":"carrier-x"}`)
	h.call(t, "session_keepalive", "")
	h.call(t, "call_list", "")
	var ids []string
	for _, tool := range []string{"ua_create", "session_keepalive", "call_list"} {
		if n := len(d.Tools.CallsFor(tool)); n != 1 {
			t.Fatalf("daemon recorded %d %s calls, want 1 (the test would compare nothing)", n, tool)
		}
		id := d.Tools.LastSession(tool)
		if id == "" {
			t.Fatalf("daemon recorded an empty session id for %s", tool)
		}
		ids = append(ids, id)
	}
	if ids[0] != ids[1] || ids[1] != ids[2] {
		t.Fatalf("daemon saw different sessions: %v", ids)
	}
}

func TestAccountListHasNoPassword(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	res := h.call(t, "account_list", "")
	out := text(res)
	if res.IsError || strings.Contains(out, "assword") || strings.Contains(out, relayPassword) || strings.Contains(out, relayPassword2) {
		t.Fatalf("account_list must not expose passwords: %q", out)
	}
	for _, want := range []string{`"name":"sbc-lab"`, `"name":"carrier-x"`, `"port":5070`, `"port":5061`, `"username":"1001"`} {
		if !strings.Contains(out, want) {
			t.Errorf("account_list missing %s in %s", want, out)
		}
	}
	if strings.Contains(out, "invalid") {
		t.Errorf("no invalid section expected for a clean config: %s", out)
	}
}

// Rule 13 F3: a password equal to a value account_list shows (here the
// username) is redacted there too, even before the account was ever used.
func TestAccountListRedactsAPasswordEqualToAListedValue(t *testing.T) {
	d := mcpdaemon.Start(t)
	accts := relayAccounts()
	accts["same"] = Account{Mode: "direct", Username: "same-as-pw-1234", Password: "same-as-pw-1234"}
	accts["short"] = Account{Mode: "direct", Username: "2002", Password: "2002"}
	h := startRelay(t, d, accts)
	out := text(h.call(t, "account_list", ""))
	if strings.Contains(out, "same-as-pw") || strings.Contains(out, `"2002"`) {
		t.Fatalf("account_list exposes a password: %s", out)
	}
	if !strings.Contains(out, `"name":"same"`) || !strings.Contains(out, `"name":"short"`) || !strings.Contains(out, `"username":"1001"`) {
		t.Fatalf("account_list lost its entries: %s", out)
	}
}

// Rule 13 G1: an INVALID account entry is still listed by name, so its password
// must be in the scrub set too ("every password in the file"). Here the entry's
// name equals its password; the name is then scrubbed, the response stays valid.
func TestAccountListScrubsThePasswordOfAnInvalidAccount(t *testing.T) {
	for _, pw := range []string{"invalid-entry-secret", "pw12"} {
		t.Run(pw, func(t *testing.T) {
			d := mcpdaemon.Start(t)
			accts := relayAccounts()
			accts[pw] = Account{Mode: "no-such-mode", Username: "u", Password: pw}
			h := startRelay(t, d, accts)
			res := h.call(t, "account_list", "")
			out := text(res)
			if res.IsError || strings.Contains(out, pw) {
				t.Fatalf("account_list exposes an invalid account's password: %s", out)
			}
			if !json.Valid([]byte(out)) || !strings.Contains(out, `"name":"sbc-lab"`) || !strings.Contains(out, `"invalid"`) {
				t.Fatalf("account_list response is not the expected valid listing: %s", out)
			}
		})
	}
}

func TestRelayNeverLeaksPasswordOrToken(t *testing.T) {
	d := mcpdaemon.Start(t)
	// The daemon echoes the password back in its payload: worst case.
	d.Tools.SetPayload("ua_create", map[string]any{"echo": relayPassword, "ok": true})
	d.Tools.SetPayload("call_list", map[string]any{"bearer": mcpdaemon.Token})
	h := startRelay(t, d, relayAccounts())

	var seen []string
	seen = append(seen, text(h.call(t, "ua_create", `{"account":"sbc-lab"}`)))
	seen = append(seen, text(h.call(t, "ua_create", `{"account":"sbc-lab","auth_pass":"x"}`)))
	seen = append(seen, text(h.call(t, "ua_create", `{"account":"nope"}`)))
	seen = append(seen, text(h.call(t, "account_list", "")))
	res := h.call(t, "ua_create", `{"account":"sbc-lab"}`)
	b, _ := json.Marshal(res)
	seen = append(seen, string(b), text(h.call(t, "call_list", "")), h.logBuf.String())

	for i, s := range seen {
		if ContainsSecret(relayPassword, s) || ContainsSecret(mcpdaemon.Token, s) {
			t.Errorf("output %d leaks a secret: %s", i, s)
		}
	}
	if !strings.Contains(seen[0], "[redacted]") {
		t.Errorf("echoed password should be replaced by [redacted]: %s", seen[0])
	}
}

// OD17: the injected password is scrubbed from EVERY later forwarded result,
// not only from the ua_create that carried it.
func TestRelayScrubsInjectedPasswordFromLaterCalls(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	h.call(t, "ua_create", `{"account":"sbc-lab"}`)
	d.Tools.SetPayload("call_list", map[string]any{"leak": relayPassword, "nested": []any{map[string]any{"x": relayPassword}}})
	out := text(h.call(t, "call_list", ""))
	if strings.Contains(out, "Rp@ss") || strings.Contains(out, "UNIQUE") || !strings.Contains(out, "[redacted]") {
		t.Fatalf("a later result leaked the injected password: %s", out)
	}
}

// The error text of a failed Inject is scrubbed too: "unknown account %q" echoes
// the requested name, so a model that passes a secret it learned as the account
// name (or a mistyped name equal to one) gets [redacted] back, not the secret.
func TestRelayScrubsSecretsFromInjectErrors(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	h.call(t, "ua_create", `{"account":"sbc-lab"}`) // registers relayPassword as a secret
	pw, _ := json.Marshal(relayPassword)
	res := h.call(t, "ua_create", `{"account":`+string(pw)+`}`)
	out := text(res)
	if !res.IsError || !strings.Contains(out, "unknown account") {
		t.Fatalf("want the unknown-account error, got %v %q", res.IsError, out)
	}
	if strings.Contains(out, "UNIQUE") || strings.Contains(out, "Rp@ss") {
		t.Fatalf("the Inject error echoed the injected password: %q", out)
	}
	if n := len(d.Tools.CallsFor("ua_create")); n != 1 {
		t.Fatalf("the failed call must not reach the daemon, saw %d ua_create calls", n)
	}
}

func TestRelayRedactsEchoedSecretWithSpecialChars(t *testing.T) {
	d := mcpdaemon.Start(t)
	// The daemon echoes the password as a JSON text carried inside a string
	// field; the daemon then encodes its own payload, so the password reaches
	// the proxy DOUBLE-escaped. Raw, single- and double-escaped forms must all go.
	esc, _ := json.Marshal(relayPassword2)
	d.Tools.SetPayload("ua_create", map[string]any{"raw": string(esc)})
	h := startRelay(t, d, relayAccounts())
	out := text(h.call(t, "ua_create", `{"account":"carrier-x"}`))
	twice, _ := json.Marshal(string(esc))
	for _, form := range []string{relayPassword2, string(esc[1 : len(esc)-1]), string(twice[1 : len(twice)-1]), "Second"} {
		if strings.Contains(out, form) {
			t.Fatalf("echo not redacted (form %q): %s", form, out)
		}
	}
	if !strings.Contains(out, "[redacted]") {
		t.Fatalf("expected [redacted] marker: %s", out)
	}
}

// OD24: URL-encoded, base64 and username:password (HTTP Basic) spellings of the
// injected password are scrubbed from later results too.
func TestRelayScrubsEncodedPasswordEchoes(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	h.call(t, "ua_create", `{"account":"sbc-lab"}`) // registers the password and the 1001:password forms
	pair := []byte("1001:" + relayPassword)
	echoes := map[string]string{
		"query-escaped": url.QueryEscape(relayPassword),
		"path-escaped":  url.PathEscape(relayPassword),
		"base64":        base64.StdEncoding.EncodeToString([]byte(relayPassword)),
		"basic":         base64.StdEncoding.EncodeToString(pair),
		"basic raw url": base64.RawURLEncoding.EncodeToString(pair),
	}
	d.Tools.SetPayload("call_list", map[string]any{"echoes": echoes})
	out := text(h.call(t, "call_list", ""))
	for name, form := range echoes {
		if strings.Contains(out, form) {
			t.Errorf("%s echo reached the model: %s", name, out)
		}
	}
	if n := strings.Count(out, "[redacted]"); n < len(echoes) {
		t.Errorf("want %d markers, got %d: %s", len(echoes), n, out)
	}
}

func TestRelayRereadsConfigEveryLookup(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	cfg, _ := LoadConfig(h.cfgPath)
	cfg.Accounts["added-later"] = Account{Mode: "direct", Username: "u", Password: "pw-later"}
	if err := Save(h.cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	if out := text(h.call(t, "account_list", "")); !strings.Contains(out, "added-later") {
		t.Fatalf("edit not visible: %s", out)
	}
	h.call(t, "ua_create", `{"account":"added-later"}`)
	if got := lastUACreate(t, d); got.AuthPass != "pw-later" {
		t.Fatalf("new account not used: %+v", got)
	}
}

// OD15: an account that became invalid after start is reported by name and
// problem; its neighbours keep working.
func TestRelayBrokenAccountAfterStart(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	bad := `{"upstream":"` + d.URL + `","token":"` + d.Token + `","accounts":{` +
		`"sbc-lab":{"mode":"register","username":"u","password":"BROKEN-CFG-SECRET"},` +
		`"carrier-x":{"mode":"direct","username":"acme","password":"still-good"}}}`
	if err := writeRaw(h.cfgPath, bad); err != nil {
		t.Fatal(err)
	}
	res := h.call(t, "ua_create", `{"account":"sbc-lab"}`)
	if !res.IsError || !strings.Contains(text(res), `account "sbc-lab"`) || !strings.Contains(text(res), "sipserver") {
		t.Fatalf("want error naming account and problem, got %v %q", res.IsError, text(res))
	}
	if strings.Contains(text(res), "BROKEN-CFG-SECRET") {
		t.Fatal("password leaked")
	}
	if len(d.Tools.CallsFor("ua_create")) != 0 {
		t.Fatal("broken account must not reach the daemon")
	}
	list := text(h.call(t, "account_list", ""))
	if !strings.Contains(list, `"invalid":[{"name":"sbc-lab"`) || !strings.Contains(list, `"name":"carrier-x"`) || strings.Contains(list, "BROKEN-CFG-SECRET") {
		t.Fatalf("account_list should show carrier-x and flag sbc-lab: %s", list)
	}
	if res := h.call(t, "ua_create", `{"account":"carrier-x"}`); res.IsError {
		t.Fatalf("a good account must keep working: %s", text(res))
	}
}

// A file that is no longer even valid JSON fails every lookup, by name of the
// problem, without echoing its content.
func TestRelayBrokenFileAfterStart(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	if err := writeRaw(h.cfgPath, `{"upstream": FILE-SECRET`); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"account_list", ""}, {"ua_create", `{"account":"sbc-lab"}`}} {
		res := h.call(t, c[0], c[1])
		if !res.IsError || !strings.Contains(text(res), "not valid JSON") || strings.Contains(text(res), "FILE-SECRET") {
			t.Fatalf("%s: got IsError=%v %q", c[0], res.IsError, text(res))
		}
	}
	if len(d.Tools.CallsFor("ua_create")) != 0 {
		t.Fatal("nothing may reach the daemon")
	}
}

func TestRunBadToken(t *testing.T) {
	d := mcpdaemon.Start(t)
	p := writeCfg(t, d.URL, "wrong-token-SECRET", relayAccounts())
	_, st := sdk.NewInMemoryTransports()
	err := New(Options{ConfigPath: p, Version: "t"}).Run(context.Background(), st)
	if err == nil {
		t.Fatal("bad token must fail Run")
	}
	if strings.Contains(err.Error(), "wrong-token-SECRET") {
		t.Fatalf("error leaks the token: %v", err)
	}
	if !strings.Contains(err.Error(), d.URL) {
		t.Errorf("error should name the upstream URL: %v", err)
	}
}

func TestRunUnreachable(t *testing.T) {
	hs := httptest.NewServer(http.NotFoundHandler())
	url := hs.URL + "/mcp"
	hs.Close()
	p := writeCfg(t, url, "tok-SECRET", relayAccounts())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, st := sdk.NewInMemoryTransports()
	err := New(Options{ConfigPath: p}).Run(ctx, st)
	if err == nil || strings.Contains(err.Error(), "tok-SECRET") {
		t.Fatalf("want an error without the token, got %v", err)
	}
}

// OD15: Run refuses to start only when the file as a whole is unusable.
func TestRunFailsFastOnUnusableConfig(t *testing.T) {
	tests := []struct{ name, body, wantSub string }{
		{"syntax error", `{"upstream": SECRET-PW`, "not valid JSON"},
		{"remote plain http", `{"upstream":"http://remote.example:8100/mcp","token":"t"}`, "https://"},
		{"blank token", `{"upstream":"https://h/mcp","token":"  "}`, "token"},
		{"unknown top-level key", `{"upstream":"https://h/mcp","token":"t","acounts":{}}`, "acounts"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "c.json")
			_ = writeRaw(p, tc.body)
			_, st := sdk.NewInMemoryTransports()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := New(Options{ConfigPath: p}).Run(ctx, st)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) || strings.Contains(err.Error(), "SECRET-PW") {
				t.Fatalf("got %v, want an error containing %q and no secret", err, tc.wantSub)
			}
		})
	}
	_, st := sdk.NewInMemoryTransports()
	if err := New(Options{ConfigPath: filepath.Join(t.TempDir(), "absent.json")}).Run(context.Background(), st); err == nil {
		t.Fatal("a missing file must fail Run")
	}
}

func TestRunStartsWithABadAccount(t *testing.T) {
	d := mcpdaemon.Start(t)
	body := `{"upstream":"` + d.URL + `","token":"` + d.Token + `","accounts":{` +
		`"good":{"mode":"direct","username":"u","password":"pw-good"},` +
		`"bad":{"mode":"register","username":"u","password":"BAD-ACCT-SECRET"}}}`
	p := filepath.Join(t.TempDir(), "c.json")
	if err := writeRaw(p, body); err != nil {
		t.Fatal(err)
	}
	h := startRelayWithConfig(t, d, p) // fails the test if Run refuses to start
	list := text(h.call(t, "account_list", ""))
	if !strings.Contains(list, `"name":"good"`) || !strings.Contains(list, `"invalid":[{"name":"bad"`) || strings.Contains(list, "BAD-ACCT-SECRET") {
		t.Fatalf("account_list = %s", list)
	}
	res := h.call(t, "ua_create", `{"account":"bad"}`)
	if !res.IsError || !strings.Contains(text(res), `account "bad": sipserver`) || strings.Contains(text(res), "BAD-ACCT-SECRET") {
		t.Fatalf("got %v %q", res.IsError, text(res))
	}
	if res := h.call(t, "ua_create", `{"account":"good"}`); res.IsError {
		t.Fatalf("good account must work: %s", text(res))
	}
}

// ---- upstream failure after startup (CF-206; OD14 reversed 2026-10-08) -----

func TestRelayUpstreamLostAfterStart(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	if res := h.call(t, "call_list", ""); res.IsError {
		t.Fatalf("premise: upstream works before the loss: %s", text(res))
	}
	d.Server.CloseClientConnections()
	d.Server.Close() // the daemon goes away

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	for _, c := range [][2]string{{"call_list", ""}, {"ua_create", `{"account":"sbc-lab"}`}, {"ua_create", `{"account":"carrier-x"}`}} {
		var a any
		if c[1] != "" {
			a = json.RawMessage(c[1])
		}
		res, err := h.cs.CallTool(ctx, &sdk.CallToolParams{Name: c[0], Arguments: a})
		if err != nil {
			t.Fatalf("%s: the failure must be a tool error the model can read, got protocol error %v", c[0], err)
		}
		out := text(res)
		if !res.IsError || !strings.Contains(out, "upstream session lost") || !strings.Contains(out, "next call") || !strings.Contains(out, "rotated") {
			t.Fatalf("%s: got IsError=%v %q", c[0], res.IsError, out)
		}
		for _, secret := range []string{relayPassword, relayPassword2, "Rp@ss", mcpdaemon.Token} {
			if strings.Contains(out, secret) {
				t.Fatalf("%s: lost-upstream message leaks %q: %s", c[0], secret, out)
			}
		}
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("calls against a lost upstream took %v; they must fail fast", d)
	}
	// Local answers keep working, and still never carry a password.
	if out := text(h.call(t, "account_list", "")); !strings.Contains(out, `"name":"sbc-lab"`) || strings.Contains(out, "assword") {
		t.Fatalf("account_list after loss: %s", out)
	}
	// A conflict is still refused locally, not reported as an upstream failure.
	if out := text(h.call(t, "ua_create", `{"account":"sbc-lab","mode":"direct"}`)); !strings.Contains(out, `combined with "mode"`) {
		t.Fatalf("local refusal lost after upstream loss: %s", out)
	}
}

// CF-206 (a): when the daemon answers 404 for an expired session, the relay opens
// a new session and sends the call again, once; the agent never sees the expiry.
func TestRelaySessionExpiredUpstream(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	if res := h.call(t, "call_list", ""); res.IsError {
		t.Fatal(text(res))
	}
	before := d.Tools.LastSession("call_list")
	d.ExpireSessions() // the daemon now answers 404 for this session id
	res := h.call(t, "call_list", "")
	if res.IsError {
		t.Fatalf("the call must be retried on a new session: %q", text(res))
	}
	if n := len(d.Tools.CallsFor("call_list")); n != 2 {
		t.Fatalf("daemon ran call_list %d times, want 2 (once per session)", n)
	}
	if after := d.Tools.LastSession("call_list"); after == "" || after == before {
		t.Fatalf("the retried call must run on a NEW session: before %q after %q", before, after)
	}
	// The injected password still reaches the daemon and never comes back.
	res = h.call(t, "ua_create", `{"account":"carrier-x"}`)
	if res.IsError || strings.Contains(text(res), relayPassword2) {
		t.Fatalf("ua_create after re-open: %v %q", res.IsError, text(res))
	}
	if lastUACreate(t, d).AuthPass != relayPassword2 {
		t.Fatal("ua_create after re-open did not carry the injected password")
	}
	logs := h.logBuf.String()
	if !strings.Contains(logs, "upstream session re-opened") {
		t.Fatalf("the re-open must be logged: %s", logs)
	}
	for _, secret := range []string{relayPassword, relayPassword2, mcpdaemon.Token} {
		if strings.Contains(logs, secret) {
			t.Fatalf("log leaks %q", secret)
		}
	}
}

// An answer from the daemon (a JSON-RPC error for a forwarded call) is not a
// lost session: the model reads it, scrubbed, and the next call still works.
func TestRelayUpstreamRejectionDoesNotPoisonTheSession(t *testing.T) {
	stub := newStub(t, "stub-token-REJECT-SECRET", nil)
	stub.Srv.AddTool(objectTool("rejects"), func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "bad arguments; token was " + stub.Token}
	})
	h := startRelay(t, stub.daemon(), relayAccounts())
	res := h.call(t, "rejects", `{}`)
	out := text(res)
	if !res.IsError || !strings.Contains(out, "upstream rejected the call") || !strings.Contains(out, "bad arguments") {
		t.Fatalf("want the daemon's rejection, got IsError=%v %q", res.IsError, out)
	}
	if strings.Contains(out, "REJECT-SECRET") || !strings.Contains(out, "[redacted]") {
		t.Fatalf("the rejection must be scrubbed: %q", out)
	}
	if res := h.call(t, "noargs", ""); res.IsError || text(res) != "ok" {
		t.Fatalf("session must survive a rejected call: %q", text(res))
	}
}

// Rule 13 F2: a JSON-RPC error the upstream sends during start-up (initialize, or
// the first tools/list) is returned by Run, and main prints it: it must not carry
// the token.
func TestRunScrubsTheTokenFromUpstreamStartupErrors(t *testing.T) {
	for _, method := range []string{"initialize", "tools/list"} {
		t.Run(method, func(t *testing.T) {
			stub := newStub(t, "stub-token-STARTUP-SECRET", nil)
			stub.Srv.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
				return func(ctx context.Context, m string, req sdk.Request) (sdk.Result, error) {
					if m == method {
						return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "refused Bearer " + stub.Token}
					}
					return next(ctx, m, req)
				}
			})
			p := writeCfg(t, stub.HS.URL, stub.Token, relayAccounts())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, st := sdk.NewInMemoryTransports()
			err := New(Options{ConfigPath: p, Version: "t"}).Run(ctx, st)
			if err == nil || !strings.Contains(err.Error(), "refused Bearer") {
				t.Fatalf("want the upstream's start-up error, got %v", err)
			}
			if strings.Contains(err.Error(), "STARTUP-SECRET") || !strings.Contains(err.Error(), "[redacted]") {
				t.Fatalf("the start-up error leaks the token: %v", err)
			}
		})
	}
}

// memSession returns a client session to an empty in-memory server.
func memSession(t *testing.T) *sdk.ClientSession {
	t.Helper()
	ct, st := sdk.NewInMemoryTransports()
	if _, err := sdk.NewServer(&sdk.Implementation{Name: "mem", Version: "0"}, nil).Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestUpstreamErrorIsScrubbedAndClassified(t *testing.T) {
	r := New(Options{})
	up := memSession(t)
	r.install(up)
	r.secrets.add("PW-IN-ERR<&>")
	res := r.upstreamError(context.Background(), up, fmt.Errorf(`Post "http://x/mcp": echo PW-IN-ERR<&> failed`))
	out := text(res)
	if !res.IsError || strings.Contains(out, "PW-IN-ERR") || !r.lost.Load() || !strings.Contains(out, "upstream session lost") {
		t.Fatalf("got %q lost=%v", out, r.lost.Load())
	}
	// A cancelled caller is not a lost upstream.
	r2 := New(Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out := text(r2.upstreamError(ctx, nil, context.Canceled)); !strings.Contains(out, "cancelled") || r2.lost.Load() {
		t.Fatalf("cancel: %q lost=%v", out, r2.lost.Load())
	}
}

func TestAnsweredByUpstream(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"invalid params from the daemon", fmt.Errorf("calling: %w", &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "bad"}), true},
		{"internal error from the daemon", &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "x"}, true},
		{"SDK-local rejected by transport", &jsonrpc.Error{Code: -32005, Message: "rejected by transport"}, false},
		{"SDK-local client closing", &jsonrpc.Error{Code: -32003, Message: "client is closing"}, false},
		{"session missing", fmt.Errorf("sending: %w", sdk.ErrSessionMissing), false},
		{"plain network error", errors.New("connection refused"), false},
	}
	for _, tc := range tests {
		if got := answeredByUpstream(tc.err); got != tc.want {
			t.Errorf("%s: answeredByUpstream = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ---- OD25: the bearer token goes to the configured origin only -------------

type sightings struct {
	mu   sync.Mutex
	auth []string
}

func (s *sightings) record(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auth = append(s.auth, r.Header.Get("Authorization"))
}

func (s *sightings) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.auth...)
}

// A redirect is handed back to the caller, never followed: a validated upstream
// that redirects to another host, or to the same host, must not make the client
// send the token anywhere else.
func TestBearerTokenNeverFollowsARedirect(t *testing.T) {
	other := &sightings{}
	otherSrv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { other.record(r) }))
	defer otherSrv.Close()
	up := &sightings{}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(_ http.ResponseWriter, r *http.Request) { up.record(r) })
	mux.HandleFunc("/to-other-origin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherSrv.URL+"/stolen", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/to-same-origin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/mcp", http.StatusTemporaryRedirect)
	})
	upSrv := httptest.NewServer(mux)
	defer upSrv.Close()
	c := newHTTPClient(upSrv.URL+"/mcp", "TOK-123", 0)

	resp, err := c.Get(upSrv.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := up.seen(); len(got) != 1 || got[0] != "Bearer TOK-123" {
		t.Fatalf("the upstream itself must receive the token: %v", got)
	}
	for _, path := range []string{"/to-other-origin", "/to-same-origin"} {
		resp, err := c.Get(upSrv.URL + path)
		if err != nil {
			t.Fatalf("%s: a redirect must be handed back, not followed and not turned into an error: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("%s: status %d, want the 307 itself", path, resp.StatusCode)
		}
	}
	if got := other.seen(); len(got) != 0 {
		t.Fatalf("the redirect target received %d request(s) carrying %v", len(got), got)
	}
	if got := up.seen(); len(got) != 1 {
		t.Fatalf("a same-origin redirect must not be followed either, upstream saw %v", got)
	}
}

// An https upstream that redirects to plain http must not get the token sent there.
func TestBearerTokenNeverDowngradesToPlainHTTP(t *testing.T) {
	plain := &sightings{}
	plainSrv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { plain.record(r) }))
	defer plainSrv.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plainSrv.URL+"/mcp", http.StatusFound)
	}))
	defer tlsSrv.Close()
	c := newBearerClient(tlsSrv.Client().Transport, tlsSrv.URL+"/mcp", "TOK-123", 0)
	resp, err := c.Get(tlsSrv.URL + "/mcp")
	if err != nil {
		t.Fatalf("the redirect must be handed back, got %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || len(plain.seen()) != 0 {
		t.Fatalf("status %d, plain-http target saw %v", resp.StatusCode, plain.seen())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The transport itself, without any client redirect logic: only the configured
// origin (scheme, host, port; default ports and host case normalised) gets the token.
func TestBearerTransportRefusesOtherOrigins(t *testing.T) {
	tests := []struct {
		upstream, target string
		ok               bool
	}{
		{"https://daemon.example:8100/mcp", "https://daemon.example:8100/other", true},
		{"https://Daemon.Example/mcp", "https://daemon.example:443/x", true},
		{"http://127.0.0.1:8100/mcp", "http://127.0.0.1:8100/mcp", true},
		{"https://daemon.example:8100/mcp", "https://daemon.example:8101/mcp", false},
		{"https://daemon.example:8100/mcp", "https://evil.example:8100/mcp", false},
		{"https://daemon.example:8100/mcp", "http://daemon.example:8100/mcp", false},
		{"https://daemon.example/mcp", "http://daemon.example:443/mcp", false},
		{"://not a url", "https://daemon.example/mcp", false},
	}
	for _, tc := range tests {
		var sent []string
		base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			sent = append(sent, r.Header.Get("Authorization"))
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
		})
		req, err := http.NewRequest(http.MethodGet, tc.target, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := newBearerClient(base, tc.upstream, "TOK-123", 0).Transport.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		switch {
		case tc.ok && (err != nil || len(sent) != 1 || sent[0] != "Bearer TOK-123"):
			t.Errorf("%s -> %s: want the token sent, got err=%v sent=%v", tc.upstream, tc.target, err, sent)
		case !tc.ok && (err == nil || len(sent) != 0):
			t.Errorf("%s -> %s: want a refusal before anything is sent, got err=%v sent=%v", tc.upstream, tc.target, err, sent)
		case err != nil && strings.Contains(err.Error(), "TOK-123"):
			t.Errorf("the refusal leaks the token: %v", err)
		}
		if req.Header.Get("Authorization") != "" {
			t.Errorf("the caller's request must not be modified")
		}
	}
}

// OD27: an upstream that accepts the connection and never answers must not hang the start.
func TestRunUpstreamNeverAnswers(t *testing.T) {
	release := make(chan struct{})
	hs := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(hs.Close)                  // runs second
	t.Cleanup(func() { close(release) }) // runs first, so the blocked handler returns
	p := writeCfg(t, hs.URL+"/mcp", "tok-SECRET", relayAccounts())
	_, st := sdk.NewInMemoryTransports()
	res := make(chan error, 1)
	go func() {
		res <- New(Options{ConfigPath: p, ConnectTimeout: 300 * time.Millisecond}).Run(context.Background(), st)
	}()
	select {
	case err := <-res:
		if err == nil || strings.Contains(err.Error(), "tok-SECRET") || !strings.Contains(err.Error(), hs.URL) {
			t.Fatalf("want an error naming the URL and not the token, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not give up on an upstream that never answers")
	}
}

// ---- concurrency ----------------------------------------------------------

func TestRelayConcurrentUACreate(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	const perAccount = 15
	var wg sync.WaitGroup
	errs := make(chan error, 2*perAccount)
	for _, name := range []string{"sbc-lab", "carrier-x"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perAccount; i++ {
				// local_addr is a free-text pass-through field: it labels which goroutine
				// sent the call, so a daemon-side call can be checked against ITS account.
				res, err := h.tryCall("ua_create", `{"account":"`+name+`","local_addr":"`+name+`"}`)
				if err != nil || res.IsError {
					errs <- fmt.Errorf("%s: %v %v", name, err, res)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	calls := d.Tools.CallsFor("ua_create")
	if len(calls) != 2*perAccount {
		t.Fatalf("daemon saw %d ua_create calls, want %d", len(calls), 2*perAccount)
	}
	for i, c := range calls {
		in := c.In.(session.UACreateInput)
		switch in.LocalAddr { // the label the calling goroutine attached
		case "sbc-lab": // must arrive with ITS registrar, user and password
			if in.Mode != "register" || in.Registrar != "sip:10.1.2.3:5070" || in.AuthUser != "1001" || in.AuthPass != relayPassword {
				t.Fatalf("call %d: sbc-lab crossed with another account: %+v", i, in)
			}
		case "carrier-x":
			if in.Mode != "direct" || in.Registrar != "" || in.AuthUser != "acme" || in.AuthPass != relayPassword2 {
				t.Fatalf("call %d: carrier-x crossed with another account: %+v", i, in)
			}
		default:
			t.Fatalf("call %d: unexpected label %q", i, in.LocalAddr)
		}
	}
}

// ---- stub-upstream tests: exact bytes and hostile results -----------------

// TestRelayForwardsRawBytes: the stub records the argument bytes it receives.
// The SDK client marshals the outgoing json.RawMessage with encoding/json, which
// compacts insignificant whitespace, so the comparison is made after
// json.Compact: numbers (1.0e+2, a 22-digit integer), key names, escapes and
// unknown fields must be preserved exactly.
func TestRelayForwardsRawBytes(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	hr := startRelay(t, stub.daemon(), relayAccounts())

	hr.call(t, "ua_create", `{"account":"carrier-x","codec_pref": [ "PCMU" ,"PCMA" ],"future":{"a" : 1.0e+2,"big":12345678901234567890123}}`)
	got := stub.lastArgs()
	for _, frag := range []string{`"codec_pref":[ "PCMU" ,"PCMA" ]`, `"future":{"a" : 1.0e+2,"big":12345678901234567890123}`} {
		// A fragment is not a JSON value on its own: wrap it, compact, unwrap.
		var buf bytes.Buffer
		if err := json.Compact(&buf, []byte("{"+frag+"}")); err != nil {
			t.Fatal(err)
		}
		want := buf.Bytes()[1 : buf.Len()-1]
		if !bytes.Contains(got, want) {
			t.Errorf("upstream did not receive %s\ngot %s", want, got)
		}
	}
	if !bytes.Contains(got, []byte(`"auth_pass":`)) {
		t.Errorf("auth_pass not injected: %s", got)
	}
	if bytes.Contains(got, []byte(`"account"`)) {
		t.Errorf("account must be stripped: %s", got)
	}
}

// The daemon accepts "arguments": null too, so only a capturing upstream can
// tell whether the proxy forwarded NO arguments or a literal null (Review Focus 5).
func TestRelayForwardsAbsentArgumentsAsAbsent(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	hr := startRelay(t, stub.daemon(), relayAccounts())
	hr.call(t, "noargs", "")
	// An SDK upstream reports absent arguments as an empty value; a literal null is the bug.
	if got := string(stub.lastArgsOf("noargs")); got == "null" {
		t.Fatalf("arguments were absent downstream but upstream received a literal %s", got)
	}
	hr.call(t, "noargs", `{"x":1}`)
	if got := stub.lastArgsOf("noargs"); string(got) != `{"x":1}` {
		t.Fatalf("explicit arguments altered: %q", got)
	}
}

func TestRelayForwardsOversizedArgumentsIntact(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	hr := startRelay(t, stub.daemon(), relayAccounts())
	big := strings.Repeat("Z", 1<<20)
	res := hr.call(t, "ua_create", `{"account":"carrier-x","future":"`+big+`"}`)
	if res.IsError {
		t.Fatalf("1 MiB argument rejected: %s", text(res))
	}
	if got := stub.lastArgs(); !bytes.Contains(got, []byte(`"future":"`+big+`"`)) {
		t.Fatalf("1 MiB argument altered or dropped (got %d bytes)", len(got))
	}
}

// OD17 / Review Focus 9: every place the password can hide in an upstream reply.
func TestRelayRedactsStructuredContentAndMeta(t *testing.T) {
	reply := func() *sdk.CallToolResult {
		return &sdk.CallToolResult{
			Meta:    sdk.Meta{"trace": relayPassword2},
			Content: []sdk.Content{&sdk.TextContent{Text: "created " + relayPassword2, Meta: sdk.Meta{"k": relayPassword2}}},
			StructuredContent: map[string]any{
				"pw":     relayPassword2, // the whole string value
				"nested": map[string]any{"list": []any{"a", map[string]any{"deep": "x" + relayPassword2}}},
				"raw":    jsonInner(jsonInner(relayPassword2, true), true), // JSON text inside a string field
			},
		}
	}
	stub := newStub(t, "stub-token", reply)
	hr := startRelay(t, stub.daemon(), relayAccounts())
	res := hr.call(t, "ua_create", `{"account":"carrier-x"}`)
	b, _ := json.Marshal(res)
	for _, leak := range []string{"Second", "UNIQUE2", "stub-token"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("%q reached the model: %s", leak, b)
		}
	}
	if res.IsError || !strings.Contains(string(b), "[redacted]") {
		t.Fatalf("unexpected result: %s", b)
	}
}

func TestRelayFailsClosedOnUninspectableContent(t *testing.T) {
	reply := func() *sdk.CallToolResult {
		return &sdk.CallToolResult{Content: []sdk.Content{
			&sdk.TextContent{Text: "created"},
			&sdk.ImageContent{Data: []byte("\x89PNG-fake"), MIMEType: "image/png"},
		}}
	}
	stub := newStub(t, "stub-token", reply)
	hr := startRelay(t, stub.daemon(), relayAccounts())

	res := hr.call(t, "ua_create", `{"account":"carrier-x"}`)
	b, _ := json.Marshal(res)
	if !res.IsError || strings.Contains(string(b), "image") || strings.Contains(string(b), "Second") || strings.Contains(string(b), "created") {
		t.Fatalf("an account-based result with an uninspectable block must be withheld entirely: %s", b)
	}
	if !strings.Contains(text(res), "withheld") {
		t.Fatalf("the model should be told why: %s", text(res))
	}
	// A call that injected no password is not withheld.
	res = hr.call(t, "ua_create", `{"mode":"direct"}`)
	if res.IsError || len(res.Content) != 2 {
		t.Fatalf("explicit ua_create must pass non-text content through: %v", res)
	}
}

// Cycle C: a secret split across adjacent text blocks, or across structured string
// values, is not found by the per-field scrub; the result is withheld instead.
func TestRelayWithholdsASecretSplitAcrossFields(t *testing.T) {
	half := len(relayPassword2) / 2
	for name, reply := range map[string]func() *sdk.CallToolResult{
		"text blocks": func() *sdk.CallToolResult {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "created " + relayPassword2[:half]}, &sdk.TextContent{Text: relayPassword2[half:] + " ok"}}}
		},
		"structured strings": func() *sdk.CallToolResult {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "created"}},
				StructuredContent: map[string]any{"a": relayPassword2[:half], "b": relayPassword2[half:]}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			stub := newStub(t, "stub-token", reply)
			hr := startRelay(t, stub.daemon(), relayAccounts())
			res := hr.call(t, "ua_create", `{"account":"carrier-x"}`)
			b, _ := json.Marshal(res)
			if !res.IsError || !strings.Contains(text(res), "withheld") {
				t.Fatalf("a result carrying a split credential must be withheld: %s", b)
			}
			for _, leak := range []string{"Second", "UNIQUE2", "created"} {
				if strings.Contains(string(b), leak) {
					t.Fatalf("%q reached the model: %s", leak, b)
				}
			}
		})
	}
}

func TestRelayPassesThroughUpstreamInstructions(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	hr := startRelay(t, stub.daemon(), relayAccounts())
	if ir := hr.cs.InitializeResult(); ir == nil || ir.Instructions != "stub-instructions" {
		t.Fatalf("instructions not passed through: %+v", ir)
	}
}

// Rule 13 H1: the unknown-account error lists every account name; a name equal
// to its password (valid or invalid entry) must not reach the model.
func TestUnknownAccountErrorScrubsWholeFileSecrets(t *testing.T) {
	d := mcpdaemon.Start(t)
	accts := relayAccounts()
	accts["valid-name-secret"] = Account{Mode: "direct", Username: "u", Password: "valid-name-secret"}
	accts["vpw12"] = Account{Mode: "direct", Username: "u", Password: "vpw12"}
	accts["invalid-name-secret"] = Account{Mode: "no-such-mode", Username: "u", Password: "invalid-name-secret"}
	accts["ipw12"] = Account{Mode: "no-such-mode", Username: "u", Password: "ipw12"}
	h := startRelay(t, d, accts)
	res := h.call(t, "ua_create", `{"account":"nope"}`)
	out := text(res)
	if !res.IsError || !strings.Contains(out, "unknown account") {
		t.Fatalf("want an unknown-account error, got %v %q", res.IsError, out)
	}
	for _, pw := range []string{"valid-name-secret", "vpw12", "invalid-name-secret", "ipw12"} {
		if strings.Contains(out, pw) {
			t.Fatalf("unknown-account error leaks %q: %s", pw, out)
		}
	}
}

// ---- Task 6 (CF-045 scoped): the whole file is the scrub set ----------------

// addEchoTool adds a stub tool "echo" that returns its "say" argument in the
// text, structured content and _meta of its result, and also sends it as a
// progress message and a log message. Call it before the relay starts.
func addEchoTool(stub *stubUpstream) {
	stub.Srv.AddTool(&sdk.Tool{Name: "echo", InputSchema: map[string]any{"type": "object"}},
		func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			var a struct {
				Say string `json:"say"`
			}
			_ = json.Unmarshal(req.Params.Arguments, &a)
			_ = req.Session.NotifyProgress(ctx, &sdk.ProgressNotificationParams{
				ProgressToken: req.Params.GetProgressToken(), Progress: 1, Message: "progress " + a.Say})
			_ = req.Session.Log(ctx, &sdk.LoggingMessageParams{Level: "warning", Logger: "stub", Data: map[string]any{"msg": "log " + a.Say}})
			return &sdk.CallToolResult{
				Meta:              sdk.Meta{"m": a.Say},
				Content:           []sdk.Content{&sdk.TextContent{Text: "echo " + a.Say}},
				StructuredContent: map[string]any{"v": a.Say},
			}, nil
		})
}

func echoArgs(say string) string {
	b, _ := json.Marshal(map[string]string{"say": say})
	return string(b)
}

// requireRedactedEverywhere fails unless say is absent from the text, structured
// content and _meta of res, with a marker in each place it was echoed.
func requireRedactedEverywhere(t *testing.T, res *sdk.CallToolResult, say string) {
	t.Helper()
	sc, _ := res.StructuredContent.(map[string]any)
	sv, _ := sc["v"].(string)
	mv, _ := res.Meta["m"].(string)
	for where, got := range map[string]string{"text": text(res), "structured content": sv, "_meta": mv} {
		if strings.Contains(got, say) || !strings.Contains(got, "[redacted]") {
			t.Errorf("%s: %q must be redacted, got %q", where, say, got)
		}
	}
}

func twoAccountsWithUnusedB(bUser, bPass string) map[string]Account {
	return map[string]Account{
		"acct-a": {Mode: "direct", Username: "user-a-1234", Password: "pass-a-UNIQUE-1"},
		"acct-b": {Mode: "direct", Username: bUser, Password: bPass},
	}
}

func TestUnusedAccountBPasswordIsScrubbedAfterAccountAIsUsed(t *testing.T) {
	const bPass = "b-unused-pw-UNIQUE"
	stub := newStub(t, "stub-token", nil)
	addEchoTool(stub)
	h := startRelay(t, stub.daemon(), twoAccountsWithUnusedB("user-b", bPass))
	h.call(t, "ua_create", `{"account":"acct-a"}`)
	requireRedactedEverywhere(t, h.call(t, "echo", echoArgs(bPass)), bPass)
}

func TestUnusedAccountBCredentialPairIsScrubbed(t *testing.T) {
	const bUser, bPass = "bobb", "pw>>??~~UNIQUE-B1"
	pair := bUser + ":" + bPass
	forms := map[string]string{
		"StdEncoding":    base64.StdEncoding.EncodeToString([]byte(pair)),
		"RawStdEncoding": base64.RawStdEncoding.EncodeToString([]byte(pair)),
		"URLEncoding":    base64.URLEncoding.EncodeToString([]byte(pair)),
		"RawURLEncoding": base64.RawURLEncoding.EncodeToString([]byte(pair)),
	}
	distinct := map[string]bool{}
	for _, f := range forms {
		distinct[f] = true
	}
	if len(distinct) != 4 {
		t.Fatalf("premise: the four encodings of %q must be pairwise distinct: %v", pair, forms)
	}
	for name, form := range forms {
		t.Run(name, func(t *testing.T) {
			stub := newStub(t, "stub-token", nil)
			addEchoTool(stub)
			ds := startBridged(t, stub.daemon(), twoAccountsWithUnusedB(bUser, bPass))
			if res, err := ds.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "ua_create", Arguments: json.RawMessage(`{"account":"acct-a"}`)}); err != nil || res.IsError {
				t.Fatalf("setup: %v %v", res, err)
			}
			p := &sdk.CallToolParams{Name: "echo", Arguments: json.RawMessage(echoArgs(form))}
			p.SetProgressToken("tok-pair")
			res, err := ds.cs.CallTool(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			requireRedactedEverywhere(t, res, form)
			waitFor(t, ds.gotProg, "the progress notification")
			ds.mu.Lock()
			msg := ds.progress[0].Message
			ds.mu.Unlock()
			if strings.Contains(msg, form) || !strings.Contains(msg, "[redacted]") {
				t.Errorf("progress message must be redacted: %q", msg)
			}
		})
	}
}

func TestAccountAddedAfterStartIsScrubbedOnTheNextCall(t *testing.T) {
	const cPass = "c-added-later-pw-UNIQUE"
	stub := newStub(t, "stub-token", nil)
	addEchoTool(stub)
	h := startRelay(t, stub.daemon(), relayAccounts())
	cfg, err := LoadConfig(h.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Accounts["acct-c"] = Account{Mode: "direct", Username: "user-c", Password: cPass}
	if err := Save(h.cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	// No ua_create and no account_list in between: only the forwarded call itself.
	requireRedactedEverywhere(t, h.call(t, "echo", echoArgs(cPass)), cPass)
}

func TestProgressAndLogCarryNoFilePassword(t *testing.T) {
	const bPass = "b-unused-pw-UNIQUE"
	stub := newStub(t, "stub-token", nil)
	addEchoTool(stub)
	ds := startBridged(t, stub.daemon(), twoAccountsWithUnusedB("user-b", bPass))
	if err := ds.cs.SetLoggingLevel(context.Background(), &sdk.SetLoggingLevelParams{Level: "info"}); err != nil {
		t.Fatal(err)
	}
	p := &sdk.CallToolParams{Name: "echo", Arguments: json.RawMessage(echoArgs(bPass))}
	p.SetProgressToken("tok-file-pw")
	if _, err := ds.cs.CallTool(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ds.gotProg, "the progress notification")
	waitFor(t, ds.gotLog, "the log message")
	ds.mu.Lock()
	msg := ds.progress[0].Message
	data, _ := json.Marshal(ds.logs[0].Data)
	ds.mu.Unlock()
	if strings.Contains(msg, bPass) || !strings.Contains(msg, "[redacted]") {
		t.Errorf("progress message carries an unused file password: %q", msg)
	}
	if strings.Contains(string(data), bPass) || !strings.Contains(string(data), "[redacted]") {
		t.Errorf("log message carries an unused file password: %s", data)
	}
}

func TestUnknownAccountErrorDoesNotEchoTheName(t *testing.T) {
	const pw = "name-equals-pw-UNIQUE"
	d := mcpdaemon.Start(t)
	accts := relayAccounts()
	accts["acct-x"] = Account{Mode: "direct", Username: "ux", Password: pw}
	h := startRelay(t, d, accts)
	for _, name := range []string{pw, "plain-unknown-name"} {
		res := h.call(t, "ua_create", `{"account":"`+name+`"}`)
		out := text(res)
		if !res.IsError || !strings.Contains(out, "unknown account (the requested name is not shown); valid accounts: ") {
			t.Fatalf("want the placeholder error for %q, got %v %q", name, res.IsError, out)
		}
		if strings.Contains(out, name) || strings.Contains(out, "[redacted]") {
			t.Errorf("the error echoes the name or a marker at its position: %q", out)
		}
		if !strings.Contains(out, "acct-x, carrier-x, sbc-lab") && !strings.Contains(out, "acct-x") {
			t.Errorf("the valid-account list is missing: %q", out)
		}
	}
}

func TestInvalidAccountNumericPasswordIsRetainedForScrubbing(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	addEchoTool(stub)
	body := `{"upstream":"` + stub.HS.URL + `","token":"stub-token","accounts":{` +
		`"carrier-x":{"mode":"direct","username":"acme","password":"fine-pw-UNIQUE"},` +
		`"num-entry":{"mode":"register","username":"u","password":12345678}}}`
	path := filepath.Join(t.TempDir(), "sipclient-proxy.json")
	if err := writeRaw(path, body); err != nil {
		t.Fatal(err)
	}
	h := startRelayWithConfig(t, stub.daemon(), path)
	list := text(h.call(t, "account_list", ""))
	if !strings.Contains(list, `"invalid":[{"name":"num-entry"`) {
		t.Fatalf("premise: the numeric-password entry must be listed invalid: %s", list)
	}
	// Standing alone in the listing: the name of a second invalid entry equal to the number.
	if err := writeRaw(path, strings.Replace(body, `"num-entry"`, `"12345678"`, 1)); err != nil {
		t.Fatal(err)
	}
	list = text(h.call(t, "account_list", ""))
	if strings.Contains(list, "12345678") || !strings.Contains(list, `"invalid":[{"name":"[redacted]"`) {
		t.Errorf("account_list shows the numeric password: %s", list)
	}
	res := h.call(t, "ua_create", `{"account":"nope"}`)
	if out := text(res); !res.IsError || strings.Contains(out, "12345678") {
		t.Errorf("unknown-account error shows the numeric password: %q", out)
	}
	res = h.call(t, "echo", echoArgs("12345678"))
	if out := text(res); strings.Contains(out, "12345678") || !strings.Contains(out, "[redacted]") {
		t.Errorf("forwarded text shows the numeric password: %q", out)
	}
}
