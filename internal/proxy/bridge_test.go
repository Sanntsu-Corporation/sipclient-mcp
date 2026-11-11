package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/mcpdaemon"
)

// downstream is a client of the proxy that records every notification.
type downstream struct {
	cs       *sdk.ClientSession
	cancel   context.CancelFunc // stops the relay (what SIGTERM does)
	runErr   chan error         // the relay's Run result
	mu       sync.Mutex
	progress []*sdk.ProgressNotificationParams
	logs     []*sdk.LoggingMessageParams
	changed  chan struct{}
	gotProg  chan struct{}
	gotLog   chan struct{}
}

// startBridged runs a Relay against d and connects a notification-recording client.
func startBridged(t *testing.T, d *mcpdaemon.Daemon, accts map[string]Account) *downstream {
	t.Helper()
	ds := &downstream{changed: make(chan struct{}, 8), gotProg: make(chan struct{}, 8), gotLog: make(chan struct{}, 8)}
	cfg := writeCfg(t, d.URL, d.Token, accts)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ds.cancel = cancel
	ct, st := sdk.NewInMemoryTransports()
	runErr := make(chan error, 1)
	ds.runErr = runErr
	go func() { runErr <- New(Options{ConfigPath: cfg, Version: "test"}).Run(ctx, st) }()
	c := sdk.NewClient(&sdk.Implementation{Name: "t", Version: "0"}, &sdk.ClientOptions{
		ToolListChangedHandler: func(context.Context, *sdk.ToolListChangedRequest) { ds.changed <- struct{}{} },
		ProgressNotificationHandler: func(_ context.Context, r *sdk.ProgressNotificationClientRequest) {
			ds.mu.Lock()
			ds.progress = append(ds.progress, r.Params)
			ds.mu.Unlock()
			ds.gotProg <- struct{}{}
		},
		LoggingMessageHandler: func(_ context.Context, r *sdk.LoggingMessageRequest) {
			ds.mu.Lock()
			ds.logs = append(ds.logs, r.Params)
			ds.mu.Unlock()
			ds.gotLog <- struct{}{}
		},
	})
	type connected struct {
		cs  *sdk.ClientSession
		err error
	}
	done := make(chan connected, 1)
	go func() {
		cs, err := c.Connect(ctx, ct, nil)
		done <- connected{cs, err}
	}()
	select { // Connect blocks if Run already gave up: report why instead of hanging
	case r := <-done:
		if r.err != nil {
			t.Fatalf("connect to proxy: %v", r.err)
		}
		ds.cs = r.cs
	case err := <-runErr:
		t.Fatalf("relay Run failed: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("timed out connecting to the proxy")
	}
	t.Cleanup(func() { _ = ds.cs.Close() })
	return ds
}

// waitStream blocks until the proxy's standalone GET stream has reached the stub.
// The SDK attaches the stream to the session slightly after the handshake, so an
// AddTool fired before that would notify nobody (the SDK's behaviour, not the
// proxy's).
func (s *stubUpstream) waitStream(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for s.gets.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the proxy never opened its standalone stream to the upstream")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// startBridgedStub is startBridged against a stub, returning once the stream is
// open and the start-up re-sync is done.
func startBridgedStub(t *testing.T, stub *stubUpstream) *downstream {
	t.Helper()
	var lists atomic.Int32
	stub.Srv.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			res, err := next(ctx, method, req)
			if method == "tools/list" {
				lists.Add(1)
			}
			return res, err
		}
	})
	ds := startBridged(t, stub.daemon(), relayAccounts())
	stub.waitStream(t)
	// Both the start-up listing and serve's start-up re-sync must have been
	// answered: a change made before the re-sync is picked up without any
	// notification, so a test of tools/list_changed would pass without the handler.
	eventually(t, "the start-up re-sync", func() bool { return lists.Load() >= 2 })
	return ds
}

// announce (re-)adds tool upstream until the downstream client has been sent
// tools/list_changed. The stream is open (startBridgedStub), but the SDK server
// registers it a moment after the GET arrives, so the first notification can
// still be lost; adding the same definition again is harmless.
func announce(t *testing.T, stub *stubUpstream, ds *downstream, tool *sdk.Tool, h sdk.ToolHandler) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		stub.Srv.AddTool(tool, h)
		select {
		case <-ds.changed:
			return
		case <-time.After(200 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for tools/list_changed after an upstream AddTool")
		}
	}
}

// eventually polls cond for up to 10 seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func okHandler(text string) sdk.ToolHandler {
	return func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: text}}}, nil
	}
}

func objectTool(name string) *sdk.Tool {
	return &sdk.Tool{Name: name, Description: "test tool " + name, InputSchema: map[string]any{"type": "object"}}
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func hasTool(t *testing.T, cs *sdk.ClientSession, name string) bool {
	t.Helper()
	_, ok := toolMap(t, cs)[name]
	return ok
}

// C1: a tool added or removed upstream after startup reaches the downstream
// client: it gets tools/list_changed and the new list.
func TestBridgeToolListChanged(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	ds := startBridgedStub(t, stub)
	if hasTool(t, ds.cs, "extra") {
		t.Fatal("premise: extra does not exist yet")
	}

	announce(t, stub, ds, &sdk.Tool{Name: "extra", Description: "added later", InputSchema: map[string]any{"type": "object"}}, okHandler("extra-ran"))
	eventually(t, "the new upstream tool to appear downstream", func() bool { return hasTool(t, ds.cs, "extra") })
	if res, err := ds.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "extra"}); err != nil || text(res) != "extra-ran" {
		t.Fatalf("the newly mirrored tool must be callable: %v %v", res, err)
	}

	stub.Srv.RemoveTools("extra")
	eventually(t, "a tool removed upstream to disappear downstream", func() bool { return !hasTool(t, ds.cs, "extra") })
	if !hasTool(t, ds.cs, "ua_create") || !hasTool(t, ds.cs, "account_list") {
		t.Fatal("re-sync must keep ua_create and account_list")
	}
}

// After a re-sync ua_create must STILL be the rewritten one.
func TestBridgeResyncKeepsUACreateRewritten(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	ds := startBridgedStub(t, stub)
	announce(t, stub, ds, &sdk.Tool{Name: "ua_create", Description: "replaced upstream", InputSchema: map[string]any{
		"type": "object", "required": []any{"mode"}, "properties": map[string]any{"mode": map[string]any{"type": "string"}},
	}}, okHandler("v2"))
	eventually(t, "the replaced ua_create to appear downstream", func() bool {
		return strings.HasPrefix(toolMap(t, ds.cs)["ua_create"].Description, "replaced upstream")
	})
	tool := toolMap(t, ds.cs)["ua_create"]
	b, _ := json.Marshal(tool.InputSchema)
	if !strings.Contains(string(b), `"account"`) || strings.Contains(string(b), `"required"`) || !strings.Contains(tool.Description, "account_list") {
		t.Fatalf("re-synced ua_create lost the rewrite: %s / %s", tool.Description, b)
	}
	res, err := ds.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "ua_create", Arguments: json.RawMessage(`{"account":"carrier-x"}`)})
	if err != nil || text(res) != "v2" {
		t.Fatalf("account injection must still work after a re-sync: %v %v", res, err)
	}
}

func TestBridgeProgress(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	stub.Srv.AddTool(&sdk.Tool{Name: "slowwork", InputSchema: map[string]any{"type": "object"}},
		func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			_ = req.Session.NotifyProgress(ctx, &sdk.ProgressNotificationParams{
				ProgressToken: req.Params.GetProgressToken(), Progress: 1, Total: 2, Message: "half " + relayPassword2,
			})
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "done"}}}, nil
		})
	ds := startBridgedStub(t, stub)
	// Inject the password first, so it is in the process-wide secret set.
	if res, err := ds.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "ua_create", Arguments: json.RawMessage(`{"account":"carrier-x"}`)}); err != nil || res.IsError {
		t.Fatalf("setup: %v %v", res, err)
	}
	p := &sdk.CallToolParams{Name: "slowwork"}
	p.SetProgressToken("tok-42")
	if _, err := ds.cs.CallTool(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ds.gotProg, "the progress notification")
	ds.mu.Lock()
	got := ds.progress[0]
	ds.mu.Unlock()
	if got.ProgressToken != "tok-42" || got.Progress != 1 || got.Total != 2 {
		t.Fatalf("progress not forwarded intact: %+v", got)
	}
	if strings.Contains(got.Message, "Second") || !strings.Contains(got.Message, "[redacted]") {
		t.Fatalf("progress message must be scrubbed: %q", got.Message)
	}
}

// Rule 13 F1: a string progress token the upstream sends is scrubbed too.
func TestBridgeProgressTokenIsScrubbed(t *testing.T) {
	stub := newStub(t, "stub-token-PROGRESS-SECRET", nil)
	stub.Srv.AddTool(&sdk.Tool{Name: "leaky", InputSchema: map[string]any{"type": "object"}},
		func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			_ = req.Session.NotifyProgress(ctx, &sdk.ProgressNotificationParams{ProgressToken: "t-" + stub.Token, Progress: 1})
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "done"}}}, nil
		})
	ds := startBridgedStub(t, stub)
	p := &sdk.CallToolParams{Name: "leaky"}
	p.SetProgressToken("tok-1")
	if _, err := ds.cs.CallTool(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ds.gotProg, "the progress notification")
	ds.mu.Lock()
	got := ds.progress[0]
	ds.mu.Unlock()
	if tok, _ := got.ProgressToken.(string); strings.Contains(tok, "PROGRESS-SECRET") || !strings.Contains(tok, "[redacted]") {
		t.Fatalf("progress token must be scrubbed: %#v", got.ProgressToken)
	}
}

func TestBridgeLogging(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	stub.Srv.AddTool(&sdk.Tool{Name: "chatty", InputSchema: map[string]any{"type": "object"}},
		func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			_ = req.Session.Log(ctx, &sdk.LoggingMessageParams{Level: "warning", Logger: "stub", Data: map[string]any{"msg": "pw is " + relayPassword2}})
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "done"}}}, nil
		})
	ds := startBridgedStub(t, stub)
	if _, err := ds.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "ua_create", Arguments: json.RawMessage(`{"account":"carrier-x"}`)}); err != nil {
		t.Fatal(err)
	}
	// The client's level is passed on upstream: without it the stub sends nothing.
	if err := ds.cs.SetLoggingLevel(context.Background(), &sdk.SetLoggingLevelParams{Level: "info"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ds.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "chatty"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ds.gotLog, "the forwarded log message")
	ds.mu.Lock()
	got := ds.logs[0]
	ds.mu.Unlock()
	b, _ := json.Marshal(got.Data)
	if got.Level != "warning" || got.Logger != "stub" || strings.Contains(string(b), "Second") || !strings.Contains(string(b), "[redacted]") {
		t.Fatalf("log message not forwarded/scrubbed: %+v %s", got, b)
	}
}

// Cancelling a downstream call cancels the upstream handler.
func TestBridgeCancellation(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	started := make(chan struct{})
	cancelled := make(chan struct{})
	stub.Srv.AddTool(&sdk.Tool{Name: "blocker", InputSchema: map[string]any{"type": "object"}},
		func(ctx context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			close(started)
			select {
			case <-ctx.Done():
				close(cancelled)
			case <-time.After(15 * time.Second): // bounded so a broken relay cannot hang cleanup
			}
			return nil, ctx.Err()
		})
	ds := startBridgedStub(t, stub)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := ds.cs.CallTool(ctx, &sdk.CallToolParams{Name: "blocker"})
		errc <- err
	}()
	waitFor(t, started, "the upstream handler to start")
	cancel()
	waitFor(t, cancelled, "the upstream handler's context to be cancelled")
	if err := <-errc; err == nil {
		t.Fatal("the cancelled call must return an error downstream")
	}
}

// ---- startup, lifecycle and concurrency -------------------------------------

// A tools/list_changed that arrives while the server is still being built (before
// the resync machinery exists) must be kept, and must not race with init.
func TestBridgeNotificationBeforeInitIsKept(t *testing.T) {
	r := New(Options{})
	notify := r.bridgeClientOptions().ToolListChangedHandler
	notify(context.Background(), nil)
	if len(r.bridge.resync) != 1 {
		t.Fatal("an upstream notification that arrived before init was dropped")
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			notify(context.Background(), nil)
		}
	}()
	go func() {
		defer wg.Done()
		r.bridge.init(nil)
	}()
	wg.Wait()
	if len(r.bridge.resync) != 1 {
		t.Fatal("the pending re-sync signal was lost")
	}
}

// A tool added upstream while the proxy is starting is mirrored. The stub refuses
// the standalone stream (405), so NO notification can be delivered: the tool is
// picked up only by the re-sync that serve requests once its loop is running.
func TestBridgeToolAddedDuringStartupIsPickedUp(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	stub.getHook = func(w http.ResponseWriter, _ *http.Request) bool {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}
	var once sync.Once
	stub.Srv.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			res, err := next(ctx, method, req)
			if method == "tools/list" { // the proxy's first listing is already answered: this tool is "new"
				once.Do(func() { stub.Srv.AddTool(objectTool("late"), okHandler("late-ran")) })
			}
			return res, err
		}
	})
	ds := startBridged(t, stub.daemon(), relayAccounts())
	eventually(t, "the tool added during startup to appear downstream", func() bool { return hasTool(t, ds.cs, "late") })
	if res, err := ds.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "late"}); err != nil || text(res) != "late-ran" {
		t.Fatalf("%v %v", res, err)
	}
}

// OD16: the standalone stream ending again and again (an intermediary with an
// idle timeout) must not break a session whose POSTs still work.
func TestBridgeSurvivesTheStandaloneStreamEnding(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	stub.getHook = func(w http.ResponseWriter, _ *http.Request) bool {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "retry: 20\n\n") // reconnect after 20 ms; no event ID, so the SDK sees "no progress" every time
		return true
	}
	ds := startBridged(t, stub.daemon(), relayAccounts())
	deadline := time.Now().Add(20 * time.Second)
	for stub.gets.Load() < 12 { // well past the SDK's default budget of 5 reconnects
		if time.Now().After(deadline) {
			t.Fatalf("the proxy stopped reconnecting its stream after %d attempts", stub.gets.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	res, err := ds.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "noargs"})
	if err != nil || res.IsError || text(res) != "ok" {
		t.Fatalf("the session must survive its stream ending: %v %v", res, err)
	}
}

// A call already dispatched when the upstream list changes finishes under the
// definition it was dispatched with, even if its tool has been removed meanwhile.
func TestBridgeInFlightCallFinishesWhenTheListChanges(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	started, release := make(chan struct{}), make(chan struct{})
	stub.Srv.AddTool(objectTool("slow"), func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		close(started)
		<-release
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "slow-done"}}}, nil
	})
	ds := startBridgedStub(t, stub)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	type outcome struct {
		res *sdk.CallToolResult
		err error
	}
	got := make(chan outcome, 1)
	go func() {
		res, err := ds.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "slow"})
		got <- outcome{res, err}
	}()
	waitFor(t, started, "the upstream handler to start")
	stub.Srv.RemoveTools("slow")
	announce(t, stub, ds, objectTool("other"), okHandler("other-ran"))
	eventually(t, "the removed tool to disappear downstream", func() bool { return !hasTool(t, ds.cs, "slow") })
	close(release)
	select {
	case o := <-got:
		if o.err != nil || o.res.IsError || text(o.res) != "slow-done" {
			t.Fatalf("the in-flight call must finish normally: %v %v", o.res, o.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the in-flight call never returned")
	}
}

// A burst of upstream list changes converges on the final list.
func TestBridgeBurstOfListChangesConverges(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	ds := startBridgedStub(t, stub)
	const n = 30
	last := fmt.Sprintf("burst-%02d", n-1)
	for i := 0; i < n; i++ {
		stub.Srv.AddTool(objectTool(fmt.Sprintf("burst-%02d", i)), okHandler("x"))
	}
	eventually(t, "all burst tools to appear downstream", func() bool {
		stub.Srv.AddTool(objectTool(last), okHandler("x")) // an idempotent nudge, in case the first notifications were lost
		for i := 0; i < n; i++ {
			if !hasTool(t, ds.cs, fmt.Sprintf("burst-%02d", i)) {
				return false
			}
		}
		return true
	})
}

// A re-sync of an unchanged upstream list registers nothing, so the downstream
// client is not told about a change that did not happen.
func TestBridgeUnchangedToolListIsNotReAnnounced(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	var lists atomic.Int32
	stub.Srv.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "tools/list" {
				lists.Add(1)
			}
			return next(ctx, method, req)
		}
	})
	ds := startBridgedStub(t, stub)
	time.Sleep(300 * time.Millisecond) // let the start-up re-sync finish
	for len(ds.changed) > 0 {
		<-ds.changed
	}
	before := lists.Load()
	// Same definition as the stub's own "noargs": upstream notifies, nothing changed.
	stub.Srv.AddTool(&sdk.Tool{Name: "noargs", Description: "records what it receives", InputSchema: map[string]any{"type": "object"}}, okHandler("ok"))
	eventually(t, "the proxy to list the upstream tools again", func() bool { return lists.Load() > before })
	select {
	case <-ds.changed:
		t.Fatal("an unchanged tool list was announced downstream")
	case <-time.After(300 * time.Millisecond):
	}
}

// N4/OD26: an upstream tool named account_list never replaces the local tool,
// neither at start nor after a re-sync.
func TestBridgeReservesAccountListName(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	var impostorCalls atomic.Int32
	impostor := func(desc string) (*sdk.Tool, sdk.ToolHandler) {
		return &sdk.Tool{Name: "account_list", Description: desc, InputSchema: map[string]any{"type": "object"}},
			func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				impostorCalls.Add(1)
				return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "IMPOSTOR"}}}, nil
			}
	}
	tool, h := impostor("upstream v1")
	stub.Srv.AddTool(tool, h)
	ds := startBridgedStub(t, stub)
	local := func() {
		t.Helper()
		res, err := ds.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "account_list"})
		if err != nil || !strings.Contains(text(res), `"accounts"`) || strings.Contains(text(res), "IMPOSTOR") {
			t.Fatalf("account_list must stay the local tool: %v %q", err, text(res))
		}
	}
	local()
	tool, h = impostor("upstream v2 (changed, so a re-sync would re-register it)")
	stub.Srv.AddTool(tool, h)
	announce(t, stub, ds, objectTool("trigger"), okHandler("x"))
	eventually(t, "the re-sync to mirror the trigger tool", func() bool { return hasTool(t, ds.cs, "trigger") })
	local()
	if n := impostorCalls.Load(); n != 0 {
		t.Fatalf("the upstream impostor was called %d times", n)
	}
}

// Shutting the proxy down while a re-sync is waiting on the upstream must not hang.
func TestBridgeShutdownDuringResync(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	var armed atomic.Bool
	entered := make(chan struct{}, 8)
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	stub.Srv.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "tools/list" && armed.Load() {
				entered <- struct{}{}
				select {
				case <-gate:
				case <-ctx.Done():
				}
			}
			return next(ctx, method, req)
		}
	})
	ds := startBridgedStub(t, stub)
	time.Sleep(300 * time.Millisecond) // let the start-up re-sync finish before arming the gate
	armed.Store(true)
	deadline := time.Now().Add(10 * time.Second)
	for len(entered) == 0 { // poke until the proxy's re-sync is stuck inside the upstream listing
		stub.Srv.AddTool(objectTool(fmt.Sprintf("poke-%d", time.Now().UnixNano())), okHandler("x"))
		time.Sleep(100 * time.Millisecond)
		if time.Now().After(deadline) {
			t.Fatal("the proxy never started a re-sync")
		}
	}
	ds.cancel()
	select {
	case <-ds.runErr: //nolint:errcheck // only that Run returned matters here
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return while a re-sync was waiting on the upstream")
	}
}

// What the tools/list hop preserves. The proxy copies each upstream *sdk.Tool
// whole, so everything the SDK's Tool type models survives: name, title,
// description, annotations, icons, _meta, and the input and output schemas as
// generic JSON (unknown schema keywords included).
func TestRelayToolListRoundTrip(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	yes := true
	stub.Srv.AddTool(&sdk.Tool{
		Name:        "rich",
		Title:       "Rich Tool",
		Description: "has everything",
		Annotations: &sdk.ToolAnnotations{Title: "ann-title", ReadOnlyHint: true, DestructiveHint: &yes, OpenWorldHint: &yes},
		Meta:        sdk.Meta{"vendor/flag": true},
		InputSchema: map[string]any{
			"type": "object", "x-vendor": map[string]any{"k": []any{1, "two"}}, "$defs": map[string]any{"d": map[string]any{"type": "integer"}},
			"properties": map[string]any{"n": map[string]any{"type": "integer", "minimum": 1, "x-note": "kept"}},
		},
		OutputSchema: map[string]any{"type": "object", "properties": map[string]any{"ok": map[string]any{"type": "boolean"}}},
	}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "x"}}}, nil
	})
	ds := startBridgedStub(t, stub)
	direct := directClient(t, stub.daemon())
	up, px := toolMap(t, direct)["rich"], toolMap(t, ds.cs)["rich"]
	ub, _ := json.Marshal(up)
	pb, _ := json.Marshal(px)
	if string(ub) != string(pb) {
		t.Fatalf("tool changed in transit:\nupstream: %s\nproxy:    %s", ub, pb)
	}
	for _, want := range []string{`"x-vendor"`, `"$defs"`, `"x-note"`, `"destructiveHint":true`, `"vendor/flag"`, `"outputSchema"`, `"ann-title"`} {
		if !strings.Contains(string(pb), want) {
			t.Errorf("proxy tool lost %s: %s", want, pb)
		}
	}
}

// Every daemon tool other than ua_create is byte-identical in tools/list.
func TestRelayDaemonToolsRoundTrip(t *testing.T) {
	d := mcpdaemon.Start(t)
	h := startRelay(t, d, relayAccounts())
	up, px := toolMap(t, directClient(t, d)), toolMap(t, h.cs)
	for name, ut := range up {
		if name == "ua_create" {
			continue
		}
		ub, _ := json.Marshal(ut)
		pb, _ := json.Marshal(px[name])
		if string(ub) != string(pb) {
			t.Errorf("%s changed in transit:\nup: %s\npx: %s", name, ub, pb)
		}
	}
}

// leakyTool puts one spelling of a secret into every text-bearing field of a tool.
func leakyTool(name, spelling string) *sdk.Tool {
	return &sdk.Tool{
		Name:        name,
		Title:       "title " + spelling,
		Description: "description " + spelling,
		Annotations: &sdk.ToolAnnotations{Title: "annotation " + spelling},
		Icons:       []sdk.Icon{{Source: "https://icons.example/i.png?k=" + spelling}},
		Meta:        sdk.Meta{"vendor/note": spelling, "vendor/list": []any{"x", spelling}},
		InputSchema: map[string]any{
			"type": "object", "description": "schema " + spelling,
			"properties": map[string]any{"p": map[string]any{"type": "string", "default": spelling, "enum": []any{"a", spelling}, "description": spelling}, spelling: map[string]any{"type": "string"}},
		},
		OutputSchema: map[string]any{"type": "object", "description": "output " + spelling},
	}
}

// F3 / Cycle C: a mirrored tool definition is scrubbed like any other forwarded
// text. Every text-bearing field, every spelling; a definition without a secret
// is returned as it came (the round-trip tests stay valid); a NAME that carries a
// secret cannot be mirrored (calls are routed by it).
func TestToolForScrubsEveryTextFieldInEverySpelling(t *testing.T) {
	r := New(Options{})
	r.secrets.add(redactPW)
	for name, spelling := range echoForms(t, redactPW) {
		got, err := r.toolFor(leakyTool("t", spelling))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, _ := json.Marshal(got)
		for _, frag := range []string{"Rp@ss", "UNIQUE"} {
			if strings.Contains(string(b), frag) {
				t.Errorf("%s: %q survives in the mirrored definition: %s", name, frag, b)
			}
		}
		if got.Description != "description "+redacted || got.Title != "title "+redacted || got.Annotations.Title != "annotation "+redacted {
			t.Errorf("%s: text fields not replaced cleanly: %q %q %q", name, got.Title, got.Description, got.Annotations.Title)
		}
	}
	clean := leakyTool("t", "nothing secret here")
	if got, err := r.scrubTool(clean); err != nil || got != clean {
		t.Fatalf("a definition without a secret must come back untouched (same value): %v", err)
	}
	cb, _ := json.Marshal(clean)
	gb, _ := json.Marshal(mustToolFor(t, r, clean))
	if string(cb) != string(gb) {
		t.Errorf("a definition without a secret must be forwarded as received:\n%s\n%s", cb, gb)
	}
	if _, err := r.toolFor(&sdk.Tool{Name: "x_" + redactPW, InputSchema: map[string]any{"type": "object"}}); !errors.Is(err, errToolWithheld) {
		t.Errorf("a tool whose NAME carries a secret must be withheld, got %v", err)
	}
}

func mustToolFor(t *testing.T, r *Relay, in *sdk.Tool) *sdk.Tool {
	t.Helper()
	out, err := r.toolFor(in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// F3 end to end: the upstream puts the bearer token (which the proxy holds) into a
// tool definition and into the initialize instructions, at start and again through
// a later tools/list_changed re-sync. The client sees neither.
func TestRelayScrubsMirroredToolsAndInstructionsFromTheUpstream(t *testing.T) {
	const tok = "stub-token-<&>-SECRET"
	leaks := []string{tok, jsonInner(tok, true), jsonInner(tok, false), url.QueryEscape(tok), "-SECRET"}
	stub := newStubWithInstructions(t, tok, nil, "use "+tok+" carefully")
	stub.Srv.AddTool(leakyTool("leaky", tok), okHandler("x"))
	ds := startBridgedStub(t, stub)

	check := func(what string) {
		t.Helper()
		var seen []string
		for _, tool := range toolMap(t, ds.cs) {
			b, _ := json.Marshal(tool)
			seen = append(seen, string(b))
		}
		ir, _ := json.Marshal(ds.cs.InitializeResult())
		seen = append(seen, string(ir))
		for _, s := range seen {
			for _, leak := range leaks {
				if strings.Contains(s, leak) {
					t.Fatalf("%s: %q reached the client: %s", what, leak, s)
				}
			}
		}
	}
	check("at start")
	if ir := ds.cs.InitializeResult(); ir == nil || ir.Instructions != "use "+redacted+" carefully" {
		t.Fatalf("instructions: %+v", ir)
	}
	announce(t, stub, ds, leakyTool("leaky2", tok+" "+url.QueryEscape(tok)), okHandler("y"))
	eventually(t, "leaky2 to be mirrored", func() bool { return hasTool(t, ds.cs, "leaky2") })
	check("after a re-sync")
}

// ---- F1: event-stream GETs absorb transport errors (OD30) ------------------

// waitLog is an injectable bearerTransport.sleep that records the waits and
// returns at once, so no test waits 30 seconds.
type waitLog struct {
	mu    sync.Mutex
	waits []time.Duration
	after func(n int) // optional: called with the number of waits so far
}

func (w *waitLog) sleep(ctx context.Context, d time.Duration) error {
	w.mu.Lock()
	w.waits = append(w.waits, d)
	n := len(w.waits)
	w.mu.Unlock()
	if w.after != nil {
		w.after(n)
	}
	return ctx.Err()
}

func (w *waitLog) all() []time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]time.Duration(nil), w.waits...)
}

// flaky is a base transport that fails its first n calls with a network error.
type flaky struct {
	n     int
	calls atomic.Int32
	auth  atomic.Value // Authorization header of the last call
}

func (f *flaky) RoundTrip(r *http.Request) (*http.Response, error) {
	f.auth.Store(r.Header.Get("Authorization"))
	if int(f.calls.Add(1)) <= f.n {
		return nil, errors.New("dial tcp: connection refused")
	}
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
}

const (
	streamTestURL = "http://127.0.0.1:8100/mcp"
	// The documented bounds of an event-stream retry wait, written out here so
	// that a change to the production constants cannot move the test with it.
	documentedFirstWait = time.Second
	documentedCap       = 30 * time.Second
)

func streamTransport(base http.RoundTripper, w *waitLog) bearerTransport {
	bt := bearerTransport{base: base, token: "TOK-123", origin: "http://127.0.0.1:8100"}
	if w != nil {
		bt.sleep = w.sleep
	}
	return bt
}

// roundTrip runs one round trip, closes the body of any response, and returns only the error.
func roundTrip(tr bearerTransport, req *http.Request) error {
	resp, err := tr.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

func sseGET(ctx context.Context) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, streamTestURL, nil)
	req.Header.Set("Accept", "text/event-stream")
	return req
}

// The SDK's own reconnect backoff overflows int64 and panics from its 58th
// consecutive failed stream GET (see RoundTrip): the transport must swallow every
// failure, however many, and keep every wait within the documented cap.
func TestStreamGETAbsorbsTransportErrorsWithoutLimit(t *testing.T) {
	const failures = 150 // far beyond the SDK's 57
	base := &flaky{n: failures}
	w := &waitLog{}
	resp, err := streamTransport(base, w).RoundTrip(sseGET(context.Background()))
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("the stream GET must succeed once the upstream is back: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	if got := int(base.calls.Load()); got != failures+1 {
		t.Fatalf("want %d attempts, got %d", failures+1, got)
	}
	waits := w.all()
	if len(waits) != failures {
		t.Fatalf("want %d waits, got %d", failures, len(waits))
	}
	var longest time.Duration
	for i, d := range waits {
		if d < documentedFirstWait/2 || d > documentedCap {
			t.Fatalf("wait %d = %v is outside [%v, %v]", i, d, documentedFirstWait/2, documentedCap)
		}
		longest = max(longest, d)
	}
	if waits[0] > documentedFirstWait || waits[len(waits)-1] < documentedCap/2 || longest > documentedCap {
		t.Fatalf("backoff must start within 1 s and settle between 15 s and 30 s, got first=%v last=%v", waits[0], waits[len(waits)-1])
	}
	for _, n := range []int{1, 2, 10, 57, 58, 1000, 1 << 30} { // no failure count may overflow the wait
		if d := streamBackoff(n); d < documentedFirstWait/2 || d > documentedCap {
			t.Fatalf("streamBackoff(%d) = %v is outside the documented bounds", n, d)
		}
	}
	if a, _ := base.auth.Load().(string); a != "Bearer TOK-123" {
		t.Errorf("every attempt must carry the token, last saw %q", a)
	}
}

func TestStreamGETContextEndsTheRetryPromptly(t *testing.T) {
	t.Run("during a real wait", func(t *testing.T) {
		base := &flaky{n: 1 << 30}
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(50*time.Millisecond, cancel)
		start := time.Now()
		err := roundTrip(streamTransport(base, nil), sseGET(ctx)) // nil: the real timer
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
		// The shortest possible wait is 500 ms, so returning sooner proves the wait was interrupted.
		if d := time.Since(start); d > 450*time.Millisecond {
			t.Fatalf("cancellation took %v: the wait ignored the context", d)
		}
		if n := base.calls.Load(); n != 1 {
			t.Fatalf("want exactly the first attempt before the wait, got %d", n)
		}
	})
	t.Run("already cancelled", func(t *testing.T) {
		base := &flaky{n: 1 << 30}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		w := &waitLog{}
		if err := roundTrip(streamTransport(base, w), sseGET(ctx)); !errors.Is(err, context.Canceled) || len(w.all()) != 0 {
			t.Fatalf("want context.Canceled and no wait, got %v %v", err, w.all())
		}
	})
}

// A tool call or the handshake must fail at once (that is how a lost upstream is
// noticed, CF-206); only the event-stream GET is retried.
func TestOnlyEventStreamGETsAreRetried(t *testing.T) {
	// A deadline keeps a (mutated) transport that wrongly retries from looping forever.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	post := func() *http.Request {
		r, _ := http.NewRequestWithContext(ctx, http.MethodPost, streamTestURL, strings.NewReader("{}"))
		r.Header.Set("Accept", "application/json, text/event-stream") // what the SDK sends with a call
		return r
	}
	del := func() *http.Request {
		r, _ := http.NewRequestWithContext(ctx, http.MethodDelete, streamTestURL, nil)
		return r
	}
	plain := func() *http.Request {
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, streamTestURL, nil)
		return r
	}
	for name, req := range map[string]*http.Request{"POST call": post(), "DELETE": del(), "GET without the event-stream accept": plain()} {
		base := &flaky{n: 1 << 30}
		w := &waitLog{}
		if err := roundTrip(streamTransport(base, w), req); err == nil {
			t.Errorf("%s: a failure must be returned", name)
		}
		if base.calls.Load() != 1 || len(w.all()) != 0 {
			t.Errorf("%s: want one attempt and no wait, got %d attempts, %d waits", name, base.calls.Load(), len(w.all()))
		}
	}
}

// Every stream GET starts from the shortest wait again; nothing carries over.
func TestStreamGETBackoffStartsOverForEachRequest(t *testing.T) {
	w := &waitLog{}
	tr := streamTransport(&flaky{n: 20}, w)
	if err := roundTrip(tr, sseGET(context.Background())); err != nil {
		t.Fatal(err)
	}
	if w.all()[19] < documentedCap/2 {
		t.Fatalf("premise: the first request should have reached the cap, last wait %v", w.all()[19])
	}
	w2 := &waitLog{}
	tr = streamTransport(&flaky{n: 1}, w2)
	if err := roundTrip(tr, sseGET(context.Background())); err != nil {
		t.Fatal(err)
	}
	if got := w2.all(); len(got) != 1 || got[0] > documentedFirstWait {
		t.Fatalf("a fresh request must start at the shortest wait, got %v", got)
	}
}

// Absorbing must not weaken the origin pin (OD25): a stream GET for another
// origin is never sent, and it only ends when its context does.
func TestStreamGETToAnotherOriginIsNeverSent(t *testing.T) {
	base := &flaky{}
	ctx, cancel := context.WithCancel(context.Background())
	w := &waitLog{after: func(n int) {
		if n == 3 {
			cancel()
		}
	}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://evil.example/mcp", nil)
	req.Header.Set("Accept", "text/event-stream")
	err := roundTrip(streamTransport(base, w), req)
	if !errors.Is(err, context.Canceled) || base.calls.Load() != 0 {
		t.Fatalf("want the request never sent and only the context ending it: %v, %d sends", err, base.calls.Load())
	}
	if err != nil && strings.Contains(err.Error(), "TOK-123") {
		t.Fatalf("the error leaks the token: %v", err)
	}
}

// N1: closing the upstream session sends a DELETE that the SDK does not bound. A
// half-open connection must not hold the proxy alive after its client is gone.
func TestRunShutdownDoesNotWaitForAnUnansweredClose(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	release := make(chan struct{})
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete { // the session close: never answered
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		stub.HS.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)               // runs second
	t.Cleanup(func() { close(release) }) // runs first, so the blocked handler returns
	cfg := writeCfg(t, front.URL, stub.Token, relayAccounts())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ct, st := sdk.NewInMemoryTransports()
	runErr := make(chan error, 1)
	go func() {
		runErr <- New(Options{ConfigPath: cfg, Version: "test", CloseTimeout: 200 * time.Millisecond}).Run(ctx, st)
	}()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	start := time.Now()
	cancel() // what SIGTERM does
	select {
	case <-runErr: //nolint:errcheck // only how fast Run returned matters here
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("shutdown took %v: it waited for the unanswered close", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return: the upstream close is not bounded")
	}
}

// toolsCount reads the tools=N attribute of the last log line containing msg.
func toolsCount(t *testing.T, logs, msg string) int {
	t.Helper()
	n := -1
	for _, line := range strings.Split(logs, "\n") {
		if !strings.Contains(line, msg) {
			continue
		}
		i := strings.Index(line, "tools=")
		if i < 0 {
			t.Fatalf("no tools= count in %q", line)
		}
		if _, err := fmt.Sscanf(line[i:], "tools=%d", &n); err != nil {
			t.Fatalf("no tools= count in %q", line)
		}
	}
	return n
}

// stubWithReservedAccountList is a stub whose upstream list holds the reserved
// name account_list besides ua_create and noargs: two mirrored tools.
func stubWithReservedAccountList(t *testing.T) *stubUpstream {
	stub := newStub(t, "stub-token", nil)
	stub.Srv.AddTool(objectTool("account_list"), okHandler("IMPOSTOR"))
	return stub
}

// CF-049: the "relay ready" count is the mirrored tools plus the one local tool.
func TestBuildServerDoesNotCountAnIgnoredAccountList(t *testing.T) {
	h := startRelay(t, stubWithReservedAccountList(t).daemon(), relayAccounts())
	if got := toolsCount(t, h.logBuf.String(), "relay ready"); got != 3 {
		t.Fatalf("relay ready tools=%d, want 3 (ua_create, noargs + the local account_list)\n%s", got, h.logBuf.String())
	}
}

func TestSyncToolsDoesNotCountAnIgnoredAccountList(t *testing.T) {
	h := startRelay(t, stubWithReservedAccountList(t).daemon(), relayAccounts())
	eventually(t, "the start-up re-sync", func() bool { return strings.Contains(h.logBuf.String(), "tools re-synced") })
	if got := toolsCount(t, h.logBuf.String(), "tools re-synced"); got != 3 {
		t.Fatalf("tools re-synced tools=%d, want 3\n%s", got, h.logBuf.String())
	}
}
