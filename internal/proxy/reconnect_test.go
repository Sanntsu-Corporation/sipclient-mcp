package proxy

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// CF-206 (OD14 reversed 2026-10-08): a lost upstream session is re-opened on
// demand. The session-expiry tests against the real daemon handler are in
// relay_test.go (TestRelaySessionExpiredUpstream, TestRelayUpstreamLostAfterStart).

// countInits counts the initialize requests the stub answers; while refuse is
// set it rejects them with a JSON-RPC error that quotes the bearer token.
func countInits(stub *stubUpstream, refuse *atomic.Bool) *atomic.Int32 {
	var n atomic.Int32
	stub.Srv.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "initialize" {
				n.Add(1)
				if refuse != nil && refuse.Load() {
					return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "refused Bearer " + stub.Token}
				}
			}
			return next(ctx, method, req)
		}
	})
	return &n
}

func requireNoSecretInLogs(t *testing.T, h *harness, secrets ...string) {
	t.Helper()
	logs := h.logBuf.String()
	for _, s := range secrets {
		if strings.Contains(logs, s) {
			t.Fatalf("the relay log leaks %q: %s", s, logs)
		}
	}
}

// (b) Concurrent calls that all hit the expired session cause exactly ONE new
// initialize; every one of them is retried on that session and succeeds.
func TestReopenIsSingleFlight(t *testing.T) {
	stub := newStub(t, "stub-token-SINGLE-FLIGHT", nil)
	inits := countInits(stub, nil)
	h := startRelay(t, stub.daemon(), relayAccounts())
	if res := h.call(t, "noargs", ""); res.IsError {
		t.Fatalf("premise: %s", text(res))
	}
	stub.expire()
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := h.tryCall("noargs", "")
			switch {
			case err != nil:
				errs <- err.Error()
			case res.IsError || text(res) != "ok":
				errs <- text(res)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("a concurrent call after the expiry failed: %s", e)
	}
	if got := inits.Load(); got != 2 {
		t.Fatalf("%d initialize requests, want 2 (start + exactly one re-open)", got)
	}
}

// A replaced session that ends later (re-open closes it in the background) must
// not mark its successor lost; the current session ending does.
func TestReplacedSessionEndingKeepsTheNewOne(t *testing.T) {
	r := New(Options{})
	s1, s2 := memSession(t), memSession(t)
	r.install(s1)
	if old := r.install(s2); old != s1 {
		t.Fatal("install must return the session it replaces")
	}
	_ = s1.Close()
	time.Sleep(50 * time.Millisecond) // let s1's watcher run
	if r.lost.Load() {
		t.Fatal("the end of a replaced session marked the current one lost")
	}
	_ = s2.Close()
	eventually(t, "the current session's end to mark it lost", r.lost.Load)
}

// (c) A failed re-open returns the lost-session error, scrubbed; a call inside
// the back-off does not touch the daemon; once the back-off has passed, a call
// re-opens the session and succeeds.
func TestReopenFailureBacksOffThenRecovers(t *testing.T) {
	stub := newStub(t, "stub-token-REOPEN-SECRET", nil)
	var refuse atomic.Bool
	inits := countInits(stub, &refuse)
	h := startRelayOpts(t, stub.daemon(), writeCfg(t, stub.HS.URL, stub.Token, relayAccounts()), Options{ReconnectInterval: time.Hour})
	if res := h.call(t, "noargs", ""); res.IsError {
		t.Fatalf("premise: %s", text(res))
	}
	refuse.Store(true)
	stub.expire()
	for i, wantInits := range []int32{2, 2} { // the second call is inside the back-off
		res := h.call(t, "noargs", "")
		out := text(res)
		if !res.IsError || !strings.Contains(out, "upstream session lost") {
			t.Fatalf("call %d: want the lost-session error, got IsError=%v %q", i, res.IsError, out)
		}
		if strings.Contains(out, "REOPEN-SECRET") {
			t.Fatalf("call %d: the error leaks the token: %q", i, out)
		}
		if got := inits.Load(); got != wantInits {
			t.Fatalf("call %d: %d initialize requests, want %d", i, got, wantInits)
		}
	}
	refuse.Store(false)
	// End the back-off without waiting an hour (lastFail is guarded by reopen).
	h.r.reopen <- struct{}{}
	h.r.lastFail = time.Time{}
	<-h.r.reopen
	if res := h.call(t, "noargs", ""); res.IsError || text(res) != "ok" {
		t.Fatalf("after the back-off the session must be re-opened: %q", text(res))
	}
	if got := inits.Load(); got != 3 {
		t.Fatalf("%d initialize requests, want 3", got)
	}
	requireNoSecretInLogs(t, h, stub.Token, relayPassword, relayPassword2)
}

// (d) A call is retried at most once: if the new session is also gone, the
// error is returned (no loop), and a later call re-opens again.
func TestExpiredCallIsRetriedOnlyOnce(t *testing.T) {
	stub := newStub(t, "stub-token-RETRY-ONCE", nil)
	inits := countInits(stub, nil)
	h := startRelay(t, stub.daemon(), relayAccounts())
	if res := h.call(t, "noargs", ""); res.IsError {
		t.Fatalf("premise: %s", text(res))
	}
	stub.expireOnCall.Store(true) // every tools/call now kills its session
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := h.cs.CallTool(ctx, &sdk.CallToolParams{Name: "noargs"})
	if err != nil {
		t.Fatalf("want a tool error, got %v", err)
	}
	out := text(res)
	if !res.IsError || !strings.Contains(out, "upstream session lost") || !strings.Contains(out, "re-established") {
		t.Fatalf("want the lost-session error with the re-open note, got IsError=%v %q", res.IsError, out)
	}
	if got := inits.Load(); got != 2 {
		t.Fatalf("%d initialize requests, want 2 (one re-open, no loop)", got)
	}
	stub.expireOnCall.Store(false)
	if res := h.call(t, "noargs", ""); res.IsError || text(res) != "ok" {
		t.Fatalf("a later call must re-open the session: %q", text(res))
	}
	if got := inits.Load(); got != 3 {
		t.Fatalf("%d initialize requests, want 3", got)
	}
	requireNoSecretInLogs(t, h, stub.Token, relayPassword, relayPassword2)
}

// A call that fails on the new session after a re-open carries a note that the
// UAs of the old session are gone; the daemon's own error is kept.
func TestFailureAfterReopenCarriesTheNote(t *testing.T) {
	stub := newStub(t, "stub-token-NOTE", nil)
	stub.Srv.AddTool(objectTool("fails"), func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return toolError("not_found: no such ua"), nil
	})
	h := startRelay(t, stub.daemon(), relayAccounts())
	if res := h.call(t, "noargs", ""); res.IsError {
		t.Fatalf("premise: %s", text(res))
	}
	stub.expire()
	res := h.call(t, "fails", "")
	out := text(res)
	if !res.IsError || !strings.Contains(out, "not_found: no such ua") || !strings.Contains(out, "UAs created earlier no longer exist") {
		t.Fatalf("want the daemon's error with the re-open note, got %q", out)
	}
	// Without a re-open the same failure carries no note.
	if out := text(h.call(t, "fails", "")); strings.Contains(out, "re-established") {
		t.Fatalf("the note belongs only to the call that re-opened: %q", out)
	}
}

// (e) After a re-open the tool list is re-synced (a tool added while nothing
// could notify the proxy appears downstream) and the downstream client's log
// level is passed on to the new session, so log notifications still arrive.
func TestReopenResyncsToolsAndKeepsBridging(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	stub.getHook = func(w http.ResponseWriter, _ *http.Request) bool {
		w.WriteHeader(http.StatusMethodNotAllowed) // no standalone stream: no tools/list_changed ever arrives
		return true
	}
	stub.Srv.AddTool(objectTool("chatty"), func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		_ = req.Session.Log(ctx, &sdk.LoggingMessageParams{Level: "warning", Logger: "stub", Data: "after re-open"})
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "done"}}}, nil
	})
	ds := startBridgedStub(t, stub)
	if err := ds.cs.SetLoggingLevel(context.Background(), &sdk.SetLoggingLevelParams{Level: "info"}); err != nil {
		t.Fatal(err)
	}
	stub.expire()
	stub.Srv.AddTool(objectTool("late"), okHandler("late-ran"))
	res, err := ds.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "chatty"})
	if err != nil || res.IsError {
		t.Fatalf("the call must be retried on a new session: %v %v", err, res)
	}
	waitFor(t, ds.gotLog, "a log notification from the re-opened session")
	eventually(t, "the tool list to be re-synced after the re-open", func() bool { return hasTool(t, ds.cs, "late") })
	if res, err := ds.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "late"}); err != nil || text(res) != "late-ran" {
		t.Fatalf("the re-synced tool must be callable: %v %v", res, err)
	}
}

// ---- Codex review round 1 (CF-206) -----------------------------------------

// Finding 1: a call whose POST the daemon ACCEPTED is never sent again, even
// when it fails with "session not found" because ANOTHER call's 404 broke the
// shared connection (the SDK retires every pending call with that error). Only
// the call whose own POST got the 404 is retried.
func TestInFlightCallIsNotRetriedWhenAnotherGets404(t *testing.T) {
	stub := newStub(t, "stub-token-IN-FLIGHT", nil)
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	var runs atomic.Int32
	stub.Srv.AddTool(objectTool("slow"), func(ctx context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		if runs.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "slow-ran"}}}, nil
	})
	h := startRelay(t, stub.daemon(), relayAccounts())
	// Registered after startRelay so that it runs first: a failed assertion must
	// not leave the stub blocked while the relay and its client close.
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	type result struct {
		res *sdk.CallToolResult
		err error
	}
	a := make(chan result, 1)
	go func() { res, err := h.tryCall("slow", ""); a <- result{res, err} }()
	waitFor(t, started, "the first call to run upstream")
	stub.expire()
	if res := h.call(t, "noargs", ""); res.IsError {
		t.Fatalf("the call whose own POST got the 404 must be retried: %q", text(res))
	}
	releaseOnce.Do(func() { close(release) })
	var got result
	select {
	case got = <-a:
	case <-time.After(10 * time.Second):
		t.Fatal("the in-flight call never returned")
	}
	if got.err != nil || !got.res.IsError || !strings.Contains(text(got.res), "upstream session lost") {
		t.Fatalf("the in-flight call must fail with the lost-session error: %v %v", got.err, got.res)
	}
	if n := runs.Load(); n != 1 {
		t.Fatalf("the accepted call ran %d times upstream, want 1", n)
	}
}

// Finding 2: a log-level replay the new session never answers is bounded (by
// the handshake timeout); the call goes on and later re-opens are not wedged.
func TestLevelReplayIsBounded(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	var sets atomic.Int32
	stub.Srv.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "logging/setLevel" && sets.Add(1) == 2 { // the replay to the first new session
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return next(ctx, method, req)
		}
	})
	h := startRelayOpts(t, stub.daemon(), writeCfg(t, stub.HS.URL, stub.Token, relayAccounts()), Options{ConnectTimeout: 300 * time.Millisecond})
	if err := h.cs.SetLoggingLevel(context.Background(), &sdk.SetLoggingLevelParams{Level: "info"}); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		stub.expire()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		res, err := h.cs.CallTool(ctx, &sdk.CallToolParams{Name: "noargs"})
		cancel()
		if err != nil || res.IsError {
			t.Fatalf("re-open %d: %v %v", i, err, res)
		}
	}
	if !strings.Contains(h.logBuf.String(), "upstream refused logging/setLevel") {
		t.Fatal("the unanswered replay must be logged")
	}
}

// Finding 3: against a daemon that accepts connections but never answers an
// initialize or a DELETE, timed-out attempts do not pile up: a new attempt waits
// until the previous one has unwound, and the unwinding (the SDK's DELETE) is
// bounded, so the proxy recovers once the daemon answers again.
func TestStalledReopenAttemptsDoNotPileUp(t *testing.T) {
	stub := newStub(t, "stub-token-STALL", nil)
	h := startRelayOpts(t, stub.daemon(), writeCfg(t, stub.HS.URL, stub.Token, relayAccounts()),
		Options{ConnectTimeout: 50 * time.Millisecond, CloseTimeout: 500 * time.Millisecond, ReconnectInterval: time.Millisecond})
	if res := h.call(t, "noargs", ""); res.IsError {
		t.Fatalf("premise: %s", text(res))
	}
	stub.expire()
	stub.stall.Store(1)
	for end := time.Now().Add(time.Second); time.Now().Before(end); {
		if res := h.call(t, "noargs", ""); !res.IsError {
			t.Fatal("premise: a stalled daemon cannot serve the call")
		}
	}
	if m := stub.maxStalled.Load(); m > 2 {
		t.Fatalf("%d unanswered requests at once: abandoned attempts pile up", m)
	}
	stub.stall.Store(0)
	eventually(t, "a call to succeed once the daemon answers again", func() bool { return !h.call(t, "noargs", "").IsError })
}

// Finding 4: an attempt cut short by the caller's cancellation counts as a
// failed attempt for the back-off, so short-deadline calls cannot hammer the daemon.
func TestCancelledReopenCountsForBackoff(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	var inits atomic.Int32
	stub.Srv.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "initialize" && inits.Add(1) > 1 { // every re-open is slow
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
				}
			}
			return next(ctx, method, req)
		}
	})
	h := startRelayOpts(t, stub.daemon(), writeCfg(t, stub.HS.URL, stub.Token, relayAccounts()), Options{ReconnectInterval: time.Hour})
	if res := h.call(t, "noargs", ""); res.IsError {
		t.Fatalf("premise: %s", text(res))
	}
	stub.expire()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, _ = h.cs.CallTool(ctx, &sdk.CallToolParams{Name: "noargs"}) // gives up during the re-open
	cancel()
	// The attempt has begun (inits), ended (the re-open slot is free) and unwound.
	eventually(t, "the cancelled attempt to unwind", func() bool {
		return inits.Load() == 2 && len(h.r.reopen) == 0 && !h.r.unwinding.Load()
	})
	if res := h.call(t, "noargs", ""); !res.IsError || inits.Load() != 2 {
		t.Fatalf("a call inside the back-off must not try again: %q, %d initialize requests", text(res), inits.Load())
	}
}

// Finding 4: a call cancelled before its attempt began does not count.
func TestCancelBeforeReopenDoesNotCount(t *testing.T) {
	for range 20 { // session's select picks either ready case at random
		r := New(Options{ReconnectInterval: time.Hour})
		r.cfg = &Config{Upstream: "http://127.0.0.1:1/mcp", Token: "tok"}
		r.lost.Store(true)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := r.session(ctx); err == nil || !r.lastFail.IsZero() {
			t.Fatalf("err %v, lastFail %v: a call cancelled before the attempt must not count", err, r.lastFail)
		}
	}
}

// Finding 5: the re-open note is scrubbed like everything else: a password
// that equals one of its words never comes back.
func TestReopenNoteIsScrubbed(t *testing.T) {
	stub := newStub(t, "stub-token-NOTE-SCRUB", nil)
	stub.Srv.AddTool(objectTool("fails"), func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return toolError("not_found: no such ua"), nil
	})
	accts := relayAccounts()
	accts["wordy"] = Account{Mode: "direct", Transport: "tls", Username: "wordy", Password: "re-established"}
	h := startRelayWithConfig(t, stub.daemon(), writeCfg(t, stub.HS.URL, stub.Token, accts))
	if res := h.call(t, "noargs", ""); res.IsError {
		t.Fatalf("premise: %s", text(res))
	}
	stub.expire()
	out := text(h.call(t, "fails", ""))
	if !strings.Contains(out, "not_found") || strings.Contains(out, "re-established") || !strings.Contains(out, "[redacted]") {
		t.Fatalf("the note must be scrubbed: %q", out)
	}
}

// Finding 6: a downstream logging/setLevel that arrives while the level is being
// replayed to a new session is applied after the replay, so the upstream ends at
// the level the client set last (and the stored level agrees); no call uses the
// new session before the replay to it has finished.
func TestLevelReplayDoesNotOverwriteANewerLevel(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	var (
		mu       sync.Mutex
		levels   = map[*sdk.ServerSession]sdk.LoggingLevel{}
		lastCall *sdk.ServerSession
		sets     atomic.Int32
	)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	stub.Srv.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			ss, _ := req.GetSession().(*sdk.ServerSession)
			switch method {
			case "logging/setLevel":
				if sets.Add(1) == 2 { // the replay to the new session
					close(entered)
					<-release
				}
				mu.Lock()
				levels[ss] = req.GetParams().(*sdk.SetLoggingLevelParams).Level
				mu.Unlock()
			case "tools/call":
				mu.Lock()
				lastCall = ss
				mu.Unlock()
			}
			return next(ctx, method, req)
		}
	})
	h := startRelay(t, stub.daemon(), relayAccounts())
	// Registered after startRelay so that it runs first: a failed assertion must
	// not leave the stub blocked while the relay and its client close.
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	if err := h.cs.SetLoggingLevel(context.Background(), &sdk.SetLoggingLevelParams{Level: "info"}); err != nil {
		t.Fatal(err)
	}
	stub.expire()
	callDone := make(chan *sdk.CallToolResult, 1)
	go func() { res, _ := h.tryCall("noargs", ""); callDone <- res }()
	waitFor(t, entered, "the level replay to the new session")
	setDone := make(chan error, 1)
	go func() {
		setDone <- h.cs.SetLoggingLevel(context.Background(), &sdk.SetLoggingLevelParams{Level: "error"})
	}()
	call2Done := make(chan struct{})
	go func() { _, _ = h.tryCall("noargs", ""); close(call2Done) }()
	select { // with serialization the set waits for the replay; give an unserialized one time to land
	case err := <-setDone:
		setDone <- err
	case <-time.After(200 * time.Millisecond):
	}
	select {
	case <-call2Done:
		t.Fatal("a call used the new session before the level replay to it had finished")
	default:
	}
	releaseOnce.Do(func() { close(release) })
	waitFor(t, call2Done, "the second call")
	if res := <-callDone; res == nil || res.IsError {
		t.Fatalf("the call must succeed on the new session: %v", res)
	}
	if err := <-setDone; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := levels[lastCall]
	mu.Unlock()
	stored := storedLevel(t, h.r)
	if got != "error" || stored != "error" {
		t.Fatalf("new session level %q, stored %q: want both \"error\" (the client's last setLevel)", got, stored)
	}
}

// ---- Codex review round 2 (CF-206) -----------------------------------------

func storedLevel(t *testing.T, r *Relay) sdk.LoggingLevel {
	t.Helper()
	if err := r.bridge.lockLevel(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer r.bridge.unlockLevel()
	return r.bridge.level
}

// Round 2 finding 1: a downstream logging/setLevel is applied to the downstream
// session (next) inside the level lock, so a concurrent one cannot finish in
// between and then be undone by the first: downstream, stored and upstream
// levels end up equal. next is called directly, so the test controls the moment
// the first level is applied downstream.
func TestDownstreamLevelIsAppliedInsideTheLock(t *testing.T) {
	r := New(Options{})
	r.install(memSession(t))
	var (
		mu         sync.Mutex
		downstream sdk.LoggingLevel
	)
	enteredA, releaseA := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseA) }) })
	handler := r.logLevelMiddleware(func(_ context.Context, _ string, req sdk.Request) (sdk.Result, error) {
		level := req.GetParams().(*sdk.SetLoggingLevelParams).Level
		if level == "info" { // A: hold it while it applies its level downstream
			close(enteredA)
			<-releaseA
		}
		mu.Lock()
		downstream = level
		mu.Unlock()
		return nil, nil
	})
	set := func(level sdk.LoggingLevel) chan error {
		done := make(chan error, 1)
		go func() {
			_, err := handler(context.Background(), "logging/setLevel",
				&sdk.ServerRequest[*sdk.SetLoggingLevelParams]{Params: &sdk.SetLoggingLevelParams{Level: level}})
			done <- err
		}()
		return done
	}
	aDone := set("info")
	waitFor(t, enteredA, "the first setLevel to reach the downstream session")
	bDone := set("error")
	select { // serialized, B waits for A; unserialized, give B time to finish first
	case err := <-bDone:
		bDone <- err
	case <-time.After(200 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(releaseA) })
	for _, done := range []chan error{aDone, bDone} {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	got := downstream
	mu.Unlock()
	if stored := storedLevel(t, r); got != "error" || stored != "error" {
		t.Fatalf("downstream %q, stored %q: want both \"error\" (the last setLevel)", got, stored)
	}
}

// Round 2 finding 2: a level replay to a daemon that answers neither the
// setLevel nor the SDK's notifications/cancelled is bounded by the handshake
// timeout plus CloseTimeout (not the SDK's own 5 s), and waiting for the level
// lock gives up with the caller's context and at the operation deadline: a
// downstream setLevel that gave up leaves no trace.
func TestStalledLevelOperationsAreBounded(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	var sets atomic.Int32
	entered, hold := make(chan struct{}), make(chan struct{})
	stub.Srv.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "logging/setLevel" && sets.Add(1) == 2 { // the replay: never answered
				close(entered)
				<-hold
			}
			return next(ctx, method, req)
		}
	})
	h := startRelayOpts(t, stub.daemon(), writeCfg(t, stub.HS.URL, stub.Token, relayAccounts()),
		Options{ConnectTimeout: 300 * time.Millisecond, CloseTimeout: 300 * time.Millisecond})
	t.Cleanup(func() { close(hold) }) // registered after startRelay, so it runs first
	if err := h.cs.SetLoggingLevel(context.Background(), &sdk.SetLoggingLevelParams{Level: "info"}); err != nil {
		t.Fatal(err)
	}
	stub.stallCancel.Store(true)
	stub.expire()
	start := time.Now()
	callDone := make(chan *sdk.CallToolResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		res, _ := h.cs.CallTool(ctx, &sdk.CallToolParams{Name: "noargs"})
		callDone <- res
	}()
	waitFor(t, entered, "the level replay to the new session")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_ = h.cs.SetLoggingLevel(ctx, &sdk.SetLoggingLevelParams{Level: "error"}) // gives up while waiting
	cancel()
	if err := h.cs.SetLoggingLevel(context.Background(), &sdk.SetLoggingLevelParams{Level: "debug"}); err == nil {
		t.Fatal("a setLevel still waiting for the lock at the operation deadline must fail")
	}
	res := <-callDone
	if res == nil || res.IsError {
		t.Fatalf("the call must go on after the bounded replay: %v", res)
	}
	if d := time.Since(start); d > 2500*time.Millisecond {
		t.Fatalf("the stalled replay held the re-open for %v; want about ConnectTimeout + CloseTimeout", d)
	}
	if stored := storedLevel(t, h.r); stored != "info" {
		t.Fatalf("stored level %q: setLevels that gave up must leave no trace", stored)
	}
}

// Round 2 finding 2: a re-open that waits for the level lock behind a stalled
// downstream setLevel gives up at its operation deadline (the handshake
// timeout) instead of waiting for the holder: the call gets the lost-session
// error. A 503 marks the session lost without breaking its connection, so the
// stalled setLevel on it keeps the lock (a 404 would fail it at once).
func TestReopenGivesUpWaitingForAStalledLevelChange(t *testing.T) {
	stub := newStub(t, "stub-token", nil)
	var sets atomic.Int32
	entered, hold := make(chan struct{}), make(chan struct{})
	stub.Srv.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "logging/setLevel" && sets.Add(1) == 1 { // the downstream change: never answered
				close(entered)
				<-hold
			}
			return next(ctx, method, req)
		}
	})
	h := startRelayOpts(t, stub.daemon(), writeCfg(t, stub.HS.URL, stub.Token, relayAccounts()),
		Options{ConnectTimeout: 300 * time.Millisecond, CloseTimeout: time.Second})
	t.Cleanup(func() { close(hold) }) // registered after startRelay, so it runs first
	stub.stallCancel.Store(true)      // the holder keeps the lock for 300 ms + 1 s
	setDone := make(chan struct{})
	go func() {
		_ = h.cs.SetLoggingLevel(context.Background(), &sdk.SetLoggingLevelParams{Level: "info"})
		close(setDone)
	}()
	waitFor(t, entered, "the downstream setLevel to reach the upstream")
	stub.rejectNextCall.Store(true)
	if res := h.call(t, "noargs", ""); !res.IsError {
		t.Fatalf("premise: the 503 marks the session lost: %q", text(res))
	}
	res := h.call(t, "noargs", "") // re-opens
	if out := text(res); !res.IsError || !strings.Contains(out, "log-level change is still in progress") {
		t.Fatalf("the re-open must give up waiting for the level lock: IsError=%v %q", res.IsError, out)
	}
	waitFor(t, setDone, "the stalled downstream setLevel to end")
}

// ---- Codex review round 3 (CF-206) -----------------------------------------

// A cancelled caller never gets the level lock, even when the lock is free (both
// select cases ready): the middleware stores and applies nothing, and the lock
// stays free. Repeated because select picks a ready case at random.
func TestCancelledSetLevelNeverTakesAFreeLock(t *testing.T) {
	r := New(Options{})
	r.install(memSession(t))
	applied := false
	handler := r.logLevelMiddleware(func(context.Context, string, sdk.Request) (sdk.Result, error) {
		applied = true
		return nil, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 50 {
		_, err := handler(ctx, "logging/setLevel",
			&sdk.ServerRequest[*sdk.SetLoggingLevelParams]{Params: &sdk.SetLoggingLevelParams{Level: "error"}})
		if err == nil || applied || len(r.bridge.levelLock) != 0 {
			t.Fatalf("err %v, applied downstream %v, lock held %v: a cancelled setLevel must do nothing", err, applied, len(r.bridge.levelLock) != 0)
		}
	}
	if stored := storedLevel(t, r); stored != "" {
		t.Fatalf("stored level %q: a cancelled setLevel must not store it", stored)
	}
}

// The same for a re-open: publish with a cancelled context fails and does not
// make the new session current.
func TestCancelledPublishNeverTakesAFreeLock(t *testing.T) {
	r := New(Options{})
	first := memSession(t)
	r.install(first)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 50 {
		if _, err := r.publish(ctx, memSession(t)); err == nil || r.bridge.current() != first || len(r.bridge.levelLock) != 0 {
			t.Fatalf("err %v: a cancelled publish must fail, install nothing and leave the lock free", err)
		}
	}
}
