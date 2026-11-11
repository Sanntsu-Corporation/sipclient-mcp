package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// streamRetries is the SDK's "no progress" budget for the standalone SSE stream
// and is deliberately huge (OD16, OD30). The SDK counts a reconnect that does not
// advance the last-event-ID (no new event ID) as "no progress" and, past the
// budget (5 by default), breaks the WHOLE session; the daemon sends no events
// today, so an intermediary that ends idle streams (a reverse proxy with an idle
// timeout) would kill a healthy session after a few minutes although POSTs still
// work. With this budget such a stream is simply re-established every 1-2 s.
//
// The same field is also the bound of the SDK's inner retry loop (connectSSE),
// whose backoff arithmetic overflows and panics from attempt 58 (see
// bearerTransport.RoundTrip). A large value is safe ONLY because that loop's
// counter advances solely when the HTTP round trip returns an error, and the
// proxy's transport never returns one for a stream GET except the context ending
// (TestStreamGETAbsorbsTransportErrorsWithoutLimit): the counter stays at 1.
const streamRetries = 1 << 20

// bridgeState carries the pieces that make the relay more than a one-time
// mirror (OD16): the downstream session (so upstream notifications can be
// re-sent to it), the definitions currently mirrored, and a coalescing re-sync
// signal.
type bridgeState struct {
	mu     sync.Mutex
	srv    *sdk.Server
	up     *sdk.ClientSession // the current upstream session (replaced on re-open, CF-206)
	known  map[string]string  // upstream tool name -> JSON of the definition mirrored for it
	ss     atomic.Pointer[sdk.ServerSession]
	resync chan struct{} // capacity 1; allocated by prepare, never replaced

	// levelLock (capacity 1, so that waiting for it can be given up) serialises a
	// downstream logging/setLevel (store, send to the current session, apply
	// downstream) with a re-open's replay of it (send to the new session, then
	// publish it), CF-206. Taken before mu, never while holding it.
	levelLock chan struct{}
	level     sdk.LoggingLevel // the downstream client's last logging/setLevel; guarded by levelLock
}

// prepare allocates what the upstream notification handlers touch. New calls it
// before any goroutine exists, so a tools/list_changed that arrives while the
// server is still being built is kept (not dropped) and never races with init.
func (b *bridgeState) prepare() {
	b.known = map[string]string{}
	b.resync = make(chan struct{}, 1)
	b.levelLock = make(chan struct{}, 1)
}

// lockLevel takes the level lock, or gives up when ctx ends. When both are
// ready select may pick the lock, so ctx is checked again after taking it: a
// caller that has given up never holds the lock.
func (b *bridgeState) lockLevel(ctx context.Context) error {
	select {
	case b.levelLock <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		<-b.levelLock
		return err
	}
	return nil
}

func (b *bridgeState) unlockLevel() { <-b.levelLock }

func (b *bridgeState) init(srv *sdk.Server) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.srv = srv
}

func (b *bridgeState) current() *sdk.ClientSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.up
}

// bridgeClientOptions wires the upstream client's notification handlers.
// Handlers run on the upstream connection's read loop, so none of them may
// block on an upstream request: the tool re-sync is signalled, not run, here.
func (r *Relay) bridgeClientOptions() *sdk.ClientOptions {
	return &sdk.ClientOptions{
		ToolListChangedHandler: func(context.Context, *sdk.ToolListChangedRequest) { r.requestResync() },
		ProgressNotificationHandler: func(ctx context.Context, req *sdk.ProgressNotificationClientRequest) {
			r.relayProgress(ctx, req.Params)
		},
		LoggingMessageHandler: func(ctx context.Context, req *sdk.LoggingMessageRequest) {
			r.relayLog(ctx, req.Params)
		},
	}
}

// addTool mirrors one upstream tool (replacing any earlier registration). A
// tool whose mirrored definition is unchanged is not registered again, so a
// re-sync of an unchanged list sends the downstream client no notification. The
// name account_list belongs to the local tool (OD26): an upstream tool of that
// name is ignored and reported as errToolReserved, so it is not counted.
func (r *Relay) addTool(t *sdk.Tool) error {
	if t.Name == toolAccountList {
		r.log.Warn("ignoring an upstream tool named account_list: the name is reserved for the local tool")
		return errToolReserved
	}
	tool, err := r.toolFor(t)
	if err != nil {
		return err
	}
	fp, err := json.Marshal(tool)
	if err != nil {
		return err
	}
	b := &r.bridge
	b.mu.Lock()
	unchanged := b.known[t.Name] == string(fp)
	b.known[t.Name] = string(fp)
	srv := b.srv
	b.mu.Unlock()
	if unchanged {
		return nil
	}
	srv.AddTool(tool, r.forward(t.Name))
	return nil
}

func (r *Relay) requestResync() {
	select {
	case r.bridge.resync <- struct{}{}:
	default: // one is already pending; it will see the latest upstream list
	}
}

// resyncLoop re-mirrors the upstream tool list whenever upstream says it changed.
func (r *Relay) resyncLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.bridge.resync:
			if err := r.syncTools(ctx); err != nil {
				r.log.Warn("tool re-sync failed; keeping the current tool list")
			}
		}
	}
}

// syncTools lists the upstream tools again, registers every changed or new one
// (the SDK then notifies the downstream client with tools/list_changed) and
// removes tools the upstream no longer has. On any listing error the current
// list is kept. A call already dispatched keeps running under the definition it
// was dispatched with; calls made after the re-sync see the new list.
func (r *Relay) syncTools(ctx context.Context) error {
	b := &r.bridge
	b.mu.Lock()
	srv, up := b.srv, b.up
	b.mu.Unlock()
	var fresh []*sdk.Tool
	for t, err := range up.Tools(ctx, nil) {
		if err != nil {
			return err
		}
		fresh = append(fresh, t)
	}
	seen := map[string]bool{}
	for _, t := range fresh {
		if err := r.addTool(t); err != nil {
			if !errors.Is(err, errToolReserved) { // addTool already warned about that
				r.log.Warn("skipping an upstream tool that cannot be mirrored")
			}
			continue
		}
		seen[t.Name] = true
	}
	b.mu.Lock()
	var gone []string
	for name := range b.known {
		if !seen[name] {
			gone = append(gone, name)
			delete(b.known, name)
		}
	}
	b.mu.Unlock()
	if len(gone) > 0 {
		sort.Strings(gone)
		srv.RemoveTools(gone...)
	}
	r.log.Info("tools re-synced", "tools", len(seen)+1)
	return nil
}

// relayProgress forwards an upstream progress notification to the downstream
// client. The progress token already matches: the proxy forwards the request's
// _meta (which carries it) upstream unchanged. Ordering against the call's final
// result is not specified: a late progress notification is harmless (the client
// ignores a token it no longer tracks).
func (r *Relay) relayProgress(ctx context.Context, p *sdk.ProgressNotificationParams) {
	ss := r.bridge.ss.Load()
	if ss == nil || p == nil {
		return
	}
	cp := *p
	cp.Message = r.secrets.scrub(p.Message)
	if tok, ok := p.ProgressToken.(string); ok {
		cp.ProgressToken = r.secrets.scrub(tok)
	}
	meta, err := r.secrets.scrubMeta(p.Meta)
	if err != nil {
		return // cannot be checked: drop
	}
	cp.Meta = meta
	_ = ss.NotifyProgress(ctx, &cp)
}

// relayLog forwards an upstream log message; the SDK sends it only if the
// downstream client set a level (see logLevelMiddleware). Like progress, a log
// message may arrive after the result of the call that caused it.
func (r *Relay) relayLog(ctx context.Context, p *sdk.LoggingMessageParams) {
	ss := r.bridge.ss.Load()
	if ss == nil || p == nil {
		return
	}
	data, err := r.secrets.scrubValue(p.Data)
	if err != nil {
		return // cannot be checked: drop
	}
	meta, err := r.secrets.scrubMeta(p.Meta)
	if err != nil {
		return
	}
	cp := *p
	cp.Data, cp.Meta, cp.Logger = data, meta, r.secrets.scrub(p.Logger)
	_ = ss.Log(ctx, &cp)
}

// logLevelMiddleware passes the downstream client's logging/setLevel on to the
// upstream session, so the upstream only sends what the client asked for. The
// level is stored, sent upstream and applied downstream (next) under the level
// lock, so a concurrent setLevel cannot finish in between and then be undone by
// this one. The whole operation, waiting for the lock included, is bounded by
// the handshake timeout (see setUpstreamLevel for the SDK's cleanup after it).
func (r *Relay) logLevelMiddleware(next sdk.MethodHandler) sdk.MethodHandler {
	return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
		if method == "logging/setLevel" {
			if p, ok := req.GetParams().(*sdk.SetLoggingLevelParams); ok {
				b := &r.bridge
				opCtx, cancel := context.WithTimeout(ctx, r.connectTimeout())
				defer cancel()
				if err := b.lockLevel(opCtx); err != nil {
					return nil, fmt.Errorf("logging/setLevel: an earlier level change is still in progress: %w", err)
				}
				defer b.unlockLevel()
				b.level = p.Level
				r.setUpstreamLevel(opCtx, b.current(), p.Level)
			}
		}
		return next(ctx, method, req)
	}
}

// serve connects the downstream transport, remembers the session for the
// notification handlers, starts the tool re-sync loop, and blocks like
// (*sdk.Server).Run: until the client disconnects or ctx ends. It returns only
// after the re-sync loop has stopped (its upstream listing honours ctx).
func (r *Relay) serve(ctx context.Context, srv *sdk.Server, t sdk.Transport) error {
	ss, err := srv.Connect(ctx, t, nil)
	if err != nil {
		return err
	}
	r.bridge.ss.Store(ss)
	loopCtx, stop := context.WithCancel(ctx)
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		r.resyncLoop(loopCtx)
	}()
	defer func() {
		stop()
		<-loopDone
	}()
	// Anything that changed upstream while the server was being built is picked up
	// now (a notification may have arrived before the stream was attached).
	r.requestResync()
	done := make(chan error, 1)
	go func() { done <- ss.Wait() }()
	select {
	case <-ctx.Done():
		_ = ss.Close()
		<-done //nolint:errcheck // wait for the stream goroutine; Run returns ctx.Err(), so its error is moot
		return ctx.Err()
	case err := <-done:
		return err
	}
}
