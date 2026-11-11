package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	toolUACreate    = "ua_create"
	toolAccountList = "account_list"

	// dialTimeout bounds connection setup so an unreachable or black-holed
	// upstream cannot hang a call. Established calls are bounded by the MCP
	// client's own cancellation, not by a timer: call_wait can legitimately block.
	dialTimeout = 10 * time.Second

	// defaultConnectTimeout bounds the whole upstream handshake (OD27): an
	// upstream that accepts the TCP connection and never answers must not hang the
	// proxy's start (the dial timeout only covers the TCP connect).
	defaultConnectTimeout = 30 * time.Second

	// defaultCloseTimeout bounds the upstream session close at shutdown: the SDK
	// sends a DELETE that has no timeout of its own, so a half-open connection
	// would keep the proxy alive for minutes after its client went away.
	defaultCloseTimeout = 3 * time.Second

	// defaultReconnectInterval is the least time between two failed attempts to
	// re-open a lost upstream session (CF-206): a down daemon gets at most one
	// handshake a second, however many calls arrive.
	defaultReconnectInterval = time.Second

	// lostMessage is what the model reads when the upstream session is gone and no
	// new one could be opened (CF-206; OD14, which never reconnected, was reversed
	// by owner ruling on 2026-10-08).
	lostMessage = "upstream session lost: the sipclient daemon is down or was restarted, the session expired, the network dropped, " +
		"or the daemon token was rotated or rejected. The proxy opens a new session on the next call (at most one attempt a second); " +
		"after a token rotation, edit \"token\" in the config file and restart this MCP client (or its sipclient-proxy server). " +
		"UAs created earlier no longer exist and must be recreated."

	// reopenNote prefixes a failed result of a call that ran on a session the
	// proxy re-opened during that call (CF-206).
	reopenNote = "the upstream session expired or the daemon restarted, and the proxy re-established it; " +
		"UAs created earlier no longer exist and must be recreated. "
)

// Options configure a Relay.
type Options struct {
	ConfigPath string
	Version    string
	// Log receives constant lifecycle messages only. Nothing that handles tool
	// arguments, results, the token or the config contents is ever passed to it.
	Log *slog.Logger
	// ConnectTimeout bounds the upstream handshake at start. Zero means
	// defaultConnectTimeout (OD27); tests set a short one.
	ConnectTimeout time.Duration
	// CloseTimeout bounds the upstream session close at shutdown. Zero means
	// defaultCloseTimeout; tests set a short one.
	CloseTimeout time.Duration
	// ReconnectInterval is the least time between two failed attempts to re-open
	// a lost upstream session. Zero means defaultReconnectInterval.
	ReconnectInterval time.Duration
}

// Relay is the stdio-facing MCP server in front of one upstream session at a
// time: a lost session is replaced on demand (CF-206).
type Relay struct {
	opts    Options
	log     *slog.Logger
	secrets *secretSet  // bearer token + every password injected so far
	lost    atomic.Bool // the current upstream session is gone; the next call re-opens it (CF-206)
	bridge  bridgeState // notification bridging and tool re-sync (OD16)

	cfg       *Config       // as loaded at start: every session uses its upstream and token
	reopen    chan struct{} // capacity 1: held by the one call re-opening the session
	lastFail  time.Time     // when the last re-open attempt failed; guarded by reopen
	unwinding atomic.Bool   // a timed-out handshake is still being closed in the background
}

// New returns a Relay.
func New(o Options) *Relay {
	l := o.Log
	if l == nil {
		l = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	r := &Relay{opts: o, log: l, secrets: newSecretSet(), reopen: make(chan struct{}, 1)}
	r.bridge.prepare() // before any goroutine exists: an early upstream notification must find its channel
	return r
}

// bearerTransport adds the bearer token to a CLONE of each request, but only to
// a request for the configured upstream origin (OD25): whatever redirects or
// rewrites a request, the token is never sent to another scheme, host or port.
//
// It also keeps the SDK's event-stream reconnects from ever failing (OD30): see
// RoundTrip.
type bearerTransport struct {
	base   http.RoundTripper
	token  string
	origin string // scheme://host:port of the configured upstream; "" matches nothing
	// sleep waits between two attempts of an event-stream GET and returns early
	// with the context's error if it ends first. nil means a real timer; tests
	// inject a recorder so that no test waits 30 seconds.
	sleep func(ctx context.Context, d time.Duration) error
	// closeTimeout bounds a DELETE (the SDK's session close); zero means
	// defaultCloseTimeout.
	closeTimeout time.Duration
}

// callProbe records what became of one tool call's POST (CF-206). The SDK
// (go-sdk v1.6.1, mcp/streamable.go Write) sends a call's POST synchronously
// inside CallTool, with the call's context, so bearerTransport finds the probe
// in that context and the record is complete when CallTool returns.
type callProbe struct{ sent, rejected atomic.Bool }

type probeKey struct{}

// neverRan reports whether the daemon cannot have run the call that failed
// with err, so that sending it again on a new session cannot run it twice:
// either its OWN POST was answered HTTP 404 (a server answers 404 for a session
// it no longer has, without processing the request), or its POST was never
// sent and err says the session is gone or closed. A call whose POST was sent
// and not rejected may have run - another call's 404 fails the shared
// connection and the SDK then fails every pending call with "session not
// found" - so it is never sent again: its caller gets the error.
func (p *callProbe) neverRan(err error) bool {
	return p.rejected.Load() || !p.sent.Load() && (errors.Is(err, sdk.ErrSessionMissing) || errors.Is(err, sdk.ErrConnectionClosed))
}

const (
	streamBackoffMin = time.Second
	streamBackoffMax = 30 * time.Second
)

// isStreamGET reports whether req is one of the SDK's event-stream GETs: the
// standalone notification stream, or the resumption of a call's stream.
func isStreamGET(req *http.Request) bool {
	return req.Method == http.MethodGet && strings.Contains(strings.ToLower(req.Header.Get("Accept")), "text/event-stream")
}

// streamBackoff is the wait before retry number failures (1-based): 1 s growing
// by half each time up to 30 s, then jittered down to between half and all of it.
func streamBackoff(failures int) time.Duration {
	d := streamBackoffMin
	for i := 1; i < failures && d < streamBackoffMax; i++ {
		d += d / 2
	}
	d = min(d, streamBackoffMax)
	return d/2 + rand.N(d/2)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// originOf returns scheme://host:port with scheme and host lower-cased and the
// default port made explicit.
func originOf(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "80"
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// RoundTrip sends req. A transport error of an event-stream GET is ABSORBED: the
// GET is retried here, after a jittered wait of at most 30 s, until it gets an
// answer or its context ends (the only error it ever returns). The SDK (go-sdk
// v1.6.1, mcp/streamable.go connectSSE) retries a failed stream GET itself, but
// its backoff is time.Duration(1s * 1.5^(attempt-1)); from attempt 58 that float
// overflows int64, min(..., 30s) keeps the negative value and rand.N panics,
// which would kill the proxy after about 40 minutes of a daemon or VPN outage.
// Because the SDK never sees a failure, its attempt counter never climbs. Any
// other request (a tool call, the initialize handshake, the closing DELETE) is
// NOT absorbed: it fails promptly, which is how a lost upstream is noticed (CF-206).
//
// A DELETE is bounded by closeTimeout: the SDK sends it with no deadline, so a
// daemon that never answers would keep a closing session, or an abandoned
// handshake, alive for ever (CF-206). So is a notifications/cancelled POST: the
// SDK sends one, with its own 5 s limit, after a request's context ended, and it
// would stretch every bounded operation by those 5 s. Their response bodies are
// unreadable once this returns; the SDK only reads the status. A POST carrying a
// callProbe is recorded in it.
func (b bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodDelete || isCancelNotification(req) {
		timeout := b.closeTimeout
		if timeout <= 0 {
			timeout = defaultCloseTimeout
		}
		ctx, cancel := context.WithTimeout(req.Context(), timeout)
		defer cancel()
		return b.send(req.WithContext(ctx))
	}
	if p, ok := req.Context().Value(probeKey{}).(*callProbe); ok && req.Method == http.MethodPost {
		p.sent.Store(true)
		resp, err := b.send(req)
		if err == nil && resp.StatusCode == http.StatusNotFound {
			p.rejected.Store(true)
		}
		return resp, err
	}
	if !isStreamGET(req) {
		return b.send(req)
	}
	ctx := req.Context()
	for failures := 1; ; failures++ {
		resp, err := b.send(req)
		if err == nil {
			return resp, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		sleep := b.sleep
		if sleep == nil {
			sleep = sleepCtx
		}
		if err := sleep(ctx, streamBackoff(failures)); err != nil {
			return nil, err
		}
	}
}

// cancelNotificationMax is far above the size of a notifications/cancelled body
// (a request id and a short reason), so larger POSTs are never scanned.
const cancelNotificationMax = 4096

// isCancelNotification reports whether req is a POST of notifications/cancelled.
func isCancelNotification(req *http.Request) bool {
	if req.Method != http.MethodPost || req.GetBody == nil || req.ContentLength < 0 || req.ContentLength > cancelNotificationMax {
		return false
	}
	body, err := req.GetBody()
	if err != nil {
		return false
	}
	defer func() { _ = body.Close() }()
	var msg struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
	}
	return json.NewDecoder(body).Decode(&msg) == nil && msg.Method == "notifications/cancelled" && msg.ID == nil
}

func (b bearerTransport) send(req *http.Request) (*http.Response, error) {
	if b.origin == "" || originOf(req.URL) != b.origin {
		return nil, fmt.Errorf("refusing to send the bearer token to %s: it is not the configured upstream origin", originOf(req.URL))
	}
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// newHTTPClient returns the upstream HTTP client: origin-pinned bearer auth, a
// dial timeout, a DELETE bounded by closeTimeout (zero: defaultCloseTimeout),
// and no redirect is ever followed (OD25).
func newHTTPClient(upstream, token string, closeTimeout time.Duration) *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DialContext = (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext
	return newBearerClient(base, upstream, token, closeTimeout)
}

// newBearerClient is newHTTPClient over an explicit base transport (tests use a
// TLS test server's transport).
func newBearerClient(base http.RoundTripper, upstream, token string, closeTimeout time.Duration) *http.Client {
	origin := ""
	if u, err := url.Parse(upstream); err == nil && u.Host != "" {
		origin = originOf(u)
	}
	return &http.Client{
		Transport:     bearerTransport{base: base, token: token, origin: origin, closeTimeout: closeTimeout},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Run connects upstream (failing fast), then serves t until the client
// disconnects or ctx ends. A session lost later is re-opened by the next call
// (CF-206). An error returned after the token is known may quote the upstream
// (a JSON-RPC error to initialize or tools/list), so it is scrubbed: the caller
// prints it.
func (r *Relay) Run(ctx context.Context, t sdk.Transport) (err error) {
	cfg, err := LoadConfig(r.opts.ConfigPath)
	if err != nil {
		return err
	}
	cfg.addSecretsTo(r.secrets)
	defer func() {
		if err != nil {
			if msg := err.Error(); r.secrets.carriesSecret(msg) {
				err = errors.New(r.secrets.scrub(msg)) // an unchanged error keeps its chain (context.Canceled)
			}
		}
	}()
	up, err := r.connectUpstream(ctx, cfg)
	if err != nil {
		return err
	}
	r.cfg = cfg
	r.install(up)
	defer func() { closeUpstream(r.bridge.current(), r.opts.CloseTimeout) }()
	srv, err := r.buildServer(ctx, up)
	if err != nil {
		return err
	}
	return r.serve(ctx, srv, t)
}

// closeUpstream closes the upstream session but never waits longer than timeout
// (default defaultCloseTimeout): the close sends a DELETE the SDK does not bound,
// and the process is about to exit, so an unanswered DELETE is abandoned.
func closeUpstream(cs *sdk.ClientSession, timeout time.Duration) {
	if timeout <= 0 {
		timeout = defaultCloseTimeout
	}
	done := make(chan struct{})
	go func() {
		_ = cs.Close()
		close(done)
	}()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
}

// install makes up the current upstream session and returns the one it
// replaces (nil at start). When up ends, it is marked lost unless it was
// already replaced.
func (r *Relay) install(up *sdk.ClientSession) (old *sdk.ClientSession) {
	b := &r.bridge
	b.mu.Lock()
	old, b.up = b.up, up
	r.lost.Store(false)
	b.mu.Unlock()
	go func() { _ = up.Wait(); r.dropSession(up) }()
	return old
}

// dropSession marks up lost if it is still the current session.
func (r *Relay) dropSession(up *sdk.ClientSession) {
	b := &r.bridge
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.up == up {
		r.lost.Store(true)
	}
}

// session returns the current upstream session, first re-opening it if it was
// lost (CF-206). One call re-opens at a time; calls that wait for it then use
// its session. After a failed attempt (including one its caller gave up on) no
// new one is made for ReconnectInterval, and none while a timed-out handshake
// is still being closed, so a down or hung daemon is not hammered and abandoned
// attempts do not pile up. The new session has the same upstream, token,
// origin pinning (OD25) and handshake timeout (OD27) as the first; the
// downstream log level is passed on before any call can use it, and the tool
// list is re-synced (OD16).
func (r *Relay) session(ctx context.Context) (*sdk.ClientSession, error) {
	if !r.lost.Load() {
		return r.bridge.current(), nil
	}
	select {
	case r.reopen <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-r.reopen }()
	if !r.lost.Load() {
		return r.bridge.current(), nil // re-opened while this call waited
	}
	if err := ctx.Err(); err != nil {
		return nil, err // given up before the attempt began: not a failed attempt
	}
	interval := r.opts.ReconnectInterval
	if interval <= 0 {
		interval = defaultReconnectInterval
	}
	if wait := interval - time.Since(r.lastFail); wait > 0 {
		return nil, fmt.Errorf("the last attempt to open a new session failed; the next is allowed in %s", wait.Round(time.Millisecond))
	}
	if r.unwinding.Load() {
		return nil, errors.New("an earlier attempt to open a new session timed out and is still being closed")
	}
	up, err := r.connectUpstream(ctx, r.cfg)
	var old *sdk.ClientSession
	if err == nil {
		if old, err = r.publish(ctx, up); err != nil {
			go closeUpstream(up, r.opts.CloseTimeout)
		}
	}
	if err != nil {
		r.lastFail = time.Now()
		r.log.Warn("upstream session could not be re-opened")
		return nil, err
	}
	if old != nil {
		go closeUpstream(old, r.opts.CloseTimeout)
	}
	r.requestResync()
	r.log.Warn("upstream session re-opened; UAs created on the old session no longer exist")
	return up, nil
}

// publish passes the downstream client's log level to the new session up, then
// makes up current, and returns the session it replaced. It holds the level
// lock, as logLevelMiddleware does, so whichever runs second wins on the new
// session and in the stored level alike, and no call uses up before it has the
// level. Waiting for the lock and the replay together are bounded by the
// handshake timeout; if the lock cannot be had in time, the re-open fails.
func (r *Relay) publish(ctx context.Context, up *sdk.ClientSession) (*sdk.ClientSession, error) {
	b := &r.bridge
	opCtx, cancel := context.WithTimeout(ctx, r.connectTimeout())
	defer cancel()
	if err := b.lockLevel(opCtx); err != nil {
		return nil, fmt.Errorf("a log-level change is still in progress: %w", err)
	}
	defer b.unlockLevel()
	if b.level != "" {
		r.setUpstreamLevel(opCtx, up, b.level)
	}
	return r.install(up), nil
}

// setUpstreamLevel sends level to up within ctx, which carries the operation's
// deadline (the handshake timeout). When that deadline ends the call, the SDK
// first sends notifications/cancelled, which the transport bounds by
// CloseTimeout: a daemon that answers neither holds the level lock (and a
// re-open) for at most the handshake timeout plus CloseTimeout.
func (r *Relay) setUpstreamLevel(ctx context.Context, up *sdk.ClientSession, level sdk.LoggingLevel) {
	if err := up.SetLoggingLevel(ctx, &sdk.SetLoggingLevelParams{Level: level}); err != nil {
		r.log.Warn("upstream refused logging/setLevel")
	}
}

func (r *Relay) connectTimeout() time.Duration {
	if r.opts.ConnectTimeout <= 0 {
		return defaultConnectTimeout
	}
	return r.opts.ConnectTimeout
}

func (r *Relay) connectUpstream(ctx context.Context, cfg *Config) (*sdk.ClientSession, error) {
	tr := &sdk.StreamableClientTransport{
		Endpoint:   cfg.Upstream,
		HTTPClient: newHTTPClient(cfg.Upstream, cfg.Token, r.opts.CloseTimeout),
		// Standalone SSE stays ON (the SDK default) so upstream notifications
		// (tools/list_changed, progress, log messages) reach bridgeClientOptions.
		MaxRetries: streamRetries,
	}
	timeout := r.connectTimeout()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := sdk.NewClient(&sdk.Implementation{Name: "sipclient-proxy", Version: r.opts.Version}, r.bridgeClientOptions())
	// Connect runs in its own goroutine because the SDK closes a half-open session
	// with a DELETE that ignores this context: against an upstream that never
	// answers, Connect itself would outlive its context. On timeout the goroutine
	// is abandoned (and closes the session if the upstream ever answers); the
	// cancelled context ends its handshake request, the transport bounds its
	// DELETE, and unwinding stays set until it has finished.
	type connected struct {
		cs  *sdk.ClientSession
		err error
	}
	ch := make(chan connected, 1)
	go func() {
		cs, err := c.Connect(cctx, tr, nil)
		ch <- connected{cs, err}
	}()
	var cs *sdk.ClientSession
	var err error
	select {
	case res := <-ch:
		cs, err = res.cs, res.err
	case <-cctx.Done():
		err = cctx.Err()
		r.unwinding.Store(true)
		go func() {
			if res := <-ch; res.cs != nil {
				_ = res.cs.Close()
			}
			r.unwinding.Store(false)
		}()
	}
	if err != nil {
		return nil, fmt.Errorf("cannot reach upstream %s (check the URL and token; the handshake is limited to %s): %w", cfg.Upstream, timeout, err)
	}
	r.log.Info("upstream connected")
	return cs, nil
}

// errToolWithheld means an upstream tool definition cannot be mirrored safely:
// it could not be checked for credentials, or its NAME contained one (the name
// is what calls are routed by, so it cannot be replaced by a placeholder).
var errToolWithheld = errors.New("upstream tool definition withheld: it could not be checked for credentials")

// errToolReserved means an upstream tool was ignored because its name is
// reserved for a local tool: it is not mirrored, so callers do not count it.
var errToolReserved = errors.New("upstream tool ignored: its name is reserved for a local tool")

// scrubTool returns t with every credential removed. The definition is scrubbed
// as the JSON document it is sent as, every string value and key like any other
// forwarded structure, so every text-bearing field is covered without a field
// list to keep up to date: name, title, description, annotations, input and
// output schemas, icons and _meta. When nothing needs scrubbing it returns t
// itself, so a definition that carries no secret is forwarded exactly as
// received (D6, TestRelayToolListRoundTrip).
func (r *Relay) scrubTool(t *sdk.Tool) (*sdk.Tool, error) {
	raw, err := json.Marshal(t)
	if err != nil {
		return nil, errToolWithheld
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if dec.Decode(&doc) != nil {
		return nil, errToolWithheld
	}
	clean, err := r.secrets.scrubValue(doc)
	if err != nil {
		return nil, errToolWithheld
	}
	if reflect.DeepEqual(doc, clean) {
		return t, nil
	}
	b, err := json.Marshal(clean)
	if err != nil {
		return nil, errToolWithheld
	}
	var out sdk.Tool
	if json.Unmarshal(b, &out) != nil || out.Name != t.Name {
		return nil, errToolWithheld
	}
	return &out, nil
}

// toolFor returns the tool as the proxy advertises it: the scrubbed upstream
// definition, except that ua_create gets the rewritten schema and description note.
func (r *Relay) toolFor(t *sdk.Tool) (*sdk.Tool, error) {
	clean, err := r.scrubTool(t)
	if err != nil {
		return nil, err
	}
	tool := *clean // copies description, annotations, output schema, title, icons, _meta
	if clean.Name == toolUACreate {
		schema, err := RewriteUACreateSchema(clean.InputSchema)
		if err != nil {
			return nil, err
		}
		tool.InputSchema = schema
		tool.Description = clean.Description + UACreateDescriptionNote
	}
	return &tool, nil
}

func (r *Relay) buildServer(ctx context.Context, up *sdk.ClientSession) (*sdk.Server, error) {
	opts := &sdk.ServerOptions{}
	if ir := up.InitializeResult(); ir != nil {
		opts.Instructions = r.secrets.scrub(ir.Instructions) // a no-op unless a secret is present
	}
	srv := sdk.NewServer(&sdk.Implementation{Name: "sipclient-proxy", Version: r.opts.Version}, opts)
	r.bridge.init(srv)
	srv.AddReceivingMiddleware(r.logLevelMiddleware)
	n := 0
	for t, err := range up.Tools(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("list upstream tools: %w", err)
		}
		switch err := r.addTool(t); {
		case errors.Is(err, errToolWithheld):
			r.log.Warn("not mirroring an upstream tool whose definition cannot be checked for credentials")
			continue
		case errors.Is(err, errToolReserved):
			continue // addTool already warned
		case err != nil:
			return nil, err
		}
		n++
	}
	srv.AddTool(&sdk.Tool{
		Name:        toolAccountList,
		Description: "List the SIP accounts configured on this machine (name, mode, sipserver, port, transport, username). Passwords are never shown. Accounts with a configuration problem are listed under \"invalid\". Use a name with ua_create {\"account\": \"<name>\"}.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}, r.accountList)
	r.log.Info("relay ready", "tools", n+1)
	return srv, nil
}

func toolError(msg string) *sdk.CallToolResult {
	return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: msg}}}
}

func (r *Relay) accountList(_ context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
	cfg, err := LoadConfig(r.opts.ConfigPath)
	if err != nil {
		return toolError("account_list: " + err.Error()), nil
	}
	b, _ := json.Marshal(struct {
		OK       bool             `json:"ok"`
		Accounts []AccountInfo    `json:"accounts"`
		Invalid  []AccountProblem `json:"invalid,omitempty"`
	}{true, cfg.List(), cfg.Invalid()})
	// A password may equal a listed value (a username, a name): scrub the listing
	// for every password in the file, used or not, and the process-wide set.
	cfg.addSecretsTo(r.secrets)
	listing := r.secrets.scrub(string(b))
	return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: listing}}}, nil
}

func (r *Relay) resolve(name string) (Account, error) {
	cfg, err := LoadConfig(r.opts.ConfigPath) // re-read on EVERY lookup
	if err != nil {
		return Account{}, err
	}
	cfg.addSecretsTo(r.secrets)
	// The error names every valid/invalid account; a password may equal a name.
	// Its only caller, forward, scrubs it through r.secrets, which cfg.addSecretsTo
	// above filled with every password in the file.
	return cfg.Resolve(name)
}

func (r *Relay) forward(name string) sdk.ToolHandler {
	return func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		args := req.Params.Arguments
		// Every password the file holds now is a secret, used or not (a failed read
		// keeps the set; it never shrinks).
		if cfg, err := LoadConfig(r.opts.ConfigPath); err == nil {
			cfg.addSecretsTo(r.secrets)
		}
		usedAccount := false
		if name == toolUACreate {
			out, acct, err := Inject(args, r.resolve)
			if err != nil {
				return toolError(r.secrets.scrub(err.Error())), nil // nothing is sent upstream
			}
			args = out
			if acct != nil {
				r.secrets.addCredential(acct.Username, acct.Password) // BEFORE the call: the reply is scrubbed for it
				usedAccount = true
			}
		}
		p := &sdk.CallToolParams{Name: name, Meta: req.Params.Meta}
		if len(args) > 0 {
			p.Arguments = args // RawMessage: values preserved; encoding/json compacts whitespace
		}
		before := r.bridge.current()
		res, up, err := r.callUpstream(ctx, p)
		if err != nil {
			res = r.upstreamError(ctx, up, err)
		}
		// A failure on a session re-opened during this call may stem from handles
		// of the old session: say so (CF-206).
		if up != nil && up != before && res.IsError {
			noted := *res
			noted.Content = append([]sdk.Content{&sdk.TextContent{Text: reopenNote}}, res.Content...)
			res = &noted
		}
		// One scrub of the complete result: upstream content, error texts and the note.
		red, rerr := r.secrets.redactResult(res, usedAccount)
		if rerr != nil {
			// Fail closed: never hand over a result that could not be checked.
			return toolError(r.secrets.scrub(name + ": the upstream result could not be checked for credentials and was withheld. " +
				"The call may have taken effect upstream; use ua_status / call_list to find out.")), nil
		}
		return red, nil
	}
}

// callUpstream sends p on the current session (re-opened first if it was
// lost). If the call provably never ran (callProbe.neverRan) the session is
// re-opened and p is sent ONCE more (CF-206). It returns the session the last
// attempt used, or nil if no session could be opened.
func (r *Relay) callUpstream(ctx context.Context, p *sdk.CallToolParams) (*sdk.CallToolResult, *sdk.ClientSession, error) {
	for retried := false; ; retried = true {
		up, err := r.session(ctx)
		if err != nil {
			return nil, nil, err
		}
		probe := &callProbe{}
		res, err := up.CallTool(context.WithValue(ctx, probeKey{}, probe), p)
		if err == nil || retried || ctx.Err() != nil || !probe.neverRan(err) {
			return res, up, err
		}
		r.dropSession(up)
		r.log.Warn("upstream session gone; re-opening it and sending the call again")
	}
}

// localRPCCodes are the JSON-RPC codes the SDK client itself fabricates when
// the peer never answered (internal/jsonrpc2: unknown, client closing, server
// closing, rejected by transport). They arrive as *jsonrpc.Error but are NOT
// answers from the daemon. Verified against go-sdk v1.6.1.
var localRPCCodes = map[int64]bool{-32001: true, -32003: true, -32004: true, -32005: true}

// answeredByUpstream reports whether err is a JSON-RPC error the daemon sent.
func answeredByUpstream(err error) bool {
	var rpcErr *jsonrpc.Error
	return errors.As(err, &rpcErr) && !localRPCCodes[rpcErr.Code] && !errors.Is(err, sdk.ErrSessionMissing)
}

// upstreamError turns a failed upstream call on session up into a model-readable
// tool error; up is nil when no session could be opened. An answer from the
// daemon (a JSON-RPC error) leaves the session usable. A cancelled call is the
// caller's doing. Anything else - refused connection, HTTP 404 for an expired
// session, a broken stream - means the session is gone: it is marked lost, and
// the next call opens a new one (CF-206).
func (r *Relay) upstreamError(ctx context.Context, up *sdk.ClientSession, err error) *sdk.CallToolResult {
	switch {
	case up != nil && answeredByUpstream(err):
		return toolError(r.secrets.scrub("upstream rejected the call: " + err.Error()))
	case ctx.Err() != nil:
		return toolError("call cancelled: " + ctx.Err().Error())
	default:
		if up != nil {
			r.dropSession(up)
			r.log.Warn("upstream session lost")
		}
		return toolError(lostMessage + " (" + r.secrets.scrub(err.Error()) + ")")
	}
}
