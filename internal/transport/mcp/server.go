// Package mcp is internal/transport/mcp: the MCP-over-HTTP server, bearer
// auth against the live policy store, and §12.6 logical session identity.
// It is the ONE API surface (contract §2.8) — everything lives in server.go
// plus the task-owned files this package's later tasks add to it.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/metrics"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// maxRequestBytes bounds the body the initialize-detection middleware buffers.
// The SDK enforces its own limit downstream; this one exists so an unbounded
// body cannot be read into memory before the session decision is taken.
const maxRequestBytes = 4 << 20

// Config is contract §2.8's declaration, VERBATIM. There is no BearerToken,
// AdminToken, MaxUAsTotal or http.Handler field: every one of those was either
// a token snapshot nothing populated (finding 14) or a limit already live in
// policy. Read them from Policy.Current().
type Config struct {
	Sessions Sessions
	Tools    Tools
	Admin    Admin

	Policy    *policy.Store
	Metrics   *metrics.Registry
	Ready     ReadyFunc
	Artifacts session.ArtifactStore
	Log       *slog.Logger
	Clock     clock.Clock
}

// Server is internal/transport/mcp's single API type (contract §2.8):
// construct one with NewServer, then serve its Handler().
type Server struct {
	cfg      Config
	identity *identityStore
	mcp      *sdk.Server

	// draining is §11.4 step 1. Set by StopAccepting; read on every /mcp
	// request. It is an atomic because StopAccepting is called from the
	// shutdown goroutine while requests are in flight.
	draining atomic.Bool

	correlationID func() string
}

// serverInstructions summarises what this server can do, for the initialize
// result. Keep it in step with the tool set (tools.go).
const serverInstructions = "SIP user-agent server: create UAs, dial/answer/reject/hangup calls, " +
	"blind and attended call transfer (SIP REFER, call_transfer), DTMF send/receive, " +
	"media play/record, signaling capture and call ladders, session keepalive, runtime config."

// NewServer validates cfg and constructs a Server. Sessions, Tools, Policy
// and Log are required; Clock defaults to clock.System().
func NewServer(cfg Config) (*Server, error) {
	if cfg.Sessions == nil {
		return nil, errors.New("mcp: Config.Sessions is required")
	}
	if cfg.Tools == nil {
		return nil, errors.New("mcp: Config.Tools is required")
	}
	if cfg.Policy == nil {
		// The live store IS the token source (contract Part 4.4). Without it
		// there is no bearer auth at all, which must fail loudly at construction
		// rather than silently accepting or rejecting every request.
		return nil, errors.New("mcp: Config.Policy is required")
	}
	if cfg.Log == nil {
		return nil, errors.New("mcp: Config.Log is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System()
	}
	s := &Server{
		cfg:      cfg,
		identity: newIdentityStore(),
		// Reuse the one CSPRNG hex generator this package already has rather
		// than growing a second (Rule 16/18).
		correlationID: newSessionID,
	}
	s.mcp = sdk.NewServer(
		&sdk.Implementation{Name: "sipclient-mcp", Version: "0.1.0"},
		&sdk.ServerOptions{
			// §12.6's id is ours, not the SDK's default: 128-bit CSPRNG hex,
			// unprefixed.
			GetSessionID: newSessionID,
			// Sent in the initialize result so an agent probing the server
			// learns its capabilities without a tools/list walk.
			Instructions: serverInstructions,
		},
	)
	// Registration reads s.cfg.Tools (Task 18 supplies the body).
	s.registerTools()
	return s, nil
}

// registerObservabilityRoutes registers §5 N5's observability routes from
// Server.Handler(). Task 17 registers ONLY GET /healthz — Step 17.12's own
// test requires it and it is bearerAuth's single exemption (N4), so the
// exemption and the registration cannot be scheduled apart. Task 21 EXTENDS
// this method with GET /readyz and GET /metrics; it does not recreate it
// (D202 amends p1d-server.md:5588 accordingly).
func (s *Server) registerObservabilityRoutes(mux *http.ServeMux) {
	// GET /healthz — liveness. NO AUTH, no information (N4's single
	// exception, §12.2). Deliberately contentless so it is safe to expose to
	// an orchestrator: no version (decision 16), no counts, no configuration.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// GET /readyz and GET /metrics — bearer token required (§5 N5, §12.2,
	// §12.2's transport-auth row). bearerAuth exempts ONLY /healthz by path,
	// so wrapping these two here is what keeps them from shipping
	// unauthenticated.
	if s.cfg.Ready != nil {
		mux.Handle("GET /readyz", s.bearerAuth(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				st := s.cfg.Ready()
				w.Header().Set("Content-Type", "application/json")
				if st.Ready {
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
				_ = json.NewEncoder(w).Encode(st) // the same shape in both cases
			})))
	}

	if s.cfg.Metrics != nil {
		mux.Handle("GET /metrics", s.bearerAuth(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_ = s.cfg.Metrics.WriteText(w)
			})))
	}

	// GET /artifacts/{call_handle}/{name} — bearer-authed per-call artifact
	// serve (§14.5), registered only when a store is configured, mirroring
	// the /readyz and /metrics optional-field pattern above.
	if s.cfg.Artifacts != nil {
		mux.Handle("GET /artifacts/{call_handle}/{name}",
			s.bearerAuth(http.HandlerFunc(s.serveArtifact)))
	}
}

// StopAccepting is §11.4 step 1. New MCP requests are refused with 503;
// IN-FLIGHT REQUESTS ARE UNTOUCHED, which is load-bearing: a parked call_wait
// must survive long enough to receive §6.3 rule 2's terminal broadcast in
// shutdown step 3. /healthz, /readyz and /metrics keep answering so an
// orchestrator can observe the drain.
func (s *Server) StopAccepting() { s.draining.Store(true) }

func (s *Server) refuseWhenDraining(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.draining.Load() {
			http.Error(w, "shutting down", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Handler builds the mux: GET /healthz (UNAUTHENTICATED — N4's single
// exception), /mcp, and — ONLY when cfg.Policy.Current().AdminEnabled() —
// the §12.7 admin routes. Task 21 extends the observability routes with
// GET /readyz and GET /metrics.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// The observability routes are registered HERE and only here.
	s.registerObservabilityRoutes(mux)

	// ONE streamable handler instance, bound here: cancelOnDisconnect posts a
	// synthetic notification back into it, and that only reaches the right MCP
	// session if it is the same instance that is serving the request.
	sh := s.streamableHandler()
	mux.Handle("/mcp", s.bearerAuth(s.refuseWhenDraining(
		s.sessionIDMiddleware(s.cancelOnDisconnect(sh)))))

	// §12.7: the admin plane is registered ONLY when auth.admin_token_file is
	// set. Unset means NOT REGISTERED AT ALL — both paths 404 for any token,
	// rather than 401ing everyone. See admin.go (Task 19).
	s.registerAdminRoutes(mux)

	return mux
}

// cancelOnDisconnect delivers §6.3 rule 4 ("client disconnect ... the waiter is
// removed from the call's waiter set immediately") for a client that simply
// DROPS THE CONNECTION, which the SDK otherwise cannot see.
//
// Why this exists: NewConnection wraps the connection context in notDone
// (go-sdk@v1.6.1/internal/jsonrpc2/conn.go:198), whose Done() and Err() are
// both nil, and every in-flight request context is a WithCancel off that dead
// parent — so cancellation never reaches a handler from the HTTP layer. The
// streamable transport also deliberately does not join req.Context() to
// in-flight requests, to keep stream resumption working (its own TODO at
// mcp/streamable.go:1300), and exposes no hook to change that. The ONE
// cancellation channel the SDK honours is conn.Cancel(id), whose only caller is
// the notifications/cancelled preempter (mcp/transport.go:215).
//
// So when a call's request context is done before the handler has responded,
// this middleware posts that exact notification back into the SAME MCP session.
// A parked call_wait is then released at once instead of holding its per-call
// and per-session waiter slots for the whole of timeout_ms — eight aborted
// retries would otherwise exhaust max_waiters_per_call and make the call
// un-waitable for up to max_wait_timeout_ms.
func (s *Server) cancelOnDisconnect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.Header.Get(sessionIDHeader)
		requestID := jsonrpcCallID(r)
		if sessionID == "" || requestID == nil {
			// No session to post into, or not a JSON-RPC call (a notification,
			// a batch, or an initialize, whose id is issued in the response and
			// which never blocks). Nothing to cancel.
			next.ServeHTTP(w, r)
			return
		}
		served := make(chan struct{})
		defer close(served)
		go func() { //nolint:contextcheck // deliberately calls postCancelled with context.Background(), not r.Context(): by the time this fires, r.Context() is already Done, so deriving from it would make postCancelled's own synthetic request stillborn before it can post the cancellation notification.
			select {
			case <-served:
			case <-r.Context().Done():
				s.postCancelled(next, sessionID, requestID)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// jsonrpcCallID returns the JSON-RPC id of a single request that expects a
// response, or nil for a notification, a batch, or an unparseable body. The id
// is kept as raw JSON so a string id and a numeric id both round-trip verbatim
// into requestId.
//
// r.Body is restored, exactly as sessionIDMiddleware restores it, because the
// SDK downstream still has to read it. No size guard is needed here: this
// handler is only ever mounted inside sessionIDMiddleware, which has already
// bounded the body at maxRequestBytes and buffered it.
func jsonrpcCallID(r *http.Request) json.RawMessage {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if json.Unmarshal(body, &msg) != nil || msg.Method == "" {
		return nil
	}
	if len(msg.ID) == 0 || string(msg.ID) == "null" {
		return nil
	}
	return msg.ID
}

// postCancelled feeds a synthetic notifications/cancelled into the streamable
// handler, on the session the aborted request named. It goes straight to the
// SDK rather than back through the mux: the notification is server-originated,
// so bearerAuth and sessionIDMiddleware have already run for the request that
// produced it and re-running them would only ask the server to authenticate
// itself.
func (s *Server) postCancelled(next http.Handler, sessionID string, requestID json.RawMessage) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/cancelled",
		"params":  map[string]any{"requestId": requestID},
	})
	if err != nil {
		s.cfg.Log.Error("build cancellation notification", "session", sessionID, "err", err)
		return
	}
	// context.Background(), NOT the aborted request's context: this exists
	// precisely because that one is done.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://localhost/mcp", bytes.NewReader(body))
	if err != nil {
		s.cfg.Log.Error("build cancellation request", "session", sessionID, "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(sessionIDHeader, sessionID)
	next.ServeHTTP(&discardResponse{}, req)
}

// discardResponse absorbs the synthetic notification's response. The SDK
// answers a notification with 202 and no body, and there is by definition no
// client left to deliver it to.
type discardResponse struct{ header http.Header }

func (d *discardResponse) Header() http.Header {
	if d.header == nil {
		d.header = http.Header{}
	}
	return d.header
}

func (d *discardResponse) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardResponse) WriteHeader(int)             {}

func (s *Server) streamableHandler() http.Handler {
	return sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return s.mcp },
		nil,
	)
}

// resolve answers §12.6's "is this a request against a known logical session?"
// It is the ONLY place the two factors are combined: internal/session decides
// liveness, identityStore decides the token binding in constant time. A dead
// record's binding is dropped here rather than by a second janitor, so the
// resume window is enforced ONCE, in internal/session (Rule 18).
func (s *Server) resolve(id string, token []byte) bool {
	if id == "" {
		return false
	}
	if !s.cfg.Sessions.Alive(id) {
		s.identity.forget(id)
		return false
	}
	return s.identity.matches(id, token)
}

// sessionIDMiddleware implements §12.6's SINGLE unknown-id rule, which the SDK
// does not: the SDK returns 404 for ANY unrecognised Mcp-Session-Id, checked
// BEFORE the body is inspected, so a stale id carried on an initialize is
// wrongly 404ed (§3e).
//
// It also closes a gap the SDK cannot see: an id the SDK recognises but which
// was issued to a DIFFERENT bearer token is treated here as unknown, per
// §12.6, and therefore never reaches the SDK at all.
//
// §12.6's single unknown-id rule (spec text, verbatim): "On an `initialize`
// request the id is ignored and a fresh session is issued. On any
// non-`initialize` request the server responds HTTP 404 ... disclosing
// nothing ... omitting the id on a non-`initialize` request likewise returns
// 404." So the body is ALWAYS read and ALWAYS parsed for isInitialize,
// regardless of whether an id was presented at all: an initialize always
// gets a fresh id (the presented id, if any, is stripped unconditionally so
// the SDK cannot echo a KNOWN-but-presented one back — §12.6's acceptance
// requires two successive initialize calls on one token to return DIFFERENT
// ids even when the second one names the first's id); a non-initialize
// request is served only when resolve(id, token) is true, and 404s
// otherwise — one branch that covers both an absent id and an unknown one.
func (s *Server) sessionIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := tokenFromContext(r.Context())
		id := r.Header.Get(sessionIDHeader)

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))

		if isInitialize(body) {
			// Every initialize gets a FRESH session, unconditionally — even
			// one presenting a KNOWN id on the SAME token (§12.6: "two
			// successive initialize calls on the same token return different
			// ids"). Stripping the header is what makes the SDK mint one.
			r.Header.Del(sessionIDHeader)
		} else if !s.resolve(id, token) {
			// Not an initialize, and the id is either absent or unknown (an
			// unrecognised id, or a known id bound to a different token):
			// §12.6's single rule answers both the same way. Disclose
			// nothing — not that the id is unknown, not that it belongs to
			// someone else, not that any handle exists.
			w.WriteHeader(http.StatusNotFound)
			return
		} else {
			s.cfg.Sessions.Seen(id)
		}

		next.ServeHTTP(&issueRecorder{
			ResponseWriter: w,
			ctx:            r.Context(),
			onIssue: func(ctx context.Context, newID string) {
				// D214/D265: sweep every bound id no longer alive BEFORE
				// binding the new one. bind is the only growth site for
				// s.identity's map, so sweeping at this same call site makes
				// the growth self-limiting; the bound is session.Manager's
				// existing session_resume_window, already enforced by
				// JanitorSweep.
				s.identity.sweep(s.cfg.Sessions.Alive)
				// D272: open the session record BEFORE binding, not after.
				// bind-before-Open put newID in identity.tokens while it was
				// still absent from Sessions (Alive(newID) == false), so a
				// concurrent initialize's sweep in that window deleted the
				// brand-new binding — a live session destroyed by the very
				// mechanism meant to reap dead ones. Opening first means an id
				// only ever enters tokens once its record exists, so sweep can
				// never observe a bound-but-not-yet-alive id. The reverse
				// window (alive but unbound) is harmless: the client has not
				// received newID yet, so nothing can present it.
				//
				// Fail closed on Open error: skip the bind too. A record that
				// failed to open never satisfies Alive, so resolve() would
				// 404 the id regardless (§12.6) — but leaving it bound would
				// break the invariant this fix exists to establish, that
				// every id in tokens has, or once had, a real session record.
				if err := s.cfg.Sessions.Open(ctx, newID); err != nil {
					s.cfg.Log.Error("session open failed", "session", newID, "err", err)
					return
				}
				// Bind AT ISSUE to the bearer token presented on THIS
				// initialize (§12.6), and to whether that SAME presented
				// token was the admin token (§2.4b) -- read back from the
				// context bearerAuth already decided it in, NOT
				// recomputed: a second Policy.Current().MatchesAdminToken
				// call here would race a concurrent admin_token_rotate and
				// could bind a genuine admin initialize to admin=false.
				s.identity.bind(newID, token, adminFromContext(ctx))
			},
		}, r)
	})
}

// issueRecorder observes the outgoing Mcp-Session-Id response header so the
// server learns the id the SDK issued, at the moment it is issued, with the
// initialize's bearer token still in hand. ctx is the request's context,
// carried explicitly rather than closed over, so onIssue's context flows
// through a parameter like every other call in this package.
type issueRecorder struct {
	http.ResponseWriter
	ctx     context.Context
	onIssue func(ctx context.Context, id string)
	done    bool
}

func (w *issueRecorder) capture() {
	if w.done {
		return
	}
	w.done = true
	if id := w.Header().Get(sessionIDHeader); id != "" {
		w.onIssue(w.ctx, id)
	}
}

func (w *issueRecorder) WriteHeader(code int) {
	w.capture()
	w.ResponseWriter.WriteHeader(code)
}

func (w *issueRecorder) Write(b []byte) (int, error) {
	w.capture()
	return w.ResponseWriter.Write(b)
}

// Flush keeps streamable HTTP's SSE responses flushable through the wrapper.
func (w *issueRecorder) Flush() {
	w.capture()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
