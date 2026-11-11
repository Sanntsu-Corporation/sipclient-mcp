package mcp

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// registerAdminRoutes implements §12.7's conditional registration. The
// condition is the LIVE POLICY's AdminEnabled(), which reports whether
// auth.admin_token_file was set at load — NOT the length of a []byte field on
// Config, which is the shape contract finding 14 deleted because nothing in
// cmd/ ever populated it.
//
// Registration is evaluated ONCE, when Handler() builds the mux, so a SIGHUP
// that ADDS auth.admin_token_file to a running daemon does not retroactively
// register routes. That is deliberate and matches §12.7's "a deployment that
// does not want the plane does not have it": route topology is fixed at
// start, while the TOKEN VALUE behind an already-registered route does rotate
// live through adminAuth.
//
// The REMOVE direction is asymmetric, and that is an accepted, documented
// property (D246): a SIGHUP that clears auth.admin_token_file on a daemon
// whose routes are already registered leaves them registered — requests then
// get 401 (adminAuth's MatchesAdminToken now always returns false, per
// policy.Policy.MatchesAdminToken's own doc) rather than 404. Fail-closed
// holds either way: no request succeeds without a valid token. Fixing the
// asymmetry would mean either a second AdminEnabled() check inside adminAuth
// (redundant with the registration gate below, for no security gain) or
// making the mux topology mutable at runtime (new concurrency surface on the
// security-critical path, for a cosmetic status-code difference). Neither is
// worth it: an operator reaches this state only by deliberately removing
// their own admin token.
//
// D245 (documented, not fixed): DELETE /admin/uas (no {ua_handle}) and
// GET /admin/uas/{ua_handle} return 405 Method Not Allowed BEFORE adminAuth
// runs — Go's http.ServeMux resolves a method mismatch on a registered
// pattern ahead of any handler, admin's included. Accepted as-is: the
// 401-when-enabled/404-when-disabled split already discloses the plane's
// existence by design (that is the whole point of the AdminEnabled() gate
// below), and a 405 carries an empty body with no admin data, so it leaks
// nothing beyond what that split already concedes. No catch-all route is
// added to route 405s through adminAuth — it would buy no security.
func (s *Server) registerAdminRoutes(mux *http.ServeMux) {
	if !s.cfg.Policy.Current().AdminEnabled() || s.cfg.Admin == nil {
		return
	}
	mux.Handle("GET /admin/uas", s.adminAuth(http.HandlerFunc(s.adminListUAs)))
	mux.Handle("DELETE /admin/uas/{ua_handle}", s.adminAuth(http.HandlerFunc(s.adminDeleteUA)))
}

// adminAuth authenticates the §12.7 operator plane with the SEPARATE admin
// token, read live from the policy store on every request via
// MatchesAdminToken. It does NOT call policy.ConstantTimeEqual —
// MatchesAdminToken already compares against the digest resolved at load, in
// constant time and with U6's hash.
//
// /admin/* is exempt from nothing else: it is not covered by N4's /healthz
// exception, the MCP bearer token is REJECTED here (§12.7 — that token is
// shared across agents by design), and an absent or wrong token returns 401.
func (s *Server) adminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented, ok := bearerToken(r)
		if !ok || !s.cfg.Policy.Current().MatchesAdminToken(presented) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type adminUAsResponse struct {
	UAs         []session.AdminUAView `json:"uas"`
	Count       int                   `json:"count"`
	MaxUAsTotal int                   `json:"max_uas_total"`
}

func (s *Server) adminListUAs(w http.ResponseWriter, r *http.Request) {
	uas := s.cfg.Admin.LiveUAs(r.Context())
	if uas == nil {
		uas = []session.AdminUAView{}
	}
	// GET carries no single session id: the body already names every one.
	s.auditAdmin(r, slog.LevelInfo, "", "", "ok", 0)
	writeJSON(w, http.StatusOK, adminUAsResponse{
		UAs:   uas,
		Count: len(uas),
		// §12.7's worked JSON carries max_uas_total. Read LIVE from policy —
		// there is no Config.MaxUAsTotal, for the same reason there is no
		// Config.BearerToken: a copied limit drifts from the one the manager
		// actually enforces after a SIGHUP.
		MaxUAsTotal: s.cfg.Policy.Current().Limits.MaxUAsTotal,
	})
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// auditAdmin emits §12.7's audit line: one structured JSON line per request,
// INFO for GET and WARN for DELETE. WARN because a DELETE destroys another
// party's live objects, and an operator reading the log later must be able to
// explain a UA that vanished.
//
// The line carries the FULL SESSION ID. §12.6 makes that a credential factor
// and this is DELIBERATE, not an oversight: the operator's whole job here is
// to correlate a stranded UA with the session that stranded it, and a
// truncated prefix that does not resolve defeats exactly that. Admin
// responses and audit lines inherit the bearer token's sensitivity and are
// operator-only material. No bearer token, admin token or profile credential
// appears in the line (D6, §12.2).
func (s *Server) auditAdmin(r *http.Request, level slog.Level, uaHandle, sessionID, result string, callsTerminated int) {
	s.cfg.Log.Log(r.Context(), level, "admin_action",
		"event", "admin_action",
		"method", r.Method,
		"path", r.URL.Path,
		"ua_handle", uaHandle,
		"session", sessionID,
		"result", result,
		"calls_terminated", callsTerminated,
		"source", r.RemoteAddr,
		"at", s.cfg.Clock.Now().UTC().Format(time.RFC3339Nano),
	)
}

func (s *Server) adminDeleteUA(w http.ResponseWriter, r *http.Request) {
	handle := r.PathValue("ua_handle")

	// DestroyUA IS ua_destroy's implementation with the ownership check
	// omitted (Rule 16). Everything §12.7 specifies — BYE to every live
	// dialog, the §11.4 grace period, REGISTER Expires: 0 when registered,
	// the §N3 terminated entry left behind — happens there, once. In
	// particular the registry lock is taken to resolve the UA and RELEASED
	// BEFORE THE BYE WAIT BEGINS: holding it across the 10 s grace period
	// inside this handler would stall every concurrent tool call on the
	// server for ten seconds. That is an OUTAGE, not a latency blip.
	// TestAdminDeleteDoesNotStallTools asserts it from the outside.
	//
	// r.Context() IS PASSED, AND IT GOVERNS THE RESPONSE ONLY — never the
	// teardown (decision 17, path 3). DestroyUA runs Hangup, Unregister and
	// Close on m.DaemonContext() under its own timeout, so an admin client
	// that disconnects mid-BYE still gets a completed teardown rather than a
	// still-registered, socket-holding, handle-less UA that no path can
	// reclaim. That is a CONTRACTUAL PROPERTY OF DestroyUA (see the Admin
	// interface in deps.go), NOT something this handler arranges: do NOT
	// "fix" a leaking request context here by spawning a goroutine or
	// minting a context.Background() — that would be a second teardown
	// path, which is the one thing Rule 16 forbids on this route.
	res, err := s.cfg.Admin.DestroyUA(r.Context(), handle)
	if err != nil {
		var ae *apierr.Error
		if errors.As(err, &ae) && ae.Code == apierr.CodeNotFound {
			s.auditAdmin(r, slog.LevelWarn, handle, "", string(apierr.CodeNotFound), 0)
			writeJSON(w, http.StatusNotFound, map[string]string{"error": string(apierr.CodeNotFound)})
			return
		}
		s.auditAdmin(r, slog.LevelWarn, handle, "", "error", 0)
		s.cfg.Log.Error("admin destroy failed", "ua_handle", handle, "err", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": string(apierr.CodeInternal)})
		return
	}
	s.auditAdmin(r, slog.LevelWarn, handle, res.Session, "ok", res.CallsTerminated)
	writeJSON(w, http.StatusOK, res)
}
