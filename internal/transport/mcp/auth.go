package mcp

import (
	"context"
	"net/http"
	"strings"
)

type tokenCtxKey struct{}

// adminCtxKey carries whether the presented bearer token matched the
// configured ADMIN token (§12.7, Phase 2 §2.4b), decided ONCE by bearerAuth
// alongside the ordinary bearer check -- see bearerAuth's doc comment for
// why this must be a single Policy.Current() read and not a second one
// later.
type adminCtxKey struct{}

// bearerAuth requires the MCP bearer token on EVERY request — /readyz and
// /metrics included — with the single exception of GET /healthz (N4, N5,
// §12.2), which an orchestrator's liveness probe cannot authenticate and which
// discloses nothing but a fixed "ok".
//
// It reads the LIVE policy on every request through
// (*policy.Policy).MatchesBearerToken (contract §2.8, Part 4.4). It does NOT
// call policy.ConstantTimeEqual: MatchesBearerToken already compares the
// presented token against the digest resolved at load, in constant time and
// with U6's hash. Two consequences follow, and both are the point:
//
//  1. auth.bearer_token_file is genuinely wired into the shipped binary — the
//     deleted []byte snapshot had NO code path populating it from cmd/.
//  2. A SIGHUP that rotates the token file takes effect immediately, with no
//     snapshot to refresh anywhere in this package.
//
// /admin/* is NOT routed through this middleware: §12.7 requires the MCP bearer
// token to be REJECTED there. See adminAuth (Task 19).
//
// Phase 2 §2.4/§2.4b amendment: bearerAuth is ALSO where the admin-scoped
// MCP tool plane's identity is decided, and it decides it from the SAME
// Policy.Current() read that already validates the ordinary bearer token --
// not a second, later read. §12.6's binding is made at initialize time, in
// sessionIDMiddleware's onIssue closure (server.go), and if THAT closure
// called Policy.Current().MatchesAdminToken again it would be reading a
// policy a concurrent admin_token_rotate (Phase 2) may have already swapped
// out from under the request that is mid-flight: a genuine admin initialize
// landing just after a rotation would bind admin=false and be locked out of
// the admin surface for the life of that session, and the decision that
// actually authorized the request would no longer be the decision recorded
// against it. One snapshot answering both questions makes that race
// impossible by construction -- there is only one Policy in play for the
// whole request.
func (s *Server) bearerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		presented, ok := bearerToken(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		cur := s.cfg.Policy.Current()
		admin := cur.MatchesAdminToken(presented)
		// Phase 2 §2.4's weakening of §12.7, spelled out here because it is
		// the one line that changes: bearerAuth now accepts EITHER token.
		// The admin token was previously valid on the /admin/* HTTP plane
		// ONLY (adminAuth, admin.go) and REJECTED here; for a single-user
		// loopback dev daemon that split bought nothing but an extra token
		// to manage, so an operator holding the admin token can now also
		// drive the ordinary MCP tool surface with it, and the three
		// admin-SCOPED tools (config_get/config_set/admin_token_rotate) are
		// the ones that still refuse a bearer-token-only session.
		if !cur.MatchesBearerToken(presented) && !admin {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), tokenCtxKey{}, presented)
		ctx = context.WithValue(ctx, adminCtxKey{}, admin)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// bearerToken extracts the credential from an Authorization header as BYTES —
// the form MatchesBearerToken/MatchesAdminToken take, which avoids
// materialising a second copy of secret material on the heap (contract §2.4).
// The scheme is matched case-insensitively per RFC 7235; the credential is not.
func bearerToken(r *http.Request) ([]byte, bool) {
	h := r.Header.Get("Authorization")
	const scheme = "Bearer "
	if len(h) <= len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return nil, false
	}
	tok := h[len(scheme):]
	if tok == "" {
		return nil, false
	}
	return []byte(tok), true
}

func tokenFromContext(ctx context.Context) []byte {
	tok, _ := ctx.Value(tokenCtxKey{}).([]byte)
	return tok
}

// adminFromContext reads the admin decision bearerAuth already made for this
// request. sessionIDMiddleware's onIssue passes this straight into
// identity.bind rather than recomputing it (§2.4b) -- see bearerAuth's doc
// comment for why recomputing it later would be a race, not just a
// redundant read.
func adminFromContext(ctx context.Context) bool {
	admin, _ := ctx.Value(adminCtxKey{}).(bool)
	return admin
}
