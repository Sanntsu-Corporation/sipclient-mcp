package mcp

import (
	"crypto/sha256"
	"sync"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// identityStore holds §12.6's binding: each issued session id to the bearer
// token presented on the initialize that issued it.
//
// It is authoritative for THAT BINDING AND NOTHING ELSE. Liveness, ownership
// and the resume window live in internal/session and are asked of it (see
// Server.resolve). This is the §3e constraint 2 boundary: no second source of
// truth for identity or authorization exists here.
//
// Tokens are stored as SHA-256 digests and compared as fixed-length digests,
// so the comparison leaks neither the token nor its length.
//
// binding also carries admin (Phase 2 §2.4b): whether the token THAT ISSUED
// this id matched the configured admin token, decided once, at bind time,
// by bearerAuth (auth.go) and never recomputed. It is never rewritten after
// bind -- a later admin_token_rotate governs the NEXT initialize, not a
// session already in flight. That is the correct semantics for a capability
// granted at authentication time: retroactively promoting or demoting a
// live session because the token file changed underneath it would surprise
// whichever side observes the flip.
type binding struct {
	sum   [32]byte
	admin bool
}

type identityStore struct {
	mu     sync.RWMutex
	tokens map[string]binding
}

func newIdentityStore() *identityStore {
	return &identityStore{tokens: make(map[string]binding)}
}

// bind records the token an id was issued to, and whether that token was the
// admin token (§2.4b). Called exactly once per id, at the initialize that
// issued it.
func (s *identityStore) bind(id string, token []byte, admin bool) {
	sum := sha256.Sum256(token)
	s.mu.Lock()
	s.tokens[id] = binding{sum: sum, admin: admin}
	s.mu.Unlock()
}

// matches reports whether id was issued to token, compared in CONSTANT TIME
// (§12.6) via Task 5's helper — one implementation, not two (Rule 16).
//
// THIS IS THE ONLY CALLER OF policy.ConstantTimeEqual IN THIS PACKAGE, and both
// of its arguments are 32-byte SHA-256 digests (contract §2.8). bearerAuth and
// adminAuth do NOT call it: they route through MatchesBearerToken /
// MatchesAdminToken, which hash internally (locked decision U6).
//
// An id that was never issued and an id presented with the wrong token return
// the same answer, false, because §12.6 gives them the same answer: both are
// "unknown", and the single unknown-id rule decides what happens next.
func (s *identityStore) matches(id string, token []byte) bool {
	s.mu.RLock()
	b, ok := s.tokens[id]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	got := sha256.Sum256(token)
	return policy.ConstantTimeEqual(b.sum[:], got[:])
}

// isAdmin reports whether id was bound to the admin token at issue (§2.4b).
// An unknown id returns false -- the SAME single-unknown-id rule matches
// already applies, for the same non-disclosure reason: this must not become
// a second, differently-shaped way to probe whether an id exists.
func (s *identityStore) isAdmin(id string) bool {
	s.mu.RLock()
	b, ok := s.tokens[id]
	s.mu.RUnlock()
	return ok && b.admin
}

// rebind repoints an ALREADY-BOUND id at a new token, leaving its admin flag
// alone. It is the one exception to the "never rewritten after bind" rule in
// the type comment above, and it exists for exactly one caller (SEC-2:
// admin_token_rotate, wired in tools.go).
//
// WHY THE EXCEPTION IS NOT A CONTRADICTION. That rule is about the ADMIN
// CAPABILITY: a session's admin-ness is decided by the token presented at
// initialize and must not flip underneath a live session. This rewrites the
// token DIGEST only, for the session that itself performed the rotation, and
// it changes no capability — the binding goes on naming the same caller, now
// by the credential that caller holds. Without it, rotating locked the
// ROTATING caller out of its own session: the id stays bound to sha256(old
// token), bearerAuth now rejects the old token outright, and presenting the
// new one authenticates but does not match the binding, so the very next tool
// call 404s under §12.6's single unknown-id rule with nothing to explain why.
//
// An id that is NOT bound is left alone rather than created: binding is
// initialize's job, and minting one here would let a rotation conjure a
// session that never authenticated.
func (s *identityStore) rebind(id string, token []byte) {
	sum := sha256.Sum256(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.tokens[id]
	if !ok {
		return
	}
	b.sum = sum
	s.tokens[id] = b
}

func (s *identityStore) forget(id string) {
	s.mu.Lock()
	delete(s.tokens, id)
	s.mu.Unlock()
}

// sweep drops every bound id for which alive reports false. It exists to
// close D214: the only growth site for s.tokens is bind, called once per
// issued id from sessionIDMiddleware's onIssue — so sweeping at that same
// call site, immediately before bind, makes the growth self-limiting. The
// bound is session.Manager's existing session_resume_window, already
// enforced by JanitorSweep: an id becomes not-alive once its session record
// is empty and past that window, and the next initialize's sweep reclaims it.
// No goroutine, no policy key, no shutdown coordination — the operation that
// grows the map is the operation that cleans it.
func (s *identityStore) sweep(alive func(string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.tokens {
		if !alive(id) {
			delete(s.tokens, id)
		}
	}
}
