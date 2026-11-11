package policy

import (
	"crypto/sha256"
	"crypto/subtle"
)

// ConstantTimeEqual reports whether a and b are equal, in time that does not
// depend on where they first differ NOR ON THEIR LENGTHS (U6).
//
// Both inputs are SHA-256'd to a fixed 32 bytes BEFORE the comparison. That
// is the whole point and MUST NOT be "simplified" away: bare
// subtle.ConstantTimeCompare returns 0 immediately on a length mismatch and
// therefore leaks the presented token's LENGTH — a real bit of a real secret,
// on the primitive behind bearer auth, admin auth and §12.6 session binding.
// §12.1's threat model does not name that channel; U6 closes it anyway, at a
// cost of one SHA-256 per authenticated request against D3's ~50-call target.
//
// Safe to call with raw tokens OR with already-hashed digests: hashing a
// digest again is harmless, and Task 17's identityStore passes two 32-byte
// digests.
//
// The parameter type is []byte, not string: transport/mcp holds the presented
// token as bytes off the wire, and []byte avoids materialising a second copy
// of secret material on the heap.
func ConstantTimeEqual(a, b []byte) bool {
	da := sha256.Sum256(a)
	db := sha256.Sum256(b)
	return subtle.ConstantTimeCompare(da[:], db[:]) == 1
}

// MatchesBearerToken reports whether presented is ANY ONE of the configured
// MCP bearer tokens (§12.2 transport auth; auth.bearer_token_file now holds
// one token per line, so a separate token can be handed to each
// machine/agent and revoked independently). It hashes internally, so
// bearerAuth retains U6's length protection without its caller doing
// anything, and each candidate is still compared in constant time; which of
// several configured tokens matched is not secret material, only a token's
// content is.
func (p *Policy) MatchesBearerToken(presented []byte) bool {
	d := sha256.Sum256(presented)
	for _, digest := range p.bearerDigests {
		if subtle.ConstantTimeCompare(d[:], digest[:]) == 1 {
			return true
		}
	}
	return false
}

// MatchesAdminToken reports whether presented is the configured operator
// admin token (§12.7). It is always false when no admin token is configured,
// but a false result is NOT how an unconfigured admin plane behaves: per
// §12.7 an unset auth.admin_token_file means the routes are not registered
// at all and both return 404, never 401. Callers must gate on AdminEnabled.
func (p *Policy) MatchesAdminToken(presented []byte) bool {
	if !p.adminEnabled {
		return false
	}
	d := sha256.Sum256(presented)
	return subtle.ConstantTimeCompare(d[:], p.adminDigest[:]) == 1
}

// AdminEnabled reports whether auth.admin_token_file is configured.
//
// Task 19 MUST branch on this at route-registration time, not at request
// time: §12.7 requires that with the key unset, GET /admin/uas and
// DELETE /admin/uas/{h} return 404 with ANY token — the plane does not
// exist. Registering the routes and returning 401 would disclose that the
// surface exists, and would change the §14.6 tool-surface configuration
// matrix the spec requires to pass unchanged in both configurations.
func (p *Policy) AdminEnabled() bool { return p.adminEnabled }
