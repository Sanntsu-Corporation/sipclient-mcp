package peer

// peer_register.go — the REGISTRAR, and only the registrar: the digest gate, RFC
// 3261 §10.2.8's Min-Expires floor, and the 200's Contact/Expires construction.
//
// Split out of peer.go by Phase 4 W2 (P4-W2-13). SCOPED TO THE METHOD, which is
// the whole point of the boundary: record() and respond()'s switch serve every
// method and stayed in peer_serve.go, so nothing here is reachable by a BYE, an
// UPDATE or an INVITE, and a reader who opens this file for REGISTER behaviour
// finds all of it and none of anything else.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/digest"
)

// respondRegister builds the response to a REGISTER: the 401 challenge when
// credentials are configured and either the digest or (opt-in) the nonce-count
// gate rejects, RFC 3261 §10.2.8's 423 when Reject423MinExpires names a floor
// above what was asked for, and otherwise cfg.RegisterStatus — carrying the
// Contact echo and Expires that RFC 3261 §12.1.1 wants on a 200.
//
// IT IS respond's POST-SWITCH TAIL, MOVED VERBATIM (P4-W2-13). Before the split
// that tail was reached by `case sip.REGISTER:` falling through, so this method
// has exactly one caller and exactly the reachability the fall-through had; cfg
// is the same snapshot respond took under the lock, passed in rather than
// re-read, so no new lock acquisition appears. THERE IS STILL ONE PATH FOR EVERY
// REGISTER 200 — initial, refresh and de-register alike — which is what Task 3's
// Contact-on-refresh pin depends on.
func (p *Peer) respondRegister(req *sip.Request, cfg Config) *sip.Response {
	// RejectRegisterCredentialAfterNAccepted: checked FIRST and unconditionally
	// on the credential's presence, not its validity ("regardless of whether
	// that credential would otherwise verify" — see the field's doc comment).
	// A REGISTER with no Authorization header at all falls through to the
	// ordinary digest gate below, which already 401s it.
	if rejectAfterN := cfg.Behaviour.RejectRegisterCredentialAfterNAccepted; rejectAfterN > 0 {
		if h := req.GetHeader("Authorization"); h != nil && h.Value() != "" {
			p.mu.Lock()
			accepted := p.registerAccepts
			p.mu.Unlock()
			if accepted >= rejectAfterN {
				return sip.NewResponseFromRequest(req, 403, "Forbidden", nil)
			}
		}
	}
	if cfg.AuthUser != "" {
		if !p.authOK(req, cfg) || (cfg.Behaviour.EnforceNonceCountMonotonic && !p.acceptNonceCount(req)) {
			res := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
			res.AppendHeader(sip.NewHeader("WWW-Authenticate",
				fmt.Sprintf(`Digest realm="%s", nonce="%s", algorithm=MD5, qop="auth"`,
					cfg.Realm, p.registerNonce())))
			return res
		}
	}
	// RFC 3261 §10.2.8 (Reject423MinExpires): a registrar whose minimum
	// acceptable registration interval is higher than what was asked for answers
	// 423 and names its floor. Evaluated AFTER the digest challenge, like the
	// final status below, and never against a de-registration.
	if minExpiresFloor := cfg.Behaviour.Reject423MinExpires; minExpiresFloor > 0 {
		if exp := registerExpires(req); exp > 0 && exp < minExpiresFloor {
			res := sip.NewResponseFromRequest(req, 423, "Interval Too Brief", nil)
			res.AppendHeader(sip.NewHeader("Min-Expires", strconv.Itoa(minExpiresFloor)))
			return res
		}
	}
	res := sip.NewResponseFromRequest(req, sip.StatusCode(cfg.RegisterStatus), cfg.RegisterReason, nil)
	if cfg.RegisterStatus == 200 {
		// Other devices' bindings for the same AOR come FIRST, so "read the
		// first Contact" and "read our own binding" are distinguishable.
		for _, raw := range cfg.Behaviour.ExtraRegisterContacts {
			res.AppendHeader(sip.NewHeader("Contact", raw))
		}
		if c := req.Contact(); c != nil && !cfg.Behaviour.SuppressRegisterContactEcho {
			echo := c.Clone()
			if cfg.Behaviour.RegisterContactExpires != "" {
				if echo.Params == nil {
					echo.Params = sip.NewParams()
				}
				echo.Params.Add("expires", cfg.Behaviour.RegisterContactExpires)
			}
			res.AppendHeader(echo)
		}
		for _, raw := range cfg.Behaviour.ExtraRegisterContactsAfter {
			res.AppendHeader(sip.NewHeader("Contact", raw))
		}
		// OmitRegisterExpires (Task 24): a registrar that does not echo
		// Expires at all, so responseExpires' fallback is observable.
		if h := req.GetHeader("Expires"); h != nil && !cfg.Behaviour.OmitRegisterExpires {
			v := h.Value()
			if cfg.RegisterExpires > 0 {
				v = strconv.Itoa(cfg.RegisterExpires)
			}
			res.AppendHeader(sip.NewHeader("Expires", v))
		}
		// OneTimeRegisterNonce: this REGISTER was accepted, so the nonce it used
		// is spent. The next challenge names a new one, which is what makes a
		// UA's cached challenge go stale (P4-D07's fallback path).
		if cfg.Behaviour.OneTimeRegisterNonce {
			p.rotateRegisterNonce()
		}
		// registerAccepts backs RejectRegisterCredentialAfterNAccepted above —
		// tracked unconditionally (same posture as record()'s maxNonceCount),
		// only read when that Behaviour field is set.
		p.mu.Lock()
		p.registerAccepts++
		p.mu.Unlock()
	}
	return res
}

// registerExpires reads the Expires header off a REGISTER, or -1 when it
// carries none or it does not parse. Only Reject423MinExpires needs it at
// request-dispatch time; record() keeps its own copy for LastExpires.
func registerExpires(req *sip.Request) int {
	h := req.GetHeader("Expires")
	if h == nil {
		return -1
	}
	v, err := strconv.Atoi(strings.TrimSpace(h.Value()))
	if err != nil {
		return -1
	}
	return v
}

// registerNonce is the nonce this peer's REGISTER challenges name right now.
// Fixed at testNonce unless Behaviour.OneTimeRegisterNonce is set, in which case
// rotateRegisterNonce replaces it on every REGISTER the peer ACCEPTS.
func (p *Peer) registerNonce() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.regNonce == "" {
		p.regNonce = testNonce
	}
	return p.regNonce
}

// rotateRegisterNonce mints the next single-use REGISTER nonce. Called only from
// respondRegister's accepted-200 tail, and only under
// Behaviour.OneTimeRegisterNonce.
func (p *Peer) rotateRegisterNonce() {
	p.mu.Lock()
	p.regNonceSeq++
	p.regNonce = fmt.Sprintf("%s-%d", testNonce, p.regNonceSeq)
	p.mu.Unlock()
}

func (p *Peer) authOK(req *sip.Request, cfg Config) bool {
	return p.credentialOK(req, cfg, "Authorization", p.registerNonce())
}

// credentialOK verifies the digest credential req carries under headerName
// against cfg's user/pass and the nonce the challenge that drew it named.
//
// SPLIT OUT OF authOK (Phase 4 W3) FOR TWO CALLERS, not for tidiness: the INVITE
// path gates on Proxy-Authorization when Behaviour.ProxyAuthInvite makes it
// challenge with 407 (peer_invite.go), and the nonce is a parameter because a
// registrar under Behaviour.OneTimeRegisterNonce rotates it. Same verification,
// one implementation — a second copy is exactly how a test double drifts from
// the behaviour it is meant to model.
func (p *Peer) credentialOK(req *sip.Request, cfg Config, headerName, wantNonce string) bool {
	h := req.GetHeader(headerName)
	if h == nil {
		return false
	}
	fields, err := digest.ParseAuthorization(h.Value())
	if err != nil {
		return false
	}
	if fields["username"] != cfg.AuthUser || fields["nonce"] != wantNonce {
		return false
	}
	return digest.VerifyMD5Auth(cfg.AuthUser, cfg.AuthPass, string(req.Method), fields)
}

// acceptNonceCount enforces RFC 7616 §3.4.3's nonce-count monotonicity: an
// Authorization whose nc is not STRICTLY GREATER than the last one this peer
// has accepted is a replay and must be rejected, exactly as a real
// registrar's nonce-count cache would reject a resent Authorization header.
// Only called when Behaviour.EnforceNonceCountMonotonic is set — see its doc
// comment for why this is opt-in.
func (p *Peer) acceptNonceCount(req *sip.Request) bool {
	h := req.GetHeader("Authorization")
	if h == nil {
		return false
	}
	nc := ncParam(h.Value())
	p.mu.Lock()
	defer p.mu.Unlock()
	if nc <= p.lastAcceptedNc {
		return false
	}
	p.lastAcceptedNc = nc
	return true
}
