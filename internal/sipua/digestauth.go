package sipua

// internal/sipua/digestauth.go
//
// digestauth.go replaces siptest.(*Client).DoRequestWithDigest
// (internal/sipengine/siptest/uac.go:152-216) for every REGISTER call site in
// this package (Phase 4 W1 M3, Inputs §1). That vendored method hardcodes the
// digest nonce-count parameter to the literal 1 on EVERY 401/407 challenge it
// answers (uac.go:189) — spec-legal only for a single-shot exchange. A
// registrar tracking nonce-count per RFC 7616 §3.4.3 sees nc=1 a second time
// (this UA's first refresh) as a REPLAY, which is indistinguishable on the
// wire from an attacker resending a captured Authorization header. G4 forbids
// editing uac.go; this file reimplements the two things DoRequestWithDigest
// provided — the challenge-response orchestration and the response pump
// (pumpFinal) — with a real, tracked nc in place of the hardcoded 1.
//
// NO REGISTER-SPECIFIC KNOWLEDGE LIVES HERE. Which four call sites use this,
// recordRegisterCSeq, and regState's Call-ID/CSeq bookkeeping all stay in
// register.go — the only file that knows this is a REGISTER. P4-D06
// (Phase 4 W2) closed this by SHARING one instance, not by adding a
// second: applyDigest below reads u.nonceCounter for both legs, because nc is a
// property of the nonce and this file still knows nothing about REGISTER. The
// shared instance keys its slots on (realm, nonce) so the two legs can also be
// talking to DIFFERENT peers without evicting each other (design §13
// Amendment 1), and pins the registrar's slot so call VOLUME cannot evict it
// either (Amendment 2). The isRegisterLeg flag both callers pass is the only
// thing this file knows about who is asking, and it names a LEG, not REGISTER
// semantics: which slot an unseen identity may install into.
//
// Rule 16 reuse decision: RawTransaction (== siptest.(*Client).doTx) is
// reused unchanged for the first, unauthenticated leg. digest.ParseChallenge,
// digest.ComputeAuthorization and sipgo.ClientRequestAddVia are reused
// unmodified. internal/sipengine/** is imported, never edited (G4).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/digest"
)

// digestHostAllowed is CF-046's destination guard (D-C): may this UA answer an
// INVITE digest challenge from target, the INVITE Request-URI host? Yes when
// cfg.AuthAnyHost, or when target equals the registrar host (register mode) or
// the AOR host, compared exactly after normHost. Ports are ignored (D-C5); no
// DNS is done, so a name never matches an IP literal; no suffix matching. The
// REGISTER leg is not checked: it only ever talks to the registrar.
func digestHostAllowed(cfg Config, target string) bool {
	if cfg.AuthAnyHost {
		return true
	}
	target = normHost(target)
	if target == "" {
		return false
	}
	if cfg.Mode == "register" && normHost(uriHost(cfg.Registrar)) == target {
		return true
	}
	return normHost(uriHost(cfg.AOR)) == target
}

// anchorLookup is a TEST-ONLY seam, NIL in production (CF-054): the call that
// resolves a host (the anchor, and each of its SRV targets, CF-180) to the
// addresses its challenges may come from. A nil value means the UA's resolver
// (net.DefaultResolver in production, as sipgo's own resolveAddrIP uses); SRV
// lookups always go through that resolver. Same no-t.Parallel invariant as call.go's seam block.
var anchorLookup func(ctx context.Context, host string) ([]net.IPAddr, error)

// anchorPins is a UA's table of resolved anchor addresses (R-7): per UA, so a
// pin outlives a single dial; the digest leg only reads it.
type anchorPins struct {
	mu     sync.Mutex
	byHost map[string][]net.IP
}

// maxAnchorSRVTargets bounds the SRV targets resolved per host, so a hostile
// zone cannot make one challenge do unbounded lookups.
const maxAnchorSRVTargets = 16

// srvServicesFor lists the SRV (service, proto) pairs the fork may resolve a
// portless INVITE with on this UA's transport (transport_layer.go): udp uses
// _sip._udp, and _sip._tcp for the CF-106 oversize switch to TCP; tcp _sip._tcp;
// tls _sips._tcp. Any other transport has none.
func srvServicesFor(transport string) [][2]string {
	switch transport {
	case "udp":
		return [][2]string{{"sip", "udp"}, {"sip", "tcp"}}
	case "tcp":
		return [][2]string{{"sip", "tcp"}}
	case "tls":
		return [][2]string{{"sips", "tcp"}}
	}
	return nil
}

// pinsFor returns the addresses a challenge for anchor (an already normHost'ed
// host) may come from. An IP-literal anchor is pinned to itself, no DNS. A name
// is resolved lazily on the first challenge that needs it (R-9) to the union of
// its own A/AAAA addresses and those of its SRV targets for the services this
// UA's transport can send on (CF-180, RFC 3263 4.2: since CF-081 the fork sends a
// portless INVITE to the SRV target), at most maxAnchorSRVTargets targets, all
// under one deadline. The set is a strict allow-list of addresses that host's own
// DNS publishes. It is kept for the UA's lifetime unless a lookup failed for a
// reason other than "not found" (a timeout or SERVFAIL would pin an incomplete
// set forever); an empty one is NOT cached either (R-8), so ok is false and the
// next challenge resolves again. Two concurrent first challenges may both
// resolve; the first stored set wins.
func (u *UA) pinsFor(ctx context.Context, anchor string) (pins []net.IP, ok bool) {
	if ip := net.ParseIP(anchor); ip != nil {
		return []net.IP{ip}, true
	}
	u.digestPins.mu.Lock()
	stored, found := u.digestPins.byHost[anchor]
	u.digestPins.mu.Unlock()
	if found {
		return stored, true
	}
	lookup := anchorLookup
	if lookup == nil {
		lookup = u.resolver.LookupIPAddr
	}
	lctx, cancel := context.WithTimeout(ctx, u.cfg.Timeout)
	defer cancel()

	var ips []net.IP
	haveIP := map[string]bool{}
	transient := false
	add := func(host string) {
		if lctx.Err() != nil { // the deadline bounds the whole collection
			transient = true
			return
		}
		addrs, err := lookup(lctx, host)
		transient = transient || (err != nil && !isNotFound(err))
		for _, a := range addrs {
			if k := a.IP.String(); !haveIP[k] {
				haveIP[k] = true
				ips = append(ips, a.IP)
			}
		}
	}
	add(anchor)
	seen := map[string]bool{}
srv:
	for _, svc := range srvServicesFor(u.cfg.Transport) {
		_, recs, err := u.resolver.LookupSRV(lctx, svc[0], svc[1], anchor)
		transient = transient || (err != nil && !isNotFound(err))
		for _, r := range recs {
			key := normHost(r.Target)
			if key == "" || seen[key] { // "." means service not available
				continue
			}
			if len(seen) == maxAnchorSRVTargets {
				break srv
			}
			seen[key] = true
			// The target is looked up as the SRV record names it (absolute, with
			// its trailing dot, as the fork does), never as a relative name the
			// resolver could expand with a search domain; only the de-dup key is
			// normalised.
			add(r.Target)
		}
	}
	if len(ips) == 0 {
		return nil, false
	}
	if transient {
		return ips, true
	}
	u.digestPins.mu.Lock()
	defer u.digestPins.mu.Unlock()
	if u.digestPins.byHost == nil {
		u.digestPins.byHost = map[string][]net.IP{}
	}
	if first, found := u.digestPins.byHost[anchor]; found {
		return first, true
	}
	u.digestPins.byHost[anchor] = ips
	return ips, true
}

// isNotFound reports a definitive "no such name / no such records" DNS answer.
func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// pinnedSource reports whether source (a "host:port" as sip.Response.Source()
// gives it) is one of pins, and the text to show in a refusal. The port is
// ignored (D-C5). An unparsable or zoned source fails CLOSED, shown as given.
func pinnedSource(pins []net.IP, source string) (shown string, ok bool) {
	host, _, err := net.SplitHostPort(source)
	if err != nil {
		return source, false
	}
	srcIP := net.ParseIP(host)
	if srcIP == nil {
		return host, false
	}
	for _, p := range pins {
		if p.Equal(srcIP) {
			return srcIP.String(), true
		}
	}
	return srcIP.String(), false
}

// challengeSourceRefusal is CF-054's pin check, run after digestHostAllowed
// passed: it returns "" when the INVITE challenge res may be answered, else the
// fixed, secret-free reason it is withheld for (R-10), and logs one Warn. Both
// the challenge's source and the request's destination must be pinned: target is
// the host the request was addressed to, destination the address it was sent to
// (the INVITE's for a dial; the in-dialog request's for CF-122). With
// cfg.AuthAnyHost there is no pin and no DNS.
func (u *UA) challengeSourceRefusal(ctx context.Context, dialogID, target, destination string, res *sip.Response) string {
	if u.cfg.AuthAnyHost {
		return ""
	}
	pins, ok := u.pinsFor(ctx, normHost(target))
	if !ok {
		u.log().Warn("digest challenge not answered: the anchor host could not be resolved to pin the challenge source",
			"dialog_id", dialogID, "target_host", target, "status", int(res.StatusCode))
		return fmt.Sprintf("credentials withheld: %s could not be resolved to pin the challenge source (ua_create auth_any_host allows it)", target)
	}
	shown, ok := pinnedSource(pins, res.Source())
	if !ok {
		u.log().Warn("digest challenge not answered: the challenge did not come from a pinned address of the target",
			"dialog_id", dialogID, "target_host", target, "source", shown, "status", int(res.StatusCode))
		return fmt.Sprintf("credentials withheld: the challenge came from %s, not a pinned address of %s (ua_create auth_any_host allows it)", shown, target)
	}
	// The digest goes to the address the INVITE itself was sent to, which sipgo
	// resolved from the name at send time. A UDP challenge's source can be
	// forged (responses match by branch from any address), so a pinned SOURCE
	// alone does not show the credential would reach a pinned address: the
	// destination must be pinned too, or a name that now resolves elsewhere
	// could unlock credentials for that other host.
	if dest, ok := pinnedSource(pins, destination); !ok {
		u.log().Warn("digest challenge not answered: the INVITE was not sent to a pinned address of the target",
			"dialog_id", dialogID, "target_host", target, "destination", dest, "status", int(res.StatusCode))
		return fmt.Sprintf("credentials withheld: the INVITE was sent to %s, not a pinned address of %s (ua_create auth_any_host allows it)", dest, target)
	}
	return ""
}

// uriHost extracts the host from a sip:/sips: URI (or bare host[:port]) through
// the canonical parse step, parseSIPURI. An unparsable URI yields "", which
// anchors nothing: the guard fails closed. An IPv6 host keeps its brackets,
// which normHost strips.
func uriHost(uri string) string {
	u, err := parseSIPURI(uri)
	if err != nil {
		return ""
	}
	return u.Host
}

// normHost canonicalises a host for comparison: brackets stripped, lower-cased
// (strings.ToLower; to_uri validation already rejects hosts a Unicode fold could
// change), exactly ONE trailing dot stripped (CF-022: "example.com." is
// valid, "example.com.." is not), IP literals in canonical text form.
func normHost(h string) string {
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	h = strings.ToLower(h)
	h = strings.TrimSuffix(h, ".")
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	return h
}

// nonceInvitePoolSlots is how many INVITE-ORIGINATED (realm, nonce) pairs this
// UA tracks a nonce-count for at once. THREE, which with the pinned registrar
// slot below makes four in total: one registrar plus up to three
// concurrently-challenged outbound calls. A fixed compile-time bound, not a
// tuning knob.
const nonceInvitePoolSlots = 3

// nonceSlot is one (realm, nonce) pair's RFC 7616 §3.4.3 nonce-count.
type nonceSlot struct {
	realm, nonce, opaque string
	count                uint32
}

// holds reports whether s is an OCCUPIED slot for ch's (realm, nonce).
//
// count > 0 IS THE OCCUPANCY MARKER, and it is load-bearing, not defensive
// noise: every installed slot starts at 1, so a zero-valued slot — an unused
// pool entry, or the registrar slot before the first REGISTER challenge — must
// not answer for a challenge whose realm and nonce are both empty. (One
// consequence, consistent with the documented overflow policy on next: a slot
// that wraps to 0 reads as free and the next challenge reinstalls it at 1.)
func (s nonceSlot) holds(ch digest.Challenge) bool {
	return s.count > 0 && s.realm == ch.Realm && s.nonce == ch.Nonce
}

// nonceCounter tracks RFC 7616 §3.4.3's nonce-count for every (realm, nonce)
// this UA is currently authenticating against — ONE counter object shared by
// both digest legs (REGISTER and the challenged outbound INVITE), because nc
// counts the requests sent WITH A GIVEN NONCE, not with a given method, and a
// peer issuing one nonce for both methods enforces monotonicity across them.
//
// FOUR SLOTS, NOT ONE, AND NOT A MAP (design §13 Amendment 1). One slot was the
// original design's choice and it is unsafe here: this UA has no outbound proxy
// (Dial builds the Request-URI from the caller's to_uri, call.go:1118-1124), so
// an INVITE can face a different realm than the registrar, and with one slot
// that INVITE's challenge would evict the registrar's — making the next REGISTER
// refresh restart at nc=1 on a nonce the registrar has already seen, i.e. a
// replay by its own rule. An unbounded map[nonce]count is rejected for the
// opposite reason: it is the peer-driven-allocation defect class B1 fixed for
// Content-Length, since a hostile registrar can mint unbounded nonces. A fixed
// value-typed array is bounded by construction — nothing is allocated per
// challenge — and evicting the least recently used slot degrades a forgotten
// CALL's realm to nc=1, which is exactly the pre-P4-D06 behaviour, never worse.
// That last clause holds for call traffic and NOT for the registrar, which is
// why the registrar's slot is not in the pool at all (next paragraph).
//
// THE REGISTRAR'S SLOT IS PINNED, NOT POOLED (design §13 Amendment 2). Four
// INTERCHANGEABLE LRU slots are still unsafe, because ordinary call traffic can
// evict the one identity that actually needs continuity: four distinct INVITE
// destinations challenged between two register refreshes push the registrar's
// entry off the tail, and the next refresh re-presents the registrar's own
// long-lived nonce with nc=1 — the same replay rejection, reached by call
// VOLUME instead of by a cross-realm call. So the registrar's slot is a field of
// its own that ONLY the REGISTER leg installs or replaces (see next), and the
// three-slot pool that absorbs INVITE-originated identities evicts only among
// itself. promote and vacate are written against the pool array alone, so no
// INVITE-originated challenge can reach the registrar slot at all — the pinning
// is structural, not a rule this code has to remember.
//
// ITS OWN MUTEX, NOT regState.mu. Two reasons, both load-bearing: (a) this file
// carries no REGISTER-specific knowledge, per the package doc comment above,
// and must not reach into register.go's lock to guard its own state; (b)
// regState's own doc comment (register.go) forbids holding that lock across a
// network write. This mutex guards the slot set's own invariant only — one
// next()/promote()/vacate() at a time; the separate guarantee that a leg's
// RESERVATION and the stamping of that nc onto its request are atomic against
// the other leg is UA.digestRetryMu's job (see its field comment in ua.go), at
// a different level. Neither lock is held across any network I/O.
type nonceCounter struct {
	mu sync.Mutex

	// registrar is the PINNED slot: the (realm, nonce) the REGISTER leg is
	// currently authenticating against. Only next's isRegisterLeg paths write
	// it. Zero-valued until the first REGISTER challenge; holds treats a zero
	// count as unoccupied, so until then it matches nothing.
	registrar nonceSlot

	// invites is the LRU pool for INVITE-ORIGINATED identities, most recently
	// used first. Eviction happens here and only here.
	invites [nonceInvitePoolSlots]nonceSlot
}

// next returns the nc value to send for ch: the previous value plus 1 when this
// UA already holds a slot for ch's (realm, nonce), otherwise 1 in a freshly
// installed slot.
//
// LOOKUP IS BY IDENTITY FIRST, LEG SECOND (design §13 Amendment 2). A challenge
// matching the pinned registrar slot counts THERE whichever leg asks — which is
// exactly what makes design §3's collision case correct, since a peer issuing
// ONE nonce for both methods is the case where both legs find the same slot and
// must share one monotonic count. isRegisterLeg decides only what happens to an
// identity that is NOT already in the pinned slot:
//
//   - REGISTER, matching a POOL slot: the slot MIGRATES into the pinned slot,
//     carrying its count (no reset), and vacates the pool entry. The pool can
//     legitimately hold an identity that later becomes the registrar's — same
//     proxy in both roles, registrar rotates its nonce, an INVITE draws the new
//     nonce first — and without the migration that identity would count
//     correctly once and then sit in an evictable slot.
//   - REGISTER, matching nothing: REPLACES the pinned slot. A REGISTER
//     challenge naming an unseen realm or nonce IS by definition the new current
//     registrar identity, and the old one is dead the moment REGISTER moves on,
//     so it is discarded rather than demoted into the pool.
//   - INVITE, matching a pool slot: increments it and makes it most recently
//     used.
//   - INVITE, matching nothing: LRU-inserts into the pool, evicting the pool's
//     own oldest entry. It can never displace the pinned slot.
//
// A NONCE CHANGE IS A NEW SLOT, NOT A RESET, and that ALSO SUBSUMES stale=true:
// digest.Challenge has no Stale field (G4 forbids adding one) and needs none
// here, because RFC 7616 §3.3 always issues a NEW nonce alongside stale=true, so
// a stale challenge is just another miss to this function.
//
// Overflow at 2^32 wraps to 0 per Go's defined unsigned-overflow rule —
// documented, not guarded: no registrar holds one nonce for four billion
// requests.
func (c *nonceCounter) next(ch digest.Challenge, isRegisterLeg bool) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.registrar.holds(ch) {
		c.registrar.count++
		return c.registrar.count
	}
	for i := range c.invites {
		if !c.invites[i].holds(ch) {
			continue
		}
		s := c.invites[i]
		s.count++
		if isRegisterLeg {
			// Migrate: this identity is the registrar's from now on.
			c.vacate(i)
			c.registrar = s
			return s.count
		}
		c.promote(i, s)
		return s.count
	}

	s := nonceSlot{realm: ch.Realm, nonce: ch.Nonce, opaque: ch.Opaque, count: 1}
	if isRegisterLeg {
		c.registrar = s
		return 1
	}
	// A pool miss overwrites the LAST pool slot, which after every promote() is
	// the least recently used one.
	c.promote(len(c.invites)-1, s)
	return 1
}

// promote writes s into invites[0], shifting invites[0:i] down one place. Pool
// slot i's prior contents are overwritten, so calling it with
// i == len(invites)-1 evicts the least recently used pooled identity. It cannot
// touch the registrar slot. Caller holds c.mu.
func (c *nonceCounter) promote(i int, s nonceSlot) {
	copy(c.invites[1:i+1], c.invites[:i])
	c.invites[0] = s
}

// vacate removes pool slot i, shifting the slots after it up one place and
// zeroing the tail — so the freed capacity ends up at the LEAST-recently-used
// end, where the next miss will take it, rather than leaving a hole that a miss
// would step over to evict a live entry. Caller holds c.mu.
func (c *nonceCounter) vacate(i int) {
	copy(c.invites[i:], c.invites[i+1:])
	c.invites[len(c.invites)-1] = nonceSlot{}
}

// doRequestWithDigest sends req; if it receives a 401/407 digest challenge,
// it answers ONCE using nc's tracked nonce-count. It mirrors
// siptest.(*Client).DoRequestWithDigest (uac.go:152-216) end to end — the
// same challenge -> recompute -> in-place header replace -> explicit CSeq
// bump -> Via strip -> retry sequence — except the nc it computes with is
// real, not the vendored method's hardcoded 1.
//
// The nonce-count comes from u.nonceCounter, the UA-scoped slot set P4-D06
// shares with the INVITE leg (see ua.go's field comment); callers no longer
// pass one. THIS FUNCTION DISPATCHES REGISTER ONLY — register.go's four sites
// are its only callers — which is why it hands applyDigest isRegisterLeg=true
// and so owns the counter's pinned registrar slot.
func (u *UA) doRequestWithDigest(ctx context.Context, req *sip.Request) (*sip.Response, answeredChallenge, error) {
	res, err := u.Client().RawTransaction(ctx, req, u.cfg.Timeout)
	if err != nil {
		// Phase 4 W1 M7c, §2/§3: this is the first point a REGISTER dispatch
		// error (including a TLS handshake/certificate failure on a tls UA)
		// becomes a returned error. classifyTLSError is a no-op passthrough
		// on any error outside its closed probe set, so a non-TLS transport
		// error reaches the caller completely unchanged.
		return nil, answeredChallenge{}, classifyTLSError(err, u.cfg.Registrar)
	}
	if res.StatusCode != 401 && res.StatusCode != 407 {
		// NO CHALLENGE WAS ANSWERED, so the zero value goes back — which
		// register.go's rememberChallenge reads as "leave the cache alone"
		// (P4-D07). Once the cache is warm this is the ORDINARY outcome, and
		// overwriting a good cached challenge with "none" here would put the UA
		// straight back on the two-REGISTER cycle.
		return res, answeredChallenge{}, nil
	}
	if u.cfg.AuthUser == "" || u.cfg.AuthPass == "" {
		return res, answeredChallenge{}, fmt.Errorf("got %d but no auth credentials configured", res.StatusCode)
	}

	// THE RESERVATION CRITICAL SECTION (ua.go's digestRetryMu): reserve this
	// leg's nonce-count without a second leg interleaving between the read and
	// the increment of the shared slot, and stamp the reserved nc onto req's
	// Authorization header. IT COVERS applyDigest ONLY — the dispatch below runs
	// with the lock RELEASED (Rule 13 Cycle 5 fix round).
	//
	// WHY THE DISPATCH IS OUTSIDE (Rule 13 Cycle 5, architecture review). The
	// section used to span TransactionRequest too, to order the two legs' WIRE
	// WRITES and not merely their reservations. That is not worth its cost:
	// TransactionRequest synchronously DIALS for a destination with no live
	// connection (TCP connect, and for tls the whole handshake), and
	// digestRetryMu is UA-global — it does not distinguish identities — so a
	// slow or unreachable callee on the INVITE leg would hold it long enough to
	// stall a healthy registrar's refresh on an entirely unrelated
	// (realm, nonce). Mutex.Lock takes no context, so the blocked leg cannot
	// even honour tctx's deadline while WAITING: unrelated call-path network
	// conditions could turn into outright registration failure.
	//
	// WHAT THAT TRADES AWAY, and why it is acceptable: with the lock dropped
	// before dispatch, two reservations that took nc=1 and nc=2 in that
	// guaranteed order (reservation itself is still atomic) can still reach the
	// wire in the other order if the scheduler favours the nc=2 sender. That is
	// NOT a new failure class — wire ordering here was always best-effort, since
	// two datagrams already in flight can reorder in the network regardless of
	// any lock this process holds — so this only widens an already-documented,
	// already-accepted window, and it removes a strictly more severe one.
	//
	// The critical section is an inner closure so it can still use a plain defer
	// (Rule 13 Cycle 3 fix round, finding #2): a future early return between
	// Lock and Unlock cannot leak the hold, and the section cannot silently grow
	// past applyDigest.
	tctx, cancel := context.WithTimeout(ctx, u.cfg.Timeout)
	defer cancel()
	var answered answeredChallenge
	applyErr := func() error {
		u.digestRetryMu.Lock()
		defer u.digestRetryMu.Unlock()
		// isRegisterLeg=true: this function IS the REGISTER leg's dispatcher —
		// its only callers are register.go's four sites, all sending REGISTER —
		// so it is the leg allowed to install into the counter's PINNED
		// registrar slot (digestauth.go's next, design §13 Amendment 2).
		var err error
		answered, err = u.applyDigest(req, res, true)
		return err
	}()
	if applyErr != nil {
		// UNCHANGED RETURN CONVENTION: the challenge response travels back
		// alongside a challenge-shape error. Unregister reads it to record
		// reg.code (register.go:858-863), so returning nil here would be a
		// silent behavior change.
		return res, answeredChallenge{}, applyErr
	}
	tx, terr := u.Client().Raw().TransactionRequest(tctx, req, sipgo.ClientRequestAddVia)
	if terr != nil {
		// Phase 4 W1 M7c, §2/§3: the second (digest-retry leg) dispatch error
		// return, classified exactly as doTxWithAddVia classified it, and still
		// returning a nil response as it did.
		//
		// THE CHALLENGE IS STILL RETURNED, AND THAT IS NOT A CACHING DECISION
		// (Rule 4 Cycle B, finding 2). It was parsed and answered, which is
		// exactly what answeredChallenge reports; whether a challenge whose
		// dispatch never completed is worth remembering is the CALLER's call, and
		// register.go's sendRegister declines it — no 200 came back, so nothing
		// here demonstrates the registrar accepts this identity. This file keeps
		// reporting the fact and taking no policy on it.
		return nil, answered, classifyTLSError(terr, u.cfg.Registrar)
	}
	final, ferr := u.pumpFinal(tctx, tx)
	return final, answered, ferr
}

// answeredChallenge is the digest challenge a request was authenticated against,
// together with the request header its credential went out under —
// "Authorization" for a 401/WWW-Authenticate, "Proxy-Authorization" for a
// 407/Proxy-Authenticate.
//
// ITS ZERO VALUE MEANS "NO CHALLENGE WAS ANSWERED" (HeaderName == ""), which is
// what every non-challenge path returns and what every consumer must treat as
// "nothing to cache".
//
// IT CARRIES NO REGISTER KNOWLEDGE, consistent with this file's header comment.
// It names WHAT was answered; whether presenting it PREEMPTIVELY on a later
// request is safe is the reader's business, and depends entirely on that leg's
// topology. P4-D07's REGISTER-side cache (register.go's regState.challenge) is
// the only consumer today, and deliberately so: the registrar is ONE long-lived
// identity, while the INVITE leg dials a different destination on every call and
// must keep drawing its own challenge.
type answeredChallenge struct {
	Challenge  digest.Challenge
	HeaderName string
}

// credentialFor computes the digest credential VALUE for ch on req — the string
// that goes on the wire after "Authorization: " or "Proxy-Authorization: " —
// reserving this UA's next RFC 7616 §3.4.3 nonce-count for ch's (realm, nonce)
// from the shared counter.
//
// IT MUTATES NOTHING ON req, and that is the whole reason it is separate from
// applyDigest (Rule 16 extraction, P4-D07). applyDigest's CSeq bump and Via strip
// exist because a digest RETRY re-sends a request that is already on the wire; a
// PREEMPTIVE credential (register.go's presentCachedChallenge) rides on a request
// the dispatcher has not sent yet, where both would be wrong — the identity's
// CSeq is already correct and sipgo will bump it on dispatch, and the builder's
// Via is the one that should go out. The digest inputs are the method, the
// Request-URI and the challenge; CSeq is NOT one of them (RFC 3261 §22.4), so
// both callers compute the identical value.
//
// CALLER MUST HOLD u.digestRetryMu, and must RELEASE IT BEFORE the dispatch that
// puts this nc on the wire (Rule 13 Cycle 5 fix round). This function consumes a
// nonce-count; the lock's job is to make reserve-and-stamp atomic against the
// other leg. See the field comment in ua.go.
func (u *UA) credentialFor(req *sip.Request, ch digest.Challenge, isRegisterLeg bool) (string, error) {
	// MD5 ONLY, AND SAY SO OUT LOUD (design §13 Amendment 3).
	// ComputeAuthorization below hashes with MD5 unconditionally, but it copies
	// ch.Algorithm onto the response verbatim (internal/sipengine/digest/
	// digest.go:109) and HeaderValue writes it out (:119) — so WITHOUT this
	// guard a SHA-256 challenge yields an MD5 digest LABELLED
	// algorithm=SHA-256. That is not a failed authentication, it is a silently
	// WRONG one: the peer rejects it and the operator reads bad credentials.
	//
	// IT IS A GUARD, NOT A CAPABILITY. P4-D06 repointed the challenged INVITE
	// (call.go's digestAuthTransaction) off sipgo.DoDigestAuth, whose engine
	// (github.com/icholy/digest) DID support SHA-256/512/512-256. So the
	// repoint costs this UA those algorithms, and this guard's only job is to
	// make that loss LOUD instead of a wrong hash on the wire. Restoring them
	// is deliberately out of scope: internal/sipengine is frozen (G4) and
	// using icholy/digest directly is a Rule 17 dependency-usage decision.
	//
	// WHY BOTH CLAUSES. ParseChallenge already defaults an ABSENT algorithm to
	// "MD5" (:57-58), so the empty check is reachable only for a Challenge built
	// in code rather than parsed — cheap, and it keeps this guard correct
	// independently of that default. EqualFold because RFC 7616 §3.3's
	// algorithm is a token whose registered values are case-insensitive, and
	// ParseChallenge lowercases only the KEY, never the value (:43-48).
	//
	// IT MUST PRECEDE next(). A refused challenge must not consume a
	// nonce-count, or a peer challenging with SHA-256 on every attempt burns
	// this UA's count for that (realm, nonce) while never authenticating.
	if ch.Algorithm != "" && !strings.EqualFold(ch.Algorithm, "MD5") {
		return "", fmt.Errorf("unsupported digest algorithm %q: this UA computes MD5 only", ch.Algorithm)
	}

	// THE FULL REQUEST-URI, not just its addr. sipgo's own digestAuthApply
	// (third_party/sipgo/client.go:438-454) passes Recipient.Addr(), which
	// DROPS URI parameters — an inherited improvement on the INVITE leg, called
	// out at closeout rather than absorbed silently. The REGISTER leg already
	// used this form before P4-D06.
	uri := req.Recipient.String()
	// THE ONE uint32->int CONVERSION SITE (Inputs §1). Nowhere else in this
	// file or its callers narrows the counter.
	auth := digest.ComputeAuthorization(
		u.cfg.AuthUser, u.cfg.AuthPass, string(req.Method), uri, ch,
		int(u.nonceCounter.next(ch, isRegisterLeg)))
	return auth.HeaderValue(), nil
}

// applyDigest answers the 401/407 challenge on res by mutating req in place:
// it parses the challenge, computes an Authorization (or Proxy-Authorization)
// value using the UA's SHARED nonce-counter, replaces that header on req,
// bumps req's CSeq, and strips req's Via after pinning its transport.
//
// EXTRACTED FROM doRequestWithDigest FOR P4-D06's SECOND CALLER (Rule 16), not
// rewritten: the sequence below is the pre-P4-D06 body verbatim, so the
// REGISTER leg's wire output is unchanged. The one difference is WHOSE counter
// it reads — u.nonceCounter, the single UA-scoped slot both legs share (see
// its field comment in ua.go), rather than a counter handed in per call.
//
// req IS MUTATED. On an error return it may be partially mutated only in the
// cases the caller already treats as fatal (an unparseable challenge, a
// missing CSeq); no caller retries a req that came back with an error.
//
// isRegisterLeg IS PASSED STRAIGHT THROUGH TO next AND USED FOR NOTHING ELSE.
// It decides which slot a NEVER-BEFORE-SEEN (realm, nonce) installs into — the
// counter's pinned registrar slot, or its LRU pool for call traffic — and
// whether a pooled identity migrates into the pinned slot (design §13
// Amendment 2). doRequestWithDigest passes true (it dispatches only REGISTER);
// digestAuthTransaction passes false.
//
// CALLER MUST HOLD u.digestRetryMu FOR THIS CALL, and must RELEASE IT BEFORE
// the dispatch that puts this nc on the wire (Rule 13 Cycle 5 fix round). The
// lock's job is to make reserve-and-stamp atomic against the other leg; holding
// it across TransactionRequest would put a synchronous dial under a UA-global
// lock. Both callers follow this; see the field's comment in ua.go.
//
// IT REPORTS THE CHALLENGE IT ANSWERED (P4-D07). The returned answeredChallenge
// is the parsed challenge plus the header name the credential went out under, so
// a caller with ONE long-lived peer identity can cache it and present a
// credential preemptively on its next request (RFC 3261 §22.1). On every error
// path the zero value is returned, which every consumer reads as "nothing to
// cache". This file does not store it and does not know who will.
//
// IT REMOVES BOTH CREDENTIAL HEADER NAMES BEFORE APPENDING, NOT ONLY THIS
// RESPONSE'S (Rule 4 Cycle B, finding 1). The invariant is that a request never
// carries two credentials from two different challenge attempts. Removing only
// the name matching res.StatusCode was sufficient while the sole author of a
// credential header was this function answering a challenge on a request it had
// already sent. P4-D07 ends that: register.go's presentCachedChallenge stamps a
// credential under whichever name the CACHED challenge used, so a request whose
// cached family is 401/Authorization and whose fresh challenge is 407 (a proxy
// inserted on this cycle, or a load balancer whose members disagree) would
// otherwise retry carrying the stale header beside the fresh one — a spent nonce
// presented to the peer alongside a live credential, which a registrar reads as a
// replay or a malformed authentication rather than as an authentication attempt.
// Fixing it HERE rather than at the stamp makes it a property of the one function
// that writes credentials, not a rule every future caller must remember.
func (u *UA) applyDigest(req *sip.Request, res *sip.Response, isRegisterLeg bool) (answeredChallenge, error) {
	if u.cfg.AuthUser == "" || u.cfg.AuthPass == "" {
		return answeredChallenge{}, fmt.Errorf("got %d but no auth credentials configured", res.StatusCode)
	}

	var (
		challengeHeader sip.Header
		authzHeaderName string
	)
	switch res.StatusCode {
	case 401:
		challengeHeader = res.GetHeader("WWW-Authenticate")
		authzHeaderName = "Authorization"
		if challengeHeader == nil {
			return answeredChallenge{}, fmt.Errorf("401 without WWW-Authenticate")
		}
	case 407:
		challengeHeader = res.GetHeader("Proxy-Authenticate")
		authzHeaderName = "Proxy-Authorization"
		if challengeHeader == nil {
			return answeredChallenge{}, fmt.Errorf("407 without Proxy-Authenticate")
		}
	default:
		return answeredChallenge{}, fmt.Errorf("applyDigest called on a %d, which is not a digest challenge", res.StatusCode)
	}

	ch, err := digest.ParseChallenge(challengeHeader.Value())
	if err != nil {
		return answeredChallenge{}, fmt.Errorf("parse digest challenge: %w", err)
	}

	// The MD5 guard, the Request-URI and the nonce-count reservation all live in
	// credentialFor now, so the preemptive path computes an identical credential
	// without inheriting the mutations below (P4-D07). Nothing on req is touched
	// until this succeeds, which is what keeps a refused challenge from leaving a
	// half-mutated request behind.
	value, err := u.credentialFor(req, ch, isRegisterLeg)
	if err != nil {
		return answeredChallenge{}, err
	}

	// Mutate req in place. BOTH names are removed, not just authzHeaderName: a
	// chained retry must not accumulate duplicates of its own header, AND a
	// preemptive credential stamped under the OTHER challenge family must not
	// survive alongside this one (see the doc comment's second appended
	// paragraph). RemoveHeader on an absent name is a no-op, so the ordinary
	// same-family case costs one extra call and nothing else.
	req.RemoveHeader("Authorization")
	req.RemoveHeader("Proxy-Authorization")
	req.AppendHeader(sip.NewHeader(authzHeaderName, value))

	// Bump CSeq explicitly (RFC 3261 §20.16 monotonicity) — the non-empty
	// options slice both callers dispatch through (ClientRequestAddVia) bypasses
	// sipgo's own automatic bump (third_party/sipgo/client.go:143-150).
	cseq := req.CSeq()
	if cseq == nil {
		return answeredChallenge{}, fmt.Errorf("%s missing CSeq header", req.Method)
	}
	cseq.SeqNo++

	// Strip Via so sipgo re-adds a fresh one via ClientRequestAddVia. Capture
	// the original Via's transport first: once the Via is gone, req.Transport()
	// has no signal left and falls back to sip.DefaultProtocol (UDP), silently
	// misrouting the retry. Pin it via SetTransport so the rebuilt Via (and the
	// transport layer's dial) use the original transport. sipgo's DoDigestAuth
	// does NOT do this, so a challenged TCP/TLS INVITE could retry over UDP —
	// the second inherited improvement, likewise called out at closeout.
	origVia := req.Via()
	req.RemoveHeader("Via")
	if origVia != nil && origVia.Transport != "" {
		req.SetTransport(origVia.Transport)
	}
	return answeredChallenge{Challenge: ch, HeaderName: authzHeaderName}, nil
}

// digestAuthTransaction is P4-D06's INVITE-leg entry point: it answers res's
// challenge on req through applyDigest — hence through the SHARED
// nonceCounter — and returns the retry's client transaction for the caller to
// drive. digestRetryMu covers the RESERVATION ONLY (see its field comment in
// ua.go and doRequestWithDigest's matching section): it is released before
// TransactionRequest, so neither a ringing INVITE nor a slow/unreachable callee
// stalling that dispatch's dial can block a REGISTER refresh on an unrelated
// (realm, nonce).
//
// IT REPLACES sipgo.(*Client).DoDigestAuth AT call.go's runDial, and returns
// the same sip.ClientTransaction so driveTx is untouched: the D5 property
// runDial depends on (the authed leg surfaces 180 Ringing through the same
// provisional-aware loop as the first leg) is preserved exactly, because it
// lives in driveTx, not here. DoDigestAuth could not be reused: it builds its
// own digest.Options with no Count field, so github.com/icholy/digest defaults
// Nc to 0 and there is no seam to feed a real nonce-count through.
func (u *UA) digestAuthTransaction(ctx context.Context, req *sip.Request, res *sip.Response) (sip.ClientTransaction, error) {
	// Reservation only, in an inner closure so the defer releases the lock
	// BEFORE the dispatch below (Rule 13 Cycle 5 fix round) — the whole point is
	// that no network I/O happens under this UA-global lock.
	if err := func() error {
		u.digestRetryMu.Lock()
		defer u.digestRetryMu.Unlock()
		// isRegisterLeg=false: an unseen (realm, nonce) from a call goes into
		// the counter's LRU pool, never into its pinned registrar slot (design
		// §13 Amendment 2). A challenge that MATCHES the registrar's current
		// (realm, nonce) still counts in the pinned slot — that is the
		// shared-nonce case design §3 exists for, and next resolves it by
		// identity, not by leg.
		//
		// THE ANSWERED CHALLENGE IS DISCARDED HERE, DELIBERATELY (P4-D07). The
		// INVITE leg dials a different destination on every call, so a cached
		// challenge from the last callee is worthless — and worse than
		// worthless against a peer that would reject it. Preemptive caching is
		// REGISTER-only, in register.go.
		_, err := u.applyDigest(req, res, false)
		return err
	}(); err != nil {
		return nil, err
	}
	return u.Client().Raw().TransactionRequest(ctx, req, sipgo.ClientRequestAddVia)
}

// pumpFinal drains tx until its FIRST FINAL (>=200) response, swallowing every
// 1xx — a registrar's 100 Trying must never become an exchange's returned
// outcome. It is doTxWithAddVia's response loop, verbatim; only the transaction
// creation moved out to the two call sites, so that digestRetryMu — which those
// sites now drop before transaction creation anyway (Rule 13 Cycle 5 fix round)
// — is nowhere near this wait.
//
// BOTH LEGS' TRANSACTIONS ARE CREATED WITH sipgo's ClientRequestAddVia option,
// mirroring siptest.(*Client).doTxWithAddVia (uac.go:225-249). Passing it means
// sipgo will NOT auto-bump CSeq (the options slice is non-empty, bypassing
// client.go:143-150 — applyDigest already bumped by hand) and WILL prepend a
// fresh Via using the client's own host:port. That posture is inherited exactly
// as every other outbound request on this UA gets it: the client was built from
// the post-bind viaAddr (ua.go:422-427), not re-derived here.
func (u *UA) pumpFinal(ctx context.Context, tx sip.ClientTransaction) (*sip.Response, error) {
	defer tx.Terminate()
	return u.awaitFinal(ctx, tx)
}

// awaitFinal is pumpFinal's wait without the Terminate: sendInDialog keeps a
// re-INVITE's transaction alive after a 2xx so the 2xx absorber can re-ACK its
// retransmissions (CF-169).
func (u *UA) awaitFinal(ctx context.Context, tx sip.ClientTransaction) (*sip.Response, error) {
	for {
		select {
		case res := <-tx.Responses():
			if res == nil {
				continue
			}
			if res.StatusCode < 200 {
				continue
			}
			return res, nil
		case <-tx.Done():
			return nil, fmt.Errorf("tx done: %v", tx.Err())
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
