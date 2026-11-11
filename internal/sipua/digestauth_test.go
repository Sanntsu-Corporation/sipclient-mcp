package sipua

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/digest"
)

func TestNonceCounterStartsAtOneOnFirstChallenge(t *testing.T) {
	var c nonceCounter
	ch := digest.Challenge{Realm: "r", Nonce: "n1"}
	if got := c.next(ch, true); got != 1 {
		t.Fatalf("next() on first challenge = %d, want 1", got)
	}
}

// TestNonceCounterIncrementsAcrossTheSameNonce is Inputs §1's core
// property: a registrar that never rotates its nonce (this project's own
// testutil/peer, testNonce) must see nc climb 1,2,3,4,... one value per
// challenged exchange, never repeating.
func TestNonceCounterIncrementsAcrossTheSameNonce(t *testing.T) {
	var c nonceCounter
	ch := digest.Challenge{Realm: "r", Nonce: "n1"}
	want := []uint32{1, 2, 3, 4}
	for i, w := range want {
		if got := c.next(ch, true); got != w {
			t.Fatalf("next() call %d = %d, want %d", i+1, got, w)
		}
	}
}

func TestNonceCounterResetsWholesaleOnNonceChange(t *testing.T) {
	var c nonceCounter
	first := digest.Challenge{Realm: "r", Nonce: "n1"}
	c.next(first, true)
	c.next(first, true)
	if got := c.next(first, true); got != 3 {
		t.Fatalf("precondition: next() = %d, want 3", got)
	}
	second := digest.Challenge{Realm: "r", Nonce: "n2"}
	if got := c.next(second, true); got != 1 {
		t.Fatalf("next() after a nonce change = %d, want 1 (wholesale slot replacement)", got)
	}
}

func TestNonceCounterResetsWholesaleOnRealmChange(t *testing.T) {
	var c nonceCounter
	first := digest.Challenge{Realm: "r1", Nonce: "n1"}
	c.next(first, true)
	c.next(first, true)
	second := digest.Challenge{Realm: "r2", Nonce: "n1"}
	if got := c.next(second, true); got != 1 {
		t.Fatalf("next() after a realm change = %d, want 1 (wholesale slot replacement)", got)
	}
}

// TestNonceCounterWrapsAtUint32Max pins the documented, deliberately
// unguarded overflow: count is a uint32, and Go's defined unsigned-overflow
// rule wraps it to 0 rather than panicking or saturating. No registrar holds
// one nonce for four billion requests; this exists so the wrap is a pinned
// fact, not an accident nobody noticed.
func TestNonceCounterWrapsAtUint32Max(t *testing.T) {
	c := nonceCounter{registrar: nonceSlot{realm: "r", nonce: "n1", count: math.MaxUint32}}
	ch := digest.Challenge{Realm: "r", Nonce: "n1"}
	if got := c.next(ch, true); got != 0 {
		t.Fatalf("next() at MaxUint32 = %d, want 0 (documented wraparound)", got)
	}
}

// TestNonceCounterKeepsEachRealmsSlotAcrossInterleaving is the Rule 4 Cycle B
// blocking finding, pinned (design §13 Amendment 1).
//
// THE FAILURE IT PREVENTS. This UA has no outbound proxy: Dial builds the
// Request-URI straight from the caller's to_uri (call.go:1118-1124) and
// policy.CheckDestination allows every destination by default, so a UA
// registered with proxy A can INVITE proxy B on the next call_dial. With ONE
// slot, B's challenge replaces A's, and the next REGISTER refresh — reusing A's
// own long-lived nonce, the exact registrar behaviour P4-D06 exists for —
// restarts at nc=1 and A rejects it as a replay. The very defect this feature
// removes, reintroduced by the topology.
func TestNonceCounterKeepsEachRealmsSlotAcrossInterleaving(t *testing.T) {
	var c nonceCounter
	registrar := digest.Challenge{Realm: "registrar.example", Nonce: "N-reg"}
	callee := digest.Challenge{Realm: "callee.example", Nonce: "N-callee"}

	if got := c.next(registrar, true); got != 1 {
		t.Fatalf("registrar's first nc = %d, want 1", got)
	}
	if got := c.next(callee, false); got != 1 {
		t.Fatalf("an unseen realm's first nc = %d, want 1", got)
	}
	if got := c.next(registrar, true); got != 2 {
		t.Fatalf("registrar's nc after an interleaved challenge from ANOTHER realm = %d, want 2 — "+
			"the registrar's slot must survive an outbound INVITE to a different peer, or its next "+
			"refresh replays nc=1 against a nonce it already used", got)
	}
}

// TestNonceCounterPinsTheRegistrarSlotAgainstInviteEviction is the SECOND round
// of Rule 4 Cycle B's blocking finding, pinned (design §13 Amendment 2).
//
// THE FAILURE IT PREVENTS. A uniform LRU treats every slot as equally evictable,
// so ordinary call traffic can push out the one identity that needs continuity:
// enough distinct INVITE destinations get challenged between two register
// refreshes, and the next refresh re-presents the registrar's own long-lived
// nonce with nc=1 — the replay rejection P4-D06 exists to remove, reached by call
// VOLUME rather than by the cross-realm collision Amendment 1 closed. FIVE
// distinct INVITE-originated challenges, more than the whole four-slot footprint,
// so this fails on ANY uniform-pool topology regardless of how it is sized.
func TestNonceCounterPinsTheRegistrarSlotAgainstInviteEviction(t *testing.T) {
	var c nonceCounter
	registrar := digest.Challenge{Realm: "registrar.example", Nonce: "N-reg"}
	if got := c.next(registrar, true); got != 1 {
		t.Fatalf("registrar's first nc = %d, want 1", got)
	}

	// Ordinary call traffic: five DIFFERENT challenged INVITE destinations.
	for i := 0; i < 5; i++ {
		ch := digest.Challenge{Realm: fmt.Sprintf("callee%d.example", i), Nonce: fmt.Sprintf("N-c%d", i)}
		if got := c.next(ch, false); got != 1 {
			t.Fatalf("INVITE destination %d's first nc = %d, want 1", i, got)
		}
	}

	if got := c.next(registrar, true); got != 2 {
		t.Fatalf("registrar's nc after 5 INVITE-originated challenges = %d, want 2 — the registrar "+
			"slot is PINNED and must not be evictable by call traffic, or its next refresh replays "+
			"nc=1 against a nonce it has already used", got)
	}
	// The pool DID evict among itself, which is what makes the assertion above
	// evidence of pinning rather than of an oversized pool.
	if got := c.next(digest.Challenge{Realm: "callee0.example", Nonce: "N-c0"}, false); got != 1 {
		t.Fatalf("the oldest pooled destination's nc = %d, want 1 (it was evicted from the pool)", got)
	}
}

// TestNonceCounterInvitePoolEvictsItsOwnLeastRecentlyUsed pins the BOUND, now
// scoped to the INVITE pool. The pool is fixed-size and value-typed, so a peer
// minting nonces allocates nothing — which is why this is not the unbounded map
// design §6 rejected. Eviction degrades a forgotten realm to nc=1, i.e. to the
// pre-P4-D06 behaviour, never to something worse. The registrar slot is not part
// of this pool and is deliberately not exercised here.
func TestNonceCounterInvitePoolEvictsItsOwnLeastRecentlyUsed(t *testing.T) {
	var c nonceCounter
	ch := func(i int) digest.Challenge {
		return digest.Challenge{Realm: fmt.Sprintf("r%d", i), Nonce: fmt.Sprintf("n%d", i)}
	}
	// Fill every pool slot. Most-recently-used first, so the order is now 2,1,0.
	for i := 0; i < nonceInvitePoolSlots; i++ {
		if got := c.next(ch(i), false); got != 1 {
			t.Fatalf("pooled slot %d's first nc = %d, want 1", i, got)
		}
	}
	// Touch the OLDEST so it becomes the newest: order 0,2,1.
	if got := c.next(ch(0), false); got != 2 {
		t.Fatalf("nc for a still-resident pooled slot = %d, want 2", got)
	}
	// One more distinct challenge evicts the least recently used, now slot 1's.
	if got := c.next(ch(nonceInvitePoolSlots), false); got != 1 {
		t.Fatalf("a fresh challenge's nc = %d, want 1", got)
	}
	if got := c.next(ch(1), false); got != 1 {
		t.Fatalf("nc for the EVICTED pooled slot = %d, want 1 (it was replaced)", got)
	}
	if got := c.next(ch(0), false); got != 3 {
		t.Fatalf("nc for the pooled slot kept alive by being touched = %d, want 3", got)
	}
}

// TestNonceCounterRegisterLegAdoptsAPooledSlot pins the migration path (design
// §13 Amendment 2).
//
// THE FAILURE IT PREVENTS. The pool can legitimately hold the identity that
// later becomes the registrar's: one proxy serving both roles rotates its nonce,
// an outbound INVITE draws the NEW nonce first and pools it, and the next
// register refresh then presents that same nonce. Counting it in the pool is
// monotonic exactly ONCE — after that the registrar's live identity sits in an
// evictable slot and call traffic can push it out, which is this amendment's own
// defect one indirection away. So a REGISTER hit on a pooled slot must carry the
// count into the PINNED slot, not just increment in place.
func TestNonceCounterRegisterLegAdoptsAPooledSlot(t *testing.T) {
	var c nonceCounter
	shared := digest.Challenge{Realm: "proxy.example", Nonce: "N-rotated"}

	// The INVITE leg sees the rotated nonce first, so it lands in the pool.
	if got := c.next(shared, false); got != 1 {
		t.Fatalf("INVITE leg's first nc on the rotated nonce = %d, want 1", got)
	}
	// The register refresh presents the SAME nonce: continue the count.
	if got := c.next(shared, true); got != 2 {
		t.Fatalf("REGISTER leg's nc on a pooled identity = %d, want 2 — it must CONTINUE that "+
			"identity's count, not restart it", got)
	}
	// And it is pinned from now on, so call traffic cannot evict it.
	for i := 0; i < 5; i++ {
		ch := digest.Challenge{Realm: fmt.Sprintf("callee%d.example", i), Nonce: fmt.Sprintf("N-c%d", i)}
		if got := c.next(ch, false); got != 1 {
			t.Fatalf("INVITE destination %d's first nc = %d, want 1", i, got)
		}
	}
	if got := c.next(shared, true); got != 3 {
		t.Fatalf("adopted identity's nc after 5 INVITE-originated challenges = %d, want 3 — the "+
			"REGISTER leg's pool hit must MIGRATE the slot into the pinned one, not leave it in "+
			"the evictable pool", got)
	}
}

// TestApplyDigestRejectsANonMD5AlgorithmInsteadOfMislabellingAnMD5Hash is the
// Rule 4 Cycle B third-round finding, pinned (design §13 Amendment 3).
//
// THE FAILURE IT PREVENTS. internal/sipengine/digest computes MD5 and only MD5,
// but it never validates the algorithm it was handed: ParseChallenge copies the
// challenge's algorithm token through unchecked (digest.go:54) and
// ComputeAuthorization stamps that token onto the response verbatim (:109),
// which HeaderValue then writes onto the wire (:119). So a SHA-256 challenge,
// unguarded, produces an MD5 digest LABELLED algorithm=SHA-256 — not a FAILED
// authentication but a silently WRONG one. The peer rejects it and the operator
// reads the rejection as bad credentials.
//
// WHY THIS MATTERS NOW AND NOT BEFORE. P4-D06 repoints the challenged INVITE off
// sipgo.DoDigestAuth, whose engine (github.com/icholy/digest) DOES support
// SHA-256/512/512-256 and returns a loud error on anything else. Without this
// guard the repoint is a silent capability regression on a security-relevant
// surface, which §1's charter forbids. THE GUARD DOES NOT RESTORE SHA-256 — it
// makes its absence loud and diagnosable.
func TestApplyDigestRejectsANonMD5AlgorithmInsteadOfMislabellingAnMD5Hash(t *testing.T) {
	// applyDigest reads only u.cfg and u.nonceCounter, so a zero-valued UA with
	// credentials is a sufficient and honest fixture — no transport, no client.
	u := &UA{cfg: Config{AuthUser: "alice", AuthPass: "s3cr3t"}}

	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "bob", Host: "proxy.example"})
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})

	res := sip.NewResponse(401, "Unauthorized")
	res.AppendHeader(sip.NewHeader("WWW-Authenticate",
		`Digest realm="proxy.example", nonce="N-1", qop="auth", algorithm=SHA-256`))

	_, err := u.applyDigest(req, res, false)
	if err == nil {
		got := "<none>"
		if h := req.GetHeader("Authorization"); h != nil {
			got = h.Value()
		}
		t.Fatalf("applyDigest ACCEPTED a SHA-256 challenge and emitted Authorization=%s — an MD5 "+
			"digest under a SHA-256 label. It must refuse instead.", got)
	}
	if !strings.Contains(err.Error(), "unsupported digest algorithm") {
		t.Fatalf("applyDigest error = %v, want it to say the algorithm is unsupported", err)
	}
	if !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("applyDigest error = %v, want it to QUOTE the offending token so an operator can "+
			"tell this apart from a credentials problem", err)
	}
	// AND IT PUT NOTHING ON THE WIRE. The whole point is that no MD5 digest is
	// emitted under a label it does not match, so req comes back unmutated.
	if h := req.GetHeader("Authorization"); h != nil {
		t.Fatalf("applyDigest added Authorization=%q on a REFUSED challenge; it must not compute a "+
			"digest it cannot label correctly", h.Value())
	}
	if cseq := req.CSeq(); cseq.SeqNo != 1 {
		t.Fatalf("applyDigest bumped CSeq to %d on a refused challenge, want it left at 1", cseq.SeqNo)
	}
	// AND IT DID NOT CONSUME A NONCE-COUNT, which is why the guard must precede
	// next(): a peer challenging with SHA-256 on every attempt would otherwise
	// burn this UA's count for that (realm, nonce) without ever authenticating.
	if got := u.nonceCounter.next(digest.Challenge{Realm: "proxy.example", Nonce: "N-1"}, false); got != 1 {
		t.Fatalf("after a REFUSED challenge, next() = %d, want 1 — the guard must run BEFORE the "+
			"counter reserves, or a hostile peer burns the count for this (realm, nonce)", got)
	}
}

// TestApplyDigestStripsAStaleCredentialFromTheOtherChallengeFamily pins Rule 4
// Cycle B finding 1: A REQUEST MUST NEVER CARRY TWO CREDENTIAL HEADERS FROM TWO
// DIFFERENT CHALLENGE ATTEMPTS.
//
// THE CONCRETE BUG, and why P4-D07 is what surfaced it. applyDigest used to
// remove only the header matching THIS response's status code — "Authorization"
// for a 401, "Proxy-Authorization" for a 407 — which was harmless while the only
// credential on a request was one applyDigest had put there itself. P4-D07 breaks
// that assumption: presentCachedChallenge stamps a preemptive credential under
// whichever header name the CACHED challenge used. If the registrar then
// challenges with the OTHER status code — a 401-cached credential meeting a
// proxy that answers 407 this cycle, or the reverse behind a load balancer whose
// members disagree — the stale header is not the one removed, and it rides along
// on the retry beside the fresh credential. Two credentials, one of them for a
// spent nonce, presented to a peer that will read the pair as a replay or a
// malformed authentication.
//
// THE FIX IS AT THE SOURCE, not at the preemptive stamp: applyDigest removes BOTH
// names before appending. That makes the invariant a property of the function
// that writes credentials rather than a rule every future caller has to remember.
func TestApplyDigestStripsAStaleCredentialFromTheOtherChallengeFamily(t *testing.T) {
	// applyDigest reads only u.cfg and u.nonceCounter, so a zero-valued UA with
	// credentials is a sufficient and honest fixture — no transport, no client.
	u := &UA{cfg: Config{AuthUser: "alice", AuthPass: "s3cr3t"}}

	req := sip.NewRequest(sip.REGISTER, sip.Uri{User: "alice", Host: "registrar.example"})
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 7, MethodName: sip.REGISTER})
	// The stale preemptive stamp: a credential presented under the header name the
	// CACHED challenge used, i.e. a 401 the registrar issued on some earlier cycle.
	req.AppendHeader(sip.NewHeader("Authorization",
		`Digest username="alice", realm="registrar.example", nonce="SPENT", `+
			`uri="sip:registrar.example", response="0123456789abcdef0123456789abcdef", nc=00000001`))

	// THIS cycle the registrar challenges with the OTHER family.
	res := sip.NewResponse(407, "Proxy Authentication Required")
	res.AppendHeader(sip.NewHeader("Proxy-Authenticate",
		`Digest realm="registrar.example", nonce="FRESH", algorithm=MD5, qop="auth"`))

	_, err := u.applyDigest(req, res, true)
	if err != nil {
		t.Fatalf("applyDigest on a 407 with a stale Authorization present: %v", err)
	}

	if h := req.GetHeader("Authorization"); h != nil {
		t.Fatalf("the retry still carries the STALE Authorization=%q alongside its fresh "+
			"Proxy-Authorization. applyDigest must remove BOTH credential header names before "+
			"appending, not only the one matching this response's status code — otherwise a "+
			"preemptive credential cached under one challenge family leaks onto a retry answering "+
			"the other (Rule 4 Cycle B finding 1).", h.Value())
	}
	if got := req.GetHeaders("Proxy-Authorization"); len(got) != 1 {
		t.Fatalf("req carries %d Proxy-Authorization headers, want exactly 1 — one challenge, "+
			"one credential", len(got))
	}
	if v := req.GetHeader("Proxy-Authorization").Value(); !strings.Contains(v, `nonce="FRESH"`) {
		t.Fatalf("Proxy-Authorization=%q want the credential computed against the FRESH nonce", v)
	}

	// AND THE SYMMETRIC DIRECTION, because the fix must not simply hardcode the
	// other name: a stale Proxy-Authorization must not survive a 401 either.
	req2 := sip.NewRequest(sip.REGISTER, sip.Uri{User: "alice", Host: "registrar.example"})
	req2.AppendHeader(&sip.CSeqHeader{SeqNo: 9, MethodName: sip.REGISTER})
	req2.AppendHeader(sip.NewHeader("Proxy-Authorization",
		`Digest username="alice", realm="registrar.example", nonce="SPENT", `+
			`uri="sip:registrar.example", response="0123456789abcdef0123456789abcdef", nc=00000001`))
	res2 := sip.NewResponse(401, "Unauthorized")
	res2.AppendHeader(sip.NewHeader("WWW-Authenticate",
		`Digest realm="registrar.example", nonce="FRESH2", algorithm=MD5, qop="auth"`))

	if _, err := u.applyDigest(req2, res2, true); err != nil {
		t.Fatalf("applyDigest on a 401 with a stale Proxy-Authorization present: %v", err)
	}
	if h := req2.GetHeader("Proxy-Authorization"); h != nil {
		t.Fatalf("the retry still carries the STALE Proxy-Authorization=%q alongside its fresh "+
			"Authorization; the strip must cover both names in both directions", h.Value())
	}
}
