package sipua_test

// P4-D07: a registration refresh is ONE REGISTER on the wire, not two.
//
// Before this change every REGISTER — initial, refresh, de-registration alike —
// went out unauthenticated, drew a 401, and was re-sent with an Authorization
// header. That was a deliberate ambient contract W1 preserved and W2 re-confirmed
// (P4-D07). It is closed here by caching the challenge
// in regState and presenting a credential on the FIRST REGISTER of every later
// cycle (RFC 3261 §22.1).
//
// THE DISCRIMINATOR IS DISTINCT CSeq VALUES, NOT A RAW MESSAGE COUNT. Every
// REGISTER attempt carries its own CSeq (sipgo bumps once on the options-less
// first dispatch, applyDigest bumps again for a digest retry), while a UDP
// RETRANSMIT is a byte-identical resend that reuses its CSeq — so counting
// distinct values is exact and immune to the 4-CPU retransmit flakiness this
// suite has a documented history of. uniqueSorted is this package's existing
// helper (register_refresh_test.go).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestRegisterRefreshPresentsTheCachedChallengePreemptively is P4-D07's
// acceptance criterion: one initial exchange of two, then three refreshes of one
// each.
func TestRegisterRefreshPresentsTheCachedChallengePreemptively(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newRegisterUAExpires(t, p, clk, 60)

	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// The FIRST-EVER registration still costs two messages: nothing is cached
	// until the registrar has challenged us once. This half must NOT change, or
	// the UA would be guessing at a challenge it has never seen.
	if n := len(uniqueSorted(p.CSeqs("REGISTER"))); n != 2 {
		t.Fatalf("initial registration = %d distinct REGISTER CSeqs (%v), want 2 "+
			"(the unauthenticated attempt and its authenticated retry)", n, p.CSeqs("REGISTER"))
	}

	for i := 0; i < 3; i++ {
		clk.BlockUntil(1)
		clk.Advance(60 * time.Second)
		// A tolerant barrier: >= is satisfied by a broken build too, so this only
		// drives the loop forward. The exact assertion is after it.
		waitForCond(t, func() bool { return len(uniqueSorted(p.CSeqs("REGISTER"))) >= 3+i })
	}
	// A real chance for a second, unwanted REGISTER of the last cycle to arrive
	// before the exact count is taken.
	time.Sleep(150 * time.Millisecond)

	if got := len(uniqueSorted(p.CSeqs("REGISTER"))); got != 5 {
		t.Fatalf("registrar saw %d distinct REGISTER CSeqs (%v), want 5 — two for the initial "+
			"registration plus exactly ONE per refresh cycle. 8 means the cached challenge is not "+
			"being presented and every refresh is still paying for a 401 round trip (P4-D07)",
			got, p.CSeqs("REGISTER"))
	}

	// NON-VACUITY. A build that simply stopped authenticating would also produce
	// one REGISTER per cycle — and would not stay registered.
	if got := p.LastRequestHeader("REGISTER", "Authorization"); !strings.Contains(got, "Digest ") {
		t.Fatalf("the last REGISTER's Authorization=%q want a Digest credential — the single "+
			"REGISTER per refresh must be the AUTHENTICATED one, not an unanswered attempt", got)
	}
	if !ua.Registered() {
		t.Fatal("the UA is not registered after three preemptively-authenticated refreshes")
	}
	// REGRESSION GUARD on the shared counter (P4-D06), which this task does not
	// touch: four credentials go out across the run (the initial retry plus three
	// refreshes) against this peer's single nonce, so nc climbs 1,2,3,4. The
	// preemptive credential must consume from the same counter the retry did.
	if got := p.MaxNonceCount(); got != 4 {
		t.Fatalf("max nonce-count=%d want 4 (1,2,3,4 across the four credentialled REGISTERs)", got)
	}
}

// TestRegisterRefreshFallsBackWhenTheRegistrarRotatesItsNonce is the SAFETY half
// of P4-D07, and it is the property that keeps the optimisation from being a
// liability: a registrar that issues single-use nonces rejects every cached
// challenge, and the UA must fall back to the ordinary challenge-then-retry flow
// — TWO REGISTERs, never three, never a loop — re-cache the NEW challenge, and
// stay registered.
//
// Behaviour.OneTimeRegisterNonce is the only registrar shape in which a cached
// challenge is ever rejected, which is why the peer double gained it.
func TestRegisterRefreshFallsBackWhenTheRegistrarRotatesItsNonce(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
		Behaviour: peer.Behaviour{OneTimeRegisterNonce: true},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newRegisterUAExpires(t, p, clk, 60)

	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !ua.Registered() {
		t.Fatal("precondition: the initial REGISTER must succeed against the one-time-nonce registrar")
	}

	for i := 0; i < 2; i++ {
		clk.BlockUntil(1)
		clk.Advance(60 * time.Second)
		waitForCond(t, func() bool { return len(uniqueSorted(p.CSeqs("REGISTER"))) >= 4+2*i })
	}
	time.Sleep(150 * time.Millisecond)

	// 2 (initial) + 2 per rotated-nonce refresh. THREE per cycle would mean the
	// fallback retried its own rejected retry; more would mean a loop.
	if got := len(uniqueSorted(p.CSeqs("REGISTER"))); got != 6 {
		t.Fatalf("registrar saw %d distinct REGISTER CSeqs (%v), want exactly 6 — a rejected "+
			"cached challenge must cost ONE extra round trip per cycle (the pre-P4-D07 shape), "+
			"never more: doRequestWithDigest answers a challenge exactly once", got, p.CSeqs("REGISTER"))
	}
	if !ua.Registered() {
		t.Fatal("the UA fell out of registration against a registrar that rotates its nonce — the " +
			"fallback must re-cache the NEW challenge and keep the binding alive")
	}
}

// TestARejectedRegisterExchangeDoesNotPublishItsChallenge pins Rule 4 Cycle B
// finding 2: the cache holds the CURRENT ACCEPTED registrar challenge, never
// merely "whatever the last exchange answered".
//
// THE BUG IT CATCHES. doRequestWithDigest answers a challenge EXACTLY ONCE, so
// an exchange whose FINAL response is itself another 401 still returns the
// challenge it answered — the credential was computed and sent, the registrar
// simply refused it. Caching that publishes a challenge the far end has already
// rejected, and the NEXT REGISTER then presents a credential for it
// preemptively: the UA pays the 401 round trip it was trying to save AND burns a
// nonce-count on the refusal, every single cycle. The gate is therefore the same
// success predicate Register uses for RegisterResult.Registered.
//
// HOW IT IS OBSERVED. The peer is configured with a password the UA does not
// have, so authOK fails forever and every exchange ends 401. Two Register calls
// then cost four REGISTERs either way — the message count CANNOT tell the two
// builds apart — but the number of CREDENTIALS differs and the peer records the
// highest nc it has seen on any Authorization header (record(), peer_serve.go):
//
//	correct: unauth, nc=1 | unauth, nc=2            -> MaxNonceCount 2
//	buggy:   unauth, nc=1 | nc=2 (preemptive), nc=3 -> MaxNonceCount 3
//
// The clock is never advanced here: the UA never registers, so no refresher is
// ever armed and there is nothing to drive.
func TestARejectedRegisterExchangeDoesNotPublishItsChallenge(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice",
		// DELIBERATELY NOT the UA's password (newRegisterUAExpires sends
		// "s3cr3t"), so every credential this UA computes is refused and every
		// exchange's FINAL response is a 401.
		AuthPass: "not-the-password-the-ua-holds", RegisterExpires: 60,
	})
	ua, _ := newRegisterUAExpires(t, p, fakeclock.New(time.Unix(0, 0)), 60)

	for i := 1; i <= 2; i++ {
		res, err := ua.Register(context.Background())
		if err != nil {
			t.Fatalf("Register #%d: %v — a rejected registration is a RESULT, not an error (§11.1)", i, err)
		}
		if res.Registered || res.Code != 401 {
			t.Fatalf("Register #%d => registered=%v code=%d, want false/401 (precondition: this "+
				"registrar refuses every credential)", i, res.Registered, res.Code)
		}
	}

	// SANITY GUARD, NOT THE DISCRIMINATOR: both the correct and the buggy build
	// send four REGISTERs. Anything else means the fallback looped.
	if got := len(uniqueSorted(p.CSeqs("REGISTER"))); got != 4 {
		t.Fatalf("registrar saw %d distinct REGISTER CSeqs (%v), want 4 — two exchanges of "+
			"challenge-then-refused-retry", got, p.CSeqs("REGISTER"))
	}

	if got := p.MaxNonceCount(); got != 2 {
		t.Fatalf("the registrar saw nc up to %d across two REJECTED exchanges, want 2 — one "+
			"credential per exchange. 3 means the FIRST exchange's challenge was cached even "+
			"though the registrar refused the credential answering it, so the second exchange "+
			"opened with a preemptive credential for an identity already known to be rejected "+
			"(Rule 4 Cycle B finding 2). rememberChallenge must be reached only when the "+
			"exchange itself ended 200.", got)
	}
}

// TestRegisterRefreshRecoversFromADefinitiveCredentialRejection pins Rule 13
// Cycle 3 finding I1: the cache P4-D07 warms on a 200 has NO invalidation path
// before this fix — sendRegister only ever WRITES reg.challenge, nothing ever
// CLEARS it. A registrar that answers the cached, preemptively-presented
// credential with a FINAL response that is neither an acceptance (200) nor a
// challenge (401/407) — 403 is the realistic example, e.g. an SBC/Kamailio
// nonce-replay guard — left every LATER refresh presenting that same dead
// credential forever: a permanent registration wedge that could not happen
// pre-P4-D07 (every REGISTER used to always draw a fresh challenge).
//
// THE DOUBLE. peer.Behaviour.RejectRegisterCredentialAfterNAccepted: 1 makes
// the registrar accept the FIRST credentialed REGISTER (warming the cache) and
// then answer 403 to every LATER REGISTER that carries ANY Authorization
// header — valid or not — while still answering an UNCREDENTIALED REGISTER
// with the ordinary 401 challenge. That last clause is what makes recovery
// observable at all.
//
// THE DISCRIMINATOR IS A DISTINCT-CSeq COUNT, NOT A HEADER SNAPSHOT, and this
// is deliberate rather than a shortcut. peer_serve.go's record() collapses
// LastRequestHeader to "the value the last time this header was PRESENT" (its
// own doc comment, F-M8 limit 1) — it does NOT clear the entry when a later
// message of the same method omits the header. Since doRequestWithDigest
// answers a fresh 401 by resending WITH a credential inside the very same
// exchange, the LAST REGISTER of any exchange that recovers still carries an
// Authorization header; checking for its ABSENCE after the fact would prove
// nothing. Counting distinct CSeqs the registrar saw does not have this blind
// spot: a self-answered challenge burns a CSeq the dead-cached retry never
// would.
//
// WHY "ROUND 2" IS A RETRY BACKOFF, NOT THE NEXT SCHEDULED INTERVAL. Rejecting
// the refresh's REGISTER makes refreshRegister return an error, and
// startRegisterRefresher's policy (backoff{Attempts: 3, Base: 2 * time.Second})
// retries within the SAME attempt loop before the next ordinary interval is
// ever scheduled (refresher.go's attempt) — so the second BlockUntil(1) below
// synchronises with THAT retry's backoff timer, still driven by the same fake
// clock. Only two rounds are driven, deliberately: a broken build needs a
// THIRD attempt to reach the same CSeq count a fixed build reaches after the
// second (see the exact arithmetic in the final assertion), so stopping at two
// keeps the counts from ever colliding.
func TestRegisterRefreshRecoversFromADefinitiveCredentialRejection(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
		Behaviour: peer.Behaviour{RejectRegisterCredentialAfterNAccepted: 1},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newRegisterUAExpires(t, p, clk, 60)

	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !ua.Registered() {
		t.Fatal("precondition: the initial REGISTER must succeed (this peer accepts the first " +
			"credentialed REGISTER unconditionally) and warm the cache")
	}
	if n := len(uniqueSorted(p.CSeqs("REGISTER"))); n != 2 {
		t.Fatalf("initial registration = %d distinct REGISTER CSeqs (%v), want 2 "+
			"(the unauthenticated attempt and its authenticated retry)", n, p.CSeqs("REGISTER"))
	}

	// ROUND 1: the refresher's scheduled REGISTER presents the cache warmed
	// above preemptively (P4-D07) — the registrar has already accepted one
	// credentialed REGISTER, so this one draws 403.
	clk.BlockUntil(1)
	clk.Advance(60 * time.Second)
	waitForCond(t, func() bool { return len(uniqueSorted(p.CSeqs("REGISTER"))) >= 3 })
	time.Sleep(150 * time.Millisecond) // a real chance for an unwanted extra message to arrive
	if got := len(uniqueSorted(p.CSeqs("REGISTER"))); got != 3 {
		t.Fatalf("after round 1, registrar saw %d distinct REGISTER CSeqs (%v), want 3 — the "+
			"refresh's ONE REGISTER, carrying the preemptively-cached credential, drawing the "+
			"peer's 403", got, p.CSeqs("REGISTER"))
	}
	if got := p.LastRequestHeader("REGISTER", "Authorization"); !strings.Contains(got, "Digest ") {
		t.Fatalf("round 1's REGISTER Authorization=%q, want a Digest credential — precondition: "+
			"this must be the PREEMPTIVE, CACHED credential being presented and rejected, not an "+
			"unauthenticated attempt", got)
	}
	// The retry budget is not exhausted (attempt 1 of 3): OnGiveUp has not run,
	// and refreshRegister's own rejection branch does not touch reg.registered
	// (read, not assumed — see refreshRegister/registrationRemoved). The stale
	// "still registered" reading is therefore the ACCURATE one at this point,
	// not a gap this fix is expected to close.
	if !ua.Registered() {
		t.Fatal("after round 1, ua.Registered() = false, want true — the retry budget has not " +
			"been exhausted yet (attempt 1 of 3), so reg.registered must still hold its last " +
			"confirmed value")
	}

	// ROUND 2: the SAME attempt loop's retry, after its Base backoff.
	clk.BlockUntil(1)
	clk.Advance(5 * time.Second)
	waitForCond(t, func() bool { return len(uniqueSorted(p.CSeqs("REGISTER"))) >= 4 })
	time.Sleep(150 * time.Millisecond) // let a recovering build's digest retry land too
	got := len(uniqueSorted(p.CSeqs("REGISTER")))
	if got != 5 {
		t.Fatalf("after round 2, registrar saw %d distinct REGISTER CSeqs (%v), want 5 — 2 for "+
			"the initial registration, 1 for round 1's rejected cached credential, and 2 for "+
			"round 2 (an UNAUTHENTICATED REGISTER drawing a fresh 401, then its authenticated "+
			"retry drawing 403 in turn). 4 means the cache was never cleared after round 1's "+
			"403, so round 2 presented the SAME dead credential again with no unauthenticated "+
			"REGISTER in between — sendRegister.forgetChallenge (Rule 13 Cycle 3 finding I1) is "+
			"missing or not being reached", got, p.CSeqs("REGISTER"))
	}
	// Same reasoning as round 1: attempt 2 of 3, OnGiveUp still has not run.
	if !ua.Registered() {
		t.Fatal("after round 2, ua.Registered() = false, want true — the retry budget has not " +
			"been exhausted yet (attempt 2 of 3)")
	}
}
