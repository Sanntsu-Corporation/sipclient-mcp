package sipua_test

import (
	"context"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/netfault"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

func TestRegisterRefreshesBetween50And90PercentOfTheGrantedExpiry(t *testing.T) {
	// Granted 60s => the refresh must land between 30s and 54s.
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newRegisterUAExpires(t, p, clk, 60)
	events := collect(t, ua)

	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if n := p.Count("REGISTER"); n != 2 {
		t.Fatalf("initial REGISTER exchange = %d messages want 2 (401 then 200)", n)
	}

	clk.BlockUntil(1)
	clk.Advance(29 * time.Second)
	if n := p.Count("REGISTER"); n != 2 {
		t.Fatal("refreshed before 50% of the granted expiry")
	}
	clk.Advance(26 * time.Second) // now at 55s > 54s, so it must have fired
	waitForCond(t, func() bool { return p.Count("REGISTER") > 2 })

	ev := waitFor(t, events, session.UAEventRefresh, 0)
	if ev.ExpiresS != 60 {
		t.Fatalf("UAEventRefresh.ExpiresS=%d want the newly GRANTED 60", ev.ExpiresS)
	}
}

// TestRegisterRefreshArmsAgainstTheContactExpiresParameter is the call site
// that made the Expires-header-only read a PERMANENT defect rather than a
// one-off: refreshRegister re-derives the granted expiry every cycle, so a
// value read from the wrong place is re-applied forever instead of
// self-correcting.
//
// The registrar here grants ONLY through the Contact `expires` parameter (RFC
// 3261 §10.2.4's required form) and sends no Expires header at all — the shape
// of a real registrar, and the one the peer double could not previously
// produce. Requested 300, granted 60: reading the header alone yields 300, arms
// the refresh at 0.85*300 = 255s, and the binding lapses at 60s with NOTHING
// failing — no OnGiveUp, no UAEventRegisterFailed, and ua_status still
// reporting 300. Both assertions below are load-bearing: the timing one proves
// the initial arm, the event one proves the refresh re-derived it correctly.
func TestRegisterRefreshArmsAgainstTheContactExpiresParameter(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t",
		Behaviour: peer.Behaviour{OmitRegisterExpires: true, RegisterContactExpires: "60"},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newRegisterUAExpires(t, p, clk, 300)
	events := collect(t, ua)

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if res.ExpiresS != 60 {
		t.Fatalf("granted expires_s=%d want the Contact parameter's 60, not the requested 300", res.ExpiresS)
	}
	if n := p.Count("REGISTER"); n != 2 {
		t.Fatalf("initial REGISTER exchange = %d messages want 2 (401 then 200)", n)
	}

	// Granted 60 => the refresh is due between 30s and 54s. Against the
	// requested 300 it would be due at ~255s and nothing would fire here.
	clk.BlockUntil(1)
	clk.Advance(29 * time.Second)
	if n := p.Count("REGISTER"); n != 2 {
		t.Fatal("refreshed before 50% of the granted expiry")
	}
	clk.Advance(26 * time.Second) // 55s > 54s: it must have fired
	waitForCond(t, func() bool { return p.Count("REGISTER") > 2 })

	ev := waitFor(t, events, session.UAEventRefresh, 0)
	if ev.ExpiresS != 60 {
		t.Fatalf("UAEventRefresh.ExpiresS=%d want 60 — refreshRegister must re-read the "+
			"Contact `expires` parameter too, or every cycle re-applies the wrong interval", ev.ExpiresS)
	}
}

func TestRegisterRefreshKeepsCSeqMonotonicAndBumpsNonceCount(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newRegisterUAExpires(t, p, clk, 60)
	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Three refresh cycles (R10). Each is ONE REGISTER from here on: P4-D07's
	// preemptive auth presents the challenge cached from the initial exchange on
	// the refresh's FIRST attempt, so only that initial registration (two
	// messages) ever pays for a 401 round trip. The barrier was `2 + 2*(i+1)`
	// while every refresh drew its own challenge.
	for i := 0; i < 3; i++ {
		clk.BlockUntil(1)
		clk.Advance(60 * time.Second)
		want := 2 + (i + 1)
		waitForCond(t, func() bool { return p.Count("REGISTER") >= want })
	}
	if !p.CSeqMonotonic("REGISTER") {
		t.Fatalf("REGISTER CSeqs are not monotonic: %v", p.CSeqs("REGISTER"))
	}
	// P4-D07, POSITIVELY ASSERTED rather than merely no longer contradicted: two
	// distinct CSeqs for the initial registration plus exactly ONE per refresh.
	// A build without preemptive auth produces 8 and fails here. DISTINCT values
	// rather than a raw count, because a UDP retransmit is a byte-identical
	// resend that reuses its CSeq and would make an exact count flaky on this
	// 4-CPU sandbox.
	if got := len(uniqueSorted(p.CSeqs("REGISTER"))); got != 5 {
		t.Fatalf("registrar saw %d distinct REGISTER CSeqs (%v), want 5 — the initial "+
			"registration's two attempts plus ONE per refresh cycle (P4-D07)",
			got, p.CSeqs("REGISTER"))
	}
	// Phase 4 W1 M3 (Inputs §1) closed the limitation this test used to
	// assert around: digestauth.go's nonceCounter tracks RFC 7616 §3.4.3's
	// nonce-count for real now, in place of the vendored
	// siptest.(*Client).DoRequestWithDigest's hardcoded nc=1
	// (internal/sipengine/siptest/uac.go, no longer called from this
	// package's REGISTER path). Against this peer's never-rotating nonce, nc
	// climbs one per CREDENTIAL SENT — which P4-D07 did not change, only the
	// number of UNCREDENTIALLED attempts alongside them: 1 (the initial
	// registration's authenticated retry), then 2, 3, 4 (the three refreshes,
	// each now carrying its credential on its first and only attempt).
	if nc := p.MaxNonceCount(); nc != 4 {
		t.Fatalf("max nonce-count=%d want 4 (one nonce across 4 credentialled REGISTERs: 1,2,3,4)", nc)
	}
}

// TestRegisterRefreshNonceCountStrictlyMonotonicUnderPeerEnforcement is
// Inputs §1's acceptance criterion 1: against a peer that REJECTS a replayed
// nonce-count (RFC 7616 §3.4.3, peer.Behaviour.EnforceNonceCountMonotonic),
// three refresh cycles must still succeed — proving the tracked nc is not
// merely OBSERVED to climb (the test above) but is actually what keeps the
// registration alive against a registrar that would reject a repeat.
func TestRegisterRefreshNonceCountStrictlyMonotonicUnderPeerEnforcement(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
		Behaviour: peer.Behaviour{EnforceNonceCountMonotonic: true},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newRegisterUAExpires(t, p, clk, 60)

	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !ua.Registered() {
		t.Fatal("precondition: the initial REGISTER must succeed against the monotonicity-enforcing peer")
	}

	// ONE REGISTER per refresh (P4-D07): the cached challenge goes out on the
	// refresh's first attempt. The nonce-count assertion below is unchanged and
	// is the point of this test — the same four credentials still climb 1,2,3,4
	// against a peer that REJECTS a replayed nc, they are simply no longer
	// preceded by four wasted unauthenticated attempts.
	for i := 0; i < 3; i++ {
		clk.BlockUntil(1)
		clk.Advance(60 * time.Second)
		want := 2 + (i + 1)
		waitForCond(t, func() bool { return p.Count("REGISTER") >= want })
	}

	// The registration must have SURVIVED all three refresh cycles: a peer
	// that rejected a replayed nc as unauthenticated would leave the binding
	// unrenewed, and this would be false.
	if !ua.Registered() {
		t.Fatal("the UA fell out of registration under nonce-count enforcement — a replayed " +
			"nc was rejected as unauthenticated")
	}
	if got := p.MaxNonceCount(); got != 4 {
		t.Fatalf("max nonce-count=%d want 4 (one nonce across 4 REGISTERs: 1,2,3,4)", got)
	}
}

// TestRegisterRefreshAndUnregisterReuseOneStableCallID is the OTHER half of the
// R10 stable registration identity, and it was pinned by nothing.
//
// RFC 3261 §10.2 requires every REGISTER of one registration to share a SINGLE
// Call-ID with a strictly increasing CSeq. applyRegisterIdentity (register.go)
// exists to enforce that over siptest.BuildRegister, which is vendored and mints
// a FRESH random Call-ID on every call. Only the CSeq half was covered
// (TestRegisterRefreshKeepsCSeqMonotonicAndBumpsNonceCount): deleting
// applyRegisterIdentity's Call-ID branch entirely — restoring the exact
// pre-fix, one-registration-per-refresh wire behaviour — left the whole
// package green. Against a real registrar a per-refresh Call-ID makes every
// refresh look like a brand-new registration; Kamailio-class registrars
// accumulate bindings or reject on Call-ID/CSeq ordering.
//
// UNREGISTER IS ASSERTED TOO, not for symmetry: Unregister's Expires: 0 goes
// through the SAME buildRegister path, and a de-registration carrying a
// different Call-ID from the binding it is trying to remove removes nothing.
func TestRegisterRefreshAndUnregisterReuseOneStableCallID(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newRegisterUAExpires(t, p, clk, 60)
	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Three refresh cycles, ONE REGISTER each (P4-D07: the cached challenge is
	// presented preemptively, so only the initial registration draws a 401).
	for i := 0; i < 3; i++ {
		clk.BlockUntil(1)
		clk.Advance(60 * time.Second)
		want := 2 + (i + 1)
		waitForCond(t, func() bool { return p.Count("REGISTER") >= want })
	}
	if err := ua.Unregister(context.Background()); err != nil {
		t.Fatalf("Unregister: %v", err)
	}

	ids := p.CallIDs("REGISTER")
	// 2 (initial exchange — the only one that draws a 401) + 3 (one per refresh)
	// + 1 (the Expires: 0 de-registration, which also presents the cached
	// challenge preemptively) = 6, down from 10 before P4-D07. Asserted as a
	// FLOOR so a retransmission cannot fail the test — a retransmit is a
	// byte-identical resend and carries the same Call-ID — but asserted at all so
	// "they were all identical" cannot pass on an empty or single-element slice.
	if len(ids) < 6 {
		t.Fatalf("registrar saw %d REGISTERs (%v), want at least 6 — "+
			"the initial two-message exchange, three one-message refresh cycles and the "+
			"de-registration", len(ids), ids)
	}
	for i, id := range ids {
		if id != ids[0] {
			t.Fatalf("REGISTER %d carried Call-ID %q, want the registration's single stable %q "+
				"(RFC 3261 §10.2) — all Call-IDs seen: %v\n"+
				"applyRegisterIdentity must REUSE the first Call-ID on every later REGISTER; "+
				"siptest.BuildRegister mints a fresh random one per call, so each refresh would "+
				"otherwise look like a brand-new registration to the far end",
				i, id, ids[0], ids)
		}
	}
}

func TestRegisterRefreshGiveUpEmitsRegisterFailedNotATransportFault(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newRegisterUAExpires(t, p, clk, 60)
	events := collect(t, ua)
	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatal(err)
	}

	p.Stop() // the registrar vanishes; every refresh attempt now fails
	clk.BlockUntil(1)
	clk.Advance(60 * time.Second) // due time
	// Three attempts at 2s/4s backoff, then give-up. Attempts:3 means only TWO
	// backoff waits between them, so a third BlockUntil(1) would block forever
	// on a refresher goroutine that has already returned after OnGiveUp fired.
	for i := 0; i < 2; i++ {
		clk.BlockUntil(1)
		clk.Advance(30 * time.Second)
	}

	ev := waitFor(t, events, session.UAEventRegisterFailed, 0)
	if ev.Err == nil {
		t.Fatal("UAEventRegisterFailed must carry the last refresh error")
	}
	// THE POINT OF THE KIND: a registration give-up must not be reported through
	// the UA-WIDE fault channel, whose session handler terminates every live call
	// on the UA.
	for _, other := range events() {
		if other.Kind == session.UAEventTransportFault {
			t.Fatal("a registration give-up must NOT emit UAEventTransportFault — " +
				"its handler terminates every live call on the UA")
		}
	}
}

// TestRegister423RetriesAtMinExpiresAndClampsTheRefresh covers RFC 3261
// §10.2.8, a hard registration failure THIS WAVE CREATED.
//
// Until Config.ExpiresS reached the wire every REGISTER carried the vendored
// builder's hardcoded Expires: 300, which essentially every registrar accepts.
// Now policy permits values down to 30, and a registrar whose Min-Expires is
// higher answers 423 Interval Too Brief to every one of them: Register reported
// Registered: false with no refresher armed, and refreshRegister burned all
// three retry attempts on identical too-short requests before OnGiveUp. Failure
// was total, on exactly the configuration (expires_s: 30..60) an operator sets
// to get faster NAT refresh.
//
// THREE THINGS ARE PINNED, and the third is the one a naive fix misses:
//
//  1. the retry goes out at the registrar's Min-Expires and registers;
//  2. it goes out ONCE — cc.Received(423) == 1. A registrar that 423s the value
//     it itself named is broken, and looping on it is how a shutdown hang ships;
//  3. the REFRESH sends the clamped value too. Retrying once without recording
//     the floor registers the UA and then dies at the first refresh, because
//     refreshRegister re-derives its requested expiry from scratch every cycle.
//     cc.Received(423) is what sees this: a refresh that re-sent the configured
//     30 would draw a SECOND 423 and only then recover.
//
// The 423-with-no-usable-Min-Expires case (keep today's behaviour: rejected, not
// an error) is TestRegisterRejectedIsNotAnError's "interval too brief" row —
// that peer sends no Min-Expires header, so it also proves this retry does not
// fire without one.
func TestRegister423RetriesAtMinExpiresAndClampsTheRefresh(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t",
		Behaviour: peer.Behaviour{Reject423MinExpires: 120},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, cc := newRegisterUAExpires(t, p, clk, 30)
	events := collect(t, ua)

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !res.Registered || res.Code != 200 {
		t.Fatalf("Register => registered=%v code=%d, want true/200 — a 423 naming a Min-Expires "+
			"must be retried at that value (RFC 3261 §10.2.8), not reported as a dead registration",
			res.Registered, res.Code)
	}
	if res.ExpiresS != 120 {
		t.Fatalf("granted expires_s=%d want the registrar's Min-Expires of 120", res.ExpiresS)
	}
	if got := p.LastRequestHeader("REGISTER", "Expires"); got != "120" {
		t.Fatalf("the retry's wire Expires=%q want \"120\"", got)
	}
	if n := cc.Received(423); n != 1 {
		t.Fatalf("UA received %d 423s registering, want exactly 1 — the retry is sent ONCE, "+
			"never in a loop", n)
	}

	afterInitial := p.Count("REGISTER")

	// The refresher must be armed against the GRANTED 120 (0.85*120 = 102s
	// +/-5%), not the requested 30 (0.85*30 = 25.5s).
	clk.BlockUntil(1)
	clk.Advance(60 * time.Second)
	time.Sleep(50 * time.Millisecond)
	if got := p.Count("REGISTER"); got != afterInitial {
		t.Fatalf("registrar saw %d REGISTERs at 60 fake seconds, want %d — the refresher was armed "+
			"against the REQUESTED 30, not the expiry the registrar actually granted", got, afterInitial)
	}

	clk.Advance(60 * time.Second) // 120s: past the whole 0.85*120 jitter band
	ev := waitFor(t, events, session.UAEventRefresh, 0)
	if ev.ExpiresS != 120 {
		t.Fatalf("UAEventRefresh.ExpiresS=%d want 120", ev.ExpiresS)
	}
	if n := cc.Received(423); n != 1 {
		t.Fatalf("UA received %d 423s in total, want 1 — the refresh must send the Min-Expires "+
			"floor the registrar already demanded, not the configured expires_s all over again; "+
			"otherwise every single refresh costs an extra rejected round trip and, once the "+
			"registrar stops naming Min-Expires, the registration dies", n)
	}
}

// TestRegister423RetriesOnceAndThenStops is the bound on the retry above. A
// registrar that answers 423 to the very interval it itself just named is
// broken, and retrying that in a loop is how a shutdown hang gets shipped — so
// the retry is sent EXACTLY ONCE and the second rejection is reported as the
// registration's outcome, like any other.
//
// The peer here names Min-Expires 120 for the too-short first attempt (the
// Reject423MinExpires gate) and then answers the compliant 120 retry with a bare
// 423 (RegisterStatus), which carries no Min-Expires and so gives the UA nothing
// new to retry at.
func TestRegister423RetriesOnceAndThenStops(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t",
		RegisterStatus: 423, RegisterReason: "Interval Too Brief",
		Behaviour: peer.Behaviour{Reject423MinExpires: 120},
	})
	ua, cc := newRegisterUAExpires(t, p, fakeclock.New(time.Unix(0, 0)), 30)

	type outcome struct {
		res session.RegisterResult
		err error
	}
	got := make(chan outcome, 1)
	go func() {
		res, err := ua.Register(context.Background())
		got <- outcome{res, err}
	}()

	var out outcome
	select {
	case out = <-got:
	case <-time.After(10 * time.Second):
		// Bounded here rather than left to the package test timeout, so a hang
		// is reported as this defect instead of as "the suite hung". It is a
		// backstop, not the loop proof: retryIntervalTooBrief also refuses to
		// re-send for a floor the request already meets, which terminates
		// independently for every registrar this peer can express. The only
		// shape that could loop is one that strictly RAISES its floor on each
		// 423, and that is bounded by the helper containing no recursion at all.
		t.Fatal("Register did not return within 10s against a registrar that 423s every " +
			"attempt — the §10.2.8 retry must be sent ONCE, never in a loop")
	}
	if out.err != nil {
		t.Fatalf("Register: %v — a rejected registration is a RESULT, not an error (§11.1)", out.err)
	}
	if out.res.Registered || out.res.Code != 423 {
		t.Fatalf("Register => registered=%v code=%d, want false/423", out.res.Registered, out.res.Code)
	}
	if n := cc.Received(423); n != 2 {
		t.Fatalf("UA received %d 423s, want exactly 2 — the original rejection and ONE retry", n)
	}
}

// TestRegisterRefresh423RetriesAtTheNewMinExpires is the refresh arm of
// §10.2.8, and it is the arm the review named as the worse one: refreshRegister
// used to return "REGISTER refresh was rejected: 423" and burn its whole
// three-attempt retry budget on identical too-short requests before OnGiveUp
// marked the UA unregistered. A registrar that RAISES its Min-Expires between
// refreshes — a configuration reload on the far end — therefore took the UA off
// the air permanently even though the fix is one longer Expires away.
//
// The peer registers the UA at 60 and only then starts demanding 240.
func TestRegisterRefresh423RetriesAtTheNewMinExpires(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, cc := newRegisterUAExpires(t, p, clk, 60)
	events := collect(t, ua)

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if res.ExpiresS != 60 {
		t.Fatalf("granted expires_s=%d want 60", res.ExpiresS)
	}

	// The registrar's floor goes up AFTER the registration is established.
	p.SetBehaviour(peer.Behaviour{Reject423MinExpires: 240})

	clk.BlockUntil(1)
	clk.Advance(60 * time.Second) // past 0.85*60 = 51s +/-5%

	ev := waitFor(t, events, session.UAEventRefresh, 0)
	if ev.ExpiresS != 240 {
		t.Fatalf("UAEventRefresh.ExpiresS=%d want the newly demanded 240 — the refresh must retry "+
			"at the registrar's Min-Expires and report what it was actually granted", ev.ExpiresS)
	}
	if n := cc.Received(423); n != 1 {
		t.Fatalf("UA received %d 423s, want exactly 1 — one rejection, one retry", n)
	}
	if !ua.Registered() {
		t.Fatal("the UA is unregistered after a 423 the refresh could have recovered from")
	}
}

// TestRegisterGrantedZeroExpiryArmsNoRefresher restores the negative property
// D/I1's deletion of TestNoReRegisterOrKeepaliveAtP1 lost for the re-register
// half (fix-round-2 verify report §2e): the replacement cited for that
// deletion, TestRegisterRefreshesBetween50And90PercentOfTheGrantedExpiry,
// asserts a POSITIVE (a refresh fires) and cannot substitute for a NEGATIVE
// (a refresh does not fire). Nothing in this package asserted that a UA which
// must not refresh does not refresh over time, and startRegisterRefresher's
// `grantedExpiresS <= 0` guard (register.go:1020-1022) had zero coverage.
//
// The registrar here grants a Contact `expires=0` (RFC 3261 §10.2.4:
// contactExpires honours it as the registrar saying the binding is gone), so
// grantedExpiresS is exactly 0 and startRegisterRefresher's
// `grantedExpiresS <= 0` guard (register.go:1020-1022) is the ONLY thing
// standing between this and an armed refresher.
//
// C7 (Phase 4 W1 M3): Register's own out.Registered now ALSO reflects this —
// a 200 granting expires=0 is no longer reported Registered:true with nothing
// refreshing it, symmetric with the refresh path's registrationRemoved. The
// assertion below used to read `want true/0`; it inverts to `want false/0`.
//
// NO clk.BlockUntil HERE, DELIBERATELY, unlike every other test in this file.
// BlockUntil synchronises with a timer the code IS going to arm; on correct,
// guarded code, startRegisterRefresher returns before newRefresher is ever
// constructed, so there is no timer to synchronise with, and blocking for one
// would hang forever rather than fail. fakeclock's package doc warning
// ("advancing before the code has armed its timer races the code it is meant
// to drive") is exactly why every other refresh test here calls BlockUntil
// first — and exactly why the deleted TestNoReRegisterOrKeepaliveAtP1 was a
// flaky false safety net, since IT advanced against a refresher shipped code
// really does arm. This test's property is the opposite shape: nothing must
// EVER be armed. The real-time Sleep below plays BlockUntil's role instead,
// giving a WRONGLY armed refresher (guard deleted) a genuine chance to
// register its own timer before Advance runs — exactly what
// TestRegisterRefresherStopsWithTheUA already does below to prove its own
// negative.
func TestRegisterGrantedZeroExpiryArmsNoRefresher(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t",
		Behaviour: peer.Behaviour{RegisterContactExpires: "0"},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newRegisterUAExpires(t, p, clk, 60)

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if res.Registered || res.ExpiresS != 0 {
		t.Fatalf("Register => registered=%v expires_s=%d, want false/0 — a granted expires=0 "+
			"removes the binding immediately (RFC 3261 §10.2.4, C7); Registered must not stay "+
			"true with nothing refreshing it", res.Registered, res.ExpiresS)
	}
	before := p.Count("REGISTER")

	// A real chance for a wrongly-armed refresher's goroutine to reach
	// r.clk.NewTimer and register itself, before any fake-clock Advance.
	time.Sleep(100 * time.Millisecond)
	clk.Advance(24 * time.Hour) // far past any interval this UA could plausibly use
	time.Sleep(50 * time.Millisecond)

	if got := p.Count("REGISTER"); got != before {
		t.Fatalf("registrar saw %d REGISTERs after 24 fake hours of a grantedExpiresS=0 "+
			"registration, want %d — startRegisterRefresher must arm nothing for a "+
			"non-positive grant (register.go:1020-1022)", got, before)
	}
}

func TestRegisterRefresherStopsWithTheUA(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newRegisterUAExpires(t, p, clk, 60)
	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := p.Count("REGISTER")
	if err := ua.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	clk.Advance(5 * time.Minute)
	time.Sleep(50 * time.Millisecond)
	if p.Count("REGISTER") != before {
		t.Fatal("the refresher must stop with the UA")
	}
}

// TestRegisterCSeqAdvancesEvenWhenTheResponseIsLost is fix-round-1 regression
// coverage for an Important review finding: recordRegisterCSeq used to run
// only AFTER DoRequestWithDigest's error check, so a REGISTER whose response
// never made it back (a genuine transport failure, not a rejection) left
// u.reg.cseq stale even though sipgo had already bumped and sent the CSeq that
// actually reached the wire. The NEXT attempt then rebuilt from that same
// stale value, sipgo bumped it to the SAME number the lost attempt already
// used, and two distinct REGISTER transactions carried one identical CSeq —
// exactly the collision Correction 4's stable-identity fix exists to prevent,
// just triggered by a dropped packet instead of a normal refresh cycle.
//
// The peer here requires NO digest auth, so each attempt is exactly one
// REGISTER/response round trip: the netfault RX drop below targets the
// FIRST ATTEMPT's responses (not just its first packet — see the Timeout and
// Pattern comments below), so the far end still fully receives and records
// every REGISTER it gets — this models a response lost in transit, not a
// registrar that never saw the request at all.
//
// TIMEOUT AND ASSERTION SHAPE, BOTH DELIBERATE (fix round 2): a first draft
// used a 150ms client Timeout to race sipgo's own 500ms T1 non-INVITE
// retransmit timer (third_party/sipgo/sip/transaction.go) — trying to make
// tx.Terminate() cancel the transaction before any retransmit could fire.
// That is exactly the wrong shape for a test on a 4-CPU sandbox with a
// documented history of losing short-deadline margins: if a retransmit DOES
// fire, its same-CSeq REGISTER lands at the peer as an extra p.CSeqs()
// entry, and an exact-length assertion (`len(seqs) != 2`) turns a correct
// production fix into a false failure. Fixed by doing the opposite: give the
// client a GENEROUS Timeout, well above 500ms, so retransmits fire
// ROUTINELY rather than racily, and assert on the number of DISTINCT CSeq
// values the peer saw rather than the raw count — sipgo's retransmit is a
// byte-identical resend and does NOT bump CSeq, so any number of retransmits
// of either attempt only ever duplicates an already-seen value; they can
// never manufacture a third distinct one. This exercises the tolerant path
// every run instead of only when the box happens to be idle.
func TestRegisterCSeqAdvancesEvenWhenTheResponseIsLost(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", RegisterExpires: 60})

	// Drop the first 4 inbound packets, then pass everything after. The first
	// attempt's own retransmits can produce at most 3 responses within its 2s
	// window below (send at t=0, T1=500ms, T1+2*T1=1500ms; the next would
	// land at 3500ms, past the deadline) — 4 gives exactly one packet of
	// margin above that measured/theoretical maximum.
	//
	// THIS MARGIN IS DELIBERATELY SMALL, NOT GENEROUS — the opposite of the
	// Timeout choice above, and for a reason specific to a PACKET-COUNT drop
	// pattern rather than a time-based one: every packet the drop zone
	// swallows beyond the first attempt's own traffic is ALSO subtracted from
	// the SECOND attempt's own retry budget, because both attempts share one
	// running packet counter. A first draft used 10 "to be safe" and that
	// safety was illusory: it silently ate the second attempt's first three
	// responses too (indices 4-6), which then had to exhaust its OWN 2s
	// Timeout before a response ever got through at index 7 — sometimes
	// succeeding by luck, sometimes not, i.e. failing with "second Register:
	// context deadline exceeded" instead of testing anything about the fix.
	// A small, close-to-measured margin is what actually keeps this
	// deterministic: it reliably drops 100% of the first attempt's traffic
	// while reliably passing the second attempt's very first response.
	dropFirstResponses := netfault.Drop{Pattern: append(dropPattern(4, true), dropPattern(30, false)...)}

	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp",
		Mode:      "register",
		AOR:       "sip:alice@example",
		Registrar: "sip:" + p.Addr(),
		ExpiresS:  60,
		// 2s: comfortably above sipgo's 500ms T1 non-INVITE retransmit
		// interval, so within the first (lost-response) attempt's window the
		// transaction routinely retransmits at least once (T1=500ms) and
		// often twice (T1+2*T1=1500ms) before this deadline fires — the
		// GENEROUS, not adversarial, choice per the Global Constraint on
		// timing tests. The unique-CSeq assertion below tolerates any number
		// of these by construction.
		Timeout:   2 * time.Second,
		LocalAddr: "127.0.0.1:0",
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			return netfault.New(pc, netfault.Config{RX: []netfault.Impairment{dropFirstResponses}})
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	if _, err := ua.Register(context.Background()); err == nil {
		t.Fatal("first Register: want a transport error (its responses were dropped in transit), got nil")
	}

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("second Register: %v", err)
	}
	if !res.Registered {
		t.Fatal("second Register: want Registered=true")
	}

	seqs := p.CSeqs("REGISTER")
	unique := uniqueSorted(seqs)
	if len(unique) != 2 {
		t.Fatalf("REGISTER CSeqs=%v (unique=%v): want exactly 2 unique values, one per attempt — "+
			"a collapsed count means the lost-response attempt's CSeq was reused by the next "+
			"attempt (recordRegisterCSeq must run even when DoRequestWithDigest returns an error); "+
			"retransmits of either attempt are tolerated here as harmless duplicates", seqs, unique)
	}
	if unique[0] >= unique[1] {
		t.Fatalf("REGISTER unique CSeqs=%v not strictly increasing", unique)
	}
}

// uniqueSorted returns seqs' distinct values in ascending order. It exists so
// TestRegisterCSeqAdvancesEvenWhenTheResponseIsLost can assert on WHICH CSeq
// values the peer saw without caring how many times a retransmit duplicated
// any one of them.
func uniqueSorted(seqs []uint32) []uint32 {
	set := make(map[uint32]struct{}, len(seqs))
	for _, s := range seqs {
		set[s] = struct{}{}
	}
	out := make([]uint32, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// dropPattern returns n copies of v, for building a netfault.Drop pattern out
// of named runs (e.g. "4 drops, then 30 passes") instead of a bare
// make([]bool, n) whose zero-value meaning is easy to misread at a glance.
func dropPattern(n int, v bool) []bool {
	out := make([]bool, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// TestRegisterRefreshGrantedZeroStopsRefreshing is Cycle 4 / C4-A's item D
// gap 3: the "granted 0 on a REFRESH" case, which had no test at all. The
// initial-REGISTER half of the same contract IS covered
// (TestRegisterGrantedZeroExpiryArmsNoRefresher above), and that asymmetry is
// the whole point — startRegisterRefresher's own doc comment states the rule
// as a property of the GRANT, not of which exchange delivered it:
//
//	"A non-positive grant arms nothing: a registrar that granted no expiry has
//	 given us no interval to refresh against, and guessing one would put
//	 unsolicited REGISTERs on the wire."
//
// A registrar dropping a binding mid-registration (administrative deregister,
// a rebuilt registrar, a policy change) answers the next refresh with
// `Contact ...;expires=0`. That is the same grant, and it must reach the same
// outcome.
//
// IT REPRODUCED A DEFECT, AND WAS COMMITTED SKIPPED UNTIL THE FIX LANDED
// (dbcbb77). At HEAD before the fix the registrar saw 6 REGISTERs where 4 were
// due: after the granted-0 refresh the loop kept its LAST POSITIVE interval
// (refresher.go's `if granted > 0` leaves `interval` untouched) and re-registered
// forever against an interval that was never granted, and refreshRegister set
// `u.reg.registered = true` unconditionally, so the UA reported
// Registered()=true with expires_s=0. registrationRemoved (register.go) is the
// fix; this test is now live.
//
// THE THREE ASSERTIONS ARE THREE DIFFERENT HALVES OF THE RULING AND NONE IS
// REDUNDANT. The wire assertion pins "stop refreshing"; Registered() pins the
// reporting half, which the wire count cannot see (the pre-fix code passed
// neither, but a fix that only disarmed the timer would pass the first and still
// report a registration that no longer exists); and the absence of
// UAEventRegisterFailed pins that the loop ended QUIETLY rather than by burning
// its retry budget into OnGiveUp — the registrar answered 200, so a
// register_failed event would report an unreachable registrar to an operator
// whose registrar replied correctly.
func TestRegisterRefreshGrantedZeroStopsRefreshing(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newRegisterUAExpires(t, p, clk, 60)
	events := collect(t, ua)

	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// The registrar drops the binding: every REGISTER from here on is granted 0.
	p.SetBehaviour(peer.Behaviour{RegisterContactExpires: "0"})

	// Drive exactly one refresh at the armed interval (granted 60 => 50-90%).
	clk.BlockUntil(1)
	clk.Advance(55 * time.Second)

	// THE BARRIER IS THE FULL EXCHANGE, AND IT IS DELIBERATELY NOT THE REMOVAL
	// EVENT. Since P4-D07 a refresh is ONE authenticated REGISTER on this peer —
	// the challenge cached from the initial two-message registration is presented
	// preemptively — so the third REGISTER IS the whole refresh exchange and the
	// baseline latched below is exact. (It was `>= 4` while every refresh drew its
	// own 401 first: `> 2` would then have been satisfied by the challenge alone
	// and the authenticated retry would have moved the baseline underneath it.)
	// Waiting for UAEventRegisterRemoved instead would work equally well on
	// correct code and be strictly worse on broken code: the wire assertion below
	// is the one that measures the defect, and it must be REACHED by a build that
	// never emits the event.
	waitForCond(t, func() bool { return p.Count("REGISTER") >= 3 })
	afterGrantedZero := p.Count("REGISTER")

	// That refresh was granted 0. Nothing may go on the wire unsolicited after
	// it — same rule, same reason, as the initial-grant path.
	time.Sleep(100 * time.Millisecond) // a real chance for a re-armed timer to register itself
	clk.Advance(24 * time.Hour)        // far past any interval this UA could plausibly use
	time.Sleep(100 * time.Millisecond)

	if got := p.Count("REGISTER"); got != afterGrantedZero {
		t.Fatalf("registrar saw %d REGISTERs after 24 fake hours following a refresh GRANTED 0, want %d — "+
			"a non-positive grant must arm nothing on the refresh path exactly as it does on the initial "+
			"path (startRegisterRefresher); refreshing on against the last positive "+
			"grant is the \"guessing an interval\" that comment forbids", got, afterGrantedZero)
	}
	if ua.Registered() {
		t.Fatalf("Registered()=true after a refresh the registrar granted expires=0 — the binding "+
			"is gone (RFC 3261 §10.2.4), and a UA reporting itself registered with no granted expiry "+
			"is the reporting half of the same defect; events=%v", kinds(events()))
	}
	waitFor(t, events, session.UAEventRegisterRemoved, 0)

	// THE RETRY BUDGET MUST BE DRIVEN BEFORE THE SCAN BELOW, OR THE SCAN CANNOT
	// FAIL. The removal event is emitted synchronously inside registrationRemoved,
	// so waitFor above returns while the refresh loop is still parked in its first
	// retry backoff — attempt() classifies nothing about a Do error, it just
	// retries, and quietStop/OnGiveUp are only reached once all three attempts are
	// spent (2s then 4s on this clock). MEASURED: dropping BOTH errRefresherStopped
	// wraps (registrationRemoved and refreshRegister's opening guard) left this
	// test, internal/session and internal/transport/mcp green, because the scan ran
	// before the give-up could arrive. Waiting for the loop to actually END is the
	// fix: that is the terminal state in BOTH arms — reached quietly at HEAD, and
	// through OnGiveUp (which emits UAEventRegisterFailed before its goroutine
	// returns) on a build that misclassifies the removal as a failure. The advance
	// crosses whatever retry timer is armed; on correct code the loop is already
	// finishing and the first poll returns.
	waitForCond(t, func() bool {
		clk.Advance(30 * time.Second)
		return ua.RegisterRefresherStopped()
	})

	for _, ev := range events() {
		if ev.Kind == session.UAEventRegisterFailed {
			t.Fatalf("UAEventRegisterFailed after a 200 OK that granted expires=0: nothing FAILED, "+
				"the registrar answered and removed the binding. The refresh loop must end quietly "+
				"through errRefresherStopped, not by exhausting its retries into OnGiveUp; events=%v",
				kinds(events()))
		}
	}
}

// TestRegisterRefreshDuringAnActiveCallLeavesTheCallAndTheBindingAlone is
// Cycle 4's group-B combination #4 — "registration refresh concurrently with an
// active call on the same UA" — and it is the one with a FIELD SYMPTOM behind
// it, not just a hole in a matrix. Cycle 2's live gate lost scenario #3 once in
// three runs with both legs seeing remote_bye ~150 ms after answer, on the
// e2e-uac-register profile whose expires_s: 60 makes a refresh NECESSARILY fire
// during a minutes-long gate run. Before this wave that profile line was inert
// (TestNoReRegisterOrKeepaliveAtP1); Task 25 made it live, and nothing anywhere
// proved a refresh mid-call does not disturb the dialog.
//
// THE CONTACT ASSERTION IS THE ONE THAT MATTERS. A refresh that re-registered
// the AOR under a DIFFERENT contact — a changed source port, an address learned
// between the two REGISTERs — is precisely how the far end would rebind the AOR
// out from under a live call and BYE it. It is also invisible to every existing
// refresh test here: they assert CSeq, nonce count, Call-ID stability and
// timing, all of which stay perfectly correct while the binding moves.
//
// Deliberately NOT asserted: the From tag. Cycle 2 §3(D) observed that each
// refresh mints a fresh one, and whether that or applyRegisterIdentity's comment
// is wrong is a separate carried item — pinning either reading here would
// prejudge it.
func TestRegisterRefreshDuringAnActiveCallLeavesTheCallAndTheBindingAlone(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newRegisterUAExpires(t, p, clk, 60)
	events := collect(t, ua)

	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	boundContact := p.LastRequestHeader("REGISTER", "Contact")
	if boundContact == "" {
		t.Fatal("the initial REGISTER carried no Contact to compare the refresh against")
	}
	registersBefore := p.Count("REGISTER")

	// The call runs on the SAME UA, which is the whole point: one socket, one
	// registration, one dialog.
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	// Granted 60 => the refresh fires at 0.85*60 = 51s +/-5%; 55s is past the
	// whole jitter band. One waiter: no keepalive and no session timer here.
	clk.BlockUntil(1)
	clk.Advance(55 * time.Second)
	waitForCond(t, func() bool { return p.Count("REGISTER") > registersBefore })
	waitFor(t, events, session.UAEventRefresh, 0)

	if got := p.LastRequestHeader("REGISTER", "Contact"); got != boundContact {
		t.Fatalf("the refresh REGISTER's Contact %q differs from the binding %q established "+
			"before the call: a registrar that rebinds the AOR to a new contact drops calls "+
			"addressed to the old one", got, boundContact)
	}
	if !ua.Registered() {
		t.Fatal("the UA is no longer registered after a refresh that ran during a call")
	}

	// The dialog is untouched by the refresh.
	if n := p.ByeCount(); n != 0 {
		t.Fatalf("the peer received %d BYEs across a REGISTER refresh; the call must be unaffected", n)
	}
	if n := countKind(events(), session.UAEventDialogEnded); n != 0 {
		t.Fatalf("dialog_ended fired %d times across a REGISTER refresh, want 0: %v",
			n, kinds(events()))
	}
	// STILL INTACT, not merely still listed: the hangup goes through
	// buildInDialogRequest, so a dialog whose phase or CSeq space the refresh had
	// disturbed fails here rather than passing silently.
	if err := ua.Hangup(context.Background(), res.DialogID, "done"); err != nil {
		t.Fatalf("Hangup after a REGISTER refresh: %v — the call did not survive it", err)
	}
	p.WaitForBye(t, 5*time.Second)
}

// TestAnAbsurdGrantedRegistrationExpiryCannotFastFireTheRefresher is the
// registration half of the F1 overflow bound.
//
// startRegisterRefresher bounded the grant only with `> 0`, then multiplied it
// into a time.Duration that wraps NEGATIVE above 9223372036 seconds. A hostile
// or compromised registrar (or any on-path proxy that can rewrite the 200 OK)
// therefore turned this UA into an unbounded REGISTER source pointed at the
// registrar, each cycle carrying a full digest challenge/response round trip.
//
// THE ASSERTION IS ON THE WIRE. Clamped to maxAcceptableRegisterExpiresS the
// refresh is due at 0.85*86400 = 73440s +/-5%, so the earliest it may fire is
// 69768s; an hour in, the wire must still show only the initial exchange.
func TestAnAbsurdGrantedRegistrationExpiryCannotFastFireTheRefresher(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t",
		RegisterExpires: 9999999999,
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newRegisterUAExpires(t, p, clk, 60)

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if res.ExpiresS != 86400 {
		t.Fatalf("granted expires_s=%d want the clamped 86400", res.ExpiresS)
	}
	if n := p.Count("REGISTER"); n != 2 {
		t.Fatalf("initial REGISTER exchange = %d messages want 2 (401 then 200)", n)
	}

	clk.BlockUntil(1)
	// Unclamped the refresher's deadline is already in the past, so this single
	// Advance crosses it and every re-arm it produces.
	clk.Advance(3600 * time.Second)
	time.Sleep(100 * time.Millisecond)
	if n := p.Count("REGISTER"); n != 2 {
		t.Fatalf("REGISTER count=%d an hour in, want 2 — a registrar-supplied expiry "+
			"that overflows time.Duration has turned the refresher into an "+
			"immediate-fire loop", n)
	}

	// And the clamped cadence is real rather than the timer simply being off:
	// 0.85*1.05*86400 = 77112s is the latest the refresh may land.
	clk.Advance(74400 * time.Second) // t = 78000s
	waitForCond(t, func() bool { return p.Count("REGISTER") > 2 })
}

// TestA423MinExpiresAboveOurCeilingIsNotAFloorWeWillHonour is F3, the last
// registrar-supplied number without a ceiling.
//
// Min-Expires is not merely scheduling data: retryIntervalTooBrief stores it in
// u.reg.minExpiresS and requestedExpires then raises EVERY later REGISTER to it,
// so it goes on the wire and returns through responseExpires' fallback into the
// refresh timer. Unbounded, a registrar answering 423 with Min-Expires:
// 9999999999 got us to put that on the wire and refresh against it.
//
// The two things the security brief asked about this path came back clean and
// are deliberately NOT changed here: the retry stays once-not-a-loop (the
// `floor <= requestedExpiresS` guard), and the floor stays monotonically
// non-decreasing (it is only written when it exceeds requestedExpires(), which
// already includes the current floor). TestRegister423RetriesAtMinExpiresAndClampsTheRefresh
// and TestRegister423RetriesOnceAndThenStops are the fences on those; only the
// missing ceiling is added.
//
// An unhonourable floor is treated exactly as a MISSING one — reported as the
// 423 it is — rather than clamped: clamping would put a value the registrar has
// just told us it rejects back on the wire.
func TestA423MinExpiresAboveOurCeilingIsNotAFloorWeWillHonour(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t",
		Behaviour: peer.Behaviour{Reject423MinExpires: 9999999999},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, cc := newRegisterUAExpires(t, p, clk, 300)

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if res.Registered || res.Code != 423 {
		t.Fatalf("Register => registered=%v code=%d, want false/423 — a Min-Expires we cannot "+
			"honour is not a floor to retry at", res.Registered, res.Code)
	}
	// The wire is the assertion that matters: the absurd floor must never leave
	// this UA, on the retry or on any REGISTER after it.
	if got := p.LastRequestHeader("REGISTER", "Expires"); got != "300" {
		t.Fatalf("the last REGISTER's wire Expires=%q want \"300\" — the registrar's "+
			"Min-Expires was adopted as our requested expiry", got)
	}
	if n := p.Count("REGISTER"); n != 2 {
		t.Fatalf("registrar saw %d REGISTERs, want 2 (401 then the 423ed one) — a floor we "+
			"cannot honour must not be retried at", n)
	}
	if n := cc.Received(423); n != 1 {
		t.Fatalf("UA received %d 423s, want exactly 1", n)
	}

	// Nothing was armed, so nothing can fire: a failed registration puts no
	// REGISTERs on the wire however far the clock runs.
	clk.Advance(7200 * time.Second)
	time.Sleep(100 * time.Millisecond)
	if n := p.Count("REGISTER"); n != 2 {
		t.Fatalf("registrar saw %d REGISTERs two hours in, want 2", n)
	}
}
