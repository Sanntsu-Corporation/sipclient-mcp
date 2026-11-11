package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

func TestIdentityStoreBinding(t *testing.T) {
	var (
		tokA = []byte("token-a")
		tokB = []byte("token-b")
	)
	id := newSessionID()

	s := newIdentityStore()
	if s.matches(id, tokA) {
		t.Fatal("unbound id matched; an unissued id must never match")
	}
	s.bind(id, tokA, false)

	tests := []struct {
		name  string
		id    string
		token []byte
		want  bool
	}{
		{"same id, same token", id, tokA, true},
		{"same id, different token", id, tokB, false},
		{"different id, same token", newSessionID(), tokA, false},
		{"empty token", id, []byte(""), false},
		{"nil token", id, nil, false},
		{"empty id", "", tokA, false},
		{"token is a prefix of the bound token", id, []byte("token-"), false},
		{"token has the bound token as a prefix", id, []byte("token-a-and-more"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.matches(tc.id, tc.token); got != tc.want {
				t.Fatalf("matches(%q, %q) = %v, want %v", tc.id, tc.token, got, tc.want)
			}
		})
	}

	s.forget(id)
	if s.matches(id, tokA) {
		t.Fatal("forgotten id still matches")
	}
}

// TestIdentityStoreSweepsDeadIDsAtBind is D214/D265's required non-vacuous
// test: bind is the only growth site for identityStore.tokens, so sweeping
// at that same call site (sessionIDMiddleware's onIssue, immediately before
// bind) must keep the map from growing without bound once the ids it holds
// are no longer alive.
//
// It drives the REAL /mcp HTTP path — 200 initialize calls on one valid
// bearer token, none of them followed up — rather than calling sweep
// directly, so the test also proves onIssue actually calls it. Each
// initialize opens an EMPTY session record (fakes.Sessions models §12.6:
// emptySince is stamped at Open and never refreshed by a bare initialize),
// so once the clock passes the resume window every one of those 200 ids is
// no longer alive. One more initialize should trigger the sweep and reclaim
// them.
func TestIdentityStoreSweepsDeadIDsAtBind(t *testing.T) {
	const window = 5 * time.Minute
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	hs, _, srv := newTestServer(t, clk, window)

	const n = 200
	for i := 0; i < n; i++ {
		initSession(t, hs, testToken)
	}

	srv.identity.mu.RLock()
	before := len(srv.identity.tokens)
	srv.identity.mu.RUnlock()
	if before != n {
		t.Fatalf("bound ids after %d initializes = %d, want %d", n, before, n)
	}

	// Past the resume window: every one of the 200 empty session records is
	// now not-alive.
	clk.Advance(window + time.Second)

	// One more initialize is the ONLY thing that can trigger a sweep — no
	// follow-up request was ever made on any of the 200 prior ids.
	initSession(t, hs, testToken)

	srv.identity.mu.RLock()
	after := len(srv.identity.tokens)
	srv.identity.mu.RUnlock()
	if after >= n {
		t.Fatalf("bound ids after the resume window and one more initialize = %d, want < %d "+
			"(D214: the sweep at onIssue must reclaim ids for sessions no longer alive)", after, n)
	}
}

// barrierSessions wraps fakes.Sessions so the FIRST call to Open blocks
// until released. D278/D279: the goroutine-load version of this test was a
// PROBABILISTIC detector — 0/10 detections at GOMAXPROCS=1 against
// known-broken code, the very regime CI most often runs under, because no
// number of unsynchronised goroutines can guarantee two of them land inside
// the live microsecond window between sweep/Open/bind. Parking one
// goroutine INSIDE Sessions.Open (a channel receive, which always yields
// the scheduler, even under GOMAXPROCS=1) and driving a second goroutine's
// entire initialize — sweep included — to completion before releasing it
// makes the window deterministic instead of relying on luck (D280).
// first, not once: sync.Once blocks EVERY concurrent caller until the first
// call's function returns, which would deadlock this design — B's Open must
// pass straight through while A's is still parked, not queue behind it.
// atomic.Bool.CompareAndSwap picks exactly one first caller without making
// anyone else wait on it.
type barrierSessions struct {
	*fakes.Sessions

	first   atomic.Bool
	parked  chan struct{} // closed once the first Open call has parked
	release chan struct{} // closed to release the parked Open call
}

func newBarrierSessions(s *fakes.Sessions) *barrierSessions {
	return &barrierSessions{Sessions: s, parked: make(chan struct{}), release: make(chan struct{})}
}

// Open parks only the FIRST caller — every later call (the second
// goroutine's Open, and anything else the test drives) passes straight
// through to the real fake.
func (b *barrierSessions) Open(ctx context.Context, id string) error {
	if b.first.CompareAndSwap(false, true) {
		close(b.parked)
		<-b.release
	}
	return b.Sessions.Open(ctx, id)
}

// TestConcurrentInitializeSparesLiveBindings is D272's required regression
// test, proving the OTHER direction from TestIdentityStoreSweepsDeadIDsAtBind
// above: D214's one-directional mutation proof ("delete the sweep, does the
// reclaimed count stay wrong?") could not detect a sweep that is too
// aggressive. This test does: does the sweep ever delete a binding for a
// session that IS alive, just not bound-and-opened yet?
//
// D280: this replaces the original 400-goroutine load test (D278/D279 — its
// detection rate was 0% at GOMAXPROCS=1 against known-broken code, no matter
// how many goroutines or how many -count reps) with a deterministic barrier.
// Goroutine A's initialize is parked, by barrierSessions, inside
// Sessions.Open — exactly the point at which onIssue's sweep/Open/bind
// ordering matters — until goroutine B's ENTIRE initialize, including its
// own onIssue sweep, has run to completion:
//
//   - correct ordering (sweep -> Open -> bind): A is parked before it has
//     bound anything, so B's sweep sees no trace of A; A binds on release
//     and its follow-up request succeeds.
//   - pre-D272 ordering (sweep -> bind -> Open): A is already bound, but
//     Sessions.Alive(A's id) is still false because Open has not run, when
//     B's sweep observes it — B's sweep deletes A's binding outright, and
//     A's follow-up 404s once released.
//
// D211: every follow-up JSON-RPC id used here is unique (2 for B, 3 for A)
// even though B and A never share an Mcp-Session-Id and so could not
// collide in the SDK's per-connection multiplexing — kept unique anyway per
// this file's established convention.
func TestConcurrentInitializeSparesLiveBindings(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	sess := fakes.NewSessions(clk, time.Hour)
	barrier := newBarrierSessions(sess)

	store, _ := testPolicyStore(t, clk, testToken, "")
	srv, err := NewServer(Config{
		Sessions: barrier,
		Tools:    fakes.NewTools(),
		Policy:   store,
		Log:      discardLogger(),
		Clock:    clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	// Guarantee release fires even if a t.Fatalf below Goexits the test
	// mid-flight — otherwise goroutine A stays parked inside Open forever.
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(barrier.release) }) }
	t.Cleanup(release)

	type initResult struct {
		code int
		id   string
	}
	aDone := make(chan initResult, 1)
	go func() {
		code, id := post(t, hs, testToken, "", initBody)
		aDone <- initResult{code, id}
	}()

	// Wait for A to be parked inside Sessions.Open before driving B.
	<-barrier.parked

	idB := initSession(t, hs, testToken)
	if code, _ := post(t, hs, testToken, idB, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`); code != http.StatusOK {
		t.Fatalf("B follow-up: status = %d, want 200", code)
	}

	// B's entire initialize, sweep included, is now complete. Release A.
	release()

	a := <-aDone
	if a.code != http.StatusOK || a.id == "" {
		t.Fatalf("A initialize: status = %d, id = %q, want 200 and a non-empty id", a.code, a.id)
	}

	// The load-bearing check: under the pre-D272 bind-before-Open ordering,
	// B's sweep — which ran while A sat bound but not-yet-alive inside the
	// parked Open call — deleted A's binding, so this 404s.
	if code, _ := post(t, hs, testToken, a.id, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`); code != http.StatusOK {
		t.Fatalf("A follow-up: status = %d, want 200 (D272: sweep must never delete a "+
			"bound-but-not-yet-alive id)", code)
	}
}
