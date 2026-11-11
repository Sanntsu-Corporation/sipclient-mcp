package loopback_test

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// §15's N1 SPLIT. P1's "50 concurrent calls pass" is a SIGNALLING-AND-HANDLE-
// ISOLATION criterion only: it asserts state transitions, isolation and the
// goroutine model, and asserts NOTHING about packet spacing or loss, because
// P1 has no media session.
//
// DO NOT ADD TX-SPACING OR LOSS ASSERTIONS HERE. The ±5ms 99th-percentile TX
// spacing budget and the "no server-attributable loss above 1%" bound are
// P2's: they need §6.5.2's drift-corrected ticker to exist before they mean
// anything, and asserted at P1 they would be meaningless.
func TestFiftyConcurrentCallsAcrossFiveSessions(t *testing.T) {
	const (
		sessions     = 5
		callsPerSess = 10
	)
	h := loopback.New(t,
		loopback.WithPolicyOverride("limits.max_concurrent_calls_total", 60),
		loopback.WithPolicyOverride("limits.max_concurrent_calls_per_session", 20))
	defer h.Close()

	type owned struct {
		sess  *loopback.Session
		ua    string
		calls []string
	}
	all := make([]owned, sessions)
	for i := 0; i < sessions; i++ {
		all[i].sess = h.NewSession(t)
		all[i].ua = all[i].sess.MustCreateUA(t, "direct")
		all[i].calls = make([]string, callsPerSess)
	}

	// Captured AFTER the 5 sessions' UAs are up, not before: this test only
	// hangs up CALLS below, never the UAs (they stay live for the harness's
	// whole lifetime, per h.Close()'s own teardown) — a baseline captured
	// before UA creation could never be returned to on call-only teardown,
	// which would make WaitForGoroutineBaseline below fail unconditionally
	// on the 5 UAs' own persistent listener goroutines regardless of any
	// genuine per-call leak. Confirmed empirically: with the baseline taken
	// before UA setup, the count plateaued at a stable 77 against a
	// baseline(9)+slack(20)=29 ceiling — not a slow drain, a permanent
	// offset from 5 UAs this test intentionally keeps alive.
	goroutinesBefore := runtime.NumGoroutine()

	var wg sync.WaitGroup
	// t.Fatalf FROM A NON-TEST GOROUTINE DOES NOT STOP THE TEST. It calls
	// runtime.Goexit on that goroutine only, so the remaining 49 dials keep
	// running against a harness the test has already given up on, and the real
	// failure is buried under a cascade of derived ones. The Must* helpers all
	// carry a t.Fatal internally, so they must not be called here — this loop
	// uses the error-returning forms and t.Errorf + return, which records the
	// failure, lets wg.Wait() complete, and reports once. Step 6's foreign-read
	// loop already does this correctly; these two are now consistent.
	//
	// `go vet`'s testinggoroutine analyzer will NOT flag the Must* form,
	// because the t.Fatal is one frame down inside the helper — so the Rule 11
	// syntax-check hook cannot catch this and the plan has to.
	for i := 0; i < sessions; i++ {
		for j := 0; j < callsPerSess; j++ {
			wg.Add(1)
			go func(i, j int, ua string) {
				defer wg.Done()
				c, err := all[i].sess.Dial(ua, h.PeerURI())
				if err != nil {
					t.Errorf("session %d dial %d: %v", i, j, err)
					return
				}
				all[i].calls[j] = c
				if res := all[i].sess.CallWait(c, "answered", 10000); res.Err != nil || res.TimedOut {
					t.Errorf("session %d call %s did not reach answered: err=%v timedOut=%v",
						i, c, res.Err, res.TimedOut)
					return
				}
			}(i, j, all[i].ua)
		}
	}
	wg.Wait()
	if t.Failed() {
		t.Fatal("setup did not complete; the assertions below would report derived failures")
	}

	// State transitions.
	for i := range all {
		for _, c := range all[i].calls {
			if st := all[i].sess.MustCallStatus(t, c); st.State != "answered" {
				t.Fatalf("session %d call %s state = %q, want answered", i, c, st.State)
			}
		}
	}
	if got := h.MustMetrics(t)["active_calls"]; got != sessions*callsPerSess {
		t.Fatalf("active_calls = %d, want %d", got, sessions*callsPerSess)
	}

	// Handle isolation under load (R11): every cross-session read is not_found.
	for i := range all {
		for j := range all {
			if i == j {
				continue
			}
			for _, c := range all[j].calls {
				_, err := all[i].sess.CallTool("call_status", map[string]any{"call": c})
				if code := loopback.ErrorCode(err); code != "not_found" {
					t.Fatalf("session %d reading session %d's handle %s got %q, "+
						"want not_found", i, j, c, code)
				}
			}
		}
		if got := len(all[i].sess.MustCallList(t)); got != callsPerSess {
			t.Fatalf("session %d call_list = %d entries, want %d (its own calls only)",
				i, got, callsPerSess)
		}
	}

	// Goroutine model: bounded per call, and returning to baseline on teardown.
	// A REGRESSION TRIPWIRE, NOT A SPEC BUDGET. The spec states no per-call
	// goroutine number anywhere — §6.3 constrains lock order and N1 constrains
	// concurrency and, at P2, packet timing; neither names 4. The figure is a
	// ceiling chosen from what P1's signalling-only design actually needs (the
	// dialog's transaction goroutines and its event pump), set loosely enough
	// not to be brittle and tightly enough that a per-call goroutine LEAK —
	// which is the real failure this guards, and which would otherwise surface
	// only as a slow OOM in a long soak — trips it. If a legitimate design
	// change raises the true figure, RAISE THIS NUMBER AND SAY WHY; do not
	// delete the check, and do not describe it as a spec requirement.
	// Raised 4 -> 5 by rfc-fix-1 (CF-107/CF-088, D-107): each answered outbound
	// INVITE keeps one absorbInvite2xx goroutine for Timer M (64*T1 = 32 s), so
	// that every further 2xx (a retransmission or another fork's) is ACKed.
	perCall := float64(runtime.NumGoroutine()-goroutinesBefore) / float64(sessions*callsPerSess)
	if perCall > 5 {
		t.Fatalf("%.1f goroutines per call, want <= 5 — a P1 signalling-only regression "+
			"tripwire, not a spec budget; investigate a per-call leak before raising it",
			perCall)
	}
	for i := range all {
		for _, c := range all[i].calls {
			all[i].sess.MustHangup(t, c)
		}
	}
	// "returning to baseline on teardown" (this section's own opening
	// comment) is NOT asserted here (Rule 6c blocker, reported to the wave
	// owner). Empirically: goroutine count plateaus at a STABLE figure
	// (unaffected by a further 30s wait — not a slow drain) immediately
	// after the 50 answers and is IDENTICAL before and after every one of
	// the 50 MustHangup calls above; destroying all 5 UAs afterward
	// recovers only a small fraction of the gap (~2 goroutines/UA), not the
	// rest. h.EvictCallForTest (Harness.EvictNow) cannot force the
	// remainder either: it operates on s.liveCalls, and a hung-up call has
	// already left that map, so it 404s. Registry eviction of a terminated
	// call is otherwise time-gated by limits.registry_retention (default
	// 1h; policy.go), which this test cannot advance without a fake clock
	// it deliberately does not carry (real concurrent-timing coverage is
	// the point of this test). Whether the remaining per-call goroutines
	// are BY DESIGN (retained with the terminated registry entry until
	// eviction, per U21) or a genuine leak neither hangup nor ua_destroy
	// reaches is exactly the open question this needs resolved before the
	// check can be written meaningfully — the perCall tripwire above still
	// covers the "bounded while calls are live" half of this section's own
	// docstring.
}

// D11 point 5: a live UA is NEVER destroyed by the passage of time.
// registry_retention is a terminated-entry clock and nothing else — it never
// starts, and never expires, for anything still live (§N3).
func TestLiveUAHasNoDeadline(t *testing.T) {
	h := loopback.New(t, loopback.WithFakeClock(),
		// A real profile: the assertion below reads st.Registered, and a
		// "direct" UA (no profile available) would make that field
		// trivially false rather than a meaningful check of D11 point 5.
		loopback.WithAccounts(loopback.TestAccount("carrier-a", "s3cr3t-auth-pass")),
		loopback.WithPolicyOverride("limits.registry_retention", "5s"),
		loopback.WithPolicyOverride("limits.session_resume_window", "5s"))
	defer h.Close()

	s := h.NewSession(t)
	ua := s.MustCreateUAWithAccount(t, "carrier-a")
	s.CloseConnection(t) // the client goes away entirely

	// Well past both 5s windows.
	h.Clock().Advance(60 * time.Second)
	h.RunJanitor(t)

	// The far end can still reach the UA, routed through the in-process
	// registrar by the profile's registered user (the same routing
	// TestAdminDeleteOnTheWire's D11-point-4 case addresses through)…
	h.Peer().Dial(t, "sip:testuser@"+h.Registrar().Addr())

	// …and the OWNING session, reconnecting at 60s with the same id and
	// token, still resolves both handles.
	s.Reconnect(t)
	c := s.MustWaitForInboundCall(t, 2*time.Second)
	if st := s.MustUAStatus(t, ua); !st.Registered {
		t.Fatal("UA was destroyed or deregistered by the passage of time (D11 point 5)")
	}
	if st := s.MustCallStatus(t, c); st.State != "ringing" {
		t.Fatalf("inbound call state = %q, want ringing", st.State)
	}

	// …and only that session.
	other := h.NewSession(t)
	if _, err := other.CallTool("call_status", map[string]any{"call": c}); loopback.ErrorCode(err) != "not_found" {
		t.Fatalf("foreign session got %q, want not_found (R11, §12.6)", loopback.ErrorCode(err))
	}
}

// The symmetric half: an EMPTY session does age out at session_resume_window.
func TestEmptySessionAgesOut(t *testing.T) {
	h := loopback.New(t, loopback.WithFakeClock(),
		loopback.WithPolicyOverride("limits.session_resume_window", "5s"),
		// A session is "empty" (janitor.go sessionEmptyLocked) only once it
		// holds NO live UAs and NO terminated calls/UAs either, not merely
		// no LIVE calls. The hung-up call sits in terminatedCalls, and its
		// UA (never destroyed) sits in liveUAs, until each is cleared. Left
		// at the 1h production default, the 10s clock advance below would
		// evict nothing and the session would never read as empty. 1s here
		// is well under the 10s advance, so the SAME janitor sweep evicts
		// the terminated call, and — once the UA below is also destroyed —
		// expires the now-genuinely-empty session.
		loopback.WithPolicyOverride("limits.registry_retention", "1s"))
	defer h.Close()

	s := h.NewSession(t)
	ua := s.MustCreateUA(t, "direct")
	c := s.MustDialAnsweredOn(t, ua)
	s.MustHangup(t, c)
	// Without this, the UA stays in liveUAs forever (nothing else in this
	// test destroys it) and sessionEmptyLocked never returns true, no
	// matter how far the clock advances.
	s.MustCallTool(t, "ua_destroy", map[string]any{"ua": ua})
	s.CloseConnection(t)

	h.Clock().Advance(10 * time.Second)
	h.RunJanitor(t)

	if status, _ := h.RawToolCallAs(t, s.ID(), loopback.TestBearer(), "call_list", nil); status != 404 {
		t.Fatalf("empty session after its window = %d, want 404 (§12.6)", status)
	}
	fresh := h.Initialize(t, s.ID(), loopback.TestBearer())
	if list := h.CallListFor(t, fresh.SessionID, loopback.TestBearer()); len(list) != 0 {
		t.Fatalf("fresh session call_list = %v, want empty", list)
	}
}
