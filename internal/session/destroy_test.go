package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// blockingAgent is a UserAgent whose Hangup parks until the test releases it.
// It is how a 10s grace period is simulated without a 10s test.
type blockingAgent struct {
	nopAgent
	hangupEntered chan struct{} // closed-ish: one send per Hangup call
	release       chan struct{}
}

func newBlockingAgent() *blockingAgent {
	return &blockingAgent{
		hangupEntered: make(chan struct{}, 8),
		release:       make(chan struct{}),
	}
}

func (a *blockingAgent) Hangup(ctx context.Context, _, _ string) error {
	a.hangupEntered <- struct{}{}
	select {
	case <-a.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TestDestroyDoesNotHoldTheRegistryLockAcrossTheByeWait is §12.7's
// registry-lock-release property, asserted against the REAL Manager.
//
// IT MUST NEVER BE REPOINTED AT A FAKE MANAGER. A fake proves the caller adds
// no serialization; only the real Manager proves the lock discipline, and the
// lock discipline is the property §12.7 names.
//
// Failure mode being excluded: holding m.mu across the BYE wait stalls every
// concurrent tool call on the server for the full grace period — an OUTAGE, not
// a latency blip.
func TestDestroyDoesNotHoldTheRegistryLockAcrossTheByeWait(t *testing.T) {
	agent := newBlockingAgent()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p := policy.Defaults()
	p.Limits.ShutdownGracePeriod = policy.Duration(10 * time.Second)
	m, err := NewManager(ManagerConfig{
		Ctx:    ctx,
		Clock:  fc,
		Policy: policy.NewStaticStore(p, fc, testLogger()),
		Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) {
			return agent, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// S1 owns a UA with one answered call; S2 is an unrelated live session.
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open(s1): %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}
	c.setDialogIdentity("dlg-1", "callid-1")
	s2Call := mustCall(t, m, "s2")

	// Start the teardown. Its BYE blocks in the fake agent, so the DELETE now
	// occupies the whole grace period.
	destroyDone := make(chan error, 1)
	go func() {
		_, err := m.DestroyUA(context.Background(), string(ua.Handle()))
		destroyDone <- err
	}()

	select {
	case <-agent.hangupEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("teardown never reached the BYE")
	}

	// THE ASSERTION. With the teardown parked mid-BYE, an unrelated session's
	// tool call must return inside N2's 50ms budget. If the registry lock were
	// held across the wait, this blocks for the full grace period.
	done := make(chan error, 1)
	go func() {
		_, err := m.ResolveCall(context.Background(), "s2", s2Call.Handle())
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unrelated session's ResolveCall: %v", err)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("an unrelated session's tool call did not return within N2's 50ms budget " +
			"while a teardown was mid-BYE — the registry lock is held across the grace " +
			"period, which stalls every concurrent tool call on the server (§12.7)")
	}

	// The teardown still completes normally once the far end answers.
	close(agent.release)
	select {
	case err := <-destroyDone:
		if err != nil {
			t.Fatalf("DestroyUA: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DestroyUA never returned after the BYE was answered")
	}
}

// TestCreateCallRejectsAUAMidTeardown is D63's regression test. destroyUA
// MarkDestroys a UA and releases the registry lock BEFORE the BYE grace
// period, but RecordUADestroyed — which removes the handle from
// s.liveUAs — does not run until teardown step 4, after that grace period.
// Without a State() check, CreateCall admits a new call on a UA that is
// already mid-teardown; that call is never BYEd and holds a
// max_concurrent_calls_total slot and an active_calls count forever, with no
// UA left to hang up through. Nothing could MarkDestroyed a UA before
// destroyUA existed, so this hole is one this task's own change created
// (Rule 19), not scope creep.
func TestCreateCallRejectsAUAMidTeardown(t *testing.T) {
	agent := newBlockingAgent()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, nil), Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}
	c.setDialogIdentity("dlg-1", "callid-1")

	// Start the teardown; its BYE parks in the fake agent, so the UA is now
	// MarkDestroyed and mid-BYE — the window this test exists to probe.
	destroyDone := make(chan error, 1)
	go func() {
		_, err := m.DestroyUA(context.Background(), string(ua.Handle()))
		destroyDone <- err
	}()
	select {
	case <-agent.hangupEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("teardown never reached the BYE")
	}
	t.Cleanup(func() {
		close(agent.release)
		<-destroyDone //nolint:errcheck // cleanup only waits for the destroy to finish
	})

	if got := ua.State(); got != UADestroyed {
		t.Fatalf("ua.State() = %q, want %q before proceeding — the hole this test guards "+
			"exists only in this window", got, UADestroyed)
	}

	// THE ASSERTION. Without the fix, this call is admitted and never BYEd.
	_, err = m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != apierr.CodeNotFound {
		t.Fatalf("CreateCall on a UA already MarkDestroyed and mid-BYE: err = %v, want "+
			"not_found — without the fix this call is admitted, holds a "+
			"max_concurrent_calls_total slot forever, and has no UA left to hang up through", err)
	}
}

// recordingAgent records the ORDER of the transport calls a teardown makes.
// The order is the assertion: §10.2 and §12.7 both specify BYE -> Unregister ->
// Close, and unregistering first would leave the in-dialog BYEs routing to an
// address the registrar no longer advertises.
type recordingAgent struct {
	nopAgent
	seq []string
}

func (a *recordingAgent) Hangup(_ context.Context, dialogID, _ string) error {
	a.seq = append(a.seq, "BYE:"+dialogID)
	return nil
}
func (a *recordingAgent) Unregister(context.Context) error {
	a.seq = append(a.seq, "REGISTER-Expires-0")
	return nil
}
func (a *recordingAgent) Close(context.Context) error {
	a.seq = append(a.seq, "CLOSE")
	return nil
}

// TestBothEntryPointsDriveOneTeardown is contract Part 4.1's acceptance and
// §14.2's admin-plane row verbatim: drive BOTH paths against the same fixture
// and compare the observed BYE and Expires: 0 sequences. THEY MUST BE
// IDENTICAL. A divergence means a second teardown path exists, which §12.7
// names as the defect this design avoids.
func TestBothEntryPointsDriveOneTeardown(t *testing.T) {
	run := func(t *testing.T, viaAdmin bool) []string {
		t.Helper()
		agent := &recordingAgent{}
		fc := newFakeClock()
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		m, err := NewManager(ManagerConfig{
			Ctx:    ctx,
			Clock:  fc,
			Policy: newTestStore(t, fc, nil),
			Logger: testLogger(),
			NewUA: func(context.Context, UAConfig) (UserAgent, error) {
				return agent, nil
			},
		})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		if err := m.Open(ctx, "s1"); err != nil {
			t.Fatalf("Open: %v", err)
		}
		ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "register", Transport: TransportUDP,
			AOR: "sip:t@example"})
		if err != nil {
			t.Fatalf("CreateUA: %v", err)
		}
		ua.setRegistered(true)
		c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
		if err != nil {
			t.Fatalf("CreateCall: %v", err)
		}
		c.setDialogIdentity("dlg-1", "callid-1")

		var res AdminDestroyed
		if viaAdmin {
			res, err = m.DestroyUA(ctx, string(ua.Handle()))
		} else {
			res, err = m.UADestroy(ctx, "s1", ua.Handle())
		}
		if err != nil {
			t.Fatalf("teardown: %v", err)
		}
		if !res.Unregistered {
			t.Error("Unregistered = false, want true")
		}
		if res.CallsTerminated != 1 {
			t.Errorf("CallsTerminated = %d, want 1", res.CallsTerminated)
		}
		if res.Session != "s1" {
			t.Errorf("Session = %q, want s1 — the AUDIT line needs it (§12.7)", res.Session)
		}
		if got := c.TerminationReason(); got != "local_hangup" {
			t.Errorf("termination_reason = %q, want local_hangup — §10.3's enum gains no "+
				"new value for an admin teardown (§12.7)", got)
		}
		return agent.seq
	}

	viaTool := run(t, false)
	viaAdmin := run(t, true)

	want := []string{"BYE:dlg-1", "REGISTER-Expires-0", "CLOSE"}
	for _, tc := range []struct {
		name string
		got  []string
	}{{"ua_destroy", viaTool}, {"admin DELETE", viaAdmin}} {
		if len(tc.got) != len(want) {
			t.Fatalf("%s: sequence %v, want %v", tc.name, tc.got, want)
		}
		for i := range want {
			if tc.got[i] != want[i] {
				t.Fatalf("%s: step %d = %q, want %q (order is load-bearing: unregistering "+
					"before the BYEs routes them to an address the registrar no longer "+
					"advertises)", tc.name, i, tc.got[i], want[i])
			}
		}
	}
	// The point of the test, stated as an assertion rather than left implicit.
	for i := range viaTool {
		if viaTool[i] != viaAdmin[i] {
			t.Fatalf("the two entry points diverged at step %d: %q vs %q — §12.7 requires ONE "+
				"teardown implementation, and a second one is a second set of bugs",
				i, viaTool[i], viaAdmin[i])
		}
	}
}

func TestDestroyOwnershipAndIdempotence(t *testing.T) {
	// RegistryRetention is set SHORTER than SessionResumeWindow (Phase 1
	// adjustment: with the strict one-UA-per-session cap there is no
	// "keeper" UA left to hold s1 open indefinitely — see the comment below
	// — so the two windows must be told apart to catch `ua`'s tombstone
	// mid-flight, after RegistryRetention evicts it but before
	// SessionResumeWindow would also delete the now-empty s1).
	m, fc := newManagerWith(t, func(l *policy.Limits) {
		l.RegistryRetention = policy.Duration(30 * time.Minute)
		l.SessionResumeWindow = policy.Duration(time.Hour)
	})
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open(s1): %v", err)
	}
	if err := m.Open(ctx, "s2"); err != nil {
		t.Fatalf("Open(s2): %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	// Phase 1's STRICT one-UA-per-session model (owner-locked decision;
	// limits.max_uas_per_session defaults to 1) means s1 cannot hold a second
	// "keeper" UA any more. Once `ua` is destroyed, sessionEmptyLocked(s1)
	// becomes true as soon as JanitorSweep evicts its tombstone — which is
	// why RegistryRetention is set below SessionResumeWindow above: a single
	// sweep AFTER RegistryRetention but BEFORE SessionResumeWindow evicts
	// `ua` into s1.uaTombstones without also deleting s1 itself, leaving the
	// `gone` tombstone this test means to exercise still reachable.

	// R11: a non-owning session gets not_found, NEVER denied — `denied` would
	// disclose that the handle exists.
	_, err = m.UADestroy(ctx, "s2", ua.Handle())
	assertCode(t, err, apierr.CodeNotFound)

	// ...while the admin DELETE on the SAME handle succeeds. That asymmetry is
	// the entire reason §12.7 exists: the operator can reclaim what no session
	// can reach.
	if _, err := m.DestroyUA(ctx, string(ua.Handle())); err != nil {
		t.Fatalf("admin DELETE on a live UA: %v", err)
	}

	// Repeating the DELETE returns 404 (§12.7) — MarkDestroyed already lost.
	_, err = m.DestroyUA(ctx, string(ua.Handle()))
	assertCode(t, err, apierr.CodeNotFound)

	// The owner's ua_destroy on the now-destroyed UA likewise.
	_, err = m.UADestroy(ctx, "s1", ua.Handle())
	assertCode(t, err, apierr.CodeNotFound)

	// §N3: the terminated entry is left behind, so the OWNER still resolves the
	// handle inside the retention window, and gets `gone` after it.
	if _, err := m.ResolveUA(ctx, "s1", ua.Handle()); err != nil {
		t.Fatalf("owner resolve inside the retention window: %v, want ok", err)
	}
	fc.Advance(35 * time.Minute) // past RegistryRetention (30m), short of SessionResumeWindow (1h)
	m.JanitorSweep(fc.Now())
	_, err = m.ResolveUA(ctx, "s1", ua.Handle())
	assertCode(t, err, apierr.CodeGone)
}

// TestConcurrentDestroyHasExactlyOneWinner is §6.3's invariant at the UA level.
// ua_destroy and the admin DELETE racing on one UA must not both tear down.
func TestConcurrentDestroyHasExactlyOneWinner(t *testing.T) {
	const iterations = 500
	for i := 0; i < iterations; i++ {
		agent := &recordingAgent{}
		fc := newFakeClock()
		ctx, cancel := context.WithCancel(context.Background())
		m, err := NewManager(ManagerConfig{
			Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, nil), Logger: testLogger(),
			NewUA: func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
		})
		if err != nil {
			cancel()
			t.Fatalf("NewManager: %v", err)
		}
		if err := m.Open(ctx, "s1"); err != nil {
			cancel()
			t.Fatalf("Open: %v", err)
		}
		ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
		if err != nil {
			cancel()
			t.Fatalf("CreateUA: %v", err)
		}

		var barrier, wg sync.WaitGroup
		barrier.Add(1)
		errs := make([]error, 2)
		wg.Add(2)
		go func() { defer wg.Done(); barrier.Wait(); _, errs[0] = m.UADestroy(ctx, "s1", ua.Handle()) }()
		go func() {
			defer wg.Done()
			barrier.Wait()
			_, errs[1] = m.DestroyUA(ctx, string(ua.Handle()))
		}()
		barrier.Done()
		wg.Wait()

		oks := 0
		for _, err := range errs {
			if err == nil {
				oks++
				continue
			}
			var ae *apierr.Error
			if !errors.As(err, &ae) || ae.Code != apierr.CodeNotFound {
				cancel()
				t.Fatalf("iteration %d: loser err = %v, want not_found", i, err)
			}
		}
		if oks != 1 {
			cancel()
			t.Fatalf("iteration %d: %d teardowns succeeded, want exactly 1 — MarkDestroyed "+
				"is what makes ua_destroy and the admin DELETE safe to race", i, oks)
		}
		cancel()
	}
}

// TestLiveUAsIsALiveObjectViewOnly pins two §12.7 boundaries at once: the view
// lists LIVE UAs only (not §N3's retention view), and it carries NO call
// handle, so R11 cannot regress through this surface.
func TestLiveUAsIsALiveObjectViewOnly(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Phase 1's STRICT one-UA-per-session model (owner-locked decision):
	// `gone` moves to its OWN session s2 — LiveUAs is a SERVER-WIDE view, so
	// which session owns which UA is immaterial to what this test asserts.
	if err := m.Open(ctx, "s2"); err != nil {
		t.Fatalf("Open(s2): %v", err)
	}
	keep, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "register", Transport: TransportUDP,
		AOR: "sip:keep@example"})
	if err != nil {
		t.Fatalf("CreateUA(keep): %v", err)
	}
	keep.setRegistered(true)
	if _, err := m.CreateCall(ctx, "s1", keep.Handle(), Outbound, StateAnswered); err != nil {
		t.Fatalf("CreateCall: %v", err)
	}
	gone, err := m.CreateUA(ctx, "s2", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA(gone): %v", err)
	}
	if _, err := m.DestroyUA(ctx, string(gone.Handle())); err != nil {
		t.Fatalf("DestroyUA: %v", err)
	}

	views := m.LiveUAs(ctx)
	if len(views) != 1 {
		t.Fatalf("LiveUAs returned %d, want 1 — a destroyed UA is retained by §N3 but is "+
			"NOT a live object (§12.7)", len(views))
	}
	v := views[0]
	if v.UAHandle != string(keep.Handle()) {
		t.Errorf("ua_handle = %q, want %q", v.UAHandle, keep.Handle())
	}
	if v.Session != "s1" {
		t.Errorf("session = %q, want s1", v.Session)
	}
	if v.ActiveCalls != 1 {
		t.Errorf("active_calls = %d, want 1", v.ActiveCalls)
	}
	if !v.Registered {
		t.Error("registered = false, want true")
	}
	if v.Mode != "register" || v.AOR != "sip:keep@example" || v.Transport != "udp" {
		t.Errorf("config fields = %q/%q/%q, want register/sip:keep@example/udp",
			v.Mode, v.AOR, v.Transport)
	}
	if v.SessionLastSeenAt.IsZero() {
		t.Error("session_last_seen_at is zero; §12.7 needs it to judge strandedness")
	}

	// R11: the marshalled view must contain no call_handle key. Asserted over
	// the raw JSON, because a field added later would otherwise slip through.
	raw, err := json.Marshal(views)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(raw, []byte("call_handle")) {
		t.Fatalf("admin view contains a call_handle: %s — §12.7 exposes no call handle and "+
			"no call content, so R11 cannot regress through this surface", raw)
	}

	// AdminDestroyed likewise carries the session id for the AUDIT line but not
	// in the response BODY (§12.7).
	body, err := json.Marshal(AdminDestroyed{UAHandle: "ua_x", Session: "s_secret"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(body, []byte("s_secret")) {
		t.Fatalf("DELETE body carries the session id: %s — §12.7 puts it in the audit line "+
			"ONLY; it is a §12.6 credential factor", body)
	}
}

// statusAgent records which teardown steps actually ran and what each one
// observed about its context. Unlike blockingAgent it does not park; it
// answers immediately, so the test is deterministic with no clock work.
//
// Named distinctly from recordingAgent (which records call ORDER): this type
// records call OUTCOME and per-step context state, a different shape used by
// exactly one test.
type statusAgent struct {
	nopAgent
	mu           sync.Mutex
	unregistered bool
	closed       bool
	byeCount     int
	sawCancelled bool // any teardown step received an already-cancelled context
}

func (a *statusAgent) note(ctx context.Context) {
	if ctx.Err() != nil {
		a.sawCancelled = true
	}
}

func (a *statusAgent) Hangup(ctx context.Context, _ string, _ string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.note(ctx)
	a.byeCount++
	return ctx.Err()
}

func (a *statusAgent) Unregister(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.note(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	a.unregistered = true
	return nil
}

func (a *statusAgent) Close(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.note(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	a.closed = true
	return nil
}

func (a *statusAgent) snapshot() (unregistered, closed, sawCancelled bool, byes int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.unregistered, a.closed, a.sawCancelled, a.byeCount
}

// TestTeardownRunsOnTheDaemonContextNotTheCallers is locked decision 17, path 3.
//
// THE CALLER'S CONTEXT IS CANCELLED BEFORE destroyUA IS EVEN ENTERED, which is
// the strongest form of the operator's `curl` timing out or a reverse proxy
// giving up below the 10s grace period. Every teardown step must nevertheless
// run to completion, because it runs on m.daemonCtx.
func TestTeardownRunsOnTheDaemonContextNotTheCallers(t *testing.T) {
	agent := &statusAgent{}
	fc := newFakeClock()
	daemonCtx, cancelDaemon := context.WithCancel(context.Background())
	t.Cleanup(cancelDaemon)

	p := policy.Defaults()
	p.Limits.ShutdownGracePeriod = policy.Duration(10 * time.Second)
	m, err := NewManager(ManagerConfig{
		Ctx: daemonCtx, Clock: fc, Policy: policy.NewStaticStore(p, fc, testLogger()),
		Logger: testLogger(),
		NewUA:  func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(daemonCtx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(daemonCtx, "s1", UAConfig{Mode: "register", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	ua.setRegistered(true)
	c, err := m.CreateCall(daemonCtx, "s1", ua.Handle(), Outbound, StateAnswered)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}
	c.setDialogIdentity("dlg-1", "callid-1@203.0.113.4")

	// The operator's client is already gone.
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	cancelCaller()

	res, err := m.DestroyUA(callerCtx, string(ua.Handle()))
	if err != nil {
		t.Fatalf("admin DELETE with a cancelled caller context: %v — the teardown must "+
			"run on the daemon context and must not fail because the client hung up", err)
	}

	unregistered, closed, sawCancelled, byes := agent.snapshot()
	if sawCancelled {
		t.Fatal("a teardown step received an ALREADY-CANCELLED context: the caller's " +
			"request context was threaded into the teardown (decision 17, path 3). " +
			"destroyUA must derive its context from m.daemonCtx")
	}
	if byes != 1 {
		t.Fatalf("BYEs sent = %d, want 1", byes)
	}
	if !unregistered {
		t.Fatal("NO `REGISTER Expires: 0` WAS SENT. The registration is still live at " +
			"the registrar while the handle has left every view and max_uas_total has " +
			"been decremented — §12.7's unreclaimable state, re-created one level down")
	}
	if !closed {
		t.Fatal("the transport was never closed: the UDP socket is leaked for the life " +
			"of the daemon, and no path in the design can reclaim it")
	}
	if !res.Unregistered {
		t.Fatalf("AdminDestroyed.Unregistered = false, want true — the response told the "+
			"operator the deregistration did not happen when it did: %+v", res)
	}
	if res.CallsTerminated != 1 {
		t.Fatalf("calls_terminated = %d, want 1", res.CallsTerminated)
	}

	// And the §12.2.2 slot was freed despite the cancelled caller context.
	if perSession, total := m.DebugLiveCallCounts("s1"); perSession != 0 || total != 0 {
		t.Fatalf("live call counts = (%d, %d) after teardown, want (0, 0)", perSession, total)
	}
}

// countingAgent records the registry's live-call total as observed from INSIDE
// each Hangup call. It reads the counts through the Manager's own accessor, and
// destroyUA has already released m.mu before its BYE loop, so this neither
// deadlocks nor needs a fake registry.
type countingAgent struct {
	nopAgent
	mu       sync.Mutex
	m        *Manager
	observed []int
}

func (a *countingAgent) Hangup(_ context.Context, _ string, _ string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, total := a.m.DebugLiveCallCounts("s1")
	a.observed = append(a.observed, total)
	return nil
}

func (a *countingAgent) seen() []int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]int(nil), a.observed...)
}

// TestTeardownRecordsEachCallBeforeTheNextBye is §6.0b INV-1 FORM B (U23).
func TestTeardownRecordsEachCallBeforeTheNextBye(t *testing.T) {
	agent := &countingAgent{}
	fc := newFakeClock()
	daemonCtx, cancelDaemon := context.WithCancel(context.Background())
	t.Cleanup(cancelDaemon)

	p := policy.Defaults()
	p.Limits.ShutdownGracePeriod = policy.Duration(10 * time.Second)
	m, err := NewManager(ManagerConfig{
		Ctx: daemonCtx, Clock: fc, Policy: policy.NewStaticStore(p, fc, testLogger()),
		Logger: testLogger(),
		NewUA:  func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	agent.m = m
	if err := m.Open(daemonCtx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(daemonCtx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	for i, id := range []string{"dlg-a", "dlg-b"} {
		c, err := m.CreateCall(daemonCtx, "s1", ua.Handle(), Outbound, StateAnswered)
		if err != nil {
			t.Fatalf("CreateCall %d: %v", i, err)
		}
		c.setDialogIdentity(id, "callid-"+id+"@203.0.113.4")
	}
	if _, total := m.DebugLiveCallCounts("s1"); total != 2 {
		t.Fatalf("live calls before teardown = %d, want 2", total)
	}

	res, err := m.DestroyUA(daemonCtx, string(ua.Handle()))
	if err != nil {
		t.Fatalf("DestroyUA: %v", err)
	}
	if res.CallsTerminated != 2 {
		t.Fatalf("calls_terminated = %d, want 2", res.CallsTerminated)
	}

	got := agent.seen()
	want := []int{2, 1}
	if len(got) != len(want) {
		t.Fatalf("BYEs written = %d, want %d (observed live totals %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("live-call total observed during BYE %d = %d, want %d (full "+
				"sequence %v, want %v). Every value equal to 2 means RecordTermination "+
				"is DEFERRED to destroyUA's exit instead of running per iteration — "+
				"§6.0b INV-1 Form A inside a loop body, which contract §5.6 U23 "+
				"FORBIDS. Under it, call 1's §12.2.2 slot, its active_calls count and "+
				"its ladder retention stay held until call N's BYE completes, for the "+
				"full shutdown_grace_period, on a far end that never answers",
				i+1, got[i], want[i], got, want)
		}
	}

	// And the loop still finished the job it was deferring nothing for.
	if perSession, total := m.DebugLiveCallCounts("s1"); perSession != 0 || total != 0 {
		t.Fatalf("live call counts after teardown = (%d, %d), want (0, 0)", perSession, total)
	}
}

// TestUADestroyAndAdminDestroyBothAnswerGoneForTheRetentionWindow pins the
// convergence the multi-UA-per-session wave introduces: Phase 1's ONE
// observable difference between the two teardown entry points (agent
// ua_destroy answering not_found immediately, because it deleted the whole
// session record; admin DELETE answering gone for the full retention window,
// because it didn't) no longer exists. ua_destroy stops deleting the session
// record, so its handle now sits in terminatedUAs exactly like the admin
// path's does, and answers gone on the same clock.
//
// The two halves run against one fixture shape and one clock so the
// convergence is the assertion rather than two separately-arranged claims.
func TestUADestroyAndAdminDestroyBothAnswerGoneForTheRetentionWindow(t *testing.T) {
	t.Run("agent ua_destroy: resolvable immediately, gone within registry_retention — same as admin DELETE", func(t *testing.T) {
		fc := newFakeClock()
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		m, err := NewManager(ManagerConfig{
			Ctx: ctx, Clock: fc, Logger: testLogger(),
			Policy: newTestStore(t, fc, func(l *policy.Limits) {
				l.RegistryRetention = policy.Duration(30 * time.Minute)
				l.SessionResumeWindow = policy.Duration(time.Hour)
			}),
			NewUA: func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
		})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		if err := m.Open(ctx, "s1"); err != nil {
			t.Fatalf("Open: %v", err)
		}
		ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
		if err != nil {
			t.Fatalf("CreateUA: %v", err)
		}

		if _, err := m.UADestroy(ctx, "s1", ua.Handle()); err != nil {
			t.Fatalf("UADestroy: %v", err)
		}

		// NO CLOCK ADVANCE: the destroyed handle sits in terminatedUAs and is
		// still resolvable (not an error), same as the admin path — the
		// divergence Phase 1 accepted (agent path deleting the whole session,
		// so the tombstone was gone before it could ever be seen) no longer
		// applies once ua_destroy stops deleting the session record.
		if _, err := m.ResolveUA(ctx, "s1", ua.Handle()); err != nil {
			t.Fatalf("ResolveUA immediately after ua_destroy: %v, want ok — this path "+
				"does NOT delete the session", err)
		}

		fc.Advance(35 * time.Minute) // past RegistryRetention, short of SessionResumeWindow
		m.JanitorSweep(fc.Now())
		_, err = m.ResolveUA(ctx, "s1", ua.Handle())
		assertCode(t, err, apierr.CodeGone) // §N3, now the SAME on both paths
	})

	t.Run("admin DELETE: gone for the retention window, as §N3 requires", func(t *testing.T) {
		fc := newFakeClock()
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		m, err := NewManager(ManagerConfig{
			Ctx: ctx, Clock: fc, Logger: testLogger(),
			Policy: newTestStore(t, fc, func(l *policy.Limits) {
				// RegistryRetention below SessionResumeWindow, so a single
				// sweep past the retention window evicts the UA into the
				// session's tombstone ring WITHOUT also dropping the session
				// record — which is what makes `gone` reachable at all.
				l.RegistryRetention = policy.Duration(30 * time.Minute)
				l.SessionResumeWindow = policy.Duration(time.Hour)
			}),
			NewUA: func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
		})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		if err := m.Open(ctx, "s1"); err != nil {
			t.Fatalf("Open: %v", err)
		}
		ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
		if err != nil {
			t.Fatalf("CreateUA: %v", err)
		}

		if _, err := m.DestroyUA(ctx, string(ua.Handle())); err != nil {
			t.Fatalf("admin DestroyUA: %v", err)
		}

		// The session record is untouched, so the terminated entry is still
		// resolvable inside the retention window.
		if _, err := m.ResolveUA(ctx, "s1", ua.Handle()); err != nil {
			t.Fatalf("owner resolve inside the retention window after an admin "+
				"DELETE: %v, want ok — this path does NOT delete the session", err)
		}

		fc.Advance(35 * time.Minute) // past RegistryRetention, short of SessionResumeWindow
		m.JanitorSweep(fc.Now())
		_, err = m.ResolveUA(ctx, "s1", ua.Handle())
		assertCode(t, err, apierr.CodeGone) // §N3, unchanged on this path
	})
}

// TestUADestroyOnOneUALeavesSiblingUAsAndTheSessionLive is the multi-UA-per-
// session wave's headline contract: destroying one UA in a session that
// holds several is observably "destroy h", nothing more — every sibling UA,
// and the session itself, are completely unaffected.
func TestUADestroyOnOneUALeavesSiblingUAsAndTheSessionLive(t *testing.T) {
	m, _ := newManagerWith(t, func(l *policy.Limits) { l.MaxUAsPerSession = 4 })
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	caller, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA caller: %v", err)
	}
	callee, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA callee: %v", err)
	}

	if _, err := m.UADestroy(ctx, "s1", callee.Handle()); err != nil {
		t.Fatalf("UADestroy(callee): %v", err)
	}

	if !m.Alive("s1") {
		t.Fatal("Alive(s1) = false after destroying one of two UAs, want true")
	}
	if _, err := m.ResolveUA(ctx, "s1", caller.Handle()); err != nil {
		t.Fatalf("ResolveUA(caller) after destroying callee: %v, want ok — caller is untouched", err)
	}
	// callee is still resolvable immediately (its tombstone entry sits in
	// terminatedUAs until registry_retention elapses — see
	// TestUADestroyAndAdminDestroyBothAnswerGoneForTheRetentionWindow for the
	// eventual gone/not_found transition); the point THIS test pins is that
	// destroying callee did not touch caller or the session, not the
	// retention-window mechanics themselves.
	if _, err := m.ResolveUA(ctx, "s1", callee.Handle()); err != nil {
		t.Fatalf("ResolveUA(callee) immediately after its own destroy: %v, want ok", err)
	}
}
