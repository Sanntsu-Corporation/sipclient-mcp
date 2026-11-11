package fakes_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

func TestAdminFakeListsAndDestroys(t *testing.T) {
	ctx := context.Background()
	a := fakes.NewAdmin()
	a.AddUA(fakes.UA{
		UAHandle: "ua_7f2a", Session: "44b1c0de", Mode: "register",
		AOR: "sip:testuser@carrier-a.example", Transport: "udp",
		Registered: true, ActiveCalls: 2,
	})
	a.AddUA(fakes.UA{UAHandle: "ua_1122", Session: "s2", Mode: "direct"})
	a.AddDestroyedUA("ua_dead")

	// The GET is a LIVE-OBJECT view: an already-destroyed handle is absent.
	got := a.LiveUAs(ctx)
	if len(got) != 2 {
		t.Fatalf("LiveUAs = %d entries, want 2 (a destroyed UA must not be listed)", len(got))
	}
	// Every field AddUA was given must survive into the AdminUAView, and the
	// two timestamps must be NON-ZERO — P1d asserts the JSON carries
	// created_at and session_last_seen_at.
	if got[0].AOR != "sip:testuser@carrier-a.example" || got[0].Transport != "udp" ||
		!got[0].Registered || got[0].ActiveCalls != 2 {
		t.Errorf("AdminUAView = %+v", got[0])
	}
	if got[0].CreatedAt.IsZero() || got[0].SessionLastSeenAt.IsZero() {
		t.Error("AddUA left a zero timestamp; P1d asserts both keys are present and meaningful")
	}

	res, err := a.DestroyUA(ctx, "ua_7f2a")
	if err != nil {
		t.Fatalf("DestroyUA: %v", err)
	}
	if res.UAHandle != "ua_7f2a" || !res.Unregistered || res.CallsTerminated != 2 {
		t.Errorf("AdminDestroyed = %+v, want {ua_7f2a true 2}", res)
	}
	if a.Live("ua_7f2a") {
		t.Error("DELETE left the UA live; it destroys")
	}
	if len(a.LiveUAs(ctx)) != 1 {
		t.Error("LiveUAs did not shrink after the DELETE")
	}

	// §12.7 is NOT an adoption path: ownership survives the destruction.
	if a.OwnerOf("ua_7f2a") != "44b1c0de" {
		t.Errorf("OwnerOf after DELETE = %q, want the original owner", a.OwnerOf("ua_7f2a"))
	}
	// §12.7 introduces NO new termination_reason.
	if r := a.TerminationReason("ua_7f2a"); r != "local_hangup" {
		t.Errorf("TerminationReason = %q, want local_hangup", r)
	}

	// A REPEATED DELETE is 404, and — the Rule 16 point — it runs NO second
	// teardown. A destroyed handle and a never-issued one behave alike here.
	for _, h := range []string{"ua_7f2a", "ua_dead", "ua_neverexisted"} {
		_, err := a.DestroyUA(ctx, h)
		var ae *apierr.Error
		if !errors.As(err, &ae) || ae.Code != apierr.CodeNotFound {
			t.Errorf("DestroyUA(%s) err = %v, want code %q", h, err, apierr.CodeNotFound)
		}
	}
	if n := a.TeardownCalls("ua_7f2a"); n != 1 {
		t.Errorf("TeardownCalls = %d after one real teardown plus a failed repeat, want 1", n)
	}
}

// TestAdminFakeTeardownCounterIsReal is the ANTI-VACUOUS-GREEN control for
// TeardownCalls. P1d asserts `TeardownCalls == 1` to prove Rule 16 — that the
// admin DELETE and ua_destroy drive ONE teardown, not two. A counter hardcoded
// to 1, or one that merely records "was called", would make that assertion
// pass against a genuine double-teardown. So: drive two REAL teardowns of the
// same handle and require the counter to distinguish them.
func TestAdminFakeTeardownCounterIsReal(t *testing.T) {
	ctx := context.Background()
	a := fakes.NewAdmin()

	a.AddUA(fakes.UA{UAHandle: "ua_x", Session: "s1", Registered: true, ActiveCalls: 1})
	if _, err := a.DestroyUA(ctx, "ua_x"); err != nil {
		t.Fatalf("first DestroyUA: %v", err)
	}
	if n := a.TeardownCalls("ua_x"); n != 1 {
		t.Fatalf("TeardownCalls after one teardown = %d, want 1", n)
	}

	// Re-add the same handle and tear it down again: a real counter reads 2.
	a.AddUA(fakes.UA{UAHandle: "ua_x", Session: "s1"})
	if _, err := a.DestroyUA(ctx, "ua_x"); err != nil {
		t.Fatalf("second DestroyUA: %v", err)
	}
	if n := a.TeardownCalls("ua_x"); n != 2 {
		t.Fatalf("TeardownCalls after TWO teardowns = %d, want 2 — the counter cannot "+
			"distinguish one teardown from two, so P1d's Rule 16 assertion would be vacuous", n)
	}
	if n := a.TeardownCalls("ua_never"); n != 0 {
		t.Errorf("TeardownCalls for an untouched handle = %d, want 0", n)
	}
}

// TestAdminFakeTeardownDelayReallyBlocks is the ANTI-VACUOUS-GREEN control for
// SetTeardownDelay. P1d's TestAdminDeleteDoesNotStallTools sets it to the full
// 10 s grace period and asserts an unrelated tool call still returns inside
// N2's 50 ms budget; if the delay did not actually block, that test would pass
// on a server that serialises every admin DELETE against every tool call.
//
// A short delay is used here — the property is "it blocks for about the
// configured time", not "it blocks for ten seconds".
func TestAdminFakeTeardownDelayReallyBlocks(t *testing.T) {
	ctx := context.Background()
	a := fakes.NewAdmin()
	a.AddUA(fakes.UA{UAHandle: "ua_slow", Session: "s1"})
	a.AddUA(fakes.UA{UAHandle: "ua_fast", Session: "s1"})
	a.SetTeardownDelay("ua_slow", 150*time.Millisecond)

	start := time.Now()
	if _, err := a.DestroyUA(ctx, "ua_slow"); err != nil {
		t.Fatalf("DestroyUA: %v", err)
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Fatalf("a delayed teardown returned in %v; SetTeardownDelay does not actually "+
			"block, so P1d's no-serialization test would prove nothing", d)
	}

	// An undelayed handle is unaffected — the delay is per-handle, not global.
	start = time.Now()
	if _, err := a.DestroyUA(ctx, "ua_fast"); err != nil {
		t.Fatalf("DestroyUA: %v", err)
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("an undelayed teardown took %v; the delay must be per-handle", d)
	}
}

// TestAdminFakeDelayDoesNotHoldTheMutex mirrors, at the fake's own level, the
// property contract Part 4.2 requires of the real manager: the lock is
// released BEFORE the BYE grace period begins. If the fake slept under its
// mutex it would serialise concurrent admin requests all by itself and hand
// P1d's no-serialization test a false positive.
func TestAdminFakeDelayDoesNotHoldTheMutex(t *testing.T) {
	ctx := context.Background()
	a := fakes.NewAdmin()
	a.AddUA(fakes.UA{UAHandle: "ua_slow", Session: "s1"})
	a.SetTeardownDelay("ua_slow", 300*time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = a.DestroyUA(ctx, "ua_slow")
	}()

	time.Sleep(50 * time.Millisecond) // let the teardown enter its delay

	start := time.Now()
	_ = a.LiveUAs(ctx)
	_ = a.TeardownCalls("ua_slow")
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("reading the fake took %v while a teardown was in its delay; the "+
			"mutex is held across the wait (contract Part 4.2 forbids exactly this)", d)
	}
	<-done
}

func TestToolsFakeRecordsPerToolWithItsSession(t *testing.T) {
	ctx := context.Background()
	tools := fakes.NewTools()
	tools.SetPayload("call_status", map[string]any{"state": "answered"})
	tools.SetErr("call_hangup", apierr.PreconditionFailed("call is already terminated"))

	if _, err := tools.CallDial(ctx, "s1", session.CallDialInput{}); err != nil {
		t.Fatalf("CallDial: %v", err)
	}
	out, err := tools.CallStatus(ctx, "s1", session.CallStatusInput{})
	if err != nil {
		t.Fatalf("CallStatus: %v", err)
	}
	if m, ok := out.(map[string]any); !ok || m["state"] != "answered" {
		t.Errorf("CallStatus payload = %#v", out)
	}

	_, err = tools.CallHangup(ctx, "s2", session.CallHangupInput{})
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != apierr.CodePreconditionFailed {
		t.Errorf("CallHangup err = %v, want code %q", err, apierr.CodePreconditionFailed)
	}

	// The SESSION ID must reach the method: R11 isolation is decided on it,
	// so a fake that dropped it would let an ownership bug pass unnoticed.
	if c := tools.CallsFor("call_dial"); len(c) != 1 || c[0].Session != "s1" {
		t.Errorf("call_dial calls = %+v", c)
	}
	if c := tools.CallsFor("call_hangup"); len(c) != 1 || c[0].Session != "s2" {
		t.Errorf("call_hangup calls = %+v", c)
	}
	if len(tools.Calls) != 3 {
		t.Errorf("recorded %d calls, want 3", len(tools.Calls))
	}

	// An UNSCRIPTED tool returns (nil, nil), which the §11.2 envelope renders
	// as ok:true with a null payload.
	got, err := tools.SessionKeepalive(ctx, "s1", session.SessionKeepaliveInput{})
	if got != nil || err != nil {
		t.Errorf("unscripted SessionKeepalive = (%v, %v), want (nil, nil)", got, err)
	}

	// LastSession is what P1d uses to prove the §12.6 logical session id
	// reaches the tool layer.
	if s := tools.LastSession("call_hangup"); s != "s2" {
		t.Errorf("LastSession(call_hangup) = %q, want s2", s)
	}
	if s := tools.LastSession("never_called"); s != "" {
		t.Errorf("LastSession for an uncalled tool = %q, want \"\"", s)
	}

	// LastEnvelopeCode/Rule render the §11.2 shape P1d asserts on.
	if c := tools.LastEnvelopeCode("call_hangup"); c != string(apierr.CodePreconditionFailed) {
		t.Errorf("LastEnvelopeCode(call_hangup) = %q", c)
	}
	if c := tools.LastEnvelopeCode("call_status"); c != "" {
		t.Errorf("LastEnvelopeCode for a SUCCESSFUL call = %q, want \"\"", c)
	}
}

// TestToolsFakeUALimitTracksTheAdminLive is the ANTI-VACUOUS-GREEN control for
// BindUALimit. P1d's §12.7 exhaustion-recovery test asserts ua_create is
// denied with resource_limit/max_uas_total while the server is full and
// SUCCEEDS once the admin DELETE frees the slots — the whole justification for
// the admin plane existing. A BindUALimit that always denied, or always
// allowed, would make one half of that pass vacuously, so both transitions are
// asserted here.
func TestToolsFakeUALimitTracksTheAdminLive(t *testing.T) {
	ctx := context.Background()
	adm := fakes.NewAdmin()
	adm.SetMaxUAsTotal(2)
	adm.AddUA(fakes.UA{UAHandle: "ua_1", Session: "s1", Registered: true, ActiveCalls: 1})
	adm.AddUA(fakes.UA{UAHandle: "ua_2", Session: "s1", Mode: "direct"})

	tools := fakes.NewTools()
	tools.BindUALimit(adm)

	// FULL: denied, naming the exact policy key with its limit and current.
	_, err := tools.UACreate(ctx, "fresh", session.UACreateInput{})
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != apierr.CodeResourceLimit {
		t.Fatalf("ua_create at the cap err = %v, want code %q", err, apierr.CodeResourceLimit)
	}
	if ae.Rule != "max_uas_total" {
		t.Errorf("denial rule = %q, want max_uas_total", ae.Rule)
	}
	if ae.Limit == nil || *ae.Limit != 2 || ae.Current == nil || *ae.Current != 2 {
		t.Errorf("denial limit/current = %v/%v, want 2/2", ae.Limit, ae.Current)
	}
	if c := tools.LastEnvelopeCode("ua_create"); c != "resource_limit" {
		t.Errorf("LastEnvelopeCode = %q, want resource_limit", c)
	}
	if r := tools.LastEnvelopeRule("ua_create"); r != "max_uas_total" {
		t.Errorf("LastEnvelopeRule = %q, want max_uas_total", r)
	}

	// RECLAIMED: the admin DELETE frees both slots and ua_create succeeds.
	for _, h := range []string{"ua_1", "ua_2"} {
		if _, err := adm.DestroyUA(ctx, h); err != nil {
			t.Fatalf("DestroyUA(%s): %v", h, err)
		}
	}
	if _, err := tools.UACreate(ctx, "fresh", session.UACreateInput{}); err != nil {
		t.Fatalf("ua_create after reclamation: %v, want success", err)
	}
	if c := tools.LastEnvelopeCode("ua_create"); c != "" {
		t.Fatalf("LastEnvelopeCode after reclamation = %q, want \"\" — the cap was "+
			"not released, so the limit is not being read live", c)
	}

	// UNBOUND Tools never denies: the limit is opt-in.
	plain := fakes.NewTools()
	if _, err := plain.UACreate(ctx, "s1", session.UACreateInput{}); err != nil {
		t.Errorf("an unbound Tools denied ua_create: %v", err)
	}
}

// TestToolsFakeDelayReallyBlocks is the ANTI-VACUOUS-GREEN control for
// SetDelay. P1d's TestN2LatencyBudget delays call_wait and asserts it is the
// ONLY tool exceeding N2's 50 ms budget — D2's async-returns-immediately
// invariant. A no-op delay would make that assertion meaningless.
func TestToolsFakeDelayReallyBlocks(t *testing.T) {
	ctx := context.Background()
	tools := fakes.NewTools()
	tools.SetDelay("call_wait", 150*time.Millisecond)

	start := time.Now()
	if _, err := tools.CallWait(ctx, "s1", session.CallWaitInput{}); err != nil {
		t.Fatalf("CallWait: %v", err)
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Fatalf("a delayed call_wait returned in %v; SetDelay does not block", d)
	}

	// Every other tool is unaffected — the delay is per-tool, and the mutex is
	// not held across it, so the twelve non-blocking tools are not serialised
	// behind call_wait.
	start = time.Now()
	if _, err := tools.CallStatus(ctx, "s1", session.CallStatusInput{}); err != nil {
		t.Fatalf("CallStatus: %v", err)
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("an undelayed tool took %v; the delay must be per-tool", d)
	}
}
