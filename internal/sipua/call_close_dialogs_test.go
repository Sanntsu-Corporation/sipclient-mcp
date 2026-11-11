package sipua

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	sippeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// CF-061, window W1, its wire consequence for an ESTABLISHED dialog: a
// call_hangup that won the session claim reaches sipua around UA.Close. The
// peer must receive exactly one BYE whichever of Close and that Hangup claims
// the dialog first.

// Close claims first: Close ends the established call with its one BYE while
// the transport is still open, and a late Hangup (for that id, or for an id
// never registered) returns nil without a second BYE.
func TestUAClosedByesAnEstablishedCallOnceAndALateHangupSucceeds(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	if err := r.answer(); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	r.ua.calls.mu.Lock()
	ml := r.d.mediaLoop
	r.ua.calls.mu.Unlock()
	if ml == nil {
		t.Fatal("the answered call has no media loop")
	}

	if err := r.ua.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r.assertNothingRunning()
	if !ml.isStopped() {
		t.Error("the media loop was not stopped inside Close")
	}
	waitFor(t, func() bool { return r.p.Count("BYE") == 1 })

	ctx := context.Background()
	if err := r.ua.Hangup(ctx, r.id, ""); err != nil {
		t.Errorf("late Hangup = %v, want nil", err)
	}
	if err := r.ua.Hangup(ctx, "no-such-id", ""); err != nil {
		t.Errorf("Hangup(no-such-id) on a closed UA = %v, want nil", err)
	}
	time.Sleep(500 * time.Millisecond) // bounded window for a second BYE
	if n := r.p.Count("BYE"); n != 1 {
		t.Errorf("peer received %d BYEs, want exactly 1", n)
	}
}

// Hangup claims first: its BYE is queued behind the dialog's send-order token
// (held by the test) when Close starts. Close must wait for that BYE instead of
// closing the transport underneath it.
func TestUAClosedWhileAHangupsByeIsQueuedStillSendsThatBye(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	if err := r.answer(); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	release := HoldSendOrderTokenForTest(t, r.ua, r.id)
	t.Cleanup(release)
	contended := signalContended(t)

	hang := r.hangupAsync(context.Background())
	waitByeContended(t, contended, "the Hangup's BYE")

	closed := make(chan error, 1)
	go func() { closed <- r.ua.Close(context.Background()) }()
	closeReturned := false
	select {
	case err := <-closed:
		closeReturned = true
		t.Errorf("Close returned within 200ms (err=%v) although a BYE is queued", err)
	case <-time.After(200 * time.Millisecond):
	}

	release()
	if !closeReturned {
		if err := recv(t, closed, 2*time.Second, "Close"); err != nil {
			t.Errorf("Close: %v", err)
		}
	}
	if err := recv(t, hang, 2*time.Second, "Hangup"); err != nil {
		t.Errorf("Hangup = %v, want nil", err)
	}
	waitFor(t, func() bool { return r.p.Count("BYE") == 1 })
	time.Sleep(500 * time.Millisecond) // bounded window for a second BYE
	if n := r.p.Count("BYE"); n != 1 {
		t.Errorf("peer received %d BYEs, want exactly 1", n)
	}
}

// signalContended installs inDialogSendContendedHook to report each send that
// finds its dialog's send-order token held (restored at cleanup).
func signalContended(t *testing.T) <-chan sip.RequestMethod {
	t.Helper()
	ch := make(chan sip.RequestMethod, 1)
	inDialogSendContendedHook = func(m sip.RequestMethod) {
		select {
		case ch <- m:
		default:
		}
	}
	t.Cleanup(func() { inDialogSendContendedHook = nil })
	return ch
}

func waitByeContended(t *testing.T, ch <-chan sip.RequestMethod, what string) {
	t.Helper()
	select {
	case m := <-ch:
		if m != sip.BYE {
			t.Fatalf("contended send = %s, want BYE", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s never queued behind the held send-order token", what)
	}
}

// Close's own BYE for a dialog it took over is queued behind the dialog's
// send-order token (held by the test): Close must wait for it instead of
// closing the transport underneath it.
func TestUAClosedWaitsForItsOwnQueuedBye(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	if err := r.answer(); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	release := HoldSendOrderTokenForTest(t, r.ua, r.id)
	t.Cleanup(release)
	contended := signalContended(t)

	closed := make(chan error, 1)
	go func() { closed <- r.ua.Close(context.Background()) }()
	waitByeContended(t, contended, "Close's own BYE")
	select {
	case err := <-closed:
		t.Fatalf("Close returned within 200ms (err=%v) although its own BYE is queued", err)
	case <-time.After(200 * time.Millisecond):
	}
	release()
	if err := recv(t, closed, 2*time.Second, "Close"); err != nil {
		t.Errorf("Close: %v", err)
	}
	waitFor(t, func() bool { return r.p.Count("BYE") == 1 })
}

// A dialog in phaseControlOp is established: Close takes it over, closes its
// owner's ended channel and releases its media inside Close, and sends its one
// BYE.
func TestUAClosedByesADialogInAControlOpOnceAndClosesItsEndedChannel(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	if err := r.answer(); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	ended, _, err := ClaimControlOpForTest(r.ua, r.id)
	if err != nil {
		t.Fatalf("ClaimControlOpForTest: %v", err)
	}
	r.ua.calls.mu.Lock()
	ml := r.d.mediaLoop
	r.ua.calls.mu.Unlock()
	if ml == nil {
		t.Fatal("the answered call has no media loop")
	}

	if err := r.ua.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-ended:
	default:
		t.Error("the control operation's ended channel was not closed inside Close")
	}
	r.assertNothingRunning()
	if !ml.isStopped() {
		t.Error("the media loop was not stopped inside Close")
	}
	if n := r.ua.RegisteredDialogCount(); n != 0 {
		t.Errorf("%d dialogs still registered after Close, want 0", n)
	}
	waitFor(t, func() bool { return r.p.Count("BYE") == 1 })
	time.Sleep(500 * time.Millisecond) // bounded window for a second BYE
	if n := r.p.Count("BYE"); n != 1 {
		t.Errorf("peer received %d BYEs, want exactly 1", n)
	}
}

// Pin of today's result: a dialog still registered on a closed UA keeps its
// late-Hangup path. phaseMediaTeardown is refused precondition_failed.
func TestALateHangupOnAClosedUAKeepsTheMediaTeardownRefusal(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	r.ua.register(&dialog{id: "mt-1", direction: session.Outbound, phase: phaseMediaTeardown})
	if err := r.ua.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := r.ua.Hangup(context.Background(), "mt-1", "")
	if apierr.CodeOf(err) != apierr.CodePreconditionFailed || !strings.Contains(err.Error(), "dialog is in phase") {
		t.Errorf("late Hangup = %v, want precondition_failed \"dialog is in phase ...\"", err)
	}
	d, err := r.ua.lookup("mt-1")
	if err != nil {
		t.Fatalf("lookup after the late Hangup: %v", err)
	}
	r.ua.calls.mu.Lock()
	phase := d.phase
	r.ua.calls.mu.Unlock()
	if phase != phaseMediaTeardown {
		t.Errorf("phase = %d, want phaseMediaTeardown", phase)
	}
}

// Pin of today's result (residual r1): Close leaves a ringing inbound dialog
// registered, and a late Hangup still claims it and attempts its 603.
func TestALateHangupOnAClosedUAStillDeclinesARingingInboundDialog(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	if err := r.ua.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := recv(t, r.hangupAsync(context.Background()), 2*time.Second, "late Hangup")
	t.Logf("late Hangup on the closed UA returned %v (recorded, not asserted)", err)
	if n := r.ua.RegisteredDialogCount(); n != 0 {
		t.Errorf("%d dialogs still registered after the late Hangup, want 0", n)
	}
	if codes := r.spy.finalCodes(); !hasCode(codes, 603) {
		t.Errorf("finals attempted = %v, want a 603", codes)
	}
}

// Residual r3's late path and the !closed count guard: a dialog that became
// established after Close's sweep (stood in for by setting closed without a
// Close) keeps today's late-Hangup path: the Hangup claims it, releases its
// media and session timer and attempts its BYE, counting nothing, so a Close
// does not wait for that BYE.
func TestALateHangupOnAClosedUAReleasesADialogEstablishedAfterTheSweep(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	if err := r.answer(); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	r.ua.calls.mu.Lock()
	r.ua.calls.closed = true
	r.ua.calls.mu.Unlock()
	release := HoldSendOrderTokenForTest(t, r.ua, r.id)
	t.Cleanup(release)
	contended := signalContended(t)

	hang := r.hangupAsync(context.Background())
	waitByeContended(t, contended, "the late Hangup's BYE")
	closed := make(chan error, 1)
	go func() { closed <- r.ua.Close(context.Background()) }()
	select {
	case err := <-closed:
		if err != nil {
			t.Errorf("Close: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Close did not return within 200ms although the late Hangup's claim counted nothing")
	}
	release()
	err := recv(t, hang, 3*time.Second, "late Hangup")
	t.Logf("late Hangup returned %v (recorded, not asserted)", err)
	if n := r.ua.RegisteredDialogCount(); n != 0 {
		t.Errorf("%d dialogs still registered after the late Hangup, want 0", n)
	}
	r.assertNothingRunning()
}

// Close's wait for BYEs is bounded: a Hangup's BYE that the peer never answers
// holds its count for up to u.cfg.Timeout (2s in the rig), and Close goes on
// after closeByeWait. The rig's Timeout being above closeByeWait plus the
// ceiling's margin is what makes an unbounded wait fail here.
func TestUAClosedWaitsAtMostCloseByeWaitForAnUnansweredBye(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	if err := r.answer(); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	r.p.SetBehaviour(sippeer.Behaviour{SwallowBye: true})
	hang := r.hangupAsync(context.Background())
	waitFor(t, func() bool { return r.p.Count("BYE") >= 1 })

	start := time.Now()
	if err := r.ua.Close(context.Background()); err != nil {
		t.Errorf("Close: %v", err)
	}
	took := time.Since(start)
	if took < closeByeWait-100*time.Millisecond || took > closeByeWait+400*time.Millisecond {
		t.Errorf("Close took %v, want between %v and %v", took, closeByeWait-100*time.Millisecond, closeByeWait+400*time.Millisecond)
	}
	err := recv(t, hang, 3*time.Second, "Hangup")
	t.Logf("Hangup returned %v (recorded, not asserted)", err)
}

// Race-detector pin only: two concurrent Close calls both return and the
// established dialog gets one BYE.
func TestConcurrentUAClosesSendOneByeAndBothReturn(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	if err := r.answer(); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			results <- r.ua.Close(context.Background())
		}()
	}
	close(start)
	for range 2 {
		if err := recv(t, results, 2*time.Second, "Close"); err != nil {
			t.Errorf("Close: %v", err)
		}
	}
	waitFor(t, func() bool { return r.p.Count("BYE") == 1 })
	time.Sleep(500 * time.Millisecond) // bounded window for a second BYE
	if n := r.p.Count("BYE"); n != 1 {
		t.Errorf("peer received %d BYEs, want exactly 1", n)
	}
}

// The close gate: the first Close is held in its sweep teardown (the session
// refresher's in-flight refresh is parked in the contended hook, so
// stopSessionTimer waits for it). A second Close must not return, and so must
// not close the transport, before the first closer has sent its BYE.
func TestAConcurrentUACloseWaitsUntilTheFirstCloserHasSentItsBye(t *testing.T) {
	p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0", Behaviour: sippeer.Behaviour{
		AnswerSessionExpires: "90;refresher=uac",
		AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
	}})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, err := New(context.Background(), Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 30 * time.Second,
		Clock: clk, LocalAddr: "127.0.0.1:0",
		SessionExpiresS: 1800, MinSES: 60,
		WrapConn: func(pc net.PacketConn) net.PacketConn { return pc },
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, func() bool {
		d, err := ua.lookup(res.DialogID)
		if err != nil {
			return false
		}
		ua.calls.mu.Lock()
		defer ua.calls.mu.Unlock()
		return d.phase == phaseAnswered
	})

	release := HoldSendOrderTokenForTest(t, ua, res.DialogID)
	refreshHeld, releaseHook := make(chan struct{}), make(chan struct{})
	var parkOnce, unparkOnce sync.Once
	unpark := func() { unparkOnce.Do(func() { close(releaseHook) }) }
	inDialogSendContendedHook = func(m sip.RequestMethod) {
		if m != sip.UPDATE {
			return
		}
		parkOnce.Do(func() {
			close(refreshHeld)
			<-releaseHook
		})
	}
	t.Cleanup(func() { inDialogSendContendedHook = nil })
	// Registered after the UA's Close cleanup so they run before it: a failing
	// run never leaves the refresh parked under a Close blocked on it.
	t.Cleanup(release)
	t.Cleanup(unpark)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	select {
	case <-refreshHeld:
	case <-time.After(2 * time.Second):
		t.Fatal("the session refresh never parked in the contended hook")
	}

	first := make(chan error, 1)
	go func() { first <- ua.Close(context.Background()) }()
	waitFor(t, func() bool { return ua.RegisteredDialogCount() == 0 })
	second := make(chan error, 1)
	go func() { second <- ua.Close(context.Background()) }()
	select {
	case err := <-first:
		t.Fatalf("the first Close returned (err=%v) while its session-timer stop was held", err)
	case err := <-second:
		t.Fatalf("the second Close returned (err=%v) before the first closer had sent its BYE", err)
	case <-time.After(closeByeWait + 500*time.Millisecond):
	}

	release()
	unpark()
	if err := recv(t, first, 3*time.Second, "first Close"); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := recv(t, second, 3*time.Second, "second Close"); err != nil {
		t.Errorf("second Close: %v", err)
	}
	waitFor(t, func() bool { return p.Count("BYE") == 1 })
	time.Sleep(500 * time.Millisecond) // bounded window for a second BYE
	if n := p.Count("BYE"); n != 1 {
		t.Errorf("peer received %d BYEs, want exactly 1", n)
	}
}
