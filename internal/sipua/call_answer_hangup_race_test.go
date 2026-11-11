package sipua

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/siptest"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	sippeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// CF-041: a call_hangup that lands while call_answer is writing its 200 is
// RECORDED (never sent: d.ok is unset) and whichever path settles Answer ends
// the call. Every interleaving is forced through respondSpy.duringFirstRespond,
// which runs while Answer is inside tx.Respond holding the phaseAnswering claim.

type raceRig struct {
	t   *testing.T
	ua  *UA
	p   *sippeer.Peer
	d   *dialog
	id  string
	spy *respondSpy

	mu     sync.Mutex
	events []session.UAEvent
}

// newRaceRig builds a UA, has the peer dial it (dial, nil = a plain INVITE) and
// returns once the inbound dialog is RINGING, so a following Answer is the
// first and only claim (CF-052: Answer before the 180 now waits in
// phaseAdmitting; the wait is kept out of this test for determinism).
func newRaceRig(t *testing.T, logger *slog.Logger, dial func(p *sippeer.Peer, target string)) *raceRig {
	t.Helper()
	p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0"})
	ua, err := New(context.Background(), Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 30 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		SessionExpiresS: 1800, MinSES: 60, Logger: logger,
		WrapConn: func(pc net.PacketConn) net.PacketConn { return pc },
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	r := &raceRig{t: t, ua: ua, p: p}
	inbound := make(chan session.UAEvent, 4)
	ua.OnAdmit(context.Background(), func(_ context.Context, ev session.UAEvent) session.Admission {
		inbound <- ev
		return session.AdmitAccept()
	})
	ua.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) {
		r.mu.Lock()
		r.events = append(r.events, ev)
		r.mu.Unlock()
	})
	target := "sip:alice@" + ua.BoundAddr().String()
	if dial == nil {
		p.Dial(t, target)
	} else {
		dial(p, target)
	}
	select {
	case in := <-inbound:
		r.id = in.DialogID
	case <-time.After(3 * time.Second):
		t.Fatal("no inbound event; the peer's INVITE never reached the UA")
	}
	d, err := ua.lookup(r.id)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	r.d = d
	waitFor(t, func() bool {
		ua.calls.mu.Lock()
		defer ua.calls.mu.Unlock()
		return d.phase == phaseRinging
	})
	r.spy = &respondSpy{}
	ua.calls.mu.Lock()
	r.spy.ServerTransaction = d.serverTx
	d.serverTx = r.spy
	ua.calls.mu.Unlock()
	return r
}

func (r *raceRig) answer() error {
	return r.ua.Answer(context.Background(), session.AnswerRequest{DialogID: r.id})
}

// hangupAsync starts a Hangup and returns its result channel.
func (r *raceRig) hangupAsync(ctx context.Context) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- r.ua.Hangup(ctx, r.id, "") }()
	return ch
}

// parkHangup starts a Hangup and waits until it is recorded (parked).
func (r *raceRig) parkHangup(ctx context.Context) <-chan error {
	r.t.Helper()
	ch := r.hangupAsync(ctx)
	// Not waitFor: this also runs on Answer's goroutine (the spy hook), where
	// t.Fatal would end that goroutine and leave the test waiting forever.
	deadline := time.Now().Add(2 * time.Second)
	for !HangupPendingForTest(r.ua, r.id) {
		if time.Now().After(deadline) {
			r.t.Error("the hangup was not recorded within 2s")
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	return ch
}

func (r *raceRig) peerSaw(code int) func() bool {
	return func() bool { return hasCode(r.p.ResponseCodes(), code) }
}

func (r *raceRig) dialogEnded() []session.UAEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []session.UAEvent
	for _, ev := range r.events {
		if ev.Kind == session.UAEventDialogEnded {
			out = append(out, ev)
		}
	}
	return out
}

func recv(t *testing.T, ch <-chan error, within time.Duration, what string) error {
	t.Helper()
	if ch == nil {
		t.Fatalf("%s was never started", what)
	}
	select {
	case err := <-ch:
		return err
	case <-time.After(within):
		t.Fatalf("%s did not return within %v", what, within)
		return nil
	}
}

// assertAnsweredThenByedOnce checks the converged end state of an answer that
// settled after a recorded hangup: the 200 went out, then exactly one BYE whose
// From-tag is the 200's To-tag (D147), and nothing is left running.
func (r *raceRig) assertAnsweredThenByedOnce() {
	t := r.t
	t.Helper()
	waitFor(t, r.peerSaw(200))
	waitFor(t, func() bool { return r.p.ByeCount() >= 1 })
	time.Sleep(100 * time.Millisecond) // bounded window for a second BYE
	if n := r.p.ByeCount(); n != 1 {
		t.Fatalf("peer received %d BYEs, want exactly 1", n)
	}
	bye := r.p.LastBye()
	if bye == nil || bye.From() == nil {
		t.Fatal("peer captured no BYE with a From header")
	}
	byeTag, _ := bye.From().Params.Get("tag")
	if okTag := r.p.LastFinalToTag(); okTag == "" || okTag != byeTag {
		t.Fatalf("BYE From-tag %q != 200 To-tag %q (D147)", byeTag, okTag)
	}
	waitFor(t, func() bool { return r.ua.RegisteredDialogCount() == 0 })
	r.assertNothingRunning()
}

func (r *raceRig) assertNothingRunning() {
	r.t.Helper()
	r.ua.calls.mu.Lock()
	defer r.ua.calls.mu.Unlock()
	if r.d.mediaLoop != nil || r.d.mediaConn != nil {
		r.t.Errorf("media still bound after the call ended: loop=%v conn=%v", r.d.mediaLoop != nil, r.d.mediaConn != nil)
	}
	if r.d.sessionTimer != nil {
		r.t.Error("a session timer is armed on a dialog that ended")
	}
}

func TestHangupDuringAnswerEndsTheAnsweredCallWithOneBye(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	var hang <-chan error
	r.spy.duringFirstRespond = func() { hang = r.parkHangup(context.Background()) }

	if err := r.answer(); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if err := recv(t, hang, 3*time.Second, "Hangup"); err != nil {
		r.ua.calls.mu.Lock()
		phase, registered := r.d.phase, len(r.ua.calls.byID)
		r.ua.calls.mu.Unlock()
		t.Logf("DIAG phase=%d registered=%d peer BYEs=%d", phase, registered, r.p.ByeCount())
		t.Fatalf("Hangup = %v, want nil", err)
	}
	r.assertAnsweredThenByedOnce()
}

func TestHangupWaitingOnAFailedAnswerDeclinesTheCall(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	r.spy.fail200 = true
	var hang <-chan error
	r.spy.duringFirstRespond = func() { hang = r.parkHangup(context.Background()) }

	err := r.answer()
	if err == nil || !strings.Contains(err.Error(), "respond 200") {
		t.Fatalf("Answer = %v, want the respond 200 error", err)
	}
	if err := recv(t, hang, 3*time.Second, "Hangup"); err != nil {
		t.Fatalf("Hangup = %v, want nil (the call was declined)", err)
	}
	waitFor(t, r.peerSaw(603))
	if hasCode(r.p.ResponseCodes(), 200) {
		t.Error("the peer saw a 200 although it was never written")
	}
	time.Sleep(100 * time.Millisecond)
	if n := r.p.ByeCount(); n != 0 {
		t.Errorf("peer received %d BYE for a call that was declined, want 0", n)
	}
	waitFor(t, func() bool { return r.ua.RegisteredDialogCount() == 0 })
	r.assertNothingRunning()
}

func TestHangupWaitingOnAnAnswerRejectedWith488EndsWithoutBye(t *testing.T) {
	// An offer with no codec in common: Answer's own first final is the 488.
	offer := []byte("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=x\r\nc=IN IP4 127.0.0.1\r\n" +
		"t=0 0\r\nm=audio 20000 RTP/AVP 99\r\na=rtpmap:99 nosuchcodec/8000\r\na=sendrecv\r\n")
	r := newRaceRig(t, nil, func(p *sippeer.Peer, target string) { p.DialWithBody(t, target, offer) })
	var hang <-chan error
	r.spy.duringFirstRespond = func() { hang = r.parkHangup(context.Background()) }

	if err := r.answer(); err == nil {
		t.Fatal("Answer succeeded against an offer with no common codec")
	}
	if err := recv(t, hang, 3*time.Second, "Hangup"); err != nil {
		t.Fatalf("Hangup = %v, want nil", err)
	}
	waitFor(t, r.peerSaw(488))
	if hasCode(r.p.ResponseCodes(), 603) || hasCode(r.p.ResponseCodes(), 200) {
		t.Errorf("peer saw %v, want only the 488 final", r.p.ResponseCodes())
	}
	time.Sleep(100 * time.Millisecond)
	if n := r.p.ByeCount(); n != 0 {
		t.Errorf("peer received %d BYE after a 488, want 0", n)
	}
}

// C1's convergence test: a recorded hangup whose waiter gave up (cap or ctx)
// still ends the call once the answer settles.
func TestARecordedHangupEndsAnAnswerThatSettlesAfterTheCap(t *testing.T) {
	run := func(t *testing.T, ctxCancelled bool) {
		r := newRaceRig(t, nil, nil)
		release := make(chan struct{})
		var releaseOnce sync.Once
		releaseAnswer := func() { releaseOnce.Do(func() { close(release) }) }
		defer releaseAnswer() // a failing test must not leave Answer parked
		inHook := make(chan struct{})
		hangCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var hang <-chan error
		var hangStart time.Time
		r.spy.duringFirstRespond = func() {
			hangStart = time.Now()
			hang = r.parkHangup(hangCtx)
			close(inHook)
			<-release
		}
		answered := make(chan error, 1)
		go func() { answered <- r.answer() }()
		select {
		case <-inHook:
		case <-time.After(5 * time.Second):
			t.Fatal("Answer never reached the hook")
		}

		if ctxCancelled {
			cancel()
			if err := recv(t, hang, time.Second, "Hangup"); !errors.Is(err, context.Canceled) {
				t.Fatalf("Hangup = %v, want context.Canceled", err)
			}
		} else {
			if err := recv(t, hang, cancelWaitCap+2*time.Second, "Hangup"); err != nil {
				t.Fatalf("Hangup = %v, want nil at the cap", err)
			}
			if el := time.Since(hangStart); el < cancelWaitCap {
				t.Fatalf("Hangup returned after %v, before the %v cap", el, cancelWaitCap)
			}
		}
		releaseAnswer()
		if err := recv(t, answered, 5*time.Second, "Answer"); err != nil {
			t.Fatalf("Answer = %v, want nil", err)
		}
		r.assertAnsweredThenByedOnce()
	}
	t.Run("cap elapsed", func(t *testing.T) { run(t, false) })
	t.Run("ctx cancelled while parked", func(t *testing.T) { run(t, true) })
}

// sendCallerBye delivers the caller's BYE for the peer's INVITE to the UA, the
// way a caller ends an early dialog (RFC 3261 §15).
func sendCallerBye(t *testing.T, r *raceRig) {
	t.Helper()
	inv := r.p.LastSentInvite()
	if inv == nil {
		t.Fatal("peer has no INVITE to build a BYE from")
	}
	// The To tag is the one on the 180 the peer received, as a caller's BYE for
	// an early dialog carries it (CF-130 matches both tags).
	var tags []string
	deadline := time.Now().Add(2 * time.Second)
	for len(tags) == 0 && time.Now().Before(deadline) {
		if tags = r.p.ProvisionalToTags(); len(tags) == 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if len(tags) == 0 {
		t.Fatal("peer received no tagged 180")
	}
	ringing := sip.NewResponse(180, "Ringing")
	ringing.AppendHeader(&sip.ToHeader{Address: inv.To().Address, Params: sip.NewParams()})
	ringing.To().Params.Add("tag", tags[len(tags)-1])
	bye := siptest.BuildByeFromInvite(inv, ringing)
	conn, err := net.Dial("udp", r.ua.BoundAddr().String())
	if err != nil {
		t.Fatalf("dial UA: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(bye.String())); err != nil {
		t.Fatalf("write BYE: %v", err)
	}
}

// C2's test: a caller BYE landing during Answer's write must not be overwritten
// by phaseAnswered (which would arm a session timer on a forgotten dialog).
func TestAPeerByeDuringAnswersWriteIsNotResurrected(t *testing.T) {
	withTimer := func(p *sippeer.Peer, target string) {
		p.DialWithHeaders(t, target, map[string]string{
			"Supported": "timer", "Session-Expires": "90;refresher=uac",
		})
	}
	check := func(t *testing.T, r *raceRig) {
		r.ua.calls.mu.Lock()
		phase := r.d.phase
		r.ua.calls.mu.Unlock()
		if phase != phaseDone {
			t.Errorf("phase after Answer = %d, want phaseDone (%d): the peer's BYE was overwritten", phase, phaseDone)
		}
		r.assertNothingRunning()
		// onBye emits dialog_ended after releasing the lock, so wait for it.
		waitFor(t, func() bool { return len(r.dialogEnded()) >= 1 })
		ended := r.dialogEnded()
		if len(ended) != 1 || ended[0].Cause != session.UACausePeerBYE {
			t.Errorf("dialog_ended events = %v, want exactly one peer_bye", ended)
		}
	}
	t.Run("no hangup", func(t *testing.T) {
		r := newRaceRig(t, nil, withTimer)
		r.spy.duringFirstRespond = func() {
			sendCallerBye(t, r)
			waitFor(t, func() bool { return r.ua.RegisteredDialogCount() == 0 })
		}
		if err := r.answer(); err != nil {
			t.Fatalf("Answer: %v", err)
		}
		check(t, r)
	})
	t.Run("with a recorded hangup", func(t *testing.T) {
		r := newRaceRig(t, nil, withTimer)
		var hang <-chan error
		r.spy.duringFirstRespond = func() {
			hang = r.parkHangup(context.Background())
			sendCallerBye(t, r)
			waitFor(t, func() bool { return r.ua.RegisteredDialogCount() == 0 })
		}
		if err := r.answer(); err != nil {
			t.Fatalf("Answer: %v", err)
		}
		if err := recv(t, hang, time.Second, "Hangup"); err != nil {
			t.Fatalf("Hangup = %v, want nil promptly after the peer's BYE", err)
		}
		time.Sleep(300 * time.Millisecond) // bounded window for a BYE of ours
		if n := r.p.ByeCount(); n != 0 {
			t.Errorf("the UA sent %d BYE on a dialog the peer had ended, want 0", n)
		}
		check(t, r)
	})
}

// A UA closed underneath a parked answer hangup: the 200 cannot be written, the
// 603 cannot either, and the hangup reports that error instead of hanging.
func TestUAClosedDuringAParkedAnswerHangupConverges(t *testing.T) {
	buf := &lockedBuf{}
	r := newRaceRig(t, slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), nil)
	var hang <-chan error
	r.spy.duringFirstRespond = func() {
		hang = r.parkHangup(context.Background())
		if err := r.ua.Close(context.Background()); err != nil {
			t.Logf("Close: %v", err)
		}
	}
	if err := r.answer(); err == nil {
		t.Fatal("Answer succeeded on a closed UA")
	}
	err := recv(t, hang, cancelWaitCap+2*time.Second, "Hangup")
	if err == nil || !strings.Contains(err.Error(), "respond 603") {
		t.Fatalf("Hangup = %v, want the wrapped respond 603 write error", err)
	}
	if n := r.ua.RegisteredDialogCount(); n != 0 {
		t.Errorf("RegisteredDialogCount = %d, want 0", n)
	}
	r.assertNothingRunning()
	log := buf.String()
	if !strings.Contains(log, "level=WARN") || !strings.Contains(log, "respond 603") || !strings.Contains(log, r.id) {
		t.Errorf("no Warn naming the dialog and the failed 603 in the log:\n%s", log)
	}
}

func TestARepeatedHangupDuringAnAnswerReturnsAtOnce(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	var first <-chan error
	var secondErr error
	var secondTook time.Duration
	r.spy.duringFirstRespond = func() {
		first = r.parkHangup(context.Background())
		start := time.Now()
		secondErr = r.ua.Hangup(context.Background(), r.id, "")
		secondTook = time.Since(start)
		if !HangupPendingForTest(r.ua, r.id) {
			t.Error("the recorded hangup was cleared by a repeat")
		}
	}
	if err := r.answer(); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if secondErr != nil || secondTook > 200*time.Millisecond {
		t.Fatalf("repeated Hangup = %v after %v, want nil within 200ms", secondErr, secondTook)
	}
	if err := recv(t, first, 3*time.Second, "first Hangup"); err != nil {
		t.Fatalf("first Hangup = %v, want nil", err)
	}
	r.assertAnsweredThenByedOnce()
}

// phaseMediaTeardown (the recorded hangup's BYE in flight) is not an
// established phase: a peer re-INVITE in that window is refused with 481.
func TestAReInviteWhileTheRecordedHangupsByeIsPendingDraws481(t *testing.T) {
	t.Cleanup(func() { SetHangupByeHook(nil) })
	r := newRaceRig(t, nil, nil)
	var hang <-chan error
	r.spy.duringFirstRespond = func() { hang = r.parkHangup(context.Background()) }
	SetHangupByeHook(func() {
		waitFor(t, r.peerSaw(200))
		r.p.SendReInvite(t)
		waitFor(t, r.peerSaw(481))
	})
	if err := r.answer(); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if err := recv(t, hang, 3*time.Second, "Hangup"); err != nil {
		t.Fatalf("Hangup = %v, want nil", err)
	}
	r.assertAnsweredThenByedOnce()
}

// S2's pre-response entry, driven directly (a real bind failure would need a
// seam between the claim and bindMediaPort).
func TestAHangupRecordedBeforeAPreResponseFailureDeclinesTheCall(t *testing.T) {
	r := newRaceRig(t, nil, nil)
	r.ua.calls.mu.Lock()
	r.d.phase = phaseAnswering
	r.ua.calls.mu.Unlock()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.ua.Hangup(cancelled, r.id, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("Hangup = %v, want context.Canceled", err)
	}
	r.ua.releaseAnsweringClaim(r.d)
	waitFor(t, r.peerSaw(603))
	waitFor(t, func() bool { return r.ua.RegisteredDialogCount() == 0 })
}
