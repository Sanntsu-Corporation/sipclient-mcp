package sipua

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	sippeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// respondSpy wraps the dialog's real sip.ServerTransaction and counts the
// FINAL responses put on it, running a hook on the first one.
//
// Embedding — not reimplementation — is what makes this safe: every other
// method of sip.ServerTransaction keeps the real transaction's behaviour, so
// the 200 OK Answer builds still goes out on the wire exactly as it would
// without the spy. Only Respond is observed.
type respondSpy struct {
	sip.ServerTransaction

	mu     sync.Mutex
	finals []int

	// fired guards duringFirstRespond with a CAS rather than a sync.Once:
	// the hook responds on THIS SAME transaction, so a sync.Once would
	// re-enter Do and deadlock.
	fired              atomic.Bool
	duringFirstRespond func()
	// fail200 makes a 200 fail without being sent (after the hook ran), so a
	// test can drive Answer's "the 200 never reached the wire" section.
	fail200 bool
}

func (s *respondSpy) Respond(res *sip.Response) error {
	if res.StatusCode >= 200 {
		s.mu.Lock()
		s.finals = append(s.finals, int(res.StatusCode))
		s.mu.Unlock()
	}
	// THE WINDOW, COLLAPSED. The hook runs while Answer is inside its
	// tx.Respond call — after Answer's phase check and before Answer's
	// post-Respond bookkeeping. That is precisely the interval an
	// already-fired ring timer occupies, and driving it from here makes the
	// interleaving deterministic instead of statistical.
	if s.duringFirstRespond != nil && s.fired.CompareAndSwap(false, true) {
		s.duringFirstRespond()
	}
	if s.fail200 && res.StatusCode == 200 {
		return errors.New("injected: the 200 was not written")
	}
	return s.ServerTransaction.Respond(res)
}

func (s *respondSpy) finalCodes() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int(nil), s.finals...)
}

// newClaimTestUA is this file's own direct-mode UA. call_outbound_test.go's
// newDirectUA is in package sipua_test and is unreachable from here; this test
// must be an IN-PACKAGE test because the window it pins is only observable
// through u.calls.mu, d.serverTx and u.finalRespond, all unexported.
func newClaimTestUA(t *testing.T, clk *fakeclock.Clock) *UA {
	t.Helper()
	ua, err := New(context.Background(), Config{
		Transport:          "udp",
		Mode:               "direct",
		AOR:                "sip:alice@example",
		ExpiresS:           300,
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              clk,
		LocalAddr:          "127.0.0.1:0",
		WrapConn:           func(pc net.PacketConn) net.PacketConn { return pc },
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua
}

// TestAnswerClaimsTheDialogBeforeRespondingSoNoOtherPathCanRespond pins the
// rule that ONE INVITE transaction carries EXACTLY ONE final response.
//
// THE DEFECT THIS GATE EXISTS FOR. Answer used to check `d.phase ==
// phaseRinging`, release u.calls.mu WITH THE DIALOG STILL phaseRinging, and
// only claim `d.phase = phaseAnswered` after tx.Respond had returned. A ring
// timer that had ALREADY FIRED — Stop() on a fired timer is a no-op and its
// goroutine is already past `<-timer.C()` — then took the lock inside that
// window, read phaseRinging, and sent 480 Temporarily Unavailable ON THE SAME
// ServerTransaction the 200 OK was going out on. Two final responses on one
// INVITE transaction is a wire-protocol violation, and the 480's
// UAEventDialogEnded{ring_timeout} made session tear down the very call
// call_answer had just reported as answered.
//
// WHY finalRespond IS CALLED DIRECTLY rather than driving the real timer
// goroutine: `u.finalRespond(d, 480, "Temporarily Unavailable")` at
// call.go:467 is the ONLY thing that goroutine does once it is past its
// channel receive. Calling it from inside the window is therefore the same
// action with the scheduling non-determinism removed — the assertion is an
// ORDERING (a claim made before responding), not a timing.
func TestAnswerClaimsTheDialogBeforeRespondingSoNoOtherPathCanRespond(t *testing.T) {
	p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newClaimTestUA(t, clk)

	inbound := make(chan session.UAEvent, 8)
	ended := make(chan session.UAEvent, 8)
	// Inbound admission is SYNCHRONOUS (I2): capture the INVITE on the OnAdmit
	// channel and accept, so the call still rings.
	ua.OnAdmit(context.Background(), func(_ context.Context, ev session.UAEvent) session.Admission {
		inbound <- ev
		return session.AdmitAccept()
	})
	ua.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) {
		if ev.Kind == session.UAEventDialogEnded {
			ended <- ev
		}
	})

	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	var in session.UAEvent
	select {
	case in = <-inbound:
	case <-time.After(3 * time.Second):
		t.Fatal("no inbound event; the peer's INVITE never reached the UA")
	}

	d, err := ua.lookup(in.DialogID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	// Install the spy in place of the dialog's real server transaction. Done
	// under u.calls.mu because that is the lock every reader of d.serverTx
	// holds.
	var lateRespond error
	spy := &respondSpy{}
	spy.duringFirstRespond = func() {
		// The already-fired ring timer, arriving mid-Answer.
		lateRespond = ua.finalRespond(d, 480, "Temporarily Unavailable")
	}
	ua.calls.mu.Lock()
	spy.ServerTransaction = d.serverTx
	d.serverTx = spy
	ua.calls.mu.Unlock()

	if err := ua.AnswerEventually(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}

	// 1. The fired ring timer must have been REFUSED. finalRespond returns
	//    precondition_failed when the dialog is no longer claimable, and
	//    Answer must have made it unclaimable BEFORE it responded.
	if lateRespond == nil {
		t.Error("a ring timer that fired during Answer's tx.Respond was allowed to send " +
			"its 480: Answer had not yet claimed the dialog, so finalRespond saw " +
			"phaseRinging and succeeded. Answer must claim the dialog in the SAME " +
			"critical section as its phase check.")
	}

	// 2. THE WIRE INVARIANT, asserted independently of (1): exactly ONE final
	//    response on this INVITE transaction, and it is the 200.
	if got := spy.finalCodes(); len(got) != 1 || got[0] != 200 {
		t.Errorf("final responses on the INVITE transaction = %v, want exactly [200]. "+
			"Two final responses on one transaction is a wire-protocol violation.", got)
	}

	// 3. And session must learn of exactly ONE outcome. A ring_timeout
	//    dialog_ended here would make handleDialogEnded TryTerminate the call
	//    that call_answer just reported as answered.
	select {
	case ev := <-ended:
		t.Errorf("an answered dialog emitted dialog_ended{cause=%q}; the answer and the "+
			"ring timeout would both be reported to session for one call", ev.Cause)
	case <-time.After(200 * time.Millisecond):
	}

	// 4. D147/F1 stays closed: once Answer has returned, the dialog is
	//    phaseAnswered AND d.ok is the response actually sent, so a concurrent
	//    Hangup can never fabricate a To-tag.
	ua.calls.mu.Lock()
	gotPhase, gotOK := d.phase, d.ok
	ua.calls.mu.Unlock()
	if gotPhase != phaseAnswered {
		t.Errorf("phase after Answer = %d, want phaseAnswered (%d)", gotPhase, phaseAnswered)
	}
	if gotOK == nil {
		t.Error("d.ok is nil after a successful Answer: Hangup would fabricate a fresh " +
			"To-tag and draw a 481 (D147/F1)")
	}
}

// TestAnsweringPhaseDefersHangupAndRefusesReject is the OTHER half of the C1 fix,
// and it is what stops the fix from reopening D147/F1.
//
// The claim Answer makes before responding must be a phase that is NEITHER
// phaseRinging — or the ring timer and call_reject could still respond — NOR
// phaseAnswered — or a concurrent Hangup would see an answered dialog whose
// d.ok is not yet set and fabricate a To-tag, which is the exact 481 D147/F1
// closed. phaseAnswering is that third state. A Hangup landing in it is
// RECORDED, never sent (CF-041: nothing may be built while d.ok is unset), and
// Reject and the ring timer are refused.
func TestAnsweringPhaseDefersHangupAndRefusesReject(t *testing.T) {
	p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newClaimTestUA(t, clk)

	inbound := make(chan session.UAEvent, 8)
	// Inbound admission is SYNCHRONOUS (I2): capture the INVITE on OnAdmit.
	ua.OnAdmit(context.Background(), func(_ context.Context, ev session.UAEvent) session.Admission {
		inbound <- ev
		return session.AdmitAccept()
	})

	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	var in session.UAEvent
	select {
	case in = <-inbound:
	case <-time.After(3 * time.Second):
		t.Fatal("no inbound event; the peer's INVITE never reached the UA")
	}

	d, err := ua.lookup(in.DialogID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	ua.calls.mu.Lock()
	d.phase = phaseAnswering
	ua.calls.mu.Unlock()

	// Hangup must RECORD, not send: d.ok is not yet set, so a BYE built here
	// would carry a To-tag the far end never issued (D147/F1). An already
	// cancelled ctx makes the recorded hangup's wait return at once.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ua.Hangup(cancelled, in.DialogID, "local_hangup"); !errors.Is(err, context.Canceled) {
		t.Errorf("Hangup on a phaseAnswering dialog = %v, want context.Canceled (recorded, then the wait ended)", err)
	}
	if !HangupPendingForTest(ua, in.DialogID) {
		t.Error("the hangup was not recorded on the phaseAnswering dialog")
	}
	time.Sleep(100 * time.Millisecond) // bounded window for a NEGATIVE check
	if n := p.ByeCount(); n != 0 {
		t.Errorf("a BYE was sent on a phaseAnswering dialog (%d): d.ok is not yet set, so it would "+
			"carry a fabricated To-tag and draw a 481 (D147/F1)", n)
	}
	// Reject must refuse: Answer has committed and a second final response on
	// the transaction is a wire-protocol violation.
	if err := ua.Reject(context.Background(), in.DialogID, 486, ""); err == nil {
		t.Error("Reject succeeded on a phaseAnswering dialog: Answer has already " +
			"committed to putting a 200 on this transaction")
	}
	// And so must the ring timer's path.
	if err := ua.finalRespond(d, 480, "Temporarily Unavailable"); err == nil {
		t.Error("finalRespond succeeded on a phaseAnswering dialog: the ring timer " +
			"would put a second final response on the INVITE transaction")
	}
}
