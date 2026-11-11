// internal/sipua/arrival_internal_test.go
package sipua

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// claimForArrivalTest puts d into a control operation. The gate only orders a
// dialog's NOTIFY/BYE while a control operation holds it (Rule 13 fix batch A,
// finding 4), so every test of the gate's ordering runs inside one.
func claimForArrivalTest(t *testing.T, u *UA, d *dialog) {
	t.Helper()
	u.calls.mu.Lock()
	_, err := claimControlOpLocked(d, session.ControlOpTransfer, "call_transfer")
	u.calls.mu.Unlock()
	if err != nil {
		t.Fatalf("claimControlOpLocked: %v", err)
	}
}

// setArrivalWaitHook installs arrivalWaitHook for one test. The returned channel
// receives once each time a request of the given method starts waiting at the
// gate (plan D18). The hook fires AFTER the bound's timer is armed.
func setArrivalWaitHook(t *testing.T, method sip.RequestMethod) <-chan struct{} {
	t.Helper()
	waiting := make(chan struct{}, 4)
	arrivalWaitHook = func(m sip.RequestMethod) {
		if m == method {
			waiting <- struct{}{}
		}
	}
	t.Cleanup(func() { arrivalWaitHook = nil })
	return waiting
}

// enterAsync runs arrivalEnter on its own goroutine, as sipgo runs a handler,
// and delivers the ticket once the request is let through.
func enterAsync(u *UA, req *sip.Request) <-chan *arrivalTicket {
	passed := make(chan *arrivalTicket, 1)
	go func() { passed <- u.arrivalEnter(req) }()
	return passed
}

func leave(u *UA, tk *arrivalTicket) {
	u.calls.mu.Lock()
	arrivalLeaveLocked(tk)
	u.calls.mu.Unlock()
}

// TestAHandlerThatBeatsItsOwnObserverStillHoldsBackALaterRequest is D18's
// self-ticketing rule. sipgo forks a request's handler goroutine BEFORE it calls
// observeArrival, so the NOTIFY's handler can reach arrivalEnter first. It must
// ticket itself then, and the observer must not ticket it again. Otherwise the
// BYE read right after it would not wait for it.
func TestAHandlerThatBeatsItsOwnObserverStillHoldsBackALaterRequest(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-arrival-self")
	claimForArrivalTest(t, u, d)
	notify := referNotifyReq("cid-arrival-self", "peer-tag", ours, "refer;id=7", "SIP/2.0 200 OK")
	bye := peerByeReq("cid-arrival-self", ours)
	waiting := setArrivalWaitHook(t, sip.BYE)

	tkN := u.arrivalEnter(notify) // the NOTIFY's handler runs before its observer
	u.observeArrival(notify)      // must not stamp a second, never-claimed ticket
	u.observeArrival(bye)
	passed := enterAsync(u, bye)
	select {
	case <-waiting:
	case <-passed:
		t.Fatal("the BYE passed the gate while the NOTIFY read before it was still being handled")
	case <-time.After(3 * time.Second):
		t.Fatal("the BYE neither waited nor passed")
	}

	leave(u, tkN)
	select {
	case tkB := <-passed:
		leave(u, tkB)
	case <-time.After(3 * time.Second):
		t.Fatal("the BYE stayed behind the gate after the NOTIFY left it")
	}
	u.calls.mu.Lock()
	n := len(d.arrivals.pending)
	u.calls.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d ticket(s) left pending after both requests left; want 0", n)
	}
}

// TestARetransmissionTheTransactionLayerAbsorbsLeavesNoTicketBehind is the gap
// case D18 exists to avoid. sipgo's transaction layer swallows a retransmitted
// NOTIFY, and no handler runs for it. If the observer ticketed it, the peer's
// next BYE would wait for a ticket nobody ever claims.
func TestARetransmissionTheTransactionLayerAbsorbsLeavesNoTicketBehind(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-arrival-retx")
	claimForArrivalTest(t, u, d)
	notify := referNotifyReq("cid-arrival-retx", "peer-tag", ours, "refer;id=7", "SIP/2.0 200 OK")
	bye := peerByeReq("cid-arrival-retx", ours)
	waiting := setArrivalWaitHook(t, sip.BYE)

	u.observeArrival(notify)
	leave(u, u.arrivalEnter(notify))
	u.observeArrival(notify) // the retransmission: absorbed by sipgo, no handler
	u.observeArrival(bye)
	select {
	case tkB := <-enterAsync(u, bye):
		leave(u, tkB)
	case <-waiting:
		t.Fatal("the BYE waited for a retransmission no handler will ever process")
	case <-time.After(3 * time.Second):
		t.Fatal("the BYE never passed the gate")
	}
}

// TestAnArrivalWaitIsBoundedWhenAnEarlierRequestNeverReachesItsHandler is D18's
// bound. sipgo can drop a request after the observer saw it, when no server
// transaction could be built for it. The later BYE waits at most u.cfg.Timeout
// and then proceeds, and the orphan is abandoned so it cannot stall the next
// request.
func TestAnArrivalWaitIsBoundedWhenAnEarlierRequestNeverReachesItsHandler(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	u := newClaimTestUA(t, clk)
	d, ours := newNotifyTestDialog(u, "cid-arrival-bound")
	claimForArrivalTest(t, u, d)
	notify := referNotifyReq("cid-arrival-bound", "peer-tag", ours, "refer;id=7", "SIP/2.0 200 OK")
	bye := peerByeReq("cid-arrival-bound", ours)
	waiting := setArrivalWaitHook(t, sip.BYE)

	u.observeArrival(notify) // its handler never runs
	u.observeArrival(bye)
	passed := enterAsync(u, bye)
	select {
	case <-waiting: // the bound's timer is armed
	case <-time.After(3 * time.Second):
		t.Fatal("the BYE did not wait for the earlier NOTIFY")
	}
	clk.Advance(u.cfg.Timeout)
	select {
	case tkB := <-passed:
		leave(u, tkB)
	case <-time.After(3 * time.Second):
		t.Fatal("the BYE waited past u.cfg.Timeout for a request that never reached its handler")
	}

	// The abandoned orphan must not hold back the next request.
	next := peerByeReq("cid-arrival-bound", ours)
	next.CSeq().SeqNo = 11
	u.observeArrival(next)
	select {
	case tk := <-enterAsync(u, next):
		leave(u, tk)
	case <-waiting:
		t.Fatal("a request waited again for the orphan an earlier bounded wait abandoned")
	case <-time.After(3 * time.Second):
		t.Fatal("the next request never passed the gate")
	}
}

func arrivalState(u *UA, d *dialog) (pending int, cseqSeen bool) {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	return len(d.arrivals.pending), d.arrivals.cseqSeen
}

// TestWithNoControlOpInFlightNotifyAndByeTakeTheFastPath is the DoS half of
// Rule 13 fix batch A, finding 4 (security I-1). sipgo's server-transaction key
// ignores the CSeq number, so a peer can make the observer see a request no
// handler will ever run (an orphan). Before the fix every NOTIFY behind it then
// waited up to u.cfg.Timeout at the gate. With no control operation on the
// dialog nothing needs ordering: the observer stamps no ticket, and the
// handlers neither ticket themselves nor wait. The fake clock is never
// advanced, so any wait at the gate would block for good. arrivalWaitHook
// reports it at once instead.
func TestWithNoControlOpInFlightNotifyAndByeTakeTheFastPath(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-arrival-noop")
	waitingN := setArrivalWaitHook(t, sip.NOTIFY)

	orphan := referNotifyReq("cid-arrival-noop", "peer-tag", ours, "refer;id=7", "SIP/2.0 100 Trying")
	orphan.CSeq().SeqNo = 20
	u.observeArrival(orphan) // its handler never runs
	if n, seen := arrivalState(u, d); n != 0 || seen {
		t.Fatalf("pending=%d cseqSeen=%v after an observed NOTIFY with no control op; want no ticket, no CSeq state", n, seen)
	}

	start := time.Now()
	for i := uint32(0); i < 200; i++ {
		n := referNotifyReqState("cid-arrival-noop", "peer-tag", ours, "refer;id=7", "SIP/2.0 100 Trying", "active;expires=60")
		n.CSeq().SeqNo = 21 + i
		u.observeArrival(n)
		tx := &stubServerTx{}
		done := make(chan struct{})
		go func() {
			defer close(done)
			u.onNotify(n, tx)
		}()
		select {
		case <-done:
		case <-waitingN:
			t.Fatalf("NOTIFY %d waited at the arrival gate with no control op in flight", i)
		case <-time.After(3 * time.Second):
			t.Fatalf("NOTIFY %d never returned", i)
		}
		if got := tx.last().StatusCode; got != 200 {
			t.Fatalf("NOTIFY %d drew %d, want 200", i, got)
		}
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("200 NOTIFYs took %v with no control op in flight; each must return without waiting", elapsed)
	}
	if n, seen := arrivalState(u, d); n != 0 || seen {
		t.Fatalf("pending=%d cseqSeen=%v after the flood; want no ticket, no CSeq state", n, seen)
	}

	// A BYE, too, is applied at once.
	bye := peerByeReq("cid-arrival-noop", ours)
	bye.CSeq().SeqNo = 500
	u.observeArrival(bye)
	if tk := u.arrivalEnter(bye); tk != nil {
		t.Fatalf("arrivalEnter returned a ticket (cseq %d) for a BYE with no control op in flight", tk.cseq)
	}
}

// TestObserveArrivalCapsPendingTicketsUnderFlood is the DoS closure for
// finding I-1 round 2 (Rule 13 security re-verify): I-1's first fix only
// stopped the flood OUTSIDE a control operation. During one, a peer reusing a
// live branch with a rising CSeq could still force observeArrival to append
// an orphan ticket forever, since nothing ever calls arrivalEnter for a
// request sipgo's transaction layer routes to an existing transaction. This
// floods a dialog held by a control operation with orphan NOTIFYs (none of
// which ever reach arrivalEnter) and checks pending never grows past
// arrivalMaxPending, then checks resetLocked still releases every ticket it
// did create and leaves pending empty.
func TestObserveArrivalCapsPendingTicketsUnderFlood(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-arrival-flood")
	claimForArrivalTest(t, u, d)

	const flood = 50
	for i := uint32(0); i < flood; i++ {
		n := referNotifyReqState("cid-arrival-flood", "peer-tag", ours, "refer;id=7", "SIP/2.0 100 Trying", "active;expires=60")
		n.CSeq().SeqNo = 100 + i // strictly increasing branch reuse; each is an orphan
		u.observeArrival(n)      // no handler ever runs for these
	}

	u.calls.mu.Lock()
	pending := append([]*arrivalTicket(nil), d.arrivals.pending...)
	n := len(pending)
	u.calls.mu.Unlock()
	if n > arrivalMaxPending {
		t.Fatalf("pending=%d after a %d-request orphan flood; want capped at arrivalMaxPending=%d", n, flood, arrivalMaxPending)
	}
	if n == 0 {
		t.Fatal("pending=0 after the flood; want the cap's worth of tickets so the release check below is meaningful")
	}

	// M-5: the high-water mark must keep advancing even while pending is
	// capped, or a later duplicate within the flooded range would be
	// re-ticketed once pending has room again. A mutation that dropped the
	// "still advance the high-water mark" line above would freeze maxCSeq at
	// the last cseq appendLocked itself advanced it to (the one that filled
	// the cap), not the true highest cseq the flood actually sent.
	u.calls.mu.Lock()
	maxCSeq, cseqSeen := d.arrivals.maxCSeq, d.arrivals.cseqSeen
	u.calls.mu.Unlock()
	wantMaxCSeq := uint32(100 + flood - 1)
	if !cseqSeen || maxCSeq != wantMaxCSeq {
		t.Fatalf("maxCSeq=%d cseqSeen=%v after the capped flood; want maxCSeq=%d cseqSeen=true (M-5): the high-water mark must keep advancing while pending is capped", maxCSeq, cseqSeen, wantMaxCSeq)
	}

	// Free one slot, as a real handler leaving its own ticket would, then
	// replay a cseq from partway through the flood (already "seen" whether or
	// not it got a ticket). With maxCSeq correctly at wantMaxCSeq, observeArrival
	// must still drop it as a duplicate at its very first check, even though
	// pending now has room to append. If maxCSeq had frozen at the cap point
	// instead, this cseq would look new and get appended.
	u.calls.mu.Lock()
	arrivalLeaveLocked(pending[0])
	freedPending := len(d.arrivals.pending)
	u.calls.mu.Unlock()
	if freedPending != n-1 {
		t.Fatalf("pending=%d after freeing one slot; want %d", freedPending, n-1)
	}
	dup := referNotifyReqState("cid-arrival-flood", "peer-tag", ours, "refer;id=7", "SIP/2.0 100 Trying", "active;expires=60")
	dup.CSeq().SeqNo = 100 + flood/2 // within the flooded range, seen while capped
	u.observeArrival(dup)
	u.calls.mu.Lock()
	afterDup := len(d.arrivals.pending)
	u.calls.mu.Unlock()
	if afterDup != freedPending {
		t.Fatalf("pending=%d after a duplicate (cseq %d) within the flooded range arrived with room to spare; want %d (unchanged): maxCSeq did not advance past the cap point (M-5)", afterDup, dup.CSeq().SeqNo, freedPending)
	}

	u.calls.mu.Lock()
	d.arrivals.resetLocked()
	remaining := len(d.arrivals.pending)
	u.calls.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("pending=%d after resetLocked; want 0", remaining)
	}
	for i, tk := range pending {
		if !tk.left {
			t.Fatalf("ticket %d (cseq %d) not left after resetLocked", i, tk.cseq)
		}
		select {
		case <-tk.done:
		default:
			t.Fatalf("ticket %d (cseq %d) done channel not closed after resetLocked", i, tk.cseq)
		}
	}
}

// TestArrivalCapRefusalLogsExactlyOneWarnPerControlOperation is CF-017: the
// cap-refusal path (distinct from the bounded-wait valve, which already logs)
// warns at most once per control operation, even when many requests are
// refused a ticket while the gate is at capacity — a flood must not produce
// one Warn line per refused request.
func TestArrivalCapRefusalLogsExactlyOneWarnPerControlOperation(t *testing.T) {
	var buf bytes.Buffer
	u, err := New(context.Background(), Config{
		Transport:          "udp",
		Mode:               "direct",
		AOR:                "sip:alice@example",
		ExpiresS:           300,
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              fakeclock.New(time.Unix(0, 0)),
		LocalAddr:          "127.0.0.1:0",
		WrapConn:           func(pc net.PacketConn) net.PacketConn { return pc },
		Logger:             slog.New(slog.NewTextHandler(&buf, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = u.Close(context.Background()) })
	d, ours := newNotifyTestDialog(u, "cid-cap-warn")
	claimForArrivalTest(t, u, d)

	// Flood past arrivalMaxPending from the observeArrival path (mirrors
	// TestObserveArrivalCapsPendingTicketsUnderFlood's flood, above).
	const flood = arrivalMaxPending + 5
	for i := uint32(0); i < flood; i++ {
		req := referNotifyReqState("cid-cap-warn", "peer-tag", ours, "refer;id=7", "SIP/2.0 100 Trying", "active;expires=60")
		req.CSeq().SeqNo = 100 + i
		u.observeArrival(req)
	}

	warnCount := strings.Count(buf.String(), "arrival gate is already at capacity")
	if warnCount != 1 {
		t.Fatalf("logged %d cap-refusal Warn lines across a %d-request flood, want exactly 1", warnCount, flood)
	}
}

// TestArrivalEnterCapsPendingTicketsUnderHandlerPathFlood is the DoS closure
// for finding I-1 round 3 (Rule 13 security re-verify): round 2's cap only
// bounded observeArrival's read-loop append. arrivalEnter has its own,
// unconditional appendLocked when a handler finds no existing ticket for
// itself, and a re-verify proved that path just as cheap to exploit: sipgo
// forks a goroutine and a server transaction for any request on a branch it
// has not seen, with no per-dialog concurrency limit, so a peer sending
// distinct-branch NOTIFY/BYE requests reaches a real handler -- and so
// arrivalEnter -- on every one of them. This drives more concurrent
// handler-path arrivals than the cap through arrivalEnter directly, each with
// a distinct cseq so none of them can find an existing ticket to claim (the
// observer-path flood above already covers same-cseq reuse), and checks that
// pending never grows past arrivalMaxPending and that calls beyond the cap
// return nil at once, without ever arming the bounded-wait timer.
func TestArrivalEnterCapsPendingTicketsUnderHandlerPathFlood(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	u := newClaimTestUA(t, clk)
	d, ours := newNotifyTestDialog(u, "cid-arrival-enter-flood")
	claimForArrivalTest(t, u, d)

	// Install the hook BEFORE any flood goroutine starts: arrivalWaitHook is a
	// package-level var arrivalEnter reads with no lock, so installing it after
	// the goroutines are already running is both a data race and a chance that
	// an early call reads it as nil and skips the signal this test waits on.
	waiting := setArrivalWaitHook(t, sip.NOTIFY)

	const flood = 50
	results := make(chan *arrivalTicket, flood)
	for i := uint32(0); i < flood; i++ {
		n := referNotifyReqState("cid-arrival-enter-flood", "peer-tag", ours, "refer;id=7", "SIP/2.0 100 Trying", "active;expires=60")
		n.CSeq().SeqNo = 200 + i // distinct per call: none can claim an existing ticket
		go func(req *sip.Request) { results <- u.arrivalEnter(req) }(n)
	}

	// The first call to append finds nothing ahead of it and returns at once;
	// every other call that appends a ticket for itself finds the first one (or
	// more) ahead of it and arms the bounded-wait timer before blocking
	// (arrivalWaitHook fires right after). Once arrivalMaxPending-1 timers have
	// armed, arrivalMaxPending calls have successfully appended, so pending has
	// hit the cap and stays there (nothing in this test ever leaves a ticket) --
	// every call still to run, now or later, is refused at once.
	wantArmed := arrivalMaxPending - 1
	for armed := 0; armed < wantArmed; armed++ {
		select {
		case <-waiting:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d/%d handler-path arrivals armed the bounded wait; the flood may be stuck", armed, wantArmed)
		}
	}

	// Collect every result available WITHOUT advancing the fake clock. A
	// result that arrives here cannot have come through the timeout branch
	// (fakeclock only fires on Advance), so this is direct evidence that the
	// refused calls returned nil promptly, not after a wait.
	wantFast := flood - arrivalMaxPending + 1 // the refused calls, plus the one call with nothing ahead of it
	fast := make([]*arrivalTicket, 0, wantFast)
	for len(fast) < wantFast {
		select {
		case tk := <-results:
			fast = append(fast, tk)
		case <-time.After(3 * time.Second):
			t.Fatalf("%d/%d handler-path arrivals returned without waiting; want exactly %d (the refused calls plus the one with nothing ahead of it) once pending hit the cap", len(fast), wantFast, wantFast)
		}
	}
	nonNilFast := 0
	for _, tk := range fast {
		if tk != nil {
			nonNilFast++
		}
	}
	if nonNilFast != 1 {
		t.Fatalf("%d of the %d prompt returns held a ticket; want exactly 1 (the very first call, which had nothing ahead of it) -- every other prompt return must be refused (nil) once pending is capped", nonNilFast, wantFast)
	}

	u.calls.mu.Lock()
	pendingAtCap := len(d.arrivals.pending)
	u.calls.mu.Unlock()
	if pendingAtCap != arrivalMaxPending {
		t.Fatalf("pending=%d once the flood's prompt returns settled; want exactly arrivalMaxPending=%d", pendingAtCap, arrivalMaxPending)
	}

	// Release the rest: every call still blocked appended its own ticket and is
	// waiting on the ones ahead of it, none of which this test ever leaves.
	clk.Advance(u.cfg.Timeout)
	for i := 0; i < wantArmed; i++ {
		select {
		case tk := <-results:
			if tk == nil {
				t.Fatal("a handler-path arrival that had already appended a ticket returned nil after its bounded wait; want its own ticket back")
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d/%d bounded waits released after the clock advanced", i, wantArmed)
		}
	}

	u.calls.mu.Lock()
	finalPending := len(d.arrivals.pending)
	u.calls.mu.Unlock()
	if finalPending > arrivalMaxPending {
		t.Fatalf("pending=%d after the flood settled; want capped at arrivalMaxPending=%d throughout", finalPending, arrivalMaxPending)
	}
}

// TestArrivalEnterCapRefusalLogsExactlyOneWarnPerControlOperation is CF-017's
// second site: arrivalEnter has its OWN cap-refusal Warn, distinct in wording
// from observeArrival's (see arrival.go), and it must be rate-limited by the
// same a.capWarned guard. TestArrivalCapRefusalLogsExactlyOneWarnPerControlOperation
// above only drives observeArrival directly, so it cannot catch a break in
// arrivalEnter's own guard. This mirrors
// TestArrivalEnterCapsPendingTicketsUnderHandlerPathFlood's handler-path flood
// (arrivalEnter is the only path exercised here; no observeArrival call) but
// asserts on the Warn count instead of on ticket accounting.
func TestArrivalEnterCapRefusalLogsExactlyOneWarnPerControlOperation(t *testing.T) {
	var buf bytes.Buffer
	clk := fakeclock.New(time.Unix(0, 0))
	u, err := New(context.Background(), Config{
		Transport:          "udp",
		Mode:               "direct",
		AOR:                "sip:alice@example",
		ExpiresS:           300,
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              clk,
		LocalAddr:          "127.0.0.1:0",
		WrapConn:           func(pc net.PacketConn) net.PacketConn { return pc },
		Logger:             slog.New(slog.NewTextHandler(&buf, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = u.Close(context.Background()) })
	d, ours := newNotifyTestDialog(u, "cid-arrival-enter-cap-warn")
	claimForArrivalTest(t, u, d)

	// Install the hook BEFORE any flood goroutine starts (same reason as
	// TestArrivalEnterCapsPendingTicketsUnderHandlerPathFlood: it's a
	// package-level var arrivalEnter reads with no lock).
	waiting := setArrivalWaitHook(t, sip.NOTIFY)

	const flood = 50
	results := make(chan *arrivalTicket, flood)
	for i := uint32(0); i < flood; i++ {
		n := referNotifyReqState("cid-arrival-enter-cap-warn", "peer-tag", ours, "refer;id=7", "SIP/2.0 100 Trying", "active;expires=60")
		n.CSeq().SeqNo = 200 + i // distinct per call: none can claim an existing ticket
		go func(req *sip.Request) { results <- u.arrivalEnter(req) }(n)
	}

	wantArmed := arrivalMaxPending - 1
	for armed := 0; armed < wantArmed; armed++ {
		select {
		case <-waiting:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d/%d handler-path arrivals armed the bounded wait; the flood may be stuck", armed, wantArmed)
		}
	}

	// Collect every result available WITHOUT advancing the fake clock, exactly
	// as TestArrivalEnterCapsPendingTicketsUnderHandlerPathFlood does: this is
	// the refused calls (nil) plus the one call with nothing ahead of it. By
	// the time these have all arrived, every cap refusal arrivalEnter is ever
	// going to log for this control operation has already happened.
	wantFast := flood - arrivalMaxPending + 1
	fast := make([]*arrivalTicket, 0, wantFast)
	for len(fast) < wantFast {
		select {
		case tk := <-results:
			fast = append(fast, tk)
		case <-time.After(3 * time.Second):
			t.Fatalf("%d/%d handler-path arrivals returned without waiting; want exactly %d", len(fast), wantFast, wantFast)
		}
	}

	warnCount := strings.Count(buf.String(), "was refused an arrival ticket")
	if warnCount != 1 {
		t.Fatalf("logged %d arrivalEnter cap-refusal Warn lines across a %d-request handler-path flood, want exactly 1", warnCount, flood)
	}

	// Release the rest so no goroutine from this test leaks past it.
	clk.Advance(u.cfg.Timeout)
	for i := 0; i < wantArmed; i++ {
		select {
		case <-results:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d/%d bounded waits released after the clock advanced", i, wantArmed)
		}
	}
}

// assertAFinalNotifyThatArrivedFirstWins runs D18's adverse schedule on a
// transfer already in flight on d: the final NOTIFY reaches the transport
// before the BYE, but the BYE's handler runs first. It must wait at the gate,
// and the transfer must settle as a success.
func assertAFinalNotifyThatArrivedFirstWins(t *testing.T, u *UA, callID, ours, event string, notifyCSeq uint32, evs <-chan session.UAEvent) {
	t.Helper()
	notify := referNotifyReq(callID, "peer-tag", ours, event, "SIP/2.0 200 OK")
	notify.CSeq().SeqNo = notifyCSeq
	bye := peerByeReq(callID, ours)
	bye.CSeq().SeqNo = notifyCSeq + 1
	waiting := setArrivalWaitHook(t, sip.BYE)

	u.observeArrival(notify)
	u.observeArrival(bye)
	byeDone := make(chan struct{})
	go func() {
		defer close(byeDone)
		u.onBye(bye, &stubServerTx{})
	}()
	select {
	case <-waiting:
	case <-byeDone:
		t.Fatal("the peer's BYE was applied before the final NOTIFY that reached the transport ahead of it (D18)")
	case <-time.After(3 * time.Second):
		t.Fatal("onBye neither waited for the earlier NOTIFY nor finished")
	}
	// Watchdogged: a stale ticket left ahead of it would park the NOTIFY on
	// the fake clock for good.
	tx := &stubServerTx{}
	notifyDone := make(chan struct{})
	go func() {
		defer close(notifyDone)
		u.onNotify(notify, tx)
	}()
	select {
	case <-notifyDone:
	case <-time.After(3 * time.Second):
		t.Fatal("the final NOTIFY stayed behind the gate: a ticket from outside this control op is still ahead of it")
	}
	if got := tx.last().StatusCode; got != 200 {
		t.Fatalf("the final NOTIFY drew %d, want 200", got)
	}
	select {
	case <-byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("onBye stayed behind the gate after the NOTIFY left it")
	}
	select {
	case final := <-evs:
		if final.Detail["final"] != true || final.Detail["success"] != true || final.Code != 200 {
			t.Fatalf("final transfer event %+v, want success (D18)", final.Detail)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no final transfer event")
	}
}

// TestAHugeCSeqCannotDisableTheArrivalGateForALaterControlOp is the
// correctness half of finding 4 (security M-5). One NOTIFY with CSeq 2^32-1
// used to pin the dialog's maxCSeq for good, so the observer never ticketed
// anything on it again and D18's ordering silently stopped for the rest of the
// dialog's life. Now CSeq state only exists while a control operation holds
// the dialog, and its release clears it.
func TestAHugeCSeqCannotDisableTheArrivalGateForALaterControlOp(t *testing.T) {
	const huge = ^uint32(0)
	t.Run("sent while no control op is in flight", func(t *testing.T) {
		u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
		d, ours := newNotifyTestDialog(u, "cid-cseq-idle")
		n := referNotifyReqState("cid-cseq-idle", "peer-tag", ours, "refer;id=3", "SIP/2.0 100 Trying", "active")
		n.CSeq().SeqNo = huge
		u.observeArrival(n)
		u.onNotify(n, &stubServerTx{})
		// P-11 (CF-101): this test is about the arrival gate's per-operation maxCSeq
		// (M-5), not the dialog's remote CSeq (RFC 3261 12.2.2). The huge NOTIFY just
		// raised the dialog's remote number, so the next NOTIFY 9 would rightly draw
		// 500; clear it so the test keeps asserting the arrival gate alone.
		u.calls.mu.Lock()
		d.remoteCSeqSet = false
		u.calls.mu.Unlock()

		evs := startNotifyTransfer(t, u, d, newReferWaiter(7, session.TransferBlind))
		assertAFinalNotifyThatArrivedFirstWins(t, u, "cid-cseq-idle", ours, "refer;id=7", 9, evs)
	})
	t.Run("sent during an earlier control op", func(t *testing.T) {
		u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
		d, ours := newNotifyTestDialog(u, "cid-cseq-earlier")
		evsA := startNotifyTransfer(t, u, d, newReferWaiter(7, session.TransferBlind))
		n := referNotifyReq("cid-cseq-earlier", "peer-tag", ours, "refer;id=7", "SIP/2.0 486 Busy Here")
		n.CSeq().SeqNo = huge
		u.observeArrival(n)
		u.onNotify(n, &stubServerTx{})
		// P-11 (CF-101): this test is about the arrival gate's per-operation maxCSeq
		// (M-5), not the dialog's remote CSeq (RFC 3261 12.2.2). The huge NOTIFY just
		// raised the dialog's remote number, so the next NOTIFY 9 would rightly draw
		// 500; clear it so the test keeps asserting the arrival gate alone.
		u.calls.mu.Lock()
		d.remoteCSeqSet = false
		u.calls.mu.Unlock()
		select {
		case ev := <-evsA:
			if ev.Detail["final"] != true || ev.Code != 486 {
				t.Fatalf("transfer A's event %+v, want its final 486", ev.Detail)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("transfer A never settled")
		}
		for deadline := time.Now().Add(3 * time.Second); ; {
			u.calls.mu.Lock()
			ph := d.phase
			u.calls.mu.Unlock()
			if ph == phaseAnswered {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("transfer A never released the dialog (phase %v)", ph)
			}
			time.Sleep(time.Millisecond)
		}

		evsB := startNotifyTransfer(t, u, d, newReferWaiter(8, session.TransferBlind))
		assertAFinalNotifyThatArrivedFirstWins(t, u, "cid-cseq-earlier", ours, "refer;id=8", 9, evsB)
	})
}
