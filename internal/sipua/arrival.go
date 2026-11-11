package sipua

// Rule 16 reuse decision for this file:
//
//   REUSED: sipgo's TransportLayer.OnMessage (third_party/sipgo/sip/
//           transport_layer.go:114, UNMODIFIED): the one point in the vendored
//           stack that runs synchronously in a connection's read loop, in
//           wire-arrival order, before that loop reads the next message (plan
//           D18). findByCallIDLocked/callIDOf (call.go): the SAME Call-ID match
//           onBye uses. u.cfg.Clock and u.cfg.Timeout for the wait's bound.
//           Searched for an existing inbound-ordering primitive in
//           internal/sipua and third_party/sipgo: none. sipgo forks every
//           request (transaction_layer.go:67), and the send-order token
//           (indialog.go, D12) orders OUR requests, not the peer's.
//   NOT ADDED: any third_party/sipgo change (plan D18 says why none is needed).

import (
	"github.com/emiago/sipgo/sip"
)

// arrivalGatedMethods are the inbound requests whose handlers apply their effect
// on a dialog in WIRE-ARRIVAL order (plan D18). Today that is NOTIFY and BYE,
// the two whose handlers race on a transfer's outcome (D16). The primitive is
// method-neutral. A handler joins by calling arrivalEnter first and
// arrivalLeaveLocked inside the critical section that applies its effect, and
// its method is added here. Nothing else changes.
//
// SCOPE: ONLY WHILE A CONTROL OPERATION HOLDS THE DIALOG (Rule 13 fix batch A,
// finding 4). Ordering only matters while an operation's outcome can depend on
// it. Outside phaseControlOp the observer stamps nothing and arrivalEnter
// returns at once, so ordinary NOTIFY/BYE traffic never tickets or waits, and
// no CSeq state exists. releaseControlOpLocked calls resetLocked, which lets
// every pending ticket leave and forgets the CSeq state. That bounds both what
// an orphan ticket can stall (security I-1) and how long a huge peer CSeq can
// suppress ticketing (M-5) to the one operation's lifetime.
var arrivalGatedMethods = map[sip.RequestMethod]bool{sip.NOTIFY: true, sip.BYE: true}

// arrivalMaxPending caps how many tickets one dialog's arrival gate can hold,
// from EITHER path that creates one: observeArrival's read-loop append, and
// arrivalEnter's own append when a handler finds no existing ticket for
// itself. Round 2 of the I-1 fix capped only the first path; a re-verify
// found the second was just as cheap to exploit, since sipgo forks a
// goroutine and a server transaction for any request on a branch it has not
// seen (no per-dialog concurrency limit), so a peer sending distinct-branch
// NOTIFY/BYE requests reaches a real handler, and so arrivalEnter, every
// time. With pending capped from both paths, it can never hold more than
// this many tickets no matter which path is appending, which is what bounds
// resetLocked's release pass AND arrivalEnter's own per-call scan of pending
// and the `ahead` slice it copies from it (Rule 13 security cycle, finding
// I-1 round 3). Legitimate NOTIFY/BYE traffic during one control operation is
// a handful of requests; a request refused a ticket under this cap (by
// either path) still gets ordinary handling, just without D18's ordering
// guarantee for that one request.
const arrivalMaxPending = 16

// arrivalWaitHook is a TEST-ONLY seam, nil in production (the
// referOutcomeArmHook precedent). arrivalEnter calls it when a request has to
// wait for an earlier one, AFTER arming the bound's timer, so a test can
// Advance the fake clock without racing the arm.
var arrivalWaitHook func(method sip.RequestMethod)

// arrivalOrder is ONE dialog's inbound ordering gate (plan D18). Gated requests
// on the dialog apply their effect in the order they reached the transport, not
// in the order sipgo's per-request goroutines happen to be scheduled. The zero
// value is ready. Guarded by u.calls.mu. It lives on the dialog and is dropped
// with it, so it needs no expiry of its own.
type arrivalOrder struct {
	observed  uint64           // observeArrival calls that matched this dialog (read by a test)
	seq       uint64           // the last arrival sequence number stamped
	cseqSeen  bool             // maxCSeq holds a value
	maxCSeq   uint32           // the highest peer CSeq ticketed during the current control operation
	pending   []*arrivalTicket // tickets that have not left, in arrival order
	capWarned bool             // true once this operation has logged the cap-refusal Warn (CF-017); reset by resetLocked
}

// arrivalTicket is one gated request's place in its dialog's arrivalOrder.
type arrivalTicket struct {
	order   *arrivalOrder
	method  sip.RequestMethod
	cseq    uint32
	seq     uint64        // arrival sequence number, for the Warn log
	claimed bool          // a handler holds it
	left    bool          // it has left the gate
	done    chan struct{} // closed when it leaves
}

// appendLocked stamps the next arrival sequence number onto a new ticket.
// Caller MUST hold u.calls.mu.
func (a *arrivalOrder) appendLocked(method sip.RequestMethod, cseq uint32, claimed bool) *arrivalTicket {
	if !a.cseqSeen || cseq > a.maxCSeq {
		a.cseqSeen, a.maxCSeq = true, cseq
	}
	a.seq++
	tk := &arrivalTicket{order: a, method: method, cseq: cseq, seq: a.seq, claimed: claimed, done: make(chan struct{})}
	a.pending = append(a.pending, tk)
	return tk
}

// resetLocked ends the gate's scope when a control operation is released:
// every pending ticket leaves directly (waking anything behind it) in one
// linear pass, paired with arrivalMaxPending capping how large that pass can
// ever be, and the CSeq high-water mark is forgotten, so the next operation
// starts clean. The operation's outcome is already settled by then, so no
// ordering is lost. A handler still holding a released ticket leaves it later
// as a no-op. Caller MUST hold u.calls.mu.
func (a *arrivalOrder) resetLocked() {
	for _, tk := range a.pending {
		if tk.left {
			continue
		}
		tk.left = true
		close(tk.done)
	}
	a.pending = nil
	a.cseqSeen, a.maxCSeq = false, 0
	a.capWarned = false
}

// observeArrival is registered on sipgo's TransportLayer.OnMessage by
// installHandlers (plan D18). sipgo calls it synchronously in the connection's
// read loop, once per parsed message, in wire order: directly AFTER the
// transaction layer has forked the message's handler goroutine
// (transaction_layer.go:67) and BEFORE the loop reads the next message. That
// last property is the whole guarantee. A gated request's ticket (appended here,
// or by its own handler if the handler reached arrivalEnter first) exists before
// any later-read request's ticket can.
//
// It runs on the read loop, so it only filters, counts and appends under
// u.calls.mu: no I/O and no waiting. It tickets nothing unless a control
// operation holds the dialog (finding 4). It does NOT ticket a request whose CSeq is
// not above every CSeq already ticketed on the dialog. That is a retransmission
// (sipgo's transaction layer absorbs it and no handler runs, so its ticket would
// never be claimed), a request whose handler already ticketed itself, or one the
// network reordered behind a higher CSeq. If its handler does run, arrivalEnter
// tickets it then.
func (u *UA) observeArrival(msg sip.Message) {
	req, ok := msg.(*sip.Request)
	if !ok || !arrivalGatedMethods[req.Method] {
		return
	}
	cs := req.CSeq()
	if cs == nil {
		return
	}
	// warn (and the fields below it) are set inside the locked section below
	// and read here, AFTER u.calls.mu.Unlock() has already run: this defer is
	// registered BEFORE "defer u.calls.mu.Unlock()" just below, and deferred
	// calls run LIFO, so Unlock (registered second) runs first and this
	// closure (registered first) runs second — off the lock, matching this
	// function's own "no I/O, no waiting" invariant (Rule 13 fix batch,
	// CF-017 Warn-under-lock finding).
	var warn bool
	var warnDialogID, warnCallID string
	var warnMethod sip.RequestMethod
	var warnCSeq uint32
	defer func() {
		if warn {
			u.log().Warn("an inbound request's arrival was not ticketed because its dialog's "+
				"arrival gate is already at capacity; proceeding without D18's ordering guarantee for it",
				"dialog_id", warnDialogID, "call_id", warnCallID, "method", string(warnMethod), "cseq", warnCSeq, "cap", arrivalMaxPending)
		}
	}()
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	d := u.findDialogForRequestLocked(req)
	if d == nil {
		return
	}
	a := &d.arrivals
	a.observed++
	if d.phase != phaseControlOp {
		return // finding 4: nothing to order, so no ticket and no CSeq state
	}
	if a.cseqSeen && cs.SeqNo <= a.maxCSeq {
		return
	}
	if len(a.pending) >= arrivalMaxPending {
		// Still advance the high-water mark so a later flood at or below this
		// CSeq keeps being dropped as a duplicate (M-5) even while capped.
		a.cseqSeen, a.maxCSeq = true, cs.SeqNo
		if !a.capWarned {
			a.capWarned = true
			warn, warnDialogID, warnCallID, warnMethod, warnCSeq = true, d.id, d.callID, req.Method, cs.SeqNo
		}
		return
	}
	a.appendLocked(req.Method, cs.SeqNo, false)
}

// arrivalEnter is the FIRST thing a gated handler does (onNotify, onBye; plan
// D18). It claims the request's ticket: the one observeArrival stamped, or a new
// one appended now if the handler beat its observer or the observer skipped it.
// It returns once every ticket AHEAD of it on the dialog has left the gate, and
// it holds no lock while it waits. The handler MUST pass the result to
// arrivalLeaveLocked inside the critical section that applies its effect. A nil
// result (no such dialog, or no control operation holds it: the fast path of
// finding 4) did not wait, and leaving it is a no-op.
//
// A handler that finds no ticket waits for EVERY pending ticket. If it beat its
// own observer, no later request has been read yet, so all of them really are
// ahead of it on the wire. If the observer skipped it (a late retransmission, or
// a request reordered behind a higher CSeq), waiting for a newer request is
// harmless: this one is stale either way.
//
// CAP. A handler that finds no ticket for itself is refused one (the fast
// path of finding 4: no ordering wait) once pending already holds
// arrivalMaxPending tickets, from either path. Because BOTH appending paths
// respect this cap, the search loop just above -- which every call runs, over
// the dialog's current pending, before it knows whether it has a ticket to
// claim -- can never scan more than arrivalMaxPending entries, and `ahead`
// can never hold more than that either, regardless of how much traffic a peer
// sends (Rule 13 security cycle, finding I-1 round 3). A ticket that already
// exists for this request is still claimed regardless of pending's size: that
// path does not grow pending, so the cap does not apply to it.
//
// BOUND. The wait ends after u.cfg.Timeout even if an earlier ticket never
// leaves. Either its request never reached a handler (sipgo drops a request it
// cannot build a server transaction for, transaction_layer.go:106-134) or its
// handler is wedged. The earlier tickets are then abandoned, so they cannot stall
// any later request, a Warn is logged, and this request proceeds. u.cfg.Timeout
// is the right size. A gated handler holds its ticket for one short critical
// section, so reaching the bound means something is already broken. It is also
// the peer's own non-INVITE transaction budget (Timer F), after which the peer
// has abandoned the request anyway.
func (u *UA) arrivalEnter(req *sip.Request) *arrivalTicket {
	var cseq uint32
	if cs := req.CSeq(); cs != nil {
		cseq = cs.SeqNo
	}
	u.calls.mu.Lock()
	d := u.findDialogForRequestLocked(req)
	if d == nil || d.phase != phaseControlOp {
		// Finding 4: with no control operation, nothing waits and nothing is
		// ticketed. A ticket the observer stamped during an operation that has
		// since been released was already let go by resetLocked.
		u.calls.mu.Unlock()
		return nil
	}
	a := &d.arrivals
	var tk *arrivalTicket
	var ahead []*arrivalTicket
	for _, p := range a.pending {
		if !p.claimed && p.method == req.Method && p.cseq == cseq {
			tk = p
			break
		}
		ahead = append(ahead, p)
	}
	if tk == nil {
		if len(a.pending) >= arrivalMaxPending {
			// Round 3 (Rule 13 security re-verify): a NEW arrival is refused
			// ticketing once the gate already holds arrivalMaxPending entries,
			// from EITHER path (observeArrival or a real handler here). This
			// closes the gap the observer-only cap left open: arrivalEnter's
			// own appendLocked was unbounded, so a peer sending distinct-branch
			// NOTIFY/BYE requests -- each reaching a real handler cheaply --
			// could still grow pending without limit, and every later handler's
			// scan into `ahead` copied the whole (unbounded) queue, which is
			// what made this O(n^2) in both memory and lock-held time. With
			// this check, `pending` never exceeds arrivalMaxPending from any
			// path, so that scan and `ahead` stay bounded by the same constant.
			// Warn (I/O) is logged AFTER Unlock, below — never while holding
			// u.calls.mu (Rule 13 fix batch, CF-017 Warn-under-lock finding).
			warn := !a.capWarned
			a.capWarned = true
			u.calls.mu.Unlock()
			if warn {
				u.log().Warn("an inbound request was refused an arrival ticket because its dialog's "+
					"arrival gate is already at capacity; proceeding without D18's ordering guarantee for it",
					"dialog_id", d.id, "call_id", d.callID, "method", string(req.Method), "cseq", cseq, "cap", arrivalMaxPending)
			}
			return nil
		}
		tk = a.appendLocked(req.Method, cseq, true)
	} else {
		tk.claimed = true
	}
	u.calls.mu.Unlock()
	if len(ahead) == 0 {
		return tk
	}

	timer := u.cfg.Clock.NewTimer(u.cfg.Timeout)
	defer timer.Stop()
	if arrivalWaitHook != nil {
		arrivalWaitHook(req.Method)
	}
	for _, p := range ahead {
		select {
		case <-p.done:
		case <-timer.C():
			u.calls.mu.Lock()
			for _, q := range ahead {
				arrivalLeaveLocked(q)
			}
			u.calls.mu.Unlock()
			u.log().Warn("an inbound request waited out the arrival-order bound behind an earlier one on its dialog; proceeding (plan D18)",
				"dialog_id", d.id, "call_id", d.callID,
				"method", string(req.Method), "cseq", cseq, "arrival_seq", tk.seq,
				"stalled_method", string(p.method), "stalled_cseq", p.cseq, "stalled_arrival_seq", p.seq)
			return tk
		}
	}
	return tk
}

// arrivalLeaveLocked lets tk leave its dialog's gate and wakes whatever waits on
// it (plan D18). Nil-safe and idempotent: a ticket abandoned by a bounded wait
// may still be left later by its own handler. Caller MUST hold u.calls.mu.
func arrivalLeaveLocked(tk *arrivalTicket) {
	if tk == nil || tk.left {
		return
	}
	tk.left = true
	close(tk.done)
	a := tk.order
	for i, p := range a.pending {
		if p == tk {
			a.pending = append(a.pending[:i], a.pending[i+1:]...)
			return
		}
	}
}
