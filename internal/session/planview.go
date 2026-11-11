package session

// §2.3 (locked decision 7): session.Call — not the UA — owns call_status's
// media_plan readout.
//
// WHY IT MOVED. call_status used to read ua.Agent().MediaPlanView(c.DialogID()),
// which returns ok == false the instant teardownDialog forgets the dialog. A
// terminated call's media_plan therefore VANISHED from its own status — the P2
// W5 carry-forward gap. Call already receives every UAEventPlanStep and already
// learns steps_total from validateMediaPlan's output, so it can maintain the
// view from its own event stream with NO new UA plumbing: this is a reuse of an
// existing channel, not a new one.
//
// UA.MediaPlanView is RETAINED and unchanged, but the earlier version of this
// paragraph gave a reason that is FALSE: it claimed the method is "still the
// live-call view the plan executor and wait_dtmf read inside sipua". Neither
// reads it. The plan executor uses mp.view()/mp.setState directly
// (sipua/call.go), and wait_dtmf goes through waitForDigits and never touches
// it. Verified: sipua.(*UA).MediaPlanView and the session.UserAgent.MediaPlanView
// obligation it satisfies (collaborators.go) have ZERO non-test callers anywhere
// in the tree — the only callers are tests and the fakes.UserAgent/nopAgent
// implementations the interface forces.
//
// The retention itself is correct and stands: Rule 19 reports pre-existing dead
// code rather than deleting it. But the reason had to be corrected, because a
// false claim of a live caller is worse than no comment — the next reader who
// goes to remove the method reads that sentence, believes it, and stops. That is
// the same failure mode as this wave's dead tests: an artefact that looks
// load-bearing only because a comment says so. The method is a removal candidate
// for a later phase, alongside session.MediaSession (already marked
// CONFIRMED-DEAD in collaborators.go).
//
// Every field below is guarded by Call.mu, like every other mutable Call field.

// SetPlanTotal registers that a §10.7 plan of n steps is running on this call.
// Called ONCE per call, by CallDial/CallAnswer, immediately after
// validateMediaPlan returns and before the UA is asked to dial or answer — so
// no plan_step event can arrive before the view exists. n <= 0 is a no-op:
// "no plan" stays "no plan".
func (c *Call) SetPlanTotal(n int) {
	if n <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.planPresent = true
	c.planTotal = n
	c.planState = "running"
	c.planFailedIndex = -1
}

// PlanView is §10.7's call_status.media_plan readout. ok is false when no plan
// ran on this call. It is answerable for the whole of the call's registry
// lifetime, including after termination — which is the entire point of the move.
func (c *Call) PlanView() (MediaPlanView, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.planPresent {
		return MediaPlanView{}, false
	}
	state := c.planState
	if state == "running" &&
		(c.planCompleted >= c.planTotal || c.planLastOp == "hangup") {
		// The executor breaks out of its run loop on a hangup step, so a
		// completed plan can legitimately have stepsCompleted < stepsTotal.
		state = "completed"
	}
	return MediaPlanView{
		State:          state,
		StepsTotal:     c.planTotal,
		StepsCompleted: c.planCompleted,
		FailedIndex:    c.planFailedIndex,
		FailedOp:       c.planFailedOp,
		Present:        true,
	}, true
}

// applyPlanStep folds one §10.7 plan_step detail into the view. An ENTRY event
// (no status) is ignored for counting; a completion moves the counters. Unknown
// or malformed details are ignored rather than fabricating state.
func (c *Call) applyPlanStep(detail map[string]any) {
	idx, idxOK := jsonInt(detail["index"])
	op, _ := detail["op"].(string)
	status, _ := detail["status"].(string)
	if !idxOK || status == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.planPresent {
		return
	}
	switch status {
	case "ok":
		if idx+1 > c.planCompleted {
			c.planCompleted = idx + 1
		}
		c.planLastOp = op
	case "failed":
		c.planState = "failed"
		c.planFailedIndex, c.planFailedOp = idx, op
	}
}

// applyPlanError folds the executor's plan_aborted_call_terminated error detail
// into the view. Every other error kind is ignored here.
func (c *Call) applyPlanError(detail map[string]any) {
	if kind, _ := detail["kind"].(string); kind != "plan_aborted_call_terminated" {
		return
	}
	idx, idxOK := jsonInt(detail["index"])
	if !idxOK {
		// Same "don't fabricate state" rule applyPlanStep follows: a missing
		// or malformed index must not silently read as index 0.
		idx = -1
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.planPresent {
		return
	}
	// E-M2: a step already recorded FAILED is more informative than a later
	// abort and must not be clobbered by it — applyPlanStep's "failed" branch
	// already ran and named the real culprit; an abort arriving afterward
	// (e.g. the call terminating as a consequence of that failure) must leave
	// it alone.
	if c.planState == "failed" {
		return
	}
	c.planState = "aborted"
	c.planFailedIndex, c.planFailedOp = idx, ""
}
