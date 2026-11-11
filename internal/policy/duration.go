package policy

import "time"

// CallDeadline returns the instant a call started at startedAt must be
// force-terminated under this policy's max_call_duration_s. ok is false when
// no cap is configured.
//
// Note that the deadline is computed from startedAt, not from now: on a
// SIGHUP that LOWERS the cap, §12.2.1 requires the new cap to be evaluated
// against each live call's CURRENT ELAPSED TIME, so a call already past the
// new cap receives a deadline in the past and its owner terminates it at
// once. Computing from now would silently grant every live call a fresh full
// duration, which is the opposite of the control's purpose.
func (p *Policy) CallDeadline(startedAt time.Time) (time.Time, bool) {
	// Phase 4 W1 M2, Inputs §3: tested against the RAW field, before any
	// multiplication — see ClampDuration's comment below for why that
	// ordering is the fix and not cosmetic. validate()'s 86400s load-time
	// ceiling is what makes this multiplication safe for every value Load
	// can ever produce; a directly-constructed *Policy that skips Load is
	// still this function's caller's responsibility, not this guard's.
	if p.Limits.MaxCallDurationS == 0 {
		return time.Time{}, false
	}
	return startedAt.Add(time.Duration(p.Limits.MaxCallDurationS) * time.Second), true
}

// ClampDuration clamps an agent-supplied max_duration_s DOWN to the policy
// cap and never up (§12.2). A zero or negative request means "no preference"
// and takes the cap; when no cap is configured, a negative request has no
// cap value to take, so it is floored to zero instead of passed through,
// keeping the result usable for arming a timer.
func (p *Policy) ClampDuration(requested time.Duration) time.Duration {
	// Phase 4 W1 M2, Inputs §3's overflow fix: "uncapped" is decided from the
	// RAW p.Limits.MaxCallDurationS field, BEFORE any multiplication —
	// NEVER inferred from a post-multiplication capD <= 0, which is what this
	// function used to test. That aliased two different things onto one
	// branch: a genuinely uncapped policy (MaxCallDurationS == 0, capD == 0)
	// and a huge configured cap whose int-seconds x time.Second multiplication
	// wrapped negative (capD < 0) — the second case then returned the
	// caller's requested duration completely UNCLAMPED, fail-open, for a
	// policy that had in fact configured a (very large but finite) cap.
	// validate()'s 86400s load-time ceiling means no value Load can ever
	// produce reaches this function able to overflow the multiplication
	// below; the guard is ordered this way regardless, so overflow can never
	// again alias onto "uncapped".
	if p.Limits.MaxCallDurationS == 0 {
		if requested < 0 {
			return 0
		}
		return requested
	}
	capD := time.Duration(p.Limits.MaxCallDurationS) * time.Second
	if requested <= 0 || requested > capD {
		return capD
	}
	return requested
}

// EarlierDeadline returns the earlier of two deadlines, treating the zero
// time as "no deadline".
//
// This is the whole mechanism behind §12.2.1's "a RAISED cap never extends a
// call already scheduled to end". A reload recomputes each live call's
// deadline and combines it with the existing one through this function, so a
// deadline can only ever move earlier. Replacing a call's deadline with the
// recomputed value directly would let a raised cap extend a live call, which
// §12.2.1 forbids.
func EarlierDeadline(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case b.Before(a):
		return b
	default:
		return a
	}
}
