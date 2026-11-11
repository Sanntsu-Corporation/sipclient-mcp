package session

import (
	"sync"
	"time"
)

// UAState is a UA record's lifecycle state.
type UAState string

// The two UAState values.
const (
	UALive      UAState = "live"
	UADestroyed UAState = "destroyed"
)

// UA is one user agent's registry entry. Its mutex is the SECOND level of the
// total order registry -> UA -> call.
type UA struct {
	handle Handle
	sid    string
	agent  UserAgent
	cfg    UAConfig

	// accounted is RecordUADestroyed's FIRES-EXACTLY-ONCE guard for the
	// GLOBAL m.liveUATotal decrement. GUARDED BY Manager.mu, THE REGISTRY
	// LOCK — deliberately NOT by u.mu below, because every read and write of
	// it happens inside a registry critical section alongside m.liveUATotal
	// itself. See Call.accounted for the leak this replaces.
	accounted bool

	mu          sync.Mutex
	state       UAState
	createdAt   time.Time
	destroyedAt time.Time
	registered  bool

	// registerCode is the far end's status code from the most recent REGISTER
	// attempt (D75): 200 on success, the far end's own code on a rejection
	// (§11.1 — a rejected registration is a successful tool call, not an
	// error), and 0 when there is NO current registration status to report —
	// either because no REGISTER has completed yet, or because
	// recordRegistrationLost cleared it when the R10 refresh gave up. It is
	// never left describing a registration that no longer exists.
	registerCode int
	// expiresS/refreshBaseAt back NextRefreshMS's countdown: expiresS is the
	// most recently granted expiry and refreshBaseAt is the instant it was
	// granted (the initial REGISTER, or the most recent refresh). Both stay
	// zero on a direct-mode UA, which has no registration to refresh.
	expiresS      int
	refreshBaseAt time.Time
}

// Handle returns the UA's own opaque handle.
func (u *UA) Handle() Handle { return u.handle }

// SessionID returns the id of the logical session that owns this UA.
func (u *UA) SessionID() string { return u.sid }

// Agent returns the underlying UserAgent this record wraps.
func (u *UA) Agent() UserAgent { return u.agent }

// Config returns the UAConfig this UA was created from. §12.7's GET /admin/uas
// reads Mode, AOR and Transport out of it; ua_status reads the same fields.
func (u *UA) Config() UAConfig { return u.cfg }

// CreatedAt reports when the UA was created.
func (u *UA) CreatedAt() time.Time { return u.createdAt }

// Registered reports the outcome of the UA's most recent REGISTER.
func (u *UA) Registered() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.registered
}

// State returns the UA's current lifecycle state.
func (u *UA) State() UAState {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.state
}

// MarkDestroyed claims the live -> destroyed transition; exactly one caller
// wins, so ua_destroy and the §12.7 admin DELETE cannot both tear down once.
func (u *UA) MarkDestroyed(now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.state == UADestroyed {
		return false
	}
	u.state = UADestroyed
	u.destroyedAt = now
	return true
}

// DestroyedAt reports when the UA transitioned to destroyed; the zero time while live.
func (u *UA) DestroyedAt() time.Time {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.destroyedAt
}

// setRegistered records the outcome of a REGISTER. Task 11a's teardown reads
// it to decide whether a REGISTER Expires: 0 is owed. Unexported: not in
// contract §2.5.4's nine-getter list (D32); `session` is the only writer.
func (u *UA) setRegistered(v bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.registered = v
}

// RegisterCode returns the far end's status code from the most recent
// REGISTER attempt: 200 on success, the exact rejection code on a denial
// (§11.1: a rejected registration is a successful tool call, not an error),
// and 0 before any REGISTER has completed or on a direct-mode UA.
func (u *UA) RegisterCode() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.registerCode
}

// ExpiresS reports the registrar's most recently GRANTED expiry in seconds
// (D136) — the same expiresS field NextRefreshMS counts down from, NOT
// UAConfig.ExpiresS (the operator-REQUESTED value: see that field's doc
// comment). 0 on a direct-mode UA or one that has never completed a
// REGISTER — the same convention NextRefreshMS uses, and for the same
// reason.
func (u *UA) ExpiresS() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.expiresS
}

// NextRefreshMS reports §10.2's registration-refresh countdown in
// milliseconds, as of `now`. 0 on a direct-mode UA or one that has never
// completed a REGISTER — neither has a refresh to count down to.
//
// sipua schedules its own refresh timer somewhere between 50% and 90% of the
// granted expiry (R10); this reports the countdown to the LATEST instant that
// timer is expected to fire — 90% of the granted expiry, measured from the
// last successful REGISTER or refresh — clamped to 0 once passed.
func (u *UA) NextRefreshMS(now time.Time) int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.expiresS <= 0 {
		return 0
	}
	refreshAt := u.refreshBaseAt.Add(time.Duration(float64(u.expiresS) * 0.9 * float64(time.Second)))
	if ms := refreshAt.Sub(now).Milliseconds(); ms > 0 {
		return ms
	}
	return 0
}

// recordRegistration records the outcome of a REGISTER: whether it
// succeeded, the far end's status code, and — when the registrar granted an
// expiry — the base instant NextRefreshMS counts down from. Unexported:
// `session` is the only writer, mirroring setRegistered.
func (u *UA) recordRegistration(reg RegisterResult, at time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.registered = reg.Registered
	u.registerCode = reg.Code
	if reg.ExpiresS > 0 {
		u.expiresS = reg.ExpiresS
		u.refreshBaseAt = at
	}
}

// recordRefresh applies R10's registration refresh: the UA is (still)
// registered and the registrar's granted expiry may have changed. It leaves
// registerCode UNTOUCHED — UAEventRefresh carries no status code of its own
// (that is UAEvent.Code, which is 0 for this kind) — so a refresh cannot
// overwrite the code the initial REGISTER learned with a zero.
func (u *UA) recordRefresh(expiresS int, at time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.registered = true
	if expiresS > 0 {
		u.expiresS = expiresS
		u.refreshBaseAt = at
	}
}

// recordRegistrationLost is recordRefresh's give-up counterpart (R10): the
// refresh exhausted its retries, so the UA is NOT registered any more.
//
// It clears the GRANTED expiry as well as the flag, because expires_s and
// next_refresh_ms are both derived from it: leaving them set would have
// ua_status report a live countdown to a refresh that will never fire, on a UA
// it simultaneously reports as unregistered. 0 is the same value both fields
// already carry for a UA that has never completed a REGISTER (see ExpiresS and
// NextRefreshMS), so no consumer needs a new case.
//
// IT ALSO ZEROES registerCode, AND THAT IS THE LOCKED ua_status SHAPE. Left set,
// a UA that has just lost its registration reports `registered: false` beside
// `register_code: 200` — a success code describing a registration that no longer
// exists, which is the most misleading pair the two fields can form. recordRefresh
// leaves the code alone for the opposite reason: it runs on SUCCESS, where the
// last code is still an accurate description of the current registration. There is
// no precedent in this package for keeping a stale SUCCESS code beside a failure
// state (call_status's `code` is the code that CAUSED the outcome it sits next to),
// so the field goes to 0 — which is the same value it already carries for a UA
// that has never completed a REGISTER, so ua_status gains no new case and no
// consumer needs one.
func (u *UA) recordRegistrationLost() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.registered = false
	u.registerCode = 0
	u.expiresS = 0
	u.refreshBaseAt = time.Time{}
}
