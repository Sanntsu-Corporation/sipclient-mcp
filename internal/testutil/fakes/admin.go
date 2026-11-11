package fakes

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// UA is the fixture struct AddUA takes. Its field names mirror
// session.AdminUAView's, because LiveUAs must return exactly that type and a
// second vocabulary for the same ten fields would be a translation layer with
// no behaviour (Rule 15).
type UA struct {
	UAHandle          string
	Session           string
	Mode              string
	AOR               string
	Transport         string
	Registered        bool
	ActiveCalls       int
	CreatedAt         time.Time
	SessionConnected  bool
	SessionLastSeenAt time.Time
}

// Admin is a hand-written fake of the Admin interface internal/transport/mcp
// declares (§12.7's operator plane). P1d Task 19's handler tests drive it so
// they exercise the TRANSPORT half — routing, auth, status codes, the body
// shape, the audit line — without a real session.Manager.
//
// It deliberately proves NOTHING about the registry-lock-release property of
// §12.7: that property lives in session and is discharged by P1b Task 11a's
// unit test and P1e Task 23's wire test. A fake cannot demonstrate that a
// lock it does not hold was released. What the transport test CAN prove with
// this fake is that the handler adds no serialization of its own, which is
// why SetTeardownDelay must really block — see below.
type Admin struct {
	mu sync.Mutex

	live        []UA
	destroyedUA map[string]bool // AddDestroyedUA: recorded, NEVER listed
	owner       map[string]string
	teardowns   map[string]int
	reasons     map[string]string
	delays      map[string]time.Duration
	maxUAsTotal int

	// DestroyErr, when set, overrides the normal outcome for EVERY handle.
	DestroyErr error
}

// NewAdmin returns an empty Admin fake with no live or destroyed UAs.
func NewAdmin() *Admin {
	return &Admin{
		destroyedUA: make(map[string]bool),
		owner:       make(map[string]string),
		teardowns:   make(map[string]int),
		reasons:     make(map[string]string),
		delays:      make(map[string]time.Duration),
	}
}

// ---- fixture setup ---------------------------------------------------------

// AddUA adds a LIVE UA. Zero CreatedAt/SessionLastSeenAt are given plausible
// non-zero values, so a test asserting the JSON carries created_at and
// session_last_seen_at cannot pass against a zero time that marshals to a
// placeholder.
func (a *Admin) AddUA(ua UA) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ua.CreatedAt.IsZero() {
		ua.CreatedAt = time.Unix(1_700_000_000, 0).UTC()
	}
	if ua.SessionLastSeenAt.IsZero() {
		ua.SessionLastSeenAt = time.Unix(1_700_000_000, 0).UTC()
	}
	a.live = append(a.live, ua)
	a.owner[ua.UAHandle] = ua.Session
}

// AddDestroyedUA records a handle that HAS been destroyed. It is never
// returned by LiveUAs — §12.7's GET is a LIVE-OBJECT view, not §N3's
// retention view — and a DELETE on it is a 404.
func (a *Admin) AddDestroyedUA(uaHandle string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.destroyedUA[uaHandle] = true
}

// SetTeardownDelay makes DestroyUA on this handle really block for d.
//
// THIS MUST ACTUALLY SLEEP. P1d's TestAdminDeleteDoesNotStallTools sets it to
// the full 10 s grace period and asserts an unrelated session's tool call
// still returns inside N2's 50 ms budget. The property under test is
// WALL-CLOCK contention between two concurrent HTTP handlers, which a
// fake-clock advance cannot exhibit — so this is one of the few places in the
// wave where a real sleep is correct rather than a smell. A no-op here would
// make that test pass while proving nothing.
func (a *Admin) SetTeardownDelay(uaHandle string, d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.delays[uaHandle] = d
}

// SetMaxUAsTotal sets the server-wide cap Tools.BindUALimit reads.
func (a *Admin) SetMaxUAsTotal(n int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.maxUAsTotal = n
}

// ---- the Admin interface ---------------------------------------------------

// LiveUAs returns every LIVE UA, as session.AdminUAView. Destroyed UAs are
// absent. There is NO time-based filtering of any kind: D11 point 5 says a
// live UA is never destroyed by the passage of time, and P1d's non-goal test
// advances the clock 72 h and requires the UA to still be listed.
func (a *Admin) LiveUAs(_ context.Context) []session.AdminUAView {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]session.AdminUAView, 0, len(a.live))
	for _, ua := range a.live {
		out = append(out, session.AdminUAView{
			UAHandle:          ua.UAHandle,
			Session:           ua.Session,
			Mode:              ua.Mode,
			AOR:               ua.AOR,
			Transport:         ua.Transport,
			Registered:        ua.Registered,
			ActiveCalls:       ua.ActiveCalls,
			CreatedAt:         ua.CreatedAt,
			SessionConnected:  ua.SessionConnected,
			SessionLastSeenAt: ua.SessionLastSeenAt,
		})
	}
	return out
}

// DestroyUA models §12.7's DELETE: ua_destroy's teardown with the ownership
// check omitted (Rule 16).
//
// A handle with no LIVE UA — never issued, or already destroyed — returns
// apierr.NotFound and increments NO counter, which is what lets
// TeardownCalls distinguish "the teardown ran once" from "it ran twice".
//
// Ownership is NOT cleared: §12.7 is not an adoption path, so OwnerOf must
// still answer after the DELETE (P1d's "§12.6 untouched" non-goal test).
func (a *Admin) DestroyUA(ctx context.Context, uaHandle string) (session.AdminDestroyed, error) {
	a.mu.Lock()
	if a.DestroyErr != nil {
		err := a.DestroyErr
		a.mu.Unlock()
		return session.AdminDestroyed{}, err
	}
	idx := -1
	for i, ua := range a.live {
		if ua.UAHandle == uaHandle {
			idx = i
			break
		}
	}
	if idx < 0 {
		a.mu.Unlock()
		return session.AdminDestroyed{}, apierr.NotFound(
			fmt.Sprintf("no live ua bears handle %s", uaHandle))
	}

	ua := a.live[idx]
	a.live = append(a.live[:idx], a.live[idx+1:]...)
	a.destroyedUA[uaHandle] = true
	a.teardowns[uaHandle]++
	// §12.7 introduces NO new termination_reason: calls torn down this way
	// carry local_hangup, exactly as ua_destroy's do (§11.4).
	a.reasons[uaHandle] = "local_hangup"
	delay := a.delays[uaHandle]
	a.mu.Unlock()

	// The sleep happens with the mutex RELEASED. That mirrors the real
	// manager, which resolves the UA under the registry lock and releases it
	// BEFORE the BYE grace period begins (contract Part 4.2) — holding a lock
	// across a 10 s wait inside an HTTP handler is an outage, not a latency
	// blip. Sleeping under the mutex here would also make this fake serialise
	// concurrent admin requests and produce a false positive in P1d's
	// no-serialization test.
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
		}
	}

	return session.AdminDestroyed{
		UAHandle:        uaHandle,
		Unregistered:    ua.Registered,
		CallsTerminated: ua.ActiveCalls,
		Session:         ua.Session,
	}, nil
}

// ---- observation -----------------------------------------------------------

// TeardownCalls reports how many times a teardown actually RAN for this
// handle. It exists to assert Rule 16 — that the admin DELETE and ua_destroy
// drive ONE teardown, not two — so it counts real teardowns and NOT failed
// attempts: a repeated DELETE returns 404 and leaves this at 1.
func (a *Admin) TeardownCalls(uaHandle string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.teardowns[uaHandle]
}

// TerminationReason reports the reason the teardown recorded, or "" if none
// ran. §12.7 adds no enum value, so this is always local_hangup at P1.
func (a *Admin) TerminationReason(uaHandle string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reasons[uaHandle]
}

// OwnerOf reports the session that owned the handle. It SURVIVES the DELETE:
// §12.7 destroys, it never transfers, so a test can assert ownership did not
// move.
func (a *Admin) OwnerOf(uaHandle string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.owner[uaHandle]
}

// Live reports whether uaHandle is currently in the LIVE set.
func (a *Admin) Live(uaHandle string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ua := range a.live {
		if ua.UAHandle == uaHandle {
			return true
		}
	}
	return false
}

// LiveCount reports how many UAs are currently LIVE.
func (a *Admin) LiveCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.live)
}

// MaxUAsTotal reports the server-wide cap set by SetMaxUAsTotal.
func (a *Admin) MaxUAsTotal() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.maxUAsTotal
}
