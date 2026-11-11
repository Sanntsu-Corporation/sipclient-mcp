package sipua

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
)

// errRefresherStopped marks an attempt loop cut short by an INTENTIONAL shutdown
// — Stop() or a cancelled owner context — rather than by a failure.
//
// IT EXISTS TO KEEP OnGiveUp HONEST. attempt's retry wait selects on r.stop and
// ctx.Done() as well as the timer, so an interruption during a backoff returns a
// non-nil error just like an exhausted budget does. Without a way to tell the two
// apart, a UA teardown or an Unregister that lands mid-retry fires OnGiveUp —
// which for the register consumer emits UAEventRegisterFailed and marks the UA
// unregistered during a clean shutdown, reporting a registration failure that did
// not happen.
//
// BOTH INTERRUPTION ARMS WRAP IT, AND THAT IS THE WHOLE CLASSIFICATION MECHANISM.
// It is tagged AT THE POINT the interruption is observed and never inferred later
// from live state, so the answer to "was this a shutdown?" is fixed the moment the
// error is created and cannot be changed by anything that happens afterwards. It
// is also private to this package, which is what makes the converse safe: no Do
// implementation can accidentally produce an error wrapping it, so a genuine
// context.DeadlineExceeded returned from inside Do (Timer F on a session-timer
// refresh send) is never mistaken for a shutdown.
var errRefresherStopped = errors.New("refresher: stopped")

// backoff is a refresher's retry schedule: at most Attempts calls to Do per
// due-time, delayed Base, 2*Base, 4*Base, ... capped at Cap. A zero Attempts
// means NO retry — one attempt, and a failure waits for the next ordinary
// interval (which is what the keepalive wants: it logs and continues).
type backoff struct {
	Attempts int
	Base     time.Duration
	Cap      time.Duration
}

// delay returns the wait before retry number n (1-based).
func (b backoff) delay(n int) time.Duration {
	d := b.Base
	for i := 1; i < n && d < b.Cap; i++ {
		d *= 2
	}
	if b.Cap > 0 && d > b.Cap {
		d = b.Cap
	}
	return d
}

// refreshPolicy configures one refresher (spec §2.4). It is the ONE abstraction
// re-register, NAT keepalive and RFC 4028 session-timer refresh all share.
//
// Do RETURNING THE GRANTED INTERVAL IS THE LOAD-BEARING PART. It is what lets
// re-register re-base on the registrar's granted expiry (D24: a registrar that
// grants 120 when we asked for 300 must not be refreshed against 300) and lets
// session-timer refresh re-base on the peer's Session-Expires in a refresh
// response — through one mechanism rather than two. 0 means "interval
// unchanged".
type refreshPolicy struct {
	// Name is the logging and metrics label: "register" | "session_timer" |
	// "session_watchdog" | "keepalive".
	//
	// THE SESSION TIMER HAS TWO INSTANCES AND THEY MUST NOT SHARE A LABEL. When we
	// hold the refresher role a "session_timer" refresher fires at interval/2 and
	// sends an UPDATE or re-INVITE (Task 29); when the PEER holds it a
	// "session_watchdog" refresher fires at the FULL interval and ENDS THE CALL
	// (Task 30). One label for both would make a routine refresh and a session
	// expiry indistinguishable in the logs — which is the one distinction an
	// operator reading them is looking for.
	Name string
	// Fraction is where in the interval the refresh fires: 0.85 for
	// re-register, 0.5 for RFC 4028 §10's session-timer rule, 1.0 for a
	// fixed-period keepalive. Values <= 0 are treated as 1.0.
	Fraction float64
	// Jitter is a +/- fraction applied to each computed delay, so a fleet of
	// UAs sharing a registrar does not refresh in lockstep. 0 disables it.
	Jitter float64
	// Initial is the first interval (the granted expiry, the negotiated
	// Session-Expires, or keepalive_interval_s).
	Initial time.Duration
	// Do performs one refresh. A non-zero grantedS re-bases the interval.
	Do func(ctx context.Context) (grantedS int, err error)
	// Retry is the per-due-time retry schedule.
	Retry backoff
	// OnGiveUp is the consumer-specific escalation after the retry cap.
	//
	// IT FIRES ONLY ON GENUINE EXHAUSTION: every attempt in the budget ran and
	// every one of them failed against the far end. It is NEVER called for a
	// Stop() or a cancelled ctx, even one that lands in the middle of a retry
	// backoff — those are intentional shutdowns, and Start recognises them through
	// quietStop/errRefresherStopped and returns silently. Escalating a shutdown
	// would have the register consumer report the UA unregistered because it was
	// asked to close.
	//
	// nil means "do nothing", which is what two of the three consumers want:
	//
	//   - re-register (Task 25): marks the UA unregistered and emits
	//     session.UAEventRegisterFailed. NOT UAEventTransportFault — that kind is
	//     UA-wide and its handler terminates every live call on the UA, so a
	//     registrar outage would reap healthy established dialogs.
	//   - session timer (Task 29): nil. A refresh the peer REJECTS exhausts the
	//     retries and stops, having already logged its own error event; a refresh
	//     that draws NO RESPONSE is terminal on the first occurrence and is
	//     handled inside Do itself, because §11.3.1's acceptance puts that
	//     termination at Timer F expiry and a second attempt would double it.
	//   - keepalive (Task 26): nil, and unreachable — its Do swallows the send
	//     error, so no error ever reaches the refresher at all.
	//
	// IT RUNS ON THE REFRESHER'S OWN GOROUTINE, exactly like Do — see Stop's
	// contract below before doing anything from here that could stop this
	// refresher.
	OnGiveUp func(err error)
}

// refresher runs one refreshPolicy on one goroutine, driven entirely by a
// clock.Clock so every timing test runs on the fake clock — the same
// clock-injection convention every other stateful timer in this package follows.
type refresher struct {
	clk clock.Clock
	log *slog.Logger
	p   refreshPolicy

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}

	// callbackGoroutine is the id of the goroutine currently inside Do or
	// OnGiveUp, or 0 when neither is running. It backs Stop's reentrancy guard and
	// NOTHING ELSE — it never changes what Stop does for an external caller.
	callbackGoroutine atomic.Uint64

	mu sync.Mutex
	// started guards Stop's wait on `done`: only Start's goroutine ever closes
	// that channel, so Stop must not block on it before Start has run.
	started bool
	nextAt  time.Time
}

// newRefresher builds a stopped refresher. Call Start to run it.
func newRefresher(clk clock.Clock, log *slog.Logger, p refreshPolicy) *refresher {
	if clk == nil {
		clk = clock.System()
	}
	if log == nil {
		log = slog.Default()
	}
	if p.Fraction <= 0 {
		p.Fraction = 1.0
	}
	return &refresher{
		clk: clk, log: log, p: p,
		stop: make(chan struct{}), done: make(chan struct{}),
	}
}

// Start launches the single goroutine. ctx is the owner's LIFETIME context —
// u.uaCtx for a UA-owned refresher, never an HTTP request context (decision
// 17): a client disconnect must not stop a live UA refreshing its registration.
func (r *refresher) Start(ctx context.Context) {
	interval := r.p.Initial
	r.mu.Lock()
	r.started = true
	r.mu.Unlock()
	go func() {
		defer close(r.done)
		for {
			delay := r.jittered(time.Duration(float64(interval) * r.p.Fraction))
			// LAST LINE OF DEFENCE, NOT THE BOUND (F1). Every producer of an
			// interval now clamps it before it becomes a Duration; this refuses
			// the schedule outright if one ever stops. A negative delay is a
			// deadline already in the past, so the timer fires the instant it is
			// armed and every subsequent tick does the same — a refresher that
			// puts SIP requests on the wire as fast as the peer will answer them.
			// Stopping is the safe reading of "we have no idea when to fire":
			// jittered() cannot rescue it (its `out <= 0` guard hands back the
			// original negative d) and nothing downstream looks at the sign.
			if delay < 0 {
				r.log.Error("refresher computed a negative delay; refusing to schedule",
					"kind", r.p.Name, "delay", delay, "interval", interval)
				return
			}
			r.setNextAt(r.clk.Now().Add(delay))
			timer := r.clk.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-r.stop:
				timer.Stop()
				return
			case <-timer.C():
			}

			granted, err := r.attempt(ctx)
			if err != nil {
				// quietStop reads ONLY err. It deliberately does not consult
				// ctx.Err() or r.stop here: by this point a concurrent teardown may
				// already have fired, and letting that decide would misreport the
				// genuine failure attempt just handed us.
				if r.quietStop(err) {
					// Stop() or ctx cancellation, NOT exhaustion. Return without
					// escalating: this is an intentional shutdown, and firing
					// OnGiveUp here is how a clean UA teardown ends up reported as
					// a registration failure.
					r.log.Debug("refresher stopping", "kind", r.p.Name)
					return
				}
				// The attempt cap was reached with real failures. Escalate and
				// stop: a refresher that kept firing after giving up would keep
				// re-escalating.
				//
				// A-M2 (D20): NOT EVERY GIVING-UP IS A WARNING. Watchdog expiry and a
				// teardown racing an in-flight refresh are the DESIGNED outcomes of this
				// loop, and logging them at WARN made a healthy call's teardown look like
				// a fault in the operator's log. quietStop was already exempt; these two
				// are the same class. Anything else still warns.
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					r.log.Debug("refresh stopped", "kind", r.p.Name, "err", err)
				} else {
					r.log.Warn("refresh gave up", "kind", r.p.Name, "err", err)
				}
				if r.p.OnGiveUp != nil {
					r.runCallback(func() { r.p.OnGiveUp(err) })
				}
				return
			}
			// `d > 0` is the same last-line-of-defence as the delay check above:
			// the producers clamp `granted`, and this refuses a value that would
			// still wrap time.Duration negative rather than adopting it as the
			// new schedule.
			if d := time.Duration(granted) * time.Second; granted > 0 && d > 0 {
				interval = d
			}
		}
	}()
}

// attempt runs Do, retrying per the policy's backoff. It returns the granted
// interval on success, or the last error once the attempt cap is reached.
//
// IT IS THE ONLY PLACE AN INTERRUPTION IS CLASSIFIED, AND IT DOES SO CAUSALLY.
// There is exactly one point at which this loop can observe an interruption — the
// between-retries select below — and BOTH of its interruption arms return an error
// wrapping errRefresherStopped: r.stop returns the sentinel itself, and ctx.Done()
// wraps it around ctx.Err() rather than returning ctx.Err() bare. Every other exit
// is a real Do failure, including the final attempt, which has no select at all and
// hands back the last Do error unchanged.
//
// The consequence is what quietStop relies on: the shutdown/failure question is
// answered at the instant the interruption happens, by the error's own identity,
// and no later observation of r.stop or ctx can revise it. A concurrent Stop() that
// arrives AFTER this function has produced a genuine error therefore cannot turn
// that error into a silent shutdown — which is precisely what a live-state recheck
// in quietStop used to do.
func (r *refresher) attempt(ctx context.Context) (int, error) {
	attempts := r.p.Retry.Attempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for n := 1; n <= attempts; n++ {
		var granted int
		var err error
		r.runCallback(func() { granted, err = r.p.Do(ctx) })
		if err == nil {
			return granted, nil
		}
		lastErr = err
		// C4: Do itself may already know this attempt loop is over — e.g.
		// refreshRegister's opening guard or registrationRemoved wrapping
		// errRefresherStopped after a clean de-registration — as opposed to
		// attempt's OWN two interruption arms below, which tag an
		// externally-observed Stop()/ctx-cancel. Without this check, a Do
		// error that already carries the sentinel still burned the rest of
		// the retry budget: a stale "retrying" WARN per remaining attempt and
		// a full backoff wait between each, chasing a registration that is
		// already known gone. quietStop treats both origins identically once
		// attempt returns, so exiting here rather than retrying changes
		// nothing about that classification — it only stops wasting the
		// budget on a foregone conclusion.
		if errors.Is(err, errRefresherStopped) {
			return 0, err
		}
		if n == attempts {
			break
		}
		r.log.Warn("refresh attempt failed; retrying",
			"kind", r.p.Name, "attempt", n, "err", err)
		timer := r.clk.NewTimer(r.p.Retry.delay(n))
		select {
		case <-ctx.Done():
			timer.Stop()
			// WRAPPED IN errRefresherStopped, not returned bare. The owner's
			// lifetime ended mid-retry, which is the same KIND of event as a Stop()
			// and must classify identically — and it has to be legible from the
			// error alone, because quietStop is forbidden from re-reading ctx. %v
			// rather than %w for the cause: the error's identity is the sentinel and
			// nothing else, and the ctx reason is carried as text for the log.
			return 0, fmt.Errorf("%w: %v", errRefresherStopped, ctx.Err())
		case <-r.stop:
			timer.Stop()
			// errRefresherStopped, NOT lastErr: the budget was not exhausted, the
			// owner asked us to shut down. Returning lastErr here is what made a
			// Stop() during a backoff fire OnGiveUp.
			return 0, errRefresherStopped
		case <-timer.C():
		}
	}
	return 0, lastErr
}

// quietStop reports whether err means "we were told to shut down" rather than
// "the retry budget was exhausted against the far end".
//
// IT IS A PURE FUNCTION OF err, AND THAT IS THE POINT. It takes no ctx, reads no
// channel and observes no clock: attempt already tagged both of its interruption
// arms with errRefresherStopped at the instant the interruption occurred, so the
// classification is settled before this is ever called and is race-free by
// construction.
//
// DO NOT ADD A LIVE RECHECK HERE. An earlier version also tested `ctx.Err() != nil`
// and did a trailing `select` on r.stop, to catch a Stop() that landed while Do was
// in flight. That made a real failure indistinguishable from a shutdown in the
// opposite direction: attempt's FINAL attempt returns the genuine Do error with no
// select, and any Stop() or cancellation arriving in the window before this call
// made that genuine error look quiet — so OnGiveUp never fired and a real
// registration or session-timer failure was swallowed. Live state at classification
// time says nothing about what CAUSED the error.
//
// ANY ERROR WITHOUT THE SENTINEL IS A REAL FAILURE and reaches OnGiveUp, including
// context.DeadlineExceeded from inside a Do (a peer that answered nothing is a
// genuine failure, not a shutdown). A Do that genuinely wants its own failure
// treated as a shutdown wraps errRefresherStopped itself — it is the only code that
// knows.
func (r *refresher) quietStop(err error) bool {
	return errors.Is(err, errRefresherStopped)
}

// runCallback runs one policy callback (Do or OnGiveUp) with this goroutine's id
// recorded, so Stop can detect a reentrant call and panic instead of self-joining.
func (r *refresher) runCallback(fn func()) {
	r.callbackGoroutine.Store(goroutineID())
	defer r.callbackGoroutine.Store(0)
	fn()
}

// goroutineID parses the calling goroutine's runtime id out of its own stack
// header.
//
// IT EXISTS SOLELY FOR Stop's FAIL-FAST REENTRANCY GUARD. Go exposes no
// goroutine identity by design, and this is the one use for which the stack-header
// hack is justified: turning a silent deadlock into a located panic. It is NOT
// used to change control flow — in particular Stop still waits for the refresher
// goroutine when called from anywhere else, which is the guarantee Tasks 25 and 26
// depend on. It runs at most once per Do and once per Stop, so its cost is
// irrelevant at these rates.
func goroutineID() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	// "goroutine 123 [running]:"
	f := bytes.Fields(bytes.TrimPrefix(buf[:n], []byte("goroutine ")))
	if len(f) == 0 {
		return 0
	}
	id, err := strconv.ParseUint(string(f[0]), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// jittered applies +/- Jitter to d, clamped to a positive duration.
func (r *refresher) jittered(d time.Duration) time.Duration {
	if r.p.Jitter <= 0 {
		return d
	}
	// rand is fine here: this is scheduling spread, not a security decision.
	factor := 1 + r.p.Jitter*(2*rand.Float64()-1)
	out := time.Duration(float64(d) * factor)
	if out <= 0 {
		return d
	}
	return out
}

// Stop halts the refresher and waits for its goroutine. It is IDEMPOTENT and
// safe to call from teardown paths that may race each other, mirroring
// mediaLoop.stop's stopOnce.
//
// It is ALSO safe on a refresher that was never Started: `done` is closed only
// by the goroutine Start launches, so an unguarded `<-r.done` would park a
// teardown path forever on a refresher that was constructed and then abandoned
// (an error path between newRefresher and Start).
//
// IT MUST NEVER BE CALLED FROM THIS REFRESHER'S OWN Do OR OnGiveUp, AND IT
// PANICS IF IT IS. Those run ON the goroutine `<-r.done` waits for, so calling
// Stop from inside one is a self-join deadlock — the goroutine waits for itself,
// forever, and the symptom is a hung dialog with no failing assertion anywhere.
// The guard converts that into an immediate panic naming the rule, which is this
// codebase's existing convention for internal misuse (fakeclock panics on a
// non-positive ticker interval, netfault on an rx-only knob used on tx, metrics on
// an unknown termination reason).
//
// The blocking wait itself is deliberate and is NOT weakened: it is the whole
// reason Task 25 and Task 26 can guarantee no timer fires a REGISTER or an
// OPTIONS onto a transport that is closing. A callback that needs to tear down
// something whose teardown stops this refresher hands the work to a new goroutine
// instead (Task 29's runOffRefresherGoroutine) — and THAT is the sanctioned fix,
// not making Stop non-blocking.
func (r *refresher) Stop() {
	if id := r.callbackGoroutine.Load(); id != 0 && id == goroutineID() {
		panic("sipua: refresher.Stop called from this refresher's own Do/OnGiveUp — " +
			"that is a self-join deadlock (Stop waits for the goroutine the callback runs on). " +
			"Hand the teardown to runOffRefresherGoroutine (sessiontimer.go) instead. " +
			"refresher=" + r.p.Name)
	}
	r.stopOnce.Do(func() { close(r.stop) })
	r.mu.Lock()
	started := r.started
	r.mu.Unlock()
	if !started {
		return
	}
	<-r.done
}

// NextAt is the instant the next refresh is scheduled for; it feeds
// ua_status.next_refresh_ms and call_status.session_timer.next_refresh_ms.
func (r *refresher) NextAt() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nextAt
}

func (r *refresher) setNextAt(t time.Time) {
	r.mu.Lock()
	r.nextAt = t
	r.mu.Unlock()
}
