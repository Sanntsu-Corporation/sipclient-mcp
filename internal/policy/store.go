package policy

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
)

// Store owns the current policy and the SIGHUP reload of §12.2.1.
//
// The current policy is an atomic pointer to an IMMUTABLE *Policy. A reload
// swaps the pointer; it never mutates the value behind it. That is what
// makes §12.2.1's non-retroactivity rule structural: an operation that
// captured Current() at its start holds a value nothing can change, so
// "continues under the policy in force when it started" needs no copying,
// no versioning and no locking on the read path.
//
// Concurrency contract (locked decision D3, AMENDED Phase 2 §2.3a): Current,
// LoadedAt, ReloadFailures and LastReloadFailed are safe for concurrent use
// from any goroutine. Reload IS NOW INTERNALLY SERIALISED — it was not,
// originally, when its only caller was Task 20's SIGHUP goroutine, but Phase
// 2 added two more callers reachable concurrently from any MCP request:
// config_set and admin_token_rotate (both routed through Mutate below).
// Without serialisation, two concurrent Reloads could swap in the OLDER
// file's contents last, and two concurrent config_sets (each a
// read-modify-write) could silently drop one caller's key from both the
// state file and memory. reloadMu closes both: it is held across the WHOLE
// of a reload or a mutation (Load/marshal/write, the swap, loadedAt, the
// failure counters and the hook invocation), so Reload, Mutate and the
// SIGHUP goroutine can never interleave.
//
// reloadMu is taken in the EXPORTED wrappers (Reload, Mutate) ONLY, never in
// reloadLocked: sync.Mutex is not reentrant, and Mutate must call
// reloadLocked (not Reload) to install what it just wrote without taking the
// lock a second time and deadlocking the daemon permanently, with the lock
// held, blocking every later config_set, admin_token_rotate and SIGHUP
// reload behind it.
//
// The read path is UNCHANGED and remains lock-free: Current() is an atomic
// pointer load, exactly as before. reloadMu only ever guards a WRITER
// against another writer.
type Store struct {
	path string
	clk  clock.Clock
	log  *slog.Logger

	// static marks a Store built by NewStaticStore, which has no file to
	// re-read. Its Reload always fails; see NewStaticStore.
	static bool

	current    atomic.Pointer[Policy]
	loadedAt   atomic.Int64 // unix nanos
	failures   atomic.Int64
	lastFailed atomic.Bool // §5 N5's /readyz; see LastReloadFailed

	// reloadMu serialises every writer (Reload, Mutate) against every other
	// writer -- see the type comment above for why Phase 2 made this
	// necessary and why it lives in the exported wrappers only.
	reloadMu sync.Mutex

	hookMu sync.Mutex
	hook   func(prev, next *Policy)
}

// NewStore loads the policy at path and returns a Store holding it. A load
// failure here is a startup failure: there is no previous policy to fall
// back to.
//
// clk is the injected clock of locked decision 18: production passes
// clock.System(), tests pass fakeclock.New(t0).
func NewStore(path string, clk clock.Clock, log *slog.Logger) (*Store, error) {
	p, err := Load(path)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, clk: clk, log: log}
	s.current.Store(p)
	s.loadedAt.Store(clk.Now().UnixNano())
	if p.TLS.InsecureSkipVerify {
		log.Warn("tls_insecure_skip_verify_enabled", slog.String("path", path))
	}
	return s, nil
}

// NewStaticStore wraps an already-constructed Policy in a Store that has no
// file behind it. internal/session's unit tests and the loopback harness use
// it with Defaults() to build a *Store without touching disk, which is what
// lets session read limits from the ONE canonical policy.Limits type instead
// of declaring a duplicate (U9, Rule 18).
//
// Reload on the returned Store ALWAYS FAILS. That is deliberate: there is no
// path to re-read, and a silent success would let a §12.2.1 reload test pass
// without having reloaded anything.
//
// It cannot fail — the Policy is already built — so it returns no error.
func NewStaticStore(p *Policy, clk clock.Clock, log *slog.Logger) *Store {
	s := &Store{clk: clk, log: log, static: true}
	s.current.Store(p)
	s.loadedAt.Store(clk.Now().UnixNano())
	return s
}

// Current returns the policy in force now. A caller whose work must not be
// affected by a later reload captures this pointer once and holds it.
func (s *Store) Current() *Policy { return s.current.Load() }

// LoadedAt is /readyz's policy_loaded_at (§5 N5).
func (s *Store) LoadedAt() time.Time { return time.Unix(0, s.loadedAt.Load()) }

// ReloadFailures is /metrics' policy_reload_failures_total (§5 N5). It is a
// lifetime total and never decreases.
func (s *Store) ReloadFailures() int64 { return s.failures.Load() }

// LastReloadFailed reports whether the MOST RECENT Reload attempt failed.
//
// §5 N5's /readyz needs this and ReloadFailures() cannot supply it: a
// lifetime total stays non-zero forever after one transient failure, so a
// daemon that failed a reload at 09:00 and succeeded at 09:05 would report
// NOT READY for the rest of its life. A successful Reload clears the flag.
func (s *Store) LastReloadFailed() bool { return s.lastFailed.Load() }

// SetReloadHook registers the single callback invoked after a successful
// swap.
//
// The composition root (cmd/sipclient-mcpd) registers
// session.Manager.RecomputeDurationCaps here: §12.2.1's max_call_duration_s
// recomputation is the ONE thing a reload applies to live calls. Everything
// else a reload changes affects NEW operations only.
//
// This comment previously claimed "Task 9's session manager registers" the
// recomputation. It did not — SetReloadHook had no production caller at all,
// so a lowered cap never reached a live call and the §12.2.1 acceptance was
// unimplemented behind a comment asserting it was wired.
//
// REQUIREMENT (Phase 2 §2.3a): the hook is invoked with reloadMu HELD — see
// reloadLocked below. It therefore MUST NOT call Reload or Mutate, directly
// or transitively, and MUST NOT block indefinitely: either one deadlocks the
// daemon permanently, the same way a Mutate that called the exported Reload
// would. It MAY call Current, LoadedAt, ReloadFailures, LastReloadFailed and
// anything outside this package that does not re-enter the Store. The one
// production hook, run.go's mgr.RecomputeDurationCaps, satisfies this: it
// takes session.Manager's own mutex and reads the *Policy it was handed,
// and never touches the Store at all.
func (s *Store) SetReloadHook(fn func(prev, next *Policy)) {
	s.hookMu.Lock()
	defer s.hookMu.Unlock()
	s.hook = fn
}

// Reload re-reads the policy file, as SIGHUP requires (§12.2.1). It is the
// thin, LOCKING wrapper: take reloadMu, run the core, release it. See
// reloadLocked for the body and for why the two are split.
func (s *Store) Reload() error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	return s.reloadLocked()
}

// reloadLocked is Reload's entire former body, moved here VERBATIM
// (Phase 2 §2.3a) so that Mutate can run it without taking reloadMu a
// second time.
//
// CALLER MUST HOLD reloadMu. THIS FUNCTION MUST NEVER TAKE IT. sync.Mutex is
// not reentrant, and Mutate already holds reloadMu when it needs this exact
// sequence (Load, swap, hook) to install what it just wrote — calling the
// EXPORTED Reload() from inside Mutate would try to lock a mutex Mutate is
// already holding and deadlock the daemon permanently, with the lock held,
// blocking every later config_set, admin_token_rotate and SIGHUP reload
// behind it. The naming follows this file's existing "...Locked" convention
// (sessionEmptyLocked, checkUACapsLocked, detachSessionLocked in
// internal/session): the suffix means "the caller holds the lock", never
// "this function takes it".
//
// On success the new policy is installed atomically and the reload hook is
// invoked — UNDER reloadMu, per SetReloadHook's documented requirement above
// — with the outgoing and incoming policies.
//
// On ANY failure the reload is abandoned WHOLESALE: the previous policy
// stays in force untouched, no hook fires, the failure counter increments
// (/metrics policy_reload_failures_total, §5 N5) and an ERROR line naming
// the offending key is logged. A PARTIAL POLICY IS NEVER APPLIED — which is
// structural here, because Load builds an entirely separate *Policy and this
// function swaps the pointer only after Load has returned nil.
func (s *Store) reloadLocked() error {
	if s.static {
		// A Store built by NewStaticStore has no file to re-read. Fail
		// loudly rather than silently succeed: a §12.2.1 test that "passed"
		// against a no-op reload would prove nothing.
		err := errors.New("policy: this Store was built by NewStaticStore and has no file to reload")
		s.failures.Add(1)
		s.lastFailed.Store(true)
		s.log.Error("policy_reload_failed", slog.String("error", err.Error()))
		return err
	}

	next, err := Load(s.path)
	if err != nil {
		s.failures.Add(1)
		s.lastFailed.Store(true)
		s.log.Error("policy_reload_failed",
			slog.String("path", s.path),
			slog.String("error", err.Error()))
		return err
	}

	prev := s.current.Swap(next)
	s.loadedAt.Store(s.clk.Now().UnixNano())
	// A SUCCESSFUL reload clears the flag: /readyz reports the state of the
	// MOST RECENT attempt, not a lifetime scar (§5 N5).
	s.lastFailed.Store(false)
	s.log.Info("policy_reloaded", slog.String("path", s.path))
	if next.TLS.InsecureSkipVerify {
		s.log.Warn("tls_insecure_skip_verify_enabled", slog.String("path", s.path))
	}

	s.hookMu.Lock()
	hook := s.hook
	s.hookMu.Unlock()
	if hook != nil {
		// See SetReloadHook's REQUIREMENT paragraph: called under reloadMu.
		hook(prev, next)
	}
	return nil
}

// Mutate is the Phase 2 §2.3a ONE serialised mutation entry point: the
// single code path config_set and admin_token_rotate both go through
// (Rule 18) rather than each calling WriteFile and Reload directly, which
// would reintroduce the exact two races this type's concurrency contract
// exists to close.
//
// It takes reloadMu, copies Current(), calls fn on the copy, validates the
// result BEFORE writing anything (so a value fn accepts at the field level
// but which violates a cross-field or ranged rule is rejected here, with the
// state file left byte-identical, rather than discovered only after
// WriteFile has already overwritten it), STAGES the new state file beside the
// real one and renames it into place, and reloads FROM DISK by calling
// reloadLocked() — never the exported
// Reload(), which would take reloadMu a second time and deadlock (see
// reloadLocked's own doc comment). Reloading from disk rather than swapping
// the in-memory copy directly is deliberate: it makes Load's strict decode,
// validate() and resolve() the gate on every mutation, exactly as they gate
// every SIGHUP, so a write that would not survive a restart never takes
// effect in the first place.
//
// The copy fn receives is a SHALLOW copy of *Current(). That is sufficient,
// not a shortcut: fn is expected to REPLACE whole exported fields (the
// config_set shape — "set limits.max_uas_total to 250", "set
// destinations.allow to this list"), never to mutate a slice element of the
// live policy in place, so sharing backing arrays with the policy still in
// force is harmless — and a deeper copy would buy nothing anyway, because
// the copy is discarded the moment reloadLocked re-Loads the just-written
// file from disk; it exists only to be marshalled.
//
// On any failure — fn's own validation, the post-fn validate(), the write,
// or the reload — nothing is swapped and the previous state file is left
// byte-identical, the same "abandoned wholesale" posture Reload has always
// had, extended to writes. The RELOAD half of that promise is what
// MutateWithCommit's staging exists to make true; see below.
func (s *Store) Mutate(fn func(cur *Policy) error) error {
	return s.MutateWithCommit(fn, nil)
}

// MutateWithCommit is Mutate plus ONE scheduling guarantee: commit runs after
// validate() and the state-file staging have both succeeded, and BEFORE the
// state file is installed and reloaded — and does not run at all if either
// earlier step failed.
//
// THE STATE FILE IS STAGED, NOT WRITTEN THROUGH. This function used to call
// WriteFile mid-sequence, which renamed the new YAML into place before the
// reload had been proven to succeed and never put it back when the reload
// failed — the SAME failure class SEC-1 closed for the admin token file,
// reintroduced on the general config path. Reproduced: `config_set
// tls.insecure_skip_verify=true` against an induced reload failure returned an
// error and left Current() unchanged, while the state file on disk already
// said `insecure_skip_verify: true`, so the NEXT restart or successful reload
// silently applied a change the caller had been told did not happen. The write
// is now StageFile + StagedFile.Commit (internal/policy/statefile.go, the same
// mechanism the token file uses), the rename is the last step before the
// reload, and a reload failure calls StagedFile.Rollback — so on every error
// path this function can return, the state file on disk is byte-identical to
// what it was when the call started.
//
// The reload is why the rename cannot be deferred past it: reloadLocked
// re-reads s.path, so the new YAML must be visible under its own name for the
// reload to see it at all. Staging buys the ordering; the rollback covers the
// one window the rename itself cannot.
//
// IT EXISTS FOR admin_token_rotate, AND THE POSITION IS THE WHOLE POINT
// (SEC-1). Rotation has a second, irreversible effect outside the state file:
// the admin token FILE. Doing it inside fn — where it used to live — fires it
// before validate/write/reload have been proven to succeed, so a failure in
// any of those three left the file holding a value the caller never received
// while the in-memory digest still matched the old token: a daemon that keeps
// working until the next restart and is then permanently locked out of its own
// admin plane. Doing it AFTER Mutate returns is no better in the opposite
// direction: reloadLocked is what recomputes the digest from the token file,
// so a rename that lands after the reload would leave the freshly returned
// token unable to authenticate until some later reload. Between the write and
// the reload is the ONE position where both halves land together.
//
// A commit failure abandons the mutation exactly as a write failure does: no
// reload happens, so nothing the commit did or did not do is installed.
//
// THE COMMIT OWNS ITS OWN UNDO, AND BOTH HALVES RUN UNDER reloadMu (SEC-3).
// commit returns a rollback closure alongside its error, and THIS function —
// never the caller — decides whether to run it, while it still holds
// reloadMu. That sequencing is the whole contract, not a style choice. The
// previous shape had the caller capture the pre-state BEFORE calling
// MutateWithCommit and run its own rollback AFTER MutateWithCommit returned,
// i.e. both outside the lock, which opened two reproduced races:
//
//	(a) two concurrent rotations — the loser captured its "previous" bytes
//	    before the winner's commit landed, so its rollback wrote back a stale
//	    snapshot and RESURRECTED a token the winner had just revoked;
//	(b) one rotation committed, its own reload failed, and a concurrent
//	    config_set or SIGHUP took reloadMu first and reloaded successfully
//	    from the just-renamed file — after which the first caller's late
//	    rollback put the OLD bytes back, leaving the live digest and the file
//	    on disk disagreeing immediately rather than only at the next restart.
//
// Capturing the pre-state inside commit (which runs under reloadMu) and
// running the undo before the lock is released makes both impossible: no
// other writer can observe or move the file between the capture, the commit
// and the undo, so a rollback can only ever restore bytes that are still the
// ones this caller replaced.
//
// If the rollback ITSELF fails the mutation error is returned wrapped
// together with the rollback error, because at that point disk holds a value
// no caller received and only a human can settle it.
//
// A FAILED MUTATION LEAVES lastFailed EXACTLY AS reloadLocked SET IT, AND
// NOTHING HERE PUTS IT BACK. A mutation whose internal reload fails is
// recorded exactly as a SIGHUP failure is: failures++ and lastFailed = true,
// set by reloadLocked and left alone by this function. Only a LATER reload
// that actually SUCCEEDS — from any caller: config_set, admin_token_rotate or
// the SIGHUP goroutine — clears it, which is reloadLocked's own long-standing
// success-path behaviour.
//
// THIS DELIBERATELY REPLACES A CLEVERER RULE THAT WAS A SECURITY DEFECT. An
// earlier round captured lastFailed before the mutation and RESTORED it
// whenever every undo reported clean, on the reasoning that an attempt which
// provably did not happen should not leave the daemon unready. Two ways that
// fails open:
//
//	(a) the breakage is EXTERNAL to the state file — auth.bearer_token_file
//	    went missing, say — so the state-file rollback is perfectly "clean"
//	    while the policy remains unloadable. lastFailed was cleared, /readyz
//	    went back to 200, and every future reload INCLUDING THE NEXT RESTART
//	    fails identically, with nothing left saying so;
//	(b) if the state file did not exist when StageFile ran, a clean Rollback
//	    DELETES it (see StagedFile.Rollback) — and with (a) that is a daemon
//	    reporting ready with its state file gone. Defaults() ships an EMPTY
//	    destinations.allow, and an empty allow list means allow-everything in
//	    CheckDestination, so the next restart would come back up fail-open with
//	    no operator-visible warning at all.
//
// The cost of the conservative rule is that an operator may see /readyz 503
// for longer than the most optimistic reading of the facts requires — until
// some reload succeeds. That is strictly preferable to reporting ready over a
// policy that cannot be loaded. DO NOT REINTRODUCE THE RESTORE.
//
// s.failures IS LIKEWISE NOT ADJUSTED. It backs
// policy_reload_failures_total, which ReloadFailures documents as a lifetime
// total that never decreases; decrementing it would show downstream as a
// counter RESET, which is a worse lie than a broad attribution. The reload
// attempt also genuinely happened and genuinely failed — that a config_set's
// own reload could not load what it had just written is exactly the kind of
// thing an operator wants counted.
//
// fn, validate, the write and the reload behave exactly as Mutate documents;
// a nil commit makes this function identical to Mutate, which is why Mutate
// is a one-line wrapper over it rather than a second copy of the sequence.
func (s *Store) MutateWithCommit(fn func(cur *Policy) error, commit func() (rollback func() error, err error)) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	if s.static {
		return errors.New("policy: this Store was built by NewStaticStore and cannot be mutated (no file to write)")
	}

	next := *s.current.Load() // shallow copy -- see the doc comment above
	if err := fn(&next); err != nil {
		return err
	}
	if err := next.validate(); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	// STAGE the state file; do not install it yet. See THE STATE FILE IS
	// STAGED, NOT WRITTEN THROUGH above.
	staged, err := StageFile(s.path, &next)
	if err != nil {
		return fmt.Errorf("policy: write state file: %w", err)
	}
	defer staged.Discard() // a no-op once Commit has run; reclaims the temp otherwise

	var rollback func() error
	if commit != nil {
		rb, err := commit()
		if err != nil {
			// Nothing of this mutation is on disk: the state file has only
			// been staged beside itself, and the deferred Discard reclaims
			// that temp file. There is nothing to roll back.
			return err
		}
		rollback = rb
	}
	// The reload re-READS s.path, so the state file has to be visible under
	// its own name before reloadLocked runs -- this rename is as late as the
	// sequence allows, and everything after it is undone below.
	if err := staged.Commit(); err != nil {
		// No reload ran, so lastFailed was never touched on this path.
		return s.undo(fmt.Errorf("policy: write state file: %w", err), nil, rollback)
	}
	if err := s.reloadLocked(); err != nil {
		// lastFailed is reloadLocked's to set and a later SUCCESSFUL reload's to
		// clear; the undo below touches the two FILES only. See A FAILED
		// MUTATION LEAVES lastFailed above.
		return s.undo(err, staged, rollback)
	}
	return nil
}

// undo runs the compensating actions for a mutation that failed after
// something had already landed on disk, and returns the error the caller
// should see.
//
// BOTH UNDOS RUN UNDER reloadMu, because MutateWithCommit still holds it --
// that is the SEC-3 property, extended to the state file: no other writer can
// observe or move either file between the commit and the undo, so a rollback
// can only ever restore bytes that are still the ones this caller replaced.
//
// If an undo ITSELF fails, its error is wrapped alongside the original,
// because at that point disk holds a value no caller received and only a human
// can settle it. staged and rollback are each nil when that half never landed.
//
// IT DOES NOT REPORT WHETHER THE UNDOS WERE CLEAN, because nothing acts on
// that any more: lastFailed is no longer restored on a clean rollback (see
// MutateWithCommit's A FAILED MUTATION LEAVES lastFailed paragraph for the
// fail-open defect that rule caused).
func (s *Store) undo(cause error, staged *StagedFile, rollback func() error) error {
	if staged != nil {
		if !staged.prevExisted {
			// StagedFile.Rollback's "restore what was there" reduces to DELETING
			// the state file when there was nothing there to begin with. For the
			// STATE file that should be unreachable in normal operation — NewStore
			// cannot construct a non-static Store without Load()ing this path
			// successfully, so a config_set reaching here means the file vanished
			// out from under a running daemon. The delete is still the faithful
			// restore of what this call found, so the behaviour is unchanged; it
			// is logged at ERROR because a daemon whose state file is gone will
			// come back up on Defaults() after a restart, and Defaults() ships an
			// EMPTY destinations.allow, which CheckDestination reads as
			// allow-everything.
			s.log.Error("policy_state_file_missing_before_mutation",
				slog.String("path", s.path),
				slog.String("error", cause.Error()))
		}
		if rbErr := staged.Rollback(); rbErr != nil {
			cause = fmt.Errorf("%w; restoring the previous state file also failed: %w", cause, rbErr)
		}
	}
	if rollback != nil {
		if rbErr := rollback(); rbErr != nil {
			cause = fmt.Errorf("%w; rolling the commit back also failed: %w", cause, rbErr)
		}
	}
	return cause
}
