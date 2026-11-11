package policy

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// TestMutateRoundTripsAndTakesEffectWithoutRestart (P2-T3): a Mutate call
// that edits a field is visible in Current() immediately, and the state
// file on disk agrees field-for-field with what Current() now reports.
func TestMutateRoundTripsAndTakesEffectWithoutRestart(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	path := writePolicy(t, fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok))

	s, err := NewStore(path, fakeclock.New(epoch), discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := s.Mutate(func(cur *Policy) error {
		cur.Limits.MaxUAsTotal = 250
		cur.Auth.BearerTokenFile = tok // Auth's own path fields round-trip too
		return nil
	}); err != nil {
		t.Fatalf("Mutate: %v", err)
	}

	if got := s.Current().Limits.MaxUAsTotal; got != 250 {
		t.Errorf("Current().Limits.MaxUAsTotal = %d, want 250 (no restart)", got)
	}

	// Reload FROM DISK (a fresh Load, bypassing Current entirely) and check
	// every field the mutation touched or left alone round-tripped.
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load after Mutate: %v", err)
	}
	if reloaded.Limits.MaxUAsTotal != 250 {
		t.Errorf("state file on disk: Limits.MaxUAsTotal = %d, want 250", reloaded.Limits.MaxUAsTotal)
	}
	if reloaded.Auth.BearerTokenFile != tok {
		t.Errorf("state file on disk: Auth.BearerTokenFile = %q, want %q", reloaded.Auth.BearerTokenFile, tok)
	}
}

// TestMutateRejectsAnInvalidValueAndLeavesTheFileByteIdentical (P2-T6's
// "an invalid value is rejected wholesale and leaves the state file
// byte-identical"): fn setting a value validate() rejects must not touch
// disk at all.
func TestMutateRejectsAnInvalidValueAndLeavesTheFileByteIdentical(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	path := writePolicy(t, fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok))

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state file before Mutate: %v", err)
	}

	s, err := NewStore(path, fakeclock.New(epoch), discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	err = s.Mutate(func(cur *Policy) error {
		// max_call_duration_s above 86400 (one day) is rejected by
		// validate()'s load-time ceiling. Was max_uas_per_session != 1
		// (Phase 1's strict one-UA model) before the multi-UA-per-session
		// wave made that key configurable and removed its own validate()
		// bound -- any other still-enforced invalid value works equally
		// well here; this test's own point is generic (Mutate rejects
		// wholesale and leaves the file untouched), not about this
		// particular key.
		cur.Limits.MaxCallDurationS = 999999
		return nil
	})
	if err == nil {
		t.Fatal("want Mutate to fail on a validate()-rejected value, got nil")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state file after failed Mutate: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("state file changed after a REJECTED Mutate:\nbefore: %s\nafter:  %s", before, after)
	}
	if got := s.Current().Limits.MaxUAsTotal; got != 200 {
		t.Errorf("Current() changed after a rejected Mutate: MaxUAsTotal = %d, want the untouched default 200", got)
	}
}

// TestMutateSerializesConcurrentCallers (P2-T3, -race): N goroutines each
// Mutate a DISTINCT key; every key must be present in the final state file
// AND in Current() afterward. This is the property reloadMu exists to
// guarantee — without it, two concurrent read-modify-writes can silently
// drop one caller's key.
//
// Mutation (per the plan): drop reloadMu and this reddens.
func TestMutateSerializesConcurrentCallers(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	path := writePolicy(t, fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok))

	s, err := NewStore(path, fakeclock.New(epoch), discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	const n = 12
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.Mutate(func(cur *Policy) error {
				cur.Prompts = append(append([]Prompt(nil), cur.Prompts...), Prompt{
					Name: fmt.Sprintf("p%02d", i),
					Path: fmt.Sprintf("/tmp/p%02d.wav", i),
				})
				return nil
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("Mutate #%d: %v", i, err)
		}
	}

	seen := make(map[string]bool, n)
	for _, p := range s.Current().Prompts {
		seen[p.Name] = true
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("p%02d", i)
		if !seen[name] {
			t.Errorf("Current().Prompts missing %q after %d concurrent Mutate calls", name, n)
		}
	}

	// The file on disk must agree with Current() -- Mutate always reloads
	// from what it just wrote.
	onDisk, err := Load(path)
	if err != nil {
		t.Fatalf("Load after concurrent Mutates: %v", err)
	}
	diskSeen := make(map[string]bool, n)
	for _, p := range onDisk.Prompts {
		diskSeen[p.Name] = true
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("p%02d", i)
		if !diskSeen[name] {
			t.Errorf("state file on disk missing %q after %d concurrent Mutate calls", name, n)
		}
	}
}

// TestConcurrentReloadAndMutateAgree (P2-T3, -race): a stream of SIGHUP-style
// Reloads racing a stream of Mutates must leave Current() matching the FINAL
// state of the file on disk -- neither an older reload nor an older mutate
// may win last and leave the two diverged.
func TestConcurrentReloadAndMutateAgree(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	path := writePolicy(t, fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok))

	s, err := NewStore(path, fakeclock.New(epoch), discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	var wg sync.WaitGroup
	const rounds = 20
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			// Reload just re-reads whatever is on disk right now; it need not
			// succeed on every iteration (a concurrent Mutate may be mid
			// rename), only never corrupt Current().
			_ = s.Reload()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			_ = s.Mutate(func(cur *Policy) error {
				cur.Limits.MaxUAsTotal = 200 + i
				return nil
			})
		}
	}()
	wg.Wait()

	onDisk, err := Load(path)
	if err != nil {
		t.Fatalf("Load after concurrent Reload/Mutate: %v", err)
	}
	if s.Current().Limits.MaxUAsTotal != onDisk.Limits.MaxUAsTotal {
		t.Errorf("Current().Limits.MaxUAsTotal = %d, state file on disk has %d -- they must agree",
			s.Current().Limits.MaxUAsTotal, onDisk.Limits.MaxUAsTotal)
	}
}

// TestMutateDoesNotDeadlock (P2-T3 [R5-2] no-deadlock test): a single Mutate
// call must return promptly. Issued on its own goroutine so the test FAILS
// on its own timeout rather than hanging the whole suite.
//
// Mutation (per the plan): make Mutate call the exported Reload() instead of
// reloadLocked() and this test times out.
func TestMutateDoesNotDeadlock(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	path := writePolicy(t, fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok))
	s, err := NewStore(path, fakeclock.New(epoch), discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- s.Mutate(func(cur *Policy) error {
			cur.Limits.MaxUAsTotal = 201
			return nil
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Mutate: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Mutate did not return within 5s -- reloadMu is held recursively (deadlock)")
	}

	// A Reload after a completed Mutate must also return promptly, proving
	// the lock was actually released.
	relDone := make(chan error, 1)
	go func() { relDone <- s.Reload() }()
	select {
	case err := <-relDone:
		if err != nil {
			t.Fatalf("Reload after Mutate: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Reload after a completed Mutate did not return within 5s -- reloadMu was left held")
	}
}

// TestReloadHookRunsUnderReloadMu (P2-T3 [R6-1]): the ONE thing that makes
// SetReloadHook's "MUST NOT call Reload or Mutate" contract true is that the
// hook runs while reloadMu is held. A hook that can successfully TryLock it
// would be free to call Reload/Mutate itself without deadlocking, which is
// exactly the reentrancy hole the contract exists to rule out. Asserting
// this directly (rather than writing a hook that actually calls Reload, which
// would hang on success and prove nothing on failure -- see the plan) reddens
// deterministically with no timing window.
//
// Mutation (per the plan): move the hook invocation out of reloadLocked to
// after the Unlock in Reload and this case must redden.
func TestReloadHookRunsUnderReloadMu(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	path := writePolicy(t, fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok))
	s, err := NewStore(path, fakeclock.New(epoch), discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	var sawLockHeld bool
	s.SetReloadHook(func(_, _ *Policy) {
		if s.reloadMu.TryLock() {
			// Getting the lock here means reloadLocked is NOT holding it
			// while the hook runs -- the contract is broken.
			s.reloadMu.Unlock()
			sawLockHeld = false
		} else {
			sawLockHeld = true
		}
	})

	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !sawLockHeld {
		t.Error("hook's TryLock succeeded -- reloadMu was NOT held while the hook ran")
	}
}

// TestReloadHookOfTheProductionShapeReturnsNormally is the companion case:
// a hook that only reads next/Current() (the shape run.go's
// RecomputeDurationCaps registration actually uses) must not be affected by
// the contract at all -- both Reload and Mutate return normally.
func TestReloadHookOfTheProductionShapeReturnsNormally(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	path := writePolicy(t, fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok))
	s, err := NewStore(path, fakeclock.New(epoch), discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	var calls int
	s.SetReloadHook(func(_, next *Policy) {
		calls++
		_ = next.Limits.MaxUAsTotal
		_ = s.Current()
	})

	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if err := s.Mutate(func(cur *Policy) error {
		cur.Limits.MaxUAsTotal = 210
		return nil
	}); err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if calls != 2 {
		t.Errorf("hook called %d times, want 2 (one Reload, one Mutate)", calls)
	}
}
