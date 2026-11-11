package policy

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// rewrite replaces the contents of an existing policy file in place.
func rewrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("rewrite %s: %v", path, err)
	}
}

func TestNewStoreLoadsAndStampsLoadedAtFromTheClock(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	path := writePolicy(t, fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok))

	clk := fakeclock.New(epoch)
	s, err := NewStore(path, clk, discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s.Current() == nil {
		t.Fatal("Current() = nil after a successful NewStore")
	}
	if !s.LoadedAt().Equal(epoch) {
		t.Errorf("LoadedAt() = %v, want the fake clock's %v", s.LoadedAt(), epoch)
	}
	if got := s.ReloadFailures(); got != 0 {
		t.Errorf("ReloadFailures() = %d, want 0", got)
	}
}

func TestNewStoreFailsOnAnInvalidFile(t *testing.T) {
	path := writePolicy(t, "destinations:\n  deny_all: ['^sip:']\n")
	if _, err := NewStore(path, fakeclock.New(epoch), discardLogger()); err == nil {
		t.Fatal("want NewStore to fail on an invalid policy, got nil")
	}
}

func TestCurrentReturnsAStableSnapshot(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	path := writePolicy(t, fmt.Sprintf(
		"auth:\n  bearer_token_file: %s\nlimits:\n  max_call_duration_s: 7200\n", tok))

	s, err := NewStore(path, fakeclock.New(epoch), discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	before := s.Current()

	rewrite(t, path, fmt.Sprintf(
		"auth:\n  bearer_token_file: %s\nlimits:\n  max_call_duration_s: 60\n", tok))
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// §12.2.1: an operation that captured a snapshot continues under the
	// policy in force when it started. The snapshot must not have changed.
	if got := before.Limits.MaxCallDurationS; got != 7200 {
		t.Errorf("held snapshot mutated: max_call_duration_s = %d, want 7200", got)
	}
	if got := s.Current().Limits.MaxCallDurationS; got != 60 {
		t.Errorf("Current() after reload = %d, want 60", got)
	}
	if before == s.Current() {
		t.Error("Reload must install a NEW *Policy, not mutate the existing one")
	}
}

// TestNewStaticStoreWrapsAPolicyWithNoFile covers the constructor session's
// unit tests and the loopback harness use (U9): a *Store over a Policy that
// was never on disk. Reload always fails, because there is no path to
// re-read — which must be an explicit, observable failure rather than a
// silent no-op that would let a test believe it had exercised §12.2.1.
func TestNewStaticStoreWrapsAPolicyWithNoFile(t *testing.T) {
	clk := fakeclock.New(epoch)
	s := NewStaticStore(Defaults(), clk, discardLogger())

	if s.Current() == nil {
		t.Fatal("Current() = nil after NewStaticStore")
	}
	if got := s.Current().Limits.MaxWaitersPerCall; got != 8 {
		t.Errorf("Current().Limits.MaxWaitersPerCall = %d, want Defaults()' 8", got)
	}
	if !s.LoadedAt().Equal(epoch) {
		t.Errorf("LoadedAt() = %v, want the fake clock's %v", s.LoadedAt(), epoch)
	}
	if s.LastReloadFailed() {
		t.Error("LastReloadFailed() = true before any Reload attempt")
	}

	before := s.Current()
	if err := s.Reload(); err == nil {
		t.Fatal("want a static Store's Reload to fail, got nil")
	}
	if s.Current() != before {
		t.Error("a failed Reload must leave the previous *Policy in force")
	}
	if !s.LastReloadFailed() {
		t.Error("LastReloadFailed() = false after a failed Reload")
	}
	if got := s.ReloadFailures(); got != 1 {
		t.Errorf("ReloadFailures() = %d, want 1", got)
	}
}

func TestReloadSuccessSwapsAndFiresTheHook(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	path := writePolicy(t, fmt.Sprintf(
		"auth:\n  bearer_token_file: %s\nlimits:\n  max_call_duration_s: 7200\n", tok))

	clk := fakeclock.New(epoch)
	s, err := NewStore(path, clk, discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	var gotPrev, gotNext *Policy
	var calls int
	s.SetReloadHook(func(prev, next *Policy) {
		calls++
		gotPrev, gotNext = prev, next
	})

	rewrite(t, path, fmt.Sprintf(
		"auth:\n  bearer_token_file: %s\nlimits:\n  max_call_duration_s: 60\n", tok))
	clk.Advance(30 * time.Second)

	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if calls != 1 {
		t.Fatalf("hook called %d times, want 1", calls)
	}
	if gotPrev.Limits.MaxCallDurationS != 7200 {
		t.Errorf("hook prev cap = %d, want 7200", gotPrev.Limits.MaxCallDurationS)
	}
	if gotNext.Limits.MaxCallDurationS != 60 {
		t.Errorf("hook next cap = %d, want 60", gotNext.Limits.MaxCallDurationS)
	}
	if gotNext != s.Current() {
		t.Error("hook must receive the policy that is now current")
	}
	if !s.LoadedAt().Equal(epoch.Add(30 * time.Second)) {
		t.Errorf("LoadedAt() = %v, want the advanced fake clock", s.LoadedAt())
	}
	if s.ReloadFailures() != 0 {
		t.Errorf("ReloadFailures() = %d, want 0", s.ReloadFailures())
	}
}

func TestReloadFailureIsWholesale(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	good := fmt.Sprintf(
		"auth:\n  bearer_token_file: %s\ndestinations:\n  deny: ['^sip:\\+?1900']\n", tok)
	path := writePolicy(t, good)

	var logBuf bytes.Buffer
	s, err := NewStore(path, fakeclock.New(epoch), slog.New(slog.NewJSONHandler(&logBuf, nil)))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	before := s.Current()

	hookCalls := 0
	s.SetReloadHook(func(_, _ *Policy) { hookCalls++ })

	bad := []struct {
		name      string
		body      string
		wantInLog string
	}{
		{
			name:      "unknown key",
			body:      fmt.Sprintf("auth:\n  bearer_token_file: %s\ndestinations:\n  deny_all: ['^x']\n", tok),
			wantInLog: "deny_all",
		},
		{
			name:      "malformed regex",
			body:      fmt.Sprintf("auth:\n  bearer_token_file: %s\ndestinations:\n  deny: ['^sip:[0-9']\n", tok),
			wantInLog: "destinations.deny[0]",
		},
		{
			name:      "unparseable yaml",
			body:      "auth: [this is not a mapping\n",
			wantInLog: "policy:",
		},
		{
			name:      "missing required key",
			body:      "destinations:\n  deny: ['^x']\n",
			wantInLog: "auth.bearer_token_file",
		},
	}

	for i, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			logBuf.Reset()
			rewrite(t, path, tt.body)

			err := s.Reload()
			if err == nil {
				t.Fatal("want Reload to fail, got nil")
			}
			// The PREVIOUS policy stays in force, unchanged and identical.
			if s.Current() != before {
				t.Error("a failed reload must leave the previous *Policy in force")
			}
			if len(s.Current().Destinations.Deny) != 1 ||
				s.Current().Destinations.Deny[0] != `^sip:\+?1900` {
				t.Errorf("previous policy was disturbed: %#v", s.Current().Destinations)
			}
			if hookCalls != 0 {
				t.Errorf("hook must not fire on a failed reload, fired %d times", hookCalls)
			}
			if got, want := s.ReloadFailures(), int64(i+1); got != want {
				t.Errorf("ReloadFailures() = %d, want %d", got, want)
			}
			// §12.2.1: the failure is logged at ERROR naming the offending key.
			line := logBuf.String()
			if !strings.Contains(line, `"level":"ERROR"`) {
				t.Errorf("want an ERROR log line, got: %s", line)
			}
			if !strings.Contains(line, tt.wantInLog) {
				t.Errorf("ERROR line must name %q, got: %s", tt.wantInLog, line)
			}
		})
	}
}

// TestLastReloadFailedTracksTheMOSTRecentAttempt is §5 N5's /readyz input.
// The distinction from ReloadFailures() is the whole point: a lifetime total
// stays non-zero forever, so a daemon that recovered from a bad edit would
// report NOT READY permanently.
func TestLastReloadFailedTracksTheMostRecentAttempt(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	good := fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok)
	path := writePolicy(t, good)

	s, err := NewStore(path, fakeclock.New(epoch), discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s.LastReloadFailed() {
		t.Fatal("LastReloadFailed() = true after a successful NewStore")
	}

	// A bad edit: the flag sets and the counter increments.
	rewrite(t, path, "destinations:\n  deny_all: ['^sip:']\n")
	if err := s.Reload(); err == nil {
		t.Fatal("want Reload to fail on an invalid policy")
	}
	if !s.LastReloadFailed() {
		t.Error("LastReloadFailed() = false after a failed Reload")
	}
	if got := s.ReloadFailures(); got != 1 {
		t.Errorf("ReloadFailures() = %d, want 1", got)
	}

	// The operator fixes it: the flag CLEARS, the lifetime counter does NOT.
	rewrite(t, path, good)
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload after the fix: %v", err)
	}
	if s.LastReloadFailed() {
		t.Error("LastReloadFailed() = true after a SUCCESSFUL Reload; /readyz would never recover")
	}
	if got := s.ReloadFailures(); got != 1 {
		t.Errorf("ReloadFailures() = %d, want it to stay at 1: it is a lifetime total", got)
	}
}

// TestStoreIsSafeForConcurrentReadersDuringReload is locked decision D3(b):
// Store is the first concurrent object in this tree, and its doc comment
// promises Current is safe for concurrent use from any goroutine while a
// single goroutine drives Reload (Task 20's SIGHUP handler). N readers hammer
// Current() while one writer repeatedly reloads; this must pass under -race
// with no data race and no reader ever observing a nil *Policy.
func TestStoreIsSafeForConcurrentReadersDuringReload(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	path := writePolicy(t, fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok))
	s, err := NewStore(path, fakeclock.New(epoch), discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	const readers = 8
	const reloads = 200

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if p := s.Current(); p == nil {
						t.Error("Current() returned nil during concurrent reload")
						return
					}
				}
			}
		}()
	}

	for i := 0; i < reloads; i++ {
		rewrite(t, path, fmt.Sprintf(
			"auth:\n  bearer_token_file: %s\nlimits:\n  max_call_duration_s: %d\n", tok, i+1))
		if err := s.Reload(); err != nil {
			t.Fatalf("Reload: %v", err)
		}
	}
	close(stop)
	wg.Wait()
}
