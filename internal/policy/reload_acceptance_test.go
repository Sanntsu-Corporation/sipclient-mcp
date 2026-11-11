package policy

import (
	"fmt"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// liveCall stands in for a call that was placed under one policy snapshot and
// is still live when a later one is loaded. It carries ONLY the snapshot,
// because that is all the retroactivity test below reads.
//
// IT DELIBERATELY NO LONGER CARRIES A DEADLINE, and there is no local
// recomputeDeadlines helper any more. Both used to exist here, and the two
// duration-cap tests that used them asserted the ARITHMETIC of CallDeadline
// and EarlierDeadline against a struct declared in this file — a test whose
// subject was not the shipped object. §12.2.1's max_call_duration_s exception
// is now driven end to end through the real manager, the real file-backed
// Store and the real Reload, in
// session.TestReloadLoweredCapTerminatesTheOverCapCallAndReschedulesTheOther
// and session.TestReloadRaisedCapNeverExtendsALiveCall. The arithmetic itself
// keeps its own unit coverage in duration_test.go, where it belongs.
type liveCall struct {
	snapshot *Policy
}

// §12.2.1 bullet 1: "New operations always use the new policy. There is no
// grace period."
func TestReload_NewOperationsUseTheNewPolicyImmediately(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	path := writePolicy(t, fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok))
	s, err := NewStore(path, fakeclock.New(epoch), discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	const dest = "sip:x@lab.internal"
	if _, _, err := s.Current().CheckDestination(dest); err != nil {
		t.Fatalf("dial must be permitted before the reload: %v", err)
	}

	rewrite(t, path, fmt.Sprintf(
		"auth:\n  bearer_token_file: %s\ndestinations:\n  deny: ['^sip:.*@lab\\.internal$']\n", tok))
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	_, rule, err := s.Current().CheckDestination(dest)
	if err == nil {
		t.Fatal("a fresh call_dial after the reload must be denied")
	}
	if rule != `^sip:.*@lab\.internal$` {
		t.Errorf("denied rule = %q, want the new deny pattern", rule)
	}
}

// §12.2.1 bullet 2: "A call already dialing, ringing or answered continues
// under the policy in force when it started."
func TestReload_TightenedDenyListIsNotRetroactive(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	path := writePolicy(t, fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok))
	s, err := NewStore(path, fakeclock.New(epoch), discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	const dest = "sip:x@lab.internal"

	// A call is placed and is answered: it captures the policy in force.
	answered := &liveCall{snapshot: s.Current()}
	if _, _, err := answered.snapshot.CheckDestination(dest); err != nil {
		t.Fatalf("the call must have been permitted when placed: %v", err)
	}

	rewrite(t, path, fmt.Sprintf(
		"auth:\n  bearer_token_file: %s\ndestinations:\n  deny: ['^sip:.*@lab\\.internal$']\n", tok))
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// The live call's own snapshot is untouched: it stays answered.
	if _, _, err := answered.snapshot.CheckDestination(dest); err != nil {
		t.Errorf("a tightened deny list must NOT apply retroactively to a live call: %v", err)
	}
	// A fresh dial to the same URI is denied, naming the new rule.
	_, rule, err := s.Current().CheckDestination(dest)
	if err == nil {
		t.Error("a fresh call_dial to the same URI must be denied")
	}
	if rule != `^sip:.*@lab\.internal$` {
		t.Errorf("denied rule = %q, want the new deny pattern", rule)
	}
}

// §12.2.1 bullet 5: "A policy file with a malformed regex in
// destinations.deny sent by SIGHUP leaves the prior policy in force,
// asserted by that same fresh call_dial still succeeding."
func TestReload_InvalidFileLeavesThePriorPolicyInForce(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	path := writePolicy(t, fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok))
	s, err := NewStore(path, fakeclock.New(epoch), discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	const dest = "sip:x@lab.internal"
	rewrite(t, path, fmt.Sprintf(
		"auth:\n  bearer_token_file: %s\ndestinations:\n  deny: ['^sip:[0-9']\n", tok))
	if err := s.Reload(); err == nil {
		t.Fatal("want the malformed-regex reload to fail, got nil")
	}

	if _, _, err := s.Current().CheckDestination(dest); err != nil {
		t.Errorf("a fresh call_dial must still succeed under the prior policy: %v", err)
	}
	if got := s.ReloadFailures(); got != 1 {
		t.Errorf("ReloadFailures() = %d, want 1", got)
	}
}
