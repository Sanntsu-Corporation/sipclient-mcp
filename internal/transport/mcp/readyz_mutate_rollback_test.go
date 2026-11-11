package mcp

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// failingCABundle writes a file that is NOT a PEM certificate and returns its
// path. Setting tls.ca_bundle to it passes Policy.validate() (which never
// opens the file) and fails Policy.resolve() at Load time with "contains no
// PEM certificate" — which is how these tests induce a reload failure INSIDE
// MutateWithCommit, after the state file has already been committed, without
// tampering with the file behind the Store's back.
func failingCABundle(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "not-a-cert.pem")
	if err := os.WriteFile(p, []byte("this is not a PEM certificate\n"), 0o600); err != nil {
		t.Fatalf("write bogus ca bundle: %v", err)
	}
	return p
}

func readyStatus(t *testing.T, env *observabilityEnv) (int, ReadyStatus) {
	t.Helper()
	rr := env.get(t, "/readyz", testToken)
	var got ReadyStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("GET /readyz body is not JSON: %v\n%s", err, rr.Body.String())
	}
	return rr.Code, got
}

// TestExternalReloadFailureStillMarksTheDaemonUnready pins the behaviour the
// rollback fix must NOT weaken: a real SIGHUP-driven Reload() that fails has
// nothing to roll back to that is better than the live state — the operator's
// file on disk really is broken — so lastFailed stays set and /readyz keeps
// answering 503 until a later reload succeeds (§5 N5).
//
// It is the control half of
// TestMutationReloadFailureStaysUnreadyUntilALaterReloadSucceeds below: with
// the conservative rule those two cases are now deliberately INDISTINGUISHABLE
// in their effect on lastFailed, and a change that stopped setting the flag at
// all would redden here.
func TestExternalReloadFailureStillMarksTheDaemonUnready(t *testing.T) {
	env := newObservabilityEnv(t)
	if env.store.LastReloadFailed() {
		t.Fatal("LastReloadFailed() = true on a freshly loaded store, want false")
	}

	env.failReload(t) // rewrites the file with malformed YAML, then Reload()

	if !env.store.LastReloadFailed() {
		t.Fatal("LastReloadFailed() = false after a failed SIGHUP reload, want true — " +
			"an operator's config error must surface as unreadiness, not only as a log line")
	}
	code, status := readyStatus(t, env)
	if code != http.StatusServiceUnavailable || status.Ready {
		t.Fatalf("GET /readyz = %d ready=%v after a failed SIGHUP reload, want 503 ready=false",
			code, status.Ready)
	}
}

// TestMutationReloadFailureStaysUnreadyUntilALaterReloadSucceeds pins the
// CONSERVATIVE contract, which replaced a clever one that failed open.
//
// THE REMOVED BEHAVIOUR. MutateWithCommit used to capture lastFailed on entry
// and RESTORE it whenever the rollback reported clean, so that a config_set
// which provably did not happen would not leave the daemon unready. But a
// "clean" state-file rollback says nothing about whether the policy is
// LOADABLE: when the real breakage is external to that file (a missing
// auth.bearer_token_file), the restore cleared the flag while every future
// reload — including the next restart — was still going to fail identically.
// Worse, StagedFile.Rollback DELETES the state file when there was none to
// begin with, so a daemon could report ready having lost its state file, and
// Defaults()' empty destinations.allow means allow-everything in
// CheckDestination: fail-open dialling with nothing saying so.
//
// THE CONTRACT NOW. A mutation whose internal reload fails leaves lastFailed
// exactly where reloadLocked put it — true — regardless of how clean the
// rollback was, and it stays true until some LATER reload actually succeeds.
// The accepted cost is a 503 that may outlast the most optimistic reading of
// the facts.
//
// MUTATION CHECK: reintroduce a `s.lastFailed.Store(failedBefore)` on
// MutateWithCommit's reload-failure branch and this test reddens on both the
// LastReloadFailed() assertion and the /readyz status code.
func TestMutationReloadFailureStaysUnreadyUntilALaterReloadSucceeds(t *testing.T) {
	env := newObservabilityEnv(t)

	if code, status := readyStatus(t, env); code != http.StatusOK || !status.Ready {
		t.Fatalf("GET /readyz = %d ready=%v before the mutation, want 200 ready=true",
			code, status.Ready)
	}
	before, err := os.ReadFile(env.policyPath)
	if err != nil {
		t.Fatalf("read state file before Mutate: %v", err)
	}
	failuresBefore := env.store.ReloadFailures()

	// A mutation whose value validate() accepts but Load's resolve() rejects:
	// the state file IS committed, the reload then fails, and the whole
	// attempt is rolled back.
	bogus := failingCABundle(t)
	mutErr := env.store.Mutate(func(cur *policy.Policy) error {
		cur.TLS.CABundle = bogus
		return nil
	})
	if mutErr == nil {
		t.Fatal("Mutate succeeded with a ca_bundle that is not a PEM certificate, " +
			"want the internal reload to fail — this test's premise")
	}

	// The rollback really was complete: disk and the live policy both say the
	// change did not happen. (If this half regressed, the readiness assertion
	// below would be asserting the wrong thing.)
	after, err := os.ReadFile(env.policyPath)
	if err != nil {
		t.Fatalf("read state file after the failed Mutate: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("state file changed after a fully rolled-back Mutate:\nbefore: %s\nafter:  %s",
			before, after)
	}
	if got := env.store.Current().TLS.CABundle; got != "" {
		t.Fatalf("Current().TLS.CABundle = %q after a fully rolled-back Mutate, want \"\"", got)
	}

	// THE CONSERVATIVE CONTRACT. However clean the rollback was, the reload
	// failed, so the daemon reports not-ready — exactly as it would for a
	// SIGHUP failure — until something proves the policy loads again.
	if !env.store.LastReloadFailed() {
		t.Error("LastReloadFailed() = false after a config_set whose internal reload " +
			"failed, want true — a clean state-file rollback does not prove the " +
			"policy is loadable, and clearing the flag here reports ready over a " +
			"daemon whose every future reload will fail the same way")
	}
	if code, status := readyStatus(t, env); code != http.StatusServiceUnavailable || status.Ready {
		t.Errorf("GET /readyz = %d ready=%v after a config_set whose reload failed, "+
			"want 503 ready=false", code, status.Ready)
	}

	// policy_reload_failures_total is a LIFETIME total that never decreases
	// (policy.Store.ReloadFailures), so the attempt stays counted: a
	// config_set whose own reload could not load what it had just written is
	// worth observing, and rewinding a monotonic counter would read downstream
	// as a counter reset.
	if got := env.store.ReloadFailures(); got != failuresBefore+1 {
		t.Errorf("ReloadFailures() = %d, want %d — the failed attempt stays counted "+
			"in the lifetime total", got, failuresBefore+1)
	}

	// THE OTHER HALF OF THE CONTRACT: the flag is not a permanent scar either.
	// The rollback put the original, loadable file back, so an ordinary reload
	// — from any caller: the SIGHUP goroutine here, a later config_set or an
	// admin_token_rotate — succeeds and clears it, which is reloadLocked's own
	// success path and the ONLY thing that ever clears it.
	if err := env.store.Reload(); err != nil {
		t.Fatalf("Reload after the rolled-back mutation: %v — the rollback restored a "+
			"file that had loaded once already, so this must succeed", err)
	}
	if env.store.LastReloadFailed() {
		t.Error("LastReloadFailed() = true after a SUCCESSFUL later reload, want false — " +
			"only a successful reload clears the flag, and it must actually clear it")
	}
	if code, status := readyStatus(t, env); code != http.StatusOK || !status.Ready {
		t.Errorf("GET /readyz = %d ready=%v after a later successful reload, want 200 ready=true",
			code, status.Ready)
	}
}

// TestRolledBackMutationDoesNotClearAPriorExternalFailure pins the property
// that mattered most while the restore existed and still matters now that it
// does not: a deliberately-failed mutation cannot be used to CLEAR a
// pre-existing reload failure. A daemon already unready from a broken file on
// disk stays unready after an unrelated config_set is abandoned.
//
// It held only conditionally before (the restore had to put back WHAT IT WAS
// rather than hardcode false); with the conservative rule nothing on this path
// writes lastFailed at all, so it now holds trivially. The test stays: it is
// cheap, and it is what would redden first if some future change reintroduced
// a clear-on-rollback.
func TestRolledBackMutationDoesNotClearAPriorExternalFailure(t *testing.T) {
	env := newObservabilityEnv(t)

	// A real SIGHUP failure first. failReload leaves malformed YAML on disk,
	// so the mutation below fails at its own reload too — for the same reason
	// the daemon is already unready, which is exactly the situation being
	// pinned.
	env.failReload(t)
	if !env.store.LastReloadFailed() {
		t.Fatal("LastReloadFailed() = false after a failed SIGHUP reload, want true")
	}

	if err := env.store.Mutate(func(cur *policy.Policy) error {
		cur.TLS.CABundle = failingCABundle(t)
		return nil
	}); err == nil {
		t.Fatal("Mutate succeeded against a broken state file, want an error")
	}

	if !env.store.LastReloadFailed() {
		t.Error("LastReloadFailed() = false after an abandoned config_set that " +
			"followed a REAL reload failure, want true — a failed mutation never " +
			"clears the flag; only a successful reload does")
	}
	if code, status := readyStatus(t, env); code != http.StatusServiceUnavailable || status.Ready {
		t.Errorf("GET /readyz = %d ready=%v, want 503 ready=false — the operator's "+
			"config on disk is still broken", code, status.Ready)
	}
}

// removeStateFileAndItsBearerToken stages the anomaly both tests below need: a
// running Store whose state file has vanished out from under it, plus the
// external file its next reload depends on (auth.bearer_token_file, written by
// testPolicyStore beside the state file) gone with it.
//
// The first disappearance makes the mutation's staging find nothing to capture
// (StagedFile.prevExisted == false, so the rollback DELETES the file it just
// committed); the second makes the reload after the commit fail, which is what
// drives the mutation onto that rollback path at all.
//
// Deleting the token FILE does not disturb the live bearer digest — that was
// computed at load time and the failed reload leaves the previous policy in
// force — so /readyz still authenticates and answers about readiness rather
// than 401.
func removeStateFileAndItsBearerToken(t *testing.T, env *observabilityEnv) {
	t.Helper()
	if err := os.Remove(env.policyPath); err != nil {
		t.Fatalf("remove the state file: %v", err)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(env.policyPath), "bearer.token")); err != nil {
		t.Fatalf("remove the bearer token file: %v", err)
	}
}

// assertStateFileGone confirms the rollback's faithful restore of "there was no
// file here" — a delete, not a write.
func assertStateFileGone(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("os.Stat(%s) = %v after the rolled-back mutation, want fs.ErrNotExist", path, err)
	}
}

// TestVanishedStateFileDuringAConfigSetLeavesTheDaemonUnready is the
// /readyz-facing half of internal/policy's
// TestMutateRollbackOfAVanishedStateFileDeletesItLogsAndStaysFailed, on the
// config_set shape.
//
// It pins the worst case the conservative lastFailed rule exists for: the
// rollback is "clean" by its own measure — it faithfully restored the nothing
// it found — yet the daemon now has NO state file, and a restart would bring it
// up on Defaults(), whose empty destinations.allow CheckDestination reads as
// allow-everything. Reporting ready here would be fail-open dialling with
// nothing saying so, so /readyz must answer 503.
//
// MUTATION CHECK: reintroduce a `s.lastFailed.Store(failedBefore)` on
// MutateWithCommit's reload-failure branch and the /readyz assertion reddens.
func TestVanishedStateFileDuringAConfigSetLeavesTheDaemonUnready(t *testing.T) {
	env := newObservabilityEnv(t)
	if code, status := readyStatus(t, env); code != http.StatusOK || !status.Ready {
		t.Fatalf("GET /readyz = %d ready=%v before the mutation, want 200 ready=true",
			code, status.Ready)
	}

	removeStateFileAndItsBearerToken(t, env)

	if err := env.store.Mutate(func(cur *policy.Policy) error {
		cur.Limits.MaxUAsTotal = 250
		return nil
	}); err == nil {
		t.Fatal("Mutate succeeded with auth.bearer_token_file missing, want the internal " +
			"reload to fail — this test's premise")
	}

	assertStateFileGone(t, env.policyPath)
	if !env.store.LastReloadFailed() {
		t.Error("LastReloadFailed() = false after a config_set that lost the state file, want true")
	}
	if code, status := readyStatus(t, env); code != http.StatusServiceUnavailable || status.Ready {
		t.Errorf("GET /readyz = %d ready=%v after a config_set whose rollback deleted the "+
			"state file, want 503 ready=false — a restart from here comes up on Defaults(), "+
			"whose empty destinations.allow is allow-everything", code, status.Ready)
	}
}

// TestVanishedStateFileDuringAnAdminTokenRotateLeavesTheDaemonUnready is the
// same scenario on the OTHER MutateWithCommit shape — the one with a non-nil
// commit hook. Every other test in this file drives plain Mutate (config_set),
// so the two-undo path (the staged STATE file AND the commit hook's own
// rollback, both run under reloadMu) went unexercised at the /readyz boundary.
//
// The hook mirrors session.ToolService.AdminTokenRotate's: stage the new token
// beside the file, commit it, and hand back the undo that puts the previous
// token back if the reload after the commit fails. It is reproduced here rather
// than called through ToolService so this stays a transport-level test of the
// readiness contract, not of the tool.
func TestVanishedStateFileDuringAnAdminTokenRotateLeavesTheDaemonUnready(t *testing.T) {
	env := newObservabilityEnv(t)
	adminFile := filepath.Join(filepath.Dir(env.policyPath), "admin.token")
	const originalToken = "the-original-admin-token"
	if err := os.WriteFile(adminFile, []byte(originalToken), 0o600); err != nil {
		t.Fatalf("write admin token file: %v", err)
	}

	removeStateFileAndItsBearerToken(t, env)

	err := env.store.MutateWithCommit(
		// A rotation changes no policy field: the mutation exists so the reload
		// underneath it recomputes the digest from the file the hook installs.
		func(*policy.Policy) error { return nil },
		func() (func() error, error) {
			staged, err := policy.StageSecretFile(adminFile, "the-rotated-admin-token")
			if err != nil {
				return nil, err
			}
			defer staged.Discard()
			if err := staged.Commit(); err != nil {
				return nil, err
			}
			return staged.Rollback, nil
		},
	)
	if err == nil {
		t.Fatal("MutateWithCommit succeeded with auth.bearer_token_file missing, want the " +
			"internal reload to fail — this test's premise")
	}

	assertStateFileGone(t, env.policyPath)

	// The commit hook's own undo ran too: the token file holds the value this
	// call refused to return to anyone, or the next restart reads a token
	// nobody has.
	got, readErr := os.ReadFile(adminFile)
	if readErr != nil {
		t.Fatalf("read admin token file after the rolled-back rotation: %v", readErr)
	}
	if string(got) != originalToken {
		t.Errorf("admin token file = %q after a rolled-back rotation, want the previous "+
			"token %q", got, originalToken)
	}

	if code, status := readyStatus(t, env); code != http.StatusServiceUnavailable || status.Ready {
		t.Errorf("GET /readyz = %d ready=%v after an admin_token_rotate whose rollback "+
			"deleted the state file, want 503 ready=false", code, status.Ready)
	}
}
