package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// newFileBackedToolService builds a ToolService backed by a REAL
// policy.Store (policy.NewStore, not NewStaticStore): Store.Mutate refuses
// to run against a static store (there is no file to write it to), and
// ConfigSet/AdminTokenRotate both go through Mutate. admin == "" leaves
// auth.admin_token_file unset. Returns the ToolService, the Store, the
// state file's own path (for tests that need to read it directly) and the
// admin token FILE path (empty when admin == "").
func newFileBackedToolService(t *testing.T, admin string) (ts *ToolService, store *policy.Store, statePath, adminFile string) {
	t.Helper()
	dir := t.TempDir()
	bearerFile := filepath.Join(dir, "bearer.token")
	if err := os.WriteFile(bearerFile, []byte("test-bearer-token"), 0o600); err != nil {
		t.Fatalf("write bearer token file: %v", err)
	}
	yaml := "auth:\n  bearer_token_file: " + bearerFile + "\n"
	if admin != "" {
		adminFile = filepath.Join(dir, "admin.token")
		if err := os.WriteFile(adminFile, []byte(admin), 0o600); err != nil {
			t.Fatalf("write admin token file: %v", err)
		}
		yaml += "  admin_token_file: " + adminFile + "\n"
	}
	statePath = filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(statePath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	fc := newFakeClock()
	s, err := policy.NewStore(statePath, fc, testLogger())
	if err != nil {
		t.Fatalf("policy.NewStore: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx:    ctx,
		Clock:  fc,
		Policy: s,
		Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) {
			return nopAgent{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return NewToolService(m), s, statePath, adminFile
}

// TestConfigGetContainsNoRevealedSecret is config_get's half of the
// credential-isolation property internal/policy's TestNoCredentialEverEscapesPolicy
// asserts for the Policy and Store types themselves.
//
// config_get is a NEW secret-adjacent surface: it marshals policy-derived
// values into a tool response, so it is a place a token could reach a caller
// that did not exist when that property was first pinned. It may report that a
// token file IS SET -- the path is configuration, not a credential -- but never
// what is in it. BOTH tokens are checked, and both renderings (the %v walk and
// the JSON a response actually travels as) are checked, because a map that
// prints clean can still marshal differently.
func TestConfigGetContainsNoRevealedSecret(t *testing.T) {
	const (
		bearerTok = "test-bearer-token" // what newFileBackedToolService writes
		adminTok  = "the-admin-token-value"
	)
	ts, _, _, _ := newFileBackedToolService(t, adminTok)
	out, err := ts.ConfigGet(context.Background(), "sess", ConfigGetInput{})
	if err != nil {
		t.Fatalf("ConfigGet: %v", err)
	}
	// The response must contain FILE PATHS, never the token bytes
	// themselves — fmt.Sprintf("%v", ...) walks the whole map/slice tree,
	// and json.Marshal is the shape it leaves the daemon in.
	asJSON, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal the ConfigGet response: %v", err)
	}
	renders := map[string]string{
		"fmt %v": fmt.Sprintf("%v", out),
		"json":   string(asJSON),
	}
	for name, body := range renders {
		for secret, value := range map[string]string{
			"bearer token": bearerTok,
			"admin token":  adminTok,
		} {
			if strings.Contains(body, value) {
				t.Errorf("ConfigGet's %s rendering leaked the %s's plaintext: %s", name, secret, body)
			}
		}
	}
	// Anti-vacuity: the response must really carry the auth section, or the
	// assertion above holds over nothing. The PATHS are what it may carry.
	for name, body := range renders {
		if !strings.Contains(body, "bearer_token_file") || !strings.Contains(body, "admin_token_file") {
			t.Errorf("ConfigGet's %s rendering is missing the auth section; the leak check is vacuous: %s", name, body)
		}
	}
}

// TestConfigGetReportsSessionLifecycleLimits is CF-002's observability half:
// session_ttl, session_resume_window, and registry_retention now have a
// real effect (Tasks 3-5), so config_get reports them instead of only
// accepting/validating them. max_uas_per_session is reported for the same
// reason (Task 1).
func TestConfigGetReportsSessionLifecycleLimits(t *testing.T) {
	ts, _, _, _ := newFileBackedToolService(t, "")
	out, err := ts.ConfigGet(context.Background(), "sess", ConfigGetInput{})
	if err != nil {
		t.Fatalf("ConfigGet: %v", err)
	}
	body, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("ConfigGet returned %T, want map[string]any", out)
	}
	limits, ok := body["limits"].(map[string]any)
	if !ok {
		t.Fatalf("ConfigGet's response has no \"limits\" map: %v", body)
	}
	want := map[string]any{
		"session_ttl":           policy.Defaults().Limits.SessionTTL.Duration().String(),
		"session_resume_window": policy.Defaults().Limits.SessionResumeWindow.Duration().String(),
		"registry_retention":    policy.Defaults().Limits.RegistryRetention.Duration().String(),
		"max_uas_per_session":   policy.Defaults().Limits.MaxUAsPerSession,
	}
	for key, wantVal := range want {
		if got := limits[key]; got != wantVal {
			t.Errorf("limits[%q] = %v, want %v", key, got, wantVal)
		}
	}
}

func TestConfigSetTakesEffectWithoutRestart(t *testing.T) {
	ts, store, _, _ := newFileBackedToolService(t, "")
	_, err := ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
		Key: "limits.max_uas_total", Value: float64(250),
	})
	if err != nil {
		t.Fatalf("ConfigSet: %v", err)
	}
	if got := store.Current().Limits.MaxUAsTotal; got != 250 {
		t.Errorf("Current().Limits.MaxUAsTotal = %d, want 250", got)
	}
}

func TestConfigSetArtifactDirIsPermanentlyDenied(t *testing.T) {
	ts, store, _, _ := newFileBackedToolService(t, "")
	before := store.Current().Artifact.Dir

	_, err := ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
		Key: "artifact.dir", Value: "/tmp/somewhere-else",
	})
	if err == nil {
		t.Fatal("want ConfigSet(artifact.dir) to fail, got nil")
	}
	if apierr.CodeOf(err) != apierr.CodeInvalidArgument {
		t.Errorf("code = %v, want invalid_argument", apierr.CodeOf(err))
	}
	msg := err.Error()
	if !strings.Contains(msg, "restart") {
		t.Errorf("error %q does not state the restart-required wording", msg)
	}
	if strings.Contains(msg, "pending") {
		t.Errorf("error %q must state the FINAL answer, not defer to a future task", msg)
	}
	if store.Current().Artifact.Dir != before {
		t.Errorf("Artifact.Dir changed despite the denial: %q -> %q", before, store.Current().Artifact.Dir)
	}
}

func TestConfigSetInvalidValueLeavesStateFileByteIdentical(t *testing.T) {
	ts, _, statePath, _ := newFileBackedToolService(t, "")
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}

	_, err = ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
		Key: "limits.max_uas_total", Value: "not-a-number",
	})
	if err == nil {
		t.Fatal("want ConfigSet to fail on a wrong-typed value, got nil")
	}

	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state file after failed ConfigSet: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("state file changed after a rejected ConfigSet")
	}
}

// TestConfigSetRejectsDegenerateNumericValues is the range-check pin.
//
// THE BUG IT PINS — applyConfigKey checked each curated key's TYPE and nothing
// else, so limits.max_uas_total=0, limits.max_uas_total=-1,
// limits.max_concurrent_calls_total=0 and artifact.max_bytes=-5 all returned
// nil, took effect LIVE and were persisted to the state file, surviving the
// restart that would otherwise have cleared them. max_uas_total=0 wedges the
// daemon outright: every ua_create fails with resource_limit and the only way
// back is editing the state file by hand. The only negative coverage
// config_set had was a TYPE error (a non-numeric string), which gave false
// confidence that ranges were checked too.
//
// The valid case in each row is not decoration: it is what proves the
// rejection is a FLOOR and not a blanket refusal of the key.
//
// Mutation check: swap any configPositive* call back to its plain decoder and
// that key's 0 and negative rows redden.
func TestConfigSetRejectsDegenerateNumericValues(t *testing.T) {
	for _, tc := range []struct {
		key   string
		valid any
		read  func(*policy.Policy) any
	}{
		{"limits.max_uas_total", float64(250), func(p *policy.Policy) any { return p.Limits.MaxUAsTotal }},
		{"limits.max_concurrent_calls_total", float64(40), func(p *policy.Policy) any { return p.Limits.MaxConcurrentCallsTotal }},
		{"limits.max_concurrent_calls_per_session", float64(4), func(p *policy.Policy) any { return p.Limits.MaxConcurrentCallsPerSession }},
		{"artifact.max_bytes", float64(4096), func(p *policy.Policy) any { return p.Artifact.MaxBytes }},
	} {
		t.Run(tc.key, func(t *testing.T) {
			for _, bad := range []float64{0, -1} {
				ts, store, statePath, _ := newFileBackedToolService(t, "")
				before, err := os.ReadFile(statePath)
				if err != nil {
					t.Fatalf("read state file: %v", err)
				}
				was := tc.read(store.Current())

				_, err = ts.ConfigSet(context.Background(), "sess", ConfigSetInput{Key: tc.key, Value: bad})
				if err == nil {
					t.Fatalf("ConfigSet(%s=%v) succeeded; a non-positive limit wedges the daemon", tc.key, bad)
				}
				if apierr.CodeOf(err) != apierr.CodeInvalidArgument {
					t.Errorf("ConfigSet(%s=%v) code = %v, want invalid_argument", tc.key, bad, apierr.CodeOf(err))
				}
				if !strings.Contains(err.Error(), tc.key) {
					t.Errorf("error %q does not name the field %q", err.Error(), tc.key)
				}
				if got := tc.read(store.Current()); got != was {
					t.Errorf("%s took effect live despite the refusal: %v -> %v", tc.key, was, got)
				}
				after, err := os.ReadFile(statePath)
				if err != nil {
					t.Fatalf("read state file after the refusal: %v", err)
				}
				if string(before) != string(after) {
					t.Errorf("%s=%v was persisted despite the refusal; it would survive a restart", tc.key, bad)
				}
			}

			ts, store, _, _ := newFileBackedToolService(t, "")
			if _, err := ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
				Key: tc.key, Value: tc.valid,
			}); err != nil {
				t.Fatalf("ConfigSet(%s=%v): %v -- the bound must be a FLOOR, not a refusal of the key",
					tc.key, tc.valid, err)
			}
			if got, want := tc.read(store.Current()), int64(tc.valid.(float64)); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("%s = %v after a valid ConfigSet, want %v", tc.key, got, want)
			}
		})
	}
}

// TestConfigSetRejectsANonPositiveRetention is artifact.retention's own row:
// a duration key, so it takes a duration string rather than a number, but the
// floor is the same one every other curated limit above gets.
func TestConfigSetRejectsANonPositiveRetention(t *testing.T) {
	for _, bad := range []string{"0s", "-1h"} {
		ts, store, _, _ := newFileBackedToolService(t, "")
		was := store.Current().Artifact.Retention
		_, err := ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
			Key: "artifact.retention", Value: bad,
		})
		if err == nil {
			t.Fatalf("ConfigSet(artifact.retention=%s) succeeded; a non-positive retention discards every artifact", bad)
		}
		if apierr.CodeOf(err) != apierr.CodeInvalidArgument {
			t.Errorf("code = %v, want invalid_argument", apierr.CodeOf(err))
		}
		if got := store.Current().Artifact.Retention; got != was {
			t.Errorf("artifact.retention took effect despite the refusal: %v -> %v", was, got)
		}
	}

	ts, store, _, _ := newFileBackedToolService(t, "")
	if _, err := ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
		Key: "artifact.retention", Value: "12h",
	}); err != nil {
		t.Fatalf("ConfigSet(artifact.retention=12h): %v", err)
	}
	if got := store.Current().Artifact.Retention.Duration(); got != 12*time.Hour {
		t.Errorf("artifact.retention = %v, want 12h", got)
	}
}

// TestConfigSetDestinationLists is destinations.allow / destinations.deny's
// own coverage — the two most security-weighted keys in the curated config_set
// whitelist (they gate which destinations a call may be placed to) and the only
// LIST-shaped ones, so they are also the sole users of configStringSlice, which
// had no test of either its happy path or its refusal.
//
// Each key is driven twice: a valid array of patterns must take effect BOTH
// live and in the state file (a change that survives the restart it is meant
// to), and a value that is not an array of strings must be refused with
// invalid_argument NAMING the key, with neither the live policy nor the state
// file moved.
//
// The patterns are real regexes because policy.resolve() compiles these two
// lists (compilePatterns); an arbitrary string would fail the reload rather
// than the decode and would test the wrong boundary.
//
// Mutation check: drop configStringSlice's `[]any` type assertion (accept any
// value and return nil) and the refusal rows redden; drop the assignment in
// applyConfigKey's destinations.* cases and the happy-path rows redden.
func TestConfigSetDestinationLists(t *testing.T) {
	const pattern = `^sip:.*@lab\.internal$`
	for _, tc := range []struct {
		key  string
		read func(*policy.Policy) []string
	}{
		{"destinations.allow", func(p *policy.Policy) []string { return p.Destinations.Allow }},
		{"destinations.deny", func(p *policy.Policy) []string { return p.Destinations.Deny }},
	} {
		t.Run(tc.key+"/valid array", func(t *testing.T) {
			ts, store, statePath, _ := newFileBackedToolService(t, "")
			if _, err := ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
				Key: tc.key, Value: []any{pattern},
			}); err != nil {
				t.Fatalf("ConfigSet(%s): %v", tc.key, err)
			}
			got := tc.read(store.Current())
			if len(got) != 1 || got[0] != pattern {
				t.Errorf("Current() %s = %v, want [%s]", tc.key, got, pattern)
			}
			onDisk, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatalf("read state file: %v", err)
			}
			if !strings.Contains(string(onDisk), pattern) {
				t.Errorf("the state file does not carry the new %s; the change would not "+
					"survive a restart:\n%s", tc.key, onDisk)
			}
		})

		for _, bad := range []struct {
			name  string
			value any
		}{
			{"a bare string", "sip:anyone@anywhere.example"},
			{"a number", float64(7)},
			{"an array holding a non-string", []any{pattern, float64(7)}},
		} {
			t.Run(tc.key+"/rejects "+bad.name, func(t *testing.T) {
				ts, store, statePath, _ := newFileBackedToolService(t, "")
				before, err := os.ReadFile(statePath)
				if err != nil {
					t.Fatalf("read state file: %v", err)
				}
				was := tc.read(store.Current())

				_, err = ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
					Key: tc.key, Value: bad.value,
				})
				if err == nil {
					t.Fatalf("ConfigSet(%s=%v) succeeded, want a refusal — %s is not an "+
						"array of strings", tc.key, bad.value, bad.name)
				}
				if apierr.CodeOf(err) != apierr.CodeInvalidArgument {
					t.Errorf("code = %v, want invalid_argument", apierr.CodeOf(err))
				}
				if !strings.Contains(err.Error(), tc.key) {
					t.Errorf("error %q does not name the field %q — with two list keys sharing "+
						"one decoder, the operator cannot tell which list was refused",
						err.Error(), tc.key)
				}
				if got := tc.read(store.Current()); len(got) != len(was) {
					t.Errorf("%s took effect live despite the refusal: %v -> %v", tc.key, was, got)
				}
				after, err := os.ReadFile(statePath)
				if err != nil {
					t.Fatalf("read state file after the refusal: %v", err)
				}
				if string(before) != string(after) {
					t.Errorf("%s was persisted despite the refusal; it would survive a restart", tc.key)
				}
			})
		}
	}
}

func TestConfigSetUnknownKeyIsInvalidArgument(t *testing.T) {
	ts, _, _, _ := newFileBackedToolService(t, "")
	_, err := ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
		Key: "auth.bearer_token_file", Value: "/etc/passwd",
	})
	if err == nil {
		t.Fatal("want ConfigSet on a non-whitelisted key to fail, got nil")
	}
	if apierr.CodeOf(err) != apierr.CodeInvalidArgument {
		t.Errorf("code = %v, want invalid_argument", apierr.CodeOf(err))
	}
}

// TestConfigSetConcurrentDistinctKeysBothPresent (-race): two goroutines
// each ConfigSet a distinct key; both must be present afterward, which
// holds only because both route through Store.Mutate's single serialised
// path.
func TestConfigSetConcurrentDistinctKeysBothPresent(t *testing.T) {
	ts, store, _, _ := newFileBackedToolService(t, "")
	var wg sync.WaitGroup
	wg.Add(2)
	var err1, err2 error
	go func() {
		defer wg.Done()
		_, err1 = ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
			Key: "limits.max_uas_total", Value: float64(300),
		})
	}()
	go func() {
		defer wg.Done()
		_, err2 = ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
			Key: "limits.max_sessions_total", Value: float64(2000),
		})
	}()
	wg.Wait()
	if err1 != nil {
		t.Errorf("ConfigSet #1: %v", err1)
	}
	if err2 != nil {
		t.Errorf("ConfigSet #2: %v", err2)
	}
	if got := store.Current().Limits.MaxUAsTotal; got != 300 {
		t.Errorf("Limits.MaxUAsTotal = %d, want 300", got)
	}
	if got := store.Current().Limits.MaxSessionsTotal; got != 2000 {
		t.Errorf("Limits.MaxSessionsTotal = %d, want 2000", got)
	}
}

// TestConfigSetDoesNotDeadlock ([R5-2]-style no-deadlock test): issued on
// its own goroutine so the test FAILS on its own timeout rather than
// hanging the suite if ConfigSet -> Store.Mutate ever took reloadMu twice.
func TestConfigSetDoesNotDeadlock(t *testing.T) {
	ts, _, _, _ := newFileBackedToolService(t, "")
	done := make(chan error, 1)
	go func() {
		_, err := ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
			Key: "limits.max_uas_total", Value: float64(260),
		})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ConfigSet: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ConfigSet did not return within 5s")
	}
}

func TestAdminTokenRotateChangesAuthentication(t *testing.T) {
	ts, store, _, _ := newFileBackedToolService(t, "old-admin-token")
	if !store.Current().MatchesAdminToken([]byte("old-admin-token")) {
		t.Fatal("precondition: the configured admin token must match before rotation")
	}

	out, err := ts.AdminTokenRotate(context.Background(), "sess", AdminTokenRotateInput{})
	if err != nil {
		t.Fatalf("AdminTokenRotate: %v", err)
	}
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("AdminTokenRotate returned %T, want map[string]any", out)
	}
	newTok, ok := m["admin_token"].(string)
	if !ok || newTok == "" {
		t.Fatalf("AdminTokenRotate response missing admin_token: %+v", m)
	}
	if len(newTok) != 64 {
		t.Errorf("new admin token is %d hex chars, want 64 (256 bits)", len(newTok))
	}

	if store.Current().MatchesAdminToken([]byte("old-admin-token")) {
		t.Error("the OLD admin token still authenticates after rotation")
	}
	if !store.Current().MatchesAdminToken([]byte(newTok)) {
		t.Error("the NEW admin token does not authenticate right after rotation")
	}
}

func TestAdminTokenRotateWithNoAdminTokenConfiguredIsInvalidArgument(t *testing.T) {
	ts, _, _, _ := newFileBackedToolService(t, "")
	_, err := ts.AdminTokenRotate(context.Background(), "sess", AdminTokenRotateInput{})
	if err == nil {
		t.Fatal("want AdminTokenRotate to fail when no admin token is configured, got nil")
	}
	if apierr.CodeOf(err) != apierr.CodeInvalidArgument {
		t.Errorf("code = %v, want invalid_argument", apierr.CodeOf(err))
	}
}

// TestAdminTokenRotateConcurrentWithConfigSetBothEffectsPresent (-race,
// serialization assertion): a rotation and a config_set fired concurrently
// must BOTH take effect -- this is only true because both route through
// Store.Mutate's one serialised path (§2.3a).
func TestAdminTokenRotateConcurrentWithConfigSetBothEffectsPresent(t *testing.T) {
	ts, store, _, _ := newFileBackedToolService(t, "old-admin-token")

	var wg sync.WaitGroup
	wg.Add(2)
	var rotateErr, setErr error
	var newTok string
	go func() {
		defer wg.Done()
		out, err := ts.AdminTokenRotate(context.Background(), "sess", AdminTokenRotateInput{})
		rotateErr = err
		if err == nil {
			newTok, _ = out.(map[string]any)["admin_token"].(string)
		}
	}()
	go func() {
		defer wg.Done()
		_, setErr = ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
			Key: "limits.max_uas_total", Value: float64(270),
		})
	}()
	wg.Wait()

	if rotateErr != nil {
		t.Fatalf("AdminTokenRotate: %v", rotateErr)
	}
	if setErr != nil {
		t.Fatalf("ConfigSet: %v", setErr)
	}
	if !store.Current().MatchesAdminToken([]byte(newTok)) {
		t.Error("the rotation's effect is missing after the concurrent pair")
	}
	if got := store.Current().Limits.MaxUAsTotal; got != 270 {
		t.Errorf("the config_set's effect is missing after the concurrent pair: MaxUAsTotal = %d, want 270", got)
	}
}

// newSplitDirToolService is newFileBackedToolService with ONE difference: the
// state file and the two token files live in SEPARATE directories. That
// separation is what lets TestAdminTokenRotateIsAtomic make the STATE write
// fail while the token directory stays perfectly writable — with both in one
// directory, staging the new token would fail first and the test would prove
// nothing about ordering.
func newSplitDirToolService(t *testing.T, admin string) (ts *ToolService, stateDir, adminFile string) {
	t.Helper()
	stateDir, tokenDir := t.TempDir(), t.TempDir()
	bearerFile := filepath.Join(tokenDir, "bearer.token")
	if err := os.WriteFile(bearerFile, []byte("test-bearer-token"), 0o600); err != nil {
		t.Fatalf("write bearer token file: %v", err)
	}
	adminFile = filepath.Join(tokenDir, "admin.token")
	if err := os.WriteFile(adminFile, []byte(admin), 0o600); err != nil {
		t.Fatalf("write admin token file: %v", err)
	}
	statePath := filepath.Join(stateDir, "policy.yaml")
	yaml := "auth:\n  bearer_token_file: " + bearerFile + "\n  admin_token_file: " + adminFile + "\n"
	if err := os.WriteFile(statePath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	fc := newFakeClock()
	s, err := policy.NewStore(statePath, fc, testLogger())
	if err != nil {
		t.Fatalf("policy.NewStore: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: s, Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return NewToolService(m), stateDir, adminFile
}

// TestAdminTokenRotateLeavesTheTokenFileUntouchedWhenTheStateWriteFails is
// SEC-1's regression pin: a rotation that cannot complete must leave the
// admin token FILE exactly as it was.
//
// THE BUG IT PINS — the token file used to be overwritten inside the closure
// Store.Mutate runs, i.e. BEFORE Mutate's validate / state-file write /
// reload. When one of those three failed, AdminTokenRotate returned an error
// and threw the new token away, but disk already held it while the in-memory
// digest still matched the OLD one. Nothing looked wrong until the next
// restart, which then read a token that had never been returned to anyone:
// the admin plane locked out permanently, with no way back in short of shell
// access to the token file.
//
// The induced failure is a read-only STATE directory, which fails
// policy.WriteFile's own temp-file creation. The token directory is separate
// and stays writable, so staging the replacement succeeds and the only reason
// the file could change is the ordering under test.
//
// Mutation check: restore the ORIGINAL shape — stage and rename from inside
// MutateWithCommit's fn argument (where the write used to live) AND drop the
// rollback closure the commit hook returns — and this test reddens with the
// file holding the new token. Both halves are needed to redden it, which is
// the point: the rollback is a second line of defence behind the ordering,
// not a substitute for it.
func TestAdminTokenRotateLeavesTheTokenFileUntouchedWhenTheStateWriteFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a 0500 directory is still writable, so the induced failure cannot be induced")
	}
	const original = "the-original-admin-token"
	ts, stateDir, adminFile := newSplitDirToolService(t, original)

	if err := os.Chmod(stateDir, 0o500); err != nil {
		t.Fatalf("chmod state dir read-only: %v", err)
	}
	// Restore before TempDir's own cleanup, which cannot remove a file from a
	// directory it may not write to.
	t.Cleanup(func() { _ = os.Chmod(stateDir, 0o700) })

	out, err := ts.AdminTokenRotate(context.Background(), "sess", AdminTokenRotateInput{})
	if err == nil {
		t.Fatalf("AdminTokenRotate succeeded with an unwritable state directory; want an error (out=%+v)", out)
	}
	if out != nil {
		t.Fatalf("AdminTokenRotate returned a payload alongside its error: %+v", out)
	}

	got, rerr := os.ReadFile(adminFile)
	if rerr != nil {
		t.Fatalf("read admin token file after the failed rotation: %v", rerr)
	}
	if string(got) != original {
		t.Fatalf("admin token file = %q after a FAILED rotation, want the original %q unchanged — "+
			"a partially applied rotation locks the admin plane out at the next restart",
			got, original)
	}
}

// TestAdminTokenRotateRollsBackTheTokenFileWhenTheReloadFails covers SEC-1's
// other half: the one window Commit cannot make atomic. The rename has
// already landed when the reload fails, so AdminTokenRotate must actively put
// the old bytes back rather than return an error over a file it has already
// changed.
//
// The induced failure is the BEARER token file disappearing: the state file
// writes fine, the commit renames fine, and then reloadLocked's Load fails in
// resolve() because auth.bearer_token_file no longer exists.
//
// Mutation check: return a nil rollback closure from the commit hook (or
// delete MutateWithCommit's `if rollback != nil` branch) and this test
// reddens.
func TestAdminTokenRotateRollsBackTheTokenFileWhenTheReloadFails(t *testing.T) {
	const original = "the-original-admin-token"
	ts, _, adminFile := newSplitDirToolService(t, original)

	// Same directory as adminFile, by construction in newSplitDirToolService.
	bearerFile := filepath.Join(filepath.Dir(adminFile), "bearer.token")
	if err := os.Remove(bearerFile); err != nil {
		t.Fatalf("remove bearer token file to induce a reload failure: %v", err)
	}

	if _, err := ts.AdminTokenRotate(context.Background(), "sess", AdminTokenRotateInput{}); err == nil {
		t.Fatal("AdminTokenRotate succeeded although the reload could not load the policy back; want an error")
	}

	got, rerr := os.ReadFile(adminFile)
	if rerr != nil {
		t.Fatalf("read admin token file after the failed rotation: %v", rerr)
	}
	if string(got) != original {
		t.Fatalf("admin token file = %q after a rotation whose reload failed, want the original %q "+
			"restored — the returned error says the rotation did not happen, so disk must agree",
			got, original)
	}
}

// TestConfigSetRollsBackTheStateFileWhenTheReloadFails is the GENERAL-PATH
// twin of TestAdminTokenRotateRollsBackTheTokenFileWhenTheReloadFails above:
// the same failure class, on a plain config_set rather than a rotation.
//
// THE BUG IT PINS — Store.MutateWithCommit wrote the state file through
// policy.WriteFile mid-sequence, i.e. renamed the new YAML into place BEFORE
// the reload had been proven to succeed, and never put it back when the reload
// failed. Reproduced with tls.insecure_skip_verify: config_set returned an
// error and Current() still said false, while the state file on disk already
// said true — so the next restart, or the next SIGHUP that happened to
// succeed, silently applied a change the caller had been told did not happen.
// Mutate's and MutateWithCommit's own doc comments promised the opposite
// ("on any failure ... the previous state file is left byte-identical").
//
// The induced failure is the same one the rotation test uses: the BEARER token
// file disappears, so reloadLocked's Load fails in resolve().
//
// Mutation check (verified): put the state-file write back before the reload
// (call policy.WriteFile where StageFile/Commit now sit, and drop the
// staged.Rollback on the reload-failure path) and this test reddens with the
// state file holding insecure_skip_verify: true.
func TestConfigSetRollsBackTheStateFileWhenTheReloadFails(t *testing.T) {
	ts, store, statePath, _ := newFileBackedToolService(t, "")

	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state file before ConfigSet: %v", err)
	}

	// Same directory as the state file, by construction in
	// newFileBackedToolService.
	bearerFile := filepath.Join(filepath.Dir(statePath), "bearer.token")
	if err := os.Remove(bearerFile); err != nil {
		t.Fatalf("remove bearer token file to induce a reload failure: %v", err)
	}

	if _, err := ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
		Key: "tls.insecure_skip_verify", Value: true,
	}); err == nil {
		t.Fatal("ConfigSet succeeded although the reload could not load the policy back; want an error")
	}

	if store.Current().TLS.InsecureSkipVerify {
		t.Error("Current().TLS.InsecureSkipVerify = true after a FAILED ConfigSet; nothing may be swapped")
	}

	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state file after the failed ConfigSet: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("state file changed after a ConfigSet whose reload failed — the caller was told the "+
			"change did not happen, so disk must agree.\nbefore: %s\nafter:  %s", before, after)
	}
}

// ---- SEC-3: stage / commit / rollback must be serialised ---------------------

// waitForStagedSecrets blocks until dir holds at least want staged-secret temp
// files (policy.StageSecretFile's ".tmp-*"), or until deadline elapses.
//
// It is how the SEC-3 test below opens the pre-fix race window from OUTSIDE
// the package under test. Under the BROKEN shape staging ran before
// MutateWithCommit took reloadMu, so both rotations write their temp file
// while a third writer holds the lock — and the temp files are the only
// externally visible evidence that both have captured the token file's
// "previous" bytes. Under the FIXED shape staging happens INSIDE the lock, no
// temp file can appear while the lock is held, and this simply waits out its
// deadline; the rotations then run serialised, which is the whole point.
func waitForStagedSecrets(t *testing.T, dir string, want int, deadline time.Duration) {
	t.Helper()
	until := time.Now().Add(deadline)
	for {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read the token directory while waiting for staged secrets: %v", err)
		}
		n := 0
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".tmp-") {
				n++
			}
		}
		if n >= want || !time.Now().Before(until) {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// TestAdminTokenRotateConcurrentRotationsNeverReviveARevokedToken is SEC-3's
// regression pin, and it pins BOTH reproduced races because both have the
// same observable signature: the admin token FILE and the LIVE digest stop
// agreeing the instant a rollback writes the file outside the reloadMu hold
// that computed that digest.
//
// THE BUG IT PINS. AdminTokenRotate used to call policy.StageSecretFile —
// which CAPTURES the token file's current bytes — before Store.MutateWithCommit
// took reloadMu, and to run staged.Rollback() after MutateWithCommit had
// already released it. So:
//
//	(a) two rotations could both capture the SAME "previous" bytes; whichever
//	    one's reload failed then wrote those bytes back over the other one's
//	    committed token, REVIVING a credential that had just been deliberately
//	    revoked — privilege restoration, not merely a lockout;
//	(b) a rotation whose own reload failed could have its late rollback land
//	    after a concurrent config_set or SIGHUP had already reloaded from the
//	    file it committed, so the live digest and the file disagreed
//	    immediately rather than only at the next restart.
//
// HOW THE WINDOW IS FORCED OPEN, deterministically rather than by hammering:
// a reload hook holds reloadMu while both rotations queue up behind it (the
// broken shape stages during exactly that window — waitForStagedSecrets sees
// it), and the SECOND hook invocation — the winning rotation's own reload —
// deletes the bearer token file, so the losing rotation's reload is the one
// step left that can still fail and it takes the rollback path every time.
//
// Mutation check (verified): move policy.StageSecretFile back out of the
// commit hook to before the MutateWithCommit call, and run staged.Rollback()
// on MutateWithCommit's error return instead of handing the undo closure
// back. This test then reddens on the revived original token.
func TestAdminTokenRotateConcurrentRotationsNeverReviveARevokedToken(t *testing.T) {
	const original = "the-original-admin-token"
	ts, store, statePath, adminFile := newFileBackedToolService(t, original)
	dir := filepath.Dir(statePath)
	bearerFile := filepath.Join(dir, "bearer.token")

	var (
		reloadHeld = make(chan struct{})
		release    = make(chan struct{})
		reloads    atomic.Int32
	)
	// The hook runs UNDER reloadMu (see policy.SetReloadHook). Blocking in it
	// is exactly what SetReloadHook's contract forbids a PRODUCTION hook from
	// doing; here it is the instrument, and the block is bounded by the
	// close(release) below.
	store.SetReloadHook(func(_, _ *policy.Policy) {
		switch reloads.Add(1) {
		case 1:
			close(reloadHeld)
			<-release
		case 2:
			// The rotation that won the lock has just installed its token and
			// recomputed the digest from it. Take the bearer token file away
			// so the loser's reload -- the only step it has left that can
			// still fail -- does fail, putting it on the rollback path.
			if err := os.Remove(bearerFile); err != nil {
				t.Errorf("remove the bearer token file from the reload hook: %v", err)
			}
		}
	})

	var holder sync.WaitGroup
	holder.Add(1)
	go func() {
		defer holder.Done()
		if err := store.Reload(); err != nil {
			t.Errorf("the lock-holding Reload failed: %v", err)
		}
	}()
	<-reloadHeld

	const rotations = 2
	tokens := make([]string, rotations)
	errs := make([]error, rotations)
	var rotators sync.WaitGroup
	rotators.Add(rotations)
	for i := 0; i < rotations; i++ {
		go func(i int) {
			defer rotators.Done()
			out, err := ts.AdminTokenRotate(context.Background(), "sess", AdminTokenRotateInput{})
			errs[i] = err
			if err == nil {
				tokens[i], _ = out.(map[string]any)["admin_token"].(string)
			}
		}(i)
	}
	waitForStagedSecrets(t, dir, rotations, 500*time.Millisecond)
	close(release)
	rotators.Wait()
	holder.Wait()

	winner, successes := "", 0
	for i, err := range errs {
		if err == nil {
			successes++
			winner = tokens[i]
		}
	}
	if successes != 1 {
		t.Fatalf("want exactly one of %d concurrent rotations to succeed (the hook fails the loser's "+
			"reload), got %d; errs=%v", rotations, successes, errs)
	}

	onDisk, err := os.ReadFile(adminFile)
	if err != nil {
		t.Fatalf("read the admin token file after the race: %v", err)
	}
	if string(onDisk) == original {
		t.Fatalf("the admin token file holds the ORIGINAL token %q again after a rotation had already "+
			"committed and installed %q — the losing rotation's rollback wrote back a snapshot it "+
			"captured before the winner moved the file forward, reviving a revoked credential",
			original, winner)
	}
	if string(onDisk) != winner {
		t.Fatalf("the admin token file holds %q, want the winning rotation's token %q — only the "+
			"winner committed without rolling back, so nothing else may be on disk", onDisk, winner)
	}
	if !store.Current().MatchesAdminToken(onDisk) {
		t.Fatalf("the admin token FILE (%q) does not authenticate against the LIVE policy digest: the "+
			"daemon accepts one token and the next restart will read a different one", onDisk)
	}
}

// TestAdminTokenRotateConcurrentWithConfigSetAndReload is the same invariant
// under the OTHER writer mix SEC-3 named: one rotation racing a config_set and
// a bare Store.Reload (the SIGHUP goroutine's own entry point), all three
// contending for reloadMu at once.
//
// Its job is the -race detector and the "whatever the interleaving, the file
// and the digest agree when the dust settles" check. The behavioural pin for
// the rollback ordering itself is the deterministic test above; this one
// covers the three-writer mix that test deliberately does not reproduce.
func TestAdminTokenRotateConcurrentWithConfigSetAndReload(t *testing.T) {
	const original = "the-original-admin-token"
	ts, store, _, adminFile := newFileBackedToolService(t, original)

	const rounds = 25
	var wg sync.WaitGroup
	var rotated atomic.Int32
	wg.Add(3)
	go func() {
		defer wg.Done()
		for r := 0; r < rounds; r++ {
			if _, err := ts.AdminTokenRotate(context.Background(), "sess", AdminTokenRotateInput{}); err != nil {
				t.Errorf("AdminTokenRotate: %v", err)
				return
			}
			rotated.Add(1)
		}
	}()
	go func() {
		defer wg.Done()
		for r := 0; r < rounds; r++ {
			if _, err := ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
				Key: "limits.max_uas_total", Value: float64(200 + r),
			}); err != nil {
				t.Errorf("ConfigSet: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for r := 0; r < rounds; r++ {
			if err := store.Reload(); err != nil {
				t.Errorf("Reload: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	if got := rotated.Load(); got != rounds {
		t.Fatalf("only %d of %d rotations completed", got, rounds)
	}
	onDisk, err := os.ReadFile(adminFile)
	if err != nil {
		t.Fatalf("read the admin token file after the race: %v", err)
	}
	if string(onDisk) == original {
		t.Fatalf("the admin token file still holds the ORIGINAL token after %d rotations", rotated.Load())
	}
	if !store.Current().MatchesAdminToken(onDisk) {
		t.Fatalf("the admin token FILE (%q) does not authenticate against the LIVE policy digest", onDisk)
	}
}

func TestConfigGetReportsMaxRedirects(t *testing.T) {
	ts, _, _, _ := newFileBackedToolService(t, "")
	out, err := ts.ConfigGet(context.Background(), "sess", ConfigGetInput{})
	if err != nil {
		t.Fatalf("ConfigGet: %v", err)
	}
	limits := out.(map[string]any)["limits"].(map[string]any)
	if got := limits["max_redirects"]; got != 3 {
		t.Errorf("limits[max_redirects] = %v, want 3", got)
	}
}

func TestConfigSetMaxRedirects(t *testing.T) {
	ts, store, statePath, _ := newFileBackedToolService(t, "")
	for _, v := range []int{0, 2} {
		if _, err := ts.ConfigSet(context.Background(), "sess", ConfigSetInput{
			Key: "limits.max_redirects", Value: float64(v),
		}); err != nil {
			t.Fatalf("ConfigSet %d: %v", v, err)
		}
		if got := store.Current().Limits.MaxRedirects; got != v {
			t.Errorf("Current().Limits.MaxRedirects = %d, want %d", got, v)
		}
		out, _ := ts.ConfigGet(context.Background(), "sess", ConfigGetInput{})
		if got := out.(map[string]any)["limits"].(map[string]any)["max_redirects"]; got != v {
			t.Errorf("config_get max_redirects = %v, want %d", got, v)
		}
		raw, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatalf("read state file: %v", err)
		}
		if want := fmt.Sprintf("max_redirects: %d", v); !strings.Contains(string(raw), want) {
			t.Errorf("state file lacks %q:\n%s", want, raw)
		}
	}
}

func TestConfigSetMaxRedirectsRejectsBadValues(t *testing.T) {
	for _, v := range []any{float64(-1), float64(11), 2.5, "3", true} {
		t.Run(fmt.Sprintf("%v", v), func(t *testing.T) {
			ts, _, statePath, _ := newFileBackedToolService(t, "")
			before, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatalf("read state file: %v", err)
			}
			_, err = ts.ConfigSet(context.Background(), "sess", ConfigSetInput{Key: "limits.max_redirects", Value: v})
			var ae *apierr.Error
			if err == nil || !errors.As(err, &ae) || ae.Code != apierr.CodeInvalidArgument {
				t.Fatalf("err = %v, want invalid_argument", err)
			}
			after, _ := os.ReadFile(statePath)
			if string(before) != string(after) {
				t.Error("state file changed after a rejected ConfigSet")
			}
		})
	}
}
