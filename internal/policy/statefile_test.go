package policy

import (
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// TestStateFileRollbackStagesUnderTheStateNamingNotTheSecretOne pins the
// naming split StagedFile documents: ".tmp-*" is a staged SECRET,
// ".policy-*.yaml.tmp" a staged STATE file, and each kind of file stays on its
// own convention in BOTH directions.
//
// THE BUG IT PINS. Rollback used to restore every staged file through
// WriteSecretFile, so rolling a STATE file back transiently created a ".tmp-*"
// entry in the state directory. internal/session's config_test.go polls that
// directory for exactly that prefix to detect an in-flight SECRET staging
// (waitForStagedSecrets), so an unrelated state-file rollback in the same
// directory could satisfy that wait and let
// TestAdminTokenRotateConcurrentRotationsNeverReviveARevokedToken pass without
// the race window it means to open ever having opened.
//
// HOW THE TRANSIENT NAME IS OBSERVED. The temp file is renamed away (or
// removed) before Rollback returns, so it cannot be caught by listing the
// directory afterwards. Making the directory unwritable instead makes the
// os.CreateTemp inside the restore fail, and the resulting *fs.PathError names
// the exact temp path it tried to create — the naming convention made
// observable, deterministically.
//
// MUTATION CHECK (verified): change Rollback back to
// WriteSecretFile(s.path, string(s.prev)) and the error names a ".tmp-" file,
// reddening this test.
func TestStateFileRollbackStagesUnderTheStateNamingNotTheSecretOne(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod-based unwritable-dir probe is a no-op as root")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	original := "limits:\n  max_uas_total: 7\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("write state file: %v", err)
	}

	next := Defaults()
	next.Limits.MaxUAsTotal = 250
	staged, err := StageFile(path, next)
	if err != nil {
		t.Fatalf("StageFile: %v", err)
	}

	// While staged, the replacement wears the STATE convention — nothing in
	// the directory looks like a staged secret.
	for _, name := range entryNames(t, dir) {
		if strings.HasPrefix(name, ".tmp-") {
			t.Errorf("StageFile created %q, a staged-SECRET name; state files stage as %q",
				name, stateTempPattern)
		}
	}

	if err := staged.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// The restore write goes through the same convention. Provoke it into
	// failing so the attempted temp name surfaces in the error.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod state dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	rbErr := staged.Rollback()
	if rbErr == nil {
		t.Fatal("Rollback succeeded into a read-only directory, want the temp-file " +
			"creation to fail — this test's premise")
	}
	var pathErr *fs.PathError
	if !errors.As(rbErr, &pathErr) {
		t.Fatalf("Rollback error %v does not wrap a *fs.PathError naming the temp file it "+
			"tried to create; this test cannot observe the naming convention without it", rbErr)
	}
	tmpName := filepath.Base(pathErr.Path)
	if strings.HasPrefix(tmpName, ".tmp-") {
		t.Errorf("rolling back a STATE file created %q, a staged-SECRET name — "+
			"internal/session's waitForStagedSecrets reads that prefix as an in-flight "+
			"secret staging and would false-positive on this", tmpName)
	}
	if !strings.HasPrefix(tmpName, ".policy-") || !strings.HasSuffix(tmpName, ".yaml.tmp") {
		t.Errorf("rolling back a STATE file created %q, want the %q convention",
			tmpName, stateTempPattern)
	}

	// And the ordinary (writable) restore really does put the original bytes
	// back — the naming fix must not have changed what Rollback does.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod state dir back: %v", err)
	}
	if err := staged.Rollback(); err != nil {
		t.Fatalf("Rollback into a writable directory: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state file after Rollback: %v", err)
	}
	if string(got) != original {
		t.Errorf("state file after Rollback = %q, want the original %q", got, original)
	}
	for _, name := range entryNames(t, dir) {
		if strings.HasPrefix(name, ".tmp-") || strings.HasSuffix(name, ".yaml.tmp") {
			t.Errorf("Rollback left temp residue %q in the state directory", name)
		}
	}
}

// TestStagedSecretsStillStageUnderTheSecretNaming is the other half of the
// split: the token file's own staging is unchanged by the state file's fix, so
// internal/session's waitForStagedSecrets still sees what it is waiting for.
func TestStagedSecretsStillStageUnderTheSecretNaming(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.token")
	if err := os.WriteFile(path, []byte("old-token"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	staged, err := StageSecretFile(path, "new-token")
	if err != nil {
		t.Fatalf("StageSecretFile: %v", err)
	}
	defer staged.Discard()

	var found int
	for _, name := range entryNames(t, dir) {
		if strings.HasPrefix(name, ".tmp-") {
			found++
		}
	}
	if found != 1 {
		t.Errorf("staged-secret temp files in %s = %d, want 1 — waitForStagedSecrets "+
			"polls for exactly this", dir, found)
	}
}

// entryNames lists dir's entry names, temp files included.
func entryNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// TestMutateRollbackOfAVanishedStateFileDeletesItLogsAndStaysFailed pins the
// !prevExisted half of Store.undo — the branch that DELETES the state file and
// logs policy_state_file_missing_before_mutation at ERROR.
//
// It is one half of the fail-open combination the conservative lastFailed rule
// closed: a daemon whose state file has vanished comes back up on Defaults()
// after a restart, and Defaults() ships an EMPTY destinations.allow, which
// CheckDestination reads as allow-everything. The ERROR line is the only thing
// saying so, and the flag staying set is the only thing keeping /readyz from
// reporting ready over it (see internal/transport/mcp's readyz rollback suite
// for the /readyz-facing half).
//
// THE SCENARIO. The state file goes missing out from under a running Store,
// and the file its reload depends on (auth.bearer_token_file) goes with it.
// The mutation stages beside the absent path, commits, then fails its own
// reload — and the faithful restore of "there was nothing here" is a delete.
//
// MUTATION CHECK (verified): drop the s.log.Error call in Store.undo and the
// log assertion reddens; make undo skip Rollback when !prevExisted and the
// os.Stat assertion reddens.
func TestMutateRollbackOfAVanishedStateFileDeletesItLogsAndStaysFailed(t *testing.T) {
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "bearer.token")
	if err := os.WriteFile(tokPath, []byte("bearer-token-value\n"), 0o600); err != nil {
		t.Fatalf("write bearer token file: %v", err)
	}
	statePath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(statePath, []byte("auth:\n  bearer_token_file: "+tokPath+"\n"), 0o600); err != nil {
		t.Fatalf("write state file: %v", err)
	}

	var logs bytes.Buffer
	s, err := NewStore(statePath, fakeclock.New(epoch), slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s.LastReloadFailed() {
		t.Fatal("LastReloadFailed() = true on a freshly loaded store, want false")
	}

	// Both disappearances at once: the state file itself (so the staging finds
	// nothing to capture) and the external file its reload needs (so the
	// reload after the commit fails).
	if err := os.Remove(statePath); err != nil {
		t.Fatalf("remove state file: %v", err)
	}
	if err := os.Remove(tokPath); err != nil {
		t.Fatalf("remove bearer token file: %v", err)
	}

	mutErr := s.Mutate(func(cur *Policy) error {
		cur.Limits.MaxUAsTotal = 250
		return nil
	})
	if mutErr == nil {
		t.Fatal("Mutate succeeded with auth.bearer_token_file missing, want the " +
			"internal reload to fail — this test's premise")
	}

	if _, statErr := os.Stat(statePath); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("os.Stat(%s) = %v after the rollback, want fs.ErrNotExist — restoring "+
			"\"there was no file\" means deleting the one the commit installed", statePath, statErr)
	}
	if got := logs.String(); !strings.Contains(got, "policy_state_file_missing_before_mutation") {
		t.Errorf("no policy_state_file_missing_before_mutation line was logged; a daemon that "+
			"has lost its state file restarts on Defaults(), whose empty destinations.allow "+
			"is allow-everything, and this line is the only warning. logs:\n%s", got)
	}
	if got := logs.String(); !strings.Contains(got, `"level":"ERROR"`) {
		t.Errorf("the missing-state-file line was not logged at ERROR. logs:\n%s", got)
	}
	if !s.LastReloadFailed() {
		t.Error("LastReloadFailed() = false after a mutation whose reload failed and whose " +
			"rollback deleted the state file, want true — this is the fail-open case the " +
			"conservative rule exists for")
	}
}
