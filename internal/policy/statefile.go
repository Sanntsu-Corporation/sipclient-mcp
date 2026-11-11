package policy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// GenerateToken returns a fresh 256-bit CSPRNG token, hex-encoded to 64
// characters. It is the ONE generator for every minted credential in this
// tree (Rule 16/18): cmd/sipclient-mcpd's first-run bootstrap (bearer and
// admin tokens) and session.ToolService's admin_token_rotate both call this
// rather than each declaring its own crypto/rand.Read call — one
// implementation to review for the "never truncate, never fall back to a
// weaker source" property every credential here depends on.
//
// It deliberately does NOT reuse internal/transport/mcp's newSessionID: that
// generator is 128 bits (session ids are not secrets an offline attacker
// gains anything from guessing faster; a bearer/admin token is), and this
// package cannot import internal/transport/mcp without inverting the layer
// boundary session/transport already depend on policy across, not the other
// way around.
func GenerateToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("policy: generate token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// The two temp-file naming conventions this package stages under. They stay
// DISTINCT, and each kind of file stays on its own one in every direction
// (stage, commit AND rollback), because the name is the only thing telling an
// outside observer which kind of write is in flight: internal/session's
// config_test.go waits for ".tmp-*" entries in the token directory to detect an
// in-flight SECRET staging, and a state-file write transiently wearing that
// name would make that wait fire on an unrelated event.
const (
	secretTempPattern = ".tmp-*"
	stateTempPattern  = ".policy-*.yaml.tmp"
)

// WriteSecretFile atomically writes value to path at mode 0600: a temp file
// in the same directory (so the rename is same-filesystem and therefore
// atomic), fsync'd close, then rename. Used for the bearer/admin token files
// (first-run mint, admin_token_rotate) — anywhere a single secret value, not
// a whole Policy, needs to land on disk without a reader ever observing a
// half-written file.
func WriteSecretFile(path, value string) error {
	return writeAtomic(path, secretTempPattern, []byte(value))
}

// writeAtomic is WriteSecretFile's body with the temp-name pattern made a
// parameter, so StagedFile.Rollback can restore a STATE file through the same
// write-then-rename without borrowing the secret naming convention (Rule 18).
func writeAtomic(path, pattern string, data []byte) error {
	tmpName, err := writeTempFile(path, pattern, data)
	if err != nil {
		return err
	}
	// Removing an already-renamed temp name is a harmless no-op (the file at
	// tmpName no longer exists); this only fires on the error path below.
	defer func() { _ = os.Remove(tmpName) }()
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("policy: rename temp file into %s: %w", path, err)
	}
	return nil
}

// writeTempFile writes data to a fresh 0600 temp file in path's own directory
// (so a later rename onto path is same-filesystem and therefore atomic) and
// returns that temp file's name. It is the one create/chmod/write/close dance
// in this package (Rule 18); the pattern is a parameter because the two kinds
// of temp file are told apart by it — see secretTempPattern/stateTempPattern.
func writeTempFile(path, pattern string, data []byte) (string, error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("policy: create temp file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("policy: chmod temp file for %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("policy: write temp file for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("policy: close temp file for %s: %w", path, err)
	}
	return tmpName, nil
}

// StagedFile is new content already written to disk beside its final path but
// NOT yet visible under it. It exists so that overwriting a file can be made
// part of a LARGER failure-atomic unit instead of being an irreversible side
// effect fired off before the rest of that unit has been proven to succeed.
//
// IT IS THE ONE STAGE/COMMIT/ROLLBACK MECHANISM IN THIS PACKAGE (Rule 18), AND
// IT HAS TWO USERS: the admin token file (StageSecretFile, for SEC-1 below) and
// the STATE FILE itself (StageFile). The second was added after the first
// shipped: Store.MutateWithCommit wrote the state file straight through
// WriteFile mid-sequence and then reloaded, so a RELOAD failure returned an
// error over a state file that had already been overwritten — the same failure
// class SEC-1 closed for the token file, on the general config path. See
// Store.MutateWithCommit.
//
// THE FAILURE IT CLOSES (SEC-1) — admin_token_rotate used to call
// WriteSecretFile from INSIDE the closure Store.Mutate runs, i.e. before
// Mutate's own validate / state-file write / reload sequence. Any failure in
// those three steps made Mutate return an error and made the rotation "not
// happen" as far as every caller was concerned — but the token FILE had
// already been overwritten with a value nothing would ever return to anyone,
// while the in-memory digest still matched the old token. The daemon kept
// working until the next reload or restart and was then permanently locked
// out of its own admin plane. Splitting the write from the rename makes the
// irreversible half schedulable: stage first, rename only once the steps that
// can still fail have passed, and Rollback if a later one fails anyway.
//
// Exactly one of Commit or Discard must be called; Rollback is for the narrow
// window after a successful Commit.
type StagedFile struct {
	path string
	tmp  string
	// pattern is the temp-name convention this file is staged under
	// (secretTempPattern or stateTempPattern). Rollback reuses it so restoring
	// a state file cannot transiently create a ".tmp-*" entry — the name
	// internal/session's config_test.go reads as an in-flight SECRET staging.
	pattern string
	// prev is path's contents as of the staging call, and prevExisted says
	// whether there was a file to read at all. Rollback restores both.
	prev        []byte
	prevExisted bool
}

// StageSecretFile writes value to a temp file beside path (0600) and captures
// path's current contents, without changing what path itself holds. See
// StagedFile for why this is split from WriteSecretFile.
func StageSecretFile(path, value string) (*StagedFile, error) {
	return stage(path, secretTempPattern, []byte(value))
}

// StageFile is StageSecretFile for a whole Policy: it marshals p exactly as
// WriteFile does and stages the result beside path, so that installing a new
// STATE file can be scheduled — and undone — the same way installing a new
// token file already is. WriteFile is now stage-then-commit over this function
// rather than a second copy of the same steps (Rule 18).
func StageFile(path string, p *Policy) (*StagedFile, error) {
	b, err := yaml.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("policy: marshal: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("policy: create state directory %s: %w", dir, err)
	}
	return stage(path, stateTempPattern, b)
}

// stage is the shared body of StageSecretFile and StageFile: capture what path
// holds now, then write the replacement beside it.
func stage(path, pattern string, data []byte) (*StagedFile, error) {
	prev, err := os.ReadFile(path)
	prevExisted := true
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		prev, prevExisted = nil, false
	default:
		return nil, fmt.Errorf("policy: read current %s before staging a replacement: %w", path, err)
	}
	tmpName, err := writeTempFile(path, pattern, data)
	if err != nil {
		return nil, err
	}
	return &StagedFile{path: path, tmp: tmpName, pattern: pattern, prev: prev, prevExisted: prevExisted}, nil
}

// Commit renames the staged content into place. This is the irreversible step;
// after it returns nil, path holds the new value.
func (s *StagedFile) Commit() error {
	if err := os.Rename(s.tmp, s.path); err != nil {
		return fmt.Errorf("policy: rename staged file into %s: %w", s.path, err)
	}
	s.tmp = ""
	return nil
}

// Discard removes the staged temp file, leaving path untouched. It is safe to
// call after Commit (where it is a no-op) so callers can defer it
// unconditionally.
func (s *StagedFile) Discard() {
	if s.tmp != "" {
		_ = os.Remove(s.tmp)
		s.tmp = ""
	}
}

// Rollback puts path back to exactly the bytes it held when the staging call
// ran — for the one window Commit cannot make atomic, where a step AFTER the
// rename fails and the change as a whole must be reported as not having
// happened.
//
// WHEN THERE WAS NO FILE AT ALL, "PUT IT BACK" MEANS DELETE IT (the
// !prevExisted branch). That is the faithful restore, and it is deliberately
// unchanged — but for the STATE file it is also an anomaly worth shouting
// about, since Store cannot have been constructed without loading that file:
// Store.undo logs it at ERROR before calling this, where the injected logger
// and the path's meaning are both in scope. This type has no logger of its own
// and is not being given one for a condition only one of its two users can
// meaningfully report.
//
// THE RESTORE WRITE REUSES THE PATTERN THIS FILE WAS STAGED UNDER, not
// WriteSecretFile's: rolling a STATE file back used to go through
// WriteSecretFile and so transiently created a ".tmp-*" entry in the state
// directory — the exact name internal/session's config_test.go polls for to
// detect an in-flight SECRET staging, which would have let an unrelated state
// rollback satisfy that wait and silently weaken the admin_token_rotate
// concurrency regression test.
func (s *StagedFile) Rollback() error {
	if !s.prevExisted {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("policy: remove %s while rolling back a staged file: %w", s.path, err)
		}
		return nil
	}
	return writeAtomic(s.path, s.pattern, s.prev)
}

// WriteFile serializes p as YAML to path, atomically (temp file in the same
// directory + rename), at mode 0600 — the state file's own permissions,
// since unlike an operator-authored --policy file this one is written by the
// daemon itself and never needs to be group- or world-readable.
//
// It round-trips against the SAME yaml: tags Load reads (§2.3 of the Phase 2
// design: the state file stays YAML, never JSON — see that section for why
// switching encodings would silently rename every key and break
// wrapRemovedKeyHint, which is written against *yaml.TypeError specifically).
// A value written here and then read back through Load produces a
// field-for-field-equal Policy for every YAML-tagged field; the unexported
// resolved fields (bearerDigests, tlsRootCAs, ...) are never marshalled and
// are recomputed by Load's own resolve() on the way back in, which is the
// correct behaviour, not a gap — they are derived state, not configuration.
//
// It is stage-then-commit over StageFile (Rule 18): the two halves exist
// anyway for Store.MutateWithCommit, which needs the rename schedulable, and a
// caller that only wants the whole write done at once gets both halves back to
// back here.
func WriteFile(path string, p *Policy) error {
	staged, err := StageFile(path, p)
	if err != nil {
		return err
	}
	defer staged.Discard() // a no-op once Commit has renamed the temp away
	return staged.Commit()
}
