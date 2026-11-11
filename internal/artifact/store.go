// Package artifact is the CANONICAL server-side artifact store (Rule 18): the
// one concrete session.ArtifactStore. W2 seeds it minimally — per-call dir,
// file create/close, path<->uri; W5 EXTENDS THIS SAME TYPE with the janitor,
// TTL, high-watermark and the mcp:// resource-URI registry. It is NOT re-homed.
package artifact

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// Store writes artifacts under {dir}/{call_handle}/{name}. W2 has no janitor,
// TTL or watermark (Rule 15); Artifact.MaxBytes is a W5 concern and is NOT read
// here — the per-call pcap byte cap is enforced by the capture engine.
type Store struct {
	dir  string
	clk  clock.Clock
	live LiveCallChecker
}

// New returns a Store rooted at dir, using clk for ArtifactInfo.ClosedAt.
func New(dir string, clk clock.Clock) *Store { return &Store{dir: dir, clk: clk} }

// uriPrefix is the NORMATIVE resource-URI scheme (governing spec §10.12). The
// bytes are also served at GET /artifacts/{h}/{name} (Task 5); that HTTP path
// is a second access route, NOT the canonical uri. W5 keeps this exact string.
const uriPrefix = "mcp://sipclient/artifacts/"

// safeComponent rejects any path.traversal-capable component: empty, ".",
// "..", anything containing a path separator, or a leading dot.
func safeComponent(c string) bool {
	return c != "" && c != "." && c != ".." &&
		!strings.ContainsAny(c, `/\`) && !strings.HasPrefix(c, ".")
}

func (s *Store) callDir(callHandle string) string {
	return filepath.Join(s.dir, callHandle)
}

// OpenCallDir creates the on-disk directory for callHandle's artifacts.
func (s *Store) OpenCallDir(_ context.Context, callHandle string) error {
	if !safeComponent(callHandle) {
		return apierr.InvalidArgument("artifact: invalid call handle")
	}
	return os.MkdirAll(s.callDir(callHandle), 0o700)
}

// Create opens name for writing under callHandle's artifact directory.
func (s *Store) Create(_ context.Context, callHandle, name string) (io.WriteCloser, error) {
	if !safeComponent(callHandle) || !safeComponent(name) {
		return nil, apierr.InvalidArgument("artifact: invalid path")
	}
	if err := os.MkdirAll(s.callDir(callHandle), 0o700); err != nil {
		return nil, err
	}
	// O_EXCL (finding 1a): fail with os.ErrExist rather than truncate an existing
	// artifact — a second capture_start on an already-captured call must not clobber it.
	return os.OpenFile(filepath.Join(s.callDir(callHandle), name),
		os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
}

// Remove deletes a just-created artifact for capture-arm rollback (finding
// NEW-2 residual). Idempotent: a missing file is not an error, so a
// double-rollback or a rollback of a never-created file is harmless — and it
// frees the O_EXCL slot Create holds for a retry.
func (s *Store) Remove(_ context.Context, callHandle, name string) error {
	if !safeComponent(callHandle) || !safeComponent(name) {
		return apierr.InvalidArgument("artifact: invalid path")
	}
	err := os.Remove(filepath.Join(s.callDir(callHandle), name))
	if errors.Is(err, os.ErrNotExist) {
		return nil // idempotent
	}
	return err
}

// Close STATS the artifact and builds its ArtifactInfo (size, uri, closed-at).
// It does NOT close a file descriptor: the pcap io.WriteCloser is owned and
// closed by its holder (the capture engine), not by the store — the fd is
// already closed by the time capture_stop calls this. W5's registry work must
// NOT mistake this for an fd close (Cycle-5 #5).
func (s *Store) Close(_ context.Context, callHandle, name string) (session.ArtifactInfo, error) {
	if !safeComponent(callHandle) || !safeComponent(name) {
		return session.ArtifactInfo{}, apierr.InvalidArgument("artifact: invalid path")
	}
	fi, err := os.Stat(filepath.Join(s.callDir(callHandle), name))
	if err != nil {
		return session.ArtifactInfo{}, err
	}
	return session.ArtifactInfo{
		CallHandle: callHandle, Name: name, URI: s.URI(callHandle, name),
		Bytes: fi.Size(), ClosedAt: s.clk.Now(),
	}, nil
}

// URI returns the NORMATIVE resource URI (governing spec §10.12). It performs
// no I/O and cannot fail (decision 17's stated exception).
func (s *Store) URI(callHandle, name string) string {
	return uriPrefix + callHandle + "/" + name
}

// goneIfMissing classifies a resolution failure: a reclaimed artifact (the
// janitor swept it, §13.5) surfaces as apierr.Gone rather than a bare
// *os.PathError, so callers classify it with apierr.CodeOf like every other
// error. Any other failure passes through unchanged.
func goneIfMissing(callHandle, name string, err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return apierr.Gone("artifact " + callHandle + "/" + name + " has been reclaimed")
	}
	return err
}

// Resolve opens the artifact named by uri for reading.
func (s *Store) Resolve(ctx context.Context, uri string) (session.ArtifactInfo, io.ReadCloser, error) {
	rest := strings.TrimPrefix(uri, uriPrefix)
	if rest == uri {
		return session.ArtifactInfo{}, nil, apierr.InvalidArgument("artifact: not an artifact uri")
	}
	callHandle, name, ok := strings.Cut(path.Clean(rest), "/")
	if !ok || !safeComponent(callHandle) || !safeComponent(name) {
		return session.ArtifactInfo{}, nil, apierr.InvalidArgument("artifact: invalid uri")
	}
	info, err := s.Close(ctx, callHandle, name) // stats + builds info (no mutation)
	if err != nil {
		return session.ArtifactInfo{}, nil, goneIfMissing(callHandle, name, err)
	}
	f, err := os.Open(filepath.Join(s.callDir(callHandle), name))
	if err != nil {
		return session.ArtifactInfo{}, nil, goneIfMissing(callHandle, name, err)
	}
	return info, f, nil
}

// LiveCallChecker reports whether a call is still live, so the janitor never
// reclaims a running test's artifacts (§13.3). Satisfied by session.Manager,
// injected at wiring (the same shape as every session->internal/* collaborator).
type LiveCallChecker interface {
	IsLive(callHandle string) bool
}

// SetLiveCallChecker installs the live-call gate. Nil means "nothing is live"
// (unit tests). Called once at wiring, before the janitor goroutine starts.
func (s *Store) SetLiveCallChecker(c LiveCallChecker) { s.live = c }

func (s *Store) isLive(callHandle string) bool {
	return s.live != nil && s.live.IsLive(callHandle)
}

// artifactEntry is one on-disk artifact seen during a sweep.
type artifactEntry struct {
	call, name string
	path       string
	size       int64
	mtime      time.Time
}

// scan enumerates every artifact under the store root, skipping live-call dirs.
func (s *Store) scan() ([]artifactEntry, error) {
	dirs, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []artifactEntry
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		call := d.Name()
		if s.isLive(call) {
			continue // §13.3: live-call dirs are skipped entirely
		}
		callDir := s.callDir(call)
		files, err := os.ReadDir(callDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			info, err := f.Info()
			if err != nil {
				continue
			}
			out = append(out, artifactEntry{
				call: call, name: f.Name(), path: filepath.Join(callDir, f.Name()),
				size: info.Size(), mtime: info.ModTime(),
			})
		}
	}
	return out, nil
}

// Sweep runs one §13.3 janitor pass: skip live-call dirs, delete artifacts older
// than retention (mtime is close-time here — §4 decision 7), remove empty dirs,
// then evict oldest-mtime-first among non-live artifacts while the tree exceeds
// maxBytes (0 disables the watermark). It logs per §13.3.
func (s *Store) Sweep(_ context.Context, retention time.Duration, maxBytes int64, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	entries, err := s.scan()
	if err != nil {
		log.Warn("janitor: scan failed", "err", err)
		return
	}

	// 1. TTL deletion.
	cutoff := s.clk.Now().Add(-retention)
	var sweptN int
	var sweptBytes int64
	survivors := make([]artifactEntry, 0, len(entries)) // fresh slice; survivors feed the watermark step
	for _, e := range entries {
		if e.mtime.Before(cutoff) {
			if err := os.Remove(e.path); err == nil {
				sweptN++
				sweptBytes += e.size
			}
			continue
		}
		survivors = append(survivors, e)
	}
	dirsRemoved := s.removeEmptyDirs()
	log.Info("janitor: swept",
		"artifacts", sweptN, "bytes", sweptBytes, "dirs", dirsRemoved)

	// 2. High-watermark eviction over the survivors (all non-live by scan()).
	if maxBytes <= 0 {
		return
	}
	var total int64
	for _, e := range survivors {
		total += e.size
	}
	if total <= maxBytes {
		return
	}
	sort.Slice(survivors, func(i, j int) bool { return survivors[i].mtime.Before(survivors[j].mtime) })
	var evictN int
	var evictBytes int64
	for _, e := range survivors {
		if total <= maxBytes {
			break
		}
		if err := os.Remove(e.path); err == nil {
			total -= e.size
			evictN++
			evictBytes += e.size
		}
	}
	s.removeEmptyDirs()
	log.Warn("janitor: watermark eviction",
		"evicted", evictN, "bytes", evictBytes, "limit", maxBytes)
}

// removeEmptyDirs deletes now-empty call dirs (never live-call dirs, which scan
// already excluded from deletion candidacy) and returns the count removed.
func (s *Store) removeEmptyDirs() int {
	dirs, err := os.ReadDir(s.dir)
	if err != nil {
		return 0
	}
	var n int
	for _, d := range dirs {
		if !d.IsDir() || s.isLive(d.Name()) {
			continue
		}
		callDir := s.callDir(d.Name())
		files, err := os.ReadDir(callDir)
		if err == nil && len(files) == 0 {
			if os.Remove(callDir) == nil {
				n++
			}
		}
	}
	return n
}

// UsageBytes returns the total bytes stored across all call dirs. It is used by
// the record-time watermark guard (§13.3) and never blocks the janitor.
func (s *Store) UsageBytes(_ context.Context) (int64, error) {
	dirs, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var total int64
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		files, err := os.ReadDir(s.callDir(d.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if info, err := f.Info(); err == nil {
				total += info.Size()
			}
		}
	}
	return total, nil
}

// NonLiveUsageBytes returns the total bytes stored across all NON-live call
// dirs — i.e. exactly the population the §13.3 janitor watermark eviction
// (Sweep) can actually reclaim. It skips live-call dirs the same way scan()
// does, so the record-time watermark guard can distinguish "over cap but
// nothing evictable" from "over cap only because of protected live data."
func (s *Store) NonLiveUsageBytes(_ context.Context) (int64, error) {
	dirs, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var total int64
	for _, d := range dirs {
		if !d.IsDir() || s.isLive(d.Name()) {
			continue
		}
		files, err := os.ReadDir(s.callDir(d.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if info, err := f.Info(); err == nil {
				total += info.Size()
			}
		}
	}
	return total, nil
}
