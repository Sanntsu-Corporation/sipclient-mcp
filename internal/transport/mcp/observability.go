package mcp

import (
	"os"
	"path/filepath"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// BuildReadyStatus reports readiness from the two facts §5 N5 names: policy has
// loaded, and the artifact directory is writable. A FAILED SIGHUP reload leaves
// LastReloadFailed() true, so an operator's config error surfaces as a 503
// rather than only as a log line.
func BuildReadyStatus(s *policy.Store, c clock.Clock, started time.Time) ReadyStatus {
	loadedAt := s.LoadedAt()
	writable := artifactDirWritable(s.Current().Artifact.Dir)
	return ReadyStatus{
		Ready:               !loadedAt.IsZero() && !s.LastReloadFailed() && writable,
		PolicyLoadedAt:      loadedAt.UTC().Format(time.RFC3339),
		ArtifactDirWritable: writable,
		UptimeS:             int64(c.Now().Sub(started).Seconds()),
	}
}

// artifactDirWritable reports whether dir exists and accepts a new file. An
// empty dir (artifact.dir unset in policy — D294) is deliberately reported
// unwritable rather than defaulted or treated as "disabled": the daemon is
// genuinely not ready to write call artifacts until an operator configures a
// real path.
func artifactDirWritable(dir string) bool {
	if dir == "" {
		return false
	}
	f, err := os.CreateTemp(dir, ".readyz-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(filepath.Clean(name))
	return true
}
