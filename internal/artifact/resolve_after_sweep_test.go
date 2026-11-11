package artifact

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
)

// §13.5: an artifact resolves from disk with no registry dependency, so it
// survives long after its (simulated) registry entry would have aged out — and a
// reclaimed one surfaces as gone via the existing os.Open failure path.
func TestResolveSurvivesRegistryButFollowsDisk(t *testing.T) {
	s := New(t.TempDir(), clock.System())
	s.SetLiveCallChecker(liveSet{})
	writeArtifact(t, s, "call-x", "recording.wav", 320, time.Now())

	uri := s.URI("call-x", "recording.wav")
	info, rc, err := s.Resolve(context.Background(), uri)
	if err != nil {
		t.Fatalf("Resolve (fresh): %v", err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if info.Bytes != int64(len(b)) || len(b) == 0 {
		t.Fatalf("resolved bytes mismatch: info=%d read=%d", info.Bytes, len(b))
	}

	// Age the SAME file out in place — Create is O_EXCL, so writeArtifact
	// cannot be called twice for one path — then sweep.
	old := time.Now().Add(-48 * time.Hour)
	p := filepath.Join(s.callDir("call-x"), "recording.wav")
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	s.Sweep(context.Background(), 24*time.Hour, 0, slog.Default())
	if _, _, err := s.Resolve(context.Background(), uri); apierr.CodeOf(err) != apierr.CodeGone {
		t.Fatalf("Resolve after reclamation: code=%v err=%v; want gone", apierr.CodeOf(err), err)
	}
}
