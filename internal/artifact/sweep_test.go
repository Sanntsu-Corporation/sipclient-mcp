package artifact

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
)

type liveSet map[string]bool

func (l liveSet) IsLive(h string) bool { return l[h] }

func writeArtifact(t *testing.T, s *Store, call, name string, size int, mtime time.Time) {
	t.Helper()
	if err := s.OpenCallDir(context.Background(), call); err != nil {
		t.Fatal(err)
	}
	w, err := s.Create(context.Background(), call, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	p := filepath.Join(s.callDir(call), name)
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func TestSweepDeletesExpiredKeepsFresh(t *testing.T) {
	s := New(t.TempDir(), clock.System())
	now := time.Now()
	writeArtifact(t, s, "call-old", "recording.wav", 100, now.Add(-48*time.Hour))
	writeArtifact(t, s, "call-new", "recording.wav", 100, now.Add(-1*time.Hour))
	s.SetLiveCallChecker(liveSet{})

	s.Sweep(context.Background(), 24*time.Hour, 0, slog.Default())

	if _, err := os.Stat(filepath.Join(s.callDir("call-old"), "recording.wav")); !os.IsNotExist(err) {
		t.Fatal("expired artifact survived")
	}
	if _, err := os.Stat(filepath.Join(s.callDir("call-new"), "recording.wav")); err != nil {
		t.Fatal("fresh artifact was deleted")
	}
	// The empty old dir is removed.
	if _, err := os.Stat(s.callDir("call-old")); !os.IsNotExist(err) {
		t.Fatal("empty call dir not removed")
	}
}

func TestSweepProtectsLiveCall(t *testing.T) {
	s := New(t.TempDir(), clock.System())
	writeArtifact(t, s, "call-live", "recording.wav", 100, time.Now().Add(-48*time.Hour))
	s.SetLiveCallChecker(liveSet{"call-live": true})

	s.Sweep(context.Background(), 24*time.Hour, 0, slog.Default())

	if _, err := os.Stat(filepath.Join(s.callDir("call-live"), "recording.wav")); err != nil {
		t.Fatal("live call's expired-by-mtime artifact was deleted (must be protected)")
	}
}

func TestSweepWatermarkEvictsOldestNonLive(t *testing.T) {
	s := New(t.TempDir(), clock.System())
	now := time.Now()
	// Three fresh (within TTL) artifacts of 1000 bytes; watermark 2500 forces
	// eviction of the single oldest.
	writeArtifact(t, s, "c1", "a.wav", 1000, now.Add(-3*time.Hour))
	writeArtifact(t, s, "c2", "a.wav", 1000, now.Add(-2*time.Hour))
	writeArtifact(t, s, "c3", "a.wav", 1000, now.Add(-1*time.Hour))
	s.SetLiveCallChecker(liveSet{})

	s.Sweep(context.Background(), 24*time.Hour, 2500, slog.Default())

	if _, err := os.Stat(filepath.Join(s.callDir("c1"), "a.wav")); !os.IsNotExist(err) {
		t.Fatal("oldest artifact not evicted under watermark")
	}
	if _, err := os.Stat(filepath.Join(s.callDir("c3"), "a.wav")); err != nil {
		t.Fatal("newest artifact wrongly evicted")
	}
}

func TestSweepWatermarkNeverEvictsLive(t *testing.T) {
	s := New(t.TempDir(), clock.System())
	now := time.Now()
	writeArtifact(t, s, "c-live", "a.wav", 5000, now.Add(-3*time.Hour))
	s.SetLiveCallChecker(liveSet{"c-live": true})

	s.Sweep(context.Background(), 24*time.Hour, 1000, slog.Default()) // way over watermark

	if _, err := os.Stat(filepath.Join(s.callDir("c-live"), "a.wav")); err != nil {
		t.Fatal("live artifact evicted under watermark (must be protected)")
	}
}
