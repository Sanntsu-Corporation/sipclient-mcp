package artifact

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, clock.System())
	ctx := context.Background()
	if err := s.OpenCallDir(ctx, "call_abc"); err != nil {
		t.Fatalf("OpenCallDir: %v", err)
	}
	w, err := s.Create(ctx, "call_abc", "capture.pcap")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write([]byte("PCAPDATA")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = w.Close()
	info, err := s.Close(ctx, "call_abc", "capture.pcap")
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if info.Bytes != 8 || info.URI != "mcp://sipclient/artifacts/call_abc/capture.pcap" {
		t.Fatalf("info = %+v", info)
	}
	gotInfo, rc, err := s.Resolve(ctx, info.URI)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	defer func() { _ = rc.Close() }()
	b, _ := io.ReadAll(rc)
	if string(b) != "PCAPDATA" || gotInfo.Bytes != 8 {
		t.Fatalf("resolved bytes = %q info=%+v", b, gotInfo)
	}
}

// finding 1a: a second Create for an existing artifact must NOT truncate it.
func TestStoreCreateIsExclusive(t *testing.T) {
	s := New(t.TempDir(), clock.System())
	ctx := context.Background()
	w, err := s.Create(ctx, "call_abc", "capture.pcap")
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, _ = w.Write([]byte("ORIGINAL"))
	_ = w.Close()
	if _, err := s.Create(ctx, "call_abc", "capture.pcap"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second Create err = %v, want os.ErrExist (must not truncate the artifact)", err)
	}
}

func TestStoreRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, clock.System())
	ctx := context.Background()

	// M2 — make the %2f case NON-TAUTOLOGICAL: plant a REAL file at the exact
	// path the undecoded "..%2fpasswd" component names, so a store WITHOUT the
	// safeComponent guard would resolve it successfully (os.Stat + os.Open both
	// succeed). The guard must therefore reject it for the RIGHT reason (a
	// leading-dot component), not merely because the file is absent — this test
	// now fails if traversal handling is removed.
	if err := os.MkdirAll(filepath.Join(dir, "call_x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "call_x", "..%2fpasswd"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{"mcp://sipclient/artifacts/../etc/passwd",
		"mcp://sipclient/artifacts/call_x/../../y",
		"mcp://sipclient/artifacts/call_x/..%2fpasswd"} {
		if _, _, err := s.Resolve(ctx, bad); err == nil {
			t.Fatalf("Resolve(%q) accepted a traversal path", bad)
		}
	}
}

func TestStoreRemoveIsIdempotentAndFreesExclusive(t *testing.T) {
	s := New(t.TempDir(), clock.System())
	ctx := context.Background()
	w, err := s.Create(ctx, "call_abc", "capture.pcap")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = w.Close()
	if err := s.Remove(ctx, "call_abc", "capture.pcap"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	// idempotent: removing a gone file is not an error.
	if err := s.Remove(ctx, "call_abc", "capture.pcap"); err != nil {
		t.Fatalf("second Remove (idempotent): %v", err)
	}
	// after Remove, the exclusive slot is free again — Create succeeds, no O_EXCL orphan.
	if _, err := s.Create(ctx, "call_abc", "capture.pcap"); err != nil {
		t.Fatalf("Create after Remove: %v", err)
	}
}
