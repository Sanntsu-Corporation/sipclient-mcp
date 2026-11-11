package main

import (
	"strings"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

func TestVersionString(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		commit    string
		buildDate string
		want      string
	}{
		{
			name:      "ldflags injected",
			version:   "v0.1.0",
			commit:    "9dd357d",
			buildDate: "2026-07-18T09:00:00Z",
			want:      "sipclient-mcpd v0.1.0 (commit 9dd357d, built 2026-07-18T09:00:00Z)",
		},
		{
			name:      "unset defaults",
			version:   "dev",
			commit:    "none",
			buildDate: "unknown",
			want:      "sipclient-mcpd dev (commit none, built unknown)",
		},
	}

	origVersion, origCommit, origBuildDate := version, commit, buildDate
	t.Cleanup(func() { version, commit, buildDate = origVersion, origCommit, origBuildDate })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, commit, buildDate = tt.version, tt.commit, tt.buildDate
			if got := versionString(); got != tt.want {
				t.Errorf("versionString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestHealthzDisclosesNothing is decision 16/§12.2: GET /healthz must never
// leak the version, even though sensitive-looking values are live in the
// package vars a mis-wired handler could reach for.
func TestHealthzDisclosesNothing(t *testing.T) {
	origVersion, origCommit, origBuildDate := version, commit, buildDate
	t.Cleanup(func() { version, commit, buildDate = origVersion, origCommit, origBuildDate })
	version, commit, buildDate = "v9.9.9-secret", "cafebabe", "2026-07-18T00:00:00Z"

	h := loopback.New(t)
	defer h.Close()

	status, body := h.GetRaw(t, "/healthz") // no Authorization header
	if status != 200 {
		t.Fatalf("GET /healthz status = %d, want 200 (N4: unauthenticated by design)", status)
	}
	if body != "ok" {
		t.Fatalf("GET /healthz body = %q, want exactly %q — §12.2 requires it to "+
			"disclose nothing: no version, no counts, no configuration", body, "ok")
	}
	for _, leak := range []string{"v9.9.9-secret", "cafebabe", "sipclient-mcpd"} {
		if strings.Contains(body, leak) {
			t.Fatalf("GET /healthz body leaks %q (locked decision 16)", leak)
		}
	}
}
