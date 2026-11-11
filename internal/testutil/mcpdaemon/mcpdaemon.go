// Package mcpdaemon runs the daemon's REAL MCP HTTP handler (bearer auth,
// session ids, generated tool schemas) over the repo's fake tool/session
// implementations, under httptest. It exists because the helpers in
// internal/transport/mcp's _test files are unexported. Test-only: production
// binaries must not import it (see internal/importguard).
package mcpdaemon

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
	mcptransport "github.com/sanntsu-corporation/sipclient-mcp/internal/transport/mcp"
)

// Token is the bearer token every Daemon accepts.
const Token = "daemon-bearer-token-do-not-leak"

// Daemon is a running fake-backed daemon.
type Daemon struct {
	URL    string // ".../mcp"
	Token  string
	Tools  *fakes.Tools
	Server *httptest.Server

	sessionClock *fakeclock.Clock
}

// ExpireSessions ages every session that owns no live UA past the daemon's
// resume window, so its next request gets HTTP 404 - what a real daemon does
// after a session TTL expires. (A daemon RESTART is simulated by Server.Close.)
func (d *Daemon) ExpireSessions() { d.sessionClock.Advance(2 * time.Hour) }

// Start launches a Daemon and registers cleanup with t.
func Start(t testing.TB) *Daemon {
	t.Helper()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "bearer.token")
	if err := os.WriteFile(tokenFile, []byte(Token), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	polPath := filepath.Join(dir, "policy.yaml")
	pol := "auth:\n  bearer_token_file: " + tokenFile + "\nartifact:\n  dir: " + dir + "\n"
	if err := os.WriteFile(polPath, []byte(pol), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	clk := clock.System()
	store, err := policy.NewStore(polPath, clk, log)
	if err != nil {
		t.Fatalf("policy.NewStore: %v", err)
	}
	tools := fakes.NewTools()
	// Only the session registry runs on the fake clock, so ExpireSessions can age
	// sessions without touching the policy store or the HTTP layer.
	sessClock := fakeclock.New(time.Now())
	srv, err := mcptransport.NewServer(mcptransport.Config{
		Sessions: fakes.NewSessions(sessClock, time.Hour),
		Tools:    tools,
		Policy:   store,
		Log:      log,
		Clock:    clk,
	})
	if err != nil {
		t.Fatalf("mcp.NewServer: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return &Daemon{URL: hs.URL + "/mcp", Token: Token, Tools: tools, Server: hs, sessionClock: sessClock}
}
