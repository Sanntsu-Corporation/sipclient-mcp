package mcp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

// newAuthTestServer builds a Server whose only job is to exercise bearerAuth.
func newAuthTestServer(t *testing.T, bearer string) *Server {
	t.Helper()
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	store, _ := testPolicyStore(t, clk, bearer, "")
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour),
		Tools:    fakes.NewTools(),
		Policy:   store,
		Log:      discardLogger(),
		Clock:    clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func TestBearerAuthHealthzException(t *testing.T) {
	const token = "s3cret"
	srv := newAuthTestServer(t, token)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("reached"))
	})
	h := srv.bearerAuth(next)

	tests := []struct {
		name       string
		method     string
		path       string
		authHeader string
		wantCode   int
	}{
		{"healthz without a token", "GET", "/healthz", "", http.StatusOK},
		{"readyz without a token", "GET", "/readyz", "", http.StatusUnauthorized},
		{"metrics without a token", "GET", "/metrics", "", http.StatusUnauthorized},
		{"mcp without a token", "POST", "/mcp", "", http.StatusUnauthorized},
		{"readyz with the token", "GET", "/readyz", "Bearer " + token, http.StatusOK},
		{"metrics with the token", "GET", "/metrics", "Bearer " + token, http.StatusOK},
		{"lowercase scheme accepted", "GET", "/readyz", "bearer " + token, http.StatusOK},
		{"wrong token", "GET", "/readyz", "Bearer wrong", http.StatusUnauthorized},
		{"token prefix", "GET", "/readyz", "Bearer s3cre", http.StatusUnauthorized},
		{"empty bearer", "GET", "/readyz", "Bearer ", http.StatusUnauthorized},
		{"basic auth", "GET", "/readyz", "Basic " + token, http.StatusUnauthorized},
		{"no scheme", "GET", "/readyz", token, http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.authHeader != "" {
				r.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantCode)
			}
		})
	}
}

func TestBearerAuthPutsTokenInContext(t *testing.T) {
	const token = "s3cret"
	srv := newAuthTestServer(t, token)
	var got []byte
	h := srv.bearerAuth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = tokenFromContext(r.Context())
	}))
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !bytes.Equal(got, []byte(token)) {
		t.Fatalf("tokenFromContext = %q, want %q", got, token)
	}
}

// TestBearerTokenRotatesOnReload is the property the deleted []byte snapshot
// COULD NOT HAVE (contract finding 14, Part 4.4): rewriting the token file and
// reloading makes the new token work and the old one 401, with no restart and
// with nothing in transport/mcp to refresh.
func TestBearerTokenRotatesOnReload(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	store, path := testPolicyStore(t, clk, "old-token", "")
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour),
		Tools:    fakes.NewTools(),
		Policy:   store,
		Log:      discardLogger(),
		Clock:    clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	h := srv.bearerAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	probe := func(token string) int {
		r := httptest.NewRequest("GET", "/readyz", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	if code := probe("old-token"); code != http.StatusOK {
		t.Fatalf("old token before rotation = %d, want 200", code)
	}

	// Rewrite the token file the policy names, then SIGHUP-equivalent reload.
	tokenFile := filepath.Join(filepath.Dir(path), "bearer.token")
	if err := os.WriteFile(tokenFile, []byte("new-token"), 0o600); err != nil {
		t.Fatalf("rewrite token file: %v", err)
	}
	if err := store.Reload(); err != nil {
		t.Fatalf("store.Reload: %v", err)
	}

	if code := probe("new-token"); code != http.StatusOK {
		t.Fatalf("new token after rotation = %d, want 200 — bearerAuth is not "+
			"reading the LIVE policy; a snapshot was cached somewhere", code)
	}
	if code := probe("old-token"); code != http.StatusUnauthorized {
		t.Fatalf("old token after rotation = %d, want 401", code)
	}
}
