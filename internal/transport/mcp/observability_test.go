package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/metrics"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

// observabilityEnv is a Server wired with a real policy store, a real metrics
// registry and the real BuildReadyStatus, plus the handles the /readyz failure
// cases need. It is built on newTestServer's SAME policy helper — there is no
// second policy-building path in this package.
type observabilityEnv struct {
	handler    http.Handler
	store      *policy.Store
	policyPath string
	artifacts  string
	clk        *fakeclock.Clock
	reg        *metrics.Registry
}

func newObservabilityEnv(t *testing.T) *observabilityEnv {
	t.Helper()
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	store, path := testPolicyStore(t, clk, testToken, "")
	started := clk.Now()
	reg := metrics.New(session.TerminationReasons)
	srv, err := NewServer(Config{
		Sessions: fakes.NewSessions(clk, time.Hour),
		Tools:    fakes.NewTools(),
		Policy:   store,
		Metrics:  reg,
		Ready:    func() ReadyStatus { return BuildReadyStatus(store, clk, started) },
		Log:      discardLogger(),
		Clock:    clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return &observabilityEnv{
		handler:    srv.Handler(),
		store:      store,
		policyPath: path,
		artifacts:  store.Current().Artifact.Dir,
		clk:        clk,
		reg:        reg,
	}
}

// breakArtifactDir makes the configured artifact.dir unwritable, which
// BuildReadyStatus reports as artifact_dir_writable:false.
func (e *observabilityEnv) breakArtifactDir(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("chmod-based unwritable-dir probe is a no-op as root")
	}
	if err := os.Chmod(e.artifacts, 0o500); err != nil {
		t.Fatalf("chmod artifact dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.artifacts, 0o700) })
}

// failReload rewrites the policy file with invalid YAML and reloads, leaving
// LastReloadFailed() true while the PREVIOUS policy stays in force (§12.2.1).
func (e *observabilityEnv) failReload(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(e.policyPath, []byte("destinations:\n  deny: ['[' \n"), 0o600); err != nil {
		t.Fatalf("write malformed policy: %v", err)
	}
	if err := e.store.Reload(); err == nil {
		t.Fatal("Reload accepted a malformed policy; §12.2.1 rejects it wholesale")
	}
}

func (e *observabilityEnv) get(t *testing.T, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	return rr
}

func TestObservabilityEndpointAuth(t *testing.T) {
	tests := []struct {
		name, path, token string
		wantStatus        int
	}{
		{"healthz no auth", "/healthz", "", http.StatusOK},
		{"healthz wrong token still ok", "/healthz", "wrong", http.StatusOK},
		{"readyz no token", "/readyz", "", http.StatusUnauthorized},
		{"readyz wrong token", "/readyz", "wrong", http.StatusUnauthorized},
		{"readyz good token", "/readyz", testToken, http.StatusOK},
		{"metrics no token", "/metrics", "", http.StatusUnauthorized},
		{"metrics wrong token", "/metrics", "wrong", http.StatusUnauthorized},
		{"metrics good token", "/metrics", testToken, http.StatusOK},
	}
	env := newObservabilityEnv(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rr := env.get(t, tt.path, tt.token); rr.Code != tt.wantStatus {
				t.Fatalf("GET %s status = %d, want %d", tt.path, rr.Code, tt.wantStatus)
			}
		})
	}
}

// TestHealthzRegisteredExactlyOnce guards the duplication the single API
// removed: /healthz was previously registered by BOTH Server.Handler() and
// registerObservability(mux, h *Handler), under two different server types. A
// second http.ServeMux registration of the same pattern PANICS, so this test
// fails loudly rather than subtly if either is reintroduced.
func TestHealthzRegisteredExactlyOnce(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("building the mux panicked — a route is registered twice: %v", r)
		}
	}()
	env := newObservabilityEnv(t)
	if rr := env.get(t, "/healthz", ""); rr.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200", rr.Code)
	}
}

func TestHealthzBodyIsExactlyOK(t *testing.T) {
	env := newObservabilityEnv(t)
	rr := env.get(t, "/healthz", "")
	if got := rr.Body.String(); got != "ok" {
		t.Fatalf("GET /healthz body = %q, want %q — deliberately contentless so it "+
			"is safe to expose to an orchestrator (§5 N5, §12.2)", got, "ok")
	}
}

func TestReadyzShape(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*testing.T, *observabilityEnv)
		wantStatus int
		wantReady  bool
	}{
		{"policy loaded and dir writable", func(*testing.T, *observabilityEnv) {}, http.StatusOK, true},
		{"artifact dir not writable", func(t *testing.T, e *observabilityEnv) { e.breakArtifactDir(t) },
			http.StatusServiceUnavailable, false},
		// The case that matters operationally: a config error must be visible
		// as unreadiness, not only as a log line (§5 N5).
		{"after a failed SIGHUP reload", func(t *testing.T, e *observabilityEnv) { e.failReload(t) },
			http.StatusServiceUnavailable, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newObservabilityEnv(t)
			tt.setup(t, env)
			rr := env.get(t, "/readyz", testToken)

			if rr.Code != tt.wantStatus {
				t.Fatalf("GET /readyz status = %d, want %d", rr.Code, tt.wantStatus)
			}
			var got ReadyStatus
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Fatalf("GET /readyz body is not JSON: %v\n%s", err, rr.Body.String())
			}
			if got.Ready != tt.wantReady {
				t.Fatalf("ready = %v, want %v", got.Ready, tt.wantReady)
			}
			// The SAME shape in both the 200 and the 503 case.
			for _, key := range []string{"ready", "policy_loaded_at",
				"artifact_dir_writable", "uptime_s"} {
				if !strings.Contains(rr.Body.String(), `"`+key+`"`) {
					t.Fatalf("GET /readyz body missing key %q in the %s case\n%s",
						key, tt.name, rr.Body.String())
				}
			}
		})
	}
}

func TestMetricsIsPlainTextKeyValue(t *testing.T) {
	env := newObservabilityEnv(t)

	// D293: framing-only checks pass a mutation that hardcodes a zero-valued
	// dump. Assert a counter that MOVED, not just that keys exist.
	env.reg.IncCallsTotal()
	env.reg.IncCallsTotal()

	rr := env.get(t, "/metrics", testToken)

	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
	for _, line := range strings.Split(strings.TrimSpace(rr.Body.String()), "\n") {
		if len(strings.Fields(line)) != 2 {
			t.Fatalf("metrics line %q is not `key value`", line)
		}
	}
	if !strings.Contains(rr.Body.String(), "calls_total 2") {
		t.Fatalf("metrics body missing %q after two IncCallsTotal calls\n%s",
			"calls_total 2", rr.Body.String())
	}
}
