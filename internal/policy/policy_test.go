package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDurationUnmarshalYAML(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    time.Duration
		wantErr bool
	}{
		{name: "hours", in: `d: 1h`, want: time.Hour},
		{name: "twenty four hours", in: `d: 24h`, want: 24 * time.Hour},
		{name: "seconds", in: `d: 5s`, want: 5 * time.Second},
		{name: "composite", in: `d: 1h30m`, want: 90 * time.Minute},
		{name: "unparseable", in: `d: banana`, wantErr: true},
		{name: "bare integer rejected", in: `d: 3600`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got struct {
				D Duration `yaml:"d"`
			}
			err := yaml.Unmarshal([]byte(tt.in), &got)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got nil (value %v)", got.D.Duration())
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.D.Duration() != tt.want {
				t.Errorf("got %v, want %v", got.D.Duration(), tt.want)
			}
		})
	}
}

// writePolicy writes body to a temp file and returns its path.
func writePolicy(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

// writeFile writes body to a temp file and returns its path. Used for token
// and credential files referenced from a policy.
func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	body := fmt.Sprintf(`
auth:
  bearer_token_file: %s
destinations:
  deny_all: ['^sip:']
`, tok)
	_, err := Load(writePolicy(t, body))
	if err == nil {
		t.Fatal("want error for unknown key destinations.deny_all, got nil")
	}
	if !strings.Contains(err.Error(), "deny_all") {
		t.Errorf("error must name the offending key, got: %v", err)
	}
}

// TestLoadHintsAtRemovedWebhooksAndQualityKeys is the production-hardening
// spec's Task 5: Phase 4 W1 deleted the dead webhooks:/quality: policy
// keys (commit 594902a). An operator's existing config that still carries
// either one now hits the same generic strict-decode rejection as any
// other typo, with nothing distinguishing "this was an intentional
// breaking change" from "I made a typo".
func TestLoadHintsAtRemovedWebhooksAndQualityKeys(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	tests := []struct {
		name     string
		body     string
		wantHint bool
	}{
		{
			name:     "webhooks",
			body:     fmt.Sprintf("auth:\n  bearer_token_file: %s\nwebhooks:\n  url: https://example/hook\n", tok),
			wantHint: true,
		},
		{
			name:     "quality",
			body:     fmt.Sprintf("auth:\n  bearer_token_file: %s\nquality:\n  mos_threshold: 3.5\n", tok),
			wantHint: true,
		},
		{
			name:     "unrelated unknown key gets no hint",
			body:     fmt.Sprintf("auth:\n  bearer_token_file: %s\ndestinations:\n  deny_all: ['^sip:']\n", tok),
			wantHint: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writePolicy(t, tt.body))
			if err == nil {
				t.Fatal("want error, got nil")
			}
			hasHint := strings.Contains(err.Error(), "CHANGELOG.md")
			if hasHint != tt.wantHint {
				t.Errorf("error = %v, hint present = %v, want %v", err, hasHint, tt.wantHint)
			}
			if tt.wantHint && !strings.Contains(err.Error(), "were removed") {
				t.Errorf("error must explain this was an intentional removal, got: %v", err)
			}
		})
	}
}

func TestLoadAppliesEveryDefault(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	body := fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok)
	p, err := Load(writePolicy(t, body))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	tests := []struct {
		key  string
		got  any
		want any
	}{
		{"auth.admin_token_file", p.Auth.AdminTokenFile, ""},
		{"limits.max_concurrent_calls_per_session", p.Limits.MaxConcurrentCallsPerSession, 50},
		{"limits.max_concurrent_calls_total", p.Limits.MaxConcurrentCallsTotal, 50},
		{"limits.max_call_duration_s", p.Limits.MaxCallDurationS, 7200},
		{"limits.max_step_duration_s", p.Limits.MaxStepDurationS, 180},
		{"limits.max_redirects", p.Limits.MaxRedirects, 3},
		{"limits.max_uas_per_session", p.Limits.MaxUAsPerSession, 8},
		{"limits.max_uas_total", p.Limits.MaxUAsTotal, 200},
		{"limits.inbound_ring_timeout_s", p.Limits.InboundRingTimeoutS, 60},
		{"limits.max_sessions_total", p.Limits.MaxSessionsTotal, 1000},
		{"limits.registry_retention", p.Limits.RegistryRetention.Duration(), time.Hour},
		{"limits.max_terminated_calls_per_session", p.Limits.MaxTerminatedCallsPerSession, 500},
		{"limits.max_terminated_uas_per_session", p.Limits.MaxTerminatedUAsPerSession, 100},
		{"limits.session_resume_window", p.Limits.SessionResumeWindow.Duration(), time.Hour},
		{"limits.session_ttl", p.Limits.SessionTTL.Duration(), 5 * time.Minute},
		{"limits.max_wait_timeout_ms", p.Limits.MaxWaitTimeoutMS, 300000},
		{"limits.max_waiters_per_call", p.Limits.MaxWaitersPerCall, 8},
		{"limits.max_waiters_per_session", p.Limits.MaxWaitersPerSession, 64},
		{"limits.shutdown_grace_period", p.Limits.ShutdownGracePeriod.Duration(), 10 * time.Second},
		{"limits.event_log_size", p.Limits.EventLogSize, 1024},
		{"limits.max_ladders", p.Limits.MaxLadders, 512},
		{"media.local_ip", p.Media.LocalIP, ""},
		{"media.port_range", p.Media.PortRange, [2]int{16384, 32767}},
		{"media.jitter_buffer_ms", p.Media.JitterBufferMS, 60},
		{"tls.insecure_skip_verify", p.TLS.InsecureSkipVerify, false},
		{"capture.max_bytes_per_call", p.Capture.MaxBytesPerCall, int64(52428800)},
		{"artifact.retention", p.Artifact.Retention.Duration(), 24 * time.Hour},
		{"artifact.max_bytes", p.Artifact.MaxBytes, int64(10737418240)},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.key, tt.got, tt.want)
			}
		})
	}

	// The two concurrency caps are INDEPENDENT keys (§12.2.2, U3): setting
	// one must not move the other.
	body2 := fmt.Sprintf("auth:\n  bearer_token_file: %s\nlimits:\n  max_concurrent_calls_total: 7\n", tok)
	p2, err := Load(writePolicy(t, body2))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p2.Limits.MaxConcurrentCallsTotal != 7 {
		t.Errorf("max_concurrent_calls_total = %d, want 7", p2.Limits.MaxConcurrentCallsTotal)
	}
	if p2.Limits.MaxConcurrentCallsPerSession != 50 {
		t.Errorf("max_concurrent_calls_per_session = %d, want its own default 50",
			p2.Limits.MaxConcurrentCallsPerSession)
	}
}

func TestMaxUAsPerSessionOverrideDoesNotMoveMaxUAsTotal(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	body := fmt.Sprintf("auth:\n  bearer_token_file: %s\nlimits:\n  max_uas_per_session: 4\n", tok)
	p, err := Load(writePolicy(t, body))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p.Limits.MaxUAsPerSession != 4 {
		t.Errorf("max_uas_per_session = %d, want 4", p.Limits.MaxUAsPerSession)
	}
	if p.Limits.MaxUAsTotal != 200 {
		t.Errorf("max_uas_total = %d, want its own default 200", p.Limits.MaxUAsTotal)
	}
}

// TestDefaultsMatchesLoadWithNoKeys pins the exported Defaults() to the same
// values Load applies when every key is absent. Defaults() exists so
// internal/session and the loopback harness can build a *Policy with no file
// on disk (U9, Rule 18: policy.Limits is the ONE canonical limits type and
// session declares no duplicate). If the two ever drift, session's unit tests
// would be running against limits the daemon never uses — which is precisely
// the hand-synchronised duplication Defaults() exists to remove.
func TestDefaultsMatchesLoadWithNoKeys(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	loaded, err := Load(writePolicy(t, fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok)))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d := Defaults()
	if d.Limits != loaded.Limits {
		t.Errorf("Defaults().Limits = %+v, want Load's %+v", d.Limits, loaded.Limits)
	}
	if d.Media != loaded.Media {
		t.Errorf("Defaults().Media = %+v, want Load's %+v", d.Media, loaded.Media)
	}
	if d.Artifact != loaded.Artifact {
		t.Errorf("Defaults().Artifact = %+v, want Load's %+v", d.Artifact, loaded.Artifact)
	}
	// Defaults() resolves NO auth material: it never reads a token file, so
	// no digest is set and the admin plane is off.
	if d.AdminEnabled() {
		t.Error("Defaults().AdminEnabled() = true, want false: Defaults resolves no auth material")
	}
	if d.MatchesBearerToken([]byte("bearer-token-value")) {
		t.Error("Defaults() must carry no bearer digest")
	}
}

func TestLoadValidation(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")

	// base carries NO profiles: section — Phase 1 deleted policy.Profile and
	// the whole []Profile schema (owner-locked decision: ua_create takes
	// account fields inline; there is no shared registry left to describe in
	// policy.yaml). A file that still writes `profiles:` is rejected
	// wholesale by the strict decoder as an unknown key, exactly like any
	// other removed key (see TestLoadRejectsRemovedKeys).
	base := func(extra string) string {
		return fmt.Sprintf(`
auth:
  bearer_token_file: %s
%s`, tok, extra)
	}

	tests := []struct {
		name      string
		body      string
		wantErr   bool
		errSubstr string // the offending key the ERROR must name (§12.2.1)
	}{
		{
			name: "valid baseline loads",
			body: base(""),
		},
		{
			name:      "unknown key rejected",
			body:      base("destinations:\n  deny_all: ['^sip:']\n"),
			wantErr:   true,
			errSubstr: "deny_all",
		},
		{
			name:      "missing required auth.bearer_token_file rejected",
			body:      "destinations:\n  allow: ['^sip:']\n",
			wantErr:   true,
			errSubstr: "auth.bearer_token_file",
		},
		{
			name:      "profiles: key is rejected wholesale (Phase 1 removed policy.Profile)",
			body:      fmt.Sprintf("auth:\n  bearer_token_file: %s\nprofiles:\n  - name: p1\n    aor: sip:t@a.example\n", tok),
			wantErr:   true,
			errSubstr: "profiles",
		},
		{
			name:      "malformed regex in destinations.deny rejected",
			body:      base("destinations:\n  deny: ['^sip:[0-9']\n"),
			wantErr:   true,
			errSubstr: "destinations.deny[0]",
		},
		{
			name:      "malformed regex in destinations.allow rejected",
			body:      base("destinations:\n  allow: ['(unclosed']\n"),
			wantErr:   true,
			errSubstr: "destinations.allow[0]",
		},
		{
			name:      "tls.client_cert without tls.client_key rejected at load",
			body:      base("tls:\n  client_cert: /nonexistent/cert.pem\n"),
			wantErr:   true,
			errSubstr: "tls.client_key",
		},
		{
			name:      "tls.client_key without tls.client_cert rejected at load",
			body:      base("tls:\n  client_key: /nonexistent/key.pem\n"),
			wantErr:   true,
			errSubstr: "tls.client_cert",
		},
		// U12 and §N3's two keys are validated like every other limit: a
		// non-positive value is a configuration error, not a silent
		// "disabled". A shutdown_grace_period of 0 would make §11.4's BYE
		// wait and §12.7's admin DELETE return before any peer could answer,
		// and an event_log_size of 0 would silently discard every §10.5
		// event while call_wait still reported success.
		{
			name:      "limits.shutdown_grace_period of zero rejected",
			body:      base("limits:\n  shutdown_grace_period: 0s\n"),
			wantErr:   true,
			errSubstr: "limits.shutdown_grace_period",
		},
		{
			name:      "limits.session_ttl zero rejected",
			body:      base("limits:\n  session_ttl: 0s\n"),
			wantErr:   true,
			errSubstr: "limits.session_ttl",
		},
		{
			name: "limits.session_ttl accepts a positive override",
			body: base("limits:\n  session_ttl: 2m\n"),
		},
		{
			name:      "limits.event_log_size of zero rejected",
			body:      base("limits:\n  event_log_size: 0\n"),
			wantErr:   true,
			errSubstr: "limits.event_log_size",
		},
		{
			name:      "limits.max_ladders of zero rejected",
			body:      base("limits:\n  max_ladders: 0\n"),
			wantErr:   true,
			errSubstr: "limits.max_ladders",
		},
		{
			name:      "limits.max_sessions_total of zero rejected",
			body:      base("limits:\n  max_sessions_total: 0\n"),
			wantErr:   true,
			errSubstr: "limits.max_sessions_total",
		},
		// Rule 13 Cycle 6 (finding F3): an operator misconfiguration this
		// large would make every Open call under cap pressure perform a full
		// linear scan of the registry's session map while holding its global
		// mutex — a self-inflicted lock-contention amplifier.
		{
			name:      "limits.max_sessions_total above 100000 rejected",
			body:      base("limits:\n  max_sessions_total: 100001\n"),
			wantErr:   true,
			errSubstr: "limits.max_sessions_total",
		},
		{
			name: "limits.shutdown_grace_period, event_log_size and max_ladders accept explicit positive values",
			body: base("limits:\n  shutdown_grace_period: 30s\n  event_log_size: 64\n  max_ladders: 32\n"),
		},
		// finding NEW-2: a sub-pcap-header positive value fails at LOAD, not on
		// the first capture_start.
		{
			name:      "capture.max_bytes_per_call of 12 rejected (below the 24-byte pcap header)",
			body:      base("capture:\n  max_bytes_per_call: 12\n"),
			wantErr:   true,
			errSubstr: "capture.max_bytes_per_call",
		},
		{
			name: "capture.max_bytes_per_call accepts 0 (unbounded), the default and the 24-byte floor",
			body: base("capture:\n  max_bytes_per_call: 0\n"),
		},
		{
			name: "capture.max_bytes_per_call accepts the default 52428800",
			body: base("capture:\n  max_bytes_per_call: 52428800\n"),
		},
		{
			name: "capture.max_bytes_per_call accepts exactly 24 (the pcap header size)",
			body: base("capture:\n  max_bytes_per_call: 24\n"),
		},
		{
			name: "limits.max_uas_per_session accepts a value other than the default",
			body: base("limits:\n  max_uas_per_session: 4\n"),
		},
		// Phase 4 W1 M2, Inputs §3: max_call_duration_s's new load-time
		// ceiling. 0 stays the uncapped sentinel (decision 8); everything else
		// is bounded to one day.
		{
			name:      "limits.max_call_duration_s above 86400 rejected",
			body:      base("limits:\n  max_call_duration_s: 86401\n"),
			wantErr:   true,
			errSubstr: "limits.max_call_duration_s",
		},
		{
			name: "limits.max_call_duration_s accepts exactly 86400",
			body: base("limits:\n  max_call_duration_s: 86400\n"),
		},
		{
			name: "limits.max_call_duration_s accepts 0 (uncapped)",
			body: base("limits:\n  max_call_duration_s: 0\n"),
		},
		// Phase 4 W1 M2, Inputs §4 (RN-1): max_step_duration_s has NO uncapped
		// sentinel — unlike max_call_duration_s, 0 is illegal here.
		{
			name:      "limits.max_redirects negative rejected",
			body:      base("limits:\n  max_redirects: -1\n"),
			wantErr:   true,
			errSubstr: "limits.max_redirects",
		},
		{
			name:      "limits.max_redirects above 10 rejected",
			body:      base("limits:\n  max_redirects: 11\n"),
			wantErr:   true,
			errSubstr: "limits.max_redirects",
		},
		{
			name: "limits.max_redirects accepts 0 (follow none)",
			body: base("limits:\n  max_redirects: 0\n"),
		},
		{
			name: "limits.max_redirects accepts exactly 10",
			body: base("limits:\n  max_redirects: 10\n"),
		},
		{
			name:      "limits.max_step_duration_s of zero rejected",
			body:      base("limits:\n  max_step_duration_s: 0\n"),
			wantErr:   true,
			errSubstr: "limits.max_step_duration_s",
		},
		{
			name:      "limits.max_step_duration_s negative rejected",
			body:      base("limits:\n  max_step_duration_s: -1\n"),
			wantErr:   true,
			errSubstr: "limits.max_step_duration_s",
		},
		{
			name:      "limits.max_step_duration_s above 86400 rejected",
			body:      base("limits:\n  max_step_duration_s: 86401\n"),
			wantErr:   true,
			errSubstr: "limits.max_step_duration_s",
		},
		{
			name: "limits.max_step_duration_s accepts exactly 86400",
			body: base("limits:\n  max_step_duration_s: 86400\n"),
		},
		{
			name: "limits.max_step_duration_s accepts exactly 1",
			body: base("limits:\n  max_step_duration_s: 1\n"),
		},
		// B3 (revised, RN-2): all 7 keys across webhooks/quality are DELETED,
		// struct fields and all — under KnownFields(true) even a bare
		// `webhooks:`/`quality:` header with no children is an unknown field,
		// not "empty and ignored". The daemon fails to start on any policy.yaml
		// that still carries either top-level block.
		{
			name:      "webhooks.allow rejected (deleted key)",
			body:      base("webhooks:\n  allow: ['^https://example.com/']\n"),
			wantErr:   true,
			errSubstr: "webhooks",
		},
		{
			name:      "webhooks.deny rejected (deleted key)",
			body:      base("webhooks:\n  deny: []\n"),
			wantErr:   true,
			errSubstr: "webhooks",
		},
		{
			name:      "webhooks.allow_http rejected (deleted key)",
			body:      base("webhooks:\n  allow_http: true\n"),
			wantErr:   true,
			errSubstr: "webhooks",
		},
		{
			name:      "webhooks.allow_private_addresses rejected (deleted key)",
			body:      base("webhooks:\n  allow_private_addresses: true\n"),
			wantErr:   true,
			errSubstr: "webhooks",
		},
		{
			name:      "webhooks.connect_timeout_ms rejected (deleted key)",
			body:      base("webhooks:\n  connect_timeout_ms: 2000\n"),
			wantErr:   true,
			errSubstr: "webhooks",
		},
		{
			name:      "quality.pesq_python rejected (deleted key)",
			body:      base("quality:\n  pesq_python: /opt/venv/bin/python\n"),
			wantErr:   true,
			errSubstr: "quality",
		},
		{
			name:      "quality.pesq_script rejected (deleted key)",
			body:      base("quality:\n  pesq_script: /opt/scripts/pesq_nb.py\n"),
			wantErr:   true,
			errSubstr: "quality",
		},
		{
			name:      "bare webhooks: header with no children still rejected",
			body:      base("webhooks:\n"),
			wantErr:   true,
			errSubstr: "webhooks",
		},
		{
			name:      "bare quality: header with no children still rejected",
			body:      base("quality:\n"),
			wantErr:   true,
			errSubstr: "quality",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writePolicy(t, tt.body))
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("want load to succeed, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("want a load error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("error must name %q, got: %v", tt.errSubstr, err)
			}
		})
	}
}

func TestLoadRejectsNonMatchingTLSPair(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	dir := t.TempDir()

	certA, keyA := genSelfSigned(t, dir, "a")
	_, keyB := genSelfSigned(t, dir, "b")

	matching := fmt.Sprintf("auth:\n  bearer_token_file: %s\ntls:\n  client_cert: %s\n  client_key: %s\n", tok, certA, keyA)
	if _, err := Load(writePolicy(t, matching)); err != nil {
		t.Fatalf("matching pair must load, got: %v", err)
	}

	mismatched := fmt.Sprintf("auth:\n  bearer_token_file: %s\ntls:\n  client_cert: %s\n  client_key: %s\n", tok, certA, keyB)
	_, err := Load(writePolicy(t, mismatched))
	if err == nil {
		t.Fatal("want a load error for a non-matching cert/key pair, got nil")
	}
	if !strings.Contains(err.Error(), "tls.client_cert") {
		t.Errorf("error must name tls.client_cert, got: %v", err)
	}
}

// TestPolicyResolvesCABundleIntoTLSRootCAs is Phase 4 M7b's producer-side
// proof: a policy.yaml naming a valid PEM file via tls.ca_bundle loads
// clean and TLSRootCAs() returns the resolved pool (non-nil). Reuses
// genSelfSigned rather than internal/testutil/tlsca — the reverse import
// would be a compile-time cycle, since tlsca_test.go already imports
// internal/policy.
func TestPolicyResolvesCABundleIntoTLSRootCAs(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	dir := t.TempDir()
	caPath, _ := genSelfSigned(t, dir, "ca")

	body := fmt.Sprintf("auth:\n  bearer_token_file: %s\ntls:\n  ca_bundle: %s\n", tok, caPath)
	p, err := Load(writePolicy(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.TLSRootCAs() == nil {
		t.Fatal("want TLSRootCAs() non-nil when tls.ca_bundle names a valid PEM file")
	}
}

// TestCABundleUnsetTLSRootCAsIsNil confirms the "nil = use the host roots"
// default: TLSRootCAs() returns nil when tls.ca_bundle is never set.
func TestCABundleUnsetTLSRootCAsIsNil(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	body := fmt.Sprintf("auth:\n  bearer_token_file: %s\n", tok)
	p, err := Load(writePolicy(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.TLSRootCAs() != nil {
		t.Error("want TLSRootCAs() nil when tls.ca_bundle is unset")
	}
}

// TestLoadRejectsMissingCABundleFile: a tls.ca_bundle naming a file that does
// not exist is a whole-file load rejection naming the offending key, not a
// deferred dial-time failure.
func TestLoadRejectsMissingCABundleFile(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	missing := filepath.Join(t.TempDir(), "does-not-exist.pem")
	body := fmt.Sprintf("auth:\n  bearer_token_file: %s\ntls:\n  ca_bundle: %s\n", tok, missing)
	_, err := Load(writePolicy(t, body))
	if err == nil {
		t.Fatal("want a load error for a missing tls.ca_bundle file, got nil")
	}
	if !strings.Contains(err.Error(), "tls.ca_bundle") {
		t.Errorf("error must name tls.ca_bundle, got: %v", err)
	}
}

// TestLoadRejectsGarbageCABundlePEM: a tls.ca_bundle file that exists but
// contains no parseable PEM certificate is also a load rejection, not a
// silently-empty trust pool.
func TestLoadRejectsGarbageCABundlePEM(t *testing.T) {
	tok := writeFile(t, "token", "bearer-token-value\n")
	garbage := writeFile(t, "garbage.pem", "this is not a certificate\n")
	body := fmt.Sprintf("auth:\n  bearer_token_file: %s\ntls:\n  ca_bundle: %s\n", tok, garbage)
	_, err := Load(writePolicy(t, body))
	if err == nil {
		t.Fatal("want a load error for a non-PEM tls.ca_bundle, got nil")
	}
	if !strings.Contains(err.Error(), "tls.ca_bundle") {
		t.Errorf("error must name tls.ca_bundle, got: %v", err)
	}
}

// genSelfSigned writes a self-signed cert/key pair into dir and returns
// their paths. Kept local to this test: internal/testutil/certs is a P4
// deliverable (locked decision 13) and must not be created here.
func genSelfSigned(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	certPath = filepath.Join(dir, name+"-cert.pem")
	keyPath = filepath.Join(dir, name+"-key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalkey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}
