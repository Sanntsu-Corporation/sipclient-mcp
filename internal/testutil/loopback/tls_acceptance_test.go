package loopback_test

// tls_acceptance_test.go — Phase 4 W1 M7c, §6/§12.5: acceptance cases 1, 2
// and 4, driven against the loopback harness's own peer over its new TLS
// listener (WithPeerTLSCert). Case 3 (mutual TLS) is out of scope — P4-D05
// defers server-side ClientAuth entirely.
import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/tlsca"
)

// tlsAccount builds a "tls"-transport Account fixture (Phase 1 replacement
// for tlsProfile/policy.Profile), reusing loopback.TestAccount (Rule 16) and
// overriding only the one field that matters here.
func tlsAccount(t *testing.T, name string) loopback.Option {
	t.Helper()
	a := loopback.TestAccount(name, "s3cr3t-auth-pass")
	a.Transport = "tls"
	return loopback.WithAccounts(a)
}

// apiErrOf extracts the *apierr.Error a tool call's error wraps, failing the
// test if err carries none.
func apiErrOf(t *testing.T, err error) *apierr.Error {
	t.Helper()
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("error = %v, want an *apierr.Error", err)
	}
	return ae
}

// ---- §12.5 case 1: verified CA, matching IP SAN ----------------------------

// TestTLSAcceptanceCase1MatchedCAAndSANRegistersAndReportsVerified is §12.5
// case 1: ua_create against a registrar whose certificate chains to the
// configured ca_bundle and whose IP SAN matches the dial target succeeds,
// and an outbound call from that UA reports call_status.tls_verified ==
// true — read from the UA's construction-time snapshot (§7), so a
// `dialing`-state call is sufficient (no answered media call is built here).
func TestTLSAcceptanceCase1MatchedCAAndSANRegistersAndReportsVerified(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	caPath, err := ca.WriteCAPEM(t.TempDir())
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	leaf, err := ca.IssueLeaf(tlsca.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}

	h := loopback.New(t,
		loopback.WithTransport("tls"),
		tlsAccount(t, "tls-case1"),
		loopback.WithPeerTLSCert(&leaf),
		loopback.WithPolicyOverride("tls.ca_bundle", caPath),
	)
	defer h.Close()

	env := h.MustCallTool(t, "ua_create", h.UACreateArgsForAccount(t, "tls-case1"))
	ua, _ := env["ua_handle"].(string)
	if ua == "" {
		t.Fatalf("ua_create returned no ua_handle: %+v", env)
	}
	if registered, _ := env["registered"].(bool); !registered {
		t.Fatalf("ua_create registered = %v, want true: %+v", env["registered"], env)
	}

	// The outbound call dials the peer's TLS listener directly (the ua's
	// transport is tls; h.PeerURI() names the peer's UDP call address, which
	// cannot answer a TLS dial).
	callEnv := h.MustCallTool(t, "call_dial",
		map[string]any{"ua": ua, "to_uri": "sip:peer@" + h.Peer().TLSAddr()})
	call, _ := callEnv["call_handle"].(string)
	if call == "" {
		t.Fatalf("call_dial returned no call_handle: %+v", callEnv)
	}

	statusEnv := h.MustCallTool(t, "call_status", map[string]any{"call": call})
	verified, ok := statusEnv["tls_verified"].(bool)
	if !ok {
		t.Fatalf("call_status.tls_verified = %v (%T), want bool true", statusEnv["tls_verified"], statusEnv["tls_verified"])
	}
	if !verified {
		t.Fatalf("call_status.tls_verified = false, want true")
	}
}

// ---- §12.5 case 2: the four classification sub-scenarios -------------------
//
// Each sub-scenario below (2a-2d) is written out directly rather than through
// a shared driver: the four differ in which CA/leaf combination they build,
// and a parameterised driver would need almost as many parameters as the
// cases have lines (Rule 15 — the direct form is the simpler one here).

// ---- §12.5 case 2a: an unrelated CA signed the peer's leaf -----------------

func TestTLSAcceptanceCase2aUnrelatedCACertificateNotTrusted(t *testing.T) {
	trustedCA, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA (trusted): %v", err)
	}
	caPath, err := trustedCA.WriteCAPEM(t.TempDir())
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	unrelatedCA, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA (unrelated): %v", err)
	}
	leaf, err := unrelatedCA.IssueLeaf(tlsca.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}

	h := loopback.New(t,
		loopback.WithTransport("tls"),
		tlsAccount(t, "tls-case2a"),
		loopback.WithPeerTLSCert(&leaf),
		loopback.WithPolicyOverride("tls.ca_bundle", caPath),
	)
	defer h.Close()

	_, err = h.CallTool("ua_create", h.UACreateArgsForAccount(t, "tls-case2a"))
	if err == nil {
		t.Fatal("ua_create against an unrelated-CA peer succeeded, want tls_failure")
	}
	ae := apiErrOf(t, err)
	if ae.Code != apierr.CodeTLSFailure {
		t.Fatalf("Code = %q, want %q", ae.Code, apierr.CodeTLSFailure)
	}
	if ae.Detail["kind"] != "certificate_not_trusted" {
		t.Fatalf("Detail[kind] = %v, want %q", ae.Detail["kind"], "certificate_not_trusted")
	}
	if ae.Detail["peer"] == nil || ae.Detail["subject"] == nil || ae.Detail["fingerprint"] == nil {
		t.Fatalf("Detail = %+v, want peer/subject/fingerprint all present", ae.Detail)
	}
	// Verified via Count("REGISTER"), NOT via inspecting the trace sink:
	// WrapConn decorates a net.PacketConn and cannot see a TLS stream, so a
	// ladder-based assertion here would be unfalsifiable.
	if n := h.Peer().Count("REGISTER"); n != 0 {
		t.Fatalf("Peer().Count(REGISTER) = %d, want 0 (the TLS handshake itself must have failed)", n)
	}
}

// ---- §12.5 case 2b: SAN mismatch -------------------------------------------

func TestTLSAcceptanceCase2bSANMismatchHostnameMismatch(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	caPath, err := ca.WriteCAPEM(t.TempDir())
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	// Same CA-A, but the leaf's IP SAN names a DIFFERENT address than the
	// dial target (127.0.0.1).
	leaf, err := ca.IssueLeaf(tlsca.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.2")}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}

	h := loopback.New(t,
		loopback.WithTransport("tls"),
		tlsAccount(t, "tls-case2b"),
		loopback.WithPeerTLSCert(&leaf),
		loopback.WithPolicyOverride("tls.ca_bundle", caPath),
	)
	defer h.Close()

	_, err = h.CallTool("ua_create", h.UACreateArgsForAccount(t, "tls-case2b"))
	if err == nil {
		t.Fatal("ua_create against a SAN-mismatched peer succeeded, want tls_failure")
	}
	ae := apiErrOf(t, err)
	if ae.Code != apierr.CodeTLSFailure {
		t.Fatalf("Code = %q, want %q", ae.Code, apierr.CodeTLSFailure)
	}
	if ae.Detail["kind"] != "hostname_mismatch" {
		t.Fatalf("Detail[kind] = %v, want %q", ae.Detail["kind"], "hostname_mismatch")
	}
	if n := h.Peer().Count("REGISTER"); n != 0 {
		t.Fatalf("Peer().Count(REGISTER) = %d, want 0", n)
	}
}

// ---- §12.5 case 2c: expired -------------------------------------------------

func TestTLSAcceptanceCase2cExpiredCertificateExpired(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	caPath, err := ca.WriteCAPEM(t.TempDir())
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	leaf, err := ca.IssueLeaf(tlsca.LeafOptions{
		IPs: []net.IP{net.ParseIP("127.0.0.1")}, Expired: true,
	})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}

	h := loopback.New(t,
		loopback.WithTransport("tls"),
		tlsAccount(t, "tls-case2c"),
		loopback.WithPeerTLSCert(&leaf),
		loopback.WithPolicyOverride("tls.ca_bundle", caPath),
	)
	defer h.Close()

	_, err = h.CallTool("ua_create", h.UACreateArgsForAccount(t, "tls-case2c"))
	if err == nil {
		t.Fatal("ua_create against an expired-cert peer succeeded, want tls_failure")
	}
	ae := apiErrOf(t, err)
	if ae.Code != apierr.CodeTLSFailure {
		t.Fatalf("Code = %q, want %q", ae.Code, apierr.CodeTLSFailure)
	}
	if ae.Detail["kind"] != "certificate_expired" {
		t.Fatalf("Detail[kind] = %v, want %q", ae.Detail["kind"], "certificate_expired")
	}
	if n := h.Peer().Count("REGISTER"); n != 0 {
		t.Fatalf("Peer().Count(REGISTER) = %d, want 0", n)
	}
}

// ---- §12.5 case 2d: not yet valid -------------------------------------------

func TestTLSAcceptanceCase2dNotYetValidCertificateNotYetValid(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	caPath, err := ca.WriteCAPEM(t.TempDir())
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	leaf, err := ca.IssueLeaf(tlsca.LeafOptions{
		IPs: []net.IP{net.ParseIP("127.0.0.1")}, NotYetValid: true,
	})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}

	h := loopback.New(t,
		loopback.WithTransport("tls"),
		tlsAccount(t, "tls-case2d"),
		loopback.WithPeerTLSCert(&leaf),
		loopback.WithPolicyOverride("tls.ca_bundle", caPath),
	)
	defer h.Close()

	_, err = h.CallTool("ua_create", h.UACreateArgsForAccount(t, "tls-case2d"))
	if err == nil {
		t.Fatal("ua_create against a not-yet-valid-cert peer succeeded, want tls_failure")
	}
	ae := apiErrOf(t, err)
	if ae.Code != apierr.CodeTLSFailure {
		t.Fatalf("Code = %q, want %q", ae.Code, apierr.CodeTLSFailure)
	}
	if ae.Detail["kind"] != "certificate_not_yet_valid" {
		t.Fatalf("Detail[kind] = %v, want %q", ae.Detail["kind"], "certificate_not_yet_valid")
	}
	if n := h.Peer().Count("REGISTER"); n != 0 {
		t.Fatalf("Peer().Count(REGISTER) = %d, want 0", n)
	}
}

// ---- §12.5 case 4: insecure_skip_verify ------------------------------------

// TestTLSAcceptanceCase4InsecureSkipVerifyRegistersUnverified is §12.5 case
// 4: with tls.insecure_skip_verify true, ua_create against an UNTRUSTED
// peer's certificate (case 2a's CA-B leaf, reused) still succeeds,
// tls_verified reads false (the construction-time snapshot of
// TLSInsecureSkipVerify), and both M7b WARN keys are observed — the load
// WARN exactly once, the per-connection fingerprint WARN at least once.
func TestTLSAcceptanceCase4InsecureSkipVerifyRegistersUnverified(t *testing.T) {
	trustedCA, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA (trusted): %v", err)
	}
	caPath, err := trustedCA.WriteCAPEM(t.TempDir())
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	untrustedCA, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA (untrusted): %v", err)
	}
	leaf, err := untrustedCA.IssueLeaf(tlsca.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}

	h := loopback.New(t,
		loopback.WithTransport("tls"),
		tlsAccount(t, "tls-case4"),
		loopback.WithPeerTLSCert(&leaf),
		loopback.WithPolicyOverride("tls.ca_bundle", caPath),
		loopback.WithPolicyOverride("tls.insecure_skip_verify", true),
	)
	defer h.Close()

	env := h.MustCallTool(t, "ua_create", h.UACreateArgsForAccount(t, "tls-case4"))
	if registered, _ := env["registered"].(bool); !registered {
		t.Fatalf("ua_create registered = %v, want true: %+v", env["registered"], env)
	}
	ua, _ := env["ua_handle"].(string)
	if ua == "" {
		t.Fatalf("ua_create returned no ua_handle: %+v", env)
	}

	callEnv := h.MustCallTool(t, "call_dial",
		map[string]any{"ua": ua, "to_uri": "sip:peer@" + h.Peer().TLSAddr()})
	call, _ := callEnv["call_handle"].(string)
	if call == "" {
		t.Fatalf("call_dial returned no call_handle: %+v", callEnv)
	}
	statusEnv := h.MustCallTool(t, "call_status", map[string]any{"call": call})
	verified, ok := statusEnv["tls_verified"].(bool)
	if !ok {
		t.Fatalf("call_status.tls_verified = %v (%T), want bool false", statusEnv["tls_verified"], statusEnv["tls_verified"])
	}
	if verified {
		t.Fatalf("call_status.tls_verified = true, want false (insecure_skip_verify)")
	}

	logged := h.RawLog()
	if n := strings.Count(logged, "tls_insecure_skip_verify_enabled"); n != 1 {
		t.Fatalf(`log contains %d occurrences of "tls_insecure_skip_verify_enabled", want exactly 1 (one policy load); log = %s`, n, logged)
	}
	if !strings.Contains(logged, "tls_peer_certificate_unverified") {
		t.Fatalf(`log does not contain "tls_peer_certificate_unverified"; log = %s`, logged)
	}
}
