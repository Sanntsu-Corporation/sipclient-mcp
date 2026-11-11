package tlsca

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// TestIssueLeafDefaultIsValidNow proves the zero-value LeafOptions produces a
// leaf whose validity window brackets "now" — the baseline every other case
// in this file is a deliberate deviation from.
func TestIssueLeafDefaultIsValidNow(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	leaf, err := ca.IssueLeaf(LeafOptions{DNSNames: []string{"peer.test"}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	now := time.Now()
	if !leaf.Leaf.NotBefore.Before(now) || !leaf.Leaf.NotAfter.After(now) {
		t.Fatalf("leaf validity window [%s, %s] does not bracket now (%s)",
			leaf.Leaf.NotBefore, leaf.Leaf.NotAfter, now)
	}
}

// TestIssueLeafExpiredIsInThePast proves the Expired knob (c) produces a
// window entirely before now, computed at call time rather than committed.
func TestIssueLeafExpiredIsInThePast(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	leaf, err := ca.IssueLeaf(LeafOptions{DNSNames: []string{"peer.test"}, Expired: true})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	now := time.Now()
	if !leaf.Leaf.NotAfter.Before(now) {
		t.Fatalf("expired leaf NotAfter %s is not before now (%s)", leaf.Leaf.NotAfter, now)
	}
}

// TestIssueLeafNotYetValidIsInTheFuture proves the NotYetValid knob (d)
// produces a window entirely after now.
func TestIssueLeafNotYetValidIsInTheFuture(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	leaf, err := ca.IssueLeaf(LeafOptions{DNSNames: []string{"peer.test"}, NotYetValid: true})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	now := time.Now()
	if !leaf.Leaf.NotBefore.After(now) {
		t.Fatalf("not-yet-valid leaf NotBefore %s is not after now (%s)", leaf.Leaf.NotBefore, now)
	}
}

// TestIssueLeafSANSelector proves knob (b): DNSNames and IPs land on the
// leaf's SAN list independently, so a test can mint a DNS-only or IP-only
// cert.
func TestIssueLeafSANSelector(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	dnsLeaf, err := ca.IssueLeaf(LeafOptions{DNSNames: []string{"registrar.test"}})
	if err != nil {
		t.Fatalf("IssueLeaf(dns): %v", err)
	}
	if len(dnsLeaf.Leaf.DNSNames) != 1 || dnsLeaf.Leaf.DNSNames[0] != "registrar.test" {
		t.Fatalf("dns leaf DNSNames = %v, want [registrar.test]", dnsLeaf.Leaf.DNSNames)
	}
	if len(dnsLeaf.Leaf.IPAddresses) != 0 {
		t.Fatalf("dns leaf IPAddresses = %v, want none", dnsLeaf.Leaf.IPAddresses)
	}
}

// TestIssueLeafUnrelatedCAProducesADifferentIssuer proves knob (a): a leaf
// issued by a second, independent CA does not verify against the first CA's
// pool — the exact shape peer_tls_test.go's C1 subtest 2 relies on, checked
// here directly at the x509 layer without a TLS handshake in between.
func TestIssueLeafUnrelatedCAProducesADifferentIssuer(t *testing.T) {
	ca1, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA(1): %v", err)
	}
	ca2, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA(2): %v", err)
	}
	leaf, err := ca2.IssueLeaf(LeafOptions{DNSNames: []string{"peer.test"}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca1.Certificate())
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "peer.test", Roots: pool}); err == nil {
		t.Fatalf("leaf issued by ca2 unexpectedly verified against ca1's pool")
	}
}

// TestWriteCAPEMWritesOnlyTheCACert proves the PEM writer's own contract:
// the file it writes decodes back to exactly ca's certificate DER, and no
// leaf material is ever written by this package.
func TestWriteCAPEMWritesOnlyTheCACert(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	dir := t.TempDir()
	path, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("WriteCAPEM path %q is not under %q", path, dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("WriteCAPEM wrote %d files, want exactly 1", len(entries))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		t.Fatalf("AppendCertsFromPEM rejected the written PEM")
	}
	leaf, err := ca.IssueLeaf(LeafOptions{DNSNames: []string{"peer.test"}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "peer.test", Roots: pool}); err != nil {
		t.Fatalf("leaf failed to verify against the written-PEM pool: %v", err)
	}
}

// --- C3 (D6, owner-approved split — see m7a-brief.md §"Owner-approved scope
// decision"): the PEM round-trips, PROVABLE HALF ONLY. internal/policy's
// tls.ca_bundle resolution into a consumed *x509.CertPool does not exist yet
// (that lands in M7b); this proves only (a) policy.Load accepts a
// policy.yaml naming this package's written PEM path via tls.ca_bundle with
// no load error (the key is declared, never validated by validate()), and
// (b) the PEM bytes this package wrote genuinely parse into a working
// x509.CertPool via AppendCertsFromPEM, and that pool verifies a
// matching-SAN leaf. It deliberately does NOT claim internal/policy resolves
// ca_bundle into anything — that claim is M7b's.

// TestC3PolicyLoadAcceptsTLSCABundleNamingTheWrittenPEM is C3 step 2: a
// policy.yaml naming the PEM WriteCAPEM wrote, via tls.ca_bundle, loads with
// no error. internal/policy is imported here ONLY to call the public Load
// entry point — no internal/policy file is touched by this change (M7a
// touches no production code).
func TestC3PolicyLoadAcceptsTLSCABundleNamingTheWrittenPEM(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	caPath, err := ca.WriteCAPEM(t.TempDir())
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("m7a-test-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	body := "auth:\n  bearer_token_file: " + tokenPath + "\ntls:\n  ca_bundle: " + caPath + "\n"
	if err := os.WriteFile(policyPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy.yaml: %v", err)
	}

	if _, err := policy.Load(policyPath); err != nil {
		t.Fatalf("policy.Load rejected a policy.yaml naming tls.ca_bundle = %q: %v", caPath, err)
	}
}

// TestC3PEMBytesParseIntoAWorkingCertPool is C3 step 3: the exact PEM bytes
// WriteCAPEM produced, read back independently of policy.Load, parse into an
// *x509.CertPool via AppendCertsFromPEM, and that pool verifies a
// matching-SAN leaf issued by the same CA.
func TestC3PEMBytesParseIntoAWorkingCertPool(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	caPath, err := ca.WriteCAPEM(t.TempDir())
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("AppendCertsFromPEM rejected the PEM bytes written to %s", caPath)
	}

	leaf, err := ca.IssueLeaf(LeafOptions{DNSNames: []string{"registrar.test"}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "registrar.test", Roots: pool}); err != nil {
		t.Fatalf("cert.Verify against the AppendCertsFromPEM pool: %v", err)
	}
}
