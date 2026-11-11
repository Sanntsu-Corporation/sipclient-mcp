package peer

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/tlsca"
)

// C1 (M7a Rule 9 acceptance criterion 1): the fake serves each chosen
// certificate. Five subtests, each dialling the peer's TLS listener with a
// bare crypto/tls client — the shape internal/sipua/ua_tls_test.go:30
// already uses — and asserting on the error TYPE via errors.As, never by
// string-matching (the same discipline M7c will separately be built to
// enforce).

// TestC1MatchingCertVerifies is C1 subtest 1: a CA-issued cert whose SAN
// matches the dial target, with that CA in the client's RootCAs, completes
// the handshake with no error.
func TestC1MatchingCertVerifies(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	leaf, err := ca.IssueLeaf(tlsca.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	p := Start(t, Config{Addr: "127.0.0.1:0", TLSCert: &leaf})

	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	conn, err := tls.Dial("tcp", p.TLSAddr(), &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("Handshake: %v", err)
	}
}

// TestC1UnrelatedCAFailsWithUnknownAuthority is C1 subtest 2: a leaf signed
// by a SECOND, independently generated CA fails verification against a
// client trusting only the first, with *x509.UnknownAuthorityError.
func TestC1UnrelatedCAFailsWithUnknownAuthority(t *testing.T) {
	trusted, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA(trusted): %v", err)
	}
	unrelated, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA(unrelated): %v", err)
	}
	leaf, err := unrelated.IssueLeaf(tlsca.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	p := Start(t, Config{Addr: "127.0.0.1:0", TLSCert: &leaf})

	pool := x509.NewCertPool()
	pool.AddCert(trusted.Certificate())
	_, err = tls.Dial("tcp", p.TLSAddr(), &tls.Config{RootCAs: pool})
	if err == nil {
		t.Fatalf("tls.Dial unexpectedly succeeded against an unrelated CA's leaf")
	}
	var uaErr x509.UnknownAuthorityError
	if !errors.As(err, &uaErr) {
		t.Fatalf("tls.Dial err = %v (%T), want x509.UnknownAuthorityError", err, err)
	}
}

// TestC1SANMismatchFailsWithHostnameError is C1 subtest 3: a DNS-SAN cert
// dialled by IP fails with *x509.HostnameError — sipgo substitutes the
// request URI's host verbatim into the TLS ServerName it verifies against
// (third_party/sipgo/sip/transport_layer.go:312-323), so an IP-literal dial
// target against a DNS-only cert is exactly the SAN-mismatch shape a real
// UA can hit.
func TestC1SANMismatchFailsWithHostnameError(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	// DNS-only SAN, no IP SAN — dialled by IP literal below.
	leaf, err := ca.IssueLeaf(tlsca.LeafOptions{DNSNames: []string{"registrar.test"}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	p := Start(t, Config{Addr: "127.0.0.1:0", TLSCert: &leaf})

	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	_, err = tls.Dial("tcp", p.TLSAddr(), &tls.Config{RootCAs: pool})
	if err == nil {
		t.Fatalf("tls.Dial unexpectedly succeeded dialling a DNS-SAN-only cert by IP")
	}
	var hostErr x509.HostnameError
	if !errors.As(err, &hostErr) {
		t.Fatalf("tls.Dial err = %v (%T), want x509.HostnameError", err, err)
	}
}

// TestC1ExpiredCertFailsWithCertificateInvalid is C1 subtest 4: a cert whose
// validity window is now-2h/now-1h (already expired) fails with
// *x509.CertificateInvalidError{Reason: x509.Expired}.
func TestC1ExpiredCertFailsWithCertificateInvalid(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	leaf, err := ca.IssueLeaf(tlsca.LeafOptions{
		IPs:     []net.IP{net.ParseIP("127.0.0.1")},
		Expired: true,
	})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	p := Start(t, Config{Addr: "127.0.0.1:0", TLSCert: &leaf})

	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	_, err = tls.Dial("tcp", p.TLSAddr(), &tls.Config{RootCAs: pool})
	if err == nil {
		t.Fatalf("tls.Dial unexpectedly succeeded against an expired cert")
	}
	var certErr x509.CertificateInvalidError
	if !errors.As(err, &certErr) {
		t.Fatalf("tls.Dial err = %v (%T), want x509.CertificateInvalidError", err, err)
	}
	if certErr.Reason != x509.Expired {
		t.Fatalf("CertificateInvalidError.Reason = %v, want x509.Expired", certErr.Reason)
	}
}

// TestC1NotYetValidCertFailsWithCertificateInvalid is C1 subtest 5: a cert
// whose validity window is now+1h/now+2h (not yet valid) fails with the
// SAME error type/reason as the expired case — Go's x509.Expired reason
// conflates "expired" and "not yet valid" (both fail the same NotBefore/
// NotAfter bracket check and share one Reason value); there is no separate
// x509.InvalidityReason for "not yet valid". This is documented Go
// behavior, not a bug in tlsca or peer — the two cases are told apart here
// by which validity window IssueLeaf was asked to generate, not by
// Reason.
func TestC1NotYetValidCertFailsWithCertificateInvalid(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	leaf, err := ca.IssueLeaf(tlsca.LeafOptions{
		IPs:         []net.IP{net.ParseIP("127.0.0.1")},
		NotYetValid: true,
	})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	p := Start(t, Config{Addr: "127.0.0.1:0", TLSCert: &leaf})

	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	_, err = tls.Dial("tcp", p.TLSAddr(), &tls.Config{RootCAs: pool})
	if err == nil {
		t.Fatalf("tls.Dial unexpectedly succeeded against a not-yet-valid cert")
	}
	var certErr x509.CertificateInvalidError
	if !errors.As(err, &certErr) {
		t.Fatalf("tls.Dial err = %v (%T), want x509.CertificateInvalidError", err, err)
	}
	if certErr.Reason != x509.Expired {
		t.Fatalf("CertificateInvalidError.Reason = %v, want x509.Expired (Go conflates not-yet-valid into this reason)", certErr.Reason)
	}
}

// TestTLSListenerUnsetByDefault proves the additive/opt-in contract (M7a §2
// point 3): a Peer started with no Config.TLSCert binds no TLS listener at
// all, and Addr() keeps returning the UDP address unchanged.
func TestTLSListenerUnsetByDefault(t *testing.T) {
	p := Start(t, Config{Addr: "127.0.0.1:0"})
	if got := p.TLSAddr(); got != "" {
		t.Fatalf("TLSAddr() = %q, want \"\" when Config.TLSCert is unset", got)
	}
	if p.Addr() == "" {
		t.Fatalf("Addr() is empty")
	}
}
