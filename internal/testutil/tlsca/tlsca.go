// Package tlsca mints in-memory ECDSA P-256 test certificate authorities and
// leaf certificates for TLS test infrastructure (Phase 4 W1 M7a). It exposes
// exactly the four generation knobs M7a §1 locks: an unrelated CA (obtained
// structurally, by issuing a leaf from a second *CA), a SAN/IP-SAN selector,
// expired, and not-yet-valid — plus a PEM writer M7c depends on.
//
// Every certificate is generated at CALL TIME from RELATIVE validity windows
// (now-2h/now-1h for expired, now+1h/now+2h for not-yet-valid) and is NEVER
// written to disk by this package — only WriteCAPEM writes anything, and
// only what the caller explicitly asks for. A committed not-yet-valid cert
// would become valid on its own timeline and silently stop testing anything
// (D6); generating fresh at test time is what this package exists to do
// instead.
//
// Rule 16: the ECDSA P-256 self-signed-cert shape matches the existing
// convention in internal/sipua/tlsconfig.go's newSelfSignedTLSConfig.
package tlsca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CA is a freshly minted, in-memory ECDSA P-256 self-signed test certificate
// authority. The zero value is not usable; construct one with NewCA.
type CA struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

// NewCA mints a fresh CA, valid from now-1h to now+24h — generous so that a
// leaf's own narrower validity window (LeafOptions.Expired/NotYetValid) is
// what a test actually exercises, never the CA's own.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlsca: generate CA key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "sipclient-mcp test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("tlsca: create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("tlsca: parse CA cert: %w", err)
	}
	return &CA{cert: cert, der: der, key: key}, nil
}

// Certificate returns ca's parsed x509 certificate — e.g. for a test that
// builds an *x509.CertPool directly via pool.AddCert without going through
// WriteCAPEM/AppendCertsFromPEM.
func (ca *CA) Certificate() *x509.Certificate { return ca.cert }

// LeafOptions configures the leaf certificate IssueLeaf mints. Its fields are
// exactly M7a §1's four generation knobs: DNSNames/IPs is the SAN selector
// (knob b), and Expired/NotYetValid are the two validity-window knobs (c,
// d). Knob (a), an unrelated CA, needs no field here — a test gets it by
// calling IssueLeaf on a SECOND, independently generated *CA than the one it
// puts in the verifying side's trust root.
type LeafOptions struct {
	// DNSNames and IPs are the leaf's SAN list; a test sets exactly one kind.
	// sipgo substitutes the request URI's host verbatim into the TLS
	// ServerName it verifies against (transport_layer.go:312-323), so an
	// IP-literal dial target needs an IP SAN and a hostname dial target
	// needs a DNS SAN — a DNS-SAN cert dialled by IP (or the reverse) is the
	// SAN-mismatch scenario.
	DNSNames []string
	IPs      []net.IP
	// Expired backdates NotBefore/NotAfter to now-2h/now-1h, computed at
	// IssueLeaf's call time.
	Expired bool
	// NotYetValid postdates NotBefore/NotAfter to now+1h/now+2h, computed at
	// IssueLeaf's call time. Ignored if Expired is also set (Expired wins).
	NotYetValid bool
}

// IssueLeaf mints a leaf certificate signed by ca, ready to serve as a TLS
// server certificate. The returned tls.Certificate's Leaf field is populated
// with the parsed *x509.Certificate, so a caller needing it directly (e.g.
// to call Verify) does not have to re-parse Certificate[0].
func (ca *CA) IssueLeaf(opts LeafOptions) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsca: generate leaf key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	switch {
	case opts.Expired:
		notBefore, notAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
	case opts.NotYetValid:
		notBefore, notAfter = time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "sipclient-mcp test leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     opts.DNSNames,
		IPAddresses:  opts.IPs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsca: create leaf cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsca: parse leaf cert: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// WriteCAPEM writes ca's certificate — never a leaf — as PEM to dir/ca.pem,
// returning the written file's path. dir must already exist; tests pass
// t.TempDir(). This is the ONE thing this package ever writes to disk, and
// only when a caller explicitly asks for it (M7c needs the path; nothing in
// this package persists a certificate on its own initiative).
func (ca *CA) WriteCAPEM(dir string) (string, error) {
	path := filepath.Join(dir, "ca.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", fmt.Errorf("tlsca: write CA PEM: %w", err)
	}
	return path, nil
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("tlsca: generate serial: %w", err)
	}
	return serial, nil
}
