package sipua

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"time"
)

// newTLSConfigs builds the ephemeral in-memory self-signed cert (bindIP in
// its SANs) and returns it wrapped in TWO separate *tls.Config values — a
// server config for the inbound listener and a client config for the
// outbound dialer (Phase 4 M7b, §7 scope item 5). A single shared config used
// to serve both roles (W3/L11); that dual-role shape is what let a
// client-only VerifyConnection hook fire on inbound handshakes too, so the
// split eliminates the hazard rather than working around it — there is no
// shared object left for a hook to leak across.
//
// rootCAs is the resolved trust anchor for the client config: nil means "use
// the host roots", and a non-nil pool (from policy tls.ca_bundle) REPLACES
// the host roots rather than adding to them (owner-approved decision, §12.5
// case 2). insecureSkipVerify is policy tls.insecure_skip_verify, client-side
// only. MinVersion pins TLS1.2 on both configs (Asterisk pins tlsv1_2).
func newTLSConfigs(bindIP net.IP, rootCAs *x509.CertPool, insecureSkipVerify bool, log *slog.Logger) (server, client *tls.Config, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsconfig: generate key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: bindIP.String()},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{bindIP},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsconfig: create cert: %w", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	server = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	logger := logOrDefault(log)
	client = &tls.Config{
		// The SAME self-signed cert, kept (Rule 19): a peer that requests a
		// client certificate still gets one. A policy-supplied pair is P4-D05,
		// not this module's concern.
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS12,
		RootCAs:            rootCAs,
		InsecureSkipVerify: insecureSkipVerify,
		// ServerName deliberately left empty: sipgo's tlsClient closure clones
		// this config and substitutes raddr.Hostname per-dial
		// (third_party/sipgo/sip/transport_tls.go:33-41). Setting it here would
		// defeat that substitution and silently disable hostname verification.
		VerifyConnection: func(cs tls.ConnectionState) error {
			// §7 scope item 5's fingerprint WARN, and NOTHING ELSE — no
			// tls_failure classification here, that is the dial-site
			// classifier (M7c, entirely separate from this hook).
			//
			// Gated on insecureSkipVerify: that is the posture (§12.5 case 4)
			// this WARN exists for — an operator who opted out of
			// verification still gets the peer's identity recorded once per
			// connection, including resumptions (VerifyConnection runs "for
			// all connections, including resumptions", unlike
			// VerifyPeerCertificate).
			if insecureSkipVerify && len(cs.PeerCertificates) > 0 {
				leaf := cs.PeerCertificates[0]
				sum := sha256.Sum256(leaf.Raw)
				logger.Warn("tls_peer_certificate_unverified",
					slog.String("subject", leaf.Subject.String()),
					slog.String("fingerprint_sha256", hex.EncodeToString(sum[:])))
			}
			return nil
		},
	}

	return server, client, nil
}
