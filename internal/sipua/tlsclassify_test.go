package sipua

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	tlspeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/tlsca"
)

// ---- §1 Rule 9 criterion 1: the TLSVerified() accessor itself -------------

// TestTLSVerifiedAccessor is Rule 9 criterion 1: (*UA).TLSVerified() reports
// (true, true) for a tls-transport UA with TLSInsecureSkipVerify false,
// (false, true) when TLSInsecureSkipVerify is true, and (_, false) for any
// non-tls transport (udp is checked here; tcp is the other non-tls case and
// behaves identically by the same `u.cfg.Transport != "tls"` guard).
func TestTLSVerifiedAccessor(t *testing.T) {
	cases := []struct {
		name                  string
		transport             string
		tlsInsecureSkipVerify bool
		wantVerified          bool
		wantOK                bool
	}{
		{"tls, verifying", "tls", false, true, true},
		{"tls, insecure_skip_verify", "tls", true, false, true},
		{"udp is not tls", "udp", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ua, err := New(context.Background(), Config{
				Transport:             tc.transport,
				LocalAddr:             "127.0.0.1:0",
				Logger:                testLogger(),
				Clock:                 clock.System(),
				TLSInsecureSkipVerify: tc.tlsInsecureSkipVerify,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer func() { _ = ua.Close(context.Background()) }()

			verified, ok := ua.TLSVerified()
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && verified != tc.wantVerified {
				t.Fatalf("verified = %v, want %v", verified, tc.wantVerified)
			}
		})
	}
}

// ---- §2 Rule 9 criterion 2: one case per probe row, synthetic errors -------

// TestClassifyTLSErrorProbeRows is the table-driven test for §2's five
// closed probe rows, using synthetic/constructed errors (Rule 9 criterion
// 2). Every row's kind is checked, and detail always carries peer.
func TestClassifyTLSErrorProbeRows(t *testing.T) {
	leafCert := &x509.Certificate{Raw: []byte("leaf-bytes")}

	cases := []struct {
		name     string
		err      error
		wantKind string
	}{
		{
			name:     "row1 hostname mismatch",
			err:      x509.HostnameError{Certificate: leafCert, Host: "127.0.0.2"},
			wantKind: tlsKindHostnameMismatch,
		},
		{
			name:     "row2 unknown authority",
			err:      x509.UnknownAuthorityError{Cert: leafCert},
			wantKind: tlsKindCertificateNotTrusted,
		},
		{
			name: "row3b certificate invalid, non-expired reason",
			err: x509.CertificateInvalidError{
				Cert: leafCert, Reason: x509.NotAuthorizedToSign,
			},
			wantKind: tlsKindHandshakeFailed,
		},
		{
			name: "row4 CertificateVerificationError with no unwrappable x509 cause",
			err: &tls.CertificateVerificationError{
				UnverifiedCertificates: []*x509.Certificate{leafCert},
				Err:                    errors.New("some other tls verification failure"),
			},
			wantKind: tlsKindHandshakeFailed,
		},
		{
			name:     "row5 not TLS at all",
			err:      tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
			wantKind: tlsKindHandshakeFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyTLSError(tc.err, "127.0.0.1:5061")
			var ae *apierr.Error
			if !errors.As(got, &ae) {
				t.Fatalf("classifyTLSError(%v) = %v, want an *apierr.Error", tc.err, got)
			}
			if ae.Code != apierr.CodeTLSFailure {
				t.Fatalf("Code = %q, want %q", ae.Code, apierr.CodeTLSFailure)
			}
			if ae.Detail["kind"] != tc.wantKind {
				t.Fatalf("Detail[kind] = %v, want %q", ae.Detail["kind"], tc.wantKind)
			}
			if ae.Detail["peer"] != "127.0.0.1:5061" {
				t.Fatalf("Detail[peer] = %v, want %q", ae.Detail["peer"], "127.0.0.1:5061")
			}
		})
	}
}

// TestClassifyTLSErrorProbeOrderRow4DoesNotSwallowRows1To3 is Rule 9
// criterion 2's mutation-sensitive test: it wraps a row-1 cause
// (*x509.HostnameError) inside a *tls.CertificateVerificationError, exactly
// how crypto/tls actually returns a certificate-shaped handshake failure,
// and asserts the SPECIFIC row (hostname_mismatch) still wins rather than
// the generic row-4 handshake_failed. Reordering rows 1-3 to come after row
// 4 in classifyTLSError collapses this to handshake_failed (verified by
// mutation, see the M7c report).
func TestClassifyTLSErrorProbeOrderRow4DoesNotSwallowRows1To3(t *testing.T) {
	leafCert := &x509.Certificate{Raw: []byte("leaf-bytes")}
	inner := x509.HostnameError{Certificate: leafCert, Host: "127.0.0.2"}
	wrapped := &tls.CertificateVerificationError{
		UnverifiedCertificates: []*x509.Certificate{leafCert},
		Err:                    inner,
	}

	got := classifyTLSError(wrapped, "peer:5061")
	var ae *apierr.Error
	if !errors.As(got, &ae) {
		t.Fatalf("classifyTLSError(%v) = %v, want an *apierr.Error", wrapped, got)
	}
	if ae.Detail["kind"] != tlsKindHostnameMismatch {
		t.Fatalf("Detail[kind] = %v, want %q (row 1 must win over row 4)",
			ae.Detail["kind"], tlsKindHostnameMismatch)
	}
}

// ---- §2 Rule 9 criterion 3: the required fallback (no catch-all) ----------

// TestClassifyTLSErrorFallbackDialToClosedPort is the REQUIRED fallback
// test: dialling a closed TCP port from a tls UA must return the error
// COMPLETELY UNCHANGED — no tls_failure code, no detail. This is the one
// assertion that reddens if a future maintainer "helpfully" restores a
// catch-all arm in classifyTLSError.
func TestClassifyTLSErrorFallbackDialToClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	closedAddr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("ln.Close: %v", err)
	}

	ua, err := New(context.Background(), Config{
		Transport: "tls",
		Mode:      "register",
		LocalAddr: "127.0.0.1:0",
		AOR:       "sip:alice@example",
		Registrar: "sip:" + closedAddr,
		Timeout:   500 * time.Millisecond,
		Logger:    testLogger(),
		Clock:     clock.System(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = ua.Close(context.Background()) }()

	_, regErr := ua.Register(context.Background())
	if regErr == nil {
		t.Fatal("Register against a closed port succeeded, want an error")
	}
	var ae *apierr.Error
	if errors.As(regErr, &ae) {
		t.Fatalf("Register against a closed port returned a classified *apierr.Error (%+v); "+
			"want the dial error unchanged — a catch-all has regressed", ae)
	}
}

// ---- §2 Rule 9 criterion 5: expired / not-yet-valid split, real certs -----

// TestClassifyTLSErrorExpiredVsNotYetValidSplit uses tlsca-generated
// certificates and a REAL x509 chain verification (not a hand-built
// x509.CertificateInvalidError) to prove classifyTLSError discriminates
// x509.Expired's two real causes by comparing the certificate's own
// NotBefore against wall time, not by inventing a second Reason value.
func TestClassifyTLSErrorExpiredVsNotYetValidSplit(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())

	t.Run("expired", func(t *testing.T) {
		leaf, err := ca.IssueLeaf(tlsca.LeafOptions{
			IPs: []net.IP{net.ParseIP("127.0.0.1")}, Expired: true,
		})
		if err != nil {
			t.Fatalf("IssueLeaf: %v", err)
		}
		_, verr := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: time.Now()})
		if verr == nil {
			t.Fatal("Verify of an expired leaf succeeded, want an error")
		}
		got := classifyTLSError(verr, "peer")
		assertTLSFailureKind(t, got, tlsKindCertificateExpired)
	})

	t.Run("not yet valid", func(t *testing.T) {
		leaf, err := ca.IssueLeaf(tlsca.LeafOptions{
			IPs: []net.IP{net.ParseIP("127.0.0.1")}, NotYetValid: true,
		})
		if err != nil {
			t.Fatalf("IssueLeaf: %v", err)
		}
		_, verr := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: time.Now()})
		if verr == nil {
			t.Fatal("Verify of a not-yet-valid leaf succeeded, want an error")
		}
		got := classifyTLSError(verr, "peer")
		assertTLSFailureKind(t, got, tlsKindCertificateNotYetValid)
	})
}

func assertTLSFailureKind(t *testing.T, err error, wantKind string) {
	t.Helper()
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("classifyTLSError result = %v, want an *apierr.Error", err)
	}
	if ae.Code != apierr.CodeTLSFailure {
		t.Fatalf("Code = %q, want %q", ae.Code, apierr.CodeTLSFailure)
	}
	if ae.Detail["kind"] != wantKind {
		t.Fatalf("Detail[kind] = %v, want %q", ae.Detail["kind"], wantKind)
	}
}

// ---- §7 required: chain-pinning through a REAL sipgo TLS dial --------------

// TestChainPinningRealSipgoTLSDialFindsUnknownAuthorityError is the REQUIRED
// (not optional) chain-pinning test (Rule 9 criterion 4). It proves that a
// REAL sipgo TLS dial against an untrusted certificate — dispatched through
// this UA's actual Client().RawTransaction, exactly as digestauth.go's wrap
// site calls it, BEFORE classifyTLSError ever sees it — still carries an
// *x509.UnknownAuthorityError reachable via errors.As. This is the guard
// against a future sipgo dependency change flattening the TLS error to a
// bare string, which would break every classifyTLSError probe silently (no
// compile error, no other test failing).
func TestChainPinningRealSipgoTLSDialFindsUnknownAuthorityError(t *testing.T) {
	untrustedCA, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA (untrusted): %v", err)
	}
	leaf, err := untrustedCA.IssueLeaf(tlsca.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	p := tlspeer.Start(t, tlspeer.Config{Addr: "127.0.0.1:0", TLSCert: &leaf})

	// A DIFFERENT, unrelated CA is what the dialling UA trusts — the peer's
	// leaf (signed by untrustedCA above) chains to nothing in this pool.
	trustedElsewhereCA, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA (trusted elsewhere): %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(trustedElsewhereCA.Certificate())

	ua, err := New(context.Background(), Config{
		Transport:  "tls",
		Mode:       "register",
		LocalAddr:  "127.0.0.1:0",
		AOR:        "sip:alice@example",
		Registrar:  "sip:" + p.TLSAddr(),
		Timeout:    2 * time.Second,
		TLSRootCAs: pool,
		Logger:     testLogger(),
		Clock:      clock.System(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = ua.Close(context.Background()) }()

	req := ua.buildRegister(ua.requestedExpires())
	_, rawErr := ua.Client().RawTransaction(context.Background(), req, ua.cfg.Timeout)
	if rawErr == nil {
		t.Fatal("RawTransaction against an untrusted-CA TLS peer succeeded, want an error")
	}

	var authErr x509.UnknownAuthorityError
	if !errors.As(rawErr, &authErr) {
		t.Fatalf("errors.As(rawErr, &x509.UnknownAuthorityError{}) = false; "+
			"rawErr = %v (%T) — sipgo's real error chain no longer carries the x509 cause", rawErr, rawErr)
	}

	// Tie it to the classifier too: the SAME real error correctly classifies.
	classified := classifyTLSError(rawErr, p.TLSAddr())
	assertTLSFailureKind(t, classified, tlsKindCertificateNotTrusted)

	// Mutation-proof of the exact regression this test guards against
	// (performed here, in-test, since the guarded behaviour lives in a
	// third-party dependency this module does not own): stringifying the
	// real error the way a flattening regression would loses the chain, and
	// the SAME assertion above must then fail.
	flattened := fmt.Errorf("%s", rawErr)
	var flatAuthErr x509.UnknownAuthorityError
	if errors.As(flattened, &flatAuthErr) {
		t.Fatal("errors.As found x509.UnknownAuthorityError through a stringified error; " +
			"the mutation proof is broken (a string-formatted wrap must not preserve Unwrap)")
	}
}

// ---- §7 criterion (b): inbound TLS to a ca_bundle-configured UA -----------

// TestInboundTLSToConfiguredUAEmitsNoFingerprintWarnOrTLSFailure is Rule 9
// criterion (b), the BEHAVIOURAL half: an inbound TLS connection to a UA
// configured with TLSRootCAs (ca_bundle) set completes cleanly and produces
// neither M7b's fingerprint WARN nor any tls_failure classification. peer
// cannot initiate an inbound TLS dial itself, so this uses a bare crypto/tls
// client dial against the UA's own inbound listener, per the brief's
// guidance.
//
// NOTE ON WHAT THIS TEST CAN AND CANNOT CATCH: the server's tls.Config sets
// no ClientAuth, so the server never requests (and so never sees) a client
// certificate — meaning cs.PeerCertificates is empty on the SERVER side of
// ANY inbound handshake regardless of whether a VerifyConnection hook is
// present there, since that hook's own body is gated on
// len(cs.PeerCertificates) > 0. A hook accidentally duplicated onto the
// server config would therefore NOT make this test redden (verified: see
// TestServerTLSConfigCarriesNoVerificationHooksOrTrustAnchor below, which is
// the test that actually catches that regression, at the *tls.Config level
// rather than through a live handshake).
func TestInboundTLSToConfiguredUAEmitsNoFingerprintWarnOrTLSFailure(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ua, err := New(context.Background(), Config{
		Transport:  "tls",
		LocalAddr:  "127.0.0.1:0",
		Logger:     logger,
		TLSRootCAs: pool, // ca_bundle configured
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = ua.Close(context.Background()) }()

	// A bare client dial into the UA's own inbound listener. InsecureSkipVerify
	// here describes the TEST CLIENT's posture, not the UA under test's — the
	// UA's inbound accept path has no verification hook to exercise either
	// way, which is exactly what this test checks.
	conn, err := tls.Dial("tcp", ua.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("Handshake: %v", err)
	}

	logged := logBuf.String()
	if bytes.Contains([]byte(logged), []byte("tls_peer_certificate_unverified")) {
		t.Fatalf("inbound TLS connection logged the fingerprint WARN; log = %s", logged)
	}
	if bytes.Contains([]byte(logged), []byte("tls_failure")) {
		t.Fatalf("inbound TLS connection logged a tls_failure; log = %s", logged)
	}
}

// TestServerTLSConfigCarriesNoVerificationHooksOrTrustAnchor is Rule 9
// criterion (b), the CONFIG-LEVEL half: newTLSConfigs's returned server
// *tls.Config carries no VerifyConnection hook and no RootCAs at all — both
// live ONLY on the client config (M7b's two-config split). This is the test
// that actually catches "the fingerprint hook moved onto the server config"
// (see the note on the behavioural test above for why a live handshake
// cannot detect that regression: the server never requests a client
// certificate, so the hook's own len(cs.PeerCertificates) > 0 guard would
// silently suppress the WARN either way).
func TestServerTLSConfigCarriesNoVerificationHooksOrTrustAnchor(t *testing.T) {
	pool := x509.NewCertPool()
	server, client, err := newTLSConfigs(net.ParseIP("127.0.0.1"), pool, true, testLogger())
	if err != nil {
		t.Fatalf("newTLSConfigs: %v", err)
	}
	if server.VerifyConnection != nil {
		t.Fatal("server tls.Config carries a VerifyConnection hook; that hook is client-only (M7b)")
	}
	if server.RootCAs != nil {
		t.Fatal("server tls.Config carries a RootCAs trust anchor; that field is client-only (M7b)")
	}
	if client.VerifyConnection == nil {
		t.Fatal("client tls.Config carries no VerifyConnection hook; the fingerprint WARN could never fire")
	}
	if client.RootCAs == nil {
		t.Fatal("client tls.Config carries no RootCAs; the configured ca_bundle would be silently ignored")
	}
}
