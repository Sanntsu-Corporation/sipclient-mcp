package sipua

// tlsclassify.go — Phase 4 W1 M7c, §2. classifyTLSError turns a raw dial-time
// error into apierr.TLSFailure's detail.kind when it recognises the error as
// one of a CLOSED, five-row probe set, and returns err UNCHANGED otherwise.
//
// THERE IS NO CATCH-ALL, AND THAT IS THE DESIGN, NOT AN OMISSION. A future
// maintainer "helpfully" adding a `default: handshake_failed` arm would make
// every unrecognised error (a plain connection refused, a context deadline,
// anything third_party/sipgo ever adds) misreport as a TLS certificate
// failure it never was. The required fallback test in tlsclassify_test.go
// (dial a closed TCP port from a tls UA) exists to catch exactly that
// regression: it reddens the instant a catch-all reappears.
//
// PROBE ORDER IS LOAD-BEARING. Rows 1-3 (the specific x509 causes) MUST be
// tried before row 4 (*tls.CertificateVerificationError), because that
// type's Unwrap() reaches the same x509 types underneath it — probing row 4
// first would match every specific cause and swallow it into a generic
// handshake_failed, silently, with no compile error and no other test
// failing (the failure mode the required probe-order mutation proof
// targets).
import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// The five closed detail.kind values classifyTLSError ever emits. Every
// value here must be reachable by some test (Rule 9 criterion 11), and
// classifyTLSError must never emit a sixth.
const (
	tlsKindHostnameMismatch       = "hostname_mismatch"
	tlsKindCertificateNotTrusted  = "certificate_not_trusted"
	tlsKindCertificateExpired     = "certificate_expired"
	tlsKindCertificateNotYetValid = "certificate_not_yet_valid"
	tlsKindHandshakeFailed        = "handshake_failed"
)

// classifyTLSError inspects err for one of §2's five closed probe rows and,
// on a match, returns apierr.TLSFailure with the matched kind and a detail
// payload built from peer and the certificate the probe found. peer is the
// dial site's OWN knowledge of the request target — never parsed out of err
// — and is carried into detail["peer"] unconditionally.
//
// On no match, err is returned COMPLETELY UNCHANGED: no wrapping, no
// apierr.Error, nothing. This is the one behaviour the fallback test proves.
func classifyTLSError(err error, peer string) error {
	if err == nil {
		return nil
	}

	// Row 1: hostname/IP-SAN mismatch. *x509.HostnameError is a struct VALUE
	// (not a pointer) in the crypto/x509 API, so the errors.As target is a
	// pointer to a plain value variable.
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return tlsFailure(tlsKindHostnameMismatch, peer, hostErr.Certificate)
	}

	// Row 2: the certificate chains to no trusted root.
	var authErr x509.UnknownAuthorityError
	if errors.As(err, &authErr) {
		return tlsFailure(tlsKindCertificateNotTrusted, peer, authErr.Cert)
	}

	// Row 3/3b: an otherwise-valid chain x509 itself rejected. Expired is the
	// ONE reason split further, into expired vs. not-yet-valid (below); every
	// other reason (row 3b) is handshake_failed.
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		if invalidErr.Reason == x509.Expired {
			return classifyExpiryReason(invalidErr, peer)
		}
		return tlsFailure(tlsKindHandshakeFailed, peer, invalidErr.Cert)
	}

	// Row 4: *tls.CertificateVerificationError is the ONLY POINTER type among
	// these probes. It is tried LAST of the certificate-shaped probes,
	// deliberately: its Unwrap() reaches the same x509 types rows 1-3 already
	// tried, so probing it first would swallow every specific cause into
	// this generic arm. Reaching here means rows 1-3 already tried and
	// missed, so this row only ever fires for a certificate failure none of
	// x509's three named causes described.
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &verifyErr) {
		var leaf *x509.Certificate
		if len(verifyErr.UnverifiedCertificates) > 0 {
			leaf = verifyErr.UnverifiedCertificates[0]
		}
		return tlsFailure(tlsKindHandshakeFailed, peer, leaf)
	}

	// Row 5: the peer answered the TCP/TLS port with something that is not
	// TLS at all (or closed the connection before a client/server hello
	// completed). No certificate was ever seen, so detail carries no
	// subject/fingerprint.
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return tlsFailure(tlsKindHandshakeFailed, peer, nil)
	}

	// No probe matched: return err UNCHANGED. No tls_failure, no detail.
	// This is the required fallback (Rule 9 criterion 3) — do not add a
	// catch-all arm here.
	return err
}

// classifyExpiryReason splits x509.Expired (row 3) into
// certificate_expired vs. certificate_not_yet_valid. The Reason enum alone
// cannot tell the two apart — RFC 5280 validity-window violations both
// surface as x509.Expired — so the split compares the CERTIFICATE'S OWN
// validity window against wall time, NOT any injected/fake clock: x509
// verified against wall time when it produced this error, so a fakeclock
// reading would disagree with the error that was actually produced.
func classifyExpiryReason(invalidErr x509.CertificateInvalidError, peer string) error {
	cert := invalidErr.Cert
	if cert == nil {
		// Defensive: no certificate to compare against, fall through to the
		// generic classification rather than guessing which side of the
		// window it was on.
		return tlsFailure(tlsKindHandshakeFailed, peer, nil)
	}
	if time.Now().Before(cert.NotBefore) {
		return tlsFailure(tlsKindCertificateNotYetValid, peer, cert)
	}
	return tlsFailure(tlsKindCertificateExpired, peer, cert)
}

// tlsFailureMessages gives each of the five closed kinds a human-readable
// sentence for apierr.Error.Message.
var tlsFailureMessages = map[string]string{
	tlsKindHostnameMismatch:       "the peer certificate does not match the dialled address",
	tlsKindCertificateNotTrusted:  "the peer certificate does not chain to a trusted CA",
	tlsKindCertificateExpired:     "the peer certificate has expired",
	tlsKindCertificateNotYetValid: "the peer certificate is not yet valid",
	tlsKindHandshakeFailed:        "the TLS handshake failed",
}

// tlsFailure builds the apierr.TLSFailure detail payload: peer always,
// subject/fingerprint only when cert is non-nil (row 5, or a defensive
// fallback with none available, carry neither).
func tlsFailure(kind, peer string, cert *x509.Certificate) error {
	detail := map[string]any{"peer": peer}
	if cert != nil {
		sum := sha256.Sum256(cert.Raw)
		detail["subject"] = cert.Subject.String()
		detail["fingerprint"] = hex.EncodeToString(sum[:])
	}
	return apierr.TLSFailure(kind, detail, tlsFailureMessages[kind])
}
