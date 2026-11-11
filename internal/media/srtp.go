package media

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// SuiteAESCM128HMACSHA180 is the one SDES suite this harness offers. Its key
// material is a 16-byte master key concatenated with a 14-byte master salt,
// base64-encoded as one 30-byte block per RFC 4568 §6.1.
const SuiteAESCM128HMACSHA180 = "AES_CM_128_HMAC_SHA1_80"

// CryptoParams is the SDES key material for one media stream. W4 feeds MasterKey
// and MasterSalt straight into pion/srtp.CreateContext with no re-negotiation
// (M4), which is why they are real bytes now, not placeholders.
type CryptoParams struct {
	Suite      string
	MasterKey  [16]byte
	MasterSalt [14]byte
	// Lifetime is the peer's key lifetime in SRTP packets (RFC 4568 6.1), 0 when
	// the line signalled none (the suite maximum, 2^48, applies).
	Lifetime uint64
}

// offerCryptoTag is the one tag BuildOffer writes (RFC 4568 4.1).
const offerCryptoTag = "1"

// maxKeyLifetime is the AES_CM_128_HMAC_SHA1_80 maximum, 2^48 SRTP packets
// (RFC 4568 6.2).
const maxKeyLifetime = uint64(1) << 48

// GenerateCryptoAttr mints a fresh master key+salt from crypto/rand and renders
// the full RFC 4568 SDP line with crypto tag 1.
func GenerateCryptoAttr() (CryptoParams, string, error) {
	cp := CryptoParams{Suite: SuiteAESCM128HMACSHA180}
	var raw [30]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return CryptoParams{}, "", fmt.Errorf("crypto/rand: %w", err)
	}
	copy(cp.MasterKey[:], raw[:16])
	copy(cp.MasterSalt[:], raw[16:])
	return cp, cp.AttrLine(), nil
}

// AttrLine renders cp as the RFC 4568 SDP line with crypto tag 1.
func (cp CryptoParams) AttrLine() string { return cp.attrLine(offerCryptoTag) }

// attrLine renders cp as the SDP line with the given tag (an answer echoes the
// tag of the offer line it accepted, RFC 4568 5.1.2). No lifetime is written.
func (cp CryptoParams) attrLine(tag string) string {
	var raw [30]byte
	copy(raw[:16], cp.MasterKey[:])
	copy(raw[16:], cp.MasterSalt[:])
	return fmt.Sprintf("a=crypto:%s %s inline:%s", tag, cp.Suite, base64.StdEncoding.EncodeToString(raw[:]))
}

// ParseCryptoAttr parses an RFC 4568 crypto line (with or without the leading
// "a=crypto:") back into CryptoParams; see parseCryptoLine for what it accepts.
func ParseCryptoAttr(line string) (CryptoParams, error) {
	_, cp, err := parseCryptoLine(line)
	return cp, err
}

// parseCryptoLine parses one crypto line into its tag and key. It accepts only
// a line this SRTP layer can run: the one supported suite, one "inline:" key of
// 30 decoded bytes, an optional valid key lifetime, and no MKI or session
// parameter except a well-formed WSH= or a "-"-prefixed one (RFC 4568 6.3.6,
// 6.3.7), which a receiver may ignore. Anything else makes the line unusable,
// so a later supported line can be taken instead (CF-187).
func parseCryptoLine(line string) (tag string, cp CryptoParams, err error) {
	s := strings.TrimPrefix(strings.TrimSpace(line), "a=crypto:")
	fields := strings.Fields(s)
	if len(fields) < 3 {
		return "", CryptoParams{}, fmt.Errorf("crypto line has too few fields: %q", line)
	}
	tag, suite, keyParams := fields[0], fields[1], fields[2]
	if !validCryptoTag(tag) {
		return "", CryptoParams{}, fmt.Errorf("crypto tag %q is not 1 to 9 digits without a leading zero", tag)
	}
	if suite != SuiteAESCM128HMACSHA180 {
		return "", CryptoParams{}, fmt.Errorf("unsupported crypto suite %q", suite)
	}
	inline, ok := strings.CutPrefix(keyParams, "inline:")
	if !ok || strings.Contains(inline, ";") {
		return "", CryptoParams{}, fmt.Errorf("crypto key-params is not one inline: key")
	}
	inline, rest, hasRest := strings.Cut(inline, "|")
	if hasRest {
		// Anything but one lifetime fails here: an MKI ("1:4") and a second
		// segment are not digits.
		if cp.Lifetime, ok = parseKeyLifetime(rest); !ok {
			return "", CryptoParams{}, fmt.Errorf("crypto key lifetime %q is invalid", rest)
		}
	}
	for _, p := range fields[3:] {
		if !supportedSessionParam(p) {
			return "", CryptoParams{}, fmt.Errorf("crypto session parameter %q unsupported", p)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(inline)
	if err != nil {
		return "", CryptoParams{}, fmt.Errorf("crypto inline base64: %w", err)
	}
	if len(raw) != 30 {
		return "", CryptoParams{}, fmt.Errorf("crypto inline decoded to %d bytes, want 30", len(raw))
	}
	cp.Suite = suite
	copy(cp.MasterKey[:], raw[:16])
	copy(cp.MasterSalt[:], raw[16:])
	return tag, cp, nil
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// validCryptoTag is RFC 4568 4.1 / 9.1: 1*9DIGIT, no leading zero.
func validCryptoTag(t string) bool {
	return len(t) <= 9 && isDigits(t) && (t == "0" || t[0] != '0')
}

// parseKeyLifetime is RFC 4568 6.1 / 9.1, lifetime = ["2^"] 1*DIGIT: no leading
// zero, at most the suite maximum 2^48. It returns the lifetime in packets.
func parseKeyLifetime(s string) (uint64, bool) {
	if e, ok := strings.CutPrefix(s, "2^"); ok {
		if len(e) > 2 || !isDigits(e) || (len(e) == 2 && e[0] == '0') {
			return 0, false
		}
		n, _ := strconv.Atoi(e)
		if n > 48 {
			return 0, false
		}
		return uint64(1) << n, true
	}
	if len(s) > 15 || !isDigits(s) || s[0] == '0' {
		return 0, false
	}
	n, _ := strconv.ParseUint(s, 10, 64)
	return n, n <= maxKeyLifetime
}

// supportedSessionParam reports whether a crypto session parameter may be
// ignored: WSH= (any case; declarative, 2*DIGIT >= 64, no leading zero; RFC 4568 6.3.6) or
// one prefixed "-" (6.3.7). KDR=, UNENCRYPTED_*, UNAUTHENTICATED_SRTP, FEC_* and
// unknown parameters are ones this layer cannot honour (7.1.2) or must treat as
// invalid (6.3.7).
func supportedSessionParam(p string) bool {
	if strings.HasPrefix(p, "-") {
		return true
	}
	// Parameter names are case-insensitive (RFC 4568 4); the value is digits.
	if len(p) < 4 || !strings.EqualFold(p[:4], "WSH=") {
		return false
	}
	v := p[4:]
	if !isDigits(v) || v[0] == '0' {
		return false
	}
	n, err := strconv.ParseUint(v, 10, 64)
	return err == nil && n >= 64
}
