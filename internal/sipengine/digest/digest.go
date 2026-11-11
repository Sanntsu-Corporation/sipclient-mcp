package digest

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

type Challenge struct {
	Realm     string
	Nonce     string
	Qop       string
	Algorithm string
	Opaque    string
}

type Response struct {
	Username  string
	Realm     string
	Nonce     string
	URI       string
	Response  string
	Algorithm string
	Qop       string
	Nc        string
	Cnonce    string
	Opaque    string
}

var kvRe = regexp.MustCompile(`(\w+)=("([^"]*)"|([^,\s]*))`)

// Parse `WWW-Authenticate: Digest realm="x", nonce="y", qop="auth"`
func ParseChallenge(h string) (Challenge, error) {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(strings.ToLower(h), "digest") {
		h = strings.TrimSpace(h[len("digest"):])
	}
	m := map[string]string{}
	for _, m0 := range kvRe.FindAllStringSubmatch(h, -1) {
		key := strings.ToLower(m0[1])
		val := m0[3]
		if val == "" {
			val = m0[4]
		}
		m[key] = val
	}
	c := Challenge{
		Realm:     m["realm"],
		Nonce:     m["nonce"],
		Qop:       pickQop(m["qop"]),
		Algorithm: m["algorithm"],
		Opaque:    m["opaque"],
	}
	if c.Algorithm == "" {
		c.Algorithm = "MD5"
	}
	if c.Realm == "" || c.Nonce == "" {
		return Challenge{}, fmt.Errorf("missing realm/nonce in challenge")
	}
	return c, nil
}

func pickQop(q string) string {
	q = strings.ReplaceAll(q, `"`, "")
	parts := strings.Split(q, ",")
	for _, p := range parts {
		if strings.TrimSpace(p) == "auth" {
			return "auth"
		}
	}
	return strings.TrimSpace(q) // may be "" (legacy)
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Compute client digest response (MD5, qop=auth)
func ComputeAuthorization(user, pass, method, uri string, ch Challenge, nc int) Response {
	ncStr := fmt.Sprintf("%08x", nc)
	cnonce := randHex(8)

	ha1 := md5hex(fmt.Sprintf("%s:%s:%s", user, ch.Realm, pass))
	ha2 := md5hex(fmt.Sprintf("%s:%s", method, uri))

	var resp string
	if ch.Qop != "" {
		resp = md5hex(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, ch.Nonce, ncStr, cnonce, ch.Qop, ha2))
	} else {
		resp = md5hex(fmt.Sprintf("%s:%s:%s", ha1, ch.Nonce, ha2))
	}

	return Response{
		Username:  user,
		Realm:     ch.Realm,
		Nonce:     ch.Nonce,
		URI:       uri,
		Response:  resp,
		Algorithm: ch.Algorithm,
		Qop:       ch.Qop,
		Nc:        ncStr,
		Cnonce:    cnonce,
		Opaque:    ch.Opaque,
	}
}

// Format Authorization header value (no leading "Authorization:")
func (r Response) HeaderValue() string {
	base := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=%s`,
		r.Username, r.Realm, r.Nonce, r.URI, r.Response, r.Algorithm)

	if r.Opaque != "" {
		base += fmt.Sprintf(`, opaque="%s"`, r.Opaque)
	}
	if r.Qop != "" {
		base += fmt.Sprintf(`, qop=%s, nc=%s, cnonce="%s"`, r.Qop, r.Nc, r.Cnonce)
	}
	return base
}

// Parse Authorization header into key/value fields (PoC-grade parser).
func ParseAuthorization(h string) (map[string]string, error) {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(strings.ToLower(h), "digest") {
		h = strings.TrimSpace(h[len("digest"):])
	}
	m := map[string]string{}
	for _, m0 := range kvRe.FindAllStringSubmatch(h, -1) {
		key := strings.ToLower(m0[1])
		val := m0[3]
		if val == "" {
			val = m0[4]
		}
		m[key] = val
	}
	if m["username"] == "" || m["realm"] == "" || m["nonce"] == "" || m["uri"] == "" || m["response"] == "" {
		return nil, fmt.Errorf("incomplete digest fields")
	}
	return m, nil
}

func VerifyMD5Auth(user, pass, method string, fields map[string]string) bool {
	realm := fields["realm"]
	nonce := fields["nonce"]
	uri := fields["uri"]
	qop := fields["qop"]
	nc := fields["nc"]
	cnonce := fields["cnonce"]
	resp := fields["response"]

	ha1 := md5hex(fmt.Sprintf("%s:%s:%s", user, realm, pass))
	ha2 := md5hex(fmt.Sprintf("%s:%s", method, uri))

	var expected string
	if qop != "" {
		expected = md5hex(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, nonce, nc, cnonce, qop, ha2))
	} else {
		expected = md5hex(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))
	}
	return strings.EqualFold(resp, expected)
}
