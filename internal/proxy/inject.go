package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ownedFields are the ua_create fields an account fully determines (spec 5).
// Order matters only for which one a ConflictError names first. If the daemon
// ever adds another credential-bearing field, add it here and nowhere else.
var ownedFields = []string{"mode", "transport", "registrar", "aor", "auth_user", "auth_pass", "auth_any_host"}

// ConflictError reports "account" combined with an account-owned field.
type ConflictError struct{ Field string }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("ua_create: \"account\" cannot be combined with %q. The account supplies mode, transport, registrar, aor, auth_user, auth_pass and auth_any_host itself; remove %q or omit \"account\".", e.Field, e.Field)
}

// Inject completes ua_create arguments from a named account. See the plan,
// Task 2, for the rules. resolve is invoked only when "account" is present.
func Inject(args json.RawMessage, resolve func(name string) (Account, error)) (json.RawMessage, *Account, error) {
	trimmed := bytes.TrimSpace(args)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return args, nil, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return args, nil, nil // not our business; the daemon will reject it
	}
	rawName, has := m["account"]
	if !has {
		return args, nil, nil
	}
	var name string
	if err := json.Unmarshal(rawName, &name); err != nil || name == "" {
		return nil, nil, errors.New(`ua_create: "account" must be a non-empty string naming an account (call account_list)`)
	}
	// Presence, not value, and not spelling: Go's JSON decoder matches object keys
	// case-insensitively (using Unicode simple folding, so "Registrar" and even
	// "tranſport" with U+017F match), so an exact-key check could be sidestepped.
	// strings.EqualFold folds exactly like the decoder does.
	for _, f := range ownedFields {
		for k := range m {
			if strings.EqualFold(k, f) {
				return nil, nil, &ConflictError{Field: f}
			}
		}
	}
	acct, err := resolve(name)
	if err != nil {
		return nil, nil, err
	}
	delete(m, "account")
	set := func(k, v string) { m[k] = jsonString(v) }
	set("mode", acct.Mode)
	set("transport", acct.Transport)
	set("auth_user", acct.Username)
	set("auth_pass", acct.Password)
	if acct.AuthAnyHost {
		m["auth_any_host"] = json.RawMessage("true")
	}
	if acct.Mode == ModeRegister {
		host := acct.uriHost() // IPv6 literals are bracketed
		set("registrar", fmt.Sprintf("sip:%s:%d", host, acct.Port))
		set("aor", "sip:"+escapeUserinfo(acct.Username)+"@"+host)
	}
	return encodeObject(m), &acct, nil
}

// escapeUserinfo percent-encodes username for the user part of a SIP URI
// (RFC 3261 section 19.1.2: "For each component, the set of valid BNF expansions
// defines exactly which characters may appear unescaped.  All other characters
// MUST be escaped."; section 25.1: unreserved / user-unreserved stay literal, every other
// byte - including ':', '@', '%', space and non-ASCII - becomes %XX). auth_user
// is NOT escaped: it is a digest username, not a URI component.
func escapeUserinfo(u string) string {
	const keep = "-_.!~*'()&=+$,;?/"
	var b strings.Builder
	for i := 0; i < len(u); i++ {
		c := u[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(keep, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// jsonString encodes s without HTML escaping.
func jsonString(s string) json.RawMessage {
	return json.RawMessage(`"` + jsonInner(s, false) + `"`)
}

// encodeObject writes m with sorted keys and VERBATIM values. json.Marshal
// would compact RawMessage values, which breaks Inject's byte-exact pass-through.
func encodeObject(m map[string]json.RawMessage) json.RawMessage {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(jsonString(k))
		b.WriteByte(':')
		b.Write(m[k])
	}
	b.WriteByte('}')
	return b.Bytes()
}
