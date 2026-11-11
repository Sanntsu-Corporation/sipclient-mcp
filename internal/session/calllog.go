package session

import "strings"

// SanitizeToURI strips SIP userinfo credentials from a to_uri before it is
// written to the N5 per-call log record (§2.5.5, locked decision 6). A
// "user:password@host" userinfo has its password removed; a bare "user@host"
// or a scheme-less "host:port" passes through unchanged.
//
// THIS IS THE ONE PLACE the per-call log's to_uri column is sanitised. Decision
// 6's whole point is that "no credential ever appears in any log line" is
// assertable against ONE code path rather than growing with every phase that
// adds a column.
func SanitizeToURI(uri string) string {
	if uri == "" {
		return uri
	}
	// The LAST "@" separates userinfo from the host: a password may itself
	// contain "@" (a pathological but real case), so the FIRST "@" would cut
	// it off mid-password rather than at the host boundary.
	at := strings.LastIndex(uri, "@")
	if at < 0 {
		return uri
	}
	userinfo := uri[:at]

	// userinfo is "scheme:user[:password]". The scheme colon is always
	// present and is not itself a credential separator; only a SECOND colon,
	// after the scheme, introduces a password.
	scheme := strings.IndexByte(userinfo, ':')
	if scheme < 0 {
		return uri // no recognisable scheme; nothing to sanitise
	}
	if pw := strings.IndexByte(userinfo[scheme+1:], ':'); pw >= 0 {
		return userinfo[:scheme+1+pw] + uri[at:]
	}
	return uri
}
