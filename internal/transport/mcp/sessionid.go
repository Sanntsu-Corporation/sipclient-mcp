package mcp

import (
	"crypto/rand"
	"encoding/hex"
)

// sessionIDHeader is the MCP streamable-HTTP session identity header (§12.6).
const sessionIDHeader = "Mcp-Session-Id"

// newSessionID returns a §12.6 logical session id: 128 bits of CSPRNG output,
// rendered hex, with NO prefix. Locked decision 12 prefixes ua_/call_ handles
// for log readability; session ids are deliberately unprefixed and are never
// parsed for anything.
func newSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read never returns an error on any supported platform;
		// if it ever does, issuing a guessable session id is not an option.
		panic("sipclient-mcp: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
