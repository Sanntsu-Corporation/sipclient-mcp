package sipua_test

import (
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
)

// Compile-time proof that *UA satisfies §6.2.1's UserAgent. Go requires an
// EXACT signature match, so LocalAddr() must return net.Addr (U17), never
// *net.UDPAddr. If this stops compiling, fix the METHOD, never the assertion.
var _ session.UserAgent = (*sipua.UA)(nil)
