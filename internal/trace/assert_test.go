package trace

import "github.com/sanntsu-corporation/sipclient-mcp/internal/session"

// §6.2.1's acceptance. Note the concrete type is Sink, NOT trace.Tap — the
// latter would collide confusingly with session.Tap.
var _ session.Tap = (*Sink)(nil)
