package mcp

import "github.com/sanntsu-corporation/sipclient-mcp/internal/session"

// Contract Part 3: Manager satisfies Sessions and Admin directly; ToolService
// satisfies Tools. These live HERE and not in internal/session, because
// `var _ mcp.Sessions = (*session.Manager)(nil)` inside session would make
// session import transport/mcp and invert §6.2's layering.
var (
	_ Sessions = (*session.Manager)(nil)
	_ Admin    = (*session.Manager)(nil)
	_ Tools    = (*session.ToolService)(nil)
)
