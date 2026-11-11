package artifact

import "github.com/sanntsu-corporation/sipclient-mcp/internal/session"

var _ session.ArtifactStore = (*Store)(nil)
