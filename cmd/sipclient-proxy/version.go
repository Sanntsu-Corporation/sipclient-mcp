package main

import "fmt"

// Injected at link time via -ldflags -X (same convention as cmd/sipclient-mcpd).
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func versionString() string {
	return fmt.Sprintf("sipclient-proxy %s (commit %s, built %s)", version, commit, buildDate)
}
