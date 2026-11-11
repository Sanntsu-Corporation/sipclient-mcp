package main

import "fmt"

// Injected at link time via -ldflags -X (locked decision 16). The defaults are
// what an un-stamped `go build` produces.
//
// These identifiers are deliberately unexported and live in package main only:
// decision 16 forbids the version from appearing in /healthz (spec §12.2 requires
// that endpoint to disclose nothing), and keeping them out of internal/ means no
// handler can reference them without a new export.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func versionString() string {
	return fmt.Sprintf("sipclient-mcpd %s (commit %s, built %s)", version, commit, buildDate)
}
