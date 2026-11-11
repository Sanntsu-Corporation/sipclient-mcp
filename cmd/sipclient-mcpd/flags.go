package main

import (
	"flag"
	"io"
)

type daemonConfig struct {
	PolicyPath  string
	ListenAddr  string
	ShowVersion bool
	// StatePath is Phase 2's --state (§2.2): where the daemon persists its
	// own generated configuration (auth token PATHS, and whatever
	// config_set has since changed). Always non-empty after parseFlags: an
	// omitted --state resolves to defaultStatePath() (bootstrap.go), never
	// left blank for run() to guess at.
	StatePath string
	// PrintTokens is Phase 2's --print-tokens (§2.2 item 4): read the two
	// token files under --state and print them, then exit without starting
	// a listener.
	PrintTokens bool
}

// parseFlags deliberately exposes NO --shutdown-grace flag: the grace period
// is limits.shutdown_grace_period in policy, read by both §11.4's shutdown and
// §12.7's admin DELETE. A flag would be a second source for one number.
//
// --policy is NO LONGER REQUIRED (Phase 2 §2.5): the daemon mints its own
// credentials and a complete default state file on first run (§2.2/§2.2a),
// so a genuinely fresh operator needs neither flag to reach a working,
// authenticated daemon. --policy, when given on that same first run, is a
// ONE-SHOT SEED (§2.5) rather than the daemon's ongoing config source — see
// bootstrap.go.
func parseFlags(args []string) (daemonConfig, error) {
	var cfg daemonConfig
	fs := flag.NewFlagSet("sipclient-mcpd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.PolicyPath, "policy", "", "path to a policy YAML file; a one-shot seed on first run only (optional)")
	fs.StringVar(&cfg.ListenAddr, "listen", "127.0.0.1:8080", "HTTP listen address")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "print version and exit")
	fs.StringVar(&cfg.StatePath, "state", "", "path to the daemon's own state file (default: $XDG_STATE_HOME/sipclient-mcp/state.yaml, or ~/.local/state/sipclient-mcp/state.yaml)")
	fs.BoolVar(&cfg.PrintTokens, "print-tokens", false, "print the bearer and admin tokens from --state and exit")
	if err := fs.Parse(args); err != nil {
		return daemonConfig{}, err
	}
	if cfg.ShowVersion {
		return cfg, nil
	}
	if cfg.StatePath == "" {
		p, err := defaultStatePath()
		if err != nil {
			return daemonConfig{}, err
		}
		cfg.StatePath = p
	}
	return cfg, nil
}
