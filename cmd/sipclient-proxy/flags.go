package main

import (
	"flag"
	"fmt"
	"io"
)

type serveConfig struct {
	ConfigPath  string
	ShowVersion bool
}

// parseServeFlags parses serve-mode flags. defaultPath is consulted only when
// --config is absent and --version is not requested.
func parseServeFlags(args []string, defaultPath func() (string, error)) (serveConfig, error) {
	var cfg serveConfig
	fs := flag.NewFlagSet("sipclient-proxy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.ConfigPath, "config", "", "path to sipclient-proxy.json (default: per-user config directory)")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return serveConfig{}, err
	}
	if fs.NArg() > 0 {
		return serveConfig{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if cfg.ShowVersion {
		return cfg, nil
	}
	if cfg.ConfigPath == "" {
		p, err := defaultPath()
		if err != nil {
			return serveConfig{}, err
		}
		cfg.ConfigPath = p
	}
	return cfg, nil
}
