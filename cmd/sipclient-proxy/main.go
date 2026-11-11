// Package main is the sipclient-proxy entry point: a local stdio MCP proxy that
// injects SIP account credentials by NAME so passwords never reach the model.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/proxy"
)

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// realMain returns the process exit code. In serve mode stdout carries only
// MCP frames; every diagnostic goes to stderr.
func realMain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "configure" {
		return runConfigure(args[1:], stdin, stdout, stderr)
	}
	cfg, err := parseServeFlags(args, proxy.DefaultConfigPathFromEnv)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "sipclient-proxy:", err)
		return 2
	}
	if cfg.ShowVersion {
		_, _ = fmt.Fprintln(stdout, versionString())
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	in, ok := stdin.(io.ReadCloser)
	if !ok {
		in = io.NopCloser(stdin)
	}
	out, ok := stdout.(io.WriteCloser)
	if !ok {
		out = nopWriteCloser{stdout}
	}
	if err := serve(ctx, cfg, in, out, stderr); err != nil {
		_, _ = fmt.Fprintln(stderr, "sipclient-proxy:", err)
		return 1
	}
	return 0
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func serve(ctx context.Context, cfg serveConfig, in io.ReadCloser, out io.WriteCloser, stderr io.Writer) error {
	if _, err := os.Stat(cfg.ConfigPath); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("config file %s not found; run 'sipclient-proxy configure' to create it", cfg.ConfigPath)
	}
	if w := proxy.PermissionWarning(cfg.ConfigPath); w != "" {
		_, _ = fmt.Fprintln(stderr, w)
	}
	cleartext := proxy.InsecureUpstreamWarning(cfg.ConfigPath)
	if cleartext != "" {
		_, _ = fmt.Fprintln(stderr, cleartext)
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if cleartext != "" {
		logger.Warn("allow_insecure_http is set: the daemon bearer token travels in cleartext") // no host: the logger carries no config contents
	}
	r := proxy.New(proxy.Options{ConfigPath: cfg.ConfigPath, Version: version, Log: logger})
	if err := r.Run(ctx, &sdk.IOTransport{Reader: in, Writer: out}); !errors.Is(err, context.Canceled) {
		return err // SIGINT/SIGTERM (a cancelled context) is a normal way to stop: exit 0
	}
	return nil
}
