// Command loop is the standing loop-call interop gate (P2 Wave-1 exit
// criterion, spec §14.5; extended by Task 33 for P3's DTMF/session-timer/
// keepalive acceptance). It spawns a LOCAL sipclient-mcpd, drives it over
// MCP-over-HTTP with the go-sdk streamable client, and runs the loop-call
// scenarios against the Asterisk rig (ext 720/721/605) — caller =
// direct-mode UA e2e-uac-direct, callee = register-mode UA e2e-uac-register,
// bridged by the Asterisk rig — plus Task 33's own local stubs
// (RULING 2) for the session-timer peer-refresher/in-dialog-timeout halves,
// keepalive, and the three local-receiver DTMF scenarios (dtmf_receiver.go)
// that prove our RX decode path. DTMF also reaches the rig: ext 602
// (Read/SayDigits) is dialled by scenarioDTMFRFC2833Rig, the §14.5
// third-party proof of our TX encoding.
//
// TRANSPORT (owner-ratified 2026-07-21): the daemon serves MCP over HTTP only
// (no stdio transport exists), so the gate spawns it with
// `--listen 127.0.0.1:<port>` and connects a go-sdk StreamableClientTransport.
//
// Three entry points:
//
//	go run ./e2e/loop            # the full gate: N/N (whatever gate.go's slice
//	                             # holds), exit 0 iff all pass
//	go run ./e2e/loop -sanity    # non-live: an inline-account ua_create/
//	                             # ua_destroy round-trip + tools/list only,
//	                             # emits NO SIP to the rig
//	go run ./e2e/loop -transport tcp|tls
//	                             # T7 (P2 W2c, §14.5): real-peer inbound+
//	                             # outbound interop over TCP/TLS instead of
//	                             # the standing UDP gate above (mutually
//	                             # exclusive with the unflagged run).
//
// CF-001 is resolved: the multi-UA-per-session wave
// removed the 1-UA-per-session cap the live paths below used to hit. rig
// already created its caller (direct mode) and callee (register mode) UA on
// one MCP session (see gate.go's rig.setup) — that shape needed no change,
// only policy.yaml's own max_uas_per_session: 2.
//
// The scenarios reach a real PBX; run them only against a healthy rig (see
// e2e/loop/README.md). DTMF (#4) is implemented as of Task 33 (P3):
// scenarioDTMFRFC2833/Inband/Info and scenarioDTMFRFC2833Rig in
// scenarios_p3.go.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	def := defaultGateConfig()
	// Env defaults, overridden by the flags below; the same names gate_test.go
	// reads (see e2e/asterisk/README.md).
	if v := os.Getenv("SIPCLIENT_E2E_ASTERISK"); v != "" {
		def.asteriskIP = v
	}
	if v := os.Getenv("SIPCLIENT_E2E_LOCAL"); v != "" {
		def.localAddr = v
	}
	if v := os.Getenv("SIPCLIENT_E2E_SSH"); v != "" {
		def.sshTarget = v
	}
	fs := flag.NewFlagSet("loop", flag.ContinueOnError)
	var (
		sanity    = fs.Bool("sanity", false, "non-live plumbing check only (inline-account ua_create/ua_destroy + tools/list); emits no SIP")
		asterisk  = fs.String("asterisk", def.asteriskIP, "Asterisk rig IP the caller dials and the callee registers to")
		local     = fs.String("local", def.localAddr, "local_addr both UAs bind (this host on the rig LAN)")
		sshHost   = fs.String("ssh", def.sshTarget, "ssh target for Asterisk cross-checks and the ext-602 DTMF assertion; empty disables the cross-checks and fails that scenario")
		port      = fs.Int("port", 0, "daemon --listen port; 0 picks a free one")
		verbose   = fs.Bool("v", false, "verbose: stream the daemon's stderr")
		transport = fs.String("transport", "", "T7 (§14.5): run only the real-peer tcp|tls gate instead of the standing UDP 8/8 gate; empty (default) runs the UDP gate unmodified")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *transport != "" && *transport != "tcp" && *transport != "tls" {
		fmt.Fprintf(os.Stderr, "invalid -transport %q: want \"tcp\" or \"tls\"\n", *transport)
		os.Exit(2)
	}

	// -sanity emits no SIP, so only the live gate needs a real rig address.
	if !*sanity && *asterisk == placeholderAddr {
		fmt.Fprintln(os.Stderr, "SIPCLIENT_E2E_ASTERISK is not set (RIG_HOST via run.sh, or pass -asterisk): see e2e/asterisk/README.md")
		os.Exit(2)
	}

	// The whole run is bounded and Ctrl-C-interruptible; the deferred daemon
	// kill in run() guarantees no orphaned daemon on any exit path.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := def
	cfg.sanity = *sanity
	cfg.asteriskIP = *asterisk
	cfg.localAddr = *local
	cfg.sshTarget = *sshHost
	cfg.listenPort = *port
	cfg.verbose = *verbose
	cfg.transport = *transport

	if err := run(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "\nFATAL: %v\n", err)
		os.Exit(1)
	}
}

type gateConfig struct {
	sanity      bool
	asteriskIP  string
	localAddr   string
	sshTarget   string
	listenPort  int
	verbose     bool
	dialPort    int
	registerP   string // register-mode account name (accounts.go)
	directP     string // direct-mode account name (accounts.go)
	readyWait   time.Duration
	startupWait time.Duration
	transport   string // T7: "" runs the UDP gate (gate.go, unmodified); "tcp"/"tls" dispatches to tcptls.go
}

// placeholderAddr is the default for -asterisk and -local: a deliberately
// unusable stand-in so no rig address is baked in. The standalone binary
// refuses to run the gate while -asterisk is still this value.
const placeholderAddr = "127.0.0.1"

// defaultGateConfig is the gate's default configuration, shared by main()'s
// flag defaults and by gate_test.go's TestE2EGate (D4, Phase 4 W2). It exists
// so the two entry points cannot drift: before D4 the only defaults lived
// inline in main()'s flag declarations, so a go test wrapper would have had to
// duplicate the rig's IP addresses and account names — the kind of copy that is
// correct on the day it is written and wrong six weeks later.
func defaultGateConfig() gateConfig {
	return gateConfig{
		asteriskIP:  placeholderAddr,
		localAddr:   placeholderAddr,
		sshTarget:   "",
		dialPort:    5070,
		registerP:   "e2e-uac-register",
		directP:     "e2e-uac-direct",
		readyWait:   15 * time.Second,
		startupWait: 20 * time.Second,
	}
}

// run owns the daemon lifecycle and dispatches to the sanity or full path.
func run(ctx context.Context, cfg gateConfig) error {
	d, err := startDaemon(ctx, cfg, false)
	if err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}
	defer d.stop()

	// Plumbing proof, always: an inline-account ua_create/ua_destroy
	// round-trip and the P1 tool set. This is the whole of -sanity and the
	// preamble of the gate. It runs BEFORE the gate's own client is connected
	// and on a session of its own — see checkPlumbing for why that is
	// mandatory rather than tidy.
	if err := checkPlumbing(ctx, d, cfg); err != nil {
		return err
	}
	if cfg.sanity {
		fmt.Println("\nnon-live sanity OK (daemon start -> MCP/HTTP -> ua_create/ua_destroy + tools/list -> shutdown)")
		return nil
	}

	cl, err := connectClient(ctx, d.endpoint, d.bearer)
	if err != nil {
		return fmt.Errorf("connect MCP client: %w", err)
	}
	defer cl.close()

	// T7 (P2 W2c, §14.5): -transport tcp|tls dispatches to the real-peer
	// TCP/TLS driver (tcptls.go) INSTEAD OF the standing UDP gate below.
	// runGate itself (gate.go) is untouched — the unflagged path is exactly
	// the pre-T7 behaviour, which is the regression-isolation property T7
	// requires.
	if cfg.transport != "" {
		callHandle, err := runTransportGate(ctx, cl, cfg, cfg.transport)
		if err != nil {
			return err
		}
		path, perr := artifactPath(callHandle, "capture.pcap")
		if perr != nil {
			fmt.Printf("note: could not resolve capture artifact path: %v\n", perr)
		} else {
			fmt.Printf("capture artifact (on disk): %s\n", path)
		}
		return nil
	}

	return runGate(ctx, cl, cfg)
}
