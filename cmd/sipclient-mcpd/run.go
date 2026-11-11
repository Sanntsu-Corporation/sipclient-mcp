package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/artifact"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/metrics"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/trace"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/transport/mcp"
)

func run(ctx context.Context, cfg daemonConfig, stdout io.Writer, logger *slog.Logger) error {
	if cfg.ShowVersion {
		_, err := fmt.Fprintln(stdout, versionString())
		return err
	}
	// Phase 2 §2.2 item 4: --print-tokens reads the two token files under
	// --state and exits WITHOUT starting a listener — handled here, before
	// the daemon context or anything else is built, the same early-return
	// shape --version already uses just above.
	if cfg.PrintTokens {
		return printTokens(filepath.Dir(cfg.StatePath), stdout)
	}

	// LOCKED DECISION 17. This is the daemon context: it owns every UA and
	// every call goroutine, and it is cancelled ONLY by a shutdown signal.
	// It is deliberately derived from the process context, NEVER from an
	// http.Request. Wiring a request context into a call's lifetime would
	// break D11 point 5 and R8. See context_test.go (Task 20b).
	daemonCtx, stopDaemon := context.WithCancel(context.Background())
	defer stopDaemon()

	clk := clock.System()
	started := clk.Now()

	// Phase 2 §2.2/§2.2a/§2.5's bootstrap: mint credentials on a genuine
	// first run, then construct the state file EXACTLY ONE of two ways —
	// from policy.Defaults() (§2.2a, no --policy) or seeded from --policy
	// (§2.5, one-shot, auth overridden) — before ever constructing the
	// Store that reads it. Neither bootstrap function runs when the state
	// file already exists; --policy is then vestigial (WARN only).
	// THE FIRST-RUN CONDITION IS THE STATE FILE'S ABSENCE, AND MINTING IS
	// GATED ON IT TOO. mintTokensIfAbsent used to run unconditionally, ahead
	// of this stat, and its own idempotency check keys on the two token files
	// under stateDir — not on the state file. A daemon started against an
	// EXISTING state.yaml whose auth.bearer_token_file/auth.admin_token_file
	// point somewhere else therefore found no token file under stateDir,
	// minted two fresh ones, and printed the "FIRST RUN — generated
	// credentials (shown ONCE)" banner for two values that authenticate
	// nothing (--print-tokens, which reads the same two stateDir paths, then
	// reported those same wrong values). There is no "partial" first run: a
	// state file that exists is a daemon that already has its credentials
	// wherever its own auth.* says they are, and policy.NewStore below fails
	// loudly if one of them is missing.
	stateDir := filepath.Dir(cfg.StatePath)
	_, statErr := os.Stat(cfg.StatePath)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		bearerPath, adminPath, err := mintTokensIfAbsent(stateDir, stdout, logger)
		if err != nil {
			return fmt.Errorf("mint credentials: %w", err)
		}
		if cfg.PolicyPath != "" {
			if err := bootstrapSeedFromPolicy(cfg.StatePath, cfg.PolicyPath, bearerPath, adminPath, logger); err != nil {
				return fmt.Errorf("seed state file from --policy: %w", err)
			}
		} else {
			if err := bootstrapDefaultState(cfg.StatePath, bearerPath, adminPath); err != nil {
				return fmt.Errorf("bootstrap default state file: %w", err)
			}
		}
	case statErr != nil:
		return fmt.Errorf("stat state file %s: %w", cfg.StatePath, statErr)
	case cfg.PolicyPath != "":
		logger.Warn("policy_flag_ignored",
			slog.String("policy_path", cfg.PolicyPath),
			slog.String("state_path", cfg.StatePath),
			slog.String("note", "--policy is vestigial once a state file exists; no re-seed, no re-mint"))
	}

	store, err := policy.NewStore(cfg.StatePath, clk, logger)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	reg := metrics.New(session.TerminationReasons)

	// The ladder sink (D9a — unconditional, no arming). It is BOTH the manager's
	// Tap and the thing every UA's ObservingConn tees into, which is §6.2.1's
	// tap-wiring exception, literally.
	//
	// U15: trace.New takes TWO bounds, and the second is the one that is easy to
	// miss. `size` bounds the DEPTH of each ladder ring; `maxLadders` bounds the
	// NUMBER of rings. Without the second, the sink grows without limit on §N3's
	// own stated workload: Tap.Evict is driven by registry eviction and therefore
	// only ever reaches Call-IDs the session registry knows about, so REGISTER,
	// OPTIONS keepalives, failed dials and inbound INVITEs rejected before a Call
	// exists all create rings that nothing ever evicts. Beyond maxLadders the
	// sink drops the least recently WRITTEN of its UNRETAINED rings (U18; the
	// eviction itself is P1c Task 16's).
	//
	// U18/U21: maxLadders bounds the UNRETAINED rings only. Rings claimed by
	// Tap.Retain for a live call are not eviction candidates. The sink's total
	// is maxLadders PLUS the retained set, which is bounded by exactly what
	// bounds the registry itself: live calls (max_concurrent_calls_total) plus
	// terminated-but-retained calls (max_terminated_calls_per_session per
	// session and registry_retention in time), released at registry eviction
	// (evictCallLocked -> Tap.Evict), not at RecordTermination.
	//
	// Read from policy at construction, like every other limit the composition
	// root passes down.
	sink := trace.New(0, store.Current().Limits.MaxLadders)

	// The canonical [P2] artifact store (D9b's capture_start/capture_stop):
	// per-call files under artifact.dir, which /readyz already requires to be
	// writable (BuildReadyStatus).
	artifacts := artifact.New(store.Current().Artifact.Dir, clk)

	mgr, err := session.NewManager(session.ManagerConfig{
		Ctx:       daemonCtx, // NOT a request context.
		Clock:     clk,
		Policy:    store,
		Logger:    logger,
		Metrics:   reg,
		Tap:       sink,
		Artifacts: artifacts,
		// THIS CLOSURE IS THE ONLY PLACE session.UAConfig BECOMES sipua.Config,
		// and it is what keeps `session` free of `sipua` — the one import edge
		// §6.2 absolutely forbids. Its parameter is session.UAConfig, NEVER
		// sipua.Config: a closure typed on sipua.Config would put sipua in
		// session.ManagerConfig's signature and invert the layering.
		NewUA: func(uaCtx context.Context, uc session.UAConfig) (session.UserAgent, error) {
			return sipua.New(uaCtx, sipua.Config{
				Mode: uc.Mode, Transport: string(uc.Transport), LocalAddr: uc.LocalAddr,
				AOR: uc.AOR, AuthUser: uc.AuthUser,

				// B2: THIS IS THE ONLY .Reveal() IN THE ENTIRE TREE OUTSIDE
				// internal/policy, AND IT MUST STAY THAT WAY.
				//
				// session.UAConfig.AuthPass is a policy.Secret, which renders
				// "[REDACTED]" from String, GoString, MarshalJSON and LogValue.
				// It has to be: UAConfig is reachable through an exported getter
				// that feeds ua_status and AdminUAView payloads, and decision 5
				// threads a *slog.Logger through every layer, so a single %+v on
				// a UAConfig would fail §14.2's no-credential assertion.
				//
				// sipua.Config.AuthPass is a plain string, and cannot be
				// anything else: Part 1.1 forbids the edge sipua -> policy, so
				// sipua cannot name policy.Secret at all.
				//
				// This wiring closure is therefore the single boundary where the
				// redacted type must become the wire value. Every OTHER reader
				// in the tree handles the Secret and never unwraps it. P1a ships
				// a greppable assertion that `\.Reveal\(\)` occurs exactly once
				// outside internal/policy — THIS call site is the one it expects
				// to find. A second one anywhere is a defect, not a convenience.
				AuthPass: uc.AuthPass.Reveal(),

				Registrar: uc.Registrar, ExpiresS: uc.ExpiresS, Keepalive: uc.Keepalive,
				InboundRingTimeout: uc.InboundRingTimeout, Timeout: uc.Timeout,
				// CF-177: the live concurrent-call limit, the same formula
				// toolservice.go gives DialRequest.CallLimit, read per initial
				// INVITE so a SIGHUP applies at once.
				CallLimit: func() int {
					l := store.Current().Limits
					return min(l.MaxConcurrentCallsPerSession, l.MaxConcurrentCallsTotal)
				},

				DTMFMode:             uc.DTMFMode,
				SessionExpiresS:      uc.SessionExpiresS,
				MinSES:               uc.MinSES,
				KeepaliveIntervalS:   uc.KeepaliveIntervalS,
				SessionRefreshMethod: uc.SessionRefreshMethod,
				AuthAnyHost:          uc.AuthAnyHost,
				// P2 W3 (M5): media negotiation policy, threaded fresh off the
				// live store on every UA construction so a SIGHUP-reloaded
				// media.local_ip/media.port_range applies to the next UA.
				CodecPref:        uc.CodecPref,
				SRTP:             uc.SRTP,
				MediaLocalIP:     store.Current().Media.LocalIP,
				MediaPortRange:   store.Current().Media.PortRange,
				JitterBufferMS:   store.Current().Media.JitterBufferMS,
				Artifacts:        artifacts,
				ArtifactMaxBytes: store.Current().Artifact.MaxBytes,
				Prompts:          promptMap(store.Current()),
				TXToneHz:         txToneHzFromEnv(),
				// Phase 4 M7b, §7.1: resolved TLS trust material, threaded
				// fresh off the live store on every UA construction (same
				// SIGHUP-applies-to-the-next-UA shape as Media above).
				TLSRootCAs:            store.Current().TLSRootCAs(),
				TLSInsecureSkipVerify: store.Current().TLS.InsecureSkipVerify,
				Logger:                logger, Clock: clk,
				// D9d/U1's socket seam. sipua binds a CONCRETE address, hands the
				// conn here, and hands the result to Server.ServeUDP. P2 composes
				// netfault on top and NOTHING ELSE CHANGES. This is the first
				// production call site for ObservingConn (D256).
				//
				// B10 (P4-W2-09, W2): sipua.Config.Tap IS GONE. It had no readers in
				// internal/sipua at any point — the live observability path is the
				// ObservingConn closure below, not a config field — so W1's "kept, not
				// removed (Rule 19); propose removal at P2's Rule 6a" is discharged here.
				// If a tap ever needs to reach sipua as configuration rather than as a
				// wrapped conn, add it back with its reader in the same commit.
				WrapConn: func(c net.PacketConn) net.PacketConn {
					// HIGH-3: the per-UA tap stamps this UA's handle, so the
					// daemon-wide sink keys by (ua_handle, call_id) and a
					// peer-chosen Call-ID cannot collide two UAs' ladders.
					return sipua.ObservingConn(c, sink, uc.Transport, clk.Now, string(uc.Handle))
				},
				// P2 W2c T5: the tcp/tls counterparts of WrapConn above — same
				// tap, same per-UA handle-stamping, same HIGH-3 rationale, just
				// one seam up (net.Listener) and one seam out (the fork's
				// instance-scoped dial-wrap hook, via sipua.Config.WrapDialConn
				// -> sipgo.WithDialConnWrap). A udp UA's TCP listener and its
				// TCP dials (CF-076, CF-106) are tapped too and labelled tcp
				// (streamTapTransport, CF-190); WrapConn keeps its udp label.
				WrapListener: func(ln net.Listener) net.Listener {
					return sipua.ObservingListener(ln, sink, streamTapTransport(uc.Transport), clk.Now, string(uc.Handle))
				},
				WrapDialConn: func(c net.Conn) net.Conn {
					return sipua.ObservingStreamConn(c, sink, streamTapTransport(uc.Transport), clk.Now, string(uc.Handle))
				},
			})
		},
	})
	if err != nil {
		return fmt.Errorf("build session manager: %w", err)
	}
	mgr.StartJanitor()
	// Phase 1's session TTL reaper (owner-locked decision: fixed 5-minute
	// session lifetime). A SEPARATE ticker from StartJanitor above — see
	// reaper.go's own doc comment for why the two must not be folded
	// together (JanitorSweep runs entirely under the registry lock; the
	// reaper's teardowns do network I/O with it released). Stopped and
	// drained by gracefulShutdown (shutdown.go steps 2a/6a).
	mgr.StartSessionReaper()

	// The ARTIFACT janitor (§13.3) — distinct from mgr.StartJanitor() above,
	// which is Manager's own registry-retention janitor. This one sweeps
	// on-disk per-call artifact files against policy.Artifact.Retention/
	// MaxBytes, protecting any call IsLive still reports as running. One
	// immediate sweep at startup (crash recovery), then hourly.
	artifacts.SetLiveCallChecker(mgr)
	go startJanitor(daemonCtx, time.Hour, func() {
		cur := store.Current()
		artifacts.Sweep(daemonCtx, cur.Artifact.Retention.Duration(), cur.Artifact.MaxBytes, logger)
	})

	// §12.2.1's ONE live-call exception, wired. Everything else a SIGHUP
	// changes applies to NEW operations only; a changed max_call_duration_s is
	// re-evaluated against every live call's elapsed time the moment the swap
	// succeeds. The hook fires only on success, so a malformed policy file
	// leaves every armed cap untouched along with the policy itself.
	store.SetReloadHook(func(_, next *policy.Policy) { mgr.RecomputeDurationCaps(next) })

	// CONTRACT PART 4.4 IS DISCHARGED HERE: `Policy: store` is the code path
	// that wires auth.bearer_token_file and auth.admin_token_file into the
	// server. The deleted mcp.Config.BearerToken []byte snapshot had NO
	// populating call site anywhere in cmd/, which meant bearer auth was
	// unconfigurable in the shipped binary. Passing the LIVE store also makes
	// SIGHUP token rotation work with nothing to refresh.
	srv, err := mcp.NewServer(mcp.Config{
		Sessions:  mgr,                         // Manager satisfies Sessions directly
		Tools:     session.NewToolService(mgr), // ToolService satisfies Tools
		Admin:     mgr,                         // Manager satisfies Admin directly
		Policy:    store,
		Metrics:   reg,
		Ready:     func() mcp.ReadyStatus { return mcp.BuildReadyStatus(store, clk, started) },
		Artifacts: artifacts,
		Log:       logger,
		Clock:     clk,
	})
	if err != nil {
		return fmt.Errorf("build mcp server: %w", err)
	}

	httpSrv := newHTTPServer(cfg.ListenAddr, srv.Handler())

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-daemonCtx.Done():
				return
			case <-hup:
				if err := store.Reload(); err != nil {
					reg.IncPolicyReloadFailures()
					logger.Error("policy reload failed; previous policy remains in force",
						slog.String("path", cfg.StatePath), slog.String("error", err.Error()))
					continue
				}
				logger.Info("policy reloaded", slog.String("path", cfg.StatePath))
			}
		}
	}()

	serveErr := make(chan error, 1)
	go func() {
		err := httpSrv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()
	logger.Info("serving", slog.String("addr", cfg.ListenAddr), slog.String("version", version))

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}

	// One source for the grace period: the U12 policy key. It is a
	// policy.Duration, so .Duration() converts.
	grace := store.Current().Limits.ShutdownGracePeriod.Duration()
	deps := shutdownDeps{
		// The CONCRETE *mcp.Server. No type assertion: NewServer returns the
		// named type precisely so StopAccepting is reachable without one
		// (contract §2.8's stated reason for choosing this API shape).
		Server:  srv,
		HTTP:    httpSrv,
		Manager: mgr,
		Logger:  logger,
		Clock:   clk,
	}
	// Decision 17: the shutdown teardown must outlive the SIGTERM/SIGINT-
	// derived ctx (already Done() by this point) — hence a fresh
	// context.Background() here, not ctx. .golangci.yml carries a scoped
	// contextcheck exclusion for this file (D263) rather than a //nolint
	// directive, which D28 forbids.
	if err := gracefulShutdown(context.Background(), deps, grace); err != nil {
		logger.Error("graceful shutdown incomplete", slog.String("error", err.Error()))
	}
	stopDaemon()
	return <-serveErr
}

// newHTTPServer builds the daemon's one public HTTP listener with the
// timeout floors that close the pre-authentication resource-exhaustion gap
// (production-hardening spec Task 1): a peer that opens a TCP connection
// and never finishes sending headers, or that finishes headers but drips
// the body forever, previously held a server goroutine (and its Handler
// call) open indefinitely.
//
// ReadHeaderTimeout bounds the time a connection may take to finish sending
// its request headers — the actual pre-auth Slowloris-class exposure; no
// legitimate MCP client needs longer than 10s to send headers regardless of
// how long the subsequent tool call takes. ReadTimeout bounds the full
// request body read; MCP request bodies are already capped at 4 MiB
// (internal/transport/mcp/server.go's maxRequestBytes), so 30s is generous,
// not tight. IdleTimeout must be set explicitly — leaving it zero makes Go
// fall back to reusing ReadTimeout for keep-alive connection idling, which
// would wrongly tear down idle pooled connections at 30s.
//
// WriteTimeout stays unset (zero value = no limit): call_wait has no
// validation ceiling on max_wait_timeout_ms (default 5 min) and it's
// SIGHUP-reloadable after this server is constructed; media_play can
// legitimately hold one SSE-framed HTTP response open for up to
// max_call_duration_s (default 2h, legally uncapped at 0). There is no safe
// constant for this field given those two tools' actual blocking semantics.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// The per-request context is what §6.3 waiter rule 4 ties waiters to.
		// It must never become a call's context — hence a Background base
		// rather than one derived from daemonCtx, so that cancelling the
		// daemon at shutdown does not race in-flight waiters ahead of the
		// terminal broadcast that is supposed to wake them.
		BaseContext: func(net.Listener) context.Context { return context.Background() },
	}
}

// txToneHzFromEnv reads the hidden e2e-gate TX tone knob. It is an env-only
// diagnostic (locked decision 3) — no MCP tool exposes it — used by the loop
// gate so Asterisk's echo extension hears a real tone. Unset => 0 => silence.
func txToneHzFromEnv() float64 {
	v := os.Getenv("SIPCLIENT_MCP_TX_TONE_HZ")
	if v == "" {
		return 0
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0
	}
	return f
}

// startJanitor runs the artifact janitor: one immediate sweep at startup (crash
// recovery, §13.3), then on `interval` until ctx is cancelled. sweep is a closure
// over artifacts.Sweep so this loop stays trivially testable.
func startJanitor(ctx context.Context, interval time.Duration, sweep func()) {
	sweep() // startup sweep
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}

// streamTapTransport is the tap label for a UA's stream (listener and dial)
// traffic: a udp UA's TCP traffic is labelled tcp, since the pcap encoder frames
// a record as TCP only when its Transport is tcp or tls (CF-190).
func streamTapTransport(t session.Transport) session.Transport {
	if t == session.TransportUDP {
		return session.TransportTCP
	}
	return t
}

// promptMap flattens policy prompts into the name->path map sipua.Config wants.
// Read fresh per UA construction so a SIGHUP-reloaded prompts list applies to
// the next UA (same freshness rule as MediaLocalIP/JitterBufferMS above).
func promptMap(p *policy.Policy) map[string]string {
	m := make(map[string]string, len(p.Prompts))
	for _, pr := range p.Prompts {
		m[pr.Name] = pr.Path
	}
	return m
}
