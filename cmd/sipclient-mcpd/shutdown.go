package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/transport/mcp"
)

type shutdownDeps struct {
	// The CONCRETE *mcp.Server (contract §2.8). mcp.Handler does not exist.
	Server  *mcp.Server
	HTTP    *http.Server
	Manager *session.Manager
	Logger  *slog.Logger
	Clock   clock.Clock
}

// gracefulShutdown performs §11.4 in the order the spec fixes. The order is
// load-bearing: refusing dials before the BYEs means no call can be created
// into a server that is already tearing calls down.
//
// grace comes from limits.shutdown_grace_period — the same key §12.7's admin
// DELETE reads, so the two BYE waits can never diverge.
func gracefulShutdown(ctx context.Context, d shutdownDeps, grace time.Duration) error {
	d.Logger.Info("graceful shutdown starting", slog.Duration("grace", grace))

	// 1. Stop accepting new MCP connections. In-flight requests keep running:
	//    a parked call_wait must live long enough to receive §6.3 rule 2's
	//    terminal broadcast in step 3.
	d.Server.StopAccepting()

	// 2. Refuse new call_dial with resource_limit (§11.2's table names this).
	d.Manager.RefuseNewDials()

	// 2a. Stop the session TTL reaper (Phase 1, owner-locked decision) BEFORE
	//    any of the registry-visible teardown steps below run. Position is
	//    load-bearing: it freezes the session set steps 3/5/6 snapshot, so
	//    none of them can race a concurrent reaper-triggered detach that
	//    deletes a record between two of their snapshots — and it loses no
	//    teardown, because a session that reaches its TTL DURING shutdown
	//    simply stays in the registry and is torn down by steps 3 and 6
	//    instead of by the reaper. Step 6a below is only sound because THIS
	//    runs first: until the reaper is stopped, a tick can still start a
	//    NEW detached teardown after 6a's drain has already observed nothing
	//    outstanding.
	d.Manager.StopSessionReaper()

	// 3. BYE every live dialog, waiting up to the grace period for 200 OK.
	//    Terminated calls carry termination_reason "local_hangup" (§11.4 — no
	//    new §10.3 enum value). Waiters parked on those calls are woken by
	//    rule 2's broadcast inside HangupAllLive, before this function returns.
	byeCtx, cancelBye := context.WithTimeout(ctx, grace)
	byeSent, confirmed := d.Manager.HangupAllLive(byeCtx, grace)
	cancelBye()
	if abandoned := byeSent - confirmed; abandoned > 0 {
		d.Logger.Warn("dialogs abandoned at grace expiry",
			slog.Int("bye_sent", byeSent), slog.Int("confirmed", confirmed),
			slog.Int("abandoned", abandoned))
	}

	// 4. Close and flush every open artifact so the D10 TTL clock starts
	//    correctly. P1 SHIPS NO ARTIFACTS — the artifact store arrives at P2 —
	//    so there is nothing to close here and no code is written for it
	//    (Rule 15). P2 inserts the flush at exactly this point.
	//
	//    Webhook queue draining, which §11.4 also names, is P5 (§10.6) and is
	//    likewise not built here.

	// 5. Final janitor pass.
	sweep := d.Manager.JanitorSweep(d.Clock.Now())
	d.Logger.Info("final janitor pass",
		slog.Int("calls_evicted", sweep.CallsEvicted),
		slog.Int("uas_evicted", sweep.UAsEvicted))

	// 6. Unregister every registered UA with Expires: 0. TWO counts come back,
	//    exactly as in step 3: Unregister BLOCKS for the registrar's final
	//    response (§2.5.3), so `confirmed` counts CONFIRMED deregistrations and
	//    `sent` counts attempts. A registrar that is unreachable, answers
	//    non-2xx, or does not answer before unregCtx expires contributes to
	//    `sent` only, and §11.4's shutdown proceeds regardless — a registrar
	//    that will not answer must not hold the daemon open.
	unregCtx, cancelUnreg := context.WithTimeout(ctx, grace)
	unregSent, unregConfirmed := d.Manager.UnregisterAllUAs(unregCtx)
	cancelUnreg()
	d.Logger.Info("unregistered UAs",
		slog.Int("sent", unregSent), slog.Int("confirmed", unregConfirmed))

	// 6a. Wait for any session-reaper-triggered teardown still in flight
	//    (Phase 1, D11's shutdown-ownership contract) rather than truncating
	//    it. Position: AFTER the registry-visible teardown steps above (so a
	//    teardown that was already detached by the time step 2a stopped the
	//    reaper is still caught here), and BEFORE step 7's HTTP.Shutdown —
	//    comfortably before run.go's stopDaemon() cancels daemonCtx, which is
	//    the context a teardown's own grace-period timeout derives from and
	//    would otherwise truncate mid-write. Sound only because step 2a ran
	//    first: with the reaper sealed, every remaining Add to the wait group
	//    already happened before this Wait, per reaperWG's own contract.
	drainCtx, cancelDrain := context.WithTimeout(ctx, grace)
	outstanding := 0
	if !d.Manager.DrainSessionReaper(drainCtx) {
		outstanding = 1
	}
	cancelDrain()
	if outstanding > 0 {
		d.Logger.Warn("a session-reaper teardown was still in flight at the drain deadline")
	}

	// 7. Close the HTTP server and exit.
	closeCtx, cancelClose := context.WithTimeout(ctx, grace)
	defer cancelClose()
	err := d.HTTP.Shutdown(closeCtx)
	d.Logger.Info("graceful shutdown complete")
	return err
}
