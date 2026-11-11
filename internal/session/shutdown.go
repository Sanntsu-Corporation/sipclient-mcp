package session

import (
	"context"
	"time"
)

// RefuseNewDials is §11.4 step 2: every subsequent CreateCall returns
// resource_limit — §11.2's exact code for "call_dial refused during graceful
// shutdown". The check itself lives in checkConcurrencyLocked (caps.go), the
// one gate on call creation (Rule 18); this method only sets the flag.
//
// IRREVERSIBLE BY DESIGN. There is no ResumeDials: a daemon that has begun
// shutting down never accepts work again, and an un-refuse path would be
// reachable only from a state that cannot occur.
func (m *Manager) RefuseNewDials() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refusing = true
}

// HangupAllLive sends BYE to every live dialog and waits up to `grace` for the
// 200 OK. It reports how many BYEs were sent and how many were confirmed, which
// is what §11.4's final log line records.
//
// THE LIVE SET IS SNAPSHOTTED UNDER THE REGISTRY LOCK AND THE LOCK IS RELEASED
// BEFORE ANY BYE — the same discipline Task 11a's destroyUA follows, for the
// same reason: `grace` is 10s by default and the lock guards every tool call on
// the server.
//
// Calls torn down here carry termination_reason "local_hangup" (§11.4): §10.3's
// enum gains NO shutdown-specific value, because a consumer could not react to
// one differently.
func (m *Manager) HangupAllLive(ctx context.Context, grace time.Duration) (byeSent, confirmed int) {
	type target struct {
		c     *Call
		agent UserAgent
	}
	m.mu.RLock()
	targets := make([]target, 0, len(m.calls))
	for _, s := range m.sessions {
		for _, c := range s.liveCalls {
			if u, ok := s.liveUAs[c.uaHandle]; ok {
				targets = append(targets, target{c: c, agent: u.agent})
			}
		}
	}
	m.mu.RUnlock()
	// ---- registry lock released; every BYE below is a network write --------

	byeCtx, cancel := context.WithTimeout(ctx, grace)
	defer cancel()
	// §6.0b INV-1, **FORM B** (contract §5.6, U23) — same shape and same reasoning
	// as destroyUA's BYE loop. Form A is FORBIDDEN in a loop body: a `defer` fires
	// at FUNCTION exit, so it would not run until HangupAllLive returned, after
	// every call had been BYEd, holding every slot for the full grace period.
	// Form B's three requirements are met below: the literal `// INV-1 LOOP FORM:`
	// marker is the line immediately following the successful TryHangup; the span
	// from that claim to the plain RecordTermination contains NO `return`,
	// `continue`, `break`, `goto` or `panic` and no nested for/switch/select —
	// Hangup's error is folded into the `confirmed` count and fallen through,
	// never returned, because an unconfirmed BYE is expected rather than
	// exceptional and the grace period exists so a silent far end cannot hold
	// shutdown open; and RecordTermination is the iteration's LAST statement.
	// The `continue` in the failed-claim branch is outside that span — nothing
	// was claimed there. Task 24's gate classifies this site here.
	//
	// `ctx` IS CORRECT HERE and is NOT a decision-17 violation: HangupAllLive is
	// called only from §11.4's shutdown sequence in cmd/, which passes the
	// shutdown context, never an HTTP request context. There is no client whose
	// disconnect could cancel it.
	for _, tg := range targets {
		if err := tg.c.TryHangup(m.clk.Now(), "local_hangup"); err != nil {
			continue // already terminated; §6.3 says exactly one caller wins
		}
		// INV-1 LOOP FORM: per-iteration record; a defer here would fire at
		// HangupAllLive's exit and hold every slot until the whole loop finished.
		byeSent++
		if err := tg.agent.Hangup(byeCtx, tg.c.DialogID(), "local_hangup"); err == nil {
			confirmed++
		} else {
			// D334: §11.4 says an unconfirmed dialog is "abandoned with an
			// error event logged" — "event" is §10.5's term of art for the
			// per-call event log, not the server's slog stream. Without this,
			// an abandoned call is indistinguishable from a confirmed one:
			// both land here, both carry termination_reason "local_hangup"
			// (already appended as EventBye by TryHangup above).
			tg.c.Append(m.clk.Now(), EventError, map[string]any{
				"kind":  "shutdown_bye_unconfirmed",
				"error": err.Error(),
			})
		}
		// An unconfirmed BYE is EXPECTED, not exceptional: the grace period
		// exists precisely so a silent far end cannot hold shutdown open.
		m.RecordTermination(tg.c)
	}
	return byeSent, confirmed
}

// UnregisterAllUAs sends REGISTER Expires: 0 for every REGISTERED UA. A
// direct-mode UA has no registration to end and is skipped rather than counted.
//
// IT RETURNS TWO COUNTS BECAUSE THEY GENUINELY DIFFER (B3). UserAgent.Unregister
// is BLOCKING — it returns nil only on a 2xx — so a registrar that is
// unreachable, slow or silent counts in `sent` and NOT in `confirmed`. A single
// count could not express "we tried to deregister 5 and 3 registrars actually
// acknowledged", which is exactly what §11.4's shutdown line must record and
// what an operator needs to know a registration may still be live upstream.
//
// SHUTDOWN PROCEEDS EITHER WAY. An unconfirmed deregistration is expected, not
// exceptional — the same reasoning §11.4's BYE grace period applies to a far
// end that never answers. Mirrors HangupAllLive's (byeSent, confirmed).
//
// `ctx` IS CORRECT HERE and is not a decision-17 violation, for the same reason
// it is correct in HangupAllLive: this is called only from §11.4's shutdown
// sequence in cmd/, which passes the shutdown context. There is no HTTP client
// whose disconnect could cancel it. Every OTHER Unregister in the project is
// reached through destroyUA, which derives its own context from m.daemonCtx.
func (m *Manager) UnregisterAllUAs(ctx context.Context) (sent, confirmed int) {
	m.mu.RLock()
	uas := make([]*UA, 0, len(m.uas))
	for _, s := range m.sessions {
		for _, u := range s.liveUAs {
			if u.Registered() {
				uas = append(uas, u)
			}
		}
	}
	m.mu.RUnlock()
	// ---- registry lock released before the REGISTER writes -----------------

	for _, u := range uas {
		sent++
		if err := u.agent.Unregister(ctx); err != nil {
			// Counted in `sent`, not in `confirmed`. The registration may still
			// be live upstream, which is a fact the operator needs and which a
			// single count would erase.
			m.log.Warn("unregister not confirmed during shutdown",
				"ua_handle", u.Handle(), "err", err)
			continue
		}
		u.setRegistered(false)
		confirmed++
	}
	return sent, confirmed
}
