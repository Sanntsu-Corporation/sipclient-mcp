package sipua

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// TestConcurrentRefreshesArmExactlyOneTimer pins the invariant the re-arm path
// is FOR: one dialog, at most one armed watchdog refresher, no matter how many
// refreshes arrive at once.
//
// THE DEFECT IT REPRODUCES IS A LOST UPDATE THROUGH A CORRECTLY-HELD MUTEX, which
// is why neither `-race` nor any wire assertion could see it. The re-arm reads the
// outgoing watchdog and nils the field in one critical section, RELEASES the lock
// to Stop it (Stop must never run under u.calls.mu — the watchdog's own Do takes
// that lock), and stores the replacement in a SECOND critical section. Two
// refreshes interleave across that gap: the first takes the old watchdog and parks
// in Stop, the second finds the field already nil and so stops NOTHING, and both
// then store — the second overwriting a refresher the first had already Started.
// The overwritten one is armed and UNREACHABLE: stopSessionTimer reads
// st.watchdog, which no longer names it, so no teardown path can stop it and it
// runs to the full interval and BYEs a perfectly healthy call with
// `Reason: SIP;cause=408`.
//
// IT NEEDS NO MISBEHAVING PEER. Two in-dialog UPDATEs is enough, and so is one
// UPDATE racing runDial's own initial arm — Asterisk's direct-media re-INVITE
// arrives a median 0.8 ms after our ACK (call.go's own measurement), which is the
// same window.
//
// WHY THE ASSERTION COUNTS ARMED REFRESHERS RATHER THAN WIRE EFFECTS. The orphan
// is unreachable by construction, so `st.watchdog` cannot show it and a BYE only
// appears a full interval later, on a fake clock the test would first have to
// advance past a race it cannot synchronise with. st.armedTimers counts starts
// against stops, so the overwrite is visible at the instant it happens.
//
// The seeded initial watchdog is load-bearing, not setup noise: it is what makes
// the first refresh park in a real Stop() join and hands the others the window.
func TestConcurrentRefreshesArmExactlyOneTimer(t *testing.T) {
	// Both roles: weRefresh=false arms the watchdog, true our own refresher.
	for _, weRefresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "watchdog", true: "refresher"}[weRefresh], func(t *testing.T) {
			testConcurrentRefreshesArmExactlyOneTimer(t, weRefresh)
		})
	}
}

func testConcurrentRefreshesArmExactlyOneTimer(t *testing.T, weRefresh bool) {
	// The interleaving is probabilistic, so the attempt is repeated. Each attempt
	// is pure goroutine work on a clock that never advances (no wire, no I/O), so
	// 200 of them cost milliseconds.
	const (
		attempts    = 200
		concurrency = 4
	)
	for attempt := 0; attempt < attempts; attempt++ {
		clk := fakeclock.New(time.Unix(0, 0))
		u := &UA{cfg: Config{Clock: clk, Logger: slog.Default()}}
		u.uaCtx = context.Background()
		st := &sessionTimerState{IntervalS: 90, Refresher: "uas", weRefresh: weRefresh}
		d := &dialog{id: "d1", phase: phaseAnswered, sessionTimer: st}
		u.register(d)
		// The initial arm, exactly as runDial and Answer make it.
		u.armSessionTimer(d, st)

		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				u.onSessionRefreshReceived(d)
			}()
		}
		close(start)
		wg.Wait()

		// Every arm has returned, so every store and every discard has already
		// happened: the count is settled, not merely eventually settled.
		u.calls.mu.Lock()
		armed, reachable := st.armedTimers, st.watchdog
		if weRefresh {
			reachable = st.refresher
		}
		u.calls.mu.Unlock()
		u.stopSessionTimer(d)

		if armed != 1 || reachable == nil {
			t.Fatalf("attempt %d: %d session timers are armed on one dialog "+
				"(reachable through its slot: %v), want exactly 1 that is reachable — "+
				"%d timer(s) are running that no teardown path can stop, and each one "+
				"BYEs this healthy dialog (or refreshes a dead one) at its interval",
				attempt, armed, reachable != nil, armed-1)
		}
	}
}
