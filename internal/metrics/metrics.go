// Package metrics is the process-wide counter registry the daemon exposes at
// GET /metrics (spec §5 N5). It is a stdlib-only leaf: session.Manager holds a
// *Registry (contract §2.3, §2.5.5), so this package MUST NEVER import
// session — that edge would be a cycle.
//
// All counters are atomics, so they may be incremented from any goroutine
// under no lock, including from inside session's m.mu/u.mu critical sections
// (§6.0b INV-2's explicit carve-out: pure atomics are not I/O).
package metrics

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Registry is the process's counter set. All counters are atomics.
type Registry struct {
	activeCalls atomic.Int64
	activeUAs   atomic.Int64
	callsTotal  atomic.Int64

	// byReason and reasons are fixed at New: byReason is keyed by every label
	// New was given, and reasons preserves that order so WriteText's
	// calls_by_termination_reason lines are deterministic.
	byReason map[string]*atomic.Int64
	reasons  []string

	webhookDeliveryFailures atomic.Int64 // [P5] present and 0 at P1
	webhookBlocked          atomic.Int64 // [P5] present and 0 at P1
	janitorSweeps           atomic.Int64
	janitorBytesReclaimed   atomic.Int64 // [P2] present and 0 at P1
	txUnderruns             atomic.Int64 // [P2] present and 0 at P1
	policyReloadFailures    atomic.Int64
	// sessionsEvicted counts Manager.Open's pressure-triggered eviction of an
	// idle session record to admit a new one under max_sessions_total (Rule
	// 13 Cycle 5). Unlike the sibling denial path (DeniedLimit, logged by the
	// caller) this has no other operator-visible signal, so it gets its own
	// counter rather than piggybacking on janitorSweeps, which counts a
	// different event (retention-window reaping, not cap pressure).
	sessionsEvicted atomic.Int64
}

// New fixes the termination-reason label set at construction.
// IncTerminationReason PANICS on a reason outside it, so a typo is a test
// failure rather than a silent counter that never appears in /metrics.
func New(terminationReasons []string) *Registry {
	r := &Registry{
		byReason: make(map[string]*atomic.Int64, len(terminationReasons)),
		reasons:  append([]string(nil), terminationReasons...),
	}
	for _, reason := range terminationReasons {
		r.byReason[reason] = new(atomic.Int64)
	}
	return r
}

// AddActiveCalls adjusts the live-call gauge by delta (positive or negative).
func (r *Registry) AddActiveCalls(delta int64) { r.activeCalls.Add(delta) }

// AddActiveUAs adjusts the live-UA gauge by delta (positive or negative).
func (r *Registry) AddActiveUAs(delta int64) { r.activeUAs.Add(delta) }

// IncCallsTotal increments the lifetime call counter.
func (r *Registry) IncCallsTotal() { r.callsTotal.Add(1) }

// IncTerminationReason PANICS if reason is outside the set New was given.
func (r *Registry) IncTerminationReason(reason string) {
	c, ok := r.byReason[reason]
	if !ok {
		panic("metrics: unknown termination reason " + reason)
	}
	c.Add(1)
}

// HasReason reports whether reason was registered with New. Callers use this
// to avoid IncTerminationReason's by-design panic on an unknown label (I1).
func (r *Registry) HasReason(reason string) bool {
	_, ok := r.byReason[reason]
	return ok
}

// IncWebhookDeliveryFailures increments the webhook-delivery-failure counter. [P5]
func (r *Registry) IncWebhookDeliveryFailures() { r.webhookDeliveryFailures.Add(1) }

// IncWebhookBlocked increments the webhook-blocked counter (§12.4). [P5]
func (r *Registry) IncWebhookBlocked() { r.webhookBlocked.Add(1) }

// IncJanitorSweeps increments the janitor-sweep counter.
func (r *Registry) IncJanitorSweeps() { r.janitorSweeps.Add(1) }

// AddJanitorBytesReclaimed adds n to the janitor-bytes-reclaimed counter. [P2]
func (r *Registry) AddJanitorBytesReclaimed(n int64) { r.janitorBytesReclaimed.Add(n) }

// IncTXUnderruns increments the TX-underrun counter. [P2]
func (r *Registry) IncTXUnderruns() { r.txUnderruns.Add(1) }

// IncPolicyReloadFailures increments the policy-reload-failure counter.
func (r *Registry) IncPolicyReloadFailures() { r.policyReloadFailures.Add(1) }

// IncSessionsEvicted increments the pressure-triggered session-eviction
// counter (Rule 13 Cycle 6, finding F2): an operator signal for
// Manager.Open evicting an idle session record under max_sessions_total
// pressure, distinct from the janitor's own retention-window reaping.
func (r *Registry) IncSessionsEvicted() { r.sessionsEvicted.Add(1) }

// WriteText renders spec §5 N5's GET /metrics body: plain-text `key value`
// lines, in the exact order and under the exact names §5 specifies.
func (r *Registry) WriteText(w io.Writer) error {
	lines := []struct {
		key string
		val int64
	}{
		{"active_calls", r.activeCalls.Load()},
		{"active_uas", r.activeUAs.Load()},
		{"calls_total", r.callsTotal.Load()},
	}
	for _, l := range lines {
		if _, err := fmt.Fprintf(w, "%s %d\n", l.key, l.val); err != nil {
			return err
		}
	}
	for _, reason := range r.reasons {
		if _, err := fmt.Fprintf(w, "calls_by_termination_reason{reason=%q} %d\n",
			reason, r.byReason[reason].Load()); err != nil {
			return err
		}
	}
	tail := []struct {
		key string
		val int64
	}{
		{"webhook_delivery_failures", r.webhookDeliveryFailures.Load()},
		{"webhook_blocked", r.webhookBlocked.Load()},
		{"janitor_sweeps_total", r.janitorSweeps.Load()},
		{"janitor_bytes_reclaimed_total", r.janitorBytesReclaimed.Load()},
		{"tx_underruns_total", r.txUnderruns.Load()},
		{"policy_reload_failures_total", r.policyReloadFailures.Load()},
		{"sessions_evicted_total", r.sessionsEvicted.Load()},
	}
	for _, l := range tail {
		if _, err := fmt.Fprintf(w, "%s %d\n", l.key, l.val); err != nil {
			return err
		}
	}
	return nil
}
