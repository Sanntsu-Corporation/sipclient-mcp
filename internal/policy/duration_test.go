package policy

import (
	"fmt"
	"testing"
	"time"
)

func policyWithCap(t *testing.T, capS int) *Policy {
	t.Helper()
	tok := writeFile(t, "token", "bearer-token-value\n")
	body := fmt.Sprintf("auth:\n  bearer_token_file: %s\nlimits:\n  max_call_duration_s: %d\n", tok, capS)
	p, err := Load(writePolicy(t, body))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return p
}

var epoch = time.Date(2026, 7, 18, 9, 0, 0, 0, time.UTC)

func TestCallDeadline(t *testing.T) {
	tests := []struct {
		name   string
		capS   int
		want   time.Time
		wantOK bool
	}{
		{name: "300s cap", capS: 300, want: epoch.Add(300 * time.Second), wantOK: true},
		{name: "60s cap", capS: 60, want: epoch.Add(60 * time.Second), wantOK: true},
		{name: "zero means no cap", capS: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := policyWithCap(t, tt.capS).CallDeadline(epoch)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && !got.Equal(tt.want) {
				t.Errorf("deadline = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClampDurationClampsDownOnly(t *testing.T) {
	tests := []struct {
		name      string
		capS      int
		requested time.Duration
		want      time.Duration
	}{
		{name: "below the cap is honoured", capS: 300, requested: 60 * time.Second, want: 60 * time.Second},
		{name: "above the cap is clamped down", capS: 300, requested: 900 * time.Second, want: 300 * time.Second},
		{name: "equal to the cap is unchanged", capS: 300, requested: 300 * time.Second, want: 300 * time.Second},
		{name: "zero means take the cap", capS: 300, requested: 0, want: 300 * time.Second},
		{name: "negative means take the cap", capS: 300, requested: -5 * time.Second, want: 300 * time.Second},
		{name: "no cap configured: negative request is floored to zero, not passed through", capS: 0, requested: -5 * time.Second, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := policyWithCap(t, tt.capS)
			if got := p.ClampDuration(tt.requested); got != tt.want {
				t.Errorf("ClampDuration(%v) = %v, want %v", tt.requested, got, tt.want)
			}
		})
	}
}

// TestCallDeadlineAtTheCeilingLandsInTheFuture pins the OTHER half of Inputs
// §3's overflow fix: CallDeadline's own pre-multiplication check was never
// the bug (it already tested the raw field before multiplying); what
// protects it is validate()'s NEW 86400s load-time ceiling, added in the
// same change, which guarantees int(MaxCallDurationS) * time.Second can
// never overflow for anything Load produces. This test exercises the
// LARGEST legal value and asserts the deadline lands where arithmetic says
// it should — 86400s in the future, not wrapped into the past.
func TestCallDeadlineAtTheCeilingLandsInTheFuture(t *testing.T) {
	p := policyWithCap(t, 86400)
	got, ok := p.CallDeadline(epoch)
	if !ok {
		t.Fatal("ok = false at the 86400s ceiling, want true")
	}
	want := epoch.Add(86400 * time.Second)
	if !got.Equal(want) {
		t.Fatalf("deadline = %v, want %v — a value this large must not overflow into the past", got, want)
	}
	if got.Before(epoch) {
		t.Fatalf("deadline %v is BEFORE the call started at %v", got, epoch)
	}
}

// TestClampDurationNeverAliasesOverflowOntoUncapped is the Rule 9 mutation
// proof for Inputs §3's ClampDuration fix. It constructs a *Policy DIRECTLY
// (bypassing Load, which validate()'s 86400s ceiling would otherwise reject
// this value at) with a MaxCallDurationS large enough that
// int64(MaxCallDurationS) * time.Second overflows int64 nanoseconds and
// wraps negative (verified: math.MaxInt64 seconds wraps to -1s here).
//
// Before the fix, ClampDuration inferred "uncapped" from the WRAPPED capD
// being <= 0 and returned the caller's requested duration COMPLETELY
// UNCLAMPED — fail-open, for a policy that in fact configured a (nonsensical
// but non-zero) cap. The fix decides "uncapped" from the raw field being
// exactly zero, BEFORE any multiplication, so a huge non-zero value can no
// longer take that branch.
func TestClampDurationNeverAliasesOverflowOntoUncapped(t *testing.T) {
	const huge = 1<<63 - 1 // math.MaxInt64: overflows to a wrapped -1s capD.
	p := &Policy{Limits: Limits{MaxCallDurationS: huge}}

	requested := 5 * time.Second
	if got := p.ClampDuration(requested); got == requested {
		t.Fatalf("ClampDuration(%v) with MaxCallDurationS=%d = %v — returned EXACTLY the requested "+
			"duration, i.e. UNCLAMPED: the overflowed multiplication aliased a huge configured cap "+
			"onto \"uncapped\" instead of the guard testing the raw field for zero", requested, huge, got)
	}
}

func TestEarlierDeadlineNeverMovesADeadlineLater(t *testing.T) {
	early := epoch.Add(60 * time.Second)
	late := epoch.Add(300 * time.Second)
	var zero time.Time

	tests := []struct {
		name string
		a, b time.Time
		want time.Time
	}{
		{name: "lowered cap moves the deadline earlier", a: late, b: early, want: early},
		{name: "raised cap does NOT extend a live call", a: early, b: late, want: early},
		{name: "equal", a: early, b: early, want: early},
		{name: "zero a means no deadline yet", a: zero, b: late, want: late},
		{name: "zero b means no new deadline", a: early, b: zero, want: early},
		{name: "both zero", a: zero, b: zero, want: zero},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EarlierDeadline(tt.a, tt.b); !got.Equal(tt.want) {
				t.Errorf("EarlierDeadline(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
