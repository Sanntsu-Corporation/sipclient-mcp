package apierr

import (
	"errors"
	"testing"
)

func intPtr(v int) *int { return &v }

func TestConstructors(t *testing.T) {
	tests := []struct {
		name        string
		err         *Error
		wantCode    Code
		wantMessage string
		wantRule    string
		wantLimit   *int
		wantCurrent *int
		wantDetail  map[string]any
	}{
		{
			name:        "denied names the rule that fired",
			err:         Denied(`deny:^sip:\+?1900`, "destination sip:19005550123@example.net matched deny rule"),
			wantCode:    CodeDenied,
			wantMessage: "destination sip:19005550123@example.net matched deny rule",
			wantRule:    `deny:^sip:\+?1900`,
		},
		{
			name:        "denied for a concurrency cap carries rule, limit and current",
			err:         DeniedLimit("max_concurrent_calls_per_session", 50, 50, "session already holds 50 concurrent calls"),
			wantCode:    CodeDenied,
			wantMessage: "session already holds 50 concurrent calls",
			wantRule:    "max_concurrent_calls_per_session",
			wantLimit:   intPtr(50),
			wantCurrent: intPtr(50),
		},
		{
			name:        "not_found",
			err:         NotFound("unknown call handle"),
			wantCode:    CodeNotFound,
			wantMessage: "unknown call handle",
		},
		{
			name:        "gone",
			err:         Gone("artifact reclaimed"),
			wantCode:    CodeGone,
			wantMessage: "artifact reclaimed",
		},
		{
			name:        "invalid_argument",
			err:         InvalidArgument("call_reject status 999 outside 300-699"),
			wantCode:    CodeInvalidArgument,
			wantMessage: "call_reject status 999 outside 300-699",
		},
		{
			name:        "precondition_failed",
			err:         PreconditionFailed("call is not in ringing"),
			wantCode:    CodePreconditionFailed,
			wantMessage: "call is not in ringing",
		},
		{
			name:        "not_supported",
			err:         NotSupported("transport tcp is not wired at P1"),
			wantCode:    CodeNotSupported,
			wantMessage: "transport tcp is not wired at P1",
		},
		{
			name: "media_negotiation carries the detail kind",
			err: MediaNegotiation("no_common_codec", map[string]any{
				"offered":    []string{"PCMA"},
				"acceptable": []string{"PCMU"},
			}, "no codec in common"),
			wantCode:    CodeMediaNegotiation,
			wantMessage: "no codec in common",
			wantDetail: map[string]any{
				"kind":       "no_common_codec",
				"offered":    []string{"PCMA"},
				"acceptable": []string{"PCMU"},
			},
		},
		{
			name:        "resource_limit",
			err:         ResourceLimit("max_uas_per_session", 10, 10, "UA cap reached"),
			wantCode:    CodeResourceLimit,
			wantMessage: "UA cap reached",
			wantRule:    "max_uas_per_session",
			wantLimit:   intPtr(10),
			wantCurrent: intPtr(10),
		},
		{
			name:        "internal echoes the correlation id in the message",
			err:         Internal("c1f0a3", "unexpected nil dialog"),
			wantCode:    CodeInternal,
			wantMessage: "unexpected nil dialog (correlation_id=c1f0a3)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", tt.err.Code, tt.wantCode)
			}
			if tt.err.Message != tt.wantMessage {
				t.Errorf("Message = %q, want %q", tt.err.Message, tt.wantMessage)
			}
			if tt.err.Rule != tt.wantRule {
				t.Errorf("Rule = %q, want %q", tt.err.Rule, tt.wantRule)
			}
			assertIntPtr(t, "Limit", tt.err.Limit, tt.wantLimit)
			assertIntPtr(t, "Current", tt.err.Current, tt.wantCurrent)
			if tt.wantDetail != nil {
				if got := tt.err.Detail["kind"]; got != tt.wantDetail["kind"] {
					t.Errorf("Detail[kind] = %v, want %v", got, tt.wantDetail["kind"])
				}
				if len(tt.err.Detail) != len(tt.wantDetail) {
					t.Errorf("Detail has %d keys, want %d: %v", len(tt.err.Detail), len(tt.wantDetail), tt.err.Detail)
				}
			} else if tt.err.Detail != nil {
				t.Errorf("Detail = %v, want nil", tt.err.Detail)
			}
		})
	}
}

func assertIntPtr(t *testing.T, field string, got, want *int) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil:
		t.Errorf("%s = nil, want %d", field, *want)
	case want == nil:
		t.Errorf("%s = %d, want nil", field, *got)
	case *got != *want:
		t.Errorf("%s = %d, want %d", field, *got, *want)
	}
}

func TestErrorImplementsError(t *testing.T) {
	var err error = NotFound("unknown call handle")

	if got, want := err.Error(), "not_found: unknown call handle"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}

	var target *Error
	if !errors.As(err, &target) {
		t.Fatalf("errors.As did not recover *apierr.Error from %T", err)
	}
	if target.Code != CodeNotFound {
		t.Errorf("recovered Code = %q, want %q", target.Code, CodeNotFound)
	}
}

func TestLimitPointersDoNotAliasCallerVariables(t *testing.T) {
	limit, current := 50, 12
	err := ResourceLimit("max_uas_total", limit, current, "UA cap reached")

	limit, current = 0, 0
	_, _ = limit, current

	if *err.Limit != 50 || *err.Current != 12 {
		t.Errorf("Limit/Current = %d/%d after caller mutation, want 50/12", *err.Limit, *err.Current)
	}
}
