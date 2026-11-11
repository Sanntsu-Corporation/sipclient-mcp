package session

import (
	"errors"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

func newTestCall(t *testing.T, state CallState) *Call {
	t.Helper()
	return newCall(newCallHandle(), newUAHandle(), &sessionRecord{id: "s1"}, Inbound, state, 1024, time.Unix(1000, 0))
}

func TestCallTransitions(t *testing.T) {
	base := time.Unix(1000, 0)
	tests := []struct {
		name      string
		from      CallState
		act       func(*Call) error
		wantState CallState
		wantCode  apierr.Code
		wantEvent EventType
	}{
		{"answer a ringing call (no event: NoteAnswered appends it)", StateRinging, func(c *Call) error { return c.TryAnswer(base) },
			StateAnswered, "", ""},
		{"note an answered call", StateAnswered, func(c *Call) error { c.NoteAnswered(base); return nil },
			StateAnswered, "", EventAnswered},
		{"note twice", StateAnswered, func(c *Call) error { c.NoteAnswered(base); c.NoteAnswered(base); return nil },
			StateAnswered, "", EventAnswered},
		{"note a terminated call", StateTerminated, func(c *Call) error { c.NoteAnswered(base); return nil },
			StateTerminated, "", ""},
		{"refuse an answered call", StateAnswered, func(c *Call) error { return c.TryAnswerRefused(base, 422, "Session Interval Too Small") },
			StateTerminated, "", EventBye},
		{"answer an answered call", StateAnswered, func(c *Call) error { return c.TryAnswer(base) },
			StateAnswered, apierr.CodePreconditionFailed, ""},
		{"answer a terminated call", StateTerminated, func(c *Call) error { return c.TryAnswer(base) },
			StateTerminated, apierr.CodePreconditionFailed, ""},
		{"reject a ringing call", StateRinging, func(c *Call) error { return c.TryReject(base, 486, "Busy Here") },
			StateTerminated, "", EventBye},
		{"reject an answered call", StateAnswered, func(c *Call) error { return c.TryReject(base, 486, "") },
			StateAnswered, apierr.CodePreconditionFailed, ""},
		{"hangup an answered call", StateAnswered, func(c *Call) error { return c.TryHangup(base, "local_hangup") },
			StateTerminated, "", EventBye},
		{"hangup a ringing call", StateRinging, func(c *Call) error { return c.TryHangup(base, "local_hangup") },
			StateTerminated, "", EventBye},
		{"hangup a terminated call", StateTerminated, func(c *Call) error { return c.TryHangup(base, "local_hangup") },
			StateTerminated, apierr.CodePreconditionFailed, ""},
		{"duration cap on an answered call", StateAnswered, func(c *Call) error {
			return c.TryTerminate(base, "policy_timeout", EventPolicyTimeout)
		}, StateTerminated, "", EventPolicyTimeout},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestCall(t, tc.from)
			err := tc.act(c)
			if tc.wantCode == "" {
				if err != nil {
					t.Fatalf("act: unexpected error %v", err)
				}
			} else {
				var ae *apierr.Error
				if !errors.As(err, &ae) {
					t.Fatalf("act: err = %v, want *apierr.Error", err)
				}
				if ae.Code != tc.wantCode {
					t.Fatalf("code = %q, want %q", ae.Code, tc.wantCode)
				}
			}
			if got := c.State(); got != tc.wantState {
				t.Errorf("state = %q, want %q", got, tc.wantState)
			}
			evs, _, _ := c.Events(0)
			if tc.wantEvent == "" {
				if len(evs) != 0 {
					t.Errorf("losing transition appended %d events, want 0", len(evs))
				}
				return
			}
			if len(evs) != 1 || evs[0].Type != tc.wantEvent {
				t.Fatalf("events = %+v, want exactly one %q", evs, tc.wantEvent)
			}
			if evs[0].Seq != 1 {
				t.Errorf("seq = %d, want 1", evs[0].Seq)
			}
		})
	}
}

func TestTerminationReasonRecordedOnce(t *testing.T) {
	c := newTestCall(t, StateAnswered)
	if err := c.TryHangup(time.Unix(1000, 0), "local_hangup"); err != nil {
		t.Fatalf("first hangup: %v", err)
	}
	if err := c.TryTerminate(time.Unix(1001, 0), "remote_bye", EventBye); err == nil {
		t.Fatal("second termination succeeded, want precondition_failed")
	}
	if got := c.TerminationReason(); got != "local_hangup" {
		t.Errorf("termination_reason = %q, want %q", got, "local_hangup")
	}
}
