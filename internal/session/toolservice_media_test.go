package session_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

func TestCallStatusEmitsNegotiatedMediaFields(t *testing.T) {
	ua := fakes.NewUserAgent()
	ua.MediaViewOK = true
	ua.MediaViewResult = session.MediaView{Codec: "PCMA", LocalMediaAddr: "192.0.2.7:16384", SRTP: false}

	m, ts, ctx, uaHandle := newFixture(t, fakes.NewArtifactStore(), fakes.NewTap(),
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return ua, nil })
	callHandle, _ := mustDial(t, m, ts, "s1", uaHandle, nil)

	out, err := ts.CallStatus(ctx, "s1", session.CallStatusInput{Call: callHandle})
	if err != nil {
		t.Fatalf("CallStatus: %v", err)
	}
	om, _ := out.(map[string]any)
	if om["codec"] != "PCMA" {
		t.Fatalf("codec=%v", om["codec"])
	}
	if om["local_media_addr"] != "192.0.2.7:16384" {
		t.Fatalf("local_media_addr=%v", om["local_media_addr"])
	}
	if om["srtp"] != false {
		t.Fatalf("srtp=%v", om["srtp"])
	}
}

// Task 16: dtmf_send on the tool surface.

// mediaToolHarness bundles a ToolService, session id, dialed *session.Call and
// its backing fakes.UserAgent. It is ADDITIVE alongside newMediaToolFixture
// (media_tools_test.go) — that helper and its existing W5 callers are
// unchanged; this one exists because three of the tests below must capture the
// arguments a call was made with, which newMediaToolFixture's 4-tuple return
// makes awkward to thread through table-driven subtests. Task 19
// (dtmf_received) reuses this identical shape.
type mediaToolHarness struct {
	tools *session.ToolService
	sess  string
	call  *session.Call
	agent *fakes.UserAgent
	mgr   *session.Manager
}

// newMediaToolHarness builds a mediaToolHarness over one dialed call in
// session "s1", via the existing newFixture/mustDial helpers (Rule 16 reuse;
// capture_test.go).
func newMediaToolHarness(t *testing.T) *mediaToolHarness {
	t.Helper()
	ua := fakes.NewUserAgent()
	m, ts, _, uaHandle := newFixture(t, fakes.NewArtifactStore(), fakes.NewTap(),
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return ua, nil })
	_, call := mustDial(t, m, ts, "s1", uaHandle, nil)
	return &mediaToolHarness{tools: ts, sess: "s1", call: call, agent: ua, mgr: m}
}

func TestDTMFSendReturnsTheSpecShape(t *testing.T) {
	h := newMediaToolHarness(t)
	h.agent.SendDTMFFn = func(_ context.Context, _, digits string, mode session.DTMFMode, dur, gap int) (int, int, error) {
		if digits != "123" || mode != session.DTMFModeInband || dur != 80 || gap != 40 {
			t.Fatalf("agent got digits=%q mode=%q dur=%d gap=%d", digits, mode, dur, gap)
		}
		return 3, 80, nil
	}
	gap := 40
	out, err := h.tools.DTMFSend(context.Background(), h.sess, session.DTMFSendInput{
		Call: string(h.call.Handle()), Digits: "123", Mode: "inband",
		DurationMs: 80, GapMs: &gap,
	})
	if err != nil {
		t.Fatalf("DTMFSend: %v", err)
	}
	res := out.(map[string]any)
	if res["digits_sent"] != 3 || res["mode"] != "inband" || res["duration_ms"] != 80 {
		t.Fatalf("payload = %+v want {digits_sent:3, mode:inband, duration_ms:80}", res)
	}
}

// TestDTMFSendReportsTheEmittedDurationNotTheRequestedOne is the tool half of
// §4's "duration_ms is a fact" contract: the agent asks for 50, the sender emits
// 60, and 60 is what comes back.
func TestDTMFSendReportsTheEmittedDurationNotTheRequestedOne(t *testing.T) {
	h := newMediaToolHarness(t)
	h.agent.SendDTMFFn = func(context.Context, string, string, session.DTMFMode, int, int) (int, int, error) {
		return 1, 60, nil // the sender rounded 50ms up to three 20ms ticks
	}
	out, err := h.tools.DTMFSend(context.Background(), h.sess, session.DTMFSendInput{
		Call: string(h.call.Handle()), Digits: "1", Mode: "rfc2833", DurationMs: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := out.(map[string]any)["duration_ms"]; got != 60 {
		t.Fatalf("duration_ms=%v want 60 — the response must report what was EMITTED, "+
			"not echo the request back", got)
	}
}

// TestDTMFSendPassesGapMsAsATriState pins the one thing a plain int cannot
// express: an omitted gap_ms and an explicit gap_ms:0 are DIFFERENT requests, and
// the tool must not collapse them before sipua's resolver sees them.
func TestDTMFSendPassesGapMsAsATriState(t *testing.T) {
	cases := []struct {
		name    string
		gap     *int
		wantGap int
	}{
		{"omitted reaches sipua as unset", nil, session.DTMFGapUnset},
		{"explicit zero reaches sipua as zero", ptrInt(0), 0},
		{"explicit value passes through", ptrInt(40), 40},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newMediaToolHarness(t)
			var gotGap int
			h.agent.SendDTMFFn = func(_ context.Context, _, _ string, _ session.DTMFMode, _, gap int) (int, int, error) {
				gotGap = gap
				return 1, 100, nil
			}
			if _, err := h.tools.DTMFSend(context.Background(), h.sess, session.DTMFSendInput{
				Call: string(h.call.Handle()), Digits: "1", GapMs: tc.gap,
			}); err != nil {
				t.Fatal(err)
			}
			if gotGap != tc.wantGap {
				t.Fatalf("sipua got gap_ms=%d want %d", gotGap, tc.wantGap)
			}
		})
	}
}

func ptrInt(v int) *int { return &v }

func TestDTMFSendPropagatesTheAgentsErrorCode(t *testing.T) {
	h := newMediaToolHarness(t)
	h.agent.SendDTMFFn = func(context.Context, string, string, session.DTMFMode, int, int) (int, int, error) {
		return 0, 0, apierr.NotSupported("telephone-event was not negotiated")
	}
	_, err := h.tools.DTMFSend(context.Background(), h.sess, session.DTMFSendInput{
		Call: string(h.call.Handle()), Digits: "1", Mode: "rfc2833",
	})
	if apierr.CodeOf(err) != apierr.CodeNotSupported {
		t.Fatalf("code=%v want not_supported", apierr.CodeOf(err))
	}
}

// TestDTMFSendPartialFailureReportsDigitsSentInDetail is F4(a)'s regression
// test. On any error, DTMFSend used to discard both of SendDTMF's return
// values — a caller could not tell whether 0 or 5 digits reached the wire
// before retrying, risking a double-send into an IVR. apierr.Error.Detail is
// already copied unconditionally into the MCP envelope (envelope.go), so a
// partial send's progress must land there.
func TestDTMFSendPartialFailureReportsDigitsSentInDetail(t *testing.T) {
	h := newMediaToolHarness(t)
	h.agent.SendDTMFFn = func(context.Context, string, string, session.DTMFMode, int, int) (int, int, error) {
		// sendDTMFInfo's own shape: 2 of 3 digits landed, then the third was
		// rejected — a partial send, not a total failure.
		return 2, 100, apierr.NotSupported("dtmf_send: INFO for digit at index 2 was rejected: 405 Method Not Allowed")
	}
	_, err := h.tools.DTMFSend(context.Background(), h.sess, session.DTMFSendInput{
		Call: string(h.call.Handle()), Digits: "123", Mode: "info",
	})
	if apierr.CodeOf(err) != apierr.CodeNotSupported {
		t.Fatalf("code=%v want not_supported", apierr.CodeOf(err))
	}
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("error is not an *apierr.Error: %v", err)
	}
	if ae.Detail == nil {
		t.Fatal("Detail is nil — a partial send's progress must reach the caller on error")
	}
	if got := ae.Detail["digits_sent"]; got != 2 {
		t.Fatalf("Detail[digits_sent]=%v want 2", got)
	}
	if got := ae.Detail["duration_ms"]; got != 100 {
		t.Fatalf("Detail[duration_ms]=%v want 100", got)
	}
}

func TestDTMFSendDefaultsModeToTheCallsEffectiveMode(t *testing.T) {
	h := newMediaToolHarness(t)
	h.agent.DTMFModeFn = func(string) (string, bool) { return "rfc2833", true }
	h.agent.SendDTMFFn = func(_ context.Context, _, _ string, mode session.DTMFMode, _, _ int) (int, int, error) {
		if mode != "" {
			t.Fatalf("mode=%q — an omitted mode must pass through empty so sipua applies the profile default", mode)
		}
		return 1, 100, nil
	}
	out, err := h.tools.DTMFSend(context.Background(), h.sess, session.DTMFSendInput{
		Call: string(h.call.Handle()), Digits: "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.(map[string]any)["mode"] != "rfc2833" {
		t.Fatalf("reported mode = %v want the call's effective mode", out.(map[string]any)["mode"])
	}
}

// dtmfSendOutOfRange enumerates the dtmf_send payloads §10.8 must reject, each
// paired with the media_plan `dtmf` step carrying the SAME arguments. Every row
// is asserted twice below — once per surface — because the defect these tests
// exist for is precisely that the two surfaces answered one input differently.
//
// The first row is the reported OOM payload verbatim: with the default
// max_call_duration_s of 300s it charges 60,000,050ms of render against a
// 300,000ms budget, and unguarded it pre-rendered ~3,000,000 silence frames
// (~1 GB) inside a single codec.NewDTMFSource call.
var dtmfSendOutOfRange = []struct {
	name   string
	digits string
	dur    int
	gap    *int // nil = omitted
	want   string
}{
	{"gap_ms of 60000000 is the reported OOM payload", "1", 0, ptrInt(60_000_000), "gap_ms"},
	{"a long digit string within the duration cap", strings.Repeat("1", 20000), 8000, nil, "digits"},
	{"a negative duration_ms is rejected, not defaulted", "1", -1, nil, "duration_ms"},
	{"a negative gap_ms is rejected, not defaulted", "1", 0, ptrInt(-5), "gap_ms"},
}

// TestDTMFSendRejectsAnOutOfRangeRequestBeforeItIsRendered is the tool half of
// the fix. It asserts the REJECTION HAPPENS BEFORE THE AGENT IS EVER CALLED —
// the pre-render lives behind SendDTMF, so "the daemon survived" is not the
// property under test and allocating a gigabyte to observe it would be
// pointless. A scripted SendDTMFFn that fails the test on entry is the check.
func TestDTMFSendRejectsAnOutOfRangeRequestBeforeItIsRendered(t *testing.T) {
	for _, tc := range dtmfSendOutOfRange {
		t.Run(tc.name, func(t *testing.T) {
			h := newMediaToolHarness(t)
			h.agent.SendDTMFFn = func(context.Context, string, string, session.DTMFMode, int, int) (int, int, error) {
				t.Fatalf("sipua.SendDTMF was reached — an out-of-range dtmf_send must be " +
					"rejected at the tool boundary, before anything is pre-rendered")
				return 0, 0, nil
			}
			_, err := h.tools.DTMFSend(context.Background(), h.sess, session.DTMFSendInput{
				Call: string(h.call.Handle()), Digits: tc.digits, DurationMs: tc.dur, GapMs: tc.gap,
			})
			if apierr.CodeOf(err) != apierr.CodeInvalidArgument {
				t.Fatalf("code=%v want invalid_argument (err=%v)", apierr.CodeOf(err), err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the offending argument %q — a tool "+
					"result is read by a model and must say WHICH argument was out of range", err, tc.want)
			}
		})
	}
}

// TestDTMFSendAndTheDTMFPlanStepAgreeOnOutOfRangeInput is the other half: every
// payload here must be rejected with the SAME code by BOTH surfaces — the
// discrete dtmf_send tool and the media_plan `dtmf` step carrying identical
// arguments, which is where these bounds already lived. One input, one
// contract. It asserts both sides in one subtest on purpose: a test that only
// re-pinned the plan path would still pass with the tool's guard removed, which
// is exactly the shape of vacuous coverage this wave has been bitten by.
func TestDTMFSendAndTheDTMFPlanStepAgreeOnOutOfRangeInput(t *testing.T) {
	// Positive control FIRST: CallDial with an in-range dtmf step must succeed,
	// so the rejections below are attributable to the step's arguments and not
	// to the harness dialing badly.
	t.Run("an in-range dtmf step still dials", func(t *testing.T) {
		ua := fakes.NewUserAgent()
		_, ts, ctx, uaHandle := newFixture(t, fakes.NewArtifactStore(), fakes.NewTap(),
			func(context.Context, session.UAConfig) (session.UserAgent, error) { return ua, nil })
		if _, err := ts.CallDial(ctx, "s1", session.CallDialInput{
			UA: uaHandle, ToURI: "sip:bob@example.com",
			MediaPlan: []map[string]any{{"op": "dtmf", "digits": "1", "duration_ms": float64(100), "gap_ms": float64(50)}},
		}); err != nil {
			t.Fatalf("CallDial with an in-range dtmf step: %v", err)
		}
	})
	for _, tc := range dtmfSendOutOfRange {
		t.Run(tc.name, func(t *testing.T) {
			ua := fakes.NewUserAgent()
			_, ts, ctx, uaHandle := newFixture(t, fakes.NewArtifactStore(), fakes.NewTap(),
				func(context.Context, session.UAConfig) (session.UserAgent, error) { return ua, nil })
			step := map[string]any{"op": "dtmf", "digits": tc.digits}
			if tc.dur != 0 {
				step["duration_ms"] = float64(tc.dur)
			}
			if tc.gap != nil {
				step["gap_ms"] = float64(*tc.gap)
			}
			_, planErr := ts.CallDial(ctx, "s1", session.CallDialInput{
				UA: uaHandle, ToURI: "sip:bob@example.com", MediaPlan: []map[string]any{step},
			})

			h := newMediaToolHarness(t)
			_, toolErr := h.tools.DTMFSend(context.Background(), h.sess, session.DTMFSendInput{
				Call: string(h.call.Handle()), Digits: tc.digits, DurationMs: tc.dur, GapMs: tc.gap,
			})

			if got, want := apierr.CodeOf(planErr), apierr.CodeInvalidArgument; got != want {
				t.Fatalf("media_plan dtmf step answered %v (err=%v), want %v", got, planErr, want)
			}
			if apierr.CodeOf(toolErr) != apierr.CodeOf(planErr) {
				t.Fatalf("dtmf_send answered %v (err=%v) but the media_plan dtmf step carrying the "+
					"SAME arguments answered %v (err=%v) — one input must not have two contracts",
					apierr.CodeOf(toolErr), toolErr, apierr.CodeOf(planErr), planErr)
			}
		})
	}
}

// TestDTMFSendStillAcceptsAnInRangeRequest pins the bound's other edge: the
// §10.8 defaults and an ordinary explicit request must still reach sipua. A
// guard that rejected everything would pass the two tests above.
func TestDTMFSendStillAcceptsAnInRangeRequest(t *testing.T) {
	h := newMediaToolHarness(t)
	reached := 0
	h.agent.SendDTMFFn = func(context.Context, string, string, session.DTMFMode, int, int) (int, int, error) {
		reached++
		return 1, 100, nil
	}
	for _, in := range []session.DTMFSendInput{
		{Call: string(h.call.Handle()), Digits: "1"}, // both defaulted
		{Call: string(h.call.Handle()), Digits: "123*#", DurationMs: 8000, GapMs: ptrInt(0)},
		{Call: string(h.call.Handle()), Digits: strings.Repeat("1", 37), DurationMs: 8000, GapMs: ptrInt(50)}, // 37*8050 = 297850ms, just inside 300s
	} {
		if _, err := h.tools.DTMFSend(context.Background(), h.sess, in); err != nil {
			t.Fatalf("DTMFSend(%+v): %v", in, err)
		}
	}
	if reached != 3 {
		t.Fatalf("sipua.SendDTMF reached %d times, want 3", reached)
	}
}

// dtmfUncappedOOM enumerates DTMF payloads whose ONLY defect is the size of the
// render. Every field is individually legal — the digits are all in 0-9A-D*#,
// duration_ms is positive, gap_ms is non-negative — so nothing but the render
// budget can reject them, and each one is a single codec.NewDTMFSource
// allocation measured in hundreds of megabytes.
//
// They are exercised under `max_call_duration_s: 0`, which is legal, non-default
// and means "calls are uncapped". That is the configuration in which the K4
// guard reopened: BOTH surfaces skipped the budget under it, identically, so
// they agreed with each other and the existing cross-surface test could not see
// it.
var dtmfUncappedOOM = []struct {
	name   string
	digits string
	dur    int
	gap    *int // nil = omitted
	want   string
}{
	{"the reported OOM payload verbatim", "1", 0, ptrInt(60_000_000), "gap_ms"},
	{"one tone held for an hour", "1", 3_600_000, ptrInt(0), "duration_ms"},
	{"20000 digits at the wire-safe maximum tone length", strings.Repeat("1", 20000), 8000, ptrInt(50), "digits"},
}

// uncappedPolicy is policy.Defaults() with the call cap removed.
func uncappedPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p := policy.Defaults()
	p.Limits.MaxCallDurationS = 0
	return p
}

// TestDTMFRenderIsBoundedWhenCallsAreUncapped is R0. It asserts the render bound
// holds on BOTH surfaces under `max_call_duration_s: 0`, and that the two still
// answer one input the same way.
//
// The two halves are asserted in ONE subtest per payload on purpose. Splitting
// them is what let the hole reopen: a per-surface test passes as long as that
// surface is self-consistent, and here both surfaces were consistently wrong.
func TestDTMFRenderIsBoundedWhenCallsAreUncapped(t *testing.T) {
	for _, tc := range dtmfUncappedOOM {
		t.Run(tc.name, func(t *testing.T) {
			// The media_plan `dtmf` step, carrying the same arguments.
			planUA := fakes.NewUserAgent()
			_, planTS, planCtx, planUAHandle := newFixtureWithPolicy(t, fakes.NewArtifactStore(), fakes.NewTap(),
				func(context.Context, session.UAConfig) (session.UserAgent, error) { return planUA, nil }, uncappedPolicy(t))
			step := map[string]any{"op": "dtmf", "digits": tc.digits, "duration_ms": float64(tc.dur), "gap_ms": float64(*tc.gap)}
			if tc.dur == 0 {
				delete(step, "duration_ms") // an explicit 0 is its own rejection; omit it
			}
			_, planErr := planTS.CallDial(planCtx, "s1", session.CallDialInput{
				UA: planUAHandle, ToURI: "sip:bob@example.com", MediaPlan: []map[string]any{step},
			})

			// The discrete dtmf_send tool. Its SendDTMF fails the test on entry:
			// the pre-render lives behind SendDTMF, so "the rejection happened
			// before anything was allocated" is the property under test, and
			// actually allocating a gigabyte to observe it would be pointless.
			toolUA := fakes.NewUserAgent()
			m, toolTS, _, toolUAHandle := newFixtureWithPolicy(t, fakes.NewArtifactStore(), fakes.NewTap(),
				func(context.Context, session.UAConfig) (session.UserAgent, error) { return toolUA, nil }, uncappedPolicy(t))
			_, call := mustDial(t, m, toolTS, "s1", toolUAHandle, nil)
			toolUA.SendDTMFFn = func(context.Context, string, string, session.DTMFMode, int, int) (int, int, error) {
				t.Fatalf("sipua.SendDTMF was reached — an uncapped max_call_duration_s " +
					"is not a licence to pre-render an unbounded DTMF source")
				return 0, 0, nil
			}
			_, toolErr := toolTS.DTMFSend(context.Background(), "s1", session.DTMFSendInput{
				Call: string(call.Handle()), Digits: tc.digits, DurationMs: tc.dur, GapMs: tc.gap,
			})

			if got := apierr.CodeOf(planErr); got != apierr.CodeInvalidArgument {
				t.Fatalf("media_plan dtmf step answered %v (err=%v), want invalid_argument — "+
					"max_call_duration_s: 0 uncaps the CALL, not one allocation", got, planErr)
			}
			if got := apierr.CodeOf(toolErr); got != apierr.CodeInvalidArgument {
				t.Fatalf("dtmf_send answered %v (err=%v), want invalid_argument — "+
					"max_call_duration_s: 0 uncaps the CALL, not one allocation", got, toolErr)
			}
			if apierr.CodeOf(toolErr) != apierr.CodeOf(planErr) {
				t.Fatalf("dtmf_send answered %v but the media_plan dtmf step carrying the SAME "+
					"arguments answered %v — one input must not have two contracts",
					apierr.CodeOf(toolErr), apierr.CodeOf(planErr))
			}
			for _, err := range []error{toolErr, planErr} {
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error %q does not name the offending argument %q — a tool result "+
						"is read by a model and must say WHICH argument was out of range", err, tc.want)
				}
			}
			// dtmf_send is UNTOUCHED by Inputs §4/RN-1 (Phase 4 W1 M2) — its
			// bound stays min(dtmfRenderCeilingMs, configured cap) only, so it
			// still names "the Nms DTMF render ceiling" exactly as R0 shipped
			// it.
			if !strings.Contains(toolErr.Error(), "ceiling") {
				t.Fatalf("dtmf_send error %q does not name the bound it hit; with no max_call_duration_s "+
					"configured the reader has no way to learn what the limit was", toolErr)
			}
			// The media_plan `dtmf` step is NOT untouched: max_step_duration_s
			// (180s default) is now tighter than the 300,000ms DTMF render
			// ceiling every one of this table's payloads also exceeds, so it is
			// what binds and what the message must name. This is the ONE
			// intentional divergence RN-1 introduces between the two surfaces —
			// both still answer invalid_argument (asserted above), but the
			// BOUND NAME is no longer required to match, because the two
			// surfaces genuinely no longer share one contract for a value this
			// large.
			if !strings.Contains(planErr.Error(), "max_step_duration_s") {
				t.Fatalf("media_plan dtmf step error %q does not name max_step_duration_s — Inputs §4 "+
					"(RN-1) made it the tighter bound for every payload in this table", planErr)
			}
		})
	}
}

// TestDTMFStillSendsUnderAnUncappedPolicy is the ceiling's other edge: removing
// the call cap must not start rejecting ordinary DTMF. A guard that rejected
// everything would pass the test above.
func TestDTMFStillSendsUnderAnUncappedPolicy(t *testing.T) {
	ua := fakes.NewUserAgent()
	m, ts, ctx, uaHandle := newFixtureWithPolicy(t, fakes.NewArtifactStore(), fakes.NewTap(),
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return ua, nil }, uncappedPolicy(t))
	if _, err := ts.CallDial(ctx, "s1", session.CallDialInput{
		UA: uaHandle, ToURI: "sip:bob@example.com",
		MediaPlan: []map[string]any{{"op": "dtmf", "digits": "123*#", "duration_ms": float64(100), "gap_ms": float64(50)}},
	}); err != nil {
		t.Fatalf("CallDial with an in-range dtmf step under an uncapped policy: %v", err)
	}
	_, call := mustDial(t, m, ts, "s1", uaHandle, nil)
	reached := 0
	ua.SendDTMFFn = func(context.Context, string, string, session.DTMFMode, int, int) (int, int, error) {
		reached++
		return 5, 100, nil
	}
	if _, err := ts.DTMFSend(context.Background(), "s1", session.DTMFSendInput{
		Call: string(call.Handle()), Digits: "123*#", DurationMs: 100, GapMs: ptrInt(50),
	}); err != nil {
		t.Fatalf("DTMFSend under an uncapped policy: %v", err)
	}
	if reached != 1 {
		t.Fatalf("sipua.SendDTMF reached %d times, want 1", reached)
	}
}

func TestCallStatusOmitsMediaFieldsWhenNotNegotiated(t *testing.T) {
	ua := fakes.NewUserAgent() // MediaViewOK defaults to false (zero value)

	m, ts, ctx, uaHandle := newFixture(t, fakes.NewArtifactStore(), fakes.NewTap(),
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return ua, nil })
	callHandle, _ := mustDial(t, m, ts, "s1", uaHandle, nil)

	out, err := ts.CallStatus(ctx, "s1", session.CallStatusInput{Call: callHandle})
	if err != nil {
		t.Fatalf("CallStatus: %v", err)
	}
	om, _ := out.(map[string]any)
	for _, k := range []string{"codec", "local_media_addr", "srtp"} {
		if _, present := om[k]; present {
			t.Fatalf("%q must be omitted when no media negotiated", k)
		}
	}
}

// Task 19: dtmf_received on the tool surface.

func TestDTMFReceivedReturnsTheSpecShapeAndPages(t *testing.T) {
	h := newMediaToolHarness(t)
	h.call.RecordDigit(time.Unix(1, 0), "1", "rfc2833", 100)
	h.call.RecordDigit(time.Unix(2, 0), "2", "rfc2833", 120)

	out, err := h.tools.DTMFReceived(context.Background(), h.sess,
		session.DTMFReceivedInput{Call: string(h.call.Handle())})
	if err != nil {
		t.Fatalf("DTMFReceived: %v", err)
	}
	m := out.(map[string]any)
	digits := m["digits"].([]session.DTMFDigit)
	if len(digits) != 2 || digits[0].Digit != "1" || digits[1].Digit != "2" {
		t.Fatalf("digits=%+v", digits)
	}
	if digits[1].AtMs != time.Unix(2, 0).UnixMilli() {
		t.Fatalf("at_ms=%d want wall-clock UnixMilli (decision 16)", digits[1].AtMs)
	}
	next := m["next_since"].(int64)

	// Paging from the cursor returns nothing new.
	out2, err := h.tools.DTMFReceived(context.Background(), h.sess,
		session.DTMFReceivedInput{Call: string(h.call.Handle()), Since: next})
	if err != nil {
		t.Fatal(err)
	}
	if got := out2.(map[string]any)["digits"].([]session.DTMFDigit); len(got) != 0 {
		t.Fatalf("paging past the cursor returned %d digits", len(got))
	}
}

func TestDTMFReceivedAnswersAfterHangupAndGoneAfterEviction(t *testing.T) {
	h := newMediaToolHarness(t)
	h.call.RecordDigit(time.Unix(1, 0), "9", "inband", 100)
	if err := h.call.TryTerminate(time.Unix(2, 0), "local_hangup", session.EventBye); err != nil {
		t.Fatal(err)
	}
	out, err := h.tools.DTMFReceived(context.Background(), h.sess,
		session.DTMFReceivedInput{Call: string(h.call.Handle())})
	if err != nil {
		t.Fatalf("dtmf_received must answer a terminated call: %v", err)
	}
	if len(out.(map[string]any)["digits"].([]session.DTMFDigit)) != 1 {
		t.Fatal("the digit ring must survive termination")
	}

	if err := h.mgr.EvictCallForTest(context.Background(), h.sess, h.call.Handle()); err != nil {
		t.Fatalf("EvictCallForTest: %v", err)
	}
	if _, err := h.tools.DTMFReceived(context.Background(), h.sess,
		session.DTMFReceivedInput{Call: string(h.call.Handle())}); apierr.CodeOf(err) != apierr.CodeGone {
		t.Fatalf("code=%v want gone once the registry has evicted the call (§N3)", apierr.CodeOf(err))
	}
}

// Task 31: call_status gains dtmf_mode and session_timer.

func TestCallStatusReportsDTMFModeAndSessionTimer(t *testing.T) {
	// Every asserted value is deliberately NOT a default or a zero value: "info"
	// is not the profile's rfc2833 default, 120/240 are neither 1800
	// (session_expires_s) nor 90 (min_se_s), and the two sub-cases disagree on
	// every field, so a hardcoded constant cannot satisfy both.
	cases := []struct {
		name string
		view session.SessionTimerView
	}{
		{"we refresh", session.SessionTimerView{IntervalS: 120, Refresher: "uac", NextRefreshMs: 37000, Armed: true}},
		// Task 30: when the PEER refreshes, next_refresh_ms is the WATCHDOG
		// deadline, not a refresh of ours.
		{"peer refreshes", session.SessionTimerView{IntervalS: 240, Refresher: "uas", NextRefreshMs: 111000, Armed: true}},
		// C9/A-M6: Armed false with next_refresh_ms 0 must render as its own
		// `armed` key, not be indistinguishable from the armed-but-due cases.
		{"no timer armed", session.SessionTimerView{IntervalS: 120, Refresher: "uac", NextRefreshMs: 0, Armed: false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newMediaToolHarness(t)
			wantDialog := h.call.DialogID()
			h.agent.DTMFModeFn = func(d string) (string, bool) {
				if d != wantDialog {
					t.Fatalf("DTMFMode got dialogID %q want the call's %q", d, wantDialog)
				}
				return "info", true
			}
			h.agent.SessionTimerViewFn = func(d string) (session.SessionTimerView, bool) {
				if d != wantDialog {
					t.Fatalf("SessionTimerView got dialogID %q want the call's %q", d, wantDialog)
				}
				return tc.view, true
			}
			out, err := h.tools.CallStatus(context.Background(), h.sess,
				session.CallStatusInput{Call: string(h.call.Handle())})
			if err != nil {
				t.Fatalf("CallStatus: %v", err)
			}
			m := out.(map[string]any)
			if m["dtmf_mode"] != "info" {
				t.Fatalf("dtmf_mode=%v want info", m["dtmf_mode"])
			}
			st, ok := m["session_timer"].(map[string]any)
			if !ok {
				t.Fatalf("session_timer missing: %+v", m)
			}
			if st["interval_s"] != tc.view.IntervalS ||
				st["refresher"] != tc.view.Refresher ||
				st["next_refresh_ms"] != tc.view.NextRefreshMs ||
				st["armed"] != tc.view.Armed {
				t.Fatalf("session_timer=%+v want %+v", st, tc.view)
			}
		})
	}
}

func TestCallStatusOmitsSessionTimerWhenNoneWasNegotiated(t *testing.T) {
	h := newMediaToolHarness(t)
	h.agent.SessionTimerViewFn = func(string) (session.SessionTimerView, bool) {
		return session.SessionTimerView{}, false
	}
	out, err := h.tools.CallStatus(context.Background(), h.sess,
		session.CallStatusInput{Call: string(h.call.Handle())})
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if _, present := m["session_timer"]; present {
		t.Fatal("session_timer must be ABSENT, not null, when RFC 4028 was not negotiated (§4)")
	}
}

func TestCallStatusOmitsDTMFModeForAnUnknownDialog(t *testing.T) {
	h := newMediaToolHarness(t)
	h.agent.DTMFModeFn = func(string) (string, bool) { return "", false }
	out, err := h.tools.CallStatus(context.Background(), h.sess,
		session.CallStatusInput{Call: string(h.call.Handle())})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := out.(map[string]any)["dtmf_mode"]; present {
		t.Fatal("dtmf_mode must be absent when the UA cannot report one")
	}
}
