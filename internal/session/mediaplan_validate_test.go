package session

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

func testPolicyWithPrompt() *policy.Policy {
	p := policy.Defaults()
	// Defaults() has no prompts; inject one via the exported field.
	p.Prompts = []policy.Prompt{{Name: "prompt-1", Path: "/x.wav"}}
	return p
}

func TestValidateMediaPlanHappyPath(t *testing.T) {
	steps, err := validateMediaPlan(testPolicyWithPrompt(), []map[string]any{
		{"op": "play", "prompt": "prompt-1"},
		{"op": "record", "duration_ms": float64(5000)},
		{"op": "wait", "duration_ms": float64(1000)},
		{"op": "hangup"},
	})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(steps) != 4 || steps[0].Op != "play" || steps[0].Prompt != "prompt-1" {
		t.Fatalf("steps=%+v", steps)
	}
	if steps[1].DurationMs != 5000 || steps[0].Repeat != 1 {
		t.Fatalf("defaults not applied: %+v", steps)
	}
}

func TestValidateMediaPlanRejects(t *testing.T) {
	cases := []struct {
		name string
		raw  []map[string]any
	}{
		{"unknown op garbage", []map[string]any{{"op": "frobnicate"}}},
		{"unregistered prompt", []map[string]any{{"op": "play", "prompt": "nope"}}},
		{"record without duration", []map[string]any{{"op": "record"}}},
		{"missing op", []map[string]any{{"prompt": "prompt-1"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := validateMediaPlan(testPolicyWithPrompt(), c.raw); apierr.CodeOf(err) != apierr.CodeInvalidArgument {
				t.Fatalf("code=%v want invalid_argument", apierr.CodeOf(err))
			}
		})
	}
}

// TestPlayStepCarriesANonDefaultRepeat pins decodePlay's `repeat` pass-through.
// Every plan test in the tree used the DEFAULT of 1 — the happy path above
// asserts steps[0].Repeat == 1, which is precisely the value planInt returns
// when the field is never read at all — so `Repeat: repeat` could be replaced
// with `Repeat: 1` and every package that can reach validateMediaPlan stayed
// green. planInt's own `return n, nil` had zero statement coverage as a result,
// and "repeat" is its only caller.
//
// The value is not cosmetic: it reaches codec.NewPromptSource through sipua's
// Play, where it decides how many times the prompt is actually served. This is
// the `play` sibling of the media-plan `dtmf` step's timing pass-through that
// the same sweep found dead earlier in this cycle.
func TestPlayStepCarriesANonDefaultRepeat(t *testing.T) {
	steps, err := validateMediaPlan(testPolicyWithPrompt(), []map[string]any{
		{"op": "play", "prompt": "prompt-1", "repeat": float64(3)},
	})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if steps[0].Repeat != 3 {
		t.Fatalf("Repeat = %d want 3 — the plan's repeat never reached the step, so the "+
			"prompt is served once however many times the caller asked for", steps[0].Repeat)
	}
}

// TestValidateMediaPlanRejectsOutOfRangeStepFields pins three per-step bounds
// that rejected nothing at all: deleting decodePlay's `repeat < 1` guard,
// decodeWait's `duration_ms <= 0` guard and decodeWaitDTMF's alphabet check each
// left every package that reaches validateMediaPlan green.
//
// Each row asserts the EXACT message rather than only the invalid_argument
// code, because a plan is usually rejectable for several reasons at once — a
// wait_dtmf carrying a bad digit is also a wait_dtmf that could be failed on
// some other field — and a code-only assertion passes on its own failure mode.
func TestValidateMediaPlanRejectsOutOfRangeStepFields(t *testing.T) {
	cases := []struct {
		name string
		raw  []map[string]any
		want string
	}{
		{"repeat below 1", []map[string]any{
			{"op": "play", "prompt": "prompt-1", "repeat": float64(0)}},
			"invalid_argument: media_plan[0]: repeat must be >= 1"},
		{"wait with no duration_ms", []map[string]any{
			{"op": "wait"}},
			"invalid_argument: media_plan[0]: wait requires a positive duration_ms"},
		{"wait with an explicit zero duration_ms", []map[string]any{
			{"op": "wait", "duration_ms": float64(0)}},
			"invalid_argument: media_plan[0]: wait requires a positive duration_ms"},
		{"wait_dtmf digit outside the alphabet", []map[string]any{
			{"op": "wait_dtmf", "digits": "12X", "timeout_ms": float64(1000)}},
			`invalid_argument: media_plan[0]: digits "12X" contains a character outside 0-9A-D*#`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateMediaPlan(testPolicyWithPrompt(), tc.raw)
			if err == nil {
				t.Fatal("expected invalid_argument")
			}
			if err.Error() != tc.want {
				t.Fatalf("message = %q want %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidateMediaPlanRejectsOversizedDuration(t *testing.T) {
	p := testPolicyWithPrompt()
	p.Limits.MaxCallDurationS = 2 // 2s cap
	// wait 3000ms alone exceeds the cap.
	if _, err := validateMediaPlan(p, []map[string]any{{"op": "wait", "duration_ms": float64(3000)}}); apierr.CodeOf(err) != apierr.CodeInvalidArgument {
		t.Fatalf("code=%v want invalid_argument for oversized plan", apierr.CodeOf(err))
	}
}

func TestPlanOpDecoderTableCoversEverySupportedOp(t *testing.T) {
	want := []string{"play", "record", "wait", "dtmf", "wait_dtmf", "hangup"}
	if len(planOps) != len(want) {
		t.Fatalf("planOps has %d entries, want %d: %v", len(planOps), len(want), planOps)
	}
	for _, op := range want {
		if planOps[op] == nil {
			t.Fatalf("planOps is missing a decoder for %q", op)
		}
	}
}

func TestTypedFieldReaderRejectsWrongTypesWithTheUniformMessage(t *testing.T) {
	p := testPolicyWithPrompt()
	cases := []struct {
		name string
		raw  []map[string]any
		want string
	}{
		{"repeat is a string", []map[string]any{
			{"op": "play", "prompt": "prompt-1", "repeat": "3"}}, "invalid_argument: media_plan[0]: repeat must be a number"},
		{"duration_ms is a string", []map[string]any{
			{"op": "wait", "duration_ms": "50"}}, "invalid_argument: media_plan[0]: duration_ms must be a number"},
		{"reason is a number", []map[string]any{
			{"op": "hangup", "reason": 7}}, "invalid_argument: media_plan[0]: reason must be a string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateMediaPlan(p, tc.raw)
			if err == nil {
				t.Fatal("expected invalid_argument")
			}
			if apierr.CodeOf(err) != apierr.CodeInvalidArgument {
				t.Fatalf("code=%v want invalid_argument", apierr.CodeOf(err))
			}
			if err.Error() != tc.want {
				t.Fatalf("message = %q want %q", err.Error(), tc.want)
			}
		})
	}
}

func TestDTMFStepDecodesWithDefaultsAndMinDuration(t *testing.T) {
	p := policy.Defaults()
	steps, err := validateMediaPlan(p, []map[string]any{
		{"op": "dtmf", "digits": "123*#"},
	})
	if err != nil {
		t.Fatalf("validateMediaPlan: %v", err)
	}
	got := steps[0]
	// The expectations are the SHARED constants, never hand-written 100/50: if the
	// canonical default moves, this test moves with it instead of pinning a stale
	// literal that the resolver no longer produces.
	if got.Op != "dtmf" || got.Digits != "123*#" ||
		got.DurationMs != DefaultDTMFDurationMs || got.GapMs != DefaultDTMFGapMs {
		t.Fatalf("step = %+v want defaults duration_ms=%d gap_ms=%d",
			got, DefaultDTMFDurationMs, DefaultDTMFGapMs)
	}
}

// TestDTMFTimingDefaultsComeFromTheSharedResolver is the anti-drift pin for the
// TWO call sites of ResolveDTMFTiming (this decoder, and sipua's
// resolveDTMFTiming at the top of SendDTMF). Both need a resolved number, at
// different times — the decoder at validation time for its min-duration bound,
// the sender at call time — so neither can be deleted; what CAN be shared is the
// default values and the tri-state rule, and this test fails if the decoder ever
// grows its own copy of them again.
func TestDTMFTimingDefaultsComeFromTheSharedResolver(t *testing.T) {
	p := policy.Defaults()
	steps, err := validateMediaPlan(p, []map[string]any{{"op": "dtmf", "digits": "1"}})
	if err != nil {
		t.Fatalf("validateMediaPlan: %v", err)
	}
	// "Absent" in the resolver's own encoding: a non-positive duration and a
	// negative gap. Whatever the shared function makes of that is what an
	// all-defaults plan step MUST carry.
	wantDur, wantGap := ResolveDTMFTiming(0, DTMFGapUnset)
	if steps[0].DurationMs != wantDur || steps[0].GapMs != wantGap {
		t.Fatalf("step timing = %d/%d, ResolveDTMFTiming(0, DTMFGapUnset) = %d/%d — the "+
			"decoder is applying its OWN defaults instead of the shared resolver's",
			steps[0].DurationMs, steps[0].GapMs, wantDur, wantGap)
	}
}

// TestResolveDTMFTimingIsTheOneTriStateRule exercises the shared function
// directly, over the whole domain both call sites depend on.
func TestResolveDTMFTimingIsTheOneTriStateRule(t *testing.T) {
	cases := []struct {
		name             string
		dur, gap         int64
		wantDur, wantGap int64
	}{
		{"both given", 80, 40, 80, 40},
		{"explicit zero gap means NO gap", 80, 0, 80, 0},
		{"unset gap defaults", 80, DTMFGapUnset, 80, DefaultDTMFGapMs},
		{"unset duration defaults", 0, 20, DefaultDTMFDurationMs, 20},
		{"both unset", 0, DTMFGapUnset, DefaultDTMFDurationMs, DefaultDTMFGapMs},
		// Idempotence is what lets a plan step be resolved at validation time and
		// then pass through the sender's resolver again unchanged.
		{"already resolved is unchanged", DefaultDTMFDurationMs, DefaultDTMFGapMs,
			DefaultDTMFDurationMs, DefaultDTMFGapMs},
		{"already resolved zero gap is unchanged", 80, 0, 80, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotDur, gotGap := ResolveDTMFTiming(tc.dur, tc.gap)
			if gotDur != tc.wantDur || gotGap != tc.wantGap {
				t.Fatalf("ResolveDTMFTiming(%d, %d) = %d, %d want %d, %d",
					tc.dur, tc.gap, gotDur, gotGap, tc.wantDur, tc.wantGap)
			}
		})
	}
}

// TestDTMFStepKeepsAnExplicitZeroGap pins the tri-state at the decode boundary:
// planInt64 returns its default ONLY when the field is absent, so an explicit
// `gap_ms: 0` survives as 0 and means NO GAP all the way down to the sender. It
// must never be rewritten to 50 — that would silently override the plan author,
// and it is also what makes the min-duration bound below honest.
func TestDTMFStepKeepsAnExplicitZeroGap(t *testing.T) {
	p := policy.Defaults()
	steps, err := validateMediaPlan(p, []map[string]any{
		{"op": "dtmf", "digits": "12", "duration_ms": 100, "gap_ms": 0},
	})
	if err != nil {
		t.Fatalf("validateMediaPlan: %v", err)
	}
	if steps[0].GapMs != 0 {
		t.Fatalf("GapMs=%d — an explicit gap_ms of 0 means NO GAP and must not become 50",
			steps[0].GapMs)
	}
	// And an ABSENT gap_ms still defaults, which is the other half of the pair.
	steps, err = validateMediaPlan(p, []map[string]any{
		{"op": "dtmf", "digits": "12", "duration_ms": 100},
	})
	if err != nil {
		t.Fatal(err)
	}
	if steps[0].GapMs != DefaultDTMFGapMs {
		t.Fatalf("GapMs=%d want the %dms default for an ABSENT gap_ms",
			steps[0].GapMs, DefaultDTMFGapMs)
	}
}

func TestDTMFStepRejectsIllegalDigitsAndModes(t *testing.T) {
	p := policy.Defaults()
	cases := []struct {
		name string
		m    map[string]any
		want string
	}{
		{"empty digits", map[string]any{"op": "dtmf"}, "invalid_argument: media_plan[0]: dtmf requires a non-empty digits string"},
		{"illegal digit", map[string]any{"op": "dtmf", "digits": "12X"}, `invalid_argument: media_plan[0]: digits "12X" contains a character outside 0-9A-D*#`},
		{"bad mode", map[string]any{"op": "dtmf", "digits": "1", "mode": "sipinfo"}, `invalid_argument: media_plan[0]: mode "sipinfo" must be rfc2833, inband or info`},
		{"negative duration", map[string]any{"op": "dtmf", "digits": "1", "duration_ms": -1}, "invalid_argument: media_plan[0]: duration_ms must be > 0"},
		// An explicitly-GIVEN zero duration is invalid_argument, and stays so under
		// the shared resolver: the decoder validates the RAW field before handing
		// it to ResolveDTMFTiming, so "the author wrote 0" never reaches the
		// resolver's "non-positive means unset" rule and get silently defaulted to
		// 100. Absence is detected by key presence, not by the value.
		{"explicit zero duration", map[string]any{"op": "dtmf", "digits": "1", "duration_ms": 0}, "invalid_argument: media_plan[0]: duration_ms must be > 0"},
		{"negative gap", map[string]any{"op": "dtmf", "digits": "1", "gap_ms": -1}, "invalid_argument: media_plan[0]: gap_ms must be >= 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateMediaPlan(p, []map[string]any{tc.m})
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err = %v want %q", err, tc.want)
			}
		})
	}
}

func TestWaitDTMFRequiresPositiveTimeoutAndContributesIt(t *testing.T) {
	p := policy.Defaults()
	if _, err := validateMediaPlan(p, []map[string]any{{"op": "wait_dtmf"}}); err == nil ||
		err.Error() != "invalid_argument: media_plan[0]: wait_dtmf requires a positive timeout_ms" {
		t.Fatalf("err = %v", err)
	}
	steps, err := validateMediaPlan(p, []map[string]any{
		{"op": "wait_dtmf", "digits": "42", "timeout_ms": 5000},
	})
	if err != nil {
		t.Fatalf("validateMediaPlan: %v", err)
	}
	if steps[0].TimeoutMs != 5000 || steps[0].Digits != "42" {
		t.Fatalf("step = %+v", steps[0])
	}
}

// TestWaitDTMFTimeoutIsBoundedAbove is the ceiling half of the rule above, and
// it is written against an UNCAPPED policy on purpose: `max_call_duration_s: 0`
// means "calls are uncapped", which skips validateMediaPlan's plan-level sum
// entirely, so before this bound existed a floor was the only thing timeout_ms
// had. 9999999999999 ms then survived validation and reached sipua's
// time.Duration(timeoutMs)*time.Millisecond, which overflows negative and makes
// the wait return AT ONCE — a wait that does not wait. The sibling `dtmf` step
// got this exact treatment as the R0 fix; wait_dtmf did not, and this is it.
func TestWaitDTMFTimeoutIsBoundedAbove(t *testing.T) {
	uncapped := policy.Defaults()
	uncapped.Limits.MaxCallDurationS = 0

	t.Run("uncapped policy still bounds one wait", func(t *testing.T) {
		_, err := validateMediaPlan(uncapped, []map[string]any{
			{"op": "wait_dtmf", "timeout_ms": int64(9999999999999)},
		})
		if err == nil {
			t.Fatal("validateMediaPlan accepted a timeout_ms that overflows time.Duration — " +
				"max_call_duration_s: 0 uncaps the CALL, not one wait")
		}
		// Phase 4 W1 M2 (Inputs §4, RN-1): max_step_duration_s (180s default) is
		// now TIGHTER than the 300,000ms DTMF render ceiling, so it is what
		// binds first and what the message must name — "ceiling" (the DTMF
		// render bound's own wording) no longer appears here at all.
		if !strings.Contains(err.Error(), "timeout_ms") || !strings.Contains(err.Error(), "max_step_duration_s") {
			t.Fatalf("error %q must name both the offending argument and the bound it hit; "+
				"a plan rejection is read by a model", err)
		}
	})
	// THE SUBTEST ABOVE DOES NOT PIN THE CEILING, AND THIS ONE DOES.
	// max_step_duration_s*1000+1 (180001ms) is now the discriminating figure,
	// not dtmfRenderCeilingMs+1 (300001ms): once Inputs §4 landed,
	// max_step_duration_s's 180s default became the tighter of the two
	// ceilings, so 300001ms no longer distinguishes decodeWaitDTMF's real
	// budget from a different one — it is caught by max_step_duration_s
	// regardless of what the (now-unreachable-here) DTMF ceiling is set to.
	// It has to be checked under the UNCAPPED policy because that is where
	// validateMediaPlan's plan-level sum is skipped entirely
	// (`max_call_duration_s: 0`), leaving decodeWaitDTMF's own bound as the
	// only thing that can reject it.
	t.Run("one millisecond over the ceiling is rejected", func(t *testing.T) {
		stepCeilingMs := int64(uncapped.Limits.MaxStepDurationS) * 1000
		_, err := validateMediaPlan(uncapped, []map[string]any{
			{"op": "wait_dtmf", "timeout_ms": stepCeilingMs + 1},
		})
		if err == nil {
			t.Fatalf("validateMediaPlan accepted timeout_ms %d, one over the %dms max_step_duration_s "+
				"ceiling it charges against — the bound decodeWaitDTMF applies is not that ceiling",
				stepCeilingMs+1, stepCeilingMs)
		}
	})
	// The accept side. A guard that rejected every wait, or that picked some
	// number far below the ceiling it advertises, would pass the case above.
	t.Run("a wait exactly at the ceiling is legal", func(t *testing.T) {
		stepCeilingMs := int64(uncapped.Limits.MaxStepDurationS) * 1000
		steps, err := validateMediaPlan(uncapped, []map[string]any{
			{"op": "wait_dtmf", "timeout_ms": stepCeilingMs},
		})
		if err != nil {
			t.Fatalf("validateMediaPlan rejected a wait AT the ceiling (%dms): %v", stepCeilingMs, err)
		}
		if steps[0].TimeoutMs != stepCeilingMs {
			t.Fatalf("step = %+v", steps[0])
		}
	})
	// And when the policy caps calls BELOW the ceiling, the cap is what binds
	// and what the message names — the budget helper's job, reused rather than
	// reimplemented.
	//
	// THE WHOLE MESSAGE IS ASSERTED, NOT A SUBSTRING OF IT, because two different
	// rejections here name max_call_duration_s (5s): decodeWaitDTMF's per-STEP
	// budget, and validateMediaPlan's plan-level minimum-duration sum at the
	// bottom of the loop, which this 6000ms wait also exceeds. A `Contains`
	// assertion is satisfied by either, so it passed with decodeWaitDTMF's budget
	// removed altogether — the sum caught the plan and the subtest could not tell.
	// Only the `media_plan[0]: timeout_ms ...` form is the per-step one.
	t.Run("a tighter call cap binds first and is named", func(t *testing.T) {
		capped := policy.Defaults()
		capped.Limits.MaxCallDurationS = 5
		_, err := validateMediaPlan(capped, []map[string]any{
			{"op": "wait_dtmf", "timeout_ms": 6000},
		})
		const want = "invalid_argument: media_plan[0]: timeout_ms 6000 exceeds max_call_duration_s (5s)"
		if err == nil || err.Error() != want {
			t.Fatalf("err = %v, want %q — the STEP's own budget must be what rejects this, "+
				"not the plan-level duration sum that happens to name the same limit", err, want)
		}
	})
}

func TestDTMFStepMinDurationCountsTowardTheCallDurationCap(t *testing.T) {
	p := policy.Defaults()
	p.Limits.MaxCallDurationS = 1 // 1000 ms
	// 20 digits x (DefaultDTMFDurationMs + DefaultDTMFGapMs) = 3000 ms > 1000 ms.
	// This is the reason decodeDTMF cannot defer resolution to call time: the bound
	// needs concrete numbers here, before the call is dialed.
	_, err := validateMediaPlan(p, []map[string]any{
		{"op": "dtmf", "digits": "12345678901234567890"},
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds max_call_duration_s") {
		t.Fatalf("err = %v want the min-duration rejection", err)
	}
}

// TestWaitAndRecordDurationAreBoundedByMaxStepDurationS is Inputs §4 (RN-1)'s
// per-step ceiling for the two ops that are NOT DTMF surfaces: wait and
// record. Neither is bound by dtmfRenderCeilingMs (that ceiling is DTMF
// renders only) — only max_step_duration_s and, when tighter, the configured
// call-duration cap.
func TestWaitAndRecordDurationAreBoundedByMaxStepDurationS(t *testing.T) {
	p := policy.Defaults()
	stepCeilingMs := int64(p.Limits.MaxStepDurationS) * 1000 // 180000 by default

	for _, op := range []string{"wait", "record"} {
		t.Run(op+" exactly at the ceiling is legal", func(t *testing.T) {
			steps, err := validateMediaPlan(p, []map[string]any{
				{"op": op, "duration_ms": float64(stepCeilingMs)},
			})
			if err != nil {
				t.Fatalf("validateMediaPlan rejected %s AT the ceiling (%dms): %v", op, stepCeilingMs, err)
			}
			if steps[0].DurationMs != stepCeilingMs {
				t.Fatalf("step = %+v", steps[0])
			}
		})
		t.Run(op+" one millisecond over the ceiling is rejected", func(t *testing.T) {
			_, err := validateMediaPlan(p, []map[string]any{
				{"op": op, "duration_ms": float64(stepCeilingMs + 1)},
			})
			want := fmt.Sprintf("invalid_argument: media_plan[0]: duration_ms %d exceeds max_step_duration_s (%ds)",
				stepCeilingMs+1, p.Limits.MaxStepDurationS)
			if err == nil || err.Error() != want {
				t.Fatalf("err = %v, want %q", err, want)
			}
		})
	}
}

// TestDTMFStepDerivedTotalIsBoundedByMaxStepDurationS is Inputs §4 (RN-1)'s
// per-step ceiling applied to a `dtmf` step's DERIVED total (len(digits) x
// (duration_ms + gap_ms)) — NOT the individual duration_ms/gap_ms factors,
// which stay bound by the DTMF render ceiling alone (checkDTMFRenderBudget,
// unchanged). max_call_duration_s is raised well above both ceilings here so
// neither it nor the plan-level minimum-duration sum is what binds; only
// decodeDTMF's own derived-total check is under test.
//
// This is NOT item 2 (P4-N01)'s mutation-proof surface — that one lives on
// checkDTMFSendBounds (toolservice_media_test.go / a dedicated
// checkDTMFSendBounds test file), specifically because this media-plan
// surface's per-step ceiling (180,000ms default) now binds BEFORE
// dtmfRenderCeilingMs (300,000ms) ever would, making dtmfRenderCeilingMs's
// own value unobservable through validateMediaPlan.
func TestDTMFStepDerivedTotalIsBoundedByMaxStepDurationS(t *testing.T) {
	p := policy.Defaults()
	p.Limits.MaxCallDurationS = 86400                        // well above both ceilings; must not bind here
	stepCeilingMs := int64(p.Limits.MaxStepDurationS) * 1000 // 180000 by default

	t.Run("derived total exactly at the ceiling is legal", func(t *testing.T) {
		// 2 digits x (89999 + 1) = 180000ms, at the ceiling.
		steps, err := validateMediaPlan(p, []map[string]any{
			{"op": "dtmf", "digits": "12", "duration_ms": float64(89999), "gap_ms": float64(1)},
		})
		if err != nil {
			t.Fatalf("validateMediaPlan rejected a derived total AT the ceiling (%dms): %v", stepCeilingMs, err)
		}
		if steps[0].DurationMs+steps[0].GapMs != 90000 {
			t.Fatalf("step = %+v", steps[0])
		}
	})
	t.Run("derived total one millisecond over the ceiling is rejected", func(t *testing.T) {
		// 2 digits x (90000 + 0) = 180000... bump gap by 1 to clear it: 2 x 90000.5
		// is not integral, so use duration_ms 90000, gap_ms 1 -> 2*90001=180002.
		_, err := validateMediaPlan(p, []map[string]any{
			{"op": "dtmf", "digits": "12", "duration_ms": float64(90000), "gap_ms": float64(1)},
		})
		want := fmt.Sprintf("invalid_argument: media_plan[0]: 2 digits x (duration_ms 90000 + gap_ms 1) = 180002ms exceeds max_step_duration_s (%ds)",
			p.Limits.MaxStepDurationS)
		if err == nil || err.Error() != want {
			t.Fatalf("err = %v, want %q", err, want)
		}
	})
}

// TestPlanLevelDurationSumSaturatesInsteadOfOverflowing is the Rule 9
// mutation proof for the plan-level minimum-duration sum's overflow fix
// (Inputs §4/RN-1). It is a direct unit test of saturatingAddMs, isolated
// from any per-step ceiling: Inputs §4's own max_step_duration_s (and item
// 2's dtmfRenderCeilingMs) now reject an individual step anywhere near 5e18ms
// long before validateMediaPlan's loop ever sums two of them, so the ONLY way
// to exercise the plan-level SUM's own overflow defence — decision 8,
// condition 3: it must not depend on any cap existing — is to test the
// accumulator directly.
func TestPlanLevelDurationSumSaturatesInsteadOfOverflowing(t *testing.T) {
	const big = int64(5_000_000_000_000_000_000) // 5e18ms; two of these overflow int64 under plain +.
	got := saturatingAddMs(big, big)
	if got <= 0 {
		t.Fatalf("saturatingAddMs(%d, %d) = %d, want a large POSITIVE saturated value — "+
			"plain addition wraps this pair negative", big, big, got)
	}
	if got < big {
		t.Fatalf("saturatingAddMs(%d, %d) = %d must not be smaller than either input", big, big, got)
	}
}

// TestUnknownStepFieldsAreRejectedPerOp is E/I4's Rule 9 mutation proof.
// Before this check existed, every decoder read only the keys it recognised
// and validateMediaPlan never checked for the rest, so
// {"op":"play","prompts":"x"} (note the typo: "prompts", not "prompt")
// validated cleanly and played nothing.
func TestUnknownStepFieldsAreRejectedPerOp(t *testing.T) {
	cases := []struct {
		name string
		raw  map[string]any
		want string
	}{
		{
			name: "a typo'd field is rejected",
			raw:  map[string]any{"op": "play", "prompts": "prompt-1"},
			want: `invalid_argument: media_plan[0]: unknown field "prompts" for op "play"`,
		},
		{
			// The PER-OP proof: "digits" is a real key — dtmf and wait_dtmf
			// both read it — just not one "wait" understands. A flat union
			// across every op would wrongly let this through.
			name: "a field valid for a DIFFERENT op is still rejected",
			raw:  map[string]any{"op": "wait", "duration_ms": float64(1000), "digits": "1"},
			want: `invalid_argument: media_plan[0]: unknown field "digits" for op "wait"`,
		},
		{
			name: "hangup rejects an unrecognised field",
			raw:  map[string]any{"op": "hangup", "code": float64(486)},
			want: `invalid_argument: media_plan[0]: unknown field "code" for op "hangup"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateMediaPlan(testPolicyWithPrompt(), []map[string]any{tc.raw})
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestOpFieldRejectsNonStringTypesWithATypedError is E-M3's Rule 9 mutation
// proof: validateMediaPlan used to read `op` via a raw `m["op"].(string)`
// comma-ok assertion, which silently reads ANY wrong-typed value as "" — so
// {"op": 7} produced the misleading "op is required" instead of a type
// error. Routed through planStr, like every other field, it now gets the
// same typed rejection repeat/duration_ms/reason already get.
func TestOpFieldRejectsNonStringTypesWithATypedError(t *testing.T) {
	_, err := validateMediaPlan(policy.Defaults(), []map[string]any{{"op": 7}})
	const want = "invalid_argument: media_plan[0]: op must be a string"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q — a non-string op must be a TYPE error, not \"op is required\"", err, want)
	}
}

// TestPlayWaitCompleteFalseIsRejectedWithASpecificMessage is the Cycle 1 fix's
// mutation proof for `play.wait_complete`: inside a plan, play is always
// wait_complete=true (call.go's execStep hardcodes true; sequencing is the
// plan's job). An explicit `false` must get a specific, actionable rejection —
// not the generic "unknown field" text E/I4 would otherwise produce, and not
// silent accept-and-ignore (the defect class the allowlist exists to
// eliminate). `true` and the field omitted must both still validate exactly
// as before.
func TestPlayWaitCompleteFalseIsRejectedWithASpecificMessage(t *testing.T) {
	const wantFalse = "invalid_argument: media_plan[0]: wait_complete: false is not supported " +
		"inside a media_plan step — play always completes before the next step runs"
	_, err := validateMediaPlan(testPolicyWithPrompt(), []map[string]any{
		{"op": "play", "prompt": "prompt-1", "wait_complete": false},
	})
	if err == nil || err.Error() != wantFalse {
		t.Fatalf("wait_complete:false err = %v, want %q", err, wantFalse)
	}

	steps, err := validateMediaPlan(testPolicyWithPrompt(), []map[string]any{
		{"op": "play", "prompt": "prompt-1", "wait_complete": true},
	})
	if err != nil || len(steps) != 1 {
		t.Fatalf("wait_complete:true should validate cleanly, got steps=%v err=%v", steps, err)
	}

	steps, err = validateMediaPlan(testPolicyWithPrompt(), []map[string]any{
		{"op": "play", "prompt": "prompt-1"},
	})
	if err != nil || len(steps) != 1 {
		t.Fatalf("wait_complete omitted should validate cleanly, got steps=%v err=%v", steps, err)
	}
}

// TestRecordUntilSilenceMsIsRejectedWithASpecificMessage is the Cycle 1 fix's
// mutation proof for `record.until_silence_ms`: no silence detection exists
// anywhere in decodeRecord/RecordStart, so the field must be rejected with a
// specific, actionable message — not the generic "unknown field" text, and
// not the unrelated "record requires a positive duration_ms" message when
// duration_ms is also absent. Supplying BOTH until_silence_ms and a positive
// duration_ms must still reject: the caller asked for something unsupported
// and must be told, not have half the request silently dropped in favor of
// duration_ms.
func TestRecordUntilSilenceMsIsRejectedWithASpecificMessage(t *testing.T) {
	const want = "invalid_argument: media_plan[0]: record: until_silence_ms is not yet supported " +
		"in media_plan steps — use duration_ms"
	cases := []struct {
		name string
		raw  map[string]any
	}{
		{"until_silence_ms with a positive duration_ms", map[string]any{
			"op": "record", "duration_ms": float64(5000), "until_silence_ms": float64(3000)}},
		{"until_silence_ms alone, no duration_ms", map[string]any{
			"op": "record", "until_silence_ms": float64(3000)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := validateMediaPlan(testPolicyWithPrompt(), []map[string]any{c.raw})
			if err == nil || err.Error() != want {
				t.Fatalf("err = %v, want %q", err, want)
			}
		})
	}
}

// TestRecordNameIsDecodedOntoTheStep pins decodeRecord's `name` field: it must
// reach the returned MediaPlanStep so call.go's execStep can thread it into
// RecordStart (previously it was decoded and then dropped — see
// TestMediaPlanRecordStepThreadsExplicitName in internal/sipua for the
// end-to-end wiring proof).
func TestRecordNameIsDecodedOntoTheStep(t *testing.T) {
	steps, err := validateMediaPlan(testPolicyWithPrompt(), []map[string]any{
		{"op": "record", "duration_ms": float64(5000), "name": "greeting"},
	})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if steps[0].Name != "greeting" {
		t.Fatalf("Name = %q, want %q", steps[0].Name, "greeting")
	}
}

// TestPlanOpsAgreesWithPlanKnownFields pins planOps and planKnownFields
// (Rule 18: two independently-maintained maps keyed by the same op names) in
// exact agreement, the same pattern
// TestSipuaKeepaliveModesAgreeWithPolicyValidKeepaliveMode
// (internal/sipua/keepalive_test.go) uses for policy.ValidKeepaliveMode vs.
// sipua's implemented keepalive set. An op present in one map but not the
// other is a silent landmine: planKnownFields[op] would be nil for a
// planOps-only entry, and validateMediaPlan's per-step unknown-field loop
// (mediaplan_validate.go) then rejects EVERY key for that op — including
// "op" itself — with the nonsensical "unknown field \"op\" for op \"X\"".
func TestPlanOpsAgreesWithPlanKnownFields(t *testing.T) {
	for op := range planOps {
		if _, ok := planKnownFields[op]; !ok {
			t.Errorf("planOps has op %q with no matching planKnownFields entry — "+
				"every field for %q, including \"op\" itself, would be rejected as unknown", op, op)
		}
	}
	for op := range planKnownFields {
		if _, ok := planOps[op]; !ok {
			t.Errorf("planKnownFields has op %q with no matching planOps entry", op)
		}
	}
}
