package session

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// planOpDecoder decodes one raw §10.7 plan step into a typed MediaPlanStep and
// reports that step's contribution to the plan's MINIMUM duration in ms (0 when
// the step's length is unknown at validation time, as a play's is). Every
// rejection is invalid_argument carrying the uniform "media_plan[%d]: ..."
// prefix.
type planOpDecoder func(i int, m map[string]any, p *policy.Policy) (MediaPlanStep, int64, error)

// planOps is the ONE table of supported ops. An op absent from it is rejected
// as unknown — there is no second place that enumerates ops (Rule 18).
var planOps = map[string]planOpDecoder{
	"play":      decodePlay,
	"record":    decodeRecord,
	"wait":      decodeWait,
	"dtmf":      decodeDTMF,
	"wait_dtmf": decodeWaitDTMF,
	"hangup":    decodeHangup,
}

// planKnownFields is E/I4's per-op known-key set: "op" plus whatever fields
// that op's own decoder actually reads. It is declared PER OP rather than as
// one flat union across every op — a flat union would let
// {"op":"wait","digits":"1"} through, since "digits" IS a real key, just not
// one "wait" understands. Before this table existed, an unrecognised key on
// any step (a typo, or an argument for the wrong op) was silently ignored:
// {"op":"play","prompts":"x"} — note the typo — validated and then no-opped,
// because decodePlay never looks at "prompts".
var planKnownFields = map[string]map[string]struct{}{
	"play":      fieldSet("op", "prompt", "repeat", "wait_complete"),
	"record":    fieldSet("op", "duration_ms", "until_silence_ms", "name"),
	"wait":      fieldSet("op", "duration_ms"),
	"dtmf":      fieldSet("op", "digits", "mode", "duration_ms", "gap_ms"),
	"wait_dtmf": fieldSet("op", "digits", "timeout_ms"),
	"hangup":    fieldSet("op", "reason"),
}

func fieldSet(fields ...string) map[string]struct{} {
	s := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		s[f] = struct{}{}
	}
	return s
}

// planErr builds the uniform per-step invalid_argument.
func planErr(i int, format string, args ...any) error {
	return apierr.InvalidArgument(fmt.Sprintf("media_plan[%d]: ", i) + fmt.Sprintf(format, args...))
}

// planStr reads an OPTIONAL string field. A field that is present but not a
// string is a typed rejection, not a silent zero — which is exactly what the
// old `m["field"].(string)` comma-ok form did.
func planStr(i int, m map[string]any, field string) (string, error) {
	v, present := m[field]
	if !present || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", planErr(i, "%s must be a string", field)
	}
	return s, nil
}

// planInt reads an OPTIONAL numeric field, returning def when absent.
func planInt(i int, m map[string]any, field string, def int) (int, error) {
	v, present := m[field]
	if !present || v == nil {
		return def, nil
	}
	n, ok := jsonInt(v)
	if !ok {
		return 0, planErr(i, "%s must be a number", field)
	}
	return n, nil
}

// planInt64 reads an OPTIONAL numeric field, returning def when absent.
func planInt64(i int, m map[string]any, field string, def int64) (int64, error) {
	v, present := m[field]
	if !present || v == nil {
		return def, nil
	}
	n, ok := jsonInt64(v)
	if !ok {
		return 0, planErr(i, "%s must be a number", field)
	}
	return n, nil
}

// planBool reads an OPTIONAL boolean field, returning def when absent. A
// field that is present but not a boolean is a typed rejection, matching
// planStr/planInt/planInt64's existing convention.
func planBool(i int, m map[string]any, field string, def bool) (bool, error) {
	v, present := m[field]
	if !present || v == nil {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, planErr(i, "%s must be a boolean", field)
	}
	return b, nil
}

func decodePlay(i int, m map[string]any, p *policy.Policy) (MediaPlanStep, int64, error) {
	prompt, err := planStr(i, m, "prompt")
	if err != nil {
		return MediaPlanStep{}, 0, err
	}
	if _, ok := p.Prompt(prompt); !ok {
		return MediaPlanStep{}, 0, planErr(i, "unregistered prompt %q", prompt)
	}
	repeat, err := planInt(i, m, "repeat", 1)
	if err != nil {
		return MediaPlanStep{}, 0, err
	}
	if repeat < 1 {
		return MediaPlanStep{}, 0, planErr(i, "repeat must be >= 1")
	}
	// Inside a plan, play is unconditionally wait_complete=true — sequencing is
	// the plan's job (§3.5, call.go's execStep "play" case hardcodes true to
	// mp.u.Play). wait_complete is read here only so an explicit `false` gets a
	// specific, actionable rejection instead of either the generic "unknown
	// field" text (E/I4) or silently behaving as true.
	waitComplete, err := planBool(i, m, "wait_complete", true)
	if err != nil {
		return MediaPlanStep{}, 0, err
	}
	if !waitComplete {
		return MediaPlanStep{}, 0, planErr(i, "wait_complete: false is not supported inside a "+
			"media_plan step — play always completes before the next step runs")
	}
	// A play's minimum duration is unknown here (prompt length is only known at
	// play time); it does not contribute to the min-duration bound.
	return MediaPlanStep{Op: "play", Prompt: prompt, Repeat: repeat}, 0, nil
}

func decodeRecord(i int, m map[string]any, p *policy.Policy) (MediaPlanStep, int64, error) {
	// until_silence_ms is a future op field (no silence detection exists
	// anywhere in this decoder or in sipua.RecordStart) — reject explicitly,
	// before the duration_ms check below, so a caller who supplies
	// until_silence_ms alongside (or instead of) a positive duration_ms is
	// told plainly rather than hitting the unrelated "requires a positive
	// duration_ms" message or having the field silently ignored.
	if v, present := m["until_silence_ms"]; present && v != nil {
		return MediaPlanStep{}, 0, planErr(i, "record: until_silence_ms is not yet supported in "+
			"media_plan steps — use duration_ms")
	}
	d, err := planInt64(i, m, "duration_ms", 0)
	if err != nil {
		return MediaPlanStep{}, 0, err
	}
	if d <= 0 {
		return MediaPlanStep{}, 0, planErr(i, "record requires a positive duration_ms")
	}
	// Inputs §4 (RN-1): every declared step duration is bound by
	// max_step_duration_s, no carve-out. record is not a DTMF surface, so the
	// DTMF render ceiling (dtmfRenderCeilingMs) never applies to it — only the
	// per-step ceiling and, when tighter, the configured call-duration cap.
	if budget, bound := stepDurationBudget(p.Limits.MaxCallDurationS, p.Limits.MaxStepDurationS); d > budget {
		return MediaPlanStep{}, 0, planErr(i, "duration_ms %d exceeds %s", d, bound)
	}
	name, err := planStr(i, m, "name")
	if err != nil {
		return MediaPlanStep{}, 0, err
	}
	return MediaPlanStep{Op: "record", DurationMs: d, Name: name}, d, nil
}

func decodeWait(i int, m map[string]any, p *policy.Policy) (MediaPlanStep, int64, error) {
	d, err := planInt64(i, m, "duration_ms", 0)
	if err != nil {
		return MediaPlanStep{}, 0, err
	}
	if d <= 0 {
		return MediaPlanStep{}, 0, planErr(i, "wait requires a positive duration_ms")
	}
	// Inputs §4 (RN-1): see decodeRecord's identical comment above.
	if budget, bound := stepDurationBudget(p.Limits.MaxCallDurationS, p.Limits.MaxStepDurationS); d > budget {
		return MediaPlanStep{}, 0, planErr(i, "duration_ms %d exceeds %s", d, bound)
	}
	return MediaPlanStep{Op: "wait", DurationMs: d}, d, nil
}

func decodeHangup(i int, m map[string]any, _ *policy.Policy) (MediaPlanStep, int64, error) {
	reason, err := planStr(i, m, "reason")
	if err != nil {
		return MediaPlanStep{}, 0, err
	}
	return MediaPlanStep{Op: "hangup", Reason: reason}, 0, nil
}

// dtmfAlphabet duplicates internal/media/codec.DTMFAlphabet's value.
//
// E-M1 / D25 (D20, W2): THE OLD COMMENT CLAIMED A CROSS-CHECK THAT DOES NOT
// EXIST, and worse, cannot: importguard forbids internal/session importing
// internal/media/codec (§14.2's import boundary), so this package cannot see the
// authoritative constant at compile time OR test time. There is no place a
// cross-check could live that both constants are visible from.
//
// WHAT THAT MEANS IN PRACTICE: the two can silently diverge, and the failure
// would be a digit this package accepts and codec rejects (or the reverse). The
// mitigation is that both are pinned by their own tests against LITERAL strings,
// so a change to either reddens its own package. That is weaker than a
// cross-check and it is what the boundary allows.
const dtmfAlphabet = "0123456789ABCD*#"

func validDTMFDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(dtmfAlphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}

// dtmfRenderCeilingMs is the ABSOLUTE bound on ONE DTMF render, charged ON TOP
// of max_call_duration_s and INDEPENDENT of it.
//
// `max_call_duration_s: 0` is legal, non-default, and means "calls are
// uncapped" — policy's CallDeadline reports no deadline for it — and an
// uncapped CALL is a reasonable thing to configure. An uncapped single
// ALLOCATION is not: both DTMF surfaces pre-render len(digits) x (duration_ms +
// gap_ms) of PCM or telephone-event ticks into one codec.NewDTMFSource call
// before a packet leaves, so under an uncapped policy — or merely a cap larger
// than this ceiling — {"digits":"1","gap_ms":60000000} still allocated
// ~3,000,000 silence frames (~1 GB) and OOM-killed the daemon. That is K4's
// hole reopened by CONFIGURATION rather than by argument, and it reopened on
// BOTH surfaces identically, which is why they still agreed and no test saw it.
//
// THE FIGURE IS A STANDALONE CONSTANT, DELIBERATELY DECOUPLED FROM
// max_call_duration_s (P4-N01, Phase 4 W1 M2). It used to be read from
// policy.Defaults().Limits.MaxCallDurationS*1000 — "one number and not two"
// (Rule 18) — but that made it move in lockstep with the call-duration
// default: raising that default from 300s to 7200s (Inputs §3, same change)
// would have silently widened this OOM-prevention ceiling 24x with it. The
// literal below is what the default used to resolve to; it no longer moves
// when max_call_duration_s's default does. A deployment that caps calls at
// more than this, or not at all, still may not render more DTMF in one burst
// than this ceiling allows. It is deliberately NOT a policy key — a render
// this long is a mistake at any cap, and making it configurable would hand
// the operator back the OOM.
const dtmfRenderCeilingMs int64 = 300_000

// dtmfRenderBudget returns the ms a single DTMF render may spend under this
// policy, and the human name of whichever bound applies — the rejection text is
// read by a model, so it must say which limit was hit and what its value is.
func dtmfRenderBudget(maxCallDurationS int) (int64, string) {
	if capMs := int64(maxCallDurationS) * 1000; capMs > 0 && capMs < dtmfRenderCeilingMs {
		return capMs, fmt.Sprintf("max_call_duration_s (%ds)", maxCallDurationS)
	}
	return dtmfRenderCeilingMs, fmt.Sprintf("the %dms DTMF render ceiling", dtmfRenderCeilingMs)
}

// checkDTMFRenderBudget is THE DTMF render budget and the only copy of it. Both
// surfaces that reach codec.NewDTMFSource charge against it: a media_plan `dtmf`
// step (decodeDTMF, below) and the discrete dtmf_send tool
// (checkDTMFSendBounds, toolservice.go). It was written twice for a while and
// the two copies skipped the budget identically under an uncapped policy, so
// they agreed with each other and no cross-surface test could tell.
//
// durMs and gapMs are the RESOLVED figures — callers run ResolveDTMFTiming
// first, because it is the resolved values that get rendered. Each factor is
// charged before the product, which is what keeps that multiplication from
// overflowing on a caller-supplied length.
//
// The returned error names the offending argument and its bound and nothing
// else; each caller wraps it in its own surface's prefix.
func checkDTMFRenderBudget(digits string, durMs, gapMs int64, maxCallDurationS int) error {
	budget, bound := dtmfRenderBudget(maxCallDurationS)
	if durMs > budget {
		return fmt.Errorf("duration_ms %d exceeds %s", durMs, bound)
	}
	if gapMs > budget {
		return fmt.Errorf("gap_ms %d exceeds %s", gapMs, bound)
	}
	if total := int64(len(digits)) * (durMs + gapMs); total > budget {
		return fmt.Errorf("%d digits x (duration_ms %d + gap_ms %d) = %dms exceeds %s",
			len(digits), durMs, gapMs, total, bound)
	}
	return nil
}

// stepDurationBudget is Inputs §4 (RN-1)'s per-step ceiling: the ms budget for
// a media-plan step's OWN declared length — a wait/record's duration_ms, or
// the "step" half of derivedDTMFTotalBudget below — and the name of whichever
// bound is smaller: min(max_step_duration_s, max_call_duration_s where > 0).
// It never folds in dtmfRenderCeilingMs — that ceiling is DTMF renders only
// (the precedence table in mediaplan_validate_test.go / the design spec), and
// wait/record are not DTMF surfaces.
//
// The name uses the literal configured-key form ("max_step_duration_s (Xs)"
// or "max_call_duration_s (Ys)"), matching how dtmfRenderBudget already names
// max_call_duration_s when IT is the tighter bound — one reporting
// convention, not two (Rule 18).
func stepDurationBudget(maxCallDurationS, maxStepDurationS int) (int64, string) {
	budget := int64(maxStepDurationS) * 1000
	name := fmt.Sprintf("max_step_duration_s (%ds)", maxStepDurationS)
	if callCapMs := int64(maxCallDurationS) * 1000; callCapMs > 0 && callCapMs < budget {
		return callCapMs, fmt.Sprintf("max_call_duration_s (%ds)", maxCallDurationS)
	}
	return budget, name
}

// derivedDTMFTotalBudget is the THREE-WAY min of Inputs §4's precedence
// table, for the two values bound by every ceiling at once: wait_dtmf's
// timeout_ms and a dtmf step's derived len(digits) x (duration_ms + gap_ms)
// total. It folds max_step_duration_s (stepDurationBudget, which already
// folds in max_call_duration_s) together with dtmfRenderBudget (which also
// already folds in max_call_duration_s) by taking whichever of the two is
// smaller — a single min, not two sequential checks, because a sequential
// check would report the WRONG bound whenever an operator configures
// max_step_duration_s above the 300,000ms DTMF render ceiling: the total
// could then exceed both, and only comparing the true minimum names the one
// that actually governs.
func derivedDTMFTotalBudget(maxCallDurationS, maxStepDurationS int) (int64, string) {
	stepBudget, stepName := stepDurationBudget(maxCallDurationS, maxStepDurationS)
	dtmfBudget, dtmfName := dtmfRenderBudget(maxCallDurationS)
	if stepBudget < dtmfBudget {
		return stepBudget, stepName
	}
	return dtmfBudget, dtmfName
}

func decodeDTMF(i int, m map[string]any, p *policy.Policy) (MediaPlanStep, int64, error) {
	digits, err := planStr(i, m, "digits")
	if err != nil {
		return MediaPlanStep{}, 0, err
	}
	if digits == "" {
		return MediaPlanStep{}, 0, planErr(i, "dtmf requires a non-empty digits string")
	}
	if !validDTMFDigits(digits) {
		return MediaPlanStep{}, 0, planErr(i, "digits %q contains a character outside 0-9A-D*#", digits)
	}
	mode, err := planStr(i, m, "mode")
	if err != nil {
		return MediaPlanStep{}, 0, err
	}
	switch mode {
	case "", "rfc2833", "inband", "info":
	default:
		return MediaPlanStep{}, 0, planErr(i, "mode %q must be rfc2833, inband or info", mode)
	}
	// The two timing fields are read and validated RAW; THE DEFAULTS ARE NOT
	// APPLIED HERE. ResolveDTMFTiming (collaborators.go) owns both default values
	// and the tri-state rule, and sipua's send path calls the same function, so
	// the literals 100 and 50 exist in exactly one place in the tree.
	//
	// ABSENCE IS DETECTED BY KEY PRESENCE, NOT BY THE VALUE — the same
	// `present && v != nil` test planInt64 makes internally. It has to be: an
	// explicit `duration_ms: 0` or `gap_ms: -1` is invalid_argument, and if either
	// were routed into the resolver as "unset" it would be silently defaulted
	// instead of rejected. Only a genuinely missing field becomes the resolver's
	// own unset encoding (non-positive duration, negative gap).
	dur, gap := int64(0), int64(DTMFGapUnset)
	if v, present := m["duration_ms"]; present && v != nil {
		if dur, err = planInt64(i, m, "duration_ms", 0); err != nil {
			return MediaPlanStep{}, 0, err
		}
		if dur <= 0 {
			return MediaPlanStep{}, 0, planErr(i, "duration_ms must be > 0")
		}
	}
	if v, present := m["gap_ms"]; present && v != nil {
		if gap, err = planInt64(i, m, "gap_ms", 0); err != nil {
			return MediaPlanStep{}, 0, err
		}
		if gap < 0 {
			return MediaPlanStep{}, 0, planErr(i, "gap_ms must be >= 0")
		}
	}
	// The plan path resolves HERE, at validation time, because the min-duration
	// bound below needs concrete numbers before the call is dialed. An explicit
	// `gap_ms: 0` survives as 0 — it means NO GAP — and the resolver's idempotence
	// is what lets the sender's own call to it leave that untouched.
	dur, gap = ResolveDTMFTiming(dur, gap)
	// Inputs §4 (RN-1): the step's DERIVED TOTAL is additionally bound by
	// max_step_duration_s — checked FIRST, against the true three-way min, so
	// whichever bound actually governs is what gets named (see
	// derivedDTMFTotalBudget's comment on why a single min beats two
	// sequential checks here). The two INDIVIDUAL factors (dur, gap) are NOT
	// bound by max_step_duration_s — only the derived total is — so they stay
	// checkDTMFRenderBudget's alone, below.
	total := int64(len(digits)) * (dur + gap)
	if budget, bound := derivedDTMFTotalBudget(p.Limits.MaxCallDurationS, p.Limits.MaxStepDurationS); total > budget {
		return MediaPlanStep{}, 0, planErr(i, "%d digits x (duration_ms %d + gap_ms %d) = %dms exceeds %s",
			len(digits), dur, gap, total, bound)
	}
	// The step's own render is bounded HERE, per step, because the plan-level
	// sum below is skipped entirely when max_call_duration_s is 0 (uncapped) —
	// and one step is one codec.NewDTMFSource allocation regardless. Its own
	// total check above is now unreachable (derivedDTMFTotalBudget's budget is
	// always <= dtmfRenderBudget's), but the factor checks (dur, gap) are not.
	if err := checkDTMFRenderBudget(digits, dur, gap, p.Limits.MaxCallDurationS); err != nil {
		return MediaPlanStep{}, 0, planErr(i, "%s", err)
	}
	step := MediaPlanStep{Op: "dtmf", Digits: digits, Mode: mode, DurationMs: dur, GapMs: gap}
	return step, total, nil
}

func decodeWaitDTMF(i int, m map[string]any, p *policy.Policy) (MediaPlanStep, int64, error) {
	digits, err := planStr(i, m, "digits")
	if err != nil {
		return MediaPlanStep{}, 0, err
	}
	if digits != "" && !validDTMFDigits(digits) {
		return MediaPlanStep{}, 0, planErr(i, "digits %q contains a character outside 0-9A-D*#", digits)
	}
	timeout, err := planInt64(i, m, "timeout_ms", 0)
	if err != nil {
		return MediaPlanStep{}, 0, err
	}
	if timeout <= 0 {
		return MediaPlanStep{}, 0, planErr(i, "wait_dtmf requires a positive timeout_ms")
	}
	// And an upper bound, from the SAME budget the sibling `dtmf` step charges
	// against (Rule 18 — one ceiling, not two). The reason is identical: the
	// plan-level sum at the bottom of validateMediaPlan is skipped entirely
	// under `max_call_duration_s: 0`, so with a floor only, `timeout_ms:
	// 9999999999999` survived validation and reached sipua's
	// time.Duration(timeoutMs)*time.Millisecond, which overflows negative above
	// ~9.2e12 and makes the wait return instantly instead of waiting.
	//
	// Inputs §4 (RN-1) folded max_step_duration_s into this same budget
	// (derivedDTMFTotalBudget) rather than adding a second check: wait_dtmf's
	// timeout_ms is bound by ALL THREE ceilings, and it is the derived total's
	// sibling for exactly that reason — see derivedDTMFTotalBudget's comment.
	if budget, bound := derivedDTMFTotalBudget(p.Limits.MaxCallDurationS, p.Limits.MaxStepDurationS); timeout > budget {
		return MediaPlanStep{}, 0, planErr(i, "timeout_ms %d exceeds %s", timeout, bound)
	}
	return MediaPlanStep{Op: "wait_dtmf", Digits: digits, TimeoutMs: timeout}, timeout, nil
}

// validateMediaPlan is §10.7's up-front validation, run at call_dial/call_answer
// BEFORE the INVITE. It dispatches through planOps, rejects an unregistered
// prompt and a plan whose MINIMUM duration exceeds max_call_duration_s. Every
// rejection is invalid_argument.
func validateMediaPlan(p *policy.Policy, raw []map[string]any) ([]MediaPlanStep, error) {
	steps := make([]MediaPlanStep, 0, len(raw))
	var minDurationMs int64
	for i, m := range raw {
		// E-M3: routed through the typed reader like every other field, so a
		// non-string op ({"op": 7}) gets a proper type-mismatch error instead
		// of the misleading "op is required" a raw `m["op"].(string)` comma-ok
		// assertion produced (it silently reads a wrong-typed value as "").
		op, err := planStr(i, m, "op")
		if err != nil {
			return nil, err
		}
		if op == "" {
			return nil, planErr(i, "op is required")
		}
		dec, ok := planOps[op]
		if !ok {
			return nil, planErr(i, "unknown op %q", op)
		}
		// E/I4: reject any field this op's own decoder does not read, instead
		// of silently no-opping it — {"op":"play","prompts":"x"} (note the
		// typo) used to validate cleanly and then play nothing. The known-key
		// set is PER OP (planKnownFields), not one flat union across every op,
		// so {"op":"wait","digits":"1"} is still rejected even though
		// "digits" is a real key for other ops. Keys are sorted so the
		// reported field is deterministic when a step carries more than one
		// unknown key.
		known := planKnownFields[op]
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, ok := known[k]; !ok {
				return nil, planErr(i, "unknown field %q for op %q", k, op)
			}
		}
		step, minMs, err := dec(i, m, p)
		if err != nil {
			return nil, err
		}
		minDurationMs = saturatingAddMs(minDurationMs, minMs)
		steps = append(steps, step)
	}
	if maxCallDurationS := p.Limits.MaxCallDurationS; maxCallDurationS > 0 && minDurationMs > int64(maxCallDurationS)*1000 {
		return nil, apierr.InvalidArgument(fmt.Sprintf(
			"media_plan minimum duration %dms exceeds max_call_duration_s (%ds)", minDurationMs, maxCallDurationS))
	}
	return steps, nil
}

// saturatingAddMs adds b to a, SATURATING at math.MaxInt64 instead of
// wrapping negative. It exists for validateMediaPlan's plan-level minimum-
// duration sum above: every individual step's minMs is non-negative (each
// decoder validates its own duration positive before returning it), but
// enough steps can still sum past int64 — two `wait` steps at 5e18ms each
// summed to a WRAPPED NEGATIVE total under plain `+`, which defeated the
// `max > 0`-guarded comparison beneath it (decision 8, condition 3: that
// guard must not depend on a cap existing, so it cannot be "fixed" by relying
// on max_step_duration_s's ceiling to keep any one step small — the SUM
// itself must not overflow, regardless of how any one step got there).
func saturatingAddMs(a, b int64) int64 {
	sum := a + b
	if sum < a { // b is always >= 0 here, so a valid sum can never be < a.
		return math.MaxInt64
	}
	return sum
}

// jsonInt/jsonInt64 read a numeric JSON value that may arrive as float64 (the
// SDK's default) or an integer.
func jsonInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}

func jsonInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}
