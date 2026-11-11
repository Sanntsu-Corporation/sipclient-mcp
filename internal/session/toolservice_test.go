package session

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/metrics"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// callListLen type-asserts a call_list payload and returns its call count.
func callListLen(t *testing.T, out any) int {
	t.Helper()
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("call_list result = %#v (%T), want map[string]any", out, out)
	}
	calls, ok := m["calls"].([]map[string]any)
	if !ok {
		t.Fatalf(`call_list result["calls"] = %#v, want []map[string]any`, m["calls"])
	}
	return len(calls)
}

// TestToolServiceEnforcesR11 proves the session id every tool method takes is
// actually used for resolution rather than accepted and ignored. Each of the
// per-handle tools is driven with a FOREIGN session id and must return
// not_found — never gone, never denied, and never a payload.
func TestToolServiceEnforcesR11(t *testing.T) {
	m, _ := newTestManager(t)
	ts := NewToolService(m)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	if err := m.Open(ctx, "s2"); err != nil {
		t.Fatalf("Open(s2): %v", err)
	}
	h := string(c.Handle())

	tests := []struct {
		name string
		call func() (any, error)
	}{
		{"call_status", func() (any, error) { return ts.CallStatus(ctx, "s2", CallStatusInput{Call: h}) }},
		{"call_events", func() (any, error) { return ts.CallEvents(ctx, "s2", CallEventsInput{Call: h}) }},
		{"call_hangup", func() (any, error) { return ts.CallHangup(ctx, "s2", CallHangupInput{Call: h}) }},
		{"call_ladder", func() (any, error) { return ts.CallLadder(ctx, "s2", CallLadderInput{Call: h}) }},
		{"call_wait", func() (any, error) {
			return ts.CallWait(ctx, "s2", CallWaitInput{Call: h, Until: "answered", TimeoutMs: 1000})
		}},
		{"call_answer", func() (any, error) { return ts.CallAnswer(ctx, "s2", CallAnswerInput{Call: h}) }},
		{"call_reject", func() (any, error) { return ts.CallReject(ctx, "s2", CallRejectInput{Call: h}) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.call()
			assertCode(t, err, apierr.CodeNotFound)
		})
	}

	// call_list is the isolation case with no handle argument: S2 sees NONE of
	// S1's calls, and an empty list is the correct answer, not an error.
	out, err := ts.CallList(ctx, "s2", CallListInput{})
	if err != nil {
		t.Fatalf("call_list for an empty session: %v, want an empty list", err)
	}
	if n := callListLen(t, out); n != 0 {
		t.Fatalf("s2 sees %d of s1's calls, want 0 (R11)", n)
	}
}

// TestCallRejectStatusRange is U13: 300-699, with boundary cases at BOTH ends.
// Three normative sources (§10.3, §11.2, D11) say 300-699; only R14's prose
// says 3xx-6xx, and U13 resolves it in the majority's favour.
func TestCallRejectStatusRange(t *testing.T) {
	tests := []struct {
		status  int
		wantErr bool
	}{
		{299, true}, {300, false}, {486, false}, {699, false}, {700, true}, {-1, true},
	}
	for _, tc := range tests {
		m, _ := newTestManager(t)
		ts := NewToolService(m)
		ctx := context.Background()
		c := mustCall(t, m, "s1")
		_, err := ts.CallReject(ctx, "s1", CallRejectInput{Call: string(c.Handle()), Status: tc.status})
		if tc.wantErr {
			assertCode(t, err, apierr.CodeInvalidArgument)
			continue
		}
		if err != nil {
			t.Errorf("status %d: %v, want accepted (U13: 300-699)", tc.status, err)
		}
	}
}

// TestCallRejectDefaultsTo486 — §10.3's documented default.
func TestCallRejectDefaultsTo486(t *testing.T) {
	m, _ := newTestManager(t)
	ts := NewToolService(m)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	if _, err := ts.CallReject(ctx, "s1", CallRejectInput{Call: string(c.Handle())}); err != nil {
		t.Fatalf("call_reject with no status: %v", err)
	}
	evs, _, _ := c.Events(0)
	if len(evs) == 0 {
		t.Fatal("no event appended")
	}
	if got := evs[len(evs)-1].Detail["sip_code"]; got != 486 {
		t.Errorf("sip_code = %v, want 486 (§10.3's default)", got)
	}
}

// dialResultAgent is a nopAgent whose Dial returns a DialResult actually
// carrying a Call-ID, which nopAgent's does not.
type dialResultAgent struct {
	nopAgent
	callID string
}

func (a *dialResultAgent) Dial(context.Context, DialRequest) (DialResult, error) {
	return DialResult{DialogID: "dlg-out", CallID: a.callID}, nil
}

// TestDialogEstablishmentRetainsTheLadder asserts U18's Retain on BOTH
// channels: DialResult.CallID (outbound) and UAEvent.CallID (inbound, R14).
//
// IT DRIVES THE REAL ToolService AND THE REAL Manager. The tap is a fake because
// trace.Sink is P1c's; the Retain calls under test are production code.
func TestDialogEstablishmentRetainsTheLadder(t *testing.T) {
	const (
		outboundCallID = "callid-out@203.0.113.20"
		inboundCallID  = "callid-in@203.0.113.21"
	)

	tp := newRecordingTap()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// retains receives every callID passed to Tap.Retain, so the test
	// synchronises on the production call actually happening rather than on a
	// sleep. A sleep here would pass on a build where Retain is never called.
	retains := make(chan string, 4)
	tp.onRetain = func(callID string) { retains <- callID }

	agent := &dialResultAgent{callID: outboundCallID}

	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: policy.NewStaticStore(policy.Defaults(), fc, testLogger()),
		Logger: testLogger(), Tap: tp,
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	ts := NewToolService(m)

	// ---- OUTBOUND: the DialResult.CallID channel --------------------------
	if _, err := ts.CallDial(ctx, "s1", CallDialInput{
		UA: string(ua.Handle()), ToURI: "sip:echo@203.0.113.20",
	}); err != nil {
		t.Fatalf("call_dial: %v", err)
	}
	select {
	case got := <-retains:
		if got != outboundCallID {
			t.Fatalf("Retain called with %q, want the DialResult's Call-ID %q — the tap "+
				"is keyed by SIP Call-ID, never by the call handle", got, outboundCallID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CallDial's goroutine never called Tap.Retain")
	}

	if !tp.isRetained(outboundCallID) {
		t.Fatal("the outbound call's ladder ring was NOT retained after dial " +
			"establishment (U18). Without the Retain, the store's least-recently-" +
			"written eviction drops a LIVE call's ring in preference to keepalive " +
			"traffic minutes older, and call_ladder on a call the session owns " +
			"answers not_found — outside §10.11's two declared errors")
	}

	// ---- INBOUND (R14): the UAEvent.CallID channel -------------------------
	// I2: the inbound call is created through the SYNCHRONOUS admission channel,
	// which must accept and Retain the ladder ring exactly as the old one-way
	// handleInbound did.
	if v := m.admitInbound(ctx, ua.Handle(), UAEvent{
		Kind:     UAEventInbound,
		DialogID: "dlg-in",
		CallID:   inboundCallID,
		At:       fc.Now(),
		FromURI:  "sip:caller@203.0.113.21",
		ToURI:    "sip:me@203.0.113.1",
	}); !v.Accept {
		t.Fatalf("inbound admission verdict = %+v, want Accept", v)
	}

	if !tp.isRetained(inboundCallID) {
		t.Fatal("the INBOUND call's ladder ring was not retained. An inbound call " +
			"never returns a DialResult, so UAEvent.CallID is its only channel — " +
			"this is the site a reviser forgets, and forgetting it leaves R14's " +
			"whole path with the pre-U18 backwards eviction")
	}

	// The count is 2 because BOTH calls are still LIVE at this point: neither the
	// outbound nor the inbound call has been terminated anywhere above, so no
	// eviction has run and no retention has been released.
	if n := tp.retainedCount(); n != 2 {
		t.Fatalf("retained rings = %d, want 2 (one per registry-resident call; both "+
			"calls are live here and neither has been evicted)", n)
	}
}

// failingAgent's Reject and Hangup return context.DeadlineExceeded, standing in
// for a far end that never answers on a lossy UDP path — which contract §2.5.3
// calls NORMAL, and which is why Reject and Hangup were made blocking.
type failingAgent struct{ nopAgent }

func (failingAgent) Reject(context.Context, string, int, string) error {
	return context.DeadlineExceeded
}
func (failingAgent) Hangup(context.Context, string, string) error {
	return context.DeadlineExceeded
}

// TestTerminalTransitionIsRecordedWhenTheSipWriteFails is §6.0b INV-1.
//
// THE CLAIM AND THE RECORD ARE session's TWO INDEPENDENT NOTIONS OF "THIS CALL
// IS OVER" — the Call's state machine and the Manager's registry accounting —
// and nothing but this invariant forces the second to follow the first. Every
// assertion below is one of RecordTermination's six effects.
func TestTerminalTransitionIsRecordedWhenTheSipWriteFails(t *testing.T) {
	for _, tc := range []struct {
		name   string
		invoke func(*ToolService, context.Context, Handle) error
		reason string
	}{
		{
			name: "call_reject",
			invoke: func(ts *ToolService, ctx context.Context, h Handle) error {
				_, err := ts.CallReject(ctx, "s1", CallRejectInput{Call: string(h), Status: 486})
				return err
			},
			reason: "rejected_locally",
		},
		{
			name: "call_hangup",
			invoke: func(ts *ToolService, ctx context.Context, h Handle) error {
				_, err := ts.CallHangup(ctx, "s1", CallHangupInput{Call: string(h)})
				return err
			},
			reason: "local_hangup",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tp := newRecordingTap()
			logger, buf := captureLogger()
			fc := newFakeClock()
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			// metrics.New fixes the label set at construction (contract §2.3);
			// TerminationReasons is P1a Task 7's §2.5.1 slice.
			reg := metrics.New(TerminationReasons)
			m, err := NewManager(ManagerConfig{
				Ctx: ctx, Clock: fc,
				Policy:  policy.NewStaticStore(policy.Defaults(), fc, testLogger()),
				Logger:  logger,
				Tap:     tp,
				Metrics: reg,
				NewUA:   func(context.Context, UAConfig) (UserAgent, error) { return failingAgent{}, nil },
			})
			if err != nil {
				t.Fatalf("NewManager: %v", err)
			}
			if err := m.Open(ctx, "s1"); err != nil {
				t.Fatalf("Open: %v", err)
			}
			ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
			if err != nil {
				t.Fatalf("CreateUA: %v", err)
			}
			c, err := m.CreateCall(ctx, "s1", ua.Handle(), Inbound, StateRinging)
			if err != nil {
				t.Fatalf("CreateCall: %v", err)
			}
			const callID = "callid-inv1@203.0.113.30"
			c.setDialogIdentity("dlg-inv1", callID)
			tp.Retain(ctx, string(c.UAHandle()), callID)
			if tc.name == "call_hangup" {
				if err := c.TryAnswer(fc.Now()); err != nil {
					t.Fatalf("answer: %v", err)
				}
			}

			// The SIP write fails. The tool reports it — and the bookkeeping
			// STILL runs, which is the entire invariant.
			if err := tc.invoke(NewToolService(m), ctx, c.Handle()); err == nil {
				t.Fatal("want the transport fault surfaced to the caller")
			}

			// Effect 1 and 2: BOTH §12.2.2 caps released.
			if perSession, total := m.DebugLiveCallCounts("s1"); perSession != 0 || total != 0 {
				t.Fatalf("live call counts = (%d, %d), want (0, 0). The Try* claimed the "+
					"terminal transition and the SIP write then failed, so the call is "+
					"terminated in the state machine and STILL LIVE in the registry: it "+
					"counts against max_concurrent_calls_per_session and "+
					"max_concurrent_calls_total FOREVER, and nothing in the design can "+
					"reclaim the slot", perSession, total)
			}

			// Effects 3 and 4: the /metrics exposition. The Registry exposes no
			// getters (contract §2.3 declares only WriteText), so the assertion
			// reads the rendered text — which is also what an operator sees.
			var metricsOut bytes.Buffer
			if err := reg.WriteText(&metricsOut); err != nil {
				t.Fatalf("WriteText: %v", err)
			}
			text := metricsOut.String()
			if !strings.Contains(text, "active_calls 0") {
				t.Fatalf("active_calls is not 0 — /metrics is permanently wrong for the "+
					"life of the daemon:\n%s", text)
			}
			wantReason := fmt.Sprintf(`calls_by_termination_reason{reason="%s"} 1`, tc.reason)
			if !strings.Contains(text, wantReason) {
				t.Fatalf("missing %q — calls_by_termination_reason undercounts:\n%s",
					wantReason, text)
			}

			// Effect 5: exactly one N5 per-call log line.
			if lines := callLogLines(t, buf); len(lines) != 1 {
				t.Fatalf("per-call log lines = %d, want exactly 1 — a call that terminated "+
					"produced no §5 N5 line at all", len(lines))
			}

			// Effect 6: the §N3 retention entry exists, so the janitor can reach
			// it. Without it the registry entry is immortal.
			if _, err := m.ResolveCall(ctx, "s1", c.Handle()); err != nil {
				t.Fatalf("resolve after termination: %v, want ok (retained)", err)
			}
			fc.Advance(2 * time.Hour)
			m.JanitorSweep(fc.Now())
			if _, err := m.ResolveCall(ctx, "s1", c.Handle()); err == nil {
				t.Fatal("the registry entry survived its retention window: the call never " +
					"entered §N3's retention list, so the janitor can never evict it")
			}

			// And the U18 retention went with it.
			if n := tp.retainedCount(); n != 0 {
				t.Fatalf("retained ladder rings = %d after eviction, want 0", n)
			}
		})
	}
}

// denyOnlyStore builds a *policy.Store whose ONLY destinations rule is a
// single deny pattern — no allow list at all. Reused (Rule 16) rather than
// duplicated: policy.Load is the ONE way to compile destinations.{allow,deny}
// into their regexes (policy.Policy.validate, unexported), so this writes a
// minimal file and goes through Load exactly as internal/policy's own
// policyWithDestinations test helper does.
func denyOnlyStore(t *testing.T, fc *fakeclock.Clock, denyPattern string) *policy.Store {
	t.Helper()
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("bearer-token-value\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	yamlPath := filepath.Join(dir, "policy.yaml")
	contents := fmt.Sprintf("auth:\n  bearer_token_file: %s\ndestinations:\n  deny:\n    - '%s'\n",
		tok, denyPattern)
	if err := os.WriteFile(yamlPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	p, err := policy.Load(yamlPath)
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}
	return policy.NewStaticStore(p, fc, testLogger())
}

// TestCallDialClosesTheSipsSchemeBypass is D72's integration proof: the
// "sips:" scheme bypass is reachable ONLY under a DENY-ONLY policy —
// policy.Defaults() ships neither an allow nor a deny list and therefore
// permits everything, so it cannot observe this at all (CheckDestination
// returns permit whenever len(p.allowRE) == 0). validateToURI must reject the
// scheme (and, separately, a CRLF header-injection attempt) BEFORE CallDial
// ever calls CheckDestination.
func TestCallDialClosesTheSipsSchemeBypass(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc,
		Policy: denyOnlyStore(t, fc, `^sip:\+?1900`),
		Logger: testLogger(),
		NewUA:  func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	ts := NewToolService(m)

	// Baseline: the equivalent sip: destination IS denied by the deny
	// pattern — proves the fixture actually enforces something, so the
	// assertions below are not vacuous.
	if _, err := ts.CallDial(ctx, "s1", CallDialInput{
		UA: string(ua.Handle()), ToURI: "sip:19005550123@example.net",
	}); err == nil {
		t.Fatal("sip: destination matching the deny pattern was accepted; " +
			"the deny-only fixture proves nothing")
	} else {
		assertCode(t, err, apierr.CodeDenied)
	}

	// THE BYPASS: without validateToURI running first, each of these
	// normalises to something the "^sip:" deny pattern never matches (a
	// different scheme, or a CRLF-injected second request), so
	// CheckDestination alone would silently PERMIT every one of them.
	for _, tc := range []struct{ name, uri string }{
		{"sips lowercase", "sips:19005550123@example.net"},
		{"sips uppercase", "SIPS:19005550123@example.net"},
		{"crlf header injection", "sip:x@lab.internal\r\nINVITE sip:evil@a.b SIP/2.0"},
		// The name-addr bracket form, BARE HOST (no "@"): policy.Normalise
		// trims the brackets BEFORE detecting the scheme, so this reaches
		// CheckDestination as a sips: URI even though its raw bytes start
		// with "<", not "sips:". Without the matching bracket trim in
		// validateToURI, this fell into the bare-host default branch (which
		// permits ANY string with no "@") and the deny-only fixture's
		// "^sip:"-anchored pattern never matched it — call_dial returned
		// success with state:dialing, proved live for exactly this input.
		{"sips bracketed name-addr, with user part", "<sips:19005550123@example.net>"},
		{"sips bracketed name-addr, bare host (the isolating case)", "<sips:lab.internal>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ts.CallDial(ctx, "s1", CallDialInput{UA: string(ua.Handle()), ToURI: tc.uri})
			assertCode(t, err, apierr.CodeInvalidArgument)
		})
	}
}

// TestCallDialRound2ToURIEvasions is D72 ROUND 2's end-to-end proof, in the
// same shape as TestCallDialClosesTheSipsSchemeBypass above: a DENY-ONLY
// policy fixture, because policy.Defaults() ships neither an allow nor a
// deny list and permits everything, so it cannot observe any of this.
//
// THE SEVEN EVASIONS: policy.Normalise's envelope trim (TrimSpace, strip one
// "<", strip one ">", TrimSpace again — destination.go) uses unicode.IsSpace,
// which also trims NBSP, NEL and the other Unicode space separators, not
// just ASCII " \t". Round 1's fix mirrored the two bracket-trim lines but not
// the whitespace trim, so any of those runes placed before "sips:" (or
// before/inside its enclosing brackets) reached CheckDestination as a bare
// sips: URI. A doubled bracket pair ("<<sips:...>>") survives round 1's
// SINGLE TrimPrefix/TrimSuffix with one layer of brackets still attached,
// which also hid the scheme from a "^sip:"-anchored pattern.
//
// THE EIGHT PERMITTED FORMS must still be accepted — the fix must not
// over-reject legitimate §10.3 destinations.
func TestCallDialRound2ToURIEvasions(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc,
		Policy: denyOnlyStore(t, fc, `^sip:\+?1900`),
		Logger: testLogger(),
		NewUA:  func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	ts := NewToolService(m)

	evasions := []struct{ name, uri string }{
		{"double bracket", "<<sips:19005550123.example.net>>"},
		{"NBSP leading", " sips:19005550123.example.net"},
		{"space inside brackets", "< sips:19005550123.example.net>"},
		{"NEL leading", "\u0085sips:19005550123.example.net"},
		{"en quad leading", " sips:19005550123.example.net"},
		{"ideographic space leading", "　sips:19005550123.example.net"},
		{"ogham space mark leading", " sips:19005550123.example.net"},
		{"NBSP before bracket", " <sips:19005550123.example.net>"},
	}
	for _, tc := range evasions {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			_, err := ts.CallDial(ctx, "s1", CallDialInput{UA: string(ua.Handle()), ToURI: tc.uri})
			assertCode(t, err, apierr.CodeInvalidArgument)
		})
	}

	permitted := []struct{ name, uri string }{
		{"plain sip", "sip:lab.internal"},
		{"bracketed sip", "<sip:lab.internal>"},
		{"sip with user and port", "sip:alice@lab.internal:5060"},
		{"bare host port", "192.0.2.10:5060"},
		{"sips as userinfo", "sip:sips@h"},
		{"sips as host substring", "sip:x@sips.example"},
		{"ipv6 literal", "sip:[2001:db8::1]:5060"},
		{"uppercase scheme", "SIP:lab.internal"},
	}
	for _, tc := range permitted {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			res, err := ts.CallDial(ctx, "s1", CallDialInput{UA: string(ua.Handle()), ToURI: tc.uri})
			if err != nil {
				t.Fatalf("CallDial(%q) = %v, want nil — this is a §10.3-permitted form "+
					"and must not be caught by the round-2 fix", tc.uri, err)
			}
			out, ok := res.(map[string]any)
			if !ok || out["state"] != string(StateDialing) {
				t.Fatalf("CallDial(%q) result = %#v, want state %q", tc.uri, res, StateDialing)
			}
		})
	}
}

// TestCallDialRound3SemicolonQuestionMarkEvasions is D72 ROUND 3's end-to-end
// proof, in the same shape as TestCallDialClosesTheSipsSchemeBypass and
// TestCallDialRound2ToURIEvasions above: a DENY-ONLY policy fixture, because
// policy.Defaults() ships neither an allow nor a deny list and permits
// everything, so it cannot observe any of this.
//
// THE FOURTH AXIS: policy.Normalise (destination.go) truncates at the first
// ';' or '?' unless doing so would discard an '@' the untruncated string
// has. With the separator at index 0 and no '@' anywhere, that guard never
// fires, so the string truncates to "" and the default branch prepends
// "sip:" — the host is gone, and CheckDestination evaluates a bare "sip:"
// that no deny pattern anchored on the real host can ever match. Proved live
// here against a deny pattern that DOES match the correctly-normalised
// control destination "sip:evil.example", so the baseline assertion is not
// vacuous.
//
// The fix is validateToURI rejecting ';' and '?' anywhere in the raw
// to_uri (Fix 1) — NOT a change to policy.Normalise, which is unchanged
// this round (Task 6's, mutation-proven, shared by CheckDestination).
func TestCallDialRound3SemicolonQuestionMarkEvasions(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc,
		Policy: denyOnlyStore(t, fc, `^sip:evil\.example$`),
		Logger: testLogger(),
		NewUA:  func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	ts := NewToolService(m)

	// Baseline: the equivalent sip: destination IS denied by the deny
	// pattern — proves the fixture actually enforces something, so the
	// assertions below are not vacuous.
	if _, err := ts.CallDial(ctx, "s1", CallDialInput{
		UA: string(ua.Handle()), ToURI: "sip:evil.example",
	}); err == nil {
		t.Fatal("sip:evil.example, which matches the deny pattern, was accepted; " +
			"the deny-only fixture proves nothing")
	} else {
		assertCode(t, err, apierr.CodeDenied)
	}

	// THE FOUR EVASIONS: each normalises to a bare "sip:" — no host at all —
	// so the "^sip:evil\.example$" deny pattern never matches, and without
	// Fix 1 running first, CallDial dials the RAW, untruncated string
	// (DialRequest{ToURI: in.ToURI}) straight to the real evil.example host
	// while policy evaluated a host-less "sip:". Fix 1 rejects all four
	// before CheckDestination ever runs.
	for _, tc := range []struct{ name, uri string }{
		{"semicolon prefix, no scheme", ";evil.example"},
		{"question-mark prefix, no scheme", "?evil.example"},
		{"semicolon prefix, sips scheme", ";sips:evil.example"},
		{"semicolon prefix, sip scheme", ";sip:evil.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ts.CallDial(ctx, "s1", CallDialInput{UA: string(ua.Handle()), ToURI: tc.uri})
			assertCode(t, err, apierr.CodeInvalidArgument)
		})
	}
}

// TestUAStatusReportsGrantedExpiresNotRequested is D136: `ua_status`'s
// expires_s must report the registrar's GRANTED expiry (session.UA.expiresS,
// written by recordRegistration from RegisterResult.ExpiresS), never
// UAConfig.ExpiresS — the operator-REQUESTED value. A UA whose registrar
// granted a DIFFERENT expiry than requested must not report two contradictory
// numbers in the same response — expires_s and next_refresh_ms (correctly
// derived from the granted value). Requested and granted are chosen distinct
// from each other AND from 300 (siptest.BuildRegister's hardcoded wire
// literal, still the default registerExpiresS falls back to) so the assertion
// cannot pass by coincidence against either wrong value.
func TestUAStatusReportsGrantedExpiresNotRequested(t *testing.T) {
	const requestedExpiresS = 120
	const grantedExpiresS = 45

	m, fc := newManagerWith(t, nil)
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{
		Mode: "register", Transport: TransportUDP, ExpiresS: requestedExpiresS,
	})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	ua.recordRegistration(RegisterResult{Registered: true, Code: 200, ExpiresS: grantedExpiresS}, fc.Now())

	ts := NewToolService(m)
	out, err := ts.UAStatus(ctx, "s1", UAStatusInput{})
	if err != nil {
		t.Fatalf("UAStatus: %v", err)
	}
	res, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("UAStatus result = %#v (%T), want map[string]any", out, out)
	}
	uas, ok := res["uas"].([]map[string]any)
	if !ok || len(uas) != 1 {
		t.Fatalf(`UAStatus result["uas"] = %#v, want exactly one entry`, res["uas"])
	}
	entry := uas[0]

	gotExpires, ok := entry["expires_s"].(int)
	if !ok || gotExpires != grantedExpiresS {
		t.Fatalf("expires_s = %#v, want the GRANTED expiry %d — not the requested %d, "+
			"which never reached the wire (D136)", entry["expires_s"], grantedExpiresS, requestedExpiresS)
	}

	wantNextRefreshMS := ua.NextRefreshMS(fc.Now())
	if wantNextRefreshMS <= 0 {
		t.Fatalf("test bug: NextRefreshMS = %d, want > 0 so the agreement check below is not vacuous",
			wantNextRefreshMS)
	}
	gotNextRefreshMS, ok := entry["next_refresh_ms"].(int64)
	if !ok || gotNextRefreshMS != wantNextRefreshMS {
		t.Fatalf("next_refresh_ms = %#v, want %d — expires_s and next_refresh_ms must agree, "+
			"both derived from the SAME granted value", entry["next_refresh_ms"], wantNextRefreshMS)
	}
}

// TestCallDialRound4UnicodeCaseFoldEvasions is D72 ROUND 4's end-to-end
// proof, in the same shape as the three round tests above: a DENY-ONLY policy
// fixture, because policy.Defaults() ships neither an allow nor a deny list
// and permits everything, so it cannot observe any of this.
//
// THE FIFTH AXIS: 'İ' (U+0130) ToLower's to 'i', collapsing 2 UTF-8 bytes to
// 1. validateToURI's (pre-fix) `lower := strings.ToLower(s)` then
// `strings.HasPrefix(lower, "sip:")` matched "sİp:..." as a sip: scheme, but
// slicing s — not lower — at byte offset len("sip:") landed ONE BYTE SHORT,
// on the ':' instead of past it. policy.Normalise disagrees with that byte
// offset check entirely: it detects the scheme with strings.EqualFold, which
// 'İ' also fails (different rune count than "sip:"/"sips:"), so Normalise
// takes the no-scheme branch and PREPENDS its own "sip:", producing a
// doubled scheme. Proved live exactly as the bug report's fixture:
// denyOnlyStore(t, fc, "^sip:\\+?1900") denies "sip:19005550123@example.net"
// but (pre-fix) PERMITTED "sİp:19005550123@example.net", reaching
// state:dialing.
func TestCallDialRound4UnicodeCaseFoldEvasions(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc,
		Policy: denyOnlyStore(t, fc, `^sip:\+?1900`),
		Logger: testLogger(),
		NewUA:  func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	ts := NewToolService(m)

	// Baseline: the equivalent sip: destination IS denied by the deny
	// pattern — proves the fixture actually enforces something, so the
	// assertions below are not vacuous. This is the EXACT baseline the bug
	// report proved live against.
	if _, err := ts.CallDial(ctx, "s1", CallDialInput{
		UA: string(ua.Handle()), ToURI: "sip:19005550123@example.net",
	}); err == nil {
		t.Fatal("sip:19005550123@example.net, which matches the deny pattern, was accepted; " +
			"the deny-only fixture proves nothing")
	} else {
		assertCode(t, err, apierr.CodeDenied)
	}

	// THE FOUR EVASIONS: each substitutes 'İ' (U+0130) for the 'i' in a
	// "sip:" scheme token. Without the fix, the first of these (with the
	// EXACT byte offsets the bug report proved live) reached CheckDestination
	// as policy.Normalise's doubled "sip:sİp:19005550123@example.net", which
	// the "^sip:\+?1900"-anchored deny pattern never matches — CallDial
	// returned success with state:dialing for this exact input.
	for _, tc := range []struct{ name, uri string }{
		{"user@host, the exact live bypass", "sİp:19005550123@example.net"},
		{"bare host, no user part", "sİp:lab.internal"},
		{"bare scheme, no host at all", "sİp:"},
		{"bare host with percent-encoding", "sİp:lab%2Einternal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ts.CallDial(ctx, "s1", CallDialInput{UA: string(ua.Handle()), ToURI: tc.uri})
			assertCode(t, err, apierr.CodeInvalidArgument)
		})
	}
}

// ---- HIGH-1: headers, from_user and call_reject.reason at the input
// boundary, driven through the REAL ToolService.CallDial/CallReject rather
// than validateHeaders/validateFromUser/validateRejectReason directly
// (those are unit-tested in input_test.go). This is the integration half:
// it proves the checks actually run from the tool entry points, in the
// order the brief locks (before CheckDestination for CallDial, before
// ResolveCall for CallReject).

// TestCallDialRejectsHeaderInjection is the finding itself: sipgo v0.24.1
// prefers a Route header over the Request-URI when resolving where an INVITE
// actually goes (sip/request.go Destination(), matched case-insensitively by
// getHeader), so an agent-supplied "Route" or "rOuTe" header redirects a
// call_dial the agent's own to_uri and policy.CheckDestination already
// approved to an arbitrary host. Uses newTestManager's permit-everything
// policy deliberately: this bug is NOT about CheckDestination denying
// anything, it is about a header smuggling a destination CheckDestination
// never saw at all.
func TestCallDialRejectsHeaderInjection(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	ts := NewToolService(m)

	tests := []struct {
		name    string
		headers map[string]string
	}{
		{"Route header", map[string]string{"Route": "sip:evil@attacker.test"}},
		// The case-fold proof: sipgo's getHeader matches by lowercased name,
		// so a case-sensitive deny list would miss this entirely.
		{"case-folded Route", map[string]string{"rOuTe": "sip:evil@attacker.test"}},
		{"CRLF in a header value", map[string]string{
			"P-Asserted-Identity": "sip:a@b\r\nP-Asserted-Identity: sip:victim@bank",
		}},
		{"non-token name, trailing space", map[string]string{"Route ": "sip:evil@attacker.test"}},
		{"non-token name, embedded space", map[string]string{"X Bad": "value"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ts.CallDial(ctx, "s1", CallDialInput{
				UA: string(ua.Handle()), ToURI: "sip:bob@example.net", Headers: tc.headers,
			})
			assertCode(t, err, apierr.CodeInvalidArgument)
		})
	}
}

// TestCallDialRejectsFromUserCRLF: from_user renders verbatim at sipgo
// sip/uri.go:74, so a bare CRLF here is the same class of header-injection
// vector as the to_uri one validateToURI already closes, reached through a
// different field.
func TestCallDialRejectsFromUserCRLF(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	ts := NewToolService(m)

	_, err = ts.CallDial(ctx, "s1", CallDialInput{
		UA: string(ua.Handle()), ToURI: "sip:bob@example.net",
		FromUser: "alice\r\nX-Injected: yes",
	})
	assertCode(t, err, apierr.CodeInvalidArgument)
}

// TestCallRejectRejectsReasonCRLF: call_reject's reason reaches
// sip.NewResponseFromRequest(inv, status, reason, nil) — the SIP STATUS LINE
// itself (sipua/call.go:669) — so a CRLF here forges response lines wholesale.
func TestCallRejectRejectsReasonCRLF(t *testing.T) {
	m, _ := newTestManager(t)
	ts := NewToolService(m)
	ctx := context.Background()
	c := mustCall(t, m, "s1")
	_, err := ts.CallReject(ctx, "s1", CallRejectInput{
		Call: string(c.Handle()), Reason: "Busy\r\nX-Injected: yes",
	})
	assertCode(t, err, apierr.CodeInvalidArgument)
}

// TestCallDialAndCallRejectAcceptLegitimateInputs is the required negative
// control (Rule 7 case 7): the three new checks must not be a blanket
// rejection. A legitimate headers entry, a legitimate from_user and a
// legitimate call_reject reason all pass.
func TestCallDialAndCallRejectAcceptLegitimateInputs(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	ts := NewToolService(m)

	if _, err := ts.CallDial(ctx, "s1", CallDialInput{
		UA: string(ua.Handle()), ToURI: "sip:bob@example.net",
		FromUser: "alice",
		Headers:  map[string]string{"X-Trace-Id": "abc-123"},
	}); err != nil {
		t.Fatalf("call_dial with a legitimate header and from_user was rejected: %v", err)
	}

	// Phase 1's STRICT one-UA-per-session model (owner-locked decision):
	// mustCall mints its OWN UA, so it needs its OWN session — s1 already
	// holds `ua` from the call_dial case above.
	c := mustCall(t, m, "s2")
	if _, err := ts.CallReject(ctx, "s2", CallRejectInput{
		Call: string(c.Handle()), Reason: "Busy Here",
	}); err != nil {
		t.Fatalf("call_reject with a legitimate reason was rejected: %v", err)
	}
}

// TestCallLadderResolvesTheCallsOwnUAHandle is HIGH-3 at the tool boundary.
// Inbound Call-IDs are peer-chosen verbatim, so one peer can hand two UAs in
// the same session (or different sessions) the SAME Call-ID. call_ladder takes
// ONLY a call_handle (CallLadderInput has no ua_handle field), and resolves the
// owning UA server-side through the session-scoped ResolveCall — so each
// call_ladder looks the ring up under its OWN UA handle, and an agent cannot
// widen access to a foreign UA's ring. The sink's (ua_handle, call_id) key then
// keeps the two identical Call-IDs isolated.
//
// Pre-fix, call_ladder looked up the ring by Call-ID alone: both calls would
// resolve to the SAME key and read each other's traffic. This test fails then,
// because both recorded lookups would carry no UA handle.
func TestCallLadderResolvesTheCallsOwnUAHandle(t *testing.T) {
	const sharedCallID = "collide@peer" // the peer sends this identical Call-ID to both UAs

	tp := newRecordingTap()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: policy.NewStaticStore(policy.Defaults(), fc, testLogger()),
		Logger: testLogger(), Tap: tp,
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	// Phase 1's STRICT one-UA-per-session model (owner-locked decision) means
	// this fixture now exercises the doc comment's OTHER named scenario —
	// "one peer can hand two UAs in the same session (OR DIFFERENT
	// SESSIONS) the same Call-ID" — with uaA/uaB on separate sessions.
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open(s1): %v", err)
	}
	if err := m.Open(ctx, "s2"); err != nil {
		t.Fatalf("Open(s2): %v", err)
	}
	uaA, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA A: %v", err)
	}
	uaB, err := m.CreateUA(ctx, "s2", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA B: %v", err)
	}
	if uaA.Handle() == uaB.Handle() {
		t.Fatal("the two UAs share a handle; the fixture cannot show isolation")
	}

	callA, err := m.CreateCall(ctx, "s1", uaA.Handle(), Inbound, StateRinging)
	if err != nil {
		t.Fatalf("CreateCall A: %v", err)
	}
	callB, err := m.CreateCall(ctx, "s2", uaB.Handle(), Inbound, StateRinging)
	if err != nil {
		t.Fatalf("CreateCall B: %v", err)
	}
	// Both calls carry the IDENTICAL peer-chosen Call-ID.
	callA.setDialogIdentity("dlgA", sharedCallID)
	callB.setDialogIdentity("dlgB", sharedCallID)

	// Seed the tap so Ladder resolves for that Call-ID.
	tp.SIPMessage(ctx, SIPRecord{UAHandle: string(uaA.Handle()), CallID: sharedCallID})

	ts := NewToolService(m)
	if _, err := ts.CallLadder(ctx, "s1", CallLadderInput{Call: string(callA.Handle()), Format: "json"}); err != nil {
		t.Fatalf("call_ladder A: %v", err)
	}
	if _, err := ts.CallLadder(ctx, "s2", CallLadderInput{Call: string(callB.Handle()), Format: "json"}); err != nil {
		t.Fatalf("call_ladder B: %v", err)
	}

	args := tp.ladderArgsSnapshot()
	if len(args) != 2 {
		t.Fatalf("tap saw %d Ladder lookups, want 2", len(args))
	}
	// Each call_ladder resolved its OWN owning UA, though the Call-ID is shared.
	if args[0].ua != string(uaA.Handle()) || args[0].callID != sharedCallID {
		t.Errorf("call_ladder(A) looked up (%q,%q), want (%q,%q)",
			args[0].ua, args[0].callID, uaA.Handle(), sharedCallID)
	}
	if args[1].ua != string(uaB.Handle()) || args[1].callID != sharedCallID {
		t.Errorf("call_ladder(B) looked up (%q,%q), want (%q,%q)",
			args[1].ua, args[1].callID, uaB.Handle(), sharedCallID)
	}
	// The security property: two calls sharing a peer-chosen Call-ID resolve to
	// DIFFERENT tap keys because their owning UA handles differ. An agent has no
	// input that could make call_ladder(A) look up uaB's ring.
	if args[0].ua == args[1].ua {
		t.Errorf("both call_ladders resolved the same UA handle %q despite different owning UAs; "+
			"the peer-chosen Call-ID would collide their rings", args[0].ua)
	}
}

// TestUACreateThreadsInlineDTMFAndTimerKeys pins D6's five inline per-UA
// settings (DTMFMode, SessionExpiresS, MinSES, KeepaliveIntervalS,
// SessionRefreshMethod): ua_create now carries them DIRECTLY on the request
// (Phase 1, owner-locked decision — session-scoped UA lifecycle), not
// resolved server-side from a policy.yaml profile name, so each must both (a)
// reach UAConfig unchanged when supplied and (b) resolve to D6's documented
// default when omitted. BOTH modes are driven: the identical threading used
// to exist as two copies (register's and direct's own profile branch), and a
// field wired into one but not the other is exactly the silent-fallback
// defect this test exists to catch.
func TestUACreateThreadsInlineDTMFAndTimerKeys(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var got UAConfig
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc,
		Policy: policy.NewStaticStore(policy.Defaults(), fc, testLogger()),
		Logger: testLogger(),
		NewUA: func(_ context.Context, cfg UAConfig) (UserAgent, error) {
			got = cfg
			return nopAgent{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	// STRICT one-UA-per-session (Phase 1, owner-locked decision): each
	// UACreate below gets its OWN session, since a second on the same
	// session would itself be refused with resource_limit.
	for _, sid := range []string{"s1", "s2", "s3"} {
		if err := m.Open(ctx, sid); err != nil {
			t.Fatalf("Open(%s): %v", sid, err)
		}
	}
	ts := NewToolService(m)

	// Every field SUPPLIED, register mode.
	if _, err := ts.UACreate(ctx, "s1", UACreateInput{
		Mode: "register", AOR: "sip:a@example", Registrar: "sip:127.0.0.1:5060",
		DTMFMode: "inband", SessionExpiresS: 1800, MinSES: 120,
		KeepaliveIntervalS: 45, SessionRefreshMethod: "update", ExpiresS: 60,
	}); err != nil {
		t.Fatalf("UACreate: %v", err)
	}
	if got.DTMFMode != "inband" || got.SessionExpiresS != 1800 || got.MinSES != 120 ||
		got.KeepaliveIntervalS != 45 || got.SessionRefreshMethod != "update" || got.ExpiresS != 60 {
		t.Fatalf("UAConfig = %+v; inline keys were not threaded", got)
	}

	// Direct mode. It takes the SAME five keys and deliberately NOT a
	// registrar (§7) — direct mode never dials through one.
	got = UAConfig{}
	if _, err := ts.UACreate(ctx, "s2", UACreateInput{
		Mode: "direct", Transport: string(TransportUDP),
		DTMFMode: "inband", SessionExpiresS: 1800, MinSES: 120,
		KeepaliveIntervalS: 45, SessionRefreshMethod: "update",
	}); err != nil {
		t.Fatalf("UACreate(direct): %v", err)
	}
	if got.DTMFMode != "inband" || got.SessionExpiresS != 1800 || got.MinSES != 120 ||
		got.KeepaliveIntervalS != 45 || got.SessionRefreshMethod != "update" {
		t.Fatalf("UAConfig = %+v; direct mode did not thread the inline keys", got)
	}

	// Mutation guard: dropping default wiring for ANY one of the five fields
	// must redden here, so a stray field left out of the request resolves to
	// D6's documented default rather than the zero value the request omitted.
	got = UAConfig{}
	if _, err := ts.UACreate(ctx, "s3", UACreateInput{Mode: "direct", Transport: string(TransportUDP)}); err != nil {
		t.Fatalf("UACreate(direct, all omitted): %v", err)
	}
	if got.DTMFMode != "rfc2833" {
		t.Errorf("DTMFMode default = %q, want rfc2833", got.DTMFMode)
	}
	if got.SessionExpiresS != policy.DefaultSessionExpiresS {
		t.Errorf("SessionExpiresS default = %d, want %d", got.SessionExpiresS, policy.DefaultSessionExpiresS)
	}
	if got.MinSES != 90 {
		t.Errorf("MinSES default = %d, want 90", got.MinSES)
	}
	if got.KeepaliveIntervalS != 30 {
		t.Errorf("KeepaliveIntervalS default = %d, want 30", got.KeepaliveIntervalS)
	}
	if got.SessionRefreshMethod != "auto" {
		t.Errorf("SessionRefreshMethod default = %q, want auto", got.SessionRefreshMethod)
	}
}

// TestUACreateKeepaliveDefaultsPerModeAndExplicitInputWins pins the per-mode
// keepalive default asymmetry (register: "crlf", direct: "none" — see
// toolservice.go's UACreate, §1.1 D6) and that an explicit ua_create input
// always wins over it. Phase 1 removed the middle "profile default" tier this
// test used to also pin (Task 26 correction 9): with policy.Profile deleted,
// only two tiers remain — the explicit input, and the per-mode default.
func TestUACreateKeepaliveDefaultsPerModeAndExplicitInputWins(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var got UAConfig
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc,
		Policy: policy.NewStaticStore(policy.Defaults(), fc, testLogger()),
		Logger: testLogger(),
		NewUA: func(_ context.Context, cfg UAConfig) (UserAgent, error) {
			got = cfg
			return nopAgent{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	// STRICT one-UA-per-session (Phase 1, owner-locked decision): each
	// UACreate below gets its OWN session.
	for _, sid := range []string{"s1", "s2", "s3"} {
		if err := m.Open(ctx, sid); err != nil {
			t.Fatalf("Open(%s): %v", sid, err)
		}
	}
	ts := NewToolService(m)

	// register mode, no explicit keepalive: "crlf".
	if _, err := ts.UACreate(ctx, "s1", UACreateInput{
		Mode: "register", AOR: "sip:a@example", Registrar: "sip:127.0.0.1:5060",
	}); err != nil {
		t.Fatalf("UACreate (register default): %v", err)
	}
	if got.Keepalive != "crlf" {
		t.Fatalf("UAConfig.Keepalive = %q, want %q (register-mode default)", got.Keepalive, "crlf")
	}

	// register mode, EXPLICIT keepalive: wins over the default.
	if _, err := ts.UACreate(ctx, "s2", UACreateInput{
		Mode: "register", AOR: "sip:a@example", Registrar: "sip:127.0.0.1:5060", Keepalive: "options",
	}); err != nil {
		t.Fatalf("UACreate (register explicit): %v", err)
	}
	if got.Keepalive != "options" {
		t.Fatalf("UAConfig.Keepalive = %q, want %q (explicit input must win)", got.Keepalive, "options")
	}

	// direct mode, no explicit keepalive: "none".
	if _, err := ts.UACreate(ctx, "s3", UACreateInput{Mode: "direct", Transport: string(TransportUDP)}); err != nil {
		t.Fatalf("UACreate (direct default): %v", err)
	}
	if got.Keepalive != "none" {
		t.Fatalf("UAConfig.Keepalive = %q, want %q (direct-mode default)", got.Keepalive, "none")
	}
}

// TestUACreateRejectsAKeepaliveModeSipuaDoesNotImplement is the ua_create half
// of D/I3. policy.Load already rejected an invalid `keepalive` in a profile's
// policy.yaml entry before Phase 1 deleted policy.Profile entirely; this
// boundary is now the ONLY place ua_create's own keepalive string is checked,
// so a UA created through the tool surface can still name a mode sipua does
// not implement. Unvalidated, that mode reaches sipua, which arms no
// keepalive at all — the UA keeps no NAT binding open while ua_status goes on
// reporting the mode as configured, and under NAT inbound calls quietly stop
// once the pinhole times out.
//
// The accept rows are not decoration: a validator that rejected everything would
// satisfy every reject row while disabling the keepalive outright, which is
// worse than the bug. "" is accepted because it means NOT SUPPLIED — it falls
// through to the per-mode default — and is not the same thing as "none".
func TestUACreateRejectsAKeepaliveModeSipuaDoesNotImplement(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p := policy.Defaults()

	created := 0
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc,
		Policy: policy.NewStaticStore(p, fc, testLogger()),
		Logger: testLogger(),
		NewUA: func(_ context.Context, _ UAConfig) (UserAgent, error) {
			created++
			return nopAgent{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ts := NewToolService(m)

	for _, mode := range []string{"crfl", "CRLF", "tcp-keep", "OPTIONS"} {
		_, err := ts.UACreate(ctx, "s1", UACreateInput{
			Mode: "register", AOR: "sip:a@example", Registrar: "sip:127.0.0.1:5060", Keepalive: mode,
		})
		if err == nil {
			t.Fatalf("ua_create keepalive=%q was accepted; sipua implements none, crlf and "+
				"options only, and anything else keeps no NAT binding open at all", mode)
		}
		assertCode(t, err, apierr.CodeInvalidArgument)
		if !strings.Contains(err.Error(), "keepalive") {
			t.Fatalf("ua_create keepalive=%q error = %q; it must name the field the operator "+
				"has to fix", mode, err)
		}
	}
	// NOTHING was created: a rejected mode must not leave a UA behind, and the
	// rejection must happen before CreateUA rather than after it.
	if created != 0 {
		t.Fatalf("%d UA(s) were created for rejected keepalive modes, want 0", created)
	}

	// STRICT one-UA-per-session (Phase 1, owner-locked decision): each
	// accepted mode gets its OWN session, since a second ua_create on the
	// same session would itself be refused with resource_limit.
	for i, mode := range []string{"", "none", "crlf", "options"} {
		sid := fmt.Sprintf("s-accept-%d", i)
		if err := m.Open(ctx, sid); err != nil {
			t.Fatalf("Open(%s): %v", sid, err)
		}
		if _, err := ts.UACreate(ctx, sid, UACreateInput{
			Mode: "register", AOR: "sip:a@example", Registrar: "sip:127.0.0.1:5060", Keepalive: mode,
		}); err != nil {
			t.Fatalf("ua_create keepalive=%q was rejected: %v", mode, err)
		}
	}
	if created != 4 {
		t.Fatalf("%d UA(s) created for the four valid keepalive modes, want 4", created)
	}
}

// tlsVerifiedAgent embeds nopAgent and scripts TLSVerified to (true, true),
// so TestCallStatusTLSVerifiedNullOnInboundCall below can prove the
// DIRECTION GATE ALONE suppresses tls_verified — independent of whatever
// the underlying UA would itself report.
type tlsVerifiedAgent struct{ nopAgent }

func (tlsVerifiedAgent) TLSVerified() (bool, bool) { return true, true }

// TestCallStatusTLSVerifiedNullOnInboundCall is Rule 9 criterion (c) (Phase
// 4 W1 M7c, §1 item 5 / §7): an INBOUND tls call's call_status.tls_verified
// reads null even though the underlying UA's TLSVerified() reports (true,
// true) — the direction gate is a hard exclusion on any inbound call,
// regardless of what the UA itself would report, and it is a SEPARATE
// property from criterion (b) (no inbound WARN/classification).
func TestCallStatusTLSVerifiedNullOnInboundCall(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, nil), Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return tlsVerifiedAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportTLS})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	c, err := m.CreateCall(ctx, "s1", ua.Handle(), Inbound, StateRinging)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}

	ts := NewToolService(m)
	out, err := ts.CallStatus(ctx, "s1", CallStatusInput{Call: string(c.Handle())})
	if err != nil {
		t.Fatalf("CallStatus: %v", err)
	}
	om, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("CallStatus result = %#v, want map[string]any", out)
	}
	if v, present := om["tls_verified"]; !present || v != nil {
		t.Fatalf("tls_verified = %v, want null (present, nil) for an inbound call "+
			"even though the UA itself reports TLSVerified()=(true,true)", v)
	}
}

// TestUACreateRejectsOutOfRangeInlineAccountFields is the internal/session
// replacement for the DTMF/timer/expires bound tests that lived in
// internal/policy's deleted policy_test.go.
//
// WHY IT HAD TO MOVE RATHER THAN DIE WITH THE PROFILE: those bounds were
// enforced at policy LOAD time against a policy.Profile, and Phase 1 deleted
// the profile outright (D1/D6). ua_create is now the ONLY way any of these
// six fields reaches a UA, so ua_create is where the bounds have to hold —
// and where the regression has to be pinned. Each case below is one of the
// checks internal/policy used to run, driven through the boundary that
// inherited it.
//
// Mutation check: delete any single case's branch from
// validateInlineAccount and exactly that subtest reddens.
func TestUACreateRejectsOutOfRangeInlineAccountFields(t *testing.T) {
	cases := []struct {
		name string
		in   UACreateInput
	}{
		{"dtmf_mode unknown", UACreateInput{DTMFMode: "sipinfo"}},
		{"session_refresh_method unknown", UACreateInput{SessionRefreshMethod: "reinvite"}},
		{"min_se_s below RFC 4028 floor", UACreateInput{MinSES: 89}},
		// min_se_s alone, above the default session_expires_s: the
		// contradiction that would put Min-SE: 2000 beside
		// Session-Expires: 1800 on the same INVITE.
		{"min_se_s above the default session_expires_s", UACreateInput{MinSES: 2000}},
		{"session_expires_s below min_se_s", UACreateInput{MinSES: 600, SessionExpiresS: 300}},
		{"session_expires_s below the 90s floor", UACreateInput{SessionExpiresS: 60}},
		// The overflow footgun: int seconds x time.Second wraps NEGATIVE and
		// every refresh timer fires in microseconds.
		{"session_expires_s above the 7200s ceiling", UACreateInput{SessionExpiresS: 9999999999}},
		{"keepalive_interval_s below 5", UACreateInput{KeepaliveIntervalS: 4}},
		{"keepalive_interval_s above 3600", UACreateInput{KeepaliveIntervalS: 3601}},
		{"expires_s below 30", UACreateInput{ExpiresS: 29}},
		{"expires_s above 86400", UACreateInput{ExpiresS: 9999999999}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := newFakeClock()
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			created := false
			m, err := NewManager(ManagerConfig{
				Ctx: ctx, Clock: fc,
				Policy: policy.NewStaticStore(policy.Defaults(), fc, testLogger()),
				Logger: testLogger(),
				NewUA: func(context.Context, UAConfig) (UserAgent, error) {
					created = true
					return nopAgent{}, nil
				},
			})
			if err != nil {
				t.Fatalf("NewManager: %v", err)
			}
			if err := m.Open(ctx, "s1"); err != nil {
				t.Fatalf("Open: %v", err)
			}
			in := tc.in
			// Every case is otherwise a VALID direct-mode create, so the only
			// thing that can make it fail is the field under test.
			in.Mode, in.Transport = "direct", string(TransportUDP)

			_, err = NewToolService(m).UACreate(ctx, "s1", in)
			if err == nil {
				t.Fatalf("UACreate(%+v) = nil error, want invalid_argument", in)
			}
			assertCode(t, err, apierr.CodeInvalidArgument)
			// The refusal must happen BEFORE anything is built: a UA created
			// and then rejected would leave a live agent behind.
			if created {
				t.Fatalf("UACreate(%+v) built a UA before rejecting the input", in)
			}
		})
	}
}

// TestUACreateAcceptsInRangeInlineAccountFields is the positive half of the
// test above: the bounds must reject the out-of-range values WITHOUT
// narrowing what was always legal. Every value here sits at an edge the
// deleted internal/policy validate() explicitly allowed.
func TestUACreateAcceptsInRangeInlineAccountFields(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc,
		Policy: policy.NewStaticStore(policy.Defaults(), fc, testLogger()),
		Logger: testLogger(),
		NewUA:  func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := NewToolService(m).UACreate(ctx, "s1", UACreateInput{
		Mode: "direct", Transport: string(TransportUDP),
		DTMFMode: "info", SessionRefreshMethod: "invite",
		MinSES: 90, SessionExpiresS: 7200,
		KeepaliveIntervalS: 5, ExpiresS: 86400,
	}); err != nil {
		t.Fatalf("UACreate with every field at a legal edge: %v", err)
	}
}

// registerFailAgent is a nopAgent whose REGISTER fails. It exists for the D9
// rollback test below: the failed REGISTER is the one path in UACreate that
// tears down what it has already created.
type registerFailAgent struct{ nopAgent }

func (registerFailAgent) Register(context.Context) (RegisterResult, error) {
	return RegisterResult{}, apierr.Internal("", "REGISTER transport failure")
}

// TestUACreateRollbackOnFailedRegisterKeepsTheMCPSessionAlive is D9's
// regression pin for UACreate's rollback path.
//
// THE BUG IT PINS — the rollback used to call t.m.UADestroy, which since
// Phase 1 tears down AND DELETES the whole MCP session record (see
// UADestroy's own doc comment), not just the one UA. So a ua_create whose
// REGISTER failed returned an ordinary tool error while silently destroying
// the caller's session underneath it: the agent's very next tool call — on a
// session it never asked to close — 404'd under §12.6's unknown-id rule with
// nothing in the ua_create error to explain it. The rollback must reverse
// only what this call itself created, which is DestroyUA (§12.7's
// single-handle teardown, no session deletion).
//
// Mutation check (verified): change the rollback in UACreate back to
// t.m.UADestroy(t.m.DaemonContext(), sess, ua.Handle()) and this test reddens
// on both assertions — Alive is false and session_keepalive returns not_found.
func TestUACreateRollbackOnFailedRegisterKeepsTheMCPSessionAlive(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx:    ctx,
		Clock:  fc,
		Policy: newTestStore(t, fc, nil),
		Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) {
			return registerFailAgent{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	ts := NewToolService(m)

	const sess = "s1"
	if err := m.Open(ctx, sess); err != nil {
		t.Fatalf("Open: %v", err)
	}

	_, err = ts.UACreate(ctx, sess, UACreateInput{
		Mode:      "register",
		AOR:       "sip:alice@example.test",
		Registrar: "sip:registrar.example.test",
	})
	if err == nil {
		t.Fatal("ua_create with a failing REGISTER returned no error")
	}

	if !m.Alive(sess) {
		t.Fatal("the MCP session was destroyed by ua_create's own rollback: a failed REGISTER must " +
			"reverse only the UA this call created, not delete the caller's whole session")
	}
	// The observable consequence of the bug, not just its internal marker: a
	// follow-up tool call on the same session still works.
	if _, err := ts.SessionKeepalive(ctx, sess, SessionKeepaliveInput{}); err != nil {
		t.Fatalf("session_keepalive on the session that survived a failed ua_create: %v "+
			"(the agent would see this as an unexplained 404 on its next call)", err)
	}
}

// TestValidateInlineAccountBoundsTheFreeTextFields covers the length ceiling
// and the CR/LF floor validateAccountString applies to aor, auth_user,
// auth_pass and registrar.
//
// THE GAP IT CLOSES — validateInlineAccount bounded only the six numeric and
// enum fields. These four were operator-authored in policy.yaml until Phase 1
// deleted policy.Profile; ua_create made them agent-reachable over MCP with
// no bound at all, so a 100 KB aor, or one carrying a raw CRLF, was accepted
// without complaint.
//
// Mutation check: delete the validateAccountString loop at the top of
// validateInlineAccount and every rejecting row below reddens.
func TestValidateInlineAccountBoundsTheFreeTextFields(t *testing.T) {
	long := strings.Repeat("a", maxAccountFieldBytes+1)
	atCeiling := strings.Repeat("b", maxAccountFieldBytes)

	base := func() UACreateInput {
		return UACreateInput{Mode: "register", AOR: "sip:alice@example.test", Registrar: "sip:reg.example.test"}
	}

	cases := []struct {
		name      string
		mutate    func(*UACreateInput)
		wantField string // "" means the input must be ACCEPTED
	}{
		{"legitimate register account", func(in *UACreateInput) {
			in.AuthUser, in.AuthPass = "alice", "s3cr3t!@#$%^&*()_+"
		}, ""},
		{"legitimate direct account", func(in *UACreateInput) {
			in.Mode, in.Registrar, in.AOR = "direct", "", "sip:bob@192.0.2.10:5060;transport=tcp"
		}, ""},
		{"every field exactly at the ceiling", func(in *UACreateInput) {
			in.AOR, in.AuthUser, in.AuthPass, in.Registrar = atCeiling, atCeiling, atCeiling, atCeiling
		}, ""},

		{"oversized aor", func(in *UACreateInput) { in.AOR = long }, "aor"},
		{"oversized auth_user", func(in *UACreateInput) { in.AuthUser = long }, "auth_user"},
		{"oversized auth_pass", func(in *UACreateInput) { in.AuthPass = long }, "auth_pass"},
		{"oversized registrar", func(in *UACreateInput) { in.Registrar = long }, "registrar"},

		{"CRLF in aor", func(in *UACreateInput) {
			in.AOR = "sip:alice@example.test\r\nX-Injected: 1"
		}, "aor"},
		{"bare LF in aor", func(in *UACreateInput) { in.AOR = "sip:alice@example.test\nX: 1" }, "aor"},
		{"bare CR in auth_user", func(in *UACreateInput) { in.AuthUser = "alice\rX: 1" }, "auth_user"},
		{"CRLF in auth_user", func(in *UACreateInput) { in.AuthUser = "alice\r\nX: 1" }, "auth_user"},
		{"CRLF in auth_pass", func(in *UACreateInput) { in.AuthPass = "s3cr3t\r\nX: 1" }, "auth_pass"},
		{"CRLF in registrar", func(in *UACreateInput) {
			in.Registrar = "sip:reg.example.test\r\nX: 1"
		}, "registrar"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			tc.mutate(&in)
			err := validateInlineAccount(in)
			if tc.wantField == "" {
				if err != nil {
					t.Fatalf("validateInlineAccount rejected a legitimate account: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateInlineAccount accepted %s; want invalid_argument naming %q", tc.name, tc.wantField)
			}
			if got := apierr.CodeOf(err); got != apierr.CodeInvalidArgument {
				t.Errorf("code = %v, want invalid_argument", got)
			}
			if !strings.Contains(err.Error(), tc.wantField) {
				t.Errorf("error %q does not name the offending field %q", err, tc.wantField)
			}
		})
	}
}

// TestUACreateRejectsAnInjectedAORBeforeCreatingAnything drives the same
// check through the TOOL rather than the helper, so the bound is pinned at
// the boundary an MCP client actually reaches — and proves the refusal
// happens before any UA is created.
func TestUACreateRejectsAnInjectedAORBeforeCreatingAnything(t *testing.T) {
	m, _ := newTestManager(t)
	ts := NewToolService(m)
	ctx := context.Background()
	const sess = "s1"
	if err := m.Open(ctx, sess); err != nil {
		t.Fatalf("Open: %v", err)
	}

	_, err := ts.UACreate(ctx, sess, UACreateInput{
		Mode:      "register",
		AOR:       "sip:alice@example.test\r\nContact: <sip:attacker@example.test>",
		Registrar: "sip:reg.example.test",
	})
	if err == nil {
		t.Fatal("ua_create accepted an aor carrying a raw CRLF")
	}
	if got := apierr.CodeOf(err); got != apierr.CodeInvalidArgument {
		t.Errorf("code = %v, want invalid_argument", got)
	}

	out, err := ts.UAStatus(ctx, sess, UAStatusInput{})
	if err != nil {
		t.Fatalf("ua_status: %v", err)
	}
	if uas, _ := out.(map[string]any)["uas"].([]map[string]any); len(uas) != 0 {
		t.Errorf("ua_status lists %d UAs after the rejected ua_create, want 0", len(uas))
	}
}

// newModeValidationManager is the fixture for the mode-validation table below:
// one Manager, one open session, and a flag reporting whether the UA factory
// was reached. A REFUSAL THAT HAS ALREADY BUILT A UA is a different (and
// worse) defect than no refusal at all — it leaks a bound socket — so the flag
// is part of the assertion, not diagnostics.
func newModeValidationManager(t *testing.T) (*ToolService, context.Context, *bool) {
	t.Helper()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	created := false
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc,
		Policy: policy.NewStaticStore(policy.Defaults(), fc, testLogger()),
		Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) {
			created = true
			return nopAgent{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	return NewToolService(m), ctx, &created
}

// TestUACreateEnforcesModeFieldRules covers the three mode-validation guards
// §7/§10.2 require of ua_create, which replaced the deleted `profile is
// required when mode="register"` check when profiles were removed.
//
// They were entirely UNCOVERED: deleting any one of the three left the whole
// internal/session suite green, so the only thing keeping register mode from
// silently registering with no AOR — or direct mode from silently ignoring a
// registrar the operator did supply — was the source line itself.
//
// MUTATION CHECK: delete any one of the three guards in ToolService.UACreate
// and exactly the matching subtest below reddens.
func TestUACreateEnforcesModeFieldRules(t *testing.T) {
	const (
		aor       = "sip:alice@example.test"
		registrar = "sip:registrar.example.test:5060"
	)

	t.Run("rejected", func(t *testing.T) {
		cases := []struct {
			name      string
			in        UACreateInput
			wantField string // the error must NAME the offending key
		}{
			{
				// §7: register mode dials THROUGH a registrar and needs an
				// identity to register AS.
				name:      `register without aor`,
				in:        UACreateInput{Mode: "register", Registrar: registrar},
				wantField: "aor",
			},
			{
				name:      `register without registrar`,
				in:        UACreateInput{Mode: "register", AOR: aor},
				wantField: "registrar",
			},
			{
				// Both missing: aor is checked first, so that is the key named.
				name:      `register with neither aor nor registrar`,
				in:        UACreateInput{Mode: "register"},
				wantField: "aor",
			},
			{
				// §10.2: direct mode INVITEs the literal to_uri and never goes
				// via a registrar, so a registrar here names an intent the mode
				// cannot act on — refused rather than silently dropped.
				name:      `direct with a registrar`,
				in:        UACreateInput{Mode: "direct", Registrar: registrar},
				wantField: "registrar",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ts, ctx, created := newModeValidationManager(t)
				in := tc.in
				in.Transport = string(TransportUDP)

				_, err := ts.UACreate(ctx, "s1", in)
				if err == nil {
					t.Fatalf("UACreate(%+v) = nil error, want invalid_argument", in)
				}
				assertCode(t, err, apierr.CodeInvalidArgument)
				if !strings.Contains(err.Error(), tc.wantField) {
					t.Errorf("UACreate error = %q, want it to name %q — the agent has "+
						"to be told WHICH field to fix", err.Error(), tc.wantField)
				}
				if *created {
					t.Errorf("UACreate(%+v) built a UA before rejecting the input — "+
						"a refusal that leaves a bound socket behind", in)
				}
			})
		}
	})

	// The negative half must not have narrowed what was always legal.
	t.Run("accepted", func(t *testing.T) {
		cases := []struct {
			name string
			in   UACreateInput
		}{
			{`register with both aor and registrar`,
				UACreateInput{Mode: "register", AOR: aor, Registrar: registrar}},
			{`direct with no registrar`, UACreateInput{Mode: "direct"}},
			{`direct with an aor but no registrar`,
				UACreateInput{Mode: "direct", AOR: aor}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ts, ctx, created := newModeValidationManager(t)
				in := tc.in
				in.Transport = string(TransportUDP)

				if _, err := ts.UACreate(ctx, "s1", in); err != nil {
					t.Fatalf("UACreate(%+v) = %v, want ok", in, err)
				}
				if !*created {
					t.Fatalf("UACreate(%+v) succeeded without building a UA", in)
				}
			})
		}
	})
}

// ttlCrossingRegisterAgent advances the fake clock from INSIDE Register, which
// is the one point of ua_create that sits between CreateUA renewing the
// session's TTL and UACreate reading the fresh deadline back. It is how the
// race below is made deterministic rather than hammered at.
type ttlCrossingRegisterAgent struct {
	nopAgent
	clk *fakeclock.Clock
	by  time.Duration
}

func (a *ttlCrossingRegisterAgent) Register(context.Context) (RegisterResult, error) {
	a.clk.Advance(a.by)
	return RegisterResult{Registered: true, Code: 200, ExpiresS: 3600}, nil
}

// TestUACreateErrorsRatherThanReturningAZeroExpiresAt pins ua_create's
// expires_at against the Go zero time.
//
// THE BUG IT PINS — UACreate read the deadline back as `expiresAt, _ :=
// t.m.SessionExpiresAt(sess)`, discarding the ok result. SessionExpiresAt
// answers false for a session that is unknown OR already past its TTL, and it
// returns the zero Time when it does, so a session reaped or expired in the
// window between CreateUA and that read produced a successful ua_create
// carrying "expires_at":"0001-01-01T00:00:00Z" — a deadline in the year 1 that
// the calling agent cannot tell from a real one and will schedule its next
// keepalive against. session_keepalive never had the hole: it propagates
// RenewSession's not_found instead of formatting whatever it got.
//
// The window is forced open through the REGISTER, which is the real work
// ua_create does between those two statements.
//
// Mutation check: put the `_` back in place of the ok check (or drop the
// `if !ok` branch) and this test reddens with a nil error and an expires_at of
// 0001-01-01T00:00:00Z.
func TestUACreateErrorsRatherThanReturningAZeroExpiresAt(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	agent := &ttlCrossingRegisterAgent{clk: fc, by: policy.Defaults().Limits.SessionTTL.Duration() + time.Second}
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc,
		Policy: policy.NewStaticStore(policy.Defaults(), fc, testLogger()),
		Logger: testLogger(),
		NewUA:  func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ts := NewToolService(m)

	out, err := ts.UACreate(ctx, "s1", UACreateInput{
		Mode: "register", AOR: "sip:a@example", Registrar: "sip:127.0.0.1:5060",
	})
	if err == nil {
		t.Fatalf("UACreate succeeded although the session crossed its TTL before the "+
			"expires_at read; want an error rather than a garbage deadline (out=%+v)", out)
	}
	assertCode(t, err, apierr.CodeNotFound)
	if out != nil {
		t.Fatalf("UACreate returned a payload alongside its error: %+v", out)
	}

	// The refused create does not leave a LIVE UA behind. That is what the
	// DestroyUA rollback buys: an error return over a still-live UA whose
	// session has expired burns a max_uas_total slot that nothing would ever
	// give back (the leak class the session-deletion race tests pin). The
	// handle itself stays in m.uas as the §N3 terminated retention entry, which
	// the session record still present here owns and the reaper reclaims.
	liveUATotal, _, _, _, _ := registryTotalsForTest(m)
	if liveUATotal != 0 {
		t.Errorf("m.liveUATotal = %d after a refused ua_create, want 0 — the rolled-back "+
			"create must not hold a max_uas_total slot", liveUATotal)
	}
}

// TestUACreateReturnsARealExpiresAt is the anti-vacuity control for the test
// above: with no TTL crossing, the SAME fixture returns ok:true and an
// expires_at that is neither zero nor in the past. Without it, a UACreate that
// errored unconditionally would pass the test above.
func TestUACreateReturnsARealExpiresAt(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	agent := &ttlCrossingRegisterAgent{clk: fc, by: 0} // no crossing
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc,
		Policy: policy.NewStaticStore(policy.Defaults(), fc, testLogger()),
		Logger: testLogger(),
		NewUA:  func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	out, err := NewToolService(m).UACreate(ctx, "s1", UACreateInput{
		Mode: "register", AOR: "sip:a@example", Registrar: "sip:127.0.0.1:5060",
	})
	if err != nil {
		t.Fatalf("UACreate: %v", err)
	}
	got, _ := out.(map[string]any)["expires_at"].(string)
	parsed, perr := time.Parse(time.RFC3339Nano, got)
	if perr != nil {
		t.Fatalf("expires_at = %q, which does not parse: %v", got, perr)
	}
	if !parsed.After(fc.Now()) {
		t.Errorf("expires_at = %v, want a deadline after now (%v)", parsed, fc.Now())
	}
}

// TestCallTransferAttendedRejectsConsultCallOnADifferentUA is the multi-UA-
// per-session wave's fix for a contract that was vacuously true under Phase
// 1's one-UA cap: TransferRequest's own doc comment (collaborators.go)
// already says session "checks both are on the same UA" for an attended
// transfer's consult_call, but nothing actually checked it before this UA
// count could exceed one. sipua would otherwise fail several layers down
// with a confusing dialog-not-found error instead of a clear one here.
func TestCallTransferAttendedRejectsConsultCallOnADifferentUA(t *testing.T) {
	m, _ := newManagerWith(t, func(l *policy.Limits) { l.MaxUAsPerSession = 4 })
	ts := NewToolService(m)
	ctx := context.Background()
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	uaA, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA uaA: %v", err)
	}
	uaB, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA uaB: %v", err)
	}
	transferee, err := m.CreateCall(ctx, "s1", uaA.Handle(), Outbound, StateAnswered)
	if err != nil {
		t.Fatalf("CreateCall transferee: %v", err)
	}
	consult, err := m.CreateCall(ctx, "s1", uaB.Handle(), Outbound, StateAnswered)
	if err != nil {
		t.Fatalf("CreateCall consult: %v", err)
	}

	_, err = ts.CallTransfer(ctx, "s1", CallTransferInput{
		Call:        string(transferee.Handle()),
		Mode:        "attended",
		ConsultCall: string(consult.Handle()),
	})
	if err == nil {
		t.Fatal("call_transfer succeeded across two different UAs, want invalid_argument")
	}
	assertCode(t, err, apierr.CodeInvalidArgument)
}
