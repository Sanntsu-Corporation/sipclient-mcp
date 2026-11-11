package session

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// TestSanitizeToURIStripsCredentials is the assertion locked decision 6 exists
// to make cheap: the per-call log line is emitted from ONE place, so "no
// credential ever appears in any log line" is asserted against ONE code path
// rather than four as the record gains columns across P2-P5.
func TestSanitizeToURIStripsCredentials(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no userinfo", "sip:bob@example.com", "sip:bob@example.com"},
		{"password", "sip:bob:hunter2@example.com", "sip:bob@example.com"},
		{"password with port", "sip:bob:hunter2@example.com:5061", "sip:bob@example.com:5061"},
		{"password containing @", "sip:bob:p@ss@example.com", "sip:bob@example.com"},
		{"bare host", "example.com:5060", "example.com:5060"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SanitizeToURI(tc.in); got != tc.want {
				t.Errorf("SanitizeToURI(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCallLogRecordCarriesNoCredential marshals a record built from a call
// whose to_uri contains a password and asserts the secret is absent from the
// serialized line. It also pins that the P2-P5 columns are PRESENT and zero at
// P1 (decision 6), so a later phase adds values rather than fields.
func TestCallLogRecordCarriesNoCredential(t *testing.T) {
	rec := CallLogRecord{
		CallHandle: "call_1", UAHandle: "ua_1", Session: "s1",
		Direction: "outbound", ToURI: SanitizeToURI("sip:bob:hunter2@example.com"),
		Transport: "udp", State: "terminated", TerminationReason: "local_hangup",
		SIPCode: 200, DurationMS: 1234,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	line := string(raw)
	if strings.Contains(line, "hunter2") {
		t.Fatalf("credential present in the per-call log line: %s", line)
	}
	for _, col := range []string{
		"call_handle", "ua_handle", "session", "direction", "to_uri", "transport",
		"state", "termination_reason", "sip_code", "duration_ms",
		"codec", "srtp", "packets_sent", "packets_received", "loss_pct", "tier",
		"mos_estimate", "mos_lqo",
	} {
		if !strings.Contains(line, `"`+col+`"`) {
			t.Errorf("column %q missing; decision 6 declares the P2-P5 columns at P1 so the "+
				"line gains VALUES, not FIELDS, in later phases", col)
		}
	}
}

// syncBuffer wraps a bytes.Buffer with a mutex (D78). captureLogger's writer
// is read by the test goroutine (buf.String()) while a duration-cap timer's
// own goroutine may concurrently write it via emitCallLog <- RecordTermination
// — a bare *bytes.Buffer races under -race in exactly that shape
// (TestEveryTerminationPathEmitsExactlyOneLogLine's duration-cap case).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLogger returns a logger writing JSON lines into buf, plus the buffer.
// Added here rather than reusing testLogger(), which discards — a test about
// log emission cannot use a logger that emits nowhere.
func captureLogger() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}
	return slog.New(slog.NewJSONHandler(buf, nil)), buf
}

// callLogLines returns the per-call log lines in buf, decoded. It filters on
// the call_handle key so an unrelated WARN in the same buffer is not counted.
func callLogLines(t *testing.T, buf *syncBuffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if raw == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("log line is not JSON: %s", raw)
		}
		if _, ok := m["call_handle"]; ok {
			out = append(out, m)
		}
	}
	return out
}

// TestEveryTerminationPathEmitsExactlyOneLogLine is §5 N5's acceptance:
// "after three calls — one hung up locally, one rejected, one force-terminated
// by the duration cap — the log contains exactly three per-call JSON lines."
//
// IT DRIVES REAL TERMINATIONS THROUGH THE REAL TOOL METHODS. That is the point:
// locked decision 6 says the line is emitted at THE terminal transition, and
// the only way to check "every path" is to exercise the paths rather than to
// call the emitter directly.
//
// EXACTLY ONE is asserted in both directions. Zero means a path skipped the
// call — the defect this test exists for, and the one that leaves the majority
// of P1's traffic silently unlogged. More than one means a path emitted
// alongside RecordTermination as well as through it, and N5's per-call
// accounting reads two lines as two calls.
func TestEveryTerminationPathEmitsExactlyOneLogLine(t *testing.T) {
	logger, buf := captureLogger()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p := policy.Defaults()
	p.Limits.MaxCallDurationS = 300
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: policy.NewStaticStore(p, fc, logger), Logger: logger,
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	ts := NewToolService(m)
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	newCallInState := func(t *testing.T, dir Direction, st CallState) *Call {
		t.Helper()
		c, err := m.CreateCall(ctx, "s1", ua.Handle(), dir, st)
		if err != nil {
			t.Fatalf("CreateCall: %v", err)
		}
		c.setDialogIdentity("dlg-"+string(c.Handle()), "callid-"+string(c.Handle()))
		return c
	}

	// 1. Hung up locally -> local_hangup.
	hungUp := newCallInState(t, Outbound, StateAnswered)
	if _, err := ts.CallHangup(ctx, "s1", CallHangupInput{Call: string(hungUp.Handle())}); err != nil {
		t.Fatalf("call_hangup: %v", err)
	}

	// 2. Rejected locally -> rejected_locally.
	rejected := newCallInState(t, Inbound, StateRinging)
	if _, err := ts.CallReject(ctx, "s1", CallRejectInput{Call: string(rejected.Handle())}); err != nil {
		t.Fatalf("call_reject: %v", err)
	}

	// 3. Force-terminated by the §11.3 duration cap -> policy_timeout.
	capped := newCallInState(t, Outbound, StateAnswered)
	m.StartDurationCap(capped, 300*time.Second, func() { m.RecordTermination(capped) })
	fc.BlockUntil(1)
	fc.Advance(300 * time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for capped.State() != StateTerminated && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if capped.State() != StateTerminated {
		t.Fatal("the duration cap never fired")
	}

	// STATE-TERMINATED DOES NOT IMPLY LOG-EMITTED, AND POLLING ON STATE ALONE IS
	// A TOCTOU BUG (Rule 13 Cycle 2, D384). TryTerminate (call.go) sets the state
	// under c.mu and RELEASES IT BEFORE RETURNING, so State() reads Terminated the
	// instant the select case body runs — but the log line is written by
	// `defer onCap()` (registry.go:424), which fires only when the ENCLOSING
	// GOROUTINE FUNCTION returns, and onCap -> RecordTermination -> emitCallLog
	// must still acquire the registry lock first. That is real, lock-contended
	// work between "state visible" and "line written".
	//
	// The other two paths in this test (call_hangup, call_reject) run
	// synchronously on the test goroutine and are always logged by the time they
	// return; only the duration-cap path is asynchronous, which is why the
	// missing line was always policy_timeout. Poll on the thing actually being
	// asserted.
	deadline = time.Now().Add(2 * time.Second)
	for len(callLogLines(t, buf)) < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	lines := callLogLines(t, buf)
	if len(lines) != 3 {
		t.Fatalf("%d per-call log lines, want exactly 3 — §5 N5 requires ONE line per "+
			"terminated call, and a path that skips emitCallLog emits ZERO. Lines: %s",
			len(lines), buf.String())
	}

	byHandle := map[string]map[string]any{}
	for _, l := range lines {
		h, _ := l["call_handle"].(string)
		if _, dup := byHandle[h]; dup {
			t.Fatalf("call %s logged twice — RecordTermination's live-check is the "+
				"fires-exactly-once guard and something bypassed it", h)
		}
		byHandle[h] = l
	}

	for _, tc := range []struct {
		name   string
		call   *Call
		reason string
	}{
		{"call_hangup", hungUp, "local_hangup"},
		{"call_reject", rejected, "rejected_locally"},
		{"duration cap", capped, "policy_timeout"},
	} {
		l, ok := byHandle[string(tc.call.Handle())]
		if !ok {
			t.Errorf("%s: no per-call log line for %s — this termination path does not "+
				"reach emitCallLog", tc.name, tc.call.Handle())
			continue
		}
		if got := l["termination_reason"]; got != tc.reason {
			t.Errorf("%s: termination_reason = %v, want %q", tc.name, got, tc.reason)
		}
		if got := l["state"]; got != string(StateTerminated) {
			t.Errorf("%s: state = %v, want terminated", tc.name, got)
		}
	}
}

// TestRemoteAndAdminTerminationsAlsoLog covers the three paths the N5 example
// does not name, so all six are pinned rather than three.
func TestRemoteAndAdminTerminationsAlsoLog(t *testing.T) {
	tests := []struct {
		name       string
		terminate  func(t *testing.T, m *Manager, c *Call, ua *UA)
		wantReason string
	}{
		{
			name: "U14 peer BYE",
			terminate: func(_ *testing.T, m *Manager, c *Call, _ *UA) {
				m.handleUAEvent(context.Background(), c.UAHandle(), UAEvent{
					Kind: UAEventDialogEnded, Cause: UACausePeerBYE,
					DialogID: c.DialogID(), At: m.clk.Now(),
				})
			},
			wantReason: "remote_bye",
		},
		{
			name: "ua_destroy teardown",
			terminate: func(t *testing.T, m *Manager, _ *Call, ua *UA) {
				if _, err := m.UADestroy(context.Background(), "s1", ua.Handle()); err != nil {
					t.Fatalf("UADestroy: %v", err)
				}
			},
			wantReason: "local_hangup",
		},
		{
			name: "§11.4 HangupAllLive",
			terminate: func(_ *testing.T, m *Manager, _ *Call, _ *UA) {
				m.HangupAllLive(context.Background(), time.Second)
			},
			wantReason: "local_hangup",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := captureLogger()
			fc := newFakeClock()
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			m, err := NewManager(ManagerConfig{
				Ctx: ctx, Clock: fc, Policy: policy.NewStaticStore(policy.Defaults(), fc, logger),
				Logger: logger,
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
			c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
			if err != nil {
				t.Fatalf("CreateCall: %v", err)
			}
			c.setDialogIdentity("dlg-1", "callid-1")

			tc.terminate(t, m, c, ua)

			lines := callLogLines(t, buf)
			if len(lines) != 1 {
				t.Fatalf("%d per-call log lines, want exactly 1. Lines: %s", len(lines), buf.String())
			}
			if got := lines[0]["termination_reason"]; got != tc.wantReason {
				t.Errorf("termination_reason = %v, want %q", got, tc.wantReason)
			}
		})
	}
}

// TestNoCredentialInAnyEmittedLogLine is the "no credential ever appears in any
// log line" assertion of §14.2 and §5 N5, driven through the REAL path rather
// than over a hand-built record. Decision 6's rationale is that this assertion
// holds against ONE code path; this test is what cashes that in.
func TestNoCredentialInAnyEmittedLogLine(t *testing.T) {
	const secret = "hunter2-should-never-appear"
	logger, buf := captureLogger()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: policy.NewStaticStore(policy.Defaults(), fc, logger),
		Logger: logger,
		NewUA:  func(context.Context, UAConfig) (UserAgent, error) { return nopAgent{}, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	ts := NewToolService(m)
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	// A UA whose credential is set, dialling a destination whose URI embeds a
	// password — both of the places a secret could leak into the line.
	// B2: AuthPass is an opaque policy.Secret, so an untyped string constant
	// cannot be assigned to it. That the wrapping is REQUIRED by the type is
	// the point — it is what makes an accidental plaintext assignment a
	// compile error rather than a code-review catch.
	ua, err := m.CreateUA(ctx, "s1", UAConfig{
		Mode: "direct", Transport: TransportUDP,
		AuthUser: "alice", AuthPass: policy.NewSecret(secret),
	})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}
	c.setDialogIdentity("dlg-1", "callid-1")
	c.setURIs("sip:alice:"+secret+"@example.com", "sip:me@example.com")

	if _, err := ts.CallHangup(ctx, "s1", CallHangupInput{Call: string(c.Handle())}); err != nil {
		t.Fatalf("call_hangup: %v", err)
	}

	if strings.Contains(buf.String(), secret) {
		t.Fatalf("a credential reached the log: %s", buf.String())
	}
	lines := callLogLines(t, buf)
	if len(lines) != 1 {
		t.Fatalf("%d per-call log lines, want 1", len(lines))
	}
	if got, _ := lines[0]["to_uri"].(string); !strings.Contains(got, "alice@example.com") {
		t.Errorf("to_uri = %q; the destination must survive sanitisation, only the "+
			"password is stripped (SanitizeToURI)", got)
	}
}

// TestCallDialRecordsSanitizedToURIInN5Log is Important Finding 2's fix: it
// drives the REAL ToolService.CallDial, unlike TestNoCredentialInAnyEmittedLogLine
// above, which calls c.setURIs(...) DIRECTLY and never exercises CallDial's
// outbound path at all. D76 added c.setURIs(in.ToURI, "") to CallDial's dial
// goroutine (toolservice.go) specifically so the N5 record's to_uri column is
// populated on the outbound path; without a test that drives CallDial itself,
// deleting that call left the whole suite green and the N5 record's to_uri
// silently empty.
func TestCallDialRecordsSanitizedToURIInN5Log(t *testing.T) {
	const secret = "hunter2-outbound"
	// The host is MIXED-CASE deliberately (Task 11d, D88): CallDial now
	// records policy.Normalise(toURI) — which lower-cases the host — rather
	// than the raw toURI, so the assertion below is non-vacuous only if
	// normalisation actually changes something. A lowercase fixture host
	// would pass even if CallDial silently reverted to recording the raw
	// string, because SanitizeToURI(raw) and SanitizeToURI(Normalise(raw))
	// would happen to agree.
	const toURI = "sip:bob:" + secret + "@EXAMPLE.com"
	logger, buf := captureLogger()
	tp := newRecordingTap()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Tap.Retain runs in CallDial's dial goroutine IMMEDIATELY AFTER
	// c.setURIs returns (toolservice.go, U18) — the same synchronisation
	// point TestDialogEstablishmentRetainsTheLadder uses. Once this fires,
	// setURIs has already recorded the real to_uri.
	retains := make(chan string, 1)
	tp.onRetain = func(callID string) { retains <- callID }

	agent := &dialResultAgent{callID: "callid-n5@203.0.113.30"}
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: policy.NewStaticStore(policy.Defaults(), fc, logger),
		Logger: logger, Tap: tp,
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	ts := NewToolService(m)
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	out, err := ts.CallDial(ctx, "s1", CallDialInput{UA: string(ua.Handle()), ToURI: toURI})
	if err != nil {
		t.Fatalf("call_dial: %v", err)
	}
	res, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("call_dial result = %#v, want map[string]any", out)
	}
	callHandle, _ := res["call_handle"].(string)
	if callHandle == "" {
		t.Fatalf("call_dial result carries no call_handle: %#v", res)
	}

	select {
	case <-retains:
	case <-time.After(2 * time.Second):
		t.Fatal("CallDial's goroutine never reached the dialog-established path " +
			"(Tap.Retain was never called)")
	}

	if _, err := ts.CallHangup(ctx, "s1", CallHangupInput{Call: callHandle}); err != nil {
		t.Fatalf("call_hangup: %v", err)
	}

	if strings.Contains(buf.String(), secret) {
		t.Fatalf("a credential reached the log: %s", buf.String())
	}
	lines := callLogLines(t, buf)
	if len(lines) != 1 {
		t.Fatalf("%d per-call log lines, want 1", len(lines))
	}
	got, _ := lines[0]["to_uri"].(string)
	if got == "" {
		t.Fatal("to_uri on the N5 record for a call driven through CallDial is " +
			"empty — D76's c.setURIs(in.ToURI, \"\") call in CallDial's dial " +
			"goroutine did not reach the log record")
	}
	// D88: CallDial now dials and records the NORMALISED to_uri (Task 11d,
	// D85) rather than the raw input, so the N5 record's to_uri is
	// SanitizeToURI applied to policy.Normalise(toURI), not to toURI itself.
	if want := SanitizeToURI(policy.Normalise(toURI)); got != want {
		t.Errorf("to_uri = %q, want %q (SanitizeToURI applied to the NORMALISED "+
			"to_uri CallDial actually dialled and recorded)", got, want)
	}
}
