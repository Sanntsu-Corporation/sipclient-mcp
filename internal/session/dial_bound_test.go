package session_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

// newLiveLimitsFixture is a one-session, one-UA fixture over a file-backed
// policy store (config_set needs a file) whose UA is agent. perSession/total
// are the two max_concurrent_calls_* limits.
func newLiveLimitsFixture(t *testing.T, agent session.UserAgent, perSession, total int) (*session.Manager, *session.ToolService, string) {
	t.Helper()
	dir := t.TempDir()
	token := filepath.Join(dir, "bearer.token")
	if err := os.WriteFile(token, []byte("test-bearer-token"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	path := filepath.Join(dir, "policy.yaml")
	body := "auth:\n  bearer_token_file: " + token + "\nlimits:\n" +
		"  max_concurrent_calls_per_session: " + strconv.Itoa(perSession) + "\n" +
		"  max_concurrent_calls_total: " + strconv.Itoa(total) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	fc := fakeclock.New(time.Unix(1_700_000_000, 0))
	store, err := policy.NewStore(path, fc, discardLogger())
	if err != nil {
		t.Fatalf("policy.NewStore: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := session.NewManager(session.ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: store, Logger: discardLogger(),
		NewUA: func(context.Context, session.UAConfig) (session.UserAgent, error) { return agent, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", session.UAConfig{Mode: "direct", Transport: session.TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	return m, session.NewToolService(m), string(ua.Handle())
}

func TestCallDialPassesTheBindingCallLimit(t *testing.T) {
	agent := fakes.NewUserAgent()
	m, ts, uaHandle := newLiveLimitsFixture(t, agent, 3, 5)

	mustDial(t, m, ts, "s1", uaHandle, nil)
	if got := agent.Dials[0].CallLimit; got != 3 {
		t.Fatalf("first dial CallLimit = %d, want min(per_session 3, total 5) = 3", got)
	}

	if _, err := ts.ConfigSet(context.Background(), "s1", session.ConfigSetInput{
		Key: "limits.max_concurrent_calls_total", Value: float64(2),
	}); err != nil {
		t.Fatalf("ConfigSet: %v", err)
	}
	mustDial(t, m, ts, "s1", uaHandle, nil)
	if got := agent.Dials[1].CallLimit; got != 2 {
		t.Fatalf("dial after config_set CallLimit = %d, want 2 (the limit is read live)", got)
	}
}

// waitDialErrorBranch installs the dial-error barrier and returns a function
// that blocks until the branch has run to its end.
func waitDialErrorBranch(t *testing.T) func() {
	t.Helper()
	done := make(chan struct{}, 1)
	session.SetDialErrorHook(func() { done <- struct{}{} })
	t.Cleanup(func() { session.SetDialErrorHook(nil) })
	return func() {
		t.Helper()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the dial-error branch never completed")
		}
	}
}

func dialFailing(t *testing.T, dialErr error) (*session.Call, func()) {
	t.Helper()
	agent := fakes.NewUserAgent()
	agent.DialErr = dialErr
	wait := waitDialErrorBranch(t)
	m, ts, ctx, uaHandle := newFixture(t, fakes.NewArtifactStore(), fakes.NewTap(),
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return agent, nil })
	out, err := ts.CallDial(ctx, "s1", session.CallDialInput{UA: uaHandle, ToURI: "sip:bob@example.com"})
	if err != nil {
		t.Fatalf("call_dial: %v", err)
	}
	c, err := m.ResolveCall(ctx, "s1", session.Handle(out.(map[string]any)["call_handle"].(string)))
	if err != nil {
		t.Fatalf("ResolveCall: %v", err)
	}
	return c, wait
}

func TestDialRefusedByTheUAIsRecordedOnTheCall(t *testing.T) {
	denial := apierr.DeniedLimit("ua_live_dialogs", 33, 34, "this user agent already holds 34 SIP dialogs")
	c, wait := dialFailing(t, denial)
	wait()

	if c.State() != session.StateTerminated || c.TerminationReason() != "transport_failure" {
		t.Fatalf("state=%q reason=%q, want terminated/transport_failure", c.State(), c.TerminationReason())
	}
	evs, _, _ := c.Events(0)
	var errs []session.Event
	for _, e := range evs {
		if e.Type == session.EventError {
			errs = append(errs, e)
		}
	}
	if len(errs) != 1 {
		t.Fatalf("got %d error events, want exactly 1: %+v", len(errs), evs)
	}
	if last := evs[len(evs)-1]; last.Seq != errs[0].Seq {
		t.Fatalf("the error event is not the last event: %+v", evs)
	}
	d := errs[0].Detail
	if d["kind"] != "dial_refused" || d["code"] != string(apierr.CodeDenied) ||
		d["rule"] != "ua_live_dialogs" || d["limit"] != 33 || d["current"] != 34 {
		t.Fatalf("detail = %+v, want {kind:dial_refused code:%s rule:ua_live_dialogs limit:33 current:34}",
			d, apierr.CodeDenied)
	}
}

func TestDialFailureOtherThanDenialKeepsANilDetail(t *testing.T) {
	c, wait := dialFailing(t, apierr.Internal("", "boom"))
	wait()

	if c.State() != session.StateTerminated || c.TerminationReason() != "transport_failure" {
		t.Fatalf("state=%q reason=%q, want terminated/transport_failure", c.State(), c.TerminationReason())
	}
	evs, _, _ := c.Events(0)
	last := evs[len(evs)-1]
	if last.Type != session.EventError || last.Detail != nil {
		t.Fatalf("last event = %+v, want an error event with no detail", last)
	}
}

// blockingDialAgent holds Dial until release is closed, then returns err.
type blockingDialAgent struct {
	*fakes.UserAgent
	entered chan struct{}
	release chan struct{}
	err     error
}

func (a *blockingDialAgent) Dial(_ context.Context, _ session.DialRequest) (session.DialResult, error) {
	close(a.entered)
	<-a.release
	return session.DialResult{}, a.err
}

func TestDialRefusalRacingCallHangupLeavesOneTerminalEvent(t *testing.T) {
	agent := &blockingDialAgent{
		UserAgent: fakes.NewUserAgent(), entered: make(chan struct{}), release: make(chan struct{}),
		err: apierr.DeniedLimit("ua_live_dialogs", 33, 33, "this user agent already holds 33 SIP dialogs"),
	}
	wait := waitDialErrorBranch(t)
	m, ts, ctx, uaHandle := newFixture(t, fakes.NewArtifactStore(), fakes.NewTap(),
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return agent, nil })

	out, err := ts.CallDial(ctx, "s1", session.CallDialInput{UA: uaHandle, ToURI: "sip:bob@example.com"})
	if err != nil {
		t.Fatalf("call_dial: %v", err)
	}
	handle := out.(map[string]any)["call_handle"].(string)
	c, err := m.ResolveCall(ctx, "s1", session.Handle(handle))
	if err != nil {
		t.Fatalf("ResolveCall: %v", err)
	}
	select {
	case <-agent.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Dial was never reached")
	}
	if _, err := ts.CallHangup(ctx, "s1", session.CallHangupInput{Call: handle}); err != nil {
		t.Fatalf("call_hangup: %v", err)
	}
	close(agent.release)
	wait() // the dial-error branch has attempted (and lost) its terminal claim

	if c.TerminationReason() != "local_hangup" {
		t.Fatalf("termination_reason = %q, want local_hangup", c.TerminationReason())
	}
	evs, _, _ := c.Events(0)
	byes := 0
	for _, e := range evs {
		if e.Type == session.EventBye {
			byes++
		}
		if e.Detail["kind"] == "dial_refused" {
			t.Fatalf("a dial_refused diagnostic survived the lost claim: %+v", evs)
		}
	}
	if byes != 1 || evs[len(evs)-1].Type != session.EventBye {
		t.Fatalf("want exactly one terminal bye, as the last event; got %+v", evs)
	}
}
