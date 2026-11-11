package session

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// instantAnswerAgent reproduces the LOST-EVENT RACE of the outbound dial path
// deterministically, by collapsing its timing window to zero.
//
// The production shape (internal/sipua/call.go) is:
//
//	d := &dialog{id: newDialogID(), ...}
//	u.register(d)
//	go u.runDial(d)          // <- INVITE/200/ACK can complete in ~1ms
//	return DialResult{...}   //    on loopback with an instant answer
//
// so `runDial`'s 200 OK can reach (*Manager).handleUAEvent BEFORE Dial has
// returned — and therefore before CallDial's post-return
// c.setDialogIdentity has bound the dialog id to the *Call. handleResponse's
// callByDialogID then returns nil and the response is DROPPED SILENTLY: the
// far end has our ACK and believes the call is up, while the MCP client sees
// `dialing` forever with an empty last_response.
//
// This fake emits the 200 from INSIDE Dial, before returning, which is the
// worst case of that window rather than a rare interleaving of it. It is
// therefore DETERMINISTIC where the natural race needs ~10,000 full-stack
// dials to land once.
//
// It emits the event only AFTER invoking req.OnDialogBound, exactly as sipua
// does: the hook is invoked between register(d) and `go u.runDial(d)`, so no
// event can precede it.
type instantAnswerAgent struct {
	nopAgent

	// now is the event timestamp. It comes from the test's fake clock, not
	// from time.Now, because the state machine's transitions are stamped
	// against the manager's clock.
	now time.Time

	mu   sync.Mutex
	fn   UAEventFunc
	hctx context.Context
}

func (a *instantAnswerAgent) OnEvent(ctx context.Context, fn UAEventFunc) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hctx, a.fn = ctx, fn
}

func (a *instantAnswerAgent) Dial(_ context.Context, req DialRequest) (DialResult, error) {
	const dialogID, callID = "dlg-instant", "callid-instant@203.0.113.7"

	// The synchronous bind, at the same point sipua invokes it.
	if req.OnDialogBound != nil {
		req.OnDialogBound(dialogID, callID)
	}

	a.mu.Lock()
	fn, hctx := a.fn, a.hctx
	a.mu.Unlock()
	if fn != nil {
		fn(hctx, UAEvent{
			Kind: UAEventFinal, DialogID: dialogID, CallID: callID,
			Code: 200, Reason: "OK", Direction: Outbound, At: a.now,
		})
	}
	return DialResult{DialogID: dialogID, CallID: callID}, nil
}

// TestInstantlyAnsweredDialReachesAnswered is the regression gate for that
// race. THE ASSERTION IS THE USER-VISIBLE CRITERION, not the mechanism: an
// outbound call whose 200 OK arrives before Dial returns must still reach
// `answered` and must still carry its last_response.
//
// Without the OnDialogBound hook this fails on both counts — the call sits in
// `dialing` with last_response.code 0 — because the only binding is
// CallDial's post-return setDialogIdentity, which has not run yet.
func TestInstantlyAnsweredDialReachesAnswered(t *testing.T) {
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	agent := &instantAnswerAgent{now: fc.Now()}
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: policy.NewStaticStore(policy.Defaults(), fc, testLogger()),
		Logger: testLogger(),
		NewUA:  func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
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

	out, err := ts.CallDial(ctx, "s1", CallDialInput{
		UA: string(ua.Handle()), ToURI: "sip:bob@example.com",
	})
	if err != nil {
		t.Fatalf("call_dial: %v", err)
	}
	res, _ := out.(map[string]any)
	callHandle, _ := res["call_handle"].(string)
	if callHandle == "" {
		t.Fatalf("call_dial result carries no call_handle: %#v", out)
	}
	c, err := m.ResolveCall(ctx, "s1", Handle(callHandle))
	if err != nil {
		t.Fatalf("ResolveCall: %v", err)
	}

	// CallDial dials on a goroutine, so the outcome is polled for rather than
	// read instantaneously. The 200 itself is delivered SYNCHRONOUSLY inside
	// Dial, so this loop is waiting only for that goroutine to be scheduled.
	deadline := time.Now().Add(2 * time.Second)
	for c.State() != StateAnswered && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	if got := c.State(); got != StateAnswered {
		t.Errorf("state = %q, want %q — the 200 OK that arrived before Dial "+
			"returned was dropped by handleResponse's callByDialogID, because "+
			"nothing had bound the dialog id to the call yet", got, StateAnswered)
	}
	if got := c.LastResponseCode(); got != 200 {
		t.Errorf("last_response.code = %d, want 200 — the response was never "+
			"recorded against the call", got)
	}
}
