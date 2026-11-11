package session

import (
	"context"
	"fmt"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// CF-061, window W2: CallHangup claims the call with TryHangup and only then
// resolves the UA a second time to reach its agent. If the session record is
// gone by that second lookup (the reaper's destroySessionAndDelete deletes it
// last), CallHangup returns not_found and sipua never hears the hangup.

// controlOpCheckAgent is a recordingAgent whose ControlOpBlocksHangup runs
// onCheck once. CallHangup calls it on the agent its FIRST ResolveUA returned,
// after ResolveCall and before the irreversible TryHangup claim, so onCheck
// lands between the pre-claim and the post-claim lookups without a seam in
// production code (R-7's no-seam route).
type controlOpCheckAgent struct {
	*recordingAgent
	onCheck func()
}

func (a *controlOpCheckAgent) ControlOpBlocksHangup(string) (ControlOpKind, bool) {
	if f := a.onCheck; f != nil {
		a.onCheck = nil
		f()
	}
	return "", false
}

// newCallHangupFixture opens session s1 with one direct UA backed by agent and
// one answered call on it (dialog dlg-1).
func newCallHangupFixture(t *testing.T, agent *controlOpCheckAgent) (*Manager, *UA, *Call) {
	t.Helper()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, nil), Logger: testLogger(),
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
	c, err := m.CreateCall(ctx, "s1", ua.Handle(), Outbound, StateAnswered)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}
	c.setDialogIdentity("dlg-1", "callid-1")
	return m, ua, c
}

// A targeted regression test of W2's failure site, the post-claim ResolveUA.
// It does NOT reproduce the reaper interleaving. Fidelity lost against a
// production hook: the record is deleted between the pre-claim lookup and the
// claim (not between the claim and the post-claim lookup), and by a direct
// delete standing in for the reaper's last step (destroySessionAndDelete),
// not by the reaper. Running m.ExpireSessions in onCheck does not work: the
// reaper's destroyUA then claims the still-unclaimed call itself. The failing
// line on the unfixed code and the line fix (1) changes are the same either way.
func TestCallHangupReachesTheAgentAfterTheSessionRecordIsDeleted(t *testing.T) {
	agent := &controlOpCheckAgent{recordingAgent: &recordingAgent{}}
	m, _, c := newCallHangupFixture(t, agent)
	agent.onCheck = func() {
		m.mu.Lock()
		delete(m.sessions, "s1")
		m.mu.Unlock()
	}

	_, err := NewToolService(m).CallHangup(context.Background(), "s1", CallHangupInput{Call: string(c.Handle())})
	if err != nil {
		t.Errorf("CallHangup = %v, want nil: the claim won, so the hangup must reach the agent", err)
	}
	if got := fmt.Sprint(agent.seq); got != "[BYE:dlg-1]" {
		t.Errorf("agent sequence = %s, want [BYE:dlg-1]", got)
	}
	if st, r := c.State(), c.TerminationReason(); st != StateTerminated || r != "local_hangup" {
		t.Errorf("call = %s/%q, want terminated/local_hangup", st, r)
	}
	m.mu.RLock()
	accounted := c.accounted
	m.mu.RUnlock()
	if !accounted {
		t.Error("the call's termination was never recorded")
	}
}

// R-12 pin: a UA that is unresolvable before the claim keeps today's
// semantics. The claim still terminates the call, RecordTermination still
// runs, the post-claim ResolveUA's not_found is returned, and no BYE is sent.
func TestCallHangupOnAnUnresolvableUAStillRecordsTheTermination(t *testing.T) {
	agent := &controlOpCheckAgent{recordingAgent: &recordingAgent{}}
	m, ua, c := newCallHangupFixture(t, agent)
	m.mu.Lock()
	s := m.sessions["s1"]
	delete(s.liveUAs, ua.Handle())
	m.mu.Unlock()

	_, err := NewToolService(m).CallHangup(context.Background(), "s1", CallHangupInput{Call: string(c.Handle())})
	if apierr.CodeOf(err) != apierr.CodeNotFound {
		t.Errorf("CallHangup = %v, want not_found", err)
	}
	if st, r := c.State(), c.TerminationReason(); st != StateTerminated || r != "local_hangup" {
		t.Errorf("call = %s/%q, want terminated/local_hangup", st, r)
	}
	m.mu.RLock()
	_, live := s.liveCalls[c.Handle()]
	terminated := 0
	for _, tc := range s.terminatedCalls {
		if tc == c {
			terminated++
		}
	}
	m.mu.RUnlock()
	if live || terminated != 1 {
		t.Errorf("call live=%v, in terminatedCalls %d times; want moved there once by RecordTermination", live, terminated)
	}
	if len(agent.seq) != 0 {
		t.Errorf("agent sequence = %v, want no BYE", agent.seq)
	}
}
