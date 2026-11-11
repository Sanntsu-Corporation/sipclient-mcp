package session

import (
	"context"
	"sync"
	"testing"
	"time"
)

// hangupLog counts Hangup calls per dialog id.
type hangupLog struct {
	nopAgent
	mu    sync.Mutex
	calls map[string]int
}

func (a *hangupLog) Hangup(_ context.Context, dialogID, _ string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls[dialogID]++
	return nil
}

func (a *hangupLog) count(id string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls[id]
}

// TestReloadOverdueCapHangsUpOnce is CF-092 on the reload path: a reload that
// makes calls overdue ends each dialog on the wire exactly once, and the
// session slots are freed by the time Reload returns.
func TestReloadOverdueCapHangsUpOnce(t *testing.T) {
	m, store, fc, path := newReloadManager(t, 300)
	agent := &hangupLog{calls: map[string]int{}}
	m.newUA = func(context.Context, UAConfig) (UserAgent, error) { return agent, nil }

	ids := []string{"dlg-a", "dlg-b"}
	for i, sid := range []string{"s1", "s2"} {
		c := answeredCall(t, m, sid)
		c.setDialogIdentity(ids[i], "callid-"+ids[i]+"@203.0.113.4")
	}
	fc.Advance(120 * time.Second)

	rewriteCap(t, path, capBody(t, path, 60))
	if err := store.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, total := m.DebugLiveCallCounts("s1"); total != 0 {
		t.Fatalf("live calls after Reload = %d, want 0", total)
	}
	for _, id := range ids {
		deadline := time.Now().Add(2 * time.Second)
		for agent.count(id) < 1 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if n := agent.count(id); n != 1 {
			t.Errorf("Hangup calls for %s = %d, want 1", id, n)
		}
	}
}
