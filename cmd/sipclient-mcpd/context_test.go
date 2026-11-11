package main

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// Decision 17, path 2 of handoff §3d: UA and call goroutines hang off the
// DAEMON context. A client disconnect must never cancel a live call — doing
// so would break D11 point 5 and R8.
func TestRequestCancellationDoesNotTerminateLiveCall(t *testing.T) {
	h := loopback.New(t, loopback.WithPeerBehaviour(loopback.PeerBehaviour{AnswerAfter: 0}))
	defer h.Close()

	ua := h.MustCreateUA(t, "direct")
	call := h.MustDial(t, ua, h.PeerURI())
	h.MustWait(t, call, "answered", 2000)

	// Issue a call_status on a request context we cancel the instant it
	// returns, simulating a client that drops its HTTP connection.
	cancelCtx, cancel := context.WithCancel(context.Background())
	if _, err := h.CallToolCtx(cancelCtx, "call_status", map[string]any{"call": call}); err != nil {
		t.Fatalf("call_status: %v", err)
	}
	cancel()

	// The call must still be live 500 ms later, and the peer must have seen no BYE.
	time.Sleep(500 * time.Millisecond)
	got := h.MustCallStatus(t, call)
	if got.State != "answered" {
		t.Fatalf("call state after request cancellation = %q, want %q (decision 17: "+
			"the request context must not own the call)", got.State, "answered")
	}
	if n := h.Peer().ByeCount(); n != 0 {
		t.Fatalf("peer observed %d BYE after a client disconnect, want 0", n)
	}
}

// Decision 17, path 3 of handoff §3d: §12.7's admin DELETE tears down calls
// the request context does not own. An admin client that disconnects mid-BYE
// must not leave a half-torn-down UA.
//
// Default limits.shutdown_grace_period is 10s (§11.4/§12.7 share one key);
// bounded to 1s here so the 3s poll deadline below is a real deadline rather
// than a race against the default (D332).
func TestAdminDeleteCompletesAfterAdminClientDisconnects(t *testing.T) {
	h := loopback.New(t,
		loopback.WithAdminToken("admin-secret"),
		loopback.WithPolicyOverride("limits.shutdown_grace_period", "1s"),
		loopback.WithPeerBehaviour(loopback.PeerBehaviour{AnswerAfter: 0, SwallowBye: true}))
	defer h.Close()

	ua := h.MustCreateUA(t, "direct")
	call := h.MustDial(t, ua, h.PeerURI())
	h.MustWait(t, call, "answered", 2000)

	adminCtx, cancelAdmin := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = h.AdminDeleteCtx(adminCtx, ua) // may error: the client goes away
	}()

	// Let the BYE go out, then drop the admin connection.
	h.Peer().WaitForBye(t, 2*time.Second)
	cancelAdmin()
	<-done
	sinceCancel := time.Now()

	// Teardown must still complete on the daemon context, within the grace
	// period.
	//
	// "UA gone from the list" ALONE IS NOT SUFFICIENT: RecordUADestroyed runs
	// UNCONDITIONALLY at the end of destroyUA regardless of whether Hangup,
	// Unregister or Close actually succeeded — a tdCtx wrongly derived from
	// the CALLER's (already-cancelled) ctx makes every one of those three
	// calls fail IMMEDIATELY with a context error, so RecordUADestroyed still
	// runs, just far FASTER than correct code, and the UA still disappears
	// from the list. Proved by mutation: deriving tdCtx from ctx made this
	// removal land in ~0.02s against the unmutated ~1.03s (SwallowBye starves
	// Hangup's wait for the full grace period on the CORRECT daemon-context
	// budget, which the admin client's disconnect must not shorten). The
	// minimum-elapsed assertion below is what actually distinguishes them.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(h.MustAdminListUAs(t)) == 0 {
			if elapsed := time.Since(sinceCancel); elapsed < 800*time.Millisecond {
				t.Fatalf("UA removed %v after the admin client disconnected, want >= ~1s "+
					"(the grace period): teardown looks bound to the caller's context, "+
					"not the daemon context (decision 17 path 3)", elapsed)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("UA still live after an admin DELETE whose client disconnected: teardown " +
		"was bound to the request context (decision 17 path 3)")
}
