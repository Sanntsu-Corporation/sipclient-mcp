package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

func TestGracefulShutdownSendsByeAndLogsLocalHangup(t *testing.T) {
	h := loopback.New(t,
		loopback.WithAccounts(loopback.TestAccount("carrier-a", "s3cr3t-auth-pass")),
		loopback.WithPolicyOverride("limits.shutdown_grace_period", "2s"),
		loopback.WithPeerBehaviour(loopback.PeerBehaviour{AnswerAfter: 0}))
	defer h.Close()
	grace := 2 * time.Second

	// Register-mode UA: only a registered UA produces the REGISTER Expires:0
	// this test asserts (D329/D332's UnregisterCount is the REGISTRAR's
	// counter, keyed by user, not the peer's — a direct UA never registers).
	ua := h.MustCreateUAWithAccount(t, "carrier-a")
	var calls []string
	for i := 0; i < 3; i++ {
		c := h.MustDial(t, ua, h.PeerURI())
		h.MustWait(t, c, "answered", 2000)
		calls = append(calls, c)
	}

	// A waiter parked across the shutdown must be woken by §6.3 rule 2's
	// terminal broadcast, not dropped with the connection.
	//
	// until MUST be a state the call has NOT yet reached: (*Call).register
	// evaluates its predicate against the WHOLE existing log first (§10.5 — a
	// waiter must not miss an event appended before it registered), so
	// until="any" on an already-answered call matches the pre-existing
	// "answered" event and returns IMMEDIATELY, never parking a waiter at
	// all — WaitForWaiterCount then times out at 0, not 1. "terminated" (->
	// EventBye) has not happened yet, so this one genuinely parks and is
	// woken by the shutdown BYE below.
	waitDone := make(chan loopback.WaitResult, 1)
	go func() { waitDone <- h.CallWait(calls[0], "terminated", 300000) }()
	h.WaitForWaiterCount(t, calls[0], 1, time.Second)

	start := time.Now()
	// These tests live in package main, where gracefulShutdown and
	// shutdownDeps ARE visible, so they pass the REAL function and REAL deps
	// in — asserting the daemon's own §11.4 ordering rather than a
	// harness-local copy of it (D306/D309/D330). HTTPServer() returns
	// *httptest.Server; its .Config field is the *http.Server shutdownDeps
	// wants (D328/D329).
	h.ShutdownWith(func() error {
		return gracefulShutdown(context.Background(), shutdownDeps{
			Server: h.MCPServer(), HTTP: h.HTTPServer().Config,
			Manager: h.Manager(), Logger: h.Logger(), Clock: h.HarnessClock(),
		}, grace)
	})
	if err := h.WaitForExit(t, 3*time.Second); err != nil {
		t.Fatalf("gracefulShutdown returned an error: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed > grace {
		t.Fatalf("shutdown took %v, want <= the %v grace period", elapsed, grace)
	}
	if n := h.Peer().ByeCount(); n != 3 {
		t.Fatalf("peer observed %d BYE, want exactly 3 (§11.4)", n)
	}
	// The REGISTRAR's counter (sipproxy.Proxy), keyed by AOR user — not
	// peer.Peer.UnregisterCount(), which takes no argument and counts at a
	// different, unregistered listener the REGISTER never reaches (D329/D332).
	if n := h.Registrar().UnregisterCount("testuser"); n != 1 {
		t.Fatalf("registrar observed %d REGISTER Expires:0, want 1", n)
	}

	select {
	case res := <-waitDone:
		if res.Err != nil {
			t.Fatalf("parked call_wait returned error %v, want the terminal event "+
				"(§11.4: waiters are woken by rule 2's broadcast before exit)", res.Err)
		}
		if res.TimedOut {
			t.Fatal("parked call_wait timed out; it must be woken by the terminal broadcast")
		}
	case <-time.After(time.Second):
		t.Fatal("parked call_wait never returned across shutdown")
	}

	// h.CallLogLines(t) CANNOT be used here: it filters on m["event"] ==
	// "call_log", a key (*Manager).emitCallLog (internal/session/janitor.go)
	// never sets — it logs msg="call terminated" with named scalar fields and
	// no "event" attribute at all (grep confirms "call_log" as an attribute
	// VALUE appears nowhere in internal/session; only loopback's own filter
	// names it). CallLogLines/CallLogLineFor/CallLogLineCountFor are therefore
	// unconditionally empty as shipped — a pre-existing testutil defect
	// (loopback/helpers.go, out of this task's file scope), reported, not
	// fixed (Rule 19). Decoding RawLog() for msg=="call terminated" directly
	// asserts the same §11.4 acceptance criterion against data production
	// code actually emits.
	var callTerminatedLines int
	for _, line := range strings.Split(h.RawLog(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil || m["msg"] != "call terminated" {
			continue
		}
		callTerminatedLines++
		if reason, _ := m["termination_reason"].(string); reason != "local_hangup" {
			t.Fatalf("termination_reason = %q, want %q — §11.4 introduces no "+
				"server_shutdown enum value", reason, "local_hangup")
		}
	}
	if callTerminatedLines != 3 {
		t.Fatalf("got %d \"call terminated\" log lines, want 3", callTerminatedLines)
	}
	if strings.Contains(h.RawLog(), "server_shutdown") {
		t.Fatal("log mentions server_shutdown: §10.3's enum is exhaustive and gained no value")
	}
}

func TestGracefulShutdownRefusesNewDialsWithResourceLimit(t *testing.T) {
	h := loopback.New(t,
		loopback.WithPolicyOverride("limits.shutdown_grace_period", "3s"),
		loopback.WithPeerBehaviour(loopback.PeerBehaviour{AnswerAfter: 0, SwallowBye: true}))
	defer h.Close()
	grace := 3 * time.Second

	ua := h.MustCreateUA(t, "direct")
	c := h.MustDial(t, ua, h.PeerURI())
	h.MustWait(t, c, "answered", 2000)

	// A second session, minted BEFORE shutdown starts, whose UA the
	// resource_limit probe below dials from once shutdown is under way.
	refuseSess := h.NewSession(t)
	refuseUA := refuseSess.MustCreateUA(t, "direct")

	h.ShutdownWith(func() error {
		return gracefulShutdown(context.Background(), shutdownDeps{
			Server: h.MCPServer(), HTTP: h.HTTPServer().Config,
			Manager: h.Manager(), Logger: h.Logger(), Clock: h.HarnessClock(),
		}, grace)
	})
	h.Peer().WaitForBye(t, 2*time.Second) // shutdown is now inside the grace period

	// h.CallTool CANNOT exercise this assertion: §11.4 step 1 (StopAccepting)
	// is a blanket transport-level 503 for EVERY /mcp request once draining —
	// confirmed against internal/transport/mcp's own
	// TestStopAcceptingRefusesNewMCPRequestsOnly, whose own body 503s a
	// non-init request on an established session too, and confirmed here by
	// probe: a call_dial issued after WaitForBye returns HTTP 503 with a
	// PLAIN-TEXT "shutting down" body, never a JSON-RPC resource_limit
	// envelope, because step 1 always completes microseconds before step 3's
	// BYE is externally observable. Calling ToolService.CallDial directly
	// against the SAME *session.Manager gracefulShutdown was handed is the
	// only way to observe step 2's (RefuseNewDials) effect — it still
	// exercises the real Manager, just below the transport layer that step 1
	// deliberately shuts first.
	_, err := session.NewToolService(h.Manager()).CallDial(context.Background(), refuseSess.ID(),
		session.CallDialInput{UA: refuseUA, ToURI: h.PeerURI()})
	if code := loopback.ErrorCode(err); code != "resource_limit" {
		t.Fatalf("call_dial during shutdown returned code %q, want %q (§11.4, §11.2)",
			code, "resource_limit")
	}
	if err := h.WaitForExit(t, 4*time.Second); err != nil {
		t.Fatalf("gracefulShutdown returned an error: %v", err)
	}
}

func TestUnconfirmedDialogsAbandonedAtGraceExpiryWithErrorEvent(t *testing.T) {
	h := loopback.New(t,
		loopback.WithPolicyOverride("limits.shutdown_grace_period", "500ms"),
		loopback.WithPeerBehaviour(loopback.PeerBehaviour{AnswerAfter: 0, SwallowBye: true}))
	defer h.Close()
	grace := 500 * time.Millisecond

	// A session minted here (rather than h's own implicit one) so its ID is
	// available below: h.HTTPServer().Config genuinely closes the listener at
	// gracefulShutdown's step 7 (D330), so once WaitForExit returns, an
	// HTTP-based read (h.MustCallEvents, which uses h's own hidden session
	// over HTTP) gets "connection refused" — verified by running this test
	// with h.MustCallEvents in place of the ToolService call below. Reading
	// call_events via ToolService directly against h.Manager() (the SAME
	// Manager gracefulShutdown was handed) reaches the call's event log
	// without going through the now-closed listener.
	sess := h.NewSession(t)
	ua := sess.MustCreateUA(t, "direct")
	c := sess.MustDial(t, ua, h.PeerURI())
	sess.MustWait(t, c, "answered", 2000)

	start := time.Now()
	h.ShutdownWith(func() error {
		return gracefulShutdown(context.Background(), shutdownDeps{
			Server: h.MCPServer(), HTTP: h.HTTPServer().Config,
			Manager: h.Manager(), Logger: h.Logger(), Clock: h.HarnessClock(),
		}, grace)
	})
	if err := h.WaitForExit(t, 3*time.Second); err != nil {
		t.Fatalf("gracefulShutdown returned an error: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("shutdown waited %v for an unanswered BYE, want abandonment at the "+
			"%v grace period", d, grace)
	}

	// D334: "event" is §10.5's term of art for the PER-CALL event log
	// (call_events), not the daemon's slog stream — LogHasEvent inspects the
	// latter and would never see this. Assert against the call's own log.
	out, err := session.NewToolService(h.Manager()).CallEvents(context.Background(), sess.ID(),
		session.CallEventsInput{Call: c})
	if err != nil {
		t.Fatalf("call_events: %v", err)
	}
	events, _ := out.(map[string]any)["events"].([]session.Event)
	found := false
	for _, ev := range events {
		if ev.Type == session.EventError {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no error event logged for the abandoned dialog (§11.4)")
	}
}
