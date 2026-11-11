package main

import (
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// §11.5: after an ungraceful kill all in-memory state is lost, and every
// previously issued handle returns not_found — NOT gone. A restarted server
// has no record the handle ever existed and must not claim it reclaimed
// something it cannot see.
//
// D331/D-2: this half stays OUT-OF-PROCESS because it is the only genuine
// way to assert "no BYE after SIGKILL" and "process death loses all state" —
// but on its own, replacing both handles below with strings never issued by
// anything ("totally-made-up-handle") still passes, proving only that an
// UNKNOWN string returns not_found, which is true of any string on any
// daemon and says nothing about crash semantics (D331, proved). The explicit
// pre-kill resolution assertion closes that hole: it fails outright on a
// garbage handle, so the not_found checks below can only be exercised by a
// handle the daemon genuinely issued and then lost to the crash.
func TestCrashLosesAllStateAndHandlesReturnNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and forks the daemon binary")
	}
	bin := filepath.Join(t.TempDir(), "sipclient-mcpd")
	build := exec.Command("go", "build", "-o", bin,
		"github.com/sanntsu-corporation/sipclient-mcp/cmd/sipclient-mcpd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build daemon: %v\n%s", err, out)
	}

	// StartDaemonProcess allocates a fresh, kernel-assigned port (D310): a
	// fixed port collides across packages under -count=2, and D329 flags the
	// plan's original "fixed listen addr" comment as contradicting this.
	d := loopback.StartDaemonProcess(t, bin)
	ua := d.MustCreateUA(t, "direct")
	call := d.MustDial(t, ua, d.PeerURI())
	d.MustWait(t, call, "answered", 2000)

	// D331: the handle must be shown to resolve BEFORE the kill, or the
	// not_found checks after restart prove nothing.
	if _, err := d.CallTool("call_status", map[string]any{"call": call}); err != nil {
		t.Fatalf("call_status on %q before the kill: %v — a handle that never "+
			"resolved proves nothing about crash semantics", call, err)
	}

	byeBefore := d.Peer().ByeCount()
	d.Signal(t, syscall.SIGKILL)
	// A SIGKILLed process exits with a signal error, not nil — the error
	// itself carries no information this test needs, only that the process
	// is gone before the state assertions below run.
	_, _ = d.WaitForExit(t, 2*time.Second)

	// No BYE is sent on a crash (§11.5): live dialogs are orphaned.
	if got := d.Peer().ByeCount(); got != byeBefore {
		t.Fatalf("peer observed %d BYE after SIGKILL, want %d — §11.5 sends none",
			got, byeBefore)
	}

	// A fresh process, its own fresh ephemeral port and its own empty registry
	// (D310) — "same address" was never true and D329 corrects the comment.
	d2 := loopback.StartDaemonProcess(t, bin)
	defer d2.Stop(t, 2*time.Second)

	for _, tc := range []struct{ tool, arg, handle string }{
		{"call_status", "call", call},
		{"call_events", "call", call},
		{"call_ladder", "call", call},
		{"call_hangup", "call", call},
		{"ua_status", "ua", ua},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			_, err := d2.CallTool(tc.tool, map[string]any{tc.arg: tc.handle})
			code := loopback.ErrorCode(err)
			if code == "gone" {
				t.Fatalf("%s on a pre-crash handle returned %q; §11.5 requires %q — a "+
					"restarted server must not claim it reclaimed something it cannot see",
					tc.tool, "gone", "not_found")
			}
			if code != "not_found" {
				t.Fatalf("%s on a pre-crash handle returned %q, want %q",
					tc.tool, code, "not_found")
			}
		})
	}
}

// D-2/D331: the "gone" branch of §N3's not_found/gone contrast is otherwise
// UNREACHABLE by any test — the out-of-process half above can only ever
// produce not_found (a fresh process has no tombstone for a pre-crash
// handle), so on its own it cannot show the daemon is capable of returning
// "gone" at all. Without exercising "gone" somewhere, "not_found" is
// unfalsifiable: a stub that always answered not_found would pass every
// check above. This in-process half proves both codes are reachable, from
// the SAME live harness: a handle this harness evicted (§N3, via EvictNow)
// returns "gone"; a handle nothing ever issued returns "not_found".
//
// D-2: does NOT widen DaemonProcess for this — Harness.EvictNow already
// exists and is in-process, so no new surface is needed.
func TestEvictedHandleIsGoneUnissuedHandleIsNotFound(t *testing.T) {
	h := loopback.New(t)
	defer h.Close()

	ua := h.MustCreateUA(t, "direct")
	call := h.MustDial(t, ua, h.PeerURI())
	h.MustWait(t, call, "answered", 2000)

	// Pre-eviction: the handle resolves. Without this, a mutation that broke
	// EvictNow into a silent no-op would still leave the "gone" assertion
	// below vacuously satisfied by coincidence rather than by eviction.
	if _, err := h.CallTool("call_status", map[string]any{"call": call}); err != nil {
		t.Fatalf("call_status on %q before eviction: %v", call, err)
	}

	h.EvictNow(call)

	_, err := h.CallTool("call_status", map[string]any{"call": call})
	if code := loopback.ErrorCode(err); code != "gone" {
		t.Fatalf("call_status on an evicted handle in a LIVE daemon returned %q, want %q (§N3)",
			code, "gone")
	}

	_, err = h.CallTool("call_status", map[string]any{"call": "totally-made-up-handle"})
	if code := loopback.ErrorCode(err); code != "not_found" {
		t.Fatalf("call_status on a never-issued handle returned %q, want %q", code, "not_found")
	}
}
