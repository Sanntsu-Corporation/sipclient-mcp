package sipua

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// (context is needed by Step 5's TestStartMediaLoopSkipsWhenDialogAlreadyTornDown,
// added up front since Go requires every import used anywhere in the file to be
// declared at the top.)

func loopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return c
}

// A media loop built for a plain-RTP call uses the identity transform, a jitter
// buffer sized from the configured depth, and stops cleanly and idempotently.
func TestStartMediaLoopPlainLifecycle(t *testing.T) {
	conn := loopbackUDP(t)
	ml := &mediaLoop{
		conn:           conn,
		codecName:      "PCMU",
		payloadType:    0,
		transform:      media.NewIdentityTransform(),
		jitterBufferMS: 60,
	}
	ml.assemble(nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000})
	ml.launch()
	// stop is idempotent and must not panic or block.
	ml.stop()
	ml.stop()
	if ml.jb.Depth() != 3 {
		t.Fatalf("jitter depth=%d want 3 (60ms/20ms)", ml.jb.Depth())
	}
}

// TestStartMediaLoopWithNilLoggerSurvivesMalformedRemoteAddr is C6's mutation
// proof. Before the fix, startMediaLoop's "bad remote addr" branch called
// u.cfg.Logger.Warn directly — a SIGSEGV (nil *slog.Logger method call) on any
// UA built without an explicit Logger, reachable from a PEER-SUPPLIED
// malformed media address (net.ResolveUDPAddr failing on sess.RemoteAddr).
// u.log() (keepalive.go) is the package's one nil-safe accessor; this drives
// startMediaLoop directly on a UA whose Config.Logger is the zero value (nil)
// against a dialog whose mediaSession.RemoteAddr cannot resolve, and asserts
// the process survives (no panic) and the loop is never published.
func TestStartMediaLoopWithNilLoggerSurvivesMalformedRemoteAddr(t *testing.T) {
	// Built directly with New(), NOT newTestUAWithDaemonCtx (that helper sets
	// Config.Logger explicitly via testLogger()) — this test needs the real
	// zero-value nil Logger production callers can leave unset.
	u, err := New(context.Background(), Config{
		Transport: "udp",
		Mode:      "direct",
		LocalAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = u.Close(context.Background()) })
	conn := loopbackUDP(t)
	defer func() { _ = conn.Close() }()

	d := &dialog{
		id: newDialogID(), phase: phaseAnswered,
		mediaConn: conn,
		mediaSession: &media.Session{
			Codec: "PCMU", RemoteAddr: "this is not a valid host:port",
		},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("startMediaLoop panicked with a nil Config.Logger: %v", r)
		}
	}()
	u.startMediaLoop(d)

	if d.mediaLoop != nil {
		t.Fatal("startMediaLoop published a mediaLoop despite an unresolvable RemoteAddr")
	}
}

// TestPlayCannotOpenPromptFileLogsWithNilLoggerWithoutPanic is C6's other
// site: call.go's Play, which was already nil-guarded (`if u.cfg.Logger !=
// nil`) before this change — converging it onto u.log() is pure idiom
// convergence (C-M6), not a bug fix, and must not regress into a panic.
func TestPlayCannotOpenPromptFileLogsWithNilLoggerWithoutPanic(t *testing.T) {
	u := &UA{cfg: Config{Prompts: map[string]string{"prompt-1": "/no/such/file/exists.wav"}}}
	ml := &mediaLoop{emit: func(session.UAEvent) {}}
	ml.assemble(nil, nil)
	d := &dialog{id: "d1", phase: phaseAnswered, mediaLoop: ml}
	u.register(d)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Play panicked with a nil Config.Logger: %v", r)
		}
	}()
	if _, err := u.Play(context.Background(), "d1", "prompt-1", 1, false); apierr.CodeOf(err) != apierr.CodeInvalidArgument {
		t.Fatalf("code=%v want invalid_argument", apierr.CodeOf(err))
	}
}

// An SRTP call whose replay window fails the §6.5.1 invariant must fail
// construction rather than silently degrade.
func TestSRTPMediaLoopAssertsReplayWindow(t *testing.T) {
	lk, _, _ := media.GenerateCryptoAttr()
	rk, _, _ := media.GenerateCryptoAttr()
	// jitterBufferMS 200 needs window >= 10; a window of 1 must be rejected.
	if err := media.AssertReplayWindow(1, 200); err == nil {
		t.Fatal("expected AssertReplayWindow to reject window 1 at 200ms")
	}
	// The production path always uses ReplayWindowFor, which never under-sizes.
	tr, err := media.NewSRTPTransform(lk, rk, media.ReplayWindowFor(200))
	if err != nil || tr == nil {
		t.Fatalf("NewSRTPTransform with ReplayWindowFor(200): %v", err)
	}
}

// TestStartMediaLoopSkipsWhenDialogAlreadyTornDown is the guard's regression:
// if a dialog's phase is no longer phaseAnswered by the time startMediaLoop's
// critical section runs (teardown raced ahead of it), the loop must never
// launch — d.mediaLoop stays nil, and no goroutine is left running against
// the dialog's already-closed conn.
func TestStartMediaLoopSkipsWhenDialogAlreadyTornDown(t *testing.T) {
	u := newTestUAWithDaemonCtx(context.Background(), t)
	conn := loopbackUDP(t)
	defer func() { _ = conn.Close() }()

	d := &dialog{
		id: newDialogID(), phase: phaseDone, // already torn down
		mediaConn: conn,
		mediaSession: &media.Session{
			Codec: "PCMU", RemoteAddr: "127.0.0.1:5004",
		},
	}

	u.startMediaLoop(d)

	if d.mediaLoop != nil {
		t.Fatal("startMediaLoop published a mediaLoop onto an already-torn-down dialog")
	}
}

// runTXStackMarker/runRXStackMarker are the substrings runtime.Stack renders
// for mediaLoop's TX/RX goroutine frames: runTX/runRX are called synchronously
// from launch's goroutine closures (mediaLoop.launch), so their own method
// frames stay on the stack for as long as they run — the same live-stack-dump
// technique armRingTimeoutStackMarker uses in ua_test.go, via the shared
// goroutineStackContains helper defined there.
const (
	runTXStackMarker = "mediaLoop).runTX("
	runRXStackMarker = "mediaLoop).runRX("
)

// waitForGoroutineState polls until marker's presence in a live stack dump
// matches want (true = must be running, false = must have exited), or fails
// the test after a bounded wait. Mirrors waitGoroutineExit's poll style
// (ua_test.go), generalized to the "must be running" direction this test also
// needs before it tears anything down.
func waitForGoroutineState(t *testing.T, marker string, want bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if goroutineStackContains(marker) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if want {
		t.Fatalf("goroutine matching %q did not start within 2s", marker)
	}
	t.Fatalf("goroutine matching %q did not exit within 2s", marker)
}

// TestStopAllMediaLoopsReleasesGoroutinesOnCtxCancellation is the deterministic
// regression test da1b018 lacked (Rule 13 Cycle 4 finding): a phaseAnswered
// dialog's mediaLoop — its runTX/runRX goroutines and UDP socket — must
// actually stop when the UA's context is cancelled directly (UA.Close(), or
// direct cancellation of the daemon ctx uaCtx is derived from), not just on
// the explicit hangup/BYE paths (teardownDialog/Hangup/onBye). Before the fix,
// stopAllMediaLoops did not exist and the ctx watcher goroutine closed only
// the transport, leaving any still-answered dialog's mediaLoop goroutines and
// socket running forever (see stopAllMediaLoops's doc comment,
// dialog_teardown.go).
func TestStopAllMediaLoopsReleasesGoroutinesOnCtxCancellation(t *testing.T) {
	daemonCtx, daemonCancel := context.WithCancel(context.Background())
	defer daemonCancel()
	u := newTestUAWithDaemonCtx(daemonCtx, t)

	conn := loopbackUDP(t)
	d := &dialog{
		id: newDialogID(), phase: phaseAnswered,
		mediaConn: conn,
		mediaSession: &media.Session{
			Codec: "PCMU", RemoteAddr: "127.0.0.1:5004",
		},
	}
	u.register(d)
	u.startMediaLoop(d)

	if d.mediaLoop == nil {
		t.Fatal("startMediaLoop did not publish a live mediaLoop onto the answered dialog")
	}

	// Confirm the TX/RX goroutines are actually running before teardown —
	// otherwise their later absence would prove nothing.
	waitForGoroutineState(t, runTXStackMarker, true)
	waitForGoroutineState(t, runRXStackMarker, true)

	daemonCancel() // simulates UA.Close() / direct daemon-ctx cancellation

	waitForGoroutineState(t, runTXStackMarker, false)
	waitForGoroutineState(t, runRXStackMarker, false)

	if _, _, err := conn.ReadFromUDP(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("mediaConn read after ctx cancellation: got %v, want net.ErrClosed", err)
	}
}

func TestStartMediaLoopKeepsTodaysPTForAHandBuiltSession(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sess     *media.Session
		wantPT   uint8
		wantRecv map[uint8]string
	}{
		{"hand-built", &media.Session{Codec: "PCMA", RemoteAddr: "127.0.0.1:5004"}, 8, map[uint8]string{8: "PCMA"}},
		{"negotiated", &media.Session{Codec: "PCMU", RemoteAddr: "127.0.0.1:5004", SendPT: 96, RecvPTs: map[uint8]string{96: "PCMU"}}, 96, map[uint8]string{96: "PCMU"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newTestUAWithDaemonCtx(context.Background(), t)
			conn := loopbackUDP(t)
			defer func() { _ = conn.Close() }()
			d := &dialog{id: newDialogID(), phase: phaseAnswered, mediaConn: conn, mediaSession: tc.sess}
			u.startMediaLoop(d)
			if d.mediaLoop == nil {
				t.Fatal("no media loop")
			}
			defer d.mediaLoop.stop()
			if d.mediaLoop.payloadType != tc.wantPT || !reflect.DeepEqual(d.mediaLoop.recvPTs, tc.wantRecv) {
				t.Fatalf("payloadType %d recvPTs %v, want %d %v", d.mediaLoop.payloadType, d.mediaLoop.recvPTs, tc.wantPT, tc.wantRecv)
			}
		})
	}
}

// A session whose policy is required but which has no SRTP keys must never run
// as plain RTP: the loop is not started.
func TestStartMediaLoopRequiredWithoutKeysDoesNotStart(t *testing.T) {
	_, sess, err := media.BuildOffer([]string{"PCMU"}, "127.0.0.1:5004", media.SRTPRequired)
	if err != nil {
		t.Fatal(err)
	}
	sess.RemoteAddr, sess.LocalCrypto = "127.0.0.1:5004", nil
	u := newTestUAWithDaemonCtx(context.Background(), t)
	conn := loopbackUDP(t)
	defer func() { _ = conn.Close() }()
	d := &dialog{id: newDialogID(), phase: phaseAnswered, mediaConn: conn, mediaSession: sess}
	u.startMediaLoop(d)
	if d.mediaLoop != nil {
		d.mediaLoop.stop()
		t.Fatal("a required session without keys started a plain RTP loop")
	}
}
