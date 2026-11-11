// Task 6 (D9b): capture_start/capture_stop, dial-time arming and the
// finding-NEW-2 no-orphan invariant.
//
// THIS FILE IS package session_test, NOT package session, and that is
// load-bearing rather than a style choice. Every other capture-adjacent
// test in this package uses internal/testutil/fakes, but fakes.Tap and
// fakes.ArtifactStore both import internal/session (so a fake can implement
// session.ArtifactStore/session.Tap) — importing internal/testutil/fakes
// from an INTERNAL test file (package session, no _test suffix) would close
// an import cycle (session -> fakes -> session), which the Go compiler
// rejects outright ("import cycle not allowed in test"). An EXTERNAL test
// package breaks the cycle: session_test depends on session and on fakes,
// and fakes never depends on session_test, so there is no cycle. Every
// other *_test.go under internal/session avoids this by hand-rolling its
// own local doubles (nopAgent, dialResultAgent, instantAnswerAgent,
// recordingTap) instead of importing internal/testutil/fakes; this file
// takes the external-package route instead, which is the only way to
// satisfy the brief's instruction to drive these tests through the
// EXISTING fakes.Tap and fakes.ArtifactStore (Rule 16 reuse) rather than
// hand-rolling yet another pair of local doubles for the same two
// interfaces.
//
// The three no-orphan tests below need REAL file-on-disk O_EXCL semantics
// that fakes.ArtifactStore's in-memory map does not enforce (its Create
// simply overwrites on a second call). The brief asks for
// internal/artifact.Store itself, but that package is UNREACHABLE from
// ANY internal/session test file, external or internal: internal/artifact
// is in internal/importguard's engineLayer ban list, and
// TestSessionTestPackageRunsOnFakes asserts internal/session's whole TEST
// BINARY (both the internal package and this external one compile into a
// single test binary) never imports it — confirmed by reproducing the
// import-cycle-vs-engineLayer distinction locally before writing this file.
// diskArtifactStore below is a minimal, test-only session.ArtifactStore
// mirroring ONLY the file-on-disk properties (O_EXCL create, Remove frees
// the slot) those three tests assert, over a real t.TempDir() — it is not a
// second production implementation, and internal/artifact.Store remains the
// one canonical concrete session.ArtifactStore (Rule 18).
package session_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func isCode(err error, want apierr.Code) bool {
	var ae *apierr.Error
	return errors.As(err, &ae) && ae.Code == want
}

// newFixture builds a Manager + ToolService over the given collaborators,
// opens session "s1" and creates one direct-mode UA in it. Every test below
// starts from this.
func newFixture(t *testing.T, art session.ArtifactStore, tap session.Tap,
	newUA func(context.Context, session.UAConfig) (session.UserAgent, error),
) (*session.Manager, *session.ToolService, context.Context, string) {
	t.Helper()
	return newFixtureWithPolicy(t, art, tap, newUA, policy.Defaults())
}

// newFixtureWithPolicy is newFixture with an explicit Policy, for the tool-layer
// tests that must reach a branch keyed off a policy value (e.g. the sub-24
// capture.max_bytes_per_call InvalidArgument gate — B2b). Every other test uses
// newFixture's Defaults().
func newFixtureWithPolicy(t *testing.T, art session.ArtifactStore, tap session.Tap,
	newUA func(context.Context, session.UAConfig) (session.UserAgent, error), pol *policy.Policy,
) (*session.Manager, *session.ToolService, context.Context, string) {
	t.Helper()
	fc := fakeclock.New(time.Unix(1_700_000_000, 0))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := session.NewManager(session.ManagerConfig{
		Ctx:       ctx,
		Clock:     fc,
		Policy:    policy.NewStaticStore(pol, fc, discardLogger()),
		Logger:    discardLogger(),
		Tap:       tap,
		Artifacts: art,
		NewUA:     newUA,
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
	return m, session.NewToolService(m), ctx, string(ua.Handle())
}

// mustDial places a call and waits for its Call-ID to be observable. The
// default fakes.UserAgent's Dial does not invoke OnDialogBound, but it DOES
// return a DialResult carrying a non-empty scripted Call-ID, which
// CallDial's post-return second bind (setDialogIdentity) applies once the
// dial goroutine's Dial call returns — so polling for a non-empty CallID is
// a sufficient, deterministic settle signal for the tests that only need a
// resolvable call and are not exercising dial-time capture arming.
func mustDial(t *testing.T, m *session.Manager, ts *session.ToolService, sid, uaHandle string, capture *session.CaptureInput) (string, *session.Call) {
	t.Helper()
	ctx := context.Background()
	out, err := ts.CallDial(ctx, sid, session.CallDialInput{
		UA: uaHandle, ToURI: "sip:bob@example.com", Capture: capture,
	})
	if err != nil {
		t.Fatalf("call_dial: %v", err)
	}
	res, _ := out.(map[string]any)
	h, _ := res["call_handle"].(string)
	if h == "" {
		t.Fatalf("call_dial result carries no call_handle: %#v", out)
	}
	c, err := m.ResolveCall(ctx, sid, session.Handle(h))
	if err != nil {
		t.Fatalf("ResolveCall: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for c.CallID() == "" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.CallID() == "" {
		t.Fatalf("call_dial's goroutine never settled a Call-ID within the deadline")
	}
	return h, c
}

// boundDialAgent is a session.UserAgent double whose Dial invokes
// req.OnDialogBound SYNCHRONOUSLY, at the same point sipua does (between
// registering the dialog and spawning the INVITE), reproducing the
// dialbind_test.go instantAnswerAgent pattern for this external package
// (that helper is unexported and internal to package session). The DEFAULT
// fakes.UserAgent deliberately does NOT do this (see its own Dial), which
// is exactly why the dial-time-arming tests need a distinct double.
type boundDialAgent struct {
	*fakes.UserAgent
	dialogID, callID string
}

func newBoundDialAgent(dialogID, callID string) *boundDialAgent {
	u := fakes.NewUserAgent()
	u.DialResult = session.DialResult{DialogID: dialogID, CallID: callID}
	return &boundDialAgent{UserAgent: u, dialogID: dialogID, callID: callID}
}

func (a *boundDialAgent) Dial(ctx context.Context, req session.DialRequest) (session.DialResult, error) {
	if req.OnDialogBound != nil {
		req.OnDialogBound(a.dialogID, a.callID)
	}
	return a.UserAgent.Dial(ctx, req)
}

// deferredBindAgent is a session.UserAgent double that CAPTURES the dial-time
// OnDialogBound callback and hands it to the test over `bound` INSTEAD OF
// invoking it inline, so the test can drive the call to a terminal state
// BEFORE the late bind fires — the exact interleaving of the Cycle-2 2b race
// (dial-time arm racing terminal-close). Its DialResult carries an EMPTY
// Call-ID, so CallDial's post-return second bind (setDialogIdentity) never sets
// a Call-ID: the test owns the single (manual) bind. Dial then BLOCKS on
// `release` until t.Cleanup closes it, so the dial goroutine's post-return
// bookkeeping can never race the test's manual bind.
type deferredBindAgent struct {
	*fakes.UserAgent
	dialogID, callID string
	bound            chan func(dialogID, callID string)
	release          chan struct{}
}

func newDeferredBindAgent(dialogID, callID string) *deferredBindAgent {
	u := fakes.NewUserAgent()
	u.DialResult = session.DialResult{} // empty Call-ID: no post-return bind
	return &deferredBindAgent{
		UserAgent: u, dialogID: dialogID, callID: callID,
		bound:   make(chan func(dialogID, callID string), 1),
		release: make(chan struct{}),
	}
}

func (a *deferredBindAgent) Dial(ctx context.Context, req session.DialRequest) (session.DialResult, error) {
	if req.OnDialogBound != nil {
		a.bound <- req.OnDialogBound
	}
	<-a.release // hold the goroutine so its post-return bind never races the manual one
	return a.UserAgent.Dial(ctx, req)
}

// ---- diskArtifactStore: real-file session.ArtifactStore, orphan tests only -

var _ session.ArtifactStore = (*diskArtifactStore)(nil)

// diskArtifactStore mirrors internal/artifact.Store's file-on-disk contract
// (O_EXCL create; Remove frees the slot) over a real t.TempDir(), for the
// three no-orphan tests that need genuine exclusivity — see this file's
// package doc comment for why internal/artifact itself cannot be imported
// here.
type diskArtifactStore struct{ dir string }

func newDiskArtifactStore(dir string) *diskArtifactStore { return &diskArtifactStore{dir: dir} }

func (s *diskArtifactStore) callDir(callHandle string) string {
	return filepath.Join(s.dir, callHandle)
}

func (s *diskArtifactStore) OpenCallDir(_ context.Context, callHandle string) error {
	return os.MkdirAll(s.callDir(callHandle), 0o700)
}

func (s *diskArtifactStore) Create(_ context.Context, callHandle, name string) (io.WriteCloser, error) {
	if err := os.MkdirAll(s.callDir(callHandle), 0o700); err != nil {
		return nil, err
	}
	// O_EXCL, exactly like internal/artifact.Store.Create (finding 1a): a
	// second Create for an existing artifact fails with os.ErrExist rather
	// than truncating it.
	return os.OpenFile(filepath.Join(s.callDir(callHandle), name),
		os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
}

func (s *diskArtifactStore) Close(_ context.Context, callHandle, name string) (session.ArtifactInfo, error) {
	fi, err := os.Stat(filepath.Join(s.callDir(callHandle), name))
	if err != nil {
		return session.ArtifactInfo{}, err
	}
	return session.ArtifactInfo{
		CallHandle: callHandle, Name: name, URI: s.URI(callHandle, name),
		Bytes: fi.Size(), ClosedAt: time.Now(),
	}, nil
}

func (s *diskArtifactStore) Remove(_ context.Context, callHandle, name string) error {
	err := os.Remove(filepath.Join(s.callDir(callHandle), name))
	if errors.Is(err, os.ErrNotExist) {
		return nil // idempotent, matching internal/artifact.Store.Remove
	}
	return err
}

func (s *diskArtifactStore) URI(callHandle, name string) string {
	return "mcp://sipclient/artifacts/" + callHandle + "/" + name
}

func (s *diskArtifactStore) Resolve(context.Context, string) (session.ArtifactInfo, io.ReadCloser, error) {
	return session.ArtifactInfo{}, nil, errors.New("diskArtifactStore: Resolve is unused by this file's tests")
}

func (s *diskArtifactStore) UsageBytes(context.Context) (int64, error) {
	var total int64
	err := filepath.Walk(s.dir, func(_ string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			total += fi.Size()
		}
		return nil
	})
	return total, err
}

// NonLiveUsageBytes: this test double models no live-call concept at all, so
// it reports the same total as UsageBytes.
func (s *diskArtifactStore) NonLiveUsageBytes(ctx context.Context) (int64, error) {
	return s.UsageBytes(ctx)
}

// exists reports whether callHandle/name is present on disk.
func (s *diskArtifactStore) exists(callHandle, name string) bool {
	_, err := os.Stat(filepath.Join(s.callDir(callHandle), name))
	return err == nil
}

// ---- capture_start / capture_stop round trip -------------------------------

// TestCaptureStartStopRoundTrip is the §10.11 (L991/L994) normative shape
// check, over the existing fakes.Tap and fakes.ArtifactStore (Rule 16).
func TestCaptureStartStopRoundTrip(t *testing.T) {
	tap := fakes.NewTap()
	tap.ArmErr = nil
	tap.DisarmErr = nil
	tap.DisarmResult = session.CaptureResult{
		Name: "capture.pcap", Bytes: 128, Packets: 4, Truncated: false,
		SignalingCiphertext: "not_requested",
		CaptureFidelity:     map[string]string{"udp": "byte_exact"},
	}
	art := fakes.NewArtifactStore()

	m, ts, ctx, uaHandle := newFixture(t, art, tap,
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return fakes.NewUserAgent(), nil })
	callHandle, _ := mustDial(t, m, ts, "s1", uaHandle, nil)

	startOut, err := ts.CaptureStart(ctx, "s1", session.CaptureStartInput{Call: callHandle})
	if err != nil {
		t.Fatalf("capture_start: %v", err)
	}
	sm, _ := startOut.(map[string]any)
	if sm["name"] != "capture.pcap" || sm["scope"] != "signaling" || sm["payload_mode"] != "plaintext" {
		t.Fatalf("capture_start shape = %#v, want name/scope/payload_mode per §10.11", sm)
	}
	if _, ok := sm["started_at_ms"].(int64); !ok {
		t.Fatalf("capture_start.started_at_ms = %#v (%T), want a numeric value", sm["started_at_ms"], sm["started_at_ms"])
	}

	stopOut, err := ts.CaptureStop(ctx, "s1", session.CaptureStopInput{Call: callHandle})
	if err != nil {
		t.Fatalf("capture_stop: %v", err)
	}
	stm, _ := stopOut.(map[string]any)
	if stm["signaling_ciphertext"] != "not_requested" {
		t.Errorf("signaling_ciphertext = %v, want not_requested", stm["signaling_ciphertext"])
	}
	if fid, ok := stm["capture_fidelity"].(map[string]string); !ok || fid["udp"] != "byte_exact" {
		t.Errorf("capture_fidelity = %#v, want {udp: byte_exact}", stm["capture_fidelity"])
	}
	wantURI := art.URI(callHandle, "capture.pcap")
	if stm["uri"] != wantURI {
		t.Errorf("uri = %v, want %v (the normative mcp://sipclient/artifacts/{call_handle}/{name} scheme, finding 2)", stm["uri"], wantURI)
	}
}

// TestCaptureStartRejectsMediaAndCiphertext is D9's not_supported gate: this
// wave captures signaling/plaintext only.
func TestCaptureStartRejectsMediaAndCiphertext(t *testing.T) {
	tap := fakes.NewTap()
	tap.ArmErr = nil
	art := fakes.NewArtifactStore()
	m, ts, ctx, uaHandle := newFixture(t, art, tap,
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return fakes.NewUserAgent(), nil })
	callHandle, _ := mustDial(t, m, ts, "s1", uaHandle, nil)

	if _, err := ts.CaptureStart(ctx, "s1", session.CaptureStartInput{Call: callHandle, Scope: "media"}); !isCode(err, apierr.CodeNotSupported) {
		t.Errorf("scope=media err = %v, want not_supported", err)
	}
	if _, err := ts.CaptureStart(ctx, "s1", session.CaptureStartInput{Call: callHandle, PayloadMode: "ciphertext"}); !isCode(err, apierr.CodeNotSupported) {
		t.Errorf("payload_mode=ciphertext err = %v, want not_supported", err)
	}
}

// TestCallDialArmsCaptureAtDialTime is D9b: call_dial(capture={...}) returns
// the accepted-intent flag AND wires a real ArmCapture at dialog bind, using
// a UA double that INVOKES OnDialogBound — the default fakes.UserAgent does
// not (see boundDialAgent's doc comment).
func TestCallDialArmsCaptureAtDialTime(t *testing.T) {
	const dialogID, callID = "dlg-dial-time", "callid-dial-time@lab.internal"
	tap := fakes.NewTap()
	tap.ArmErr = nil
	art := fakes.NewArtifactStore()
	agent := newBoundDialAgent(dialogID, callID)

	_, ts, ctx, uaHandle := newFixture(t, art, tap,
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return agent, nil })

	out, err := ts.CallDial(ctx, "s1", session.CallDialInput{
		UA: uaHandle, ToURI: "sip:bob@example.com",
		Capture: &session.CaptureInput{Scope: "signaling"},
	})
	if err != nil {
		t.Fatalf("call_dial: %v", err)
	}
	res, _ := out.(map[string]any)
	if res["capture_armed"] != true {
		t.Fatalf("capture_armed = %v, want true (accepted-intent, D9b)", res["capture_armed"])
	}

	deadline := time.Now().Add(2 * time.Second)
	var armed []fakes.ArmCall
	for time.Now().Before(deadline) {
		armed = tap.ArmedSnapshot()
		if len(armed) > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(armed) != 1 {
		t.Fatalf("Tap.ArmCapture calls = %d, want exactly 1", len(armed))
	}
	if armed[0].UAHandle != uaHandle || armed[0].CallID != callID {
		t.Fatalf("Armed = %+v, want ua=%s callID=%s", armed[0], uaHandle, callID)
	}
}

// TestTerminatedCaptureIsClosedPromptly is finding 1b: an armed capture is
// disarmed at the TERMINAL TRANSITION, not left open until registry
// eviction.
func TestTerminatedCaptureIsClosedPromptly(t *testing.T) {
	tap := fakes.NewTap()
	tap.ArmErr = nil
	tap.DisarmErr = nil
	art := fakes.NewArtifactStore()
	m, ts, ctx, uaHandle := newFixture(t, art, tap,
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return fakes.NewUserAgent(), nil })
	callHandle, c := mustDial(t, m, ts, "s1", uaHandle, nil)

	if _, err := ts.CaptureStart(ctx, "s1", session.CaptureStartInput{Call: callHandle}); err != nil {
		t.Fatalf("capture_start: %v", err)
	}
	if _, err := ts.CallHangup(ctx, "s1", session.CallHangupInput{Call: callHandle}); err != nil {
		t.Fatalf("call_hangup: %v", err)
	}
	// CallHangup's RecordTermination runs SYNCHRONOUSLY (deferred, fires
	// before CallHangup returns) on this same goroutine, so no polling is
	// needed here — unlike the dial-time tests, whose arm happens on
	// CallDial's own goroutine.
	if len(tap.DisarmCalls) != 1 || tap.DisarmCalls[0] != c.CallID() {
		t.Fatalf("DisarmCalls = %v, want exactly one call for %q — the terminal-close "+
			"hook must call DisarmCapture promptly, not wait for registry eviction",
			tap.DisarmCalls, c.CallID())
	}
}

// TestCaptureStartAlreadyArmedPreconditionFailed is D9's already-armed gate at
// the TOOL layer (B1b): a second capture_start on the same call fails
// precondition_failed. The dedup is the store's O_EXCL Create — the standard
// fakes.ArtifactStore does not emulate it, so this uses diskArtifactStore
// (real O_EXCL) so the second Create genuinely hits os.ErrExist.
func TestCaptureStartAlreadyArmedPreconditionFailed(t *testing.T) {
	store := newDiskArtifactStore(t.TempDir())
	tap := fakes.NewTap()
	tap.ArmErr = nil
	m, ts, ctx, uaHandle := newFixture(t, store, tap,
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return fakes.NewUserAgent(), nil })
	callHandle, _ := mustDial(t, m, ts, "s1", uaHandle, nil)

	if _, err := ts.CaptureStart(ctx, "s1", session.CaptureStartInput{Call: callHandle}); err != nil {
		t.Fatalf("first capture_start: %v", err)
	}
	_, err := ts.CaptureStart(ctx, "s1", session.CaptureStartInput{Call: callHandle})
	if !isCode(err, apierr.CodePreconditionFailed) {
		t.Fatalf("second capture_start err = %v, want precondition_failed (already armed, O_EXCL)", err)
	}
}

// TestCaptureStartSubHeaderMaxBytesInvalidArgument is D9's MaxBytes>0 && <24
// gate at the TOOL layer (B2b): a policy whose capture.max_bytes_per_call is a
// sub-24 value reaches the tool-layer check and fails invalid_argument BEFORE
// any file is created. Constructed via newFixtureWithPolicy so the tool-layer
// branch — not the engine or policy-load branch — is the one that fires.
func TestCaptureStartSubHeaderMaxBytesInvalidArgument(t *testing.T) {
	pol := policy.Defaults()
	pol.Capture.MaxBytesPerCall = 12 // 0 < 12 < 24: below the pcap global header size
	tap := fakes.NewTap()
	tap.ArmErr = nil
	art := fakes.NewArtifactStore()
	m, ts, ctx, uaHandle := newFixtureWithPolicy(t, art, tap,
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return fakes.NewUserAgent(), nil }, pol)
	callHandle, _ := mustDial(t, m, ts, "s1", uaHandle, nil)

	_, err := ts.CaptureStart(ctx, "s1", session.CaptureStartInput{Call: callHandle})
	if !isCode(err, apierr.CodeInvalidArgument) {
		t.Fatalf("capture_start with sub-24 max_bytes err = %v, want invalid_argument", err)
	}
}

// ---- finding NEW-2: no orphan capture.pcap ever survives -------------------

// TestRejectedCaptureLeavesNoOrphan drives BOTH orphan vectors over a REAL
// file-on-disk store (diskArtifactStore): a rejected arm — whether rejected
// by validation before Create, or by a failing ArmCapture after Create
// succeeds — must never leave an O_EXCL-orphaning capture.pcap that would
// block every retry.
func TestRejectedCaptureLeavesNoOrphan(t *testing.T) {
	store := newDiskArtifactStore(t.TempDir())
	tap := fakes.NewTap()
	tap.ArmErr = nil
	m, ts, ctx, uaHandle := newFixture(t, store, tap,
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return fakes.NewUserAgent(), nil })

	t.Run("validation rejection before Create", func(t *testing.T) {
		callHandle, _ := mustDial(t, m, ts, "s1", uaHandle, nil)
		if _, err := ts.CaptureStart(ctx, "s1", session.CaptureStartInput{Call: callHandle, Scope: "media"}); !isCode(err, apierr.CodeNotSupported) {
			t.Fatalf("scope=media err = %v, want not_supported", err)
		}
		if store.exists(callHandle, "capture.pcap") {
			t.Fatalf("capture.pcap exists after a rejected capture_start — validation must " +
				"run before Create (finding NEW-2)")
		}
		if _, err := ts.CaptureStart(ctx, "s1", session.CaptureStartInput{Call: callHandle, Scope: "signaling"}); err != nil {
			t.Fatalf("capture_start(signaling) after the rejection: %v, want success (no orphan)", err)
		}
	})

	t.Run("arm-failure rejection after Create", func(t *testing.T) {
		callHandle, _ := mustDial(t, m, ts, "s1", uaHandle, nil)
		tap.ArmErr = apierr.NotSupported("simulated arm failure")
		if _, err := ts.CaptureStart(ctx, "s1", session.CaptureStartInput{Call: callHandle, Scope: "signaling"}); err == nil {
			t.Fatal("capture_start with a failing ArmCapture returned a nil error, want the arm's error")
		}
		if store.exists(callHandle, "capture.pcap") {
			t.Fatalf("capture.pcap exists after a failed ArmCapture — Create must be rolled " +
				"back via Close+Remove (finding NEW-2 residual)")
		}
		tap.ArmErr = nil
		if _, err := ts.CaptureStart(ctx, "s1", session.CaptureStartInput{Call: callHandle, Scope: "signaling"}); err != nil {
			t.Fatalf("capture_start(signaling) retry after rollback: %v, want success "+
				"(no O_EXCL orphan blocks the retry)", err)
		}
	})
}

// TestDialTimeCaptureNoOrphanWhenBindNeverFires: OnDialogBound is OPTIONAL
// (finding NEW-2 residual). With the DEFAULT fakes.UserAgent, which never
// invokes it, no file is ever created — even though capture_armed:true is
// the accepted-intent response.
func TestDialTimeCaptureNoOrphanWhenBindNeverFires(t *testing.T) {
	store := newDiskArtifactStore(t.TempDir())
	tap := fakes.NewTap()
	tap.ArmErr = nil
	m, ts, ctx, uaHandle := newFixture(t, store, tap,
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return fakes.NewUserAgent(), nil })

	out, err := ts.CallDial(ctx, "s1", session.CallDialInput{
		UA: uaHandle, ToURI: "sip:bob@example.com",
		Capture: &session.CaptureInput{Scope: "signaling"},
	})
	if err != nil {
		t.Fatalf("call_dial: %v", err)
	}
	res, _ := out.(map[string]any)
	if res["capture_armed"] != true {
		t.Fatalf("capture_armed = %v, want true (accepted-intent, independent of whether the bind ever fires)", res["capture_armed"])
	}
	callHandle, _ := res["call_handle"].(string)
	c, err := m.ResolveCall(ctx, "s1", session.Handle(callHandle))
	if err != nil {
		t.Fatalf("ResolveCall: %v", err)
	}
	// The default fakes.UserAgent's Dial never invokes OnDialogBound, so if it
	// were EVER going to fire it would have to happen before Dial returns —
	// and Dial returning is exactly what unblocks the post-return second bind
	// (setDialogIdentity) that sets CallID here. Once CallID is observed, the
	// whole dial goroutine body up to that point has already run.
	deadline := time.Now().Add(2 * time.Second)
	for c.CallID() == "" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.CallID() == "" {
		t.Fatal("call_dial's goroutine never settled within the deadline")
	}
	if store.exists(callHandle, "capture.pcap") {
		t.Fatalf("capture.pcap exists though OnDialogBound never fired (default fakes.UserAgent) — " +
			"no file may be created off the dial-time path unless the bind actually happens")
	}
}

// TestDialTimeArmFailureRemovesFile: OnDialogBound DOES fire (boundDialAgent)
// and the store's Create succeeds, but ArmCapture fails — the file it
// created must be removed, not left as an orphan (finding NEW-2 residual).
func TestDialTimeArmFailureRemovesFile(t *testing.T) {
	const dialogID, callID = "dlg-armfail", "callid-armfail@lab.internal"
	store := newDiskArtifactStore(t.TempDir())
	tap := fakes.NewTap()
	tap.ArmErr = apierr.NotSupported("simulated dial-time arm failure")
	agent := newBoundDialAgent(dialogID, callID)

	m, ts, ctx, uaHandle := newFixture(t, store, tap,
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return agent, nil })

	out, err := ts.CallDial(ctx, "s1", session.CallDialInput{
		UA: uaHandle, ToURI: "sip:bob@example.com",
		Capture: &session.CaptureInput{Scope: "signaling"},
	})
	if err != nil {
		t.Fatalf("call_dial: %v", err)
	}
	res, _ := out.(map[string]any)
	callHandle, _ := res["call_handle"].(string)
	c, err := m.ResolveCall(ctx, "s1", session.Handle(callHandle))
	if err != nil {
		t.Fatalf("ResolveCall: %v", err)
	}
	// boundDialAgent invokes OnDialogBound SYNCHRONOUSLY inside Dial, before
	// Dial returns — so the whole Create-then-ArmCapture-then-rollback
	// sequence has already completed by the time Dial's return unblocks the
	// post-return second bind that sets CallID here.
	deadline := time.Now().Add(2 * time.Second)
	for c.CallID() == "" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.CallID() == "" {
		t.Fatal("call_dial's goroutine never settled within the deadline")
	}
	if store.exists(callHandle, "capture.pcap") {
		t.Fatalf("capture.pcap survives a failed dial-time ArmCapture — OnDialogBound must " +
			"Close+Remove on arm failure (finding NEW-2 residual), the same rollback CaptureStart uses")
	}
}

// TestDialTimeArmAfterTerminalDisarmsPromptly is the Cycle-2 2b race guard: a
// dial-time capture arm that fires AFTER the call already reached a terminal
// state must be disarmed IMMEDIATELY, not left armed-open (fd held) until
// registry Evict. RecordTermination's terminal-close DisarmCapture ran while
// the Call-ID was still empty (a no-op), so the late OnDialogBound bind is the
// last writer and must clean up after itself.
func TestDialTimeArmAfterTerminalDisarmsPromptly(t *testing.T) {
	const dialogID, callID = "dlg-race-2b", "callid-race-2b@lab.internal"
	tap := fakes.NewTap()
	tap.ArmErr = nil
	tap.DisarmErr = nil
	art := fakes.NewArtifactStore()
	agent := newDeferredBindAgent(dialogID, callID)
	t.Cleanup(func() { close(agent.release) })

	m, ts, ctx, uaHandle := newFixture(t, art, tap,
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return agent, nil })

	out, err := ts.CallDial(ctx, "s1", session.CallDialInput{
		UA: uaHandle, ToURI: "sip:bob@example.com",
		Capture: &session.CaptureInput{Scope: "signaling"},
	})
	if err != nil {
		t.Fatalf("call_dial: %v", err)
	}
	res, _ := out.(map[string]any)
	callHandle, _ := res["call_handle"].(string)
	c, err := m.ResolveCall(ctx, "s1", session.Handle(callHandle))
	if err != nil {
		t.Fatalf("ResolveCall: %v", err)
	}

	// Capture the dial-time bind callback WITHOUT letting it fire yet.
	var bind func(dialogID, callID string)
	select {
	case bind = <-agent.bound:
	case <-time.After(2 * time.Second):
		t.Fatal("dial goroutine never delivered OnDialogBound")
	}

	// Drive the call TERMINAL before the bind fires. RecordTermination's
	// terminal-close DisarmCapture runs synchronously here with an EMPTY
	// Call-ID (not yet set), so it cannot reach the capture the late bind is
	// about to arm.
	if _, err := ts.CallHangup(ctx, "s1", session.CallHangupInput{Call: callHandle}); err != nil {
		t.Fatalf("call_hangup: %v", err)
	}
	if got := c.State(); got != session.StateTerminated {
		t.Fatalf("call state = %q, want terminated before the late bind", got)
	}

	// NOW fire the late dial-time bind. It sets the Call-ID and arms a capture
	// on a call that is ALREADY terminal — the 2b window.
	bind(dialogID, callID)

	// The race guard must have disarmed the just-armed capture promptly, keyed
	// by the now-set Call-ID. Safe to read tap.DisarmCalls directly: the dial
	// goroutine is parked on release and bind() ran synchronously in this
	// goroutine, so there is no concurrent writer.
	found := false
	for _, cid := range tap.DisarmCalls {
		if cid == callID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("DisarmCalls = %v, want a DisarmCapture for %q after a dial-time arm on an "+
			"already-terminal call (Cycle-2 2b): the capture was left armed-open until registry Evict",
			tap.DisarmCalls, callID)
	}
}
