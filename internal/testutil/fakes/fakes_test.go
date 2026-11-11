package fakes_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

// TestSessionsFakeAgesOnlyEmptyRecords is the ANTI-VACUOUS-GREEN control for
// the Sessions fake. P1d's §12.6 identity matrix and its
// TestResumeWindowOnlyAgesEmptySessions both rest on this behaviour; an Alive
// that always returned true would make every one of those cases pass,
// including the unknown-id ones, while asserting nothing. BOTH halves are
// therefore asserted here, and they are asymmetric by design.
func TestSessionsFakeAgesOnlyEmptyRecords(t *testing.T) {
	ctx := context.Background()
	const window = time.Hour
	epoch := time.Unix(1_700_000_000, 0)

	t.Run("an unknown id is never alive", func(t *testing.T) {
		s := fakes.NewSessions(fakeclock.New(epoch), window)
		if s.Alive("never-issued") {
			t.Error("Alive on an unissued id = true; §12.6 requires unknown ids to be unknown")
		}
	})

	t.Run("an EMPTY record ages out at the window", func(t *testing.T) {
		clk := fakeclock.New(epoch)
		s := fakes.NewSessions(clk, window)
		if err := s.Open(ctx, "s1"); err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !s.Alive("s1") {
			t.Fatal("a freshly opened record is not alive")
		}
		clk.Advance(window - time.Second)
		if !s.Alive("s1") {
			t.Error("an empty record aged out BEFORE the window elapsed")
		}
		clk.Advance(2 * time.Second)
		if s.Alive("s1") {
			t.Error("an empty record survived past session_resume_window")
		}
	})

	t.Run("a record owning a live object NEVER ages out", func(t *testing.T) {
		clk := fakeclock.New(epoch)
		s := fakes.NewSessions(clk, window)
		if err := s.Open(ctx, "s2"); err != nil {
			t.Fatalf("Open: %v", err)
		}
		s.AddLiveObject("s2")

		// D11 point 5: a live UA is never destroyed by the passage of time,
		// so its owning record has NO deadline at all.
		clk.Advance(72 * time.Hour)
		if !s.Alive("s2") {
			t.Fatal("a record owning a live object aged out; D11 point 5 gives it NO deadline")
		}

		// The window starts only when the LAST live object goes away.
		s.DropLiveObject("s2")
		if !s.Alive("s2") {
			t.Error("the record died the instant it emptied; the window must start now, not end now")
		}
		clk.Advance(window + time.Second)
		if s.Alive("s2") {
			t.Error("the emptied record never aged out")
		}
	})

	t.Run("Seen does not extend the window", func(t *testing.T) {
		clk := fakeclock.New(epoch)
		s := fakes.NewSessions(clk, window)
		if err := s.Open(ctx, "s3"); err != nil {
			t.Fatalf("Open: %v", err)
		}
		clk.Advance(window - time.Second)
		s.Seen("s3") // a bare poll must not resurrect an abandoned session
		clk.Advance(2 * time.Second)
		if s.Alive("s3") {
			t.Error("Seen extended the resume window; an abandoned session would live forever")
		}
	})
}

func TestUserAgentFakeRecordsAndEmits(t *testing.T) {
	ctx := context.Background()
	ua := fakes.NewUserAgent()

	var got []session.UAEvent
	ua.OnEvent(ctx, func(_ context.Context, ev session.UAEvent) {
		got = append(got, ev)
	})
	// Inbound admission is SYNCHRONOUS (I2): Emit routes a UAEventInbound to the
	// AdmitFunc, not the one-way OnEvent handler, so record it here and accept.
	ua.OnAdmit(ctx, func(_ context.Context, ev session.UAEvent) session.Admission {
		got = append(got, ev)
		return session.AdmitAccept()
	})

	if _, err := ua.Register(ctx); err != nil {
		t.Fatalf("Register: %v", err)
	}
	res, err := ua.Dial(ctx, session.DialRequest{ToURI: "sip:x@lab.internal"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if res.DialogID == "" {
		t.Error("Dial returned an empty DialogID")
	}
	// The OUTBOUND channel for the SIP Call-ID. (*Call).CallID() is the
	// Tap's ladder key and U7 keys every per-call Tap method by it, so an
	// empty value here would make call_ladder and Tap.Evict key on "".
	if res.CallID == "" {
		t.Error("Dial returned an empty CallID; session would have no ladder key (§2.5.4, U7)")
	}
	if err := ua.Hangup(ctx, res.DialogID, "local_hangup"); err != nil {
		t.Fatalf("Hangup: %v", err)
	}

	ua.Emit(session.UAEvent{
		Kind: session.UAEventInbound, DialogID: "d2", Direction: session.Inbound,
		OfferedCodecs: []string{"PCMU"},
	})

	// §3d: LocalAddr is the CONCRETE post-bind address, never a wildcard.
	//
	// LocalAddr() is declared net.Addr (U17), so the concreteness assertion
	// goes through a type assertion. This is DELIBERATELY NOT WEAKENED to
	// `addr != nil`: net.Addr's method set is String() and Network(), and a
	// string check would pass on "0.0.0.0:0". U17 widened the DECLARED type
	// for O1's sake; §3d's property is about the VALUE, and the value the
	// fake hands back is still a concrete *net.UDPAddr.
	addr := ua.LocalAddr()
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr() = %T (%v), want the fake's concrete *net.UDPAddr (§3d)", addr, addr)
	}
	if udp.Port == 0 || udp.IP == nil || udp.IP.IsUnspecified() {
		t.Errorf("LocalAddr() = %v, want a concrete non-wildcard IP:port (§3d)", udp)
	}

	if ua.RegisterCalls != 1 {
		t.Errorf("RegisterCalls = %d, want 1", ua.RegisterCalls)
	}
	if len(ua.Dials) != 1 || ua.Dials[0].ToURI != "sip:x@lab.internal" {
		t.Errorf("Dials = %+v", ua.Dials)
	}
	if len(ua.Hangups) != 1 || ua.Hangups[0].Reason != "local_hangup" {
		t.Errorf("Hangups = %+v", ua.Hangups)
	}
	if len(got) != 1 || got[0].Kind != session.UAEventInbound {
		t.Errorf("emitted events = %+v", got)
	}
	// UAEvent is PROTOCOL-LEVEL: it carries Direction and the codecs sipua
	// parsed out of the SDP, and it carries NO CallState and NO
	// termination_reason — that mapping is session's, in one place (Rule 18).
	if got[0].Direction != session.Inbound {
		t.Errorf("event Direction = %q, want %q", got[0].Direction, session.Inbound)
	}
	if len(got[0].OfferedCodecs) != 1 || got[0].OfferedCodecs[0] != "PCMU" {
		t.Errorf("OfferedCodecs = %v, want [PCMU]", got[0].OfferedCodecs)
	}
	// The INBOUND channel for the SIP Call-ID. An inbound call never returns
	// a DialResult, so this callback is session's ONLY way to learn the
	// Call-ID on R14's incoming_call path — amending DialResult alone would
	// have left this half of the wave broken.
	if got[0].CallID == "" {
		t.Error("inbound UAEvent carried an empty CallID; R14's incoming_call path has no ladder key")
	}
}

// TestUAEventKindsAndTheCauseInvariant pins U14's shape. Both halves rot
// silently otherwise: a sixth kind added without a test looks like five, and
// the "iff" is the sort of invariant that decays the first time someone
// attaches a Cause to a `final` event because it seemed informative.
func TestUAEventKindsAndTheCauseInvariant(t *testing.T) {
	ctx := context.Background()

	// All SIX kinds U14 leaves in place. `dialog_ended` is last because it is
	// the one that carries a Cause.
	kinds := []session.UAEventKind{
		session.UAEventInbound,
		session.UAEventProvisional,
		session.UAEventFinal,
		session.UAEventRefresh,
		session.UAEventTransportFault,
		session.UAEventDialogEnded,
	}
	if len(kinds) != 6 {
		t.Fatalf("enumerated %d kinds, want 6", len(kinds))
	}

	ua := fakes.NewUserAgent()
	var got []session.UAEvent
	ua.OnEvent(ctx, func(_ context.Context, ev session.UAEvent) {
		got = append(got, ev)
	})
	// Inbound admission is SYNCHRONOUS (I2): Emit routes a UAEventInbound to the
	// AdmitFunc, not the one-way OnEvent handler, so record it here and accept.
	ua.OnAdmit(ctx, func(_ context.Context, ev session.UAEvent) session.Admission {
		got = append(got, ev)
		return session.AdmitAccept()
	})

	// Every kind EXCEPT dialog_ended: Cause must stay empty.
	for _, k := range kinds[:len(kinds)-1] {
		ua.Emit(session.UAEvent{Kind: k, DialogID: "d1"})
	}
	// U14's two P1-reachable causes, through the fake's dedicated helper.
	ua.EmitDialogEnded("d1", session.UACausePeerBYE)
	ua.EmitDialogEnded("d2", session.UACauseRingTimeout)

	if len(got) != 7 {
		t.Fatalf("received %d events, want 7", len(got))
	}
	for _, ev := range got {
		switch ev.Kind {
		case session.UAEventDialogEnded:
			if ev.Cause == "" {
				t.Errorf("kind %q carried an empty Cause; U14 requires one", ev.Kind)
			}
		default:
			if ev.Cause != "" {
				t.Errorf("kind %q carried Cause %q; U14 sets Cause IF AND ONLY IF Kind is %q",
					ev.Kind, ev.Cause, session.UAEventDialogEnded)
			}
		}
	}

	// The two causes are DISTINCT values, and neither is a §10.3
	// termination_reason: `session` owns that mapping (Rule 18), and a fake
	// asserting the reason here would duplicate it.
	if session.UACausePeerBYE == session.UACauseRingTimeout {
		t.Error("the two P1 causes must be distinct")
	}
	if got[5].Cause != session.UACausePeerBYE || got[6].Cause != session.UACauseRingTimeout {
		t.Errorf("causes = %q, %q", got[5].Cause, got[6].Cause)
	}
}

func TestMediaSessionFakeRecordsAndEmits(t *testing.T) {
	ctx := context.Background()
	m := fakes.NewMediaSession()

	var digits []rune
	m.OnDTMF(ctx, func(_ context.Context, ev session.DTMFEvent) {
		digits = append(digits, ev.Digit)
	})

	if err := m.Start(ctx, session.MediaConfig{Codec: "PCMU", PayloadType: 0}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.SendDTMF(ctx, "123", session.DTMFModeRFC2833); err != nil {
		t.Fatalf("SendDTMF: %v", err)
	}
	m.EmitDTMF(session.DTMFEvent{Digit: '5'})
	if err := m.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if len(m.Starts) != 1 || m.Starts[0].Codec != "PCMU" {
		t.Errorf("Starts = %+v", m.Starts)
	}
	if len(m.DTMFSent) != 1 || m.DTMFSent[0].Digits != "123" {
		t.Errorf("DTMFSent = %+v", m.DTMFSent)
	}
	if len(digits) != 1 || digits[0] != '5' {
		t.Errorf("received digits = %q", string(digits))
	}
	if m.StopCalls != 1 {
		t.Errorf("StopCalls = %d, want 1", m.StopCalls)
	}
}

func TestTapFakeAccumulatesInOrder(t *testing.T) {
	ctx := context.Background()
	tap := fakes.NewTap()
	tap.LadderResult = session.Ladder{Format: session.LadderText, Rendered: "INVITE ->", Messages: 1}

	const callID = "a84b4c76e66710@lab.internal"

	// D9a: the ladder path is UNCONDITIONAL. Nothing is armed first, and
	// recording still happens.
	tap.SIPMessage(ctx, session.SIPRecord{
		Method: "INVITE", Direction: session.Outbound, CallID: callID,
		Serialized: "INVITE sip:x@lab.internal SIP/2.0", Fidelity: "byte_exact",
	})
	tap.SIPMessage(ctx, session.SIPRecord{
		StatusCode: 200, Reason: "OK", Direction: session.Inbound, CallID: callID,
		Serialized: "SIP/2.0 200 OK", Fidelity: "byte_exact",
	})

	recs := tap.SIPRecordsSnapshot()
	if len(recs) != 2 || recs[0].Method != "INVITE" || recs[1].StatusCode != 200 {
		t.Fatalf("SIP records = %+v", recs)
	}
	if recs[0].Direction != session.Outbound || recs[1].Direction != session.Inbound {
		t.Errorf("directions = %q, %q", recs[0].Direction, recs[1].Direction)
	}
	if recs[1].Reason != "OK" {
		t.Errorf("response Reason = %q, want OK", recs[1].Reason)
	}

	// U7: every per-call method is KEYED BY Call-ID.
	l, err := tap.Ladder(ctx, "", callID, session.LadderText)
	if err != nil {
		t.Fatalf("Ladder: %v", err)
	}
	if l.Rendered != "INVITE ->" {
		t.Errorf("Ladder = %+v", l)
	}
	if len(tap.LadderCalls) != 1 ||
		tap.LadderCalls[0].CallID != callID ||
		tap.LadderCalls[0].Format != session.LadderText {
		t.Errorf("LadderCalls = %+v", tap.LadderCalls)
	}

	// U18: Retain is the seventh method. P1b Task 8 calls it at dialog
	// establishment so the LRU may never evict a LIVE call's ladder — without
	// it the ordering is exactly backwards, because a P1 call writes nothing
	// to its ladder between the ACK and the BYE while keepalive OPTIONS
	// refresh their own recency continuously.
	tap.Retain(ctx, "", callID)
	if len(tap.Retained) != 1 || tap.Retained[0] != callID {
		t.Errorf("Retained = %v, want [%s]", tap.Retained, callID)
	}

	// U7: Evict lets Task 10's janitor free a terminated call's ring promptly,
	// ahead of LRU pressure (U15: it is not itself §N3's bound). U18: it is
	// ALSO the release for the Retain above, and the only one — so the pair
	// (Retain at establishment, Evict at termination) is what a caller's
	// retention test asserts on this fake.
	tap.Evict(ctx, "", callID)
	if len(tap.Evicted) != 1 || tap.Evicted[0] != callID {
		t.Errorf("Evicted = %v, want [%s]", tap.Evicted, callID)
	}
}

// TestTapFakeCaptureIsNotSupportedAtP1 pins D9b's half of U7. The fake
// defaults to apierr.NotSupported because that is what trace.Sink returns at
// P1 (Task 16): capture is OPT-IN and arrives at P2. A silent nil here would
// let a caller believe a capture was armed when nothing was recorded, which
// is the exact failure the not_supported choice exists to prevent.
// nopWriteCloser is a package-local no-op io.WriteCloser. fakes_test.go is
// package fakes_test (external), so it cannot reach the unexported
// nopWriteCloser in artifactstore.go (package fakes).
type nopWriteCloser struct{}

func (nopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriteCloser) Close() error                { return nil }

func TestTapFakeCaptureIsNotSupportedAtP1(t *testing.T) {
	ctx := context.Background()
	tap := fakes.NewTap()
	const uaHandle = "ua_1"
	const callID = "a84b4c76e66710@lab.internal"

	err := tap.ArmCapture(ctx, uaHandle, callID, nopWriteCloser{}, session.CaptureConfig{Scope: "signaling"})
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != apierr.CodeNotSupported {
		t.Errorf("ArmCapture err = %v, want an *apierr.Error with code %q", err, apierr.CodeNotSupported)
	}
	if len(tap.Armed) != 1 || tap.Armed[0].CallID != callID {
		t.Errorf("Armed = %+v, want the call id recorded", tap.Armed)
	}

	_, err = tap.DisarmCapture(ctx, uaHandle, callID)
	if !errors.As(err, &ae) || ae.Code != apierr.CodeNotSupported {
		t.Errorf("DisarmCapture err = %v, want an *apierr.Error with code %q", err, apierr.CodeNotSupported)
	}
	if len(tap.DisarmCalls) != 1 || tap.DisarmCalls[0] != callID {
		t.Errorf("DisarmCalls = %v, want [%s]", tap.DisarmCalls, callID)
	}
}

func TestArtifactStoreFakeRoundTrips(t *testing.T) {
	ctx := context.Background()
	st := fakes.NewArtifactStore()

	if err := st.OpenCallDir(ctx, "call_91c4"); err != nil {
		t.Fatalf("OpenCallDir: %v", err)
	}
	w, err := st.Create(ctx, "call_91c4", "capture.pcap")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write([]byte("pcapbytes")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close writer: %v", err)
	}

	info, err := st.Close(ctx, "call_91c4", "capture.pcap")
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	want := "mcp://sipclient/artifacts/call_91c4/capture.pcap"
	if info.URI != want {
		t.Errorf("URI = %q, want %q", info.URI, want)
	}
	if info.Bytes != 9 {
		t.Errorf("Bytes = %d, want 9", info.Bytes)
	}

	// Resolution is registry-independent: a URI alone is enough.
	got, rc, err := st.Resolve(ctx, want)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	defer func() { _ = rc.Close() }()
	if got.Name != "capture.pcap" {
		t.Errorf("resolved name = %q", got.Name)
	}
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(b) != "pcapbytes" {
		t.Errorf("content = %q", b)
	}
}

// TestUnscriptedUserAgentHooksAllReportFailure is the regression test for
// F/I5: SendDTMF's nil hook returned (0, 0, nil) — SILENT SUCCESS — while its
// two siblings reported ok=false. A caller that reached the fake's SendDTMF
// without scripting it saw "sent 0 digits, no fault", which is a real,
// legitimate UA answer, so no test could ever notice the call happened by
// accident.
func TestUnscriptedUserAgentHooksAllReportFailure(t *testing.T) {
	u := fakes.NewUserAgent()

	if _, _, err := u.SendDTMF(context.Background(), "d", "123", session.DTMFModeRFC2833, 100, 50); err == nil {
		t.Fatal("unscripted SendDTMF returned a nil error — silent success is exactly what a " +
			"double must never report for a call it was never told how to handle")
	}
	if _, ok := u.DTMFMode("d"); ok {
		t.Fatal("unscripted DTMFMode reported ok=true")
	}
	if _, ok := u.SessionTimerView("d"); ok {
		t.Fatal("unscripted SessionTimerView reported ok=true")
	}
}
