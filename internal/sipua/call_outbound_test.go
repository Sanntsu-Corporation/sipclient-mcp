package sipua_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// newDirectUA builds a direct-mode UA whose socket is decorated through Task
// 13's WrapConn seam, with a 2 s inbound ring timeout so the R14 timeout case
// is short to express against the fake clock. Direct mode knows no remote
// peer at ua_create, so sipua resolves the bind through §6.5.3 rule 4.
func newDirectUA(t *testing.T, clk *fakeclock.Clock) (*sipua.UA, *countingConn) {
	t.Helper()
	var cc *countingConn
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport:          "udp",
		Mode:               "direct",
		AOR:                "sip:alice@example",
		ExpiresS:           300,
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              clk,
		LocalAddr:          "127.0.0.1:0",
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			cc = &countingConn{PacketConn: pc}
			return cc
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	// C6/D137: sipua.Destroy is DELETED (a second teardown path per
	// session/destroy.go:20; session/destroy.go:destroyUA is the ONE
	// implementation). Test cleanup uses Close, transport teardown only.
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua, cc
}

// sipuaConfigMods carries the P2 W3 Task 8 media fields a test wants layered
// onto newDirectUA's base Config — codec preference and SRTP policy — plus
// Task 33's DTMFMode, so a DTMF acceptance test can select a UA's default
// signalling mode without a parallel sipua.New literal (Rule 16/18).
type sipuaConfigMods struct {
	Codecs   []string
	SRTP     string
	DTMFMode string
}

// newDirectUACfg mirrors newDirectUA but threads mods.Codecs/mods.SRTP into
// CodecPref/SRTP and sets a loopback media port range so bindMediaPort
// succeeds on 127.0.0.1 in-process.
func newDirectUACfg(t *testing.T, clk *fakeclock.Clock, mods sipuaConfigMods) (*sipua.UA, string) {
	t.Helper()
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport:          "udp",
		Mode:               "direct",
		AOR:                "sip:alice@example",
		ExpiresS:           300,
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              clk,
		LocalAddr:          "127.0.0.1:0",
		CodecPref:          mods.Codecs,
		SRTP:               mods.SRTP,
		DTMFMode:           mods.DTMFMode,
		MediaPortRange:     [2]int{16384, 32767},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua, ""
}

// newDirectUAWithCodecs builds a direct-mode UA whose CodecPref/SRTP are set
// per the caller, on a loopback media range so bindMediaPort succeeds.
func newDirectUAWithCodecs(t *testing.T, clk *fakeclock.Clock, codecs []string, srtp string) (*sipua.UA, string) {
	t.Helper()
	return newDirectUACfg(t, clk, sipuaConfigMods{Codecs: codecs, SRTP: srtp})
}

// asAPIErr is errors.As's thin alias for this test file's *apierr.Error
// assertions (Task 8).
func asAPIErr(err error, target **apierr.Error) bool { return errors.As(err, target) }

// contains2 is strings.Contains's thin alias, named to avoid colliding with
// any existing `contains` helper in this test package (Task 8).
func contains2(s, sub string) bool { return strings.Contains(s, sub) }

// collect installs BOTH upward channels session would wire: the one-way
// OnEvent callback, and — since I2 moved inbound admission to the synchronous
// OnAdmit channel — an OnAdmit handler that records the inbound event into the
// same buffer and ACCEPTS, so onInvite still rings and tests can waitFor a
// UAEventInbound exactly as before. ctx is the daemon context, as session would
// pass — never a request context.
func collect(t *testing.T, ua *sipua.UA) func() []session.UAEvent {
	t.Helper()
	var mu sync.Mutex
	var got []session.UAEvent
	record := func(ev session.UAEvent) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	}
	ua.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) {
		record(ev)
	})
	ua.OnAdmit(context.Background(), func(_ context.Context, ev session.UAEvent) session.Admission {
		if !ev.AdmitProbe { // an OPTIONS capacity probe is not an inbound call
			record(ev)
		}
		return session.AdmitAccept()
	})
	return func() []session.UAEvent {
		mu.Lock()
		defer mu.Unlock()
		out := make([]session.UAEvent, len(got))
		copy(out, got)
		return out
	}
}

// waitFor matches on PROTOCOL facts — a kind, and for provisional and final
// events a status code — because session.UAEvent carries no call state and no
// termination reason to match on. code == 0 means "any code".
func waitFor(t *testing.T, events func() []session.UAEvent, kind session.UAEventKind, code int) session.UAEvent {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range events() {
			if ev.Kind == kind && (code == 0 || ev.Code == code) {
				return ev
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no %q event with code %d within 3s; got %v", kind, code, kinds(events()))
	return session.UAEvent{}
}

func kinds(evs []session.UAEvent) []string {
	out := make([]string, len(evs))
	for i, ev := range evs {
		out[i] = fmt.Sprintf("%s/%d", ev.Kind, ev.Code)
	}
	return out
}

func TestDialReturnsImmediately(t *testing.T) {
	// The peer delays its final response by 400 ms: if Dial blocked on it, the
	// N2 budget assertion below would fail.
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{AnswerAfter: 400 * time.Millisecond}})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	start := time.Now()
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if res.DialogID == "" {
		t.Error("DialogID is empty")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Dial took %v, want < 500ms; dialling must be asynchronous", elapsed)
	}
	// Dial asserts NO call state — session.DialResult has no State field,
	// because CallState is session.Call's (Rule 18). "Returned before the call
	// resolved" is therefore asserted the honest way: no FINAL event has been
	// emitted yet, even though the peer will send one 400 ms from now.
	for _, ev := range events() {
		if ev.Kind == session.UAEventFinal {
			t.Errorf("Dial returned after a final response arrived (%d); dialling must be asynchronous", ev.Code)
		}
	}
	// And it does resolve, on the daemon context, after Dial has returned.
	waitFor(t, events, session.UAEventFinal, 200)
}

func TestDialRejectsAnEmptyDestination(t *testing.T) {
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "   "}); err == nil {
		t.Error("Dial with an empty to_uri succeeded; want invalid_argument")
	}
}

// TestDialRejectsIPv6ToURI pins D134/C7 on the Dial path, with the CORRECTED
// assertions (D146): the originally mandated "zero datagrams" and
// elapsed-time assertions are COULD-ONLY-PASS artifacts — sipgo fails at
// address-build before any write either way, so the datagram count is 0 and
// the elapsed time is microseconds whether or not the call.go:202 guard runs.
// The only assertion that discriminates the guard from its absence is (c):
// with the guard removed, tryParseURI falls through silently, BuildInvite
// still dispatches a bogus request, and the call fails as a transport_fault
// only after the FULL cfg.Timeout — so waiting cfg.Timeout and asserting zero
// events proves the guard fired synchronously instead.
func TestDialRejectsIPv6ToURI(t *testing.T) {
	// newDirectUA fixes cfg.Timeout at 2s; this test must wait that long (plus
	// margin) to give the slow, guard-absent path a chance to prove itself.
	const uaTimeout = 2 * time.Second

	cases := []string{
		"sip:[2001:db8::1]:5060",
		"sip:alice@[2001:db8::1]:5060",
	}
	for _, toURI := range cases {
		t.Run(toURI, func(t *testing.T) {
			ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
			events := collect(t, ua)

			res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: toURI})

			// (a) Dial returns a non-nil apierr.InvalidArgument.
			var apiErr *apierr.Error
			if !errors.As(err, &apiErr) || apiErr.Code != apierr.CodeInvalidArgument {
				t.Fatalf("Dial(%q) err = %v (%T), want *apierr.Error with code invalid_argument", toURI, err, err)
			}
			// (b) the returned DialogID is empty.
			if res.DialogID != "" {
				t.Errorf("Dial(%q) DialogID = %q, want empty", toURI, res.DialogID)
			}
			// (c) after cfg.Timeout has elapsed, no event of any kind was
			// emitted — the ONLY assertion discriminating the slow
			// transport_fault path from the fast invalid_argument one.
			time.Sleep(uaTimeout + 500*time.Millisecond)
			if got := events(); len(got) != 0 {
				t.Errorf("Dial(%q) emitted %d event(s) after cfg.Timeout elapsed, want 0: %v", toURI, len(got), kinds(got))
			}
		})
	}
}

// TestDialOutboundInviteCarriesPCMUBody pins the SDP synthesis wiring on the
// Dial side (D148): FixedPCMUSDP is unit-tested in isolation (sdp_test.go),
// but nothing previously asserted that Dial actually attaches its output to
// the outbound INVITE — deleting the synthesis call site left the package
// green.
func TestDialOutboundInviteCarriesPCMUBody(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	body := string(p.LastInviteBody())
	if !strings.Contains(body, "a=rtpmap:0 PCMU/8000") {
		t.Errorf("outbound INVITE body = %q, want it to carry the fixed PCMU rtpmap", body)
	}
}

// TestHangupHonoursCtxExpiry pins D152 (Hangup MUST honour ctx expiry, USER
// RULING): collaborators.go's UserAgent.Hangup contract requires ctx expiry
// to return ctx.Err() with the dialog abandoned. As shipped before this fix,
// call.go:645-649 swallowed every transaction error — including ctx
// expiry — and returned nil, which session/destroy.go could not distinguish
// from a clean hangup.
func TestHangupHonoursCtxExpiry(t *testing.T) {
	// SwallowBye: the peer receives the BYE but sends no response, so the
	// transaction genuinely waits on ctx rather than resolving instantly.
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{SwallowBye: true}})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	// newDirectUA's cfg.Timeout is 2s; this ctx expires well before that, so
	// the ctx — not sipua's own internal budget — is what ends the wait.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	hangErr := ua.Hangup(ctx, res.DialogID, "")
	if !errors.Is(hangErr, context.DeadlineExceeded) {
		t.Fatalf("Hangup(ctx expiring in 100ms) = %v, want context.DeadlineExceeded", hangErr)
	}
	if p.Count("BYE") != 1 {
		t.Errorf("peer saw %d BYEs, want 1 — the BYE was sent, it just was never answered", p.Count("BYE"))
	}
}

func TestOutboundProvisionalThenFinal(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{AnswerAfter: 100 * time.Millisecond}})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// sipua reports PROTOCOL FACTS. session.Call maps 180 -> "ringing" and the
	// 2xx -> "answered"; nothing here names a CallState (Rule 18).
	ringing := waitFor(t, events, session.UAEventProvisional, 180)
	if ringing.Direction != session.Outbound {
		t.Errorf("provisional Direction = %q, want %q", ringing.Direction, session.Outbound)
	}
	answered := waitFor(t, events, session.UAEventFinal, 200)
	if answered.Direction != session.Outbound {
		t.Errorf("final Direction = %q, want %q", answered.Direction, session.Outbound)
	}
	if answered.Reason == "" {
		t.Error("final event carries no reason phrase")
	}
	// Ordering: the provisional precedes the final.
	got := kinds(events())
	rIdx, aIdx := -1, -1
	for i, k := range got {
		if k == "provisional/180" && rIdx < 0 {
			rIdx = i
		}
		if k == "final/200" && aIdx < 0 {
			aIdx = i
		}
	}
	if rIdx < 0 || aIdx <= rIdx {
		t.Errorf("event order = %v; want the 180 before the 200", got)
	}
	// §15's R14 split: P1 asserts NO negotiated codec. OfferedCodecs is R14's
	// INCOMING_CALL detail and must not appear on an outbound final.
	if len(answered.OfferedCodecs) != 0 {
		t.Errorf("outbound final carries OfferedCodecs %v; P1 asserts no codec", answered.OfferedCodecs)
	}
	// UAEvent is protocol-level: it has no State, Phase or TerminationReason
	// fields at all, so there is nothing here for session's mapping to be
	// second-guessed by. That is asserted by internal/sipua/assert_test.go and
	// by this file compiling.
}

func TestOutboundSIPFailureIsASuccessfulOperation(t *testing.T) {
	cases := []struct {
		name   string
		status int
		reason string
	}{
		{"busy", 486, "Busy Here"},
		{"decline", 603, "Decline"},
		{"not found", 404, "Not Found"},
		{"server error", 500, "Server Internal Error"},
		{"moved", 302, "Moved Temporarily"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RejectStatus: tc.status}})
			ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
			events := collect(t, ua)

			// Dial itself must NOT error: the SIP failure is a RESULT (§11.1).
			res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
			if err != nil {
				t.Fatalf("Dial returned an error for a %d; a SIP failure response is a SUCCESSFUL tool call (§11.1): %v", tc.status, err)
			}
			// The failure surfaces as a FINAL RESPONSE — a protocol fact —
			// never as a transport fault and never as an error return. session
			// is what turns a non-2xx final into §10.3's "failed".
			ev := waitFor(t, events, session.UAEventFinal, tc.status)
			if ev.Reason != tc.reason {
				t.Errorf("result = {%d,%q}, want {%d,%q}", ev.Code, ev.Reason, tc.status, tc.reason)
			}
			if ev.Err != nil {
				t.Errorf("Err = %v on a SIP failure response; Err is for TRANSPORT faults only (§11.1)", ev.Err)
			}
			for _, other := range events() {
				if other.Kind == session.UAEventTransportFault {
					t.Errorf("a %d produced a transport_fault event; a SIP failure response is not a transport failure", tc.status)
				}
				if other.Kind == session.UAEventDialogEnded && other.Cause == session.UACauseTransportFailure && other.DialogID == res.DialogID {
					t.Errorf("a %d produced a transport_failure dialog end; a SIP failure response is not a transport failure", tc.status)
				}
			}
		})
	}
}

// The complementary case: NO response at all ends only that dialog, with a
// dialog-scoped end that carries Err (the only path that sets it) and no code.
// It is not the UA-wide transport fault (CF-037, D-A). Without this, the
// assertion above is only half a discrimination.
func TestDialTimeoutEmitsADialogScopedEndNotATransportFault(t *testing.T) {
	// A closed socket on a port nothing is listening on: the INVITE goes
	// nowhere and the transaction times out.
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := dead.LocalAddr().String()
	_ = dead.Close()

	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + addr})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	ev := waitForDialog(t, events, res.DialogID, session.UAEventDialogEnded, 0)
	assertDialogScopedEnd(t, ev, res.DialogID)
	time.Sleep(100 * time.Millisecond)
	n := 0
	for _, e := range events() {
		if e.Kind == session.UAEventTransportFault {
			t.Errorf("a dial timeout emitted the UA-wide transport_fault: %v", kinds(events()))
		}
		if e.DialogID == res.DialogID && e.Kind == session.UAEventDialogEnded {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d dialog-ended events for the dialog, want exactly 1", n)
	}
}

func TestHangupSendsExactlyOneBYE(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	if err := ua.Hangup(context.Background(), res.DialogID, "any free text at all"); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	if p.Count("BYE") != 1 {
		t.Errorf("peer saw %d BYEs, want 1", p.Count("BYE"))
	}
	// §6.3: the hangup is a ONE-TIME CLAIM. The second caller loses.
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err == nil {
		t.Error("second Hangup succeeded; want precondition_failed")
	}
	if p.Count("BYE") != 1 {
		t.Errorf("peer saw %d BYEs after a losing second hangup, want still 1", p.Count("BYE"))
	}
	// session records termination_reason "local_hangup" because IT called
	// Hangup; sipua emits no event and names no reason (Rule 18).
}

// §10.3: call_hangup's errors are not_found, gone and precondition_failed —
// and DELIBERATELY NO invalid_argument, because `reason` is free text and no
// value of it is rejected. These cases assert both halves.
func TestHangupErrorSetExcludesInvalidArgument(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	// No value of `reason` is rejected: empty, very long, and control-laden
	// all succeed on a live call.
	for _, reason := range []string{"", strings.Repeat("x", 8192), "line\r\nbreak; and \x00 nul"} {
		// Only the first will find the call answered; the rest assert that the
		// FAILURE is precondition_failed, never invalid_argument.
		err := ua.Hangup(context.Background(), res.DialogID, reason)
		if err == nil {
			continue
		}
		if strings.Contains(err.Error(), "invalid") {
			t.Errorf("Hangup(reason=%q) returned an invalid_argument-flavoured error; §10.3 says call_hangup has none: %v", reason, err)
		}
	}
	// not_found on an unknown handle, whatever the reason text.
	if err := ua.Hangup(context.Background(), "nope", strings.Repeat("y", 4096)); err == nil {
		t.Error("Hangup on an unknown handle succeeded; want not_found")
	}
}

// newDirectAuthUA is newDirectUA with digest credentials: only an
// authenticated UA drives the DoRequestWithDigest retry that advances a
// challenged INVITE's CSeq, which §14.5's stale-BYE-CSeq regression needs.
func newDirectAuthUA(t *testing.T, clk *fakeclock.Clock) *sipua.UA {
	t.Helper()
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport:          "udp",
		Mode:               "direct",
		AOR:                "sip:alice@example",
		AuthUser:           "alice",
		AuthPass:           "s3cr3t",
		AuthAnyHost:        true, // CF-046: the peer is on 127.0.0.1, not this AOR's host
		ExpiresS:           300,
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              clk,
		LocalAddr:          "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua
}

// TestHangupBYECSeqExceedsChallengedInviteCSeq pins §14.5's stale-BYE-CSeq
// fix. BuildByeFromInvite hardcodes the BYE at CSeq 2, valid only for an INVITE
// that went out at CSeq 1. A digest-challenged INVITE is retried at an ADVANCED
// CSeq (here the peer 401-challenges it, driving DoRequestWithDigest), so the
// answered INVITE lands well above 2; a BYE at 2 is then LOWER than the INVITE
// it ends — which RFC 3261 §12.2.1.1 forbids and Asterisk rejects 500 Invalid
// CSeq. Hangup must derive the BYE's CSeq from the INVITE actually answered so
// it stays strictly higher. The in-process peer does not itself enforce CSeq
// ordering (the live §14.5 rig against Asterisk is the authoritative proof);
// this test discriminates the fix on the wire-observed CSeq values alone.
func TestHangupBYECSeqExceedsChallengedInviteCSeq(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	ua := newDirectAuthUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// A 200 final proves the digest exchange completed and the INVITE's CSeq
	// advanced past the initial value.
	waitFor(t, events, session.UAEventFinal, 200)

	inviteCSeq := p.AnsweredInviteCSeq()
	if inviteCSeq < 3 {
		t.Fatalf("answered INVITE CSeq = %d, want >= 3 — the challenge must advance it past BuildByeFromInvite's hardcoded 2, or this test cannot discriminate the fix", inviteCSeq)
	}

	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	p.WaitForBye(t, 2*time.Second)

	// THE ASSERTION: the BYE's CSeq must exceed the INVITE it ends (RFC 3261
	// §12.2.1.1). Against the hardcoded BYE CSeq 2 this fails — the BYE lands
	// below the digest-advanced INVITE — which is precisely the 500 Invalid
	// CSeq Asterisk returns.
	if byeCSeq := p.LastByeCSeq(); byeCSeq <= inviteCSeq {
		t.Errorf("BYE CSeq = %d, answered INVITE CSeq = %d; a BYE ending the dialog must carry a strictly higher CSeq (RFC 3261 §12.2.1.1), else Asterisk rejects it 500 Invalid CSeq", byeCSeq, inviteCSeq)
	}
}
