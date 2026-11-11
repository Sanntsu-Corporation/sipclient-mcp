package sipua_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// newKeepaliveUA builds a register-mode UA with the given Keepalive mode and
// interval, mirroring newRegisterUAExpires (register_test.go:31).
func newKeepaliveUA(t *testing.T, p *peer.Peer, clk *fakeclock.Clock, mode string, intervalS int) *sipua.UA {
	t.Helper()
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport:          "udp",
		Mode:               "register",
		AOR:                "sip:alice@example",
		Registrar:          "sip:" + p.Addr(),
		AuthUser:           "alice",
		AuthPass:           "s3cr3t",
		Keepalive:          mode,
		KeepaliveIntervalS: intervalS,
		Timeout:            2 * time.Second,
		Clock:              clk,
		LocalAddr:          "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua
}

func TestKeepaliveNoneSendsNothing(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newKeepaliveUA(t, p, clk, "none", 30)

	// keepalive="none" must arm NOTHING. Asserting only that the wire stays
	// quiet (below) is not enough on its own — deleting the "none" gate in
	// sendKeepalive still passes that check, because the default: arm error
	// is swallowed by startKeepalive's Do closure (mutation-proven in this
	// task's report).
	if ua.KeepaliveArmed() {
		t.Fatal(`keepalive="none" armed a refresher; it must arm nothing`)
	}

	clk.Advance(5 * time.Minute)
	time.Sleep(50 * time.Millisecond)
	if n := p.Count("OPTIONS"); n != 0 {
		t.Fatalf("%d OPTIONS sent with keepalive=none", n)
	}
	if n := p.CRLFKeepalives(); n != 0 {
		t.Fatalf("%d CRLF keepalives sent with keepalive=none", n)
	}
}

// TestSipuaKeepaliveModesAgreeWithPolicyValidKeepaliveMode pins the
// CROSS-PACKAGE fact that internal/sipua's implemented keepalive set and
// policy.ValidKeepaliveMode's accepted set agree, mode for mode.
//
// THIS TEST USED TO BE NAMED TestKeepaliveArmsExactlyTheModesSendKeepaliveImplements
// AND ALSO PINNED A SECOND, IN-PACKAGE PROPERTY: that startKeepalive's arming
// gate agreed with sendKeepalive's dispatch switch — two hand-written
// switches that could drift apart. Phase 4 W1 M3's Cycle 5 fix collapsed both
// into ONE function, keepaliveSender, so that particular drift is no longer
// constructible and the assertion that used to catch it (comparing
// ua.KeepaliveArmed() against a hardcoded wantArmed table, once here) went
// tautological — it could only fail if this table itself disagreed with
// keepaliveSender, which the wire-silence check below and the OTHER keepalive
// tests (TestKeepaliveCRLFWritesADoubleCRLFAtTheInterval,
// TestKeepaliveOptionsSendsOutOfDialogOPTIONS) already prove one way (armed
// modes send real traffic) and the wire-silence rows below prove the other
// (unarmed modes send nothing). It was retired rather than left in place
// quietly not testing anything (§9's "50 tests that could not fail" pattern).
//
// WHAT SURVIVES is the cross-package half: this package's TEST binary already
// imports policy (sessiontimer_test.go), and no importguard row forbids it —
// sipua itself has no production edge to policy (the SIP stack stays off the
// YAML schema), so the coupling is stated here, where it can fail loudly,
// rather than hidden behind an import. "" and "none" still matter as their
// own case: both are valid policy values and both MEAN "do not arm", which is
// a different thing from "not implemented" and keepaliveSender must keep them
// distinguishable (see startKeepalive's own early return for them).
func TestSipuaKeepaliveModesAgreeWithPolicyValidKeepaliveMode(t *testing.T) {
	cases := []struct {
		mode      string
		wantArmed bool
	}{
		{"crlf", true},
		{"options", true},
		{"none", false},
		{"", false},
		{"crfl", false}, // the transposition typo
		{"CRLF", false}, // the set is exact; policy validates lowercase only
		{"tcp-keep", false},
	}
	for _, tc := range cases {
		name := tc.mode
		if name == "" {
			name = "unset"
		}
		t.Run(name, func(t *testing.T) {
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
			clk := fakeclock.New(time.Unix(0, 0))
			// newKeepaliveUA registers its own t.Cleanup; the handle itself is
			// unused below now (see the retirement comment).
			newKeepaliveUA(t, p, clk, tc.mode, 30)

			// The ua.KeepaliveArmed() == tc.wantArmed check that used to live
			// here retired itself (Cycle 5, see the doc comment above):
			// startKeepalive's arm gate and sendKeepalive's dispatch now BOTH
			// resolve through keepaliveSender(mode), so an arm-gate/
			// dispatch-switch divergence is no longer constructible, and
			// re-asserting it here would only check that this table agrees
			// with itself. tc.wantArmed lives on below, as the input to the
			// policy comparison and the wire-silence check, which is the real
			// remaining guard.

			// The cross-package side, as two implications over the same rows. "" and
			// "none" are the exception on the accept side: both are valid policy
			// values and both MEAN "do not arm", so accepting them while arming
			// nothing is correct rather than drift.
			off := tc.mode == "" || tc.mode == "none"
			switch {
			case policy.ValidKeepaliveMode(tc.mode) && !off && !tc.wantArmed:
				t.Fatalf("policy.ValidKeepaliveMode(%q) accepts a mode startKeepalive refuses "+
					"to arm — an operator's policy.yaml loads clean, ua_status reports the "+
					"mode as configured, and the UA then sends nothing, forever", tc.mode)
			case !policy.ValidKeepaliveMode(tc.mode) && tc.wantArmed:
				t.Fatalf("policy.ValidKeepaliveMode(%q) rejects a mode sipua implements and "+
					"arms — the operator cannot configure a mode that works", tc.mode)
			}

			if tc.wantArmed {
				return
			}
			// Ten intervals of fake time. An armed-but-unimplemented mode puts
			// nothing on the wire either, so this is not what distinguishes the
			// two — it is what proves the refusal did not merely move the silence.
			clk.Advance(5 * time.Minute)
			time.Sleep(50 * time.Millisecond)
			if n := p.Count("OPTIONS"); n != 0 {
				t.Fatalf("keepalive=%q sent %d OPTIONS", tc.mode, n)
			}
			if n := p.CRLFKeepalives(); n != 0 {
				t.Fatalf("keepalive=%q sent %d CRLF keepalives", tc.mode, n)
			}
		})
	}
}

func TestKeepaliveCRLFWritesADoubleCRLFAtTheInterval(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	clk := fakeclock.New(time.Unix(0, 0))
	// 45, NOT 30. Every other keepalive fixture in this file passes 30, which is
	// exactly keepaliveIntervalS()'s own default — so replacing that accessor's
	// body with a bare `return 30`, ignoring Config.KeepaliveIntervalS
	// altogether, left the whole internal/sipua package green. The
	// config -> timer path had no unit coverage at all: the only non-default
	// interval in the tree is internal/session's threading test, which asserts
	// the field is COPIED and never that it reaches a timer.
	ua := newKeepaliveUA(t, p, clk, "crlf", 45)
	defer func() { _ = ua.Close(context.Background()) }()

	clk.BlockUntil(1)
	// THE FLOOR, which no keepalive test asserted: advance to just SHORT of the
	// interval and confirm nothing has fired yet. Without it the interval is
	// pinned from above only — every wait below is `>= n`, and fakeclock.Advance
	// fires any waiter it crosses, so a keepalive rearming every second
	// satisfies them exactly as well as one rearming every forty-five. Replacing
	// `Initial: keepaliveIntervalS() * time.Second` with `Initial: time.Second`
	// left the whole package green. The policy sets no jitter, so 44s is an
	// exact, non-flaky boundary. This is the only test pinning either line;
	// TestKeepaliveOptionsSendsOutOfDialogOPTIONS shares them.
	clk.Advance(44 * time.Second)
	time.Sleep(50 * time.Millisecond) // a wrongly-early send needs a moment to land
	if n := p.CRLFKeepalives(); n != 0 {
		t.Fatalf("%d CRLF keepalives at 44 fake seconds, want 0 — a 45s keepalive must not "+
			"fire early, and must not silently run at the 30s default", n)
	}
	clk.Advance(2 * time.Second)
	waitForCond(t, func() bool { return p.CRLFKeepalives() >= 1 })
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	waitForCond(t, func() bool { return p.CRLFKeepalives() >= 2 })
}

func TestKeepaliveOptionsSendsOutOfDialogOPTIONS(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newKeepaliveUA(t, p, clk, "options", 30)
	defer func() { _ = ua.Close(context.Background()) }()

	clk.BlockUntil(1)
	clk.Advance(31 * time.Second)
	waitForCond(t, func() bool { return p.Count("OPTIONS") >= 1 })

	// Out-of-dialog: no To-tag on the request. This alone is NOT sufficient
	// evidence sipua ever sets a To at all — sipgo's clientRequestBuildReq
	// synthesises a tagless To of its own when the request carries none
	// (third_party/sipgo/client.go:292-304), so a tag-only check passes even
	// under a mutation that deletes req.AppendHeader(to) entirely
	// (mutation-proven in this task's report). The port distinguishes the
	// two: sipgo's synthesised copy drops the registrar's port.
	to := p.LastRequestHeader("OPTIONS", "To")
	if strings.Contains(to, "tag=") {
		t.Fatalf("OPTIONS To=%q must carry no tag (out of dialog)", to)
	}
	if want := "sip:" + p.Addr(); !strings.Contains(to, want) {
		t.Fatalf("OPTIONS To=%q must address the registrar %q", to, want)
	}
	if got := p.LastRequestHeader("OPTIONS", "From"); !strings.Contains(got, "sip:alice@example") {
		t.Fatalf("OPTIONS From=%q must carry the UA's AOR identity", got)
	}
}

// TestKeepaliveKeepsFiringDuringAnActiveCall is the keepalive's COMMON
// PRODUCTION CASE, and until this test it had zero coverage: every keepalive
// test above runs on a UA with no call at all, and every call test runs on a UA
// with no keepalive. Both layers were covered on their own terms; the seam
// between them was not, and a NAT keepalive exists precisely to hold the
// pinhole open across a long call — the state where its absence costs an
// operator inbound calls.
//
// THREE THINGS ARE ASSERTED, AND EACH IS A DIFFERENT FAILURE:
//
//   - the keepalive keeps firing WHILE the call is up, across MORE THAN ONE
//     interval. One tick is not enough: a keepalive that fires once and then
//     stops — its refresher wedged behind a lock the call path holds, or its
//     attempt context cancelled by something in the dial — passes a single-tick
//     check and still lets the pinhole lapse. The counts are taken as deltas
//     from an explicit `before`, so a stray pre-call tick cannot satisfy them.
//   - the keepalive stays OUT OF DIALOG. sendOPTIONSKeepalive builds its own
//     From/To and lets sipgo mint the Call-ID, so an OPTIONS that adopted the
//     live dialog's Call-ID or carried a To-tag would be read by the far end as
//     an in-dialog request on the call — and an in-dialog request the peer
//     cannot match draws a 481, which RFC 3261 §12.2.1.2 makes terminal.
//   - the CALL is untouched: no BYE, no dialog_ended, and — the assertion that
//     actually proves the dialog survived INTACT rather than merely appearing
//     to — it is still hangup-able afterwards, which exercises its phase and
//     its CSeq space through buildInDialogRequest.
//
// BOTH MODES RUN. crlf is not a redundant copy of options: it writes four raw
// bytes onto the SAME signalling socket the dialog's own requests travel on
// (sendCRLFKeepalive, u.conn.WriteTo), where options goes through a normal
// client transaction. A far end whose parser mis-frames the double-CRLF, or a
// write that raced the dialog's, would break the call in the crlf mode only.
func TestKeepaliveKeepsFiringDuringAnActiveCall(t *testing.T) {
	for _, mode := range []string{"options", "crlf"} {
		t.Run(mode, func(t *testing.T) {
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
			clk := fakeclock.New(time.Unix(0, 0))
			ua := newKeepaliveUA(t, p, clk, mode, 30)
			events := collect(t, ua)

			res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			waitFor(t, events, session.UAEventFinal, 200)

			sent := func() int {
				if mode == "crlf" {
					return p.CRLFKeepalives()
				}
				return p.Count("OPTIONS")
			}
			before := sent()

			// No session timer is negotiated on this dialog (the peer sends no
			// Session-Expires and the UA advertises none), so the keepalive is
			// the ONE fake-clock waiter and BlockUntil(1) — an exact-count wait
			// — is correct.
			for tick := 1; tick <= 2; tick++ {
				clk.BlockUntil(1)
				clk.Advance(31 * time.Second)
				want := before + tick
				waitForCond(t, func() bool { return sent() >= want })
			}

			if mode == "options" {
				// The live dialog's Call-ID, read off the INVITE the peer
				// actually received.
				dialogCallIDs := p.CallIDs("INVITE")
				if len(dialogCallIDs) == 0 {
					t.Fatal("the peer recorded no INVITE Call-ID to compare the keepalive against")
				}
				if got := p.LastRequestHeader("OPTIONS", "Call-ID"); got == dialogCallIDs[0] {
					t.Fatalf("the keepalive OPTIONS carries the live call's Call-ID %q — a keepalive "+
						"is an OUT-OF-DIALOG request and must never ride the dialog", got)
				}
				if got := p.LastRequestHeader("OPTIONS", "To"); strings.Contains(got, "tag=") {
					t.Fatalf("keepalive OPTIONS To=%q carries a tag during an active call", got)
				}
			}

			// The call is untouched by two intervals of keepalive.
			if n := p.ByeCount(); n != 0 {
				t.Fatalf("the peer received %d BYEs during a keepalive; the call must be unaffected", n)
			}
			if n := countKind(events(), session.UAEventDialogEnded); n != 0 {
				t.Fatalf("dialog_ended fired %d times during a keepalive, want 0: got %v",
					n, kinds(events()))
			}
			// STILL INTACT, not merely still listed: the hangup goes through
			// buildInDialogRequest, so a dialog whose phase or CSeq space the
			// keepalive had disturbed fails here rather than passing silently.
			if err := ua.Hangup(context.Background(), res.DialogID, "done"); err != nil {
				t.Fatalf("Hangup after two keepalive intervals: %v — the call did not survive them", err)
			}
			p.WaitForBye(t, 5*time.Second)
		})
	}
}

func TestKeepaliveFailureDoesNotTerminateAnything(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newKeepaliveUA(t, p, clk, "options", 30)
	events := collect(t, ua)

	// REGISTER FIRST. Without a live registration "does not terminate
	// anything" asserts nothing: a keepalive that marked the UA unregistered
	// would still pass (mutation-proven in this task's report: injecting
	// u.reg.registered = false into the keepalive failure path left the
	// brief's original test passing).
	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !ua.Registered() {
		t.Fatal("precondition: UA must be registered before the keepalive fails")
	}

	p.Stop() // the registrar vanishes

	// TWO waiters, not one: Register armed the R10 registration refresher
	// alongside the keepalive. BlockUntil is an EXACT-count wait, so
	// BlockUntil(1) here would block forever.
	clk.BlockUntil(2)
	clk.Advance(31 * time.Second)
	// Longer than Config.Timeout (2s), so the failed OPTIONS has actually
	// completed and any escalation it would perform has happened.
	time.Sleep(2500 * time.Millisecond)

	if !ua.Registered() {
		t.Fatal("a failed keepalive marked the UA UNREGISTERED; spec §2.4's keepalive row is log-only")
	}
	for _, ev := range events() {
		// UAEventTransportFault is UA-WIDE and its handler terminates every
		// live call; UAEventRegisterFailed marks the UA unregistered on
		// evidence a keepalive cannot provide.
		if ev.Kind == session.UAEventTransportFault || ev.Kind == session.UAEventRegisterFailed {
			t.Fatalf("a failed keepalive must log and continue; it emitted %q", ev.Kind)
		}
	}
}

// closePromptBudget is what "promptly" means for the two shutdown tests below.
// With stopRefresher cancelling the attempt context first, Close returns in
// milliseconds; the budget is padded for the documented 4-CPU sandbox and still
// sits an order of magnitude under the ~30s these tests measure without the fix.
const closePromptBudget = 5 * time.Second

// TestKeepaliveCloseReturnsPromptlyWithAnInFlightKeepalive: UA.Close calls
// stopRefreshers, and refresher.Stop blocks until the in-flight Do returns, so
// an unanswered keepalive OPTIONS against a dead registrar must not hold
// ua_destroy / daemon shutdown open for the length of the SIP transaction.
//
// THIS TEST RUNS AT PRODUCTION DEFAULTS, AND THAT IS THE POINT. Its previous
// form set KeepaliveIntervalS: 1 with Timeout: 6s to show that
// keepaliveSendTimeout's min(interval, Timeout) bounded the send — but
// policy.Validate floors keepalive_interval_s at 5 (policy.go), so it measured a
// configuration no deployment can reach, and at the reachable default (interval
// 30, Timeout 32) that min() is 30 SECONDS. The test passed; Close still hung
// for ~30s in production. Both values below are therefore the defaults an
// operator actually gets: KeepaliveIntervalS 30 (ua.go's keepaliveIntervalS)
// and Timeout unset, which sipua.New normalises to RFC 3261's 32s Timer B/F.
func TestKeepaliveCloseReturnsPromptlyWithAnInFlightKeepalive(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	registrar := p.Addr()
	p.Stop() // the registrar vanishes; nothing will ever answer the OPTIONS

	clk := fakeclock.New(time.Unix(0, 0))
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp",
		Mode:      "register",
		AOR:       "sip:alice@example",
		Registrar: "sip:" + registrar,
		AuthUser:  "alice",
		AuthPass:  "s3cr3t",
		Keepalive: "options",
		// Production defaults, spelled out rather than left to the accessors so
		// the numbers this test depends on are visible here. Real wall-clock
		// durations — fakeclock governs only the refresher's own scheduling, not
		// the SIP transaction's context.WithTimeout deadline.
		KeepaliveIntervalS: 30,
		Clock:              clk,
		LocalAddr:          "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}

	clk.BlockUntil(1)
	clk.Advance(31 * time.Second)
	// Give the refresher's goroutine time to actually enter sendOPTIONSKeepalive
	// before Close races it.
	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	if err := ua.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > closePromptBudget {
		t.Fatalf("Close took %s with an in-flight keepalive OPTIONS; stopRefreshers "+
			"must cancel the attempt context rather than wait out the %s send timeout",
			elapsed, 30*time.Second)
	}
}

// TestCloseReturnsPromptlyWithAnInFlightRegisterRefresh is the mirror of the
// test above for the OTHER UA-owned refresher. refreshRegister has no bound of
// its own at all: DoRequestWithDigest uses config.Config.Timeout (32s at the
// default), and refresher.Stop waits out every second of it.
//
// It matters more than the keepalive case, not less: Unregister calls
// stopRefreshers BEFORE it sends its own Expires: 0 REGISTER, and
// Manager.UnregisterAllUAs iterates UAs serially, so this cost is paid once per
// registered UA on every daemon shutdown against an unreachable registrar.
func TestCloseReturnsPromptlyWithAnInFlightRegisterRefresh(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp",
		Mode:      "register",
		AOR:       "sip:alice@example",
		Registrar: "sip:" + p.Addr(),
		AuthUser:  "alice",
		AuthPass:  "s3cr3t",
		ExpiresS:  60,
		// Timeout unset, as in production: sipua.New normalises it to 32s, which
		// is what DoRequestWithDigest spends on a refresh nothing answers.
		Clock:     clk,
		LocalAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !ua.Registered() {
		t.Fatal("precondition: the UA must be registered so a refresher is armed")
	}

	p.Stop() // the registrar vanishes; the refresh REGISTER draws no answer

	// Granted 60 => the refresh fires at 0.85*60 = 51s +/-5%; 55s is past the
	// whole jitter band. One waiter: no keepalive is configured on this UA.
	clk.BlockUntil(1)
	clk.Advance(55 * time.Second)
	// Let the refresher's goroutine actually enter DoRequestWithDigest before
	// Close races it.
	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	if err := ua.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > closePromptBudget {
		t.Fatalf("Close took %s with an in-flight REGISTER refresh; stopRefreshers "+
			"must cancel the attempt context rather than wait out Config.Timeout", elapsed)
	}
}

// TestKeepaliveCRLFAnswersAnInboundPingWithAPong is D22's acceptance
// criterion: RFC 5626 §3.5.1's keep-alive is bidirectional, and this UA used
// to count an inbound double-CRLF ping (sipgo's own transport layer already
// treats it as a no-op, see readyConn.ReadFrom's doc comment) without ever
// answering it. The read path now answers with a single CRLF, regardless of
// which keepalive mode (if any) THIS UA itself sends with — it is a property
// of the UDP read path, not of startKeepalive — so "none" is deliberately
// used here to keep the two concerns separate.
func TestKeepaliveCRLFAnswersAnInboundPingWithAPong(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newKeepaliveUA(t, p, clk, "none", 30)
	defer func() { _ = ua.Close(context.Background()) }()

	p.SendCRLFPing(t, ua.BoundAddr().String())
	waitForCond(t, func() bool { return p.PongCount() >= 1 })
}

// TestUnregisterLeavesTheKeepaliveArmedForANextRegister is D20 D-M1's
// acceptance criterion: Unregister used to call the undifferentiated
// stopRefreshers, which nils BOTH the register refresher and the NAT
// keepalive — so a Register() after an Unregister() re-armed the register
// refresher but left the keepalive silently dead until the next full UA
// restart. stopRegisterRefresher (register.go) fixes this by construction:
// Unregister now stops only the register refresher.
func TestUnregisterLeavesTheKeepaliveArmedForANextRegister(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newKeepaliveUA(t, p, clk, "options", 30)
	defer func() { _ = ua.Close(context.Background()) }()

	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !ua.KeepaliveArmed() {
		t.Fatal("precondition: the keepalive must be armed after Register")
	}

	if err := ua.Unregister(context.Background()); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if !ua.KeepaliveArmed() {
		t.Fatal("Unregister disarmed the NAT keepalive; it must stop only the register " +
			"refresher (D20 D-M1)")
	}

	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("re-Register: %v", err)
	}
	if !ua.KeepaliveArmed() {
		t.Fatal("keepalive not armed after re-Register")
	}
}
