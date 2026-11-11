package sipua

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	sippeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

func TestParseSessionExpires(t *testing.T) {
	cases := []struct {
		in        string
		intervalS int
		refresher string
		ok        bool
	}{
		{"1800", 1800, "", true},
		{"1800;refresher=uac", 1800, "uac", true},
		{" 90 ; refresher=uas ", 90, "uas", true},
		{"1800;refresher=UAS", 1800, "uas", true},
		{"1800;other=x;refresher=uac", 1800, "uac", true},
		{"", 0, "", false},
		{"abc", 0, "", false},
		{"0", 0, "", false},
		{"-5", 0, "", false},
	}
	for _, tc := range cases {
		got, ok := parseSessionExpires(tc.in)
		if ok != tc.ok {
			t.Fatalf("parseSessionExpires(%q) ok=%v want %v", tc.in, ok, tc.ok)
		}
		if !ok {
			continue
		}
		if got.IntervalS != tc.intervalS || got.Refresher != tc.refresher {
			t.Fatalf("parseSessionExpires(%q) = %+v want %d/%q", tc.in, got, tc.intervalS, tc.refresher)
		}
	}
}

func TestFormatSessionExpires(t *testing.T) {
	if got := formatSessionExpires(sessionExpires{IntervalS: 1800, Refresher: "uac"}); got != "1800;refresher=uac" {
		t.Fatalf("got %q", got)
	}
	if got := formatSessionExpires(sessionExpires{IntervalS: 90}); got != "90" {
		t.Fatalf("got %q", got)
	}
}

func TestSupportsTimer(t *testing.T) {
	if !supportsTimer([]string{"replaces, timer, 100rel"}) {
		t.Fatal("a comma-joined Supported value naming timer must match")
	}
	if !supportsTimer([]string{"replaces", "TIMER"}) {
		t.Fatal("matching must be case-insensitive and across repeated headers")
	}
	if supportsTimer([]string{"replaces, 100rel"}) {
		t.Fatal("no timer token must not match")
	}
}

func TestOutboundRefresherRoleFallsBackToUACWhenThePeerOmitsTheParam(t *testing.T) {
	// RFC 4028 §7.2: an answer carrying Session-Expires with no ;refresher means
	// the UAC refreshes.
	se, ok := parseSessionExpires("120")
	if !ok {
		t.Fatal("parse")
	}
	if role := outboundRefresherRole(se); role != "uac" {
		t.Fatalf("role=%q want uac", role)
	}
	se2, _ := parseSessionExpires("120;refresher=uas")
	if role := outboundRefresherRole(se2); role != "uas" {
		t.Fatalf("role=%q want uas", role)
	}
}

// TestRetryIntervalFor422IsBoundedByOurCeiling exercises Correction 3's
// package-level ceiling (maxAcceptableSessionIntervalS), which the brief's own
// per-UA sessionExpiresS() bound could never reach in practice: a conformant
// 422 always demands MORE than the interval we proposed, so a peer's demand is
// only ever refused when it exceeds the fixed 7200s ceiling, never our own
// (comparatively tiny) SessionExpiresS.
func TestRetryIntervalFor422IsBoundedByOurCeiling(t *testing.T) {
	u := &UA{cfg: Config{SessionExpiresS: 1800, MinSES: 90}}
	// The peer demands 600: honour it.
	if got := u.retryIntervalFor422(600); got != 600 {
		t.Fatalf("got %d want 600", got)
	}
	// The peer demands more than our own SessionExpiresS but still under the
	// package ceiling: honour it too — this is the realistic §6 shape.
	if got := u.retryIntervalFor422(1801); got != 1801 {
		t.Fatalf("got %d want 1801 — a demand above our proposal but under the ceiling must be honoured", got)
	}
	// The peer demands more than the package ceiling: refuse (0 means "fail the
	// dial").
	if got := u.retryIntervalFor422(7201); got != 0 {
		t.Fatalf("got %d want 0 — a demand above the ceiling fails the dial", got)
	}
	// A nonsensical demand below RFC 4028's floor: refuse.
	if got := u.retryIntervalFor422(10); got != 0 {
		t.Fatalf("got %d want 0", got)
	}
	// The floor's own BOUNDARY. Probed only at 10, the guard is pinned merely
	// to the open interval (10, 600] — lowering the constant from 90 to 20 kept
	// the whole internal/sipua package green, so RFC 4028 §4's 90-second
	// minimum was asserted by nothing. 89/90 is the only pair that can tell a
	// correct floor from a lower one.
	if got := u.retryIntervalFor422(89); got != 0 {
		t.Fatalf("got %d want 0 — 89 is below RFC 4028 §4's 90s floor", got)
	}
	if got := u.retryIntervalFor422(90); got != 90 {
		t.Fatalf("got %d want 90 — the floor itself is acceptable", got)
	}
}

func TestInboundRefresherRoleHonoursAnExplicitPeerRequest(t *testing.T) {
	// Decision 12: we claim uas for calls we accept...
	req := inboundTimerRequest{Present: true, Requested: sessionExpires{IntervalS: 300}}
	if got := inboundRefresherRole(req); got != "uas" {
		t.Fatalf("role=%q want uas", got)
	}
	// ...unless the peer explicitly asked to refresh (decision 9).
	req2 := inboundTimerRequest{Present: true, Supported: true, Requested: sessionExpires{IntervalS: 300, Refresher: "uac"}}
	if got := inboundRefresherRole(req2); got != "uac" {
		t.Fatalf("role=%q want uac — an explicit peer request is honoured", got)
	}
	// ...but only a request that indicated support for timer (CF-119).
	req4 := inboundTimerRequest{Present: true, Requested: sessionExpires{IntervalS: 300, Refresher: "uac"}}
	if got := inboundRefresherRole(req4); got != "uas" {
		t.Fatalf("role=%q want uas — refresher=uac without Supported is not honoured", got)
	}
	req3 := inboundTimerRequest{Present: true, Requested: sessionExpires{IntervalS: 300, Refresher: "uas"}}
	if got := inboundRefresherRole(req3); got != "uas" {
		t.Fatalf("role=%q want uas", got)
	}
}

func TestOurAllowNamesUPDATE(t *testing.T) {
	if !strings.Contains(ourAllow(), "UPDATE") {
		t.Fatalf("Allow=%q must name UPDATE — the peer-as-refresher case sends them", ourAllow())
	}
	for _, m := range []string{"INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "INFO"} {
		if !strings.Contains(ourAllow(), m) {
			t.Fatalf("Allow=%q must name %s", ourAllow(), m)
		}
	}
}

func TestReadInboundSessionTimer(t *testing.T) {
	req := sip.NewRequest(sip.INVITE, sip.Uri{Host: "example"})
	req.AppendHeader(sip.NewHeader("Supported", "timer, 100rel"))
	req.AppendHeader(sip.NewHeader("Session-Expires", "300;refresher=uac"))
	req.AppendHeader(sip.NewHeader("Min-SE", "120"))
	req.AppendHeader(sip.NewHeader("Allow", "INVITE, ACK, BYE, UPDATE"))
	got := readInboundSessionTimer(req)
	if !got.Present || got.Requested.IntervalS != 300 || got.Requested.Refresher != "uac" ||
		got.MinSE != 120 || got.Required {
		t.Fatalf("got %+v", got)
	}
	if !peerAllowsUPDATE(got.Allow) {
		t.Fatal("the peer's Allow names UPDATE")
	}

	bare := sip.NewRequest(sip.INVITE, sip.Uri{Host: "example"})
	if readInboundSessionTimer(bare).Present {
		t.Fatal("an INVITE with neither Supported: timer nor Session-Expires has no timer request")
	}

	required := sip.NewRequest(sip.INVITE, sip.Uri{Host: "example"})
	required.AppendHeader(sip.NewHeader("Require", "timer"))
	required.AppendHeader(sip.NewHeader("Session-Expires", "300"))
	if r := readInboundSessionTimer(required); !r.Required || !r.Present {
		t.Fatalf("Require: timer must be recorded: %+v", r)
	}
}

func TestNegotiatedIntervalHonoursTheRequestsMinSE(t *testing.T) {
	cases := []struct {
		name           string
		ses, minSES    int
		want, reqMinSE int
		out, refuse    int
	}{
		{"in range", 1800, 90, 600, 0, 600, 0},
		{"below our min_se_s => 422", 1800, 300, 120, 0, 120, 422},
		{"above our ceiling, no peer floor", 1800, 90, 3600, 0, 1800, 0},
		{"above our ceiling, peer floor higher", 1800, 90, 3600, 2400, 2400, 0},
		{"supported-only, no Session-Expires", 1800, 90, 0, 0, 1800, 0},
		{"supported-only, peer floor above ours", 1800, 90, 0, 2400, 2400, 0},
		{"peer floor above its own request", 1800, 90, 100, 200, 200, 0},
		{"NEWC6 shape: floor above the 7200 config ceiling", 90, 90, 10000, 10000, 10000, 0},
		{"at the Min-SE ceiling", 90, 90, 86400, 86400, 86400, 0},
		{"above the Min-SE ceiling => 400", 90, 90, 86401, 86401, 0, 400},
		{"400 wins over 422", 1800, 300, 120, 90000, 0, 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := &UA{cfg: Config{SessionExpiresS: c.ses, MinSES: c.minSES}}
			req := inboundTimerRequest{Present: true, MinSE: c.reqMinSE,
				Requested: sessionExpires{IntervalS: c.want}}
			got, refuse := u.negotiatedInterval(req)
			if got != c.out || refuse != c.refuse {
				t.Fatalf("negotiatedInterval=(%d, %d) want (%d, %d)", got, refuse, c.out, c.refuse)
			}
		})
	}
}

func TestBuildInboundSessionTimerSetsWhoRefreshesAndThePeersAllow(t *testing.T) {
	st := buildInboundSessionTimer(600, "uas", []string{"INVITE, UPDATE"}, 120)
	if !st.weRefresh {
		t.Fatal("refresher=uas on a dialog WE answered means WE refresh (Task 29 branches on this)")
	}
	if !peerAllowsUPDATE(st.peerAllow) {
		t.Fatal("the peer's Allow must be cached for decision 11's UPDATE-vs-re-INVITE choice")
	}
	if st.minSE != 120 {
		t.Fatalf("minSE=%d want 120: the initial INVITE's Min-SE seeds the dialog's floor (CF-121)", st.minSE)
	}
	if buildInboundSessionTimer(600, "uac", nil, 0).weRefresh {
		t.Fatal("refresher=uac on a dialog WE answered means the PEER refreshes")
	}
}

func TestRequireTimerInAnswerFollowsRFC4028Section9(t *testing.T) {
	if !requireTimerInAnswer(inboundTimerRequest{Supported: false}, "uac") {
		t.Fatal("refresher=uac in the 2xx: RFC 4028 §9 MUST include Require: timer")
	}
	if !requireTimerInAnswer(inboundTimerRequest{Supported: true}, "uas") {
		t.Fatal("refresher=uas and the request advertised Supported: timer: SHOULD include it")
	}
	if requireTimerInAnswer(inboundTimerRequest{Supported: false}, "uas") {
		t.Fatal("a peer that never advertised Supported: timer must not be handed Require: timer")
	}
}

type stubServerTx struct{ res []*sip.Response }

func (t *stubServerTx) Terminate()                       {}
func (t *stubServerTx) Done() <-chan struct{}            { return nil }
func (t *stubServerTx) Err() error                       { return nil }
func (t *stubServerTx) Acks() <-chan *sip.Request        { return nil }
func (t *stubServerTx) OnCancel(func(*sip.Request) bool) {}
func (t *stubServerTx) Respond(r *sip.Response) error    { t.res = append(t.res, r); return nil }
func (t *stubServerTx) last() *sip.Response              { return t.res[len(t.res)-1] }

var _ sip.ServerTransaction = (*stubServerTx)(nil)

func newAnsweredInboundDialog(u *UA, callID string) (*dialog, string) {
	inv := sip.NewRequest(sip.INVITE, sip.Uri{User: "alice", Host: "here"})
	cid := sip.CallIDHeader(callID)
	inv.AppendHeader(&cid)
	inv.AppendHeader(&sip.FromHeader{Address: sip.Uri{User: "bob", Host: "peer"}, Params: sip.NewParams()})
	inv.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "alice", Host: "here"}, Params: sip.NewParams()})
	d := &dialog{id: "d-" + callID, direction: session.Inbound, phase: phaseAnswered,
		callID: callID, invite: inv}
	d.ok = sip.NewResponseFromRequest(inv, 200, "OK", nil)
	d.sessionTimer = &sessionTimerState{IntervalS: 600, Refresher: "uac"}
	u.register(d)
	tag, _ := d.ok.To().Params.Get("tag")
	return d, tag
}

func updateReq(callID, toTag string) *sip.Request {
	req := sip.NewRequest(sip.UPDATE, sip.Uri{User: "alice", Host: "here"})
	cid := sip.CallIDHeader(callID)
	req.AppendHeader(&cid)
	req.AppendHeader(&sip.FromHeader{Address: sip.Uri{User: "bob", Host: "peer"}, Params: sip.NewParams()})
	to := &sip.ToHeader{Address: sip.Uri{User: "alice", Host: "here"}, Params: sip.NewParams()}
	if toTag != "" {
		to.Params.Add("tag", toTag)
	}
	req.AppendHeader(to)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 5, MethodName: sip.UPDATE})
	return req
}

func TestOnUpdateAnswers481UnlessTheDialogIsAnsweredAndTheTagMatches(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, tag := newAnsweredInboundDialog(u, "cid-live")
	for _, c := range []struct {
		name   string
		setup  func()
		toTag  string
		callID string
		want   sip.StatusCode
	}{
		{"answered, right tag", func() {}, tag, "cid-live", 200},
		{"unknown Call-ID", func() {}, tag, "cid-nope", 481},
		{"wrong To-tag", func() {}, "not-our-tag", "cid-live", 481},
		{"not yet answered", func() { d.phase = phaseRinging }, tag, "cid-live", 481},
		{"answering window, right tag", func() { d.phase = phaseAnswering }, tag, "cid-live", 200},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.setup()
			tx := &stubServerTx{}
			u.onUpdate(updateReq(c.callID, c.toTag), tx)
			if got := tx.last().StatusCode; got != c.want {
				t.Fatalf("UPDATE -> %d, want %d", got, c.want)
			}
		})
		d.phase = phaseAnswered
	}
}

// TestOnUpdateRejectsANoTagUPDATEDuringTheAnsweringWindow is C-M1's
// regression test. onUpdate's known-dialog gate degenerates to `"" == ""`
// on an INBOUND dialog still in phaseAnswering: Answer sets d.phase and d.ok
// TOGETHER, in one critical section (call.go:1976-1980), only after its 200
// OK has reached the wire — so for the whole of phaseAnswering, d.ok is nil
// and ourReInviteTagLocked(d) reads "". Unlike
// TestOnUpdateAnswers481UnlessTheDialogIsAnsweredAndTheTagMatches's
// "answering window" case (which uses newAnsweredInboundDialog, whose d.ok is
// already set), this test builds the dialog WITHOUT d.ok to reproduce the
// actual mid-Answer state, so an UPDATE carrying no To-tag at all would
// otherwise match "" == "" and be answered 200 for a dialog that is not yet
// confirmed.
func TestOnUpdateRejectsANoTagUPDATEDuringTheAnsweringWindow(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	inv := sip.NewRequest(sip.INVITE, sip.Uri{User: "alice", Host: "here"})
	cid := sip.CallIDHeader("cid-mid-answer")
	inv.AppendHeader(&cid)
	inv.AppendHeader(&sip.FromHeader{Address: sip.Uri{User: "bob", Host: "peer"}, Params: sip.NewParams()})
	inv.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "alice", Host: "here"}, Params: sip.NewParams()})
	st := &sessionTimerState{IntervalS: 90, Refresher: "uas"}
	d := &dialog{id: "d-mid-answer", direction: session.Inbound, phase: phaseAnswering,
		callID: "cid-mid-answer", invite: inv, sessionTimer: st}
	// d.ok is deliberately left nil: this is Answer's mid-write window, before
	// the 200 OK (and its To-tag) exist.
	u.register(d)

	tx := &stubServerTx{}
	u.onUpdate(updateReq("cid-mid-answer", ""), tx)
	if got := tx.last().StatusCode; got != 481 {
		t.Fatalf("no-tag UPDATE during the answering window -> %d, want 481", got)
	}
	if st.watchdog != nil {
		t.Fatal("a 481'd UPDATE must not rearm the watchdog")
	}

	// The dialog settles: d.phase and d.ok land together, exactly as Answer's
	// own critical section does.
	d.ok = sip.NewResponseFromRequest(inv, 200, "OK", nil)
	d.phase = phaseAnswered
	tag, _ := d.ok.To().Params.Get("tag")

	// A refresh that lists timer and names the peer keeps the peer refreshing
	// (Table 2 "Y, uac"), so the watchdog stays armed; a bare UPDATE would hand
	// refreshing to us.
	upd2 := updateReq("cid-mid-answer", tag)
	upd2.AppendHeader(sip.NewHeader("Supported", "timer"))
	upd2.AppendHeader(sip.NewHeader("Session-Expires", "90;refresher=uac"))
	tx2 := &stubServerTx{}
	u.onUpdate(upd2, tx2)
	if got := tx2.last().StatusCode; got != 200 {
		t.Fatalf("correctly-tagged UPDATE after the dialog settled -> %d, want 200", got)
	}
	if st.watchdog == nil {
		t.Fatal("a 200'd UPDATE on a known dialog must rearm the watchdog")
	}
}

func infoReq(callID, toTag string) *sip.Request {
	req := sip.NewRequest(sip.INFO, sip.Uri{User: "alice", Host: "here"})
	cid := sip.CallIDHeader(callID)
	req.AppendHeader(&cid)
	req.AppendHeader(&sip.FromHeader{Address: sip.Uri{User: "bob", Host: "peer"}, Params: sip.NewParams()})
	to := &sip.ToHeader{Address: sip.Uri{User: "alice", Host: "here"}, Params: sip.NewParams()}
	to.Params.Add("tag", toTag)
	req.AppendHeader(to)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 5, MethodName: sip.INFO})
	return req
}

// SUBJECT LIVES IN dtmf.go (onInfo), not in this file's sessiontimer.go — the
// fixtures for an in-dialog request are here, so the test is too (B-M12, D20).
//
// TestOnInfoAccepts481UnlessTheDialogIsAnsweredOrAnswering is the C2 gate's own
// regression test (Rule 13 Cycle 2 fix round 2, non-blocking item #1): onInfo
// widened to accept phaseAnswering alongside phaseAnswered (dtmf.go), the third
// and last of the three answering-window gates to be widened. Driven through the
// same in-package seams the sibling onUpdate gate above already uses —
// stubServerTx, newAnsweredInboundDialog, newClaimTestUA — so no new production
// hook and no duplication of the peer harness's SendXToCaller.
func TestOnInfoAccepts481UnlessTheDialogIsAnsweredOrAnswering(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, tag := newAnsweredInboundDialog(u, "cid-live")
	for _, c := range []struct {
		name   string
		setup  func()
		callID string
		want   sip.StatusCode
	}{
		{"answered", func() {}, "cid-live", 200},
		{"answering window", func() { d.phase = phaseAnswering }, "cid-live", 200},
		{"not yet answered", func() { d.phase = phaseRinging }, "cid-live", 481},
		{"unknown Call-ID", func() {}, "cid-nope", 481},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.setup()
			tx := &stubServerTx{}
			u.onInfo(infoReq(c.callID, tag), tx)
			if got := tx.last().StatusCode; got != c.want {
				t.Fatalf("INFO -> %d, want %d", got, c.want)
			}
		})
		d.phase = phaseAnswered
	}
}

// TestExpireSessionTimerIsSilentWhenAConcurrentTerminatorAlreadyWon pins
// expireSessionTimer's concurrent-terminator guard against the code that is
// actually produced, which is not_found rather than precondition_failed.
//
// The state below is exactly what a losing race leaves: every teardown path in
// this package sets phase = phaseDone AND calls forgetLocked in the SAME
// critical section, so a watchdog whose goroutine was already spawned when the
// teardown started reaches hangupWithReason to find the dialog gone. Its
// opening u.lookup then returns not_found and never gets as far as the phase
// check that would have returned precondition_failed.
//
// The consequence the guard prevents is a SECOND UAEventDialogEnded carrying
// session_timer_expired on top of whatever cause the winning terminator already
// reported — a §6.3 exactly-one-terminal-event violation. session's own handler
// happens to absorb the duplicate today, but that masking is incidental, so this
// is asserted at the UA's emit boundary where the invariant actually lives.
func TestExpireSessionTimerIsSilentWhenAConcurrentTerminatorAlreadyWon(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, _ := newAnsweredInboundDialog(u, "cid-raced")

	var ended int
	// emit invokes this synchronously on the caller's goroutine, so a plain
	// counter needs no synchronisation here.
	u.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) {
		if ev.Kind == session.UAEventDialogEnded {
			ended++
		}
	})

	// The concurrent terminator wins: it claims the phase and forgets the
	// dialog under one lock, then would go on to emit its own terminal event.
	u.calls.mu.Lock()
	d.phase = phaseDone
	u.forgetLocked(d.id)
	u.calls.mu.Unlock()

	u.expireSessionTimer(d)

	if ended != 0 {
		t.Fatalf("expireSessionTimer emitted %d dialog_ended event(s) for a dialog a "+
			"concurrent terminator had already ended; §6.3 allows exactly one", ended)
	}
}

// TestNoTimerIsArmedOnADialogThatIsNoLongerAnswered pins the re-arm gate. The
// re-arm path in onSessionRefreshReceived releases u.calls.mu to Stop the previous
// watchdog, so a dialog can terminate before the new one is stored; a watchdog
// armed then is invisible to every teardown path (they read the fields this write
// would clobber) and survives until the UA's context dies, at which point it BYEs
// a dialog that ended minutes ago.
//
// Both arms are asserted, because both store into a state block a concurrent
// teardown may already have cleared.
func TestNoTimerIsArmedOnADialogThatIsNoLongerAnswered(t *testing.T) {
	for _, tc := range []struct {
		name      string
		weRefresh bool
		arm       func(u *UA, d *dialog, st *sessionTimerState)
		got       func(st *sessionTimerState) *refresher
	}{
		{
			name: "watchdog", weRefresh: false,
			arm: func(u *UA, d *dialog, st *sessionTimerState) { u.startSessionWatchdog(d, st) },
			got: func(st *sessionTimerState) *refresher { return st.watchdog },
		},
		{
			name: "refresher", weRefresh: true,
			arm: func(u *UA, d *dialog, st *sessionTimerState) { u.startSessionRefresher(d, st) },
			got: func(st *sessionTimerState) *refresher { return st.refresher },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := fakeclock.New(time.Unix(0, 0))
			u := &UA{cfg: Config{Clock: clk, Logger: slog.Default()}}
			u.uaCtx = context.Background()
			st := &sessionTimerState{IntervalS: 90, Refresher: "uas", weRefresh: tc.weRefresh}
			// The dialog has ALREADY terminated — the state a losing race leaves.
			d := &dialog{id: "d1", phase: phaseDone, sessionTimer: st}
			u.register(d)

			tc.arm(u, d, st)

			if r := tc.got(st); r != nil {
				t.Fatalf("a %s was armed on a dialog in phaseDone; no teardown path will "+
					"ever stop it, so it outlives its own dialog", tc.name)
			}
		})
	}
}

// TestArmingWorksOnAnAnsweredDialog is the gate's other half: the check must not
// have broken the ordinary path.
func TestArmingWorksOnAnAnsweredDialog(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	u := &UA{cfg: Config{Clock: clk, Logger: slog.Default()}}
	u.uaCtx = context.Background()
	st := &sessionTimerState{IntervalS: 90, Refresher: "uas"}
	d := &dialog{id: "d1", phase: phaseAnswered, sessionTimer: st}
	u.register(d)
	u.startSessionWatchdog(d, st)
	if st.watchdog == nil {
		t.Fatal("an answered peer-refreshed dialog MUST get a watchdog")
	}
	u.stopSessionTimer(d)
}

// TestNoWatchdogWhenWeAreTheRefresher closes the surviving mutant: dropping
// startSessionWatchdog's `st.weRefresh` gate arms a watchdog on a dialog we
// refresh ourselves, and our own refreshes never rearm it, so the call is
// reaped at the full interval while refreshing perfectly.
func TestNoWatchdogWhenWeAreTheRefresher(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	u := &UA{cfg: Config{Clock: clk, Logger: slog.Default()}}
	u.uaCtx = context.Background()
	st := &sessionTimerState{IntervalS: 90, Refresher: "uac", weRefresh: true}
	d := &dialog{id: "d1", phase: phaseAnswered, sessionTimer: st}
	u.register(d)
	u.startSessionWatchdog(d, st)
	if st.watchdog != nil {
		t.Fatal("a watchdog was armed on a dialog WE refresh; our own refreshes never rearm it")
	}
}

// TestSessionTimerViewReportsArmed is C9/A-M6's regression test: next_refresh_ms
// alone cannot tell apart (a) no timer armed at all, (b) armed but the
// deadline already passed, and (c) armed but read in the instant right after
// Start() before the refresher's launched goroutine has called setNextAt —
// all three read 0. Armed distinguishes (a) from (b)/(c) without touching
// refresher.go's internals: SessionTimerView already snapshots whether
// rf/wd are non-nil.
//
// Cases (b) and (c) are built by constructing the refresher/watchdog DIRECTLY
// rather than through startSessionWatchdog + a real fire/race, which would be
// nondeterministic (goroutine scheduling for (c), a full expiry-and-teardown
// for (b)). Both constructions reproduce the exact OBSERVABLE state
// SessionTimerView reads — a non-nil refresher whose NextAt() is either in
// the past (b) or the zero value because setNextAt was never called (c),
// which is precisely refresher.go's own default before its first
// setNextAt(refresher.go:195) — without depending on timing.
func TestSessionTimerViewReportsArmed(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	for _, tc := range []struct {
		name      string
		setup     func(st *sessionTimerState)
		wantArmed bool
	}{
		{
			name:      "no timer armed at all",
			setup:     func(*sessionTimerState) {},
			wantArmed: false,
		},
		{
			name: "armed, deadline already passed",
			setup: func(st *sessionTimerState) {
				r := newRefresher(clk, slog.Default(), refreshPolicy{
					Name: "session_watchdog", Fraction: 1.0, Initial: 90 * time.Second,
					Do: func(context.Context) (int, error) { return 0, nil },
				})
				r.setNextAt(clk.Now().Add(-time.Second))
				st.watchdog = r
			},
			wantArmed: true,
		},
		{
			name: "armed, race window right after Start() before setNextAt has run",
			setup: func(st *sessionTimerState) {
				r := newRefresher(clk, slog.Default(), refreshPolicy{
					Name: "session_watchdog", Fraction: 1.0, Initial: 90 * time.Second,
					Do: func(context.Context) (int, error) { return 0, nil },
				})
				st.watchdog = r // NextAt() is still the zero value: setNextAt never ran.
			},
			wantArmed: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := &UA{cfg: Config{Clock: clk, Logger: slog.Default()}}
			u.uaCtx = context.Background()
			st := &sessionTimerState{IntervalS: 90, Refresher: "uas"}
			tc.setup(st)
			d := &dialog{id: "d-armed", phase: phaseAnswered, sessionTimer: st}
			u.register(d)

			view, ok := u.SessionTimerView(d.id)
			if !ok {
				t.Fatal("SessionTimerView ok=false, want true — a session timer was negotiated")
			}
			if view.Armed != tc.wantArmed {
				t.Fatalf("Armed=%v want %v", view.Armed, tc.wantArmed)
			}
			if view.NextRefreshMs != 0 {
				t.Fatalf("NextRefreshMs=%d want 0 — every case here reads the ambiguous zero", view.NextRefreshMs)
			}
		})
	}
}

// TestTheOfferedDefaultsMatchWhatPolicyValidatesAgainst pins the coupling
// policy.DefaultSessionExpiresS's own doc comment asserts ("The two must not
// diverge") and which nothing enforced. policy.validate() rejects `min_se_s:
// 2000` precisely because it knows an omitted session_expires_s resolves to
// 1800 — but the value actually offered on the wire is this package's separate
// literal. BOTH copies were unpinned: either could be changed to 1500 with
// `go test ./...` fully green. A drift would load a profile clean and then put
// Min-SE above Session-Expires on one INVITE, which is the RFC 4028 §5
// contradiction that check exists to catch.
//
// It survived because every other session-timer test passes 1800 in explicitly
// (newSessionTimerUA(t, clk, 1800, 90)), so the default branch is never the
// thing under test — the configured and defaulted values coincide.
func TestTheOfferedDefaultsMatchWhatPolicyValidatesAgainst(t *testing.T) {
	u := &UA{}
	if got := u.sessionExpiresS(); got != policy.DefaultSessionExpiresS {
		t.Fatalf("a UA with no session_expires_s offers Session-Expires: %d, but policy "+
			"validates min_se_s against %d — a profile can now load clean and still put "+
			"Min-SE above Session-Expires on one INVITE (RFC 4028 §5)",
			got, policy.DefaultSessionExpiresS)
	}
	// The other half of the same coupling. policy's `floor := 90` for
	// session_expires_s is only correct while the Min-SE we actually advertise is
	// 90; raising this default to 120 leaves `session_expires_s: 90` loading
	// clean and offering Session-Expires: 90 beside Min-SE: 120. 90 is not an
	// implementation choice to be pinned to itself — it is RFC 4028 §3's absolute
	// minimum, which is why policy spells it as a literal too.
	if got := u.minSES(); got != 90 {
		t.Fatalf("a UA with no min_se_s advertises Min-SE: %d, want RFC 4028 §3's floor of 90 "+
			"— policy validates session_expires_s against 90 and cannot see this value", got)
	}
}

// armTestUA builds a bare UA on a fake clock with one registered dialog carrying
// st, for the arm/re-arm tests that drive armSessionTimer directly.
func armTestUA(st *sessionTimerState, ph phase) (*UA, *dialog) {
	clk := fakeclock.New(time.Unix(0, 0))
	u := &UA{cfg: Config{Clock: clk, Logger: slog.Default()}}
	u.uaCtx = context.Background()
	d := &dialog{id: "d1", phase: ph, sessionTimer: st}
	u.register(d)
	return u, d
}

func isClosed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// TestAPeerRefreshRestartsOurRefresher: RFC 4028 9 restarts the session on every
// 2xx to a refresh, so a peer refresh must replace OUR refresher too, not only
// the watchdog (LB-D4). Mutation: build a watchdog regardless of weRefresh ->
// refresher nil -> FAIL.
func TestAPeerRefreshRestartsOurRefresher(t *testing.T) {
	st := &sessionTimerState{IntervalS: 90, Refresher: "uac", weRefresh: true}
	u, d := armTestUA(st, phaseAnswered)
	u.startSessionRefresher(d, st)
	u.calls.mu.Lock()
	r1 := st.refresher
	u.calls.mu.Unlock()
	if r1 == nil {
		t.Fatal("startSessionRefresher armed nothing")
	}

	u.onSessionRefreshReceived(d)

	u.calls.mu.Lock()
	r2, w, n := st.refresher, st.watchdog, st.armedTimers
	u.calls.mu.Unlock()
	if r2 == nil || r2 == r1 || w != nil || n != 1 {
		t.Fatalf("after a peer refresh: refresher replaced=%v watchdog=%v armedTimers=%d, want a new refresher, no watchdog, 1",
			r2 != nil && r2 != r1, w != nil, n)
	}
	if !isClosed(r1.done) {
		t.Fatal("the replaced refresher is still running")
	}
	u.stopSessionTimer(d)
}

// TestARoleChangeSwapsTheArmedTimer: a writer that flips weRefresh gets the other
// kind of timer on its next arm, and the old one is stopped and uncounted.
func TestARoleChangeSwapsTheArmedTimer(t *testing.T) {
	for _, tc := range []struct {
		name       string
		from, to   bool
		old, now   func(*sessionTimerState) *refresher
		oldN, newN string
	}{
		{"watchdog to refresher", false, true,
			func(st *sessionTimerState) *refresher { return st.watchdog },
			func(st *sessionTimerState) *refresher { return st.refresher }, "watchdog", "refresher"},
		{"refresher to watchdog", true, false,
			func(st *sessionTimerState) *refresher { return st.refresher },
			func(st *sessionTimerState) *refresher { return st.watchdog }, "refresher", "watchdog"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &sessionTimerState{IntervalS: 90, Refresher: "uac", weRefresh: tc.from}
			u, d := armTestUA(st, phaseAnswered)
			u.armSessionTimer(d, st)
			u.calls.mu.Lock()
			old := tc.old(st)
			st.weRefresh = tc.to
			u.calls.mu.Unlock()
			if old == nil {
				t.Fatalf("the initial arm stored no %s", tc.oldN)
			}

			u.onSessionRefreshReceived(d)

			u.calls.mu.Lock()
			cur, left, n := tc.now(st), tc.old(st), st.armedTimers
			u.calls.mu.Unlock()
			if cur == nil || left != nil || n != 1 {
				t.Fatalf("after the swap: %s=%v %s=%v armedTimers=%d, want %s set, %s nil, 1",
					tc.newN, cur != nil, tc.oldN, left != nil, n, tc.newN, tc.oldN)
			}
			if !isClosed(old.done) {
				t.Fatalf("the old %s is still running", tc.oldN)
			}
			u.stopSessionTimer(d)
		})
	}
}

// TestOurRefresherIsRearmedDuringAControlOp: the store gate is dialogEstablished,
// which includes phaseControlOp (H8); a peer refresh during a transfer must not
// stop our refresher and arm nothing.
func TestOurRefresherIsRearmedDuringAControlOp(t *testing.T) {
	st := &sessionTimerState{IntervalS: 90, Refresher: "uac", weRefresh: true}
	u, d := armTestUA(st, phaseControlOp)
	u.onSessionRefreshReceived(d)
	u.calls.mu.Lock()
	r := st.refresher
	u.calls.mu.Unlock()
	if r == nil {
		t.Fatal("no refresher was armed on a dialog in a control op")
	}
	u.stopSessionTimer(d)
}

// TestAReplacedRefresherHasExitedBeforeItsSuccessorOrTeardownProceeds: with R1
// genuinely blocked in Do, a second arm and a teardown must both wait for it
// (armMu, I8): no successor runs beside R1 and stopSessionTimer does not return
// before R1 has exited. Mutations: drop armMu from armSessionTimer -> G2 starts
// a second timer during the wait; drop it from stopSessionTimer -> G3 returns
// before release.
func TestAReplacedRefresherHasExitedBeforeItsSuccessorOrTeardownProceeds(t *testing.T) {
	st := &sessionTimerState{IntervalS: 90, Refresher: "uac", weRefresh: true}
	u, d := armTestUA(st, phaseAnswered)
	clk := u.cfg.Clock.(*fakeclock.Clock)
	entered, release := make(chan struct{}), make(chan struct{})
	r1 := newRefresher(clk, slog.Default(), refreshPolicy{
		Name: "session_timer", Fraction: sessionRefreshFraction, Initial: 90 * time.Second,
		Do: func(context.Context) (int, error) {
			close(entered)
			<-release
			return 0, errRefresherStopped
		},
	})
	u.calls.mu.Lock()
	st.refresher = r1
	st.armedTimers = 1
	u.calls.mu.Unlock()
	r1.Start(context.Background())
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("R1's Do never ran")
	}

	var wg sync.WaitGroup
	returned := make(chan string, 3)
	run := func(name string, f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f(); returned <- name }()
	}
	run("G1", func() { u.onSessionRefreshReceived(d) })
	run("G2", func() { u.onSessionRefreshReceived(d) })
	time.Sleep(100 * time.Millisecond) // both parked: G1 in R1.Stop, G2 on armMu
	run("G3", func() {
		u.calls.mu.Lock()
		d.phase = phaseDone
		u.calls.mu.Unlock()
		u.stopSessionTimer(d)
	})
	time.Sleep(100 * time.Millisecond)

	u.calls.mu.Lock()
	r, n := st.refresher, st.armedTimers
	u.calls.mu.Unlock()
	if r != nil || n != 0 {
		t.Fatalf("while R1 is still in Do: refresher=%v armedTimers=%d, want nil and 0 (a successor started beside it)", r != nil, n)
	}
	select {
	case name := <-returned:
		t.Fatalf("%s returned while R1 was still in Do", name)
	default:
	}

	close(release)
	wg.Wait()
	u.calls.mu.Lock()
	r, w, n := st.refresher, st.watchdog, st.armedTimers
	u.calls.mu.Unlock()
	if r != nil || w != nil || n != 0 {
		t.Fatalf("after teardown: refresher=%v watchdog=%v armedTimers=%d, want all clear", r != nil, w != nil, n)
	}
	if !isClosed(r1.done) {
		t.Fatal("R1 had not exited")
	}
}

// TestAStaleRefreshCommitsNothing: a refresh whose generation has been superseded
// writes nothing to st even when the peer's 2xx names a new interval (I9).
// Mutation: drop the armGen == gen check -> the interval is re-based -> FAIL.
func TestAStaleRefreshCommitsNothing(t *testing.T) {
	p := sippeer.Start(t, sippeer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: sippeer.Behaviour{
			AnswerSessionExpires:  "90;refresher=uac",
			RefreshSessionExpires: []string{"300;refresher=uac"},
			AnswerAllow:           "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	u, d, st := dialedRefreshingDialog(t, p)
	u.calls.mu.Lock()
	stale := st.armGen - 1
	u.calls.mu.Unlock()
	_, err := u.refreshSession(context.Background(), d, st, stale)
	if !errors.Is(err, errRefresherStopped) {
		t.Fatalf("a stale refresh returned %v, want errRefresherStopped", err)
	}
	u.calls.mu.Lock()
	got := st.IntervalS
	u.calls.mu.Unlock()
	if got != 90 {
		t.Fatalf("a stale refresh re-based the interval to %d, want it to commit nothing (90)", got)
	}
}

// dialedRefreshingDialog dials p from a fake-clock UA (the clock is never advanced)
// and returns the UA, the answered dialog and its session-timer state, on which we
// are the refresher.
func dialedRefreshingDialog(t *testing.T, p *sippeer.Peer) (*UA, *dialog, *sessionTimerState) {
	t.Helper()
	u, err := New(context.Background(), Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		SessionExpiresS: 1800, MinSES: 60,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = u.Close(context.Background()) })
	res, err := u.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	d, err := u.lookup(res.DialogID)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		return d.phase == phaseAnswered && d.sessionTimer != nil && d.sessionTimer.refresher != nil
	})
	return u, d, d.sessionTimer
}

// TestRefreshSessionSendsNothingOnceThePeerRefreshes (J1): a refresher that fires
// after the dialog's role was handed to the peer puts nothing on the wire.
func TestRefreshSessionSendsNothingOnceThePeerRefreshes(t *testing.T) {
	st := &sessionTimerState{IntervalS: 90, Refresher: "uac", weRefresh: false}
	u, d := armTestUA(st, phaseAnswered)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("refreshSession tried to send as the non-refresher: %v", r)
		}
	}()
	_, err := u.refreshSession(context.Background(), d, st, st.armGen)
	if !errors.Is(err, errRefresherStopped) {
		t.Fatalf("refreshSession = %v, want errRefresherStopped", err)
	}
}

// TestAStale422StillRaisesTheDialogMinSE (I9, B2): a superseded refresher whose
// refresh draws a 422 commits no interval but still records the Min-SE (a monotone
// max cannot be stale). Mutation: merge the Min-SE after the fence -> st.minSE 0.
func TestAStale422StillRaisesTheDialogMinSE(t *testing.T) {
	p := sippeer.Start(t, sippeer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: sippeer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			RejectUpdateStatus:   422,
			RejectUpdateMinSE:    300,
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	u, d, st := dialedRefreshingDialog(t, p)
	u.calls.mu.Lock()
	stale := st.armGen - 1
	u.calls.mu.Unlock()
	_, err := u.refreshSession(context.Background(), d, st, stale)
	if !errors.Is(err, errRefresherStopped) {
		t.Fatalf("a stale 422'd refresh returned %v, want errRefresherStopped", err)
	}
	u.calls.mu.Lock()
	minSE, intervalS := st.minSE, st.IntervalS
	u.calls.mu.Unlock()
	if minSE != 300 || intervalS != 90 {
		t.Fatalf("minSE=%d IntervalS=%d, want 300 and 90", minSE, intervalS)
	}
}

// failingServerTx fails the 2xx write; blockingServerTx parks it until released.
type failingServerTx struct{ stubServerTx }

func (t *failingServerTx) Respond(r *sip.Response) error {
	t.res = append(t.res, r)
	return errors.New("write failed")
}

type blockingServerTx struct {
	stubServerTx
	entered chan struct{}
	release chan struct{}
}

func (t *blockingServerTx) Respond(r *sip.Response) error {
	close(t.entered)
	<-t.release
	return t.stubServerTx.Respond(r)
}

func refreshingInboundDialog(t *testing.T) (*UA, *dialog, *sessionTimerState, string) {
	t.Helper()
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, tag := newAnsweredInboundDialog(u, "cid-order")
	st := &sessionTimerState{IntervalS: 90, Refresher: "uas", weRefresh: true}
	u.calls.mu.Lock()
	d.sessionTimer = st
	u.calls.mu.Unlock()
	t.Cleanup(func() { u.stopSessionTimer(d) })
	return u, d, st, tag
}

func peerNamesItselfUpdate(tag string) *sip.Request {
	upd := updateReq("cid-order", tag)
	upd.AppendHeader(sip.NewHeader("Supported", "timer"))
	upd.AppendHeader(sip.NewHeader("Session-Expires", "120;refresher=uac"))
	return upd
}

// TestAFailedRefreshAnswerWriteKeepsTheOldRoleAndTimer (Cycle 4, finding 2): the
// negotiation is committed only once the 2xx is written; a failed write leaves the
// role, interval and generation alone (the peer never saw the new ones).
func TestAFailedRefreshAnswerWriteKeepsTheOldRoleAndTimer(t *testing.T) {
	u, d, st, tag := refreshingInboundDialog(t)
	u.armSessionTimer(d, st)
	u.calls.mu.Lock()
	r1, gen := st.refresher, st.armGen
	u.calls.mu.Unlock()
	u.onUpdate(peerNamesItselfUpdate(tag), &failingServerTx{})
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if !st.weRefresh || st.IntervalS != 90 || st.Refresher != "uas" || st.refresher != r1 || st.watchdog != nil || st.armGen != gen {
		t.Fatalf("a failed 2xx write changed the dialog: weRefresh=%v Refresher=%q timerSame=%v watchdog=%v gen %d->%d",
			st.weRefresh, st.Refresher, st.refresher == r1, st.watchdog != nil, gen, st.armGen)
	}
}

// TestRefreshAnswersCommitInResponseOrder (Cycle 4, finding 1): while request A's
// 2xx is parked in the write, answerMu is held (so a concurrent B cannot negotiate,
// respond or commit), and after both finish the dialog carries the LAST answered
// request's role. The hold is observed with TryLock rather than a sleep.
func TestRefreshAnswersCommitInResponseOrder(t *testing.T) {
	u, _, st, tag := refreshingInboundDialog(t)
	a := &blockingServerTx{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	releaseA := func() { once.Do(func() { close(a.release) }) }
	defer releaseA()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); u.onUpdate(peerNamesItselfUpdate(tag), a) }() // peer refreshes
	select {
	case <-a.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("A never reached its 2xx write")
	}
	if st.answerMu.TryLock() {
		st.answerMu.Unlock()
		t.Fatal("answerMu is free while A's 2xx is being written: B could negotiate and respond first")
	}
	releaseA()
	wg.Wait()
	// A's negotiation (peer refreshes, 120 s) must have been committed and re-armed
	// as a watchdog before B is sent; the fixture started as weRefresh=true, 90 s.
	u.calls.mu.Lock()
	aWe, aInt, aWd, aRf := st.weRefresh, st.IntervalS, st.watchdog != nil, st.refresher != nil
	u.calls.mu.Unlock()
	if aWe || aInt != 120 || !aWd || aRf {
		t.Fatalf("after A: weRefresh=%v IntervalS=%d watchdog=%v refresher=%v, want false 120 true false", aWe, aInt, aWd, aRf)
	}
	b := &stubServerTx{}
	u.onUpdate(updateReq("cid-order", tag), b) // B, Table 2 "N": we refresh
	u.calls.mu.Lock()
	we, has := st.weRefresh, st.refresher != nil
	u.calls.mu.Unlock()
	if len(b.res) != 1 || !we || !has {
		t.Fatalf("after A then B: B responses=%d weRefresh=%v refresher armed=%v, want 1, true, true", len(b.res), we, has)
	}
}

// TestAnswerMuIsReleasedWhenRespondPanics: a panic in the 2xx write must not leave
// answerMu held (every later refresh answer would block).
func TestAnswerMuIsReleasedWhenRespondPanics(t *testing.T) {
	u, _, st, tag := refreshingInboundDialog(t)
	func() {
		defer func() { _ = recover() }()
		u.onUpdate(peerNamesItselfUpdate(tag), &panickingServerTx{})
	}()
	if !st.answerMu.TryLock() {
		t.Fatal("answerMu still held after a panic in Respond")
	}
	st.answerMu.Unlock()
}

type panickingServerTx struct{ stubServerTx }

func (t *panickingServerTx) Respond(*sip.Response) error { panic("respond") }

// TestAnswerMuIsReleasedWhenStagingPanics: a panic while staging (here a nil
// request) must not leave answerMu held before ownership passes to done.
func TestAnswerMuIsReleasedWhenStagingPanics(t *testing.T) {
	u, d, st, _ := refreshingInboundDialog(t)
	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		var req *sip.Request
		_, _ = u.appendInDialogRefreshHeaders(sip.NewResponseFromRequest(updateReq("cid-order", ""), 200, "OK", nil), req, d, st)
	}()
	if !panicked {
		t.Skip("a nil request no longer panics in staging; pick another panic source")
	}
	if !st.answerMu.TryLock() {
		t.Fatal("answerMu still held after a panic while staging")
	}
	st.answerMu.Unlock()
}

// TestAnswerMuIsReleasedWhenTheRefusalConstructorPanics (Rule 13 round 3): a
// request with Min-SE 86401 and no To header makes the 400's constructor panic;
// the hand-off to done happens only after the response exists, so the staging
// guard must still release answerMu.
func TestAnswerMuIsReleasedWhenTheRefusalConstructorPanics(t *testing.T) {
	u, d, st, _ := refreshingInboundDialog(t)
	req := sip.NewRequest(sip.UPDATE, sip.Uri{User: "alice", Host: "here"})
	req.AppendHeader(sip.NewHeader("Supported", "timer"))
	req.AppendHeader(sip.NewHeader("Min-SE", "86401"))
	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		_, _ = u.appendInDialogRefreshHeaders(sip.NewResponseFromRequest(updateReq("cid-order", ""), 200, "OK", nil), req, d, st)
	}()
	if !panicked {
		t.Skip("the 400 constructor no longer panics on a To-less request; pick another panic source")
	}
	if !st.answerMu.TryLock() {
		t.Fatal("answerMu still held after the refusal constructor panicked")
	}
	st.answerMu.Unlock()
}
