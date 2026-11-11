// internal/sipua/transfer_internal_test.go
package sipua

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// newNotifyTestDialog registers an answered INBOUND dialog whose peer tag is
// "peer-tag" and returns it with OUR tag (the To-tag a NOTIFY must carry).
func newNotifyTestDialog(u *UA, callID string) (*dialog, string) {
	inv := sip.NewRequest(sip.INVITE, sip.Uri{User: "alice", Host: "here"})
	cid := sip.CallIDHeader(callID)
	inv.AppendHeader(&cid)
	from := &sip.FromHeader{Address: sip.Uri{User: "bob", Host: "peer"}, Params: sip.NewParams()}
	from.Params.Add("tag", "peer-tag")
	inv.AppendHeader(from)
	inv.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "alice", Host: "here"}, Params: sip.NewParams()})
	inv.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})
	d := &dialog{id: "d-" + callID, direction: session.Inbound, phase: phaseAnswered,
		callID: callID, invite: inv, ok: sip.NewResponseFromRequest(inv, 200, "OK", nil)}
	u.register(d)
	ours, _ := d.ok.To().Params.Get("tag")
	return d, ours
}

func referNotifyReq(callID, fromTag, toTag, event, sipfrag string) *sip.Request {
	return referNotifyReqState(callID, fromTag, toTag, event, sipfrag, "terminated")
}

func referNotifyReqState(callID, fromTag, toTag, event, sipfrag, subState string) *sip.Request {
	req := sip.NewRequest(sip.NOTIFY, sip.Uri{User: "alice", Host: "here"})
	cid := sip.CallIDHeader(callID)
	req.AppendHeader(&cid)
	from := &sip.FromHeader{Address: sip.Uri{User: "bob", Host: "peer"}, Params: sip.NewParams()}
	if fromTag != "" {
		from.Params.Add("tag", fromTag)
	}
	req.AppendHeader(from)
	to := &sip.ToHeader{Address: sip.Uri{User: "alice", Host: "here"}, Params: sip.NewParams()}
	to.Params.Add("tag", toTag)
	req.AppendHeader(to)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 9, MethodName: sip.NOTIFY})
	req.AppendHeader(sip.NewHeader("Event", event))
	req.AppendHeader(sip.NewHeader("Subscription-State", subState))
	req.AppendHeader(sip.NewHeader("Content-Type", "message/sipfrag;version=2.0"))
	req.SetBody([]byte(sipfrag + "\r\n"))
	return req
}

func settled(w *referWaiter) bool {
	select {
	case <-w.resolved:
		return true
	default:
		return false
	}
}

// TestOnNotifyRoutesOnlyWhenBothDialogTagsMatch is D13 (Cycle C finding 2,
// case b), amended by CF-176 (RFC 3261 12.2.2; supersedes the transfer wave's
// locked decision 5). A NOTIFY with the right Call-ID, To-tag and id but a
// WRONG or MISSING From-tag matches no dialog: it is answered 481 and routed
// to no waiter. The same NOTIFY with the peer's real tag settles it.
func TestOnNotifyRoutesOnlyWhenBothDialogTagsMatch(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-notify-tags")
	w := newReferWaiter(7, session.TransferBlind)
	u.calls.mu.Lock()
	d.referWaiter = w
	u.calls.mu.Unlock()

	for _, fromTag := range []string{"someone-else", ""} {
		tx := &stubServerTx{}
		u.onNotify(referNotifyReq("cid-notify-tags", fromTag, ours, "refer;id=7", "SIP/2.0 200 OK"), tx)
		if got := tx.last().StatusCode; got != 481 {
			t.Fatalf("From-tag %q: NOTIFY drew %d, want 481", fromTag, got)
		}
		if settled(w) {
			t.Fatalf("From-tag %q: a NOTIFY not from this dialog's peer settled the transfer", fromTag)
		}
	}
	tx := &stubServerTx{}
	u.onNotify(referNotifyReq("cid-notify-tags", "peer-tag", ours, "refer;id=7", "SIP/2.0 200 OK"), tx)
	if got := tx.last().StatusCode; got != 200 || !settled(w) {
		t.Fatalf("matching NOTIFY: code %d, settled %v; want 200 and settled", got, settled(w))
	}
}

// TestOnNotifyLogsACappedFromTagOnAMissedRoute is CF-021: the peer-controlled
// From-tag of a refer NOTIFY that matched no in-flight transfer reaches the
// miss-route Warn log CAPPED, not verbatim — a hostile or misbehaving peer
// could otherwise write an arbitrarily long From-tag straight into the log.
// Since CF-176 a NOTIFY must carry the dialog's peer tag to reach the route at
// all, so the dialog's peer tag is the long tag here and the miss is the
// still-reachable "Event id is not the in-flight REFER's CSeq". The Warn's
// expected_from_tag is our own value and intentionally logged uncapped, so the
// assertions are scoped to the from_tag attribute.
func TestOnNotifyLogsACappedFromTagOnAMissedRoute(t *testing.T) {
	var buf bytes.Buffer
	u, err := New(context.Background(), Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example",
		ExpiresS: 300, Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		WrapConn: func(pc net.PacketConn) net.PacketConn { return pc },
		Logger:   slog.New(slog.NewTextHandler(&buf, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = u.Close(context.Background()) })
	d, ours := newNotifyTestDialog(u, "cid-fromtag-cap")
	w := newReferWaiter(7, session.TransferBlind)
	u.calls.mu.Lock()
	d.referWaiter = w
	u.calls.mu.Unlock()

	longTag := strings.Repeat("Z", referReasonMaxLen+50)
	u.calls.mu.Lock()
	d.invite.From().Params.Add("tag", longTag) // the dialog's peer tag (Add overwrites)
	u.calls.mu.Unlock()
	tx := &stubServerTx{}
	u.onNotify(referNotifyReq("cid-fromtag-cap", longTag, ours, "refer;id=8", "SIP/2.0 200 OK"), tx)
	if got := tx.last().StatusCode; got != 200 {
		t.Fatalf("NOTIFY drew %d, want 200", got)
	}
	if settled(w) {
		t.Fatal("a NOTIFY for another REFER's id settled the transfer")
	}

	logged := buf.String()
	if !strings.Contains(logged, "matched no in-flight transfer") {
		t.Fatalf("no miss-route Warn logged: %s", logged)
	}
	if strings.Contains(logged, " from_tag="+longTag) {
		t.Fatalf("log line contains the full %d-byte uncapped from_tag; want it capped to %d bytes: %s",
			len(longTag), referReasonMaxLen, logged)
	}
	if !strings.Contains(logged, " from_tag="+longTag[:referReasonMaxLen]+" ") {
		t.Fatalf("log line does not contain the capped from_tag's %d-byte prefix: %s", referReasonMaxLen, logged)
	}
}

// TestOnNotifyAcceptsAnIdlessNotifyOnlyWhenNoEarlierSubscriptionMayBeLive is
// D13's routing rule in isolation, bounded by CF-012 (the dialog's count and
// window against the clock's now). The loopback tests
// TestADelayedIdlessNotifyForAnEarlierTransferCannotSettleALaterOne and
// TestAnIdlessNotifyIsAcceptedForARetryWhenNoEarlierSubscriptionCanBeLive
// cover the end-to-end stories.
func TestOnNotifyAcceptsAnIdlessNotifyOnlyWhenNoEarlierSubscriptionMayBeLive(t *testing.T) {
	for _, tc := range []struct {
		name         string
		subs         int
		untilFromNow time.Duration
		wantSettled  bool
	}{
		{"no earlier subscription may be live", 0, time.Hour, true},
		{"one may be live, window still open", 1, time.Second, false},
		{"one may be live, now is exactly the window's end", 1, 0, true},
		{"one may be live, window over", 1, -time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := fakeclock.New(time.Unix(0, 0))
			u := newClaimTestUA(t, clk)
			d, ours := newNotifyTestDialog(u, "cid-gen")
			w := newReferWaiter(7, session.TransferBlind)
			u.calls.mu.Lock()
			d.referSubsMaybeLive = tc.subs
			d.referSubsLiveUntil = u.now().Add(tc.untilFromNow)
			d.referWaiter = w
			u.calls.mu.Unlock()
			tx := &stubServerTx{}
			u.onNotify(referNotifyReq("cid-gen", "peer-tag", ours, "refer", "SIP/2.0 200 OK"), tx)
			if got := tx.last().StatusCode; got != 200 {
				t.Fatalf("id-less NOTIFY drew %d, want 200", got)
			}
			if settled(w) != tc.wantSettled {
				t.Fatalf("settled=%v want %v", settled(w), tc.wantSettled)
			}
		})
	}
}

// TestTerminatedNotifyWithNoTransferInFlightEndsOneMaybeLiveSubscription is
// CF-012's termination evidence: a terminated refer NOTIFY from the peer with no
// transfer in flight ends ONE counted earlier subscription, and only then.
func TestTerminatedNotifyWithNoTransferInFlightEndsOneMaybeLiveSubscription(t *testing.T) {
	for _, tc := range []struct {
		name       string
		subs       int
		fromTag    string
		subState   string
		inFlight   bool
		wantSubs   int
		wantUntil0 bool // referSubsLiveUntil is zero afterwards
		wantCode   int  // 0 means 200; a From-tag that is not the peer's is a 481 (CF-176)
	}{
		{"terminated, no transfer: ends one of two", 2, "peer-tag", "terminated;reason=noresource", false, 1, false, 0},
		{"terminated, no transfer: ends the last", 1, "peer-tag", "terminated;reason=noresource", false, 0, true, 0},
		{"active is not evidence", 2, "peer-tag", "active", false, 2, false, 0},
		{"a wrong From-tag is not the peer's", 2, "other-tag", "terminated;reason=noresource", false, 2, false, 481},
		{"a transfer is in flight", 2, "peer-tag", "terminated;reason=noresource", true, 2, false, 0},
		{"nothing counted stays zero", 0, "peer-tag", "terminated;reason=noresource", false, 0, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
			d, ours := newNotifyTestDialog(u, "cid-evidence")
			until := u.now().Add(time.Hour)
			var w *referWaiter
			u.calls.mu.Lock()
			d.referSubsMaybeLive = tc.subs
			d.referSubsLiveUntil = until
			if tc.inFlight {
				w = newReferWaiter(7, session.TransferBlind)
				d.referWaiter = w
			}
			u.calls.mu.Unlock()
			tx := &stubServerTx{}
			u.onNotify(referNotifyReqState("cid-evidence", tc.fromTag, ours, "refer", "SIP/2.0 486 Busy Here", tc.subState), tx)
			wantCode := tc.wantCode
			if wantCode == 0 {
				wantCode = 200
			}
			if got := int(tx.last().StatusCode); got != wantCode {
				t.Fatalf("NOTIFY drew %d, want %d", got, wantCode)
			}
			u.calls.mu.Lock()
			gotSubs, gotUntil := d.referSubsMaybeLive, d.referSubsLiveUntil
			u.calls.mu.Unlock()
			if gotSubs != tc.wantSubs {
				t.Fatalf("referSubsMaybeLive=%d want %d", gotSubs, tc.wantSubs)
			}
			if tc.wantUntil0 != gotUntil.IsZero() || (!tc.wantUntil0 && !gotUntil.Equal(until)) {
				t.Fatalf("referSubsLiveUntil=%v, want zero=%v (else %v)", gotUntil, tc.wantUntil0, until)
			}
			if tc.inFlight && settled(w) {
				t.Fatal("a refused terminated NOTIFY settled the in-flight transfer")
			}
		})
	}
}

// parkingServerTx parks inside Respond until release is closed, after
// reporting entered. It lets a test hold onNotify at the point where it writes
// its own 200 OK, which is exactly the window where a concurrent peer BYE used
// to win (D16).
type parkingServerTx struct {
	stubServerTx
	entered chan struct{}
	release chan struct{}
}

func (t *parkingServerTx) Respond(r *sip.Response) error {
	close(t.entered)
	<-t.release
	return t.stubServerTx.Respond(r)
}

// peerByeReq is the peer's in-dialog BYE on newNotifyTestDialog's dialog.
func peerByeReq(callID, toTag string) *sip.Request {
	req := sip.NewRequest(sip.BYE, sip.Uri{User: "alice", Host: "here"})
	cid := sip.CallIDHeader(callID)
	req.AppendHeader(&cid)
	from := &sip.FromHeader{Address: sip.Uri{User: "bob", Host: "peer"}, Params: sip.NewParams()}
	from.Params.Add("tag", "peer-tag")
	req.AppendHeader(from)
	to := &sip.ToHeader{Address: sip.Uri{User: "alice", Host: "here"}, Params: sip.NewParams()}
	to.Params.Add("tag", toTag)
	req.AppendHeader(to)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 10, MethodName: sip.BYE})
	return req
}

// startNotifyTransfer puts a newNotifyTestDialog dialog into a transfer's
// NOTIFY wait exactly as Transfer does after a 2xx: claimed, waiter installed,
// awaitReferOutcome running. It returns the UA's transfer events.
func startNotifyTransfer(t *testing.T, u *UA, d *dialog, w *referWaiter) <-chan session.UAEvent {
	t.Helper()
	evs := make(chan session.UAEvent, 8)
	u.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) {
		if ev.Kind == session.UAEventTransfer {
			evs <- ev
		}
	})
	u.calls.mu.Lock()
	ended, err := claimControlOpLocked(d, session.ControlOpTransfer, "call_transfer")
	d.referWaiter = w
	u.calls.mu.Unlock()
	if err != nil {
		t.Fatalf("claimControlOpLocked: %v", err)
	}
	go u.awaitReferOutcome(d, w, ended)
	return evs
}

// TestFinalSuccessNotifyWinsAgainstAConcurrentPeerBye is D16 (Cycle C round 2,
// B1). It reproduces Asterisk's NOTIFY(200 sipfrag)-then-BYE order with sipgo's
// one-goroutine-per-request dispatch. The final NOTIFY is parked inside
// onNotify's own 200 OK write. The peer's BYE is then processed to completion
// on another goroutine, and the transfer must STILL settle as a success.
// Before the fix, onNotify recorded the outcome only after that write, so the
// BYE's teardown (controlOpEnded) was the only signal awaitReferOutcome could
// see, and the transfer settled "the dialog ended before a final NOTIFY",
// deterministically. No sleep: the park is a channel handshake.
//
// It does NOT cover the opposite real order: a BYE that genuinely arrives
// first, then a stale NOTIFY. That NOTIFY correctly draws 481, and the
// transfer correctly settles as "dialog ended" (D16's residual limitation).
func TestFinalSuccessNotifyWinsAgainstAConcurrentPeerBye(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-notify-bye-race")
	w := newReferWaiter(7, session.TransferBlind)
	evs := startNotifyTransfer(t, u, d, w)

	tx := &parkingServerTx{entered: make(chan struct{}), release: make(chan struct{})}
	notifyDone := make(chan struct{})
	go func() {
		defer close(notifyDone)
		u.onNotify(referNotifyReq("cid-notify-bye-race", "peer-tag", ours, "refer;id=7", "SIP/2.0 200 OK"), tx)
	}()
	select {
	case <-tx.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("onNotify never reached its own 200 OK")
	}

	// The final NOTIFY is now parked on its 200 OK. The peer's BYE runs to
	// completion concurrently, on this goroutine.
	u.onBye(peerByeReq("cid-notify-bye-race", ours), &stubServerTx{})

	var final session.UAEvent
	select {
	case final = <-evs:
	case <-time.After(3 * time.Second):
		t.Fatal("no final transfer event after the peer's BYE")
	}
	close(tx.release)
	<-notifyDone
	if final.Detail["final"] != true || final.Detail["success"] != true || final.Code != 200 {
		t.Fatalf("final transfer event %+v: a successful transfer was reported as failed because the "+
			"peer's BYE overtook the final NOTIFY's own 200 OK (D16)", final.Detail)
	}
	select {
	case ev := <-evs:
		t.Fatalf("a second transfer event after the final one: %+v", ev.Detail)
	default:
	}
}

// TestAFinalNotifyIsSettledBeforeAnyRearm is D16's B1a. A FINAL NOTIFY that
// also states active;expires=0 must be recorded as final, never turned into a
// near-zero re-arm that could fire as a timeout first.
func TestAFinalNotifyIsSettledBeforeAnyRearm(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-final-rearm")
	w := newReferWaiter(7, session.TransferBlind)
	u.calls.mu.Lock()
	d.referWaiter = w
	u.calls.mu.Unlock()

	u.onNotify(referNotifyReqState("cid-final-rearm", "peer-tag", ours, "refer;id=7", "SIP/2.0 200 OK", "active;expires=0"), &stubServerTx{})
	if !settled(w) {
		t.Fatal("a final NOTIFY did not settle the waiter")
	}
	u.calls.mu.Lock()
	code := w.code
	u.calls.mu.Unlock()
	if code != 200 {
		t.Fatalf("settled with code %d, want the NOTIFY's 200", code)
	}
	if n := len(w.rearm); n != 0 {
		t.Fatalf("a final NOTIFY queued %d re-arm(s); it must never re-arm the deadline", n)
	}
}

// TestATerminatedSubscriptionEndsTheWaitAtOnce is Cycle C round 2's
// non-blocking 2. A routed NOTIFY whose Subscription-State is terminated, but
// whose sipfrag is provisional or unparseable, means no final status will ever
// come. The wait ends now, with the timeout reason, exactly as expires=0 does
// (D14), instead of running out the deadline. The fake clock is never advanced.
func TestATerminatedSubscriptionEndsTheWaitAtOnce(t *testing.T) {
	for _, tc := range []struct{ name, sipfrag, subState string }{
		{"terminated, provisional sipfrag", "SIP/2.0 180 Ringing", "terminated;reason=timeout"},
		{"terminated, unparseable sipfrag", "garbage", "terminated"},
		{"active;expires=0, provisional sipfrag", "SIP/2.0 100 Trying", "active;expires=0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
			d, ours := newNotifyTestDialog(u, "cid-terminated")
			evs := startNotifyTransfer(t, u, d, newReferWaiter(7, session.TransferBlind))
			u.onNotify(referNotifyReqState("cid-terminated", "peer-tag", ours, "refer;id=7", tc.sipfrag, tc.subState), &stubServerTx{})
			select {
			case ev := <-evs:
				if ev.Detail["final"] != true || ev.Detail["reason"] != referReasonTimeout || ev.Code != 0 {
					t.Fatalf("event %+v, want the final timeout-reason outcome", ev.Detail)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the transfer kept waiting after the notifier ended the subscription")
			}
		})
	}
}

// TestConcludeReferRecordsWhetherAnEarlierSubscriptionMayBeLive is D13's
// bookkeeping in isolation, bounded by CF-012. A REFER whose subscription is not
// known to be over adds one to the dialog's count and extends the window to the
// ceiling plus Timer F (or the notifier's stated end plus Timer F, if later,
// never shortening another window). One known to be over (never created, or
// terminated by the notifier) records nothing. A window that has already ended
// stops counting its subscriptions.
func TestConcludeReferRecordsWhetherAnEarlierSubscriptionMayBeLive(t *testing.T) {
	const day = 24 * time.Hour
	base := time.Unix(1000, 0)
	ceiling := base.Add(referOutcomeMaxWait + sip.Timer_F)
	for _, tc := range []struct {
		name             string
		subsBefore       int
		untilBefore      time.Time
		subscriptionOver bool
		extendExp        time.Duration // 0: no stated expiry
		wantSubs         int
		wantUntil        time.Time
	}{
		{"subscription may be live", 0, time.Time{}, false, 0, 1, ceiling},
		{"subscription over", 0, time.Time{}, true, 0, 0, time.Time{}},
		{"subscription over, one already counted", 1, ceiling, true, 0, 1, ceiling},
		{"a stated end later than the ceiling wins", 0, time.Time{}, false, 900 * time.Second, 1, base.Add(900*time.Second + sip.Timer_F)},
		{"earlier window over: stop counting, then count this one", 3, base.Add(-time.Second), false, 0, 1, ceiling},
		{"another window ends later: kept, counted", 1, base.Add(day), false, 0, 2, base.Add(day)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := fakeclock.New(base)
			u := newClaimTestUA(t, clk)
			d, _ := newNotifyTestDialog(u, "cid-conclude")
			w := newReferWaiter(7, session.TransferBlind)
			u.calls.mu.Lock()
			d.referSubsMaybeLive, d.referSubsLiveUntil = tc.subsBefore, tc.untilBefore
			w.subscriptionOver = tc.subscriptionOver
			if tc.extendExp > 0 {
				w.extendLocked(tc.extendExp, base)
			}
			d.referWaiter = w
			u.calls.mu.Unlock()
			u.concludeRefer(d, w, 0, referReasonTimeout)
			u.calls.mu.Lock()
			gotSubs, gotUntil := d.referSubsMaybeLive, d.referSubsLiveUntil
			u.calls.mu.Unlock()
			if gotSubs != tc.wantSubs || !gotUntil.Equal(tc.wantUntil) {
				t.Fatalf("subs=%d until=%v, want subs=%d until=%v", gotSubs, gotUntil, tc.wantSubs, tc.wantUntil)
			}
		})
	}
}

// TestConcludeReferCapsAPeerSuppliedReasonButNeverTruncatesOurOwnConstants is
// CF-006: a peer-supplied NOTIFY/REFER reason string is capped before it
// reaches a transfer event's Detail, but this package's own six documented
// "no wire status" reason constants (spec §10.14) are never touched by that
// cap, however it is implemented.
//
// CF-019 moved the cap to the two ingestion points (Transfer's own read of a
// REFER response's res.Reason, and onNotify's read of a NOTIFY's parsed
// sipfrag reason); concludeRefer itself no longer re-caps its reason argument,
// so it no longer has a "long peer-supplied reason is capped" case of its own
// to test — every real caller already passes an already-capped value.
// TestTransferNonSuccessReasonIsCappedInTheReturnedResult and
// TestTransferAcceptedReasonIsCappedInTheReturnedResult (transfer_test.go)
// cover the REFER-response ingestion point end to end, and
// TestFinalNotifyWithALongPeerReasonIsCappedDespiteSettleLockedsFirstWins and
// TestProvisionalNotifyWithALongPeerReasonIsCapped (below) cover the NOTIFY
// one.
func TestConcludeReferCapsAPeerSuppliedReasonButNeverTruncatesOurOwnConstants(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))

	for _, own := range []string{
		referReasonNoResponse, referReasonNotSent, referReasonTimeout, referReasonEnded,
		referReasonHungUp, referReasonUAClosed,
	} {
		own := own
		t.Run("own constant "+own+" is never truncated", func(t *testing.T) {
			d, _ := newNotifyTestDialog(u, "cid-reason-cap-"+own)
			w := newReferWaiter(7, session.TransferBlind)
			u.calls.mu.Lock()
			d.referWaiter = w
			u.calls.mu.Unlock()
			u.concludeRefer(d, w, 0, own)
			u.calls.mu.Lock()
			got := w.reason
			u.calls.mu.Unlock()
			if got != own {
				t.Fatalf("own reason constant %q was altered to %q", own, got)
			}
		})
	}
}

// TestFinalNotifyWithALongPeerReasonIsCappedDespiteSettleLockedsFirstWins is
// CF-006 (Cycle C fix): a final NOTIFY records its reason through
// resolveLocked, BEFORE concludeRefer ever runs. settleLocked's
// first-settle-wins (D16) then returns that already-recorded reason verbatim,
// discarding whatever concludeRefer's own argument was capped to — so capping
// only at concludeRefer's entry never touches this path. The cap must apply to
// the sipfrag-parsed reason itself, in onNotify, before resolveLocked stores it.
func TestFinalNotifyWithALongPeerReasonIsCappedDespiteSettleLockedsFirstWins(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-final-notify-cap")
	w := newReferWaiter(7, session.TransferBlind)
	evs := startNotifyTransfer(t, u, d, w)

	long := strings.Repeat("A", referReasonMaxLen+50)
	u.onNotify(referNotifyReq("cid-final-notify-cap", "peer-tag", ours, "refer;id=7", "SIP/2.0 200 "+long), &stubServerTx{})

	var final session.UAEvent
	select {
	case final = <-evs:
	case <-time.After(3 * time.Second):
		t.Fatal("no final transfer event after the final NOTIFY")
	}
	got, _ := final.Detail["reason"].(string)
	if len(got) != referReasonMaxLen || got != long[:referReasonMaxLen] {
		t.Fatalf("final NOTIFY reason=%q (len %d) want the first %d bytes of the peer-supplied text",
			got, len(got), referReasonMaxLen)
	}
}

// TestProvisionalNotifyWithALongPeerReasonIsCapped is CF-006 (Cycle C fix): a
// provisional NOTIFY's reason reaches emitReferProvisional directly, never
// through concludeRefer, so capping only at concludeRefer's entry never
// touches this path either.
func TestProvisionalNotifyWithALongPeerReasonIsCapped(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-provisional-notify-cap")
	w := newReferWaiter(7, session.TransferBlind)
	evs := startNotifyTransfer(t, u, d, w)

	long := strings.Repeat("A", referReasonMaxLen+50)
	u.onNotify(referNotifyReqState("cid-provisional-notify-cap", "peer-tag", ours, "refer;id=7",
		"SIP/2.0 100 "+long, "active;expires=60"), &stubServerTx{})

	var prov session.UAEvent
	select {
	case prov = <-evs:
	case <-time.After(3 * time.Second):
		t.Fatal("no provisional transfer event after the provisional NOTIFY")
	}
	if prov.Detail["final"] != false {
		t.Fatalf("event %+v is not provisional", prov.Detail)
	}
	got, _ := prov.Detail["reason"].(string)
	if len(got) != referReasonMaxLen || got != long[:referReasonMaxLen] {
		t.Fatalf("provisional NOTIFY reason=%q (len %d) want the first %d bytes of the peer-supplied text",
			got, len(got), referReasonMaxLen)
	}
}

// TestCapReferReasonNeverSplitsAMultibyteRune is CF-006 (Cycle C round 4 fix):
// a raw byte-offset truncation can cut a multi-byte UTF-8 rune in half,
// producing an invalid string. capReferReason must back off to the last full
// rune instead.
func TestCapReferReasonNeverSplitsAMultibyteRune(t *testing.T) {
	// "é" is 2 bytes (0xC3 0xA9); placed so a raw byte-256 cut would fall
	// exactly between them.
	prefix := strings.Repeat("A", referReasonMaxLen-1)
	s := prefix + "é" + "more text after the cap point"
	got := capReferReason(s)
	if !utf8.ValidString(got) {
		t.Fatalf("capReferReason(%d-byte input) = %q, not valid UTF-8", len(s), got)
	}
	if len(got) > referReasonMaxLen {
		t.Fatalf("capReferReason result is %d bytes, want <= %d", len(got), referReasonMaxLen)
	}
	if got != prefix {
		t.Fatalf("capReferReason(...) = %q, want exactly the %d-byte prefix (the split rune dropped, not mangled)",
			got, len(prefix))
	}
}

// TestCapReferReasonLeavesAnExactlyMaxLenInputUntouched is Rule 13 wave
// review, Cycle 4: every existing capReferReason test is either well over
// referReasonMaxLen or one rune past it (the multibyte-rune test above);
// none pins the exact boundary (len(s) == referReasonMaxLen), where a
// strict-vs-loose comparison (`<=` vs `<`) in the implementation's fast path
// changes behavior.
func TestCapReferReasonLeavesAnExactlyMaxLenInputUntouched(t *testing.T) {
	s := strings.Repeat("A", referReasonMaxLen)
	if got := capReferReason(s); got != s {
		t.Fatalf("capReferReason(%d-byte input) = %q (len %d), want the input unchanged", len(s), got, len(got))
	}
}

func TestParseSubscriptionExpires(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"active;expires=90", 90 * time.Second, true},
		{" Pending ; EXPIRES = 30 ", 30 * time.Second, true},
		{"active;retry-after=5;expires=60", 60 * time.Second, true},
		{"active;expires=0", 0, true},
		{"active", 0, false},
		{"active;expires=abc", 0, false},
		{"active;expires=-5", 0, false},
		{"terminated;reason=noresource", 0, false},
		{"terminated;expires=60", 0, false}, // a terminated subscription states no remaining life
		{"", 0, false},
	} {
		got, ok := parseSubscriptionExpires(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parseSubscriptionExpires(%q)=(%v,%v) want (%v,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestReferOutcomeWindowIsBoundedByTheAbsoluteCeiling is D14's ceiling: a
// notifier-stated duration is honoured only up to what remains before
// acceptedAt + referOutcomeMaxWait, so re-arming NOTIFYs cannot stretch the
// wait without bound.
func TestReferOutcomeWindowIsBoundedByTheAbsoluteCeiling(t *testing.T) {
	accepted := time.Unix(1000, 0)
	hardStop := accepted.Add(referOutcomeMaxWait)
	for _, tc := range []struct {
		name    string
		expires time.Duration
		now     time.Time
		want    time.Duration
	}{
		{"under the ceiling", 90 * time.Second, accepted, 90 * time.Second},
		{"clamped to the ceiling", time.Hour, accepted, referOutcomeMaxWait},
		{"clamped to what remains", 200 * time.Second, accepted.Add(250 * time.Second), 50 * time.Second},
		{"past the ceiling", 60 * time.Second, hardStop.Add(time.Second), 0},
		{"expires=0 ends the wait now", 0, accepted, 0},
	} {
		if got := referOutcomeWindow(tc.expires, tc.now, hardStop); got != tc.want {
			t.Errorf("%s: referOutcomeWindow=%v want %v", tc.name, got, tc.want)
		}
	}
}

// TestAFinalNotifyThatArrivedFirstWinsEvenWhenTheByesHandlerRunsFirst is D18
// (Cycle C round 3): the ADVERSE schedule. The final NOTIFY reaches the
// transport FIRST: observeArrival is called for it first, exactly as sipgo's read
// loop does. But its goroutine is delayed, and the BYE's handler runs before the
// NOTIFY's handler has started at all. Under D16 alone, the BYE takes u.calls.mu
// first and tears the dialog down, the NOTIFY draws 481, and the transfer settles
// success:false every time. With D18 the BYE waits at the gate, the NOTIFY is
// applied first, and the transfer succeeds. No sleep. The BYE's wait is observed
// through arrivalWaitHook, and the "delayed goroutine" is simply the test not
// calling onNotify yet.
func TestAFinalNotifyThatArrivedFirstWinsEvenWhenTheByesHandlerRunsFirst(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-arrival-notify-first")
	evs := startNotifyTransfer(t, u, d, newReferWaiter(7, session.TransferBlind))
	notify := referNotifyReq("cid-arrival-notify-first", "peer-tag", ours, "refer;id=7", "SIP/2.0 200 OK") // CSeq 9
	bye := peerByeReq("cid-arrival-notify-first", ours)                                                    // CSeq 10
	waiting := setArrivalWaitHook(t, sip.BYE)

	// sipgo's transport read loop, in wire order: the NOTIFY, then the BYE.
	u.observeArrival(notify)
	u.observeArrival(bye)

	// The adverse schedule: the BYE's goroutine runs; the NOTIFY's has not started.
	byeDone := make(chan struct{})
	go func() {
		defer close(byeDone)
		u.onBye(bye, &stubServerTx{})
	}()
	select {
	case <-waiting:
	case <-byeDone:
		t.Fatal("the peer's BYE was applied before the final NOTIFY that reached the transport ahead of it (D18)")
	case <-time.After(3 * time.Second):
		t.Fatal("onBye neither waited for the earlier NOTIFY nor finished")
	}

	// The delayed NOTIFY goroutine finally runs.
	tx := &stubServerTx{}
	u.onNotify(notify, tx)
	if got := tx.last().StatusCode; got != 200 {
		t.Fatalf("the final NOTIFY drew %d, want 200: the BYE tore the dialog down first", got)
	}
	select {
	case <-byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("onBye stayed behind the gate after the NOTIFY left it")
	}

	var final session.UAEvent
	select {
	case final = <-evs:
	case <-time.After(3 * time.Second):
		t.Fatal("no final transfer event")
	}
	if final.Detail["final"] != true || final.Detail["success"] != true || final.Code != 200 {
		t.Fatalf("final transfer event %+v: a transfer whose final NOTIFY reached the wire before the "+
			"peer's BYE was reported as failed (D18)", final.Detail)
	}
	select {
	case ev := <-evs:
		t.Fatalf("a second transfer event after the final one: %+v", ev.Detail)
	default:
	}
	u.calls.mu.Lock()
	ph := d.phase
	u.calls.mu.Unlock()
	if ph != phaseDone {
		t.Fatalf("phase=%v after the BYE; the BYE must still be applied, after the NOTIFY", ph)
	}
}

// TestAPeerByeThatArrivedFirstWinsEvenWhenTheNotifysHandlerRunsFirst is D18's
// mirror image, and the other half of "wire order, not lock order". The BYE
// reaches the transport first. A stale final NOTIFY (a late retransmission,
// lower CSeq) is read after it, but its handler is scheduled first. It must wait
// for the BYE and then draw 481, and the transfer settles "the dialog ended
// before a final NOTIFY", because the dialog really was gone when the NOTIFY
// arrived.
func TestAPeerByeThatArrivedFirstWinsEvenWhenTheNotifysHandlerRunsFirst(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-arrival-bye-first")
	evs := startNotifyTransfer(t, u, d, newReferWaiter(7, session.TransferBlind))
	notify := referNotifyReq("cid-arrival-bye-first", "peer-tag", ours, "refer;id=7", "SIP/2.0 200 OK") // CSeq 9
	bye := peerByeReq("cid-arrival-bye-first", ours)                                                    // CSeq 10
	waiting := setArrivalWaitHook(t, sip.NOTIFY)

	// Wire order: the BYE, then the stale NOTIFY. The observer skips the NOTIFY
	// (CSeq 9 is not above 10), so its handler tickets itself behind the BYE.
	u.observeArrival(bye)
	u.observeArrival(notify)

	tx := &stubServerTx{}
	notifyDone := make(chan struct{})
	go func() {
		defer close(notifyDone)
		u.onNotify(notify, tx)
	}()
	select {
	case <-waiting:
	case <-notifyDone:
		t.Fatal("the NOTIFY was applied before the BYE that reached the transport ahead of it (D18)")
	case <-time.After(3 * time.Second):
		t.Fatal("onNotify neither waited for the earlier BYE nor finished")
	}

	u.onBye(bye, &stubServerTx{})
	select {
	case <-notifyDone:
	case <-time.After(3 * time.Second):
		t.Fatal("onNotify stayed behind the gate after the BYE left it")
	}
	if got := tx.last().StatusCode; got != 481 {
		t.Fatalf("the NOTIFY that arrived after the BYE drew %d, want 481", got)
	}
	select {
	case final := <-evs:
		if final.Detail["final"] != true || final.Detail["success"] != false ||
			final.Detail["reason"] != referReasonEnded || final.Code != 0 {
			t.Fatalf("final transfer event %+v, want the %q outcome", final.Detail, referReasonEnded)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no final transfer event after the peer's BYE")
	}
}

// TestAProvisionalExtensionAcceptedJustBeforeTheOldDeadlineBeatsTheStaleTimer is
// D14's re-arm guarantee under the adverse interleaving (Rule 13 fix batch A,
// finding 1). A provisional NOTIFY stating active;expires=90 is accepted under
// u.calls.mu one second before the default deadline, then parks in its own 200
// OK write, BEFORE it emits or re-arms. The old deadline then passes, so the
// stale timer is the ONLY thing awaitReferOutcome can select. The extension was
// already accepted on the wire, so the wait must continue against the new
// deadline (119 s + 90 s, i.e. 89 s from now) instead of settling as a timeout.
// No sleep: the park is a channel handshake and the clock is fake.
func TestAProvisionalExtensionAcceptedJustBeforeTheOldDeadlineBeatsTheStaleTimer(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	u := newClaimTestUA(t, clk)
	armed := make(chan time.Duration, 8)
	SetReferOutcomeArmHook(func(wait time.Duration) { armed <- wait })
	t.Cleanup(func() { SetReferOutcomeArmHook(nil) })
	d, ours := newNotifyTestDialog(u, "cid-extend-race")
	evs := startNotifyTransfer(t, u, d, newReferWaiter(7, session.TransferBlind))
	nextArmed := func() time.Duration {
		t.Helper()
		select {
		case w := <-armed:
			return w
		case ev := <-evs:
			t.Fatalf("the transfer settled (%+v) instead of re-arming its deadline", ev.Detail)
		case <-time.After(3 * time.Second):
			t.Fatal("the outcome timer was never (re)armed")
		}
		return 0
	}
	if got := nextArmed(); got != referOutcomeDefaultWait {
		t.Fatalf("initial window %v, want %v", got, referOutcomeDefaultWait)
	}

	clk.Advance(referOutcomeDefaultWait - time.Second)
	tx := &parkingServerTx{entered: make(chan struct{}), release: make(chan struct{})}
	notifyDone := make(chan struct{})
	go func() {
		defer close(notifyDone)
		u.onNotify(referNotifyReqState("cid-extend-race", "peer-tag", ours, "refer;id=7",
			"SIP/2.0 180 Ringing", "active;expires=90"), tx)
	}()
	select {
	case <-tx.entered: // accepted under u.calls.mu; not yet emitted or re-armed
	case <-time.After(3 * time.Second):
		t.Fatal("onNotify never reached its own 200 OK")
	}

	clk.Advance(time.Second) // the OLD deadline: only the stale timer is ready
	if got := nextArmed(); got != 89*time.Second {
		t.Fatalf("re-armed window %v, want 89s (the accepted NOTIFY's arrival + 90s)", got)
	}
	close(tx.release)
	<-notifyDone
	select {
	case ev := <-evs:
		if ev.Detail["final"] != false || ev.Code != 180 {
			t.Fatalf("event %+v, want the provisional 180", ev.Detail)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no provisional transfer event for the accepted NOTIFY")
	}

	u.onNotify(referNotifyReq("cid-extend-race", "peer-tag", ours, "refer;id=7", "SIP/2.0 200 OK"), &stubServerTx{})
	select {
	case ev := <-evs:
		if ev.Detail["final"] != true || ev.Detail["success"] != true || ev.Code != 200 {
			t.Fatalf("final event %+v, want the successful 200", ev.Detail)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no final transfer event")
	}
}

// TestTheUAClosingSettlesAPendingTransfer covers awaitReferOutcome's uaDone
// branch (Rule 13 fix batch A, finding 2). The UA's own lifetime ends while the
// NOTIFY outcome is pending, with no advance of the clock. The transfer settles
// at once, with exactly the documented referReasonUAClosed reason, and releases
// the control op.
//
// The waiter gets its OWN uaCtx, swapped in before awaitReferOutcome reads it.
// Cancelling the UA's real uaCtx would also run New's lifetime watcher, whose
// stopAllMediaLoops tears the dialog down and closes controlOpEnded: then both
// select arms are ready and the reported reason is scheduling-dependent. Only
// the uaDone arm is under test here.
func TestTheUAClosingSettlesAPendingTransfer(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, _ := newNotifyTestDialog(u, "cid-ua-closed")
	uaCtx, closeUA := context.WithCancel(context.Background())
	realCtx := u.uaCtx
	u.uaCtx = uaCtx
	t.Cleanup(func() { u.uaCtx = realCtx })
	evs := startNotifyTransfer(t, u, d, newReferWaiter(7, session.TransferBlind))

	closeUA() // the UA's lifetime ends; nothing tears the dialog down
	select {
	case ev := <-evs:
		if ev.Detail["final"] != true || ev.Detail["reason"] != "the user agent closed before a final NOTIFY" || ev.Code != 0 {
			t.Fatalf("event %+v, want the final %q outcome", ev.Detail, "the user agent closed before a final NOTIFY")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the transfer kept waiting after the user agent closed")
	}
	u.calls.mu.Lock()
	ph, w := d.phase, d.referWaiter
	u.calls.mu.Unlock()
	if ph == phaseControlOp || w != nil {
		t.Fatalf("phase=%v referWaiter=%v after the UA closed; the control op must be released", ph, w)
	}
}

// TestARetransmittedTerminatedNotifyEndsOneSubscriptionOnce: sipgo terminates a
// NOTIFY's server transaction when the handler returns, so a retransmission that
// arrives later runs onNotify again. It carries the same CSeq and must not end a
// second counted subscription; a NOTIFY with a higher CSeq does.
func TestARetransmittedTerminatedNotifyEndsOneSubscriptionOnce(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-retrans")
	u.calls.mu.Lock()
	d.referSubsMaybeLive = 2
	d.referSubsLiveUntil = u.now().Add(time.Hour)
	u.calls.mu.Unlock()
	send := func(cseq uint32) {
		req := referNotifyReqState("cid-retrans", "peer-tag", ours, "refer", "SIP/2.0 486 Busy Here", "terminated;reason=noresource")
		req.CSeq().SeqNo = cseq
		tx := &stubServerTx{}
		u.onNotify(req, tx)
		if got := tx.last().StatusCode; got != 200 {
			t.Fatalf("NOTIFY cseq %d drew %d, want 200", cseq, got)
		}
	}
	subs := func() int {
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		return d.referSubsMaybeLive
	}
	send(9)
	send(9) // the retransmission
	if got := subs(); got != 1 {
		t.Fatalf("after a terminated NOTIFY and its retransmission: %d counted, want 1", got)
	}
	send(10)
	if got := subs(); got != 0 {
		t.Fatalf("after a second terminated NOTIFY with a higher CSeq: %d counted, want 0", got)
	}
}
