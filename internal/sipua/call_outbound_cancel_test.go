package sipua_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// Hanging up an outbound call that is still ringing must CANCEL the INVITE
// (RFC 3261 §9.1). It used to be refused precondition_failed ("a BYE can only
// end an answered dialog") while the session layer had already recorded the
// call terminated, so the far end kept ringing — found with a live packet
// capture.

// waitPeerCount polls until the peer has received at least n requests of
// method, failing after 3s.
func waitPeerCount(t *testing.T, p *peer.Peer, method string, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for p.Count(method) < n {
		if time.Now().After(deadline) {
			t.Fatalf("peer received %d %s within 3s, want >= %d; methods: %v",
				p.Count(method), method, n, p.Methods())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// cseqNum is the sequence-number half of a CSeq header value ("7 INVITE").
func cseqNum(v string) string {
	n, _, _ := strings.Cut(strings.TrimSpace(v), " ")
	return n
}

// hangupResult is one asynchronous Hangup's outcome and when it returned.
type hangupResult struct {
	err error
	at  time.Time
}

// hangupAsync runs Hangup on its own goroutine, for the deferred-CANCEL cases
// in which it now BLOCKS until the CANCEL is written or the dial settles.
func hangupAsync(ua interface {
	Hangup(context.Context, string, string) error
}, dialogID string) <-chan hangupResult {
	done := make(chan hangupResult, 1)
	go func() {
		err := ua.Hangup(context.Background(), dialogID, "")
		done <- hangupResult{err: err, at: time.Now()}
	}()
	return done
}

// assertCancelMatchesLastInvite checks the CANCEL the peer received against the
// LAST INVITE it received: same Call-ID, same CSeq number with method CANCEL,
// and the same top-Via branch — the three things a UAS matches a CANCEL to its
// INVITE transaction by — plus the same From and To (RFC 3261 §9.1: the To
// carries no tag the INVITE did not) and no body.
func assertCancelMatchesLastInvite(t *testing.T, p *peer.Peer) {
	t.Helper()
	for _, h := range []string{"From", "To"} {
		if got, want := p.LastRequestHeader("CANCEL", h), p.LastRequestHeader("INVITE", h); got == "" || got != want {
			t.Errorf("CANCEL %s = %q, want the INVITE's %q", h, got, want)
		}
	}
	invCSeq, canCSeq := p.LastRequestHeader("INVITE", "CSeq"), p.LastRequestHeader("CANCEL", "CSeq")
	if !strings.HasSuffix(strings.TrimSpace(canCSeq), "CANCEL") || cseqNum(canCSeq) != cseqNum(invCSeq) {
		t.Errorf("CANCEL CSeq = %q, want the INVITE's number with method CANCEL (INVITE CSeq %q)", canCSeq, invCSeq)
	}
	if got, want := p.LastRequestHeader("CANCEL", "Call-ID"), p.LastRequestHeader("INVITE", "Call-ID"); got == "" || got != want {
		t.Errorf("CANCEL Call-ID = %q, want the INVITE's %q", got, want)
	}
	invVia, canVia := p.LastRequestHeader("INVITE", "Via"), p.LastRequestHeader("CANCEL", "Via")
	if b := branchOf(canVia); b == "" || b != branchOf(invVia) {
		t.Errorf("CANCEL top-Via branch = %q, want the INVITE's %q (Via %q vs %q)", b, branchOf(invVia), canVia, invVia)
	}
	if body := p.LastRequestBody("CANCEL"); body != "" {
		t.Errorf("CANCEL carries a body %q, want none", body)
	}
}

// Criterion A: ringing -> Hangup puts a CANCEL on the wire, returns without
// waiting for the 487, and the peer's 487 then ends the dialog with NO BYE.
func TestHangupWhileRingingSendsCancelAndA487EndsTheDialogWithoutBye(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RingThenSilent: true}})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventProvisional, 180)

	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup on a ringing outbound call = %v, want nil (CANCEL sent)", err)
	}
	waitPeerCount(t, p, "CANCEL", 1)
	assertCancelMatchesLastInvite(t, p)

	p.SendFinal(t, res.CallID, 487)
	waitFor(t, events, session.UAEventFinal, 487)
	deadline := time.Now().Add(2 * time.Second)
	for ua.RegisteredDialogCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := ua.RegisteredDialogCount(); n != 0 {
		t.Fatalf("%d dialogs still registered after the 487, want 0", n)
	}
	time.Sleep(150 * time.Millisecond)
	if n := p.ByeCount(); n != 0 {
		t.Fatalf("peer received %d BYE after a 487 ended the cancelled INVITE, want 0", n)
	}
	if n := p.Count("CANCEL"); n != 1 {
		t.Fatalf("peer received %d CANCEL, want exactly 1", n)
	}
}

// Criterion B: a hangup before ANY provisional sends no CANCEL (RFC 3261 §9.1
// forbids it) until the first 1xx arrives, and then exactly one. Hangup BLOCKS
// meanwhile and returns only once that CANCEL is on the wire.
func TestHangupBeforeAnyProvisionalDefersTheCancelUntilTheFirst1xx(t *testing.T) {
	release := make(chan struct{})
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{RingThenSilent: true, HoldProvisionals: release}})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeerCount(t, p, "INVITE", 1)

	done := hangupAsync(ua, res.DialogID)
	time.Sleep(200 * time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("Hangup before any provisional returned (%v) before the CANCEL could be sent", r.err)
	default:
	}
	if n := p.Count("CANCEL"); n != 0 {
		t.Fatalf("peer received %d CANCEL before any provisional, want 0 (RFC 3261 §9.1)", n)
	}

	close(release)
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Hangup = %v, want nil once the deferred CANCEL is sent", r.err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Hangup did not return promptly after the first provisional released its CANCEL")
	}
	waitPeerCount(t, p, "CANCEL", 1)
	assertCancelMatchesLastInvite(t, p)
	// The peer 200s the CANCEL on receipt; give the UA time to complete that
	// transaction, then a provisional arriving AFTER it must not draw a second
	// CANCEL.
	time.Sleep(200 * time.Millisecond)
	p.SendProvisional(t, res.CallID, 180)
	time.Sleep(200 * time.Millisecond)
	if n := p.Count("CANCEL"); n != 1 {
		t.Fatalf("peer received %d CANCEL, want exactly 1", n)
	}

	p.SendFinal(t, res.CallID, 487)
	waitFor(t, events, session.UAEventFinal, 487)
}

// Criterion C: a 200 OK that crosses the CANCEL must be ACKed and then BYE'd,
// exactly once, and the dialog must end.
func TestA200CrossingTheCancelIsAckedThenByedOnce(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RingThenSilent: true}})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventProvisional, 180)
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	waitPeerCount(t, p, "CANCEL", 1)

	// The far end answered anyway: its 200 crossed our CANCEL on the wire.
	p.SendFinal(t, res.CallID, 200)
	p.WaitForBye(t, 3*time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for ua.RegisteredDialogCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := ua.RegisteredDialogCount(); n != 0 {
		t.Fatalf("%d dialogs still registered after the crossing 200 was BYE'd, want 0", n)
	}
	time.Sleep(150 * time.Millisecond)
	if !p.AckBeforeBye() {
		t.Errorf("peer methods %v: want the 200 ACKed before the BYE", p.Methods())
	}
	if n := p.ByeCount(); n != 1 {
		t.Fatalf("peer received %d BYE, want exactly 1", n)
	}
	if n := p.Count("ACK"); n != 1 {
		t.Fatalf("peer received %d ACK for the crossing 200, want exactly 1", n)
	}
	// The call was already hung up: runDial must not report it answered.
	for _, ev := range events() {
		if ev.Kind == session.UAEventFinal && ev.Code == 200 {
			t.Fatalf("a UAEventFinal(200) was emitted for a call the caller had already hung up: %v", kinds(events()))
		}
	}
}

// Criterion D: on a digest-challenged dial the CANCEL must target the AUTHED
// INVITE (the one outstanding), not the first, challenged one — the retry
// carries a new branch and a higher CSeq.
func TestCancelOnADigestChallengedDialMatchesTheAuthedInvite(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t",
		Behaviour: peer.Behaviour{RingThenSilent: true}})
	ua := newDirectAuthUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventProvisional, 180)
	seqs := p.CSeqs("INVITE")
	if len(seqs) < 2 || seqs[len(seqs)-1] <= seqs[0] {
		t.Fatalf("INVITE CSeqs %v: want a challenged INVITE then a higher-CSeq authed retry", seqs)
	}

	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	waitPeerCount(t, p, "CANCEL", 1)
	assertCancelMatchesLastInvite(t, p)
	if got := cseqNum(p.LastRequestHeader("CANCEL", "CSeq")); got == strconv.FormatUint(uint64(seqs[0]), 10) {
		t.Fatalf("CANCEL CSeq %s is the CHALLENGED INVITE's; want the authed retry's %d", got, seqs[len(seqs)-1])
	}
}

// Inbound, still ringing: Hangup (ua_destroy's path) declines it with 603.
func TestHangupOnARingingInboundCallDeclinesIt603(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	incoming := waitFor(t, events, session.UAEventInbound, 0)
	waitForCode(t, p, 180)

	if err := ua.Hangup(context.Background(), incoming.DialogID, ""); err != nil {
		t.Fatalf("Hangup on a ringing inbound call = %v, want nil (603 sent)", err)
	}
	if code := p.WaitForInviteFinal(t, 3*time.Second); code != 603 {
		t.Fatalf("caller received final %d, want 603 Decline", code)
	}
	// CF-033(b): exactly one final on the wire. Pins the behaviour of the
	// inline claim; it passes on the old Reject-based path too, because the
	// Answer-race window that differed is too narrow to hit deterministically.
	time.Sleep(150 * time.Millisecond)
	n := 0
	for _, c := range p.ResponseCodes() {
		if c >= 200 {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("caller saw %d final responses %v, want exactly one 603", n, p.ResponseCodes())
	}
}

// pollFast is a 200us-cadence poll (the stock helpers poll every 5ms, which
// would dominate a several-hundred-iteration stress loop), failing after 3s.
func pollFast(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 3s")
		}
		time.Sleep(200 * time.Microsecond)
	}
}

func hasCode(codes []int, want int) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}

// CF-033(b) stress: Hangup and Answer racing on a ringing inbound call. Hangup
// must never surface Reject's "call_reject requires" precondition error (the
// old ringing special case unlocked between its phase check and Reject's own
// re-check, so an Answer landing in that window tripped it), and the caller
// must never see both a 603 and a 200. Hangup returning the phase error when
// Answer wins is legitimate and not asserted on. Probabilistic: ~10/400 red on
// the pre-fix code, 0/400 on the fix.
func TestHangupRacingAnswerOnARingingInboundCallNeverReportsRejectPrecondition(t *testing.T) {
	const iterations = 400
	for i := 0; i < iterations; i++ {
		t.Run("", func(t *testing.T) {
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
			ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
			events := collect(t, ua)

			p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
			var incoming session.UAEvent
			pollFast(t, func() bool {
				for _, ev := range events() {
					if ev.Kind == session.UAEventInbound {
						incoming = ev
						return true
					}
				}
				return false
			})
			pollFast(t, func() bool { return hasCode(p.ResponseCodes(), 180) })

			start := make(chan struct{})
			var wg sync.WaitGroup
			var hangErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				hangErr = ua.Hangup(context.Background(), incoming.DialogID, "")
			}()
			go func() {
				defer wg.Done()
				<-start
				_ = ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID})
			}()
			close(start)
			wg.Wait()

			if hangErr != nil && strings.Contains(hangErr.Error(), "call_reject requires") {
				t.Fatalf("Hangup leaked Reject's precondition error: %v", hangErr)
			}
			pollFast(t, func() bool { return p.InviteFinalCode() != 0 })
			time.Sleep(2 * time.Millisecond)
			var declines, oks int
			for _, c := range p.ResponseCodes() {
				switch c {
				case 603:
					declines++
				case 200:
					oks++
				}
			}
			if declines > 1 || (declines == 1 && oks > 0) {
				t.Fatalf("caller saw %d x 603 and %d x 200 (%v), want exactly one kind of final", declines, oks, p.ResponseCodes())
			}
		})
	}
}

// Inbound, still being admitted (no 180 yet): Hangup declines it 603 and the
// 180 onInvite would have sent never follows.
func TestHangupOnAnInboundCallStillBeingAdmittedDeclinesIt603(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))

	admitted := make(chan string, 1)
	proceed := make(chan struct{})
	ua.OnAdmit(context.Background(), func(_ context.Context, ev session.UAEvent) session.Admission {
		admitted <- ev.DialogID
		<-proceed
		return session.AdmitAccept()
	})

	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	var id string
	select {
	case id = <-admitted:
	case <-time.After(3 * time.Second):
		t.Fatal("the INVITE never reached admission")
	}
	err := ua.Hangup(context.Background(), id, "")
	close(proceed)
	if err != nil {
		t.Fatalf("Hangup on an inbound call mid-admission = %v, want nil (603 sent)", err)
	}
	if code := p.WaitForInviteFinal(t, 3*time.Second); code != 603 {
		t.Fatalf("caller received final %d, want 603 Decline", code)
	}
	time.Sleep(150 * time.Millisecond)
	for _, c := range p.ResponseCodes() {
		if c == 180 {
			t.Fatalf("caller received a 180 after the 603 (codes %v)", p.ResponseCodes())
		}
	}
	// CF-034: ua_destroy's HangupAllLive reaches this same UA.Hangup for a call
	// still being admitted; the dialog must be gone afterwards.
	if n := ua.RegisteredDialogCount(); n != 0 {
		t.Fatalf("%d dialogs still registered after the admitting call was declined, want 0", n)
	}
}

// A peer that never sends any provisional: the deferred Hangup gives up
// waiting after the cap (sipua's cancelWaitCap, 2s), returns nil, and has put
// no CANCEL on the wire. The UA's pre-ring budget is 5s so the dial itself does
// not settle first.
func TestDeferredHangupReturnsNilAfterTheCapWhenNoProvisionalComes(t *testing.T) {
	hold := make(chan struct{}) // never closed: no provisional, ever
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{HoldProvisionals: hold}})
	ua := newAuthUAWithTimeout(t, fakeclock.New(time.Unix(0, 0)), "", "", 5*time.Second)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeerCount(t, p, "INVITE", 1)

	start := time.Now()
	r := <-hangupAsync(ua, res.DialogID)
	elapsed := r.at.Sub(start)
	if r.err != nil {
		t.Fatalf("Hangup = %v, want nil when the cap elapses", r.err)
	}
	if elapsed < 1500*time.Millisecond || elapsed > 4*time.Second {
		t.Fatalf("Hangup returned after %v, want about the 2s cap", elapsed)
	}
	if n := p.Count("CANCEL"); n != 0 {
		t.Fatalf("peer received %d CANCEL with no provisional ever sent, want 0", n)
	}
}

// A final response arriving while a deferred Hangup waits settles the dial and
// releases Hangup at once — not at the cap — with no CANCEL sent.
func TestAFinalDuringTheDeferredWaitReleasesHangupPromptly(t *testing.T) {
	hold := make(chan struct{})
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{HoldProvisionals: hold}})
	ua := newAuthUAWithTimeout(t, fakeclock.New(time.Unix(0, 0)), "", "", 5*time.Second)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeerCount(t, p, "INVITE", 1)

	done := hangupAsync(ua, res.DialogID)
	time.Sleep(150 * time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("Hangup returned (%v) before the dial settled", r.err)
	default:
	}
	sent := time.Now()
	p.SendFinal(t, res.CallID, 486)
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Hangup = %v, want nil", r.err)
		}
		if d := r.at.Sub(sent); d > time.Second {
			t.Fatalf("Hangup returned %v after the final, want promptly (well under the 2s cap)", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Hangup never returned after the final response")
	}
	if n := p.Count("CANCEL"); n != 0 {
		t.Fatalf("peer received %d CANCEL, want 0 (no provisional ever arrived)", n)
	}
}

// A hangup pending when the first leg draws a digest challenge or a 422 must
// NOT send the retry INVITE: the challenge/422 is the dial's final response.
func TestAHangupBeforeAChallengeOrA422StopsTheRetry(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  peer.Config
		want int
	}{
		{"401", peer.Config{AuthUser: "alice", AuthPass: "s3cr3t"}, 401},
		{"422", peer.Config{Behaviour: peer.Behaviour{Reject422MinSE: 1800}}, 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hold := make(chan struct{})
			cfg := tc.cfg
			cfg.Addr = "127.0.0.1:0"
			cfg.Behaviour.HoldProvisionals = hold
			cfg.Behaviour.RingThenSilent = true
			p := peer.Start(t, cfg)
			ua := newAuthUAWithTimeout(t, fakeclock.New(time.Unix(0, 0)), "alice", "s3cr3t", 5*time.Second)
			events := collect(t, ua)

			res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			waitPeerCount(t, p, "INVITE", 1)
			done := hangupAsync(ua, res.DialogID)
			time.Sleep(100 * time.Millisecond)
			close(hold) // the peer now answers the first INVITE with its 401/422

			select {
			case r := <-done:
				if r.err != nil {
					t.Fatalf("Hangup = %v, want nil", r.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Hangup never returned after the 401/422 settled the dial")
			}
			waitFor(t, events, session.UAEventFinal, tc.want)
			time.Sleep(300 * time.Millisecond)
			if n := p.Count("INVITE"); n != 1 {
				t.Fatalf("peer received %d INVITE, want 1 — a retry went out after the hangup", n)
			}
			if n := p.Count("CANCEL"); n != 0 {
				t.Fatalf("peer received %d CANCEL, want 0", n)
			}
		})
	}
}

// When the CHALLENGED leg itself drew a provisional (its CANCEL was armed), the
// authed retry must re-arm: a later CANCEL targets the authed INVITE, not the
// challenged one.
func TestCancelTargetsTheAuthedInviteEvenWhenTheChallengedLegRang(t *testing.T) {
	hold := make(chan struct{})
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t",
		Behaviour: peer.Behaviour{RingThenSilent: true, HoldProvisionals: hold}})
	ua := newAuthUAWithTimeout(t, fakeclock.New(time.Unix(0, 0)), "alice", "s3cr3t", 5*time.Second)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeerCount(t, p, "INVITE", 1)
	p.SendProvisional(t, res.CallID, 100) // the challenged leg rings...
	time.Sleep(100 * time.Millisecond)
	close(hold) // ...then is challenged 401; the authed retry rings and goes silent
	waitFor(t, events, session.UAEventProvisional, 180)
	seqs := p.CSeqs("INVITE")
	if len(seqs) < 2 || seqs[len(seqs)-1] <= seqs[0] {
		t.Fatalf("INVITE CSeqs %v: want a challenged INVITE then a higher-CSeq authed retry", seqs)
	}

	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	waitPeerCount(t, p, "CANCEL", 1)
	assertCancelMatchesLastInvite(t, p)
}

// RFC 3261 §9.1 allows a CANCEL from the FIRST provisional of any code: a 100
// Trying, a 180 or a 183 alone arms it, so Hangup sends it at once.
func TestAnyFirstProvisionalArmsTheCancel(t *testing.T) {
	for _, code := range []int{100, 180, 183} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			hold := make(chan struct{}) // inviteFlow sends nothing; the test sends one 1xx
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{HoldProvisionals: hold}})
			ua := newAuthUAWithTimeout(t, fakeclock.New(time.Unix(0, 0)), "", "", 5*time.Second)

			res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			waitPeerCount(t, p, "INVITE", 1)
			p.SendProvisional(t, res.CallID, code)
			time.Sleep(100 * time.Millisecond)

			start := time.Now()
			if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
				t.Fatalf("Hangup = %v", err)
			}
			if d := time.Since(start); d > time.Second {
				t.Fatalf("Hangup took %v after a %d: the CANCEL was not armed by it", d, code)
			}
			waitPeerCount(t, p, "CANCEL", 1)
			assertCancelMatchesLastInvite(t, p)
		})
	}
}

// The CANCEL carries the INVITE's Route set (RFC 3261 §9.1).
func TestCancelCarriesTheInvitesRouteSet(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RingThenSilent: true}})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	route := "<sip:" + p.Addr() + ";lr>"
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr(),
		Headers: map[string]string{"Route": route}})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventProvisional, 180)
	if got := p.LastRequestHeader("INVITE", "Route"); got == "" {
		t.Fatal("the INVITE carried no Route header; the test premise failed")
	}
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	waitPeerCount(t, p, "CANCEL", 1)
	if got, want := p.LastRequestHeader("CANCEL", "Route"), p.LastRequestHeader("INVITE", "Route"); got != want {
		t.Fatalf("CANCEL Route = %q, want the INVITE's %q", got, want)
	}
}

// A caller whose ctx ends while its deferred Hangup waits for a first
// provisional is released at once with ctx.Err() — the existing Hangup
// contract (D152: a caller-ctx end is reported, not swallowed) — NOT nil and
// NOT at the 2s cap; nil is returned only when the cap itself elapses.
func TestDeferredHangupReturnsCtxErrWhenTheCallersCtxEnds(t *testing.T) {
	hold := make(chan struct{}) // never closed: no provisional, ever
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{HoldProvisionals: hold}})
	ua := newAuthUAWithTimeout(t, fakeclock.New(time.Unix(0, 0)), "", "", 5*time.Second)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeerCount(t, p, "INVITE", 1)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = ua.Hangup(ctx, res.DialogID, "")
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Hangup = %v, want context.DeadlineExceeded (the caller's ctx ended the wait)", err)
	}
	if elapsed > time.Second {
		t.Fatalf("Hangup returned after %v, want shortly after the 200ms ctx deadline, well under the 2s cap", elapsed)
	}
}

// failCancelConn fails every CANCEL the UA tries to write, as a transport
// that has gone away between the first provisional and the CANCEL would.
type failCancelConn struct{ net.PacketConn }

func (c failCancelConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if strings.HasPrefix(string(b), "CANCEL ") {
		return 0, errors.New("injected CANCEL write failure")
	}
	return c.PacketConn.WriteTo(b, addr)
}

// A deferred CANCEL whose write FAILS when the first provisional arrives must
// not be reported as sent: the waiting Hangup returns the write error (the
// direct path's "send CANCEL: ..." shape), not nil.
func TestDeferredHangupReturnsTheCancelWriteError(t *testing.T) {
	hold := make(chan struct{}) // inviteFlow sends nothing; the test sends the 1xx
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{HoldProvisionals: hold}})
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 5 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		WrapConn: func(pc net.PacketConn) net.PacketConn { return failCancelConn{pc} },
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeerCount(t, p, "INVITE", 1)
	done := hangupAsync(ua, res.DialogID)
	time.Sleep(100 * time.Millisecond)
	p.SendProvisional(t, res.CallID, 180)

	select {
	case r := <-done:
		if r.err == nil || !strings.Contains(r.err.Error(), "send CANCEL") {
			t.Fatalf("Hangup = %v, want the CANCEL write error (send CANCEL: ...)", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Hangup never returned after the failed CANCEL write")
	}
}

// A hangup landing in runDial's ACK -> phaseAnswered window (the outbound
// phaseAnswering claim) is recorded, not refused: runDial then ACKs (already
// done) and BYEs exactly once instead of establishing the call, and emits no
// answered event. Before, Hangup returned precondition_failed there while the
// session had already recorded the call terminated, and the call went live.
func TestHangupInsideTheOutboundAnsweringWindowIsByedOnce(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	opened, release := make(chan struct{}), make(chan struct{})
	sipua.SetDialAnsweringHook(func() {
		close(opened)
		<-release
	})
	t.Cleanup(func() { sipua.SetDialAnsweringHook(nil) })
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	select {
	case <-opened:
	case <-time.After(5 * time.Second):
		t.Fatal("runDial never reached the ACK -> phaseAnswered window")
	}

	done := hangupAsync(ua, res.DialogID)
	deadline := time.Now().Add(2 * time.Second)
	for !sipua.HangupPendingForTest(ua, res.DialogID) {
		select {
		case r := <-done:
			t.Fatalf("Hangup inside the answering window returned %v instead of recording the hangup", r.err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("Hangup never recorded its intent inside the answering window")
		}
		time.Sleep(time.Millisecond)
	}
	released = true
	close(release)

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Hangup = %v, want nil", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Hangup never returned")
	}
	p.WaitForBye(t, 3*time.Second)
	deadline = time.Now().Add(2 * time.Second)
	for ua.RegisteredDialogCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := ua.RegisteredDialogCount(); n != 0 {
		t.Fatalf("%d dialogs still registered, want 0", n)
	}
	time.Sleep(150 * time.Millisecond)
	if !p.AckBeforeBye() {
		t.Errorf("peer methods %v: want the ACK before the BYE", p.Methods())
	}
	if n := p.ByeCount(); n != 1 {
		t.Fatalf("peer received %d BYE, want exactly 1", n)
	}
	for _, ev := range events() {
		if ev.Kind == session.UAEventFinal && ev.Code == 200 {
			t.Fatalf("an answered event was emitted for a call hung up before it was established: %v", kinds(events()))
		}
	}
	if _, ok := ua.MediaView(res.DialogID); ok {
		t.Fatal("a media view exists for a call hung up before it was established")
	}
}

// failByeConn fails every BYE the UA tries to write.
type failByeConn struct{ net.PacketConn }

func (c failByeConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if strings.HasPrefix(string(b), "BYE ") {
		return 0, errors.New("injected BYE write failure")
	}
	return c.PacketConn.WriteTo(b, addr)
}

// parkInAnsweringWindow dials p, parks runDial in its ACK -> phaseAnswered
// window (dialAnsweringHook), starts an asynchronous Hangup and returns once
// that hangup is RECORDED, with the release func for the window.
func parkInAnsweringWindow(t *testing.T, ua *sipua.UA, p *peer.Peer) (session.DialResult, <-chan hangupResult, func()) {
	t.Helper()
	opened, release := make(chan struct{}), make(chan struct{})
	sipua.SetDialAnsweringHook(func() {
		close(opened)
		<-release
	})
	var once sync.Once
	rel := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() { rel(); sipua.SetDialAnsweringHook(nil) })

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	select {
	case <-opened:
	case <-time.After(5 * time.Second):
		t.Fatal("runDial never reached the ACK -> phaseAnswered window")
	}
	done := hangupAsync(ua, res.DialogID)
	deadline := time.Now().Add(2 * time.Second)
	for !sipua.HangupPendingForTest(ua, res.DialogID) {
		if time.Now().After(deadline) {
			t.Fatal("Hangup never recorded its intent inside the answering window")
		}
		time.Sleep(time.Millisecond)
	}
	return res, done, rel
}

// A hangup recorded in the answering window whose BYE cannot be WRITTEN must
// not be reported as done: Hangup returns the write error ("send BYE: ...").
func TestAnsweringWindowHangupReturnsTheByeWriteError(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		WrapConn: func(pc net.PacketConn) net.PacketConn { return failByeConn{pc} },
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	_, done, release := parkInAnsweringWindow(t, ua, p)
	release()
	select {
	case r := <-done:
		if r.err == nil || !strings.Contains(r.err.Error(), "send BYE") {
			t.Fatalf("Hangup = %v, want the BYE write error (send BYE: ...)", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Hangup never returned")
	}
}

// A peer BYE that ends the call after our hangup was RECORDED (answering
// window) releases the waiting Hangup at once — not at the 2s cap — and we send
// no BYE of our own.
func TestAPeerByeReleasesARecordedHangupPromptly(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))

	_, done, release := parkInAnsweringWindow(t, ua, p)
	sent := time.Now()
	p.SendBye(t)
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Hangup = %v, want nil (the peer ended the call)", r.err)
		}
		if d := r.at.Sub(sent); d > time.Second {
			t.Fatalf("Hangup returned %v after the peer BYE, want promptly (well under the 2s cap)", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Hangup never returned")
	}
	release()
	time.Sleep(200 * time.Millisecond)
	if n := p.ByeCount(); n != 0 {
		t.Fatalf("peer received %d BYE from us, want 0 (the peer ended the call)", n)
	}
}

// A peer BYE landing AFTER runDial claimed a hung-up answering-window dial for
// its own BYE but BEFORE that BYE is sent ends the call: runDial must then send
// NO BYE (the dialog is gone; the peer would answer 481), and the waiting
// Hangup returns nil promptly.
func TestAPeerByeBetweenTheClaimAndOurByeSuppressesOurBye(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))

	claimed, releaseBye := make(chan struct{}), make(chan struct{})
	sipua.SetHangupByeHook(func() {
		close(claimed)
		<-releaseBye
	})
	var once sync.Once
	relBye := func() { once.Do(func() { close(releaseBye) }) }
	t.Cleanup(func() { relBye(); sipua.SetHangupByeHook(nil) })

	_, done, release := parkInAnsweringWindow(t, ua, p)
	release()
	select {
	case <-claimed:
	case <-time.After(3 * time.Second):
		t.Fatal("runDial never claimed the hung-up dial for its BYE")
	}
	sent := time.Now()
	p.SendBye(t)
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Hangup = %v, want nil (the peer ended the call)", r.err)
		}
		if d := r.at.Sub(sent); d > time.Second {
			t.Fatalf("Hangup returned %v after the peer BYE, want promptly", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Hangup never returned")
	}
	relBye()
	time.Sleep(300 * time.Millisecond)
	if n := p.ByeCount(); n != 0 {
		t.Fatalf("peer received %d BYE from us on a dialog it had already ended, want 0", n)
	}
}

// A hangup recorded in the answering window whose 200 then FAILS media
// negotiation: runDial's media-failure path sends the one BYE, and if that BYE
// cannot be written the waiting Hangup gets the error, not nil.
func TestMediaFailureByeWriteErrorReachesARecordedHangup(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSDP: peer.AnswerRaw([]byte("garbage"))}})
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		WrapConn: func(pc net.PacketConn) net.PacketConn { return failByeConn{pc} },
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	_, done, release := parkInAnsweringWindow(t, ua, p)
	release() // ParseAnswer now fails on the garbage answer
	select {
	case r := <-done:
		if r.err == nil || !strings.Contains(r.err.Error(), "send BYE") {
			t.Fatalf("Hangup = %v, want the media-failure BYE's write error (send BYE: ...)", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Hangup never returned")
	}
}

// waitDialogsReaped polls until no dialog is registered, failing after d.
func waitDialogsReaped(t *testing.T, ua *sipua.UA, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for ua.RegisteredDialogCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d dialogs still registered after %v, want 0", ua.RegisteredDialogCount(), d)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// CF-030: once a CANCEL is written, runDial stops waiting the ~180s ring
// budget for the INVITE's final response and gives up after the post-CANCEL
// re-arm (RFC 3261 §9.1's 64*T1), reaping the dialog as a transport fault.
func TestPostCancelWaitIsReArmedNotTheRingBudget(t *testing.T) {
	defer sipua.SetOutboundRingBudget(30 * time.Second)()
	defer sipua.SetPostCancelWait(300 * time.Millisecond)()
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RingThenSilent: true}})
	ua, logs := newLoggedUA(t, nil)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventProvisional, 180)
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	waitPeerCount(t, p, "CANCEL", 1)

	// The hung-up dialog emits nothing when reaped; the reap is observed as the
	// dialog leaving the registry and the Warn naming the post-CANCEL wait.
	waitDialogsReaped(t, ua, 2*time.Second)
	assertLoggedPostCancelWait(t, logs)
}

// CF-030: a 487 or a crossing 200 that arrives INSIDE the post-CANCEL window
// still settles through the normal arms: 487 -> final, 200 -> ACK then BYE,
// and neither is a transport fault.
func TestLateFinalInsideThePostCancelWindowStillSettles(t *testing.T) {
	for _, code := range []int{487, 200} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			defer sipua.SetOutboundRingBudget(30 * time.Second)()
			defer sipua.SetPostCancelWait(3 * time.Second)()
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RingThenSilent: true}})
			ua, logs := newLoggedUA(t, nil)
			events := collect(t, ua)

			res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			waitFor(t, events, session.UAEventProvisional, 180)
			if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
				t.Fatalf("Hangup: %v", err)
			}
			waitPeerCount(t, p, "CANCEL", 1)
			time.Sleep(100 * time.Millisecond) // inside the window

			p.SendFinal(t, res.CallID, code)
			if code == 487 {
				waitFor(t, events, session.UAEventFinal, 487)
			} else {
				p.WaitForBye(t, 2*time.Second)
				if n := p.Count("ACK"); n != 1 || !p.AckBeforeBye() {
					t.Fatalf("crossing 200: peer saw %d ACK (want 1), ACK before BYE = %v; methods %v",
						n, p.AckBeforeBye(), p.Methods())
				}
			}
			waitDialogsReaped(t, ua, 2*time.Second)
			// The late final settled through its own path above. A hung-up
			// dialog that the post-CANCEL expiry reaped emits nothing, so the
			// expiry's only observable is its Warn: it must be absent here.
			time.Sleep(100 * time.Millisecond)
			if line := failedDialLog(logs); line != "" {
				t.Fatalf("a late %d inside the post-CANCEL window still ended as a failed dial: %s", code, line)
			}
		})
	}
}

// CF-030: the DEFERRED CANCEL (hangup before any 1xx, written on the first
// 1xx by dialProvisional) arms the same post-CANCEL re-arm.
func TestDeferredCancelAlsoArmsThePostCancelReArm(t *testing.T) {
	defer sipua.SetOutboundRingBudget(30 * time.Second)()
	defer sipua.SetPostCancelWait(300 * time.Millisecond)()
	release := make(chan struct{})
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{RingThenSilent: true, HoldProvisionals: release}})
	ua, logs := newLoggedUA(t, nil)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeerCount(t, p, "INVITE", 1)
	done := hangupAsync(ua, res.DialogID)
	time.Sleep(100 * time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("Hangup returned (%v) before the first 1xx: this would test the direct path", r.err)
	default:
	}
	close(release)
	if r := <-done; r.err != nil {
		t.Fatalf("Hangup = %v, want nil", r.err)
	}
	waitPeerCount(t, p, "CANCEL", 1)

	waitDialogsReaped(t, ua, 2*time.Second)
	assertLoggedPostCancelWait(t, logs)
	time.Sleep(100 * time.Millisecond)
	assertNoDialogEnd(t, events, res.DialogID)
}

// CF-030: repeat hangups return nil and put exactly one CANCEL on the wire (a
// repeat finds cancelRequested set and returns before any second send, which is
// what makes markCancelSent's bare close safe).
func TestRepeatHangupsReturnNilAndSendOneCancel(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RingThenSilent: true}})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventProvisional, 180)
	for i := 0; i < 3; i++ {
		if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
			t.Fatalf("Hangup #%d = %v, want nil", i+1, err)
		}
	}
	waitPeerCount(t, p, "CANCEL", 1)
	time.Sleep(100 * time.Millisecond)
	if n := p.Count("CANCEL"); n != 1 {
		t.Fatalf("peer received %d CANCEL, want exactly 1", n)
	}
	p.SendFinal(t, res.CallID, 487)
	waitFor(t, events, session.UAEventFinal, 487)
}

// newFailCancelUA is a direct-mode UA (its slog output captured) whose transport
// fails every CANCEL write.
func newFailCancelUA(t *testing.T) (*sipua.UA, *syncBuf) {
	t.Helper()
	return newLoggedUA(t, func(c *sipua.Config) {
		c.WrapConn = func(pc net.PacketConn) net.PacketConn { return failCancelConn{pc} }
	})
}

// CF-030: the post-CANCEL re-arm starts at the CANCEL ATTEMPT. A CANCEL whose
// write fails (direct path) still ends the dial at the re-arm; nothing else
// would end it before the ring budget.
func TestFailedDirectCancelWriteStillArmsThePostCancelReArm(t *testing.T) {
	defer sipua.SetOutboundRingBudget(30 * time.Second)()
	defer sipua.SetPostCancelWait(300 * time.Millisecond)()
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RingThenSilent: true}})
	ua, logs := newFailCancelUA(t)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventProvisional, 180)
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err == nil || !strings.Contains(err.Error(), "send CANCEL") {
		t.Fatalf("Hangup = %v, want the CANCEL write error", err)
	}
	waitDialogsReaped(t, ua, 2*time.Second)
	assertLoggedPostCancelWait(t, logs)
}

// CF-030: same, for the DEFERRED CANCEL (written on the first 1xx).
func TestFailedDeferredCancelWriteStillArmsThePostCancelReArm(t *testing.T) {
	defer sipua.SetOutboundRingBudget(30 * time.Second)()
	defer sipua.SetPostCancelWait(300 * time.Millisecond)()
	release := make(chan struct{})
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{RingThenSilent: true, HoldProvisionals: release}})
	ua, logs := newFailCancelUA(t)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeerCount(t, p, "INVITE", 1)
	done := hangupAsync(ua, res.DialogID)
	time.Sleep(100 * time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("Hangup returned (%v) before the first 1xx: this would test the direct path", r.err)
	default:
	}
	close(release)
	if r := <-done; r.err == nil || !strings.Contains(r.err.Error(), "send CANCEL") {
		t.Fatalf("Hangup = %v, want the CANCEL write error", r.err)
	}
	waitDialogsReaped(t, ua, 2*time.Second)
	assertLoggedPostCancelWait(t, logs)
	time.Sleep(100 * time.Millisecond)
	assertNoDialogEnd(t, events, res.DialogID)
}

// CF-030: a retry leg (digest 401 or 422) that rings, is hung up, and meets a
// silent far end is reaped at the post-CANCEL re-arm too: every leg's driveTx
// gets the dialog's cancelSent. The peer saw both INVITEs.
func TestRetryLegRingingThenHungUpIsReapedAtThePostCancelReArm(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  peer.Config
	}{
		{"401", peer.Config{AuthUser: "alice", AuthPass: "s3cr3t"}},
		{"422", peer.Config{Behaviour: peer.Behaviour{Reject422MinSE: 1800}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer sipua.SetOutboundRingBudget(30 * time.Second)()
			defer sipua.SetPostCancelWait(300 * time.Millisecond)()
			cfg := tc.cfg
			cfg.Addr = "127.0.0.1:0"
			cfg.Behaviour.RingThenSilent = true
			p := peer.Start(t, cfg)
			ua, logs := newLoggedUA(t, func(c *sipua.Config) {
				c.AuthUser, c.AuthPass = "alice", "s3cr3t"
				c.AuthAnyHost = true // CF-046: the peer is on 127.0.0.1, not the AOR host
			})
			events := collect(t, ua)

			res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			waitFor(t, events, session.UAEventProvisional, 180) // rung on the RETRY leg
			if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
				t.Fatalf("Hangup: %v", err)
			}
			waitPeerCount(t, p, "CANCEL", 1)
			waitDialogsReaped(t, ua, 2*time.Second)
			assertLoggedPostCancelWait(t, logs)
			if n := p.Count("INVITE"); n != 2 {
				t.Fatalf("peer received %d INVITE, want 2 (challenge/422, then the retry)", n)
			}
		})
	}
}

// CF-034: the CANCEL's Request-URI, Max-Forwards, Content-Length and single Via
// (RFC 3261 §9.1). The peer cannot show these (its header map keeps the last
// Via, the Request-URI is not a header), so the test reads the UA's OWN
// outbound bytes through the observing conn.
func TestCancelHeadersMatchTheInviteAndCarryOneVia(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RingThenSilent: true}})
	tap := &capturingTap{}
	ua, _ := newLoggedUA(t, func(c *sipua.Config) {
		c.WrapConn = func(pc net.PacketConn) net.PacketConn {
			return sipua.ObservingConn(pc, tap, session.TransportUDP, nil, "")
		}
	})
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventProvisional, 180)
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	waitPeerCount(t, p, "CANCEL", 1)

	var invRaw, canRaw []byte
	for _, rec := range tap.all() {
		if rec.Direction != session.Outbound {
			continue
		}
		switch rec.Method {
		case "INVITE":
			invRaw = rec.Raw
		case "CANCEL":
			canRaw = rec.Raw
		}
	}
	if invRaw == nil || canRaw == nil {
		t.Fatalf("observed outbound INVITE=%v CANCEL=%v, want both", invRaw != nil, canRaw != nil)
	}
	parse := func(raw []byte) *sip.Request {
		msg, err := sip.NewParser().ParseSIP(raw)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		req, ok := msg.(*sip.Request)
		if !ok {
			t.Fatalf("not a request: %T", msg)
		}
		return req
	}
	inv, can := parse(invRaw), parse(canRaw)

	if got, want := can.Recipient.String(), inv.Recipient.String(); got != want {
		t.Errorf("CANCEL Request-URI = %q, want the INVITE's %q", got, want)
	}
	if mf := can.GetHeader("Max-Forwards"); mf == nil || mf.Value() != "70" {
		t.Errorf("CANCEL Max-Forwards = %v, want 70", mf)
	}
	if cl := can.ContentLength(); cl == nil || cl.Value() != "0" {
		t.Errorf("CANCEL Content-Length = %v, want 0", cl)
	}
	vias := 0
	for _, line := range strings.Split(string(canRaw), "\r\n") {
		name, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if n := strings.ToLower(strings.TrimSpace(name)); n == "via" || n == "v" {
			vias++
			if strings.Contains(val, ",") {
				t.Errorf("CANCEL Via line %q carries more than one value", line)
			}
		}
	}
	if vias != 1 {
		t.Errorf("CANCEL carries %d Via header lines, want exactly 1", vias)
	}
	cv, iv := can.Via(), inv.Via()
	if cv == nil || iv == nil {
		t.Fatal("missing Via")
	}
	// Fields, never Via().Value(): the param map renders in varying order.
	cb, _ := cv.Params.Get("branch")
	ib, _ := iv.Params.Get("branch")
	if cv.Transport != iv.Transport || cv.Host != iv.Host || cv.Port != iv.Port || cb == "" || cb != ib {
		t.Errorf("CANCEL Via = %s %s:%d branch %q, want the INVITE's top Via %s %s:%d branch %q",
			cv.Transport, cv.Host, cv.Port, cb, iv.Transport, iv.Host, iv.Port, ib)
	}
}

// CF-034: a hangup whose wait hit the cap before any 1xx is still enacted: the
// late first provisional sends exactly one CANCEL.
func TestALate1xxAfterTheHangupCapStillSendsTheCancel(t *testing.T) {
	hold := make(chan struct{}) // never closed: only SendProvisional speaks
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{HoldProvisionals: hold}})
	ua := newAuthUAWithTimeout(t, fakeclock.New(time.Unix(0, 0)), "", "", 10*time.Second)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeerCount(t, p, "INVITE", 1)
	start := time.Now()
	r := <-hangupAsync(ua, res.DialogID)
	if r.err != nil {
		t.Fatalf("Hangup = %v, want nil at the cap", r.err)
	}
	if el := r.at.Sub(start); el < 1500*time.Millisecond {
		t.Fatalf("Hangup returned after %v, want about the 2s cap", el)
	}
	if n := p.Count("CANCEL"); n != 0 {
		t.Fatalf("peer received %d CANCEL before any provisional, want 0", n)
	}

	p.SendProvisional(t, res.CallID, 180)
	waitPeerCount(t, p, "CANCEL", 1)
	time.Sleep(150 * time.Millisecond)
	if n := p.Count("CANCEL"); n != 1 {
		t.Fatalf("peer received %d CANCEL, want exactly 1", n)
	}
	p.SendFinal(t, res.CallID, 487)
	waitFor(t, events, session.UAEventFinal, 487)
	waitDialogsReaped(t, ua, 2*time.Second)
}

// CF-034: a second Hangup issued while the first waits for its deferred CANCEL
// returns at once, and only one CANCEL goes out after the 1xx.
func TestRepeatHangupDuringADeferredWaitReturnsNil(t *testing.T) {
	release := make(chan struct{})
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{RingThenSilent: true, HoldProvisionals: release}})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeerCount(t, p, "INVITE", 1)
	first := hangupAsync(ua, res.DialogID)
	waitHangupParked(t, ua, res.DialogID)
	start := time.Now()
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("second Hangup = %v, want nil", err)
	}
	if el := time.Since(start); el > 200*time.Millisecond {
		t.Fatalf("second Hangup took %v, want at once (within 200ms)", el)
	}
	close(release)
	if r := <-first; r.err != nil {
		t.Fatalf("first Hangup = %v, want nil", r.err)
	}
	waitPeerCount(t, p, "CANCEL", 1)
	time.Sleep(150 * time.Millisecond)
	if n := p.Count("CANCEL"); n != 1 {
		t.Fatalf("peer received %d CANCEL, want exactly 1", n)
	}
	p.SendFinal(t, res.CallID, 487)
	waitFor(t, events, session.UAEventFinal, 487)
}

// CF-034: a 200 arriving during the deferred (no-1xx) wait is ACKed and BYE'd
// and releases the parked Hangup promptly; no CANCEL is sent.
func TestA200DuringTheDeferredWaitIsAckedByedAndReleasesHangup(t *testing.T) {
	hold := make(chan struct{})
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{HoldProvisionals: hold}})
	ua := newAuthUAWithTimeout(t, fakeclock.New(time.Unix(0, 0)), "", "", 5*time.Second)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeerCount(t, p, "INVITE", 1)
	done := hangupAsync(ua, res.DialogID)
	waitHangupParked(t, ua, res.DialogID)
	select {
	case r := <-done:
		t.Fatalf("Hangup returned (%v) before the dial settled", r.err)
	default:
	}
	sent := time.Now()
	p.SendFinal(t, res.CallID, 200)
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Hangup = %v, want nil", r.err)
		}
		if d := r.at.Sub(sent); d > time.Second {
			t.Fatalf("Hangup returned %v after the 200, want well under the 2s cap", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Hangup never returned after the 200")
	}
	p.WaitForBye(t, 3*time.Second)
	time.Sleep(150 * time.Millisecond)
	if n := p.Count("ACK"); n != 1 {
		t.Errorf("peer received %d ACK for the 200, want exactly 1", n)
	}
	if n := p.ByeCount(); n != 1 {
		t.Errorf("peer received %d BYE, want exactly 1", n)
	}
	if n := p.Count("CANCEL"); n != 0 {
		t.Errorf("peer received %d CANCEL, want 0", n)
	}
	waitDialogsReaped(t, ua, 2*time.Second)
}

// CF-034: a final other than 487 after the CANCEL (the far end refused or was
// busy) ends the dial as the dial's final, with the one CANCEL sent.
func TestANon487FinalAfterTheCancelEndsTheDial(t *testing.T) {
	for _, code := range []int{603, 486} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RingThenSilent: true}})
			ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
			events := collect(t, ua)

			res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			waitFor(t, events, session.UAEventProvisional, 180)
			if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
				t.Fatalf("Hangup: %v", err)
			}
			waitPeerCount(t, p, "CANCEL", 1)
			p.SendFinal(t, res.CallID, code)
			waitFor(t, events, session.UAEventFinal, code)
			waitDialogsReaped(t, ua, 2*time.Second)
			if n := p.Count("CANCEL"); n != 1 {
				t.Errorf("peer received %d CANCEL, want exactly 1", n)
			}
		})
	}
}

// waitHangupParked fails the test unless a Hangup has recorded its intent on the
// dialog within 2s (a sleep would let the interleaving under test silently not
// happen).
func waitHangupParked(t *testing.T, ua *sipua.UA, dialogID string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !sipua.HangupPendingForTest(ua, dialogID) {
		if time.Now().After(deadline) {
			t.Fatal("the Hangup was not recorded within 2s")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
