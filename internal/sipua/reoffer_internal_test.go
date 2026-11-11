package sipua

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

const reofferA = "v=0\r\no=probe 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 15282 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
const reofferB = "v=0\r\no=probe 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 15284 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"

// reofferDialog is an answered inbound dialog whose media was negotiated from
// reofferA, with no loop.
func reofferDialog(t *testing.T) (*UA, *dialog, []byte) {
	t.Helper()
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	// The direct onInvite callers below drive stub transactions that panic on a
	// second final: no 2xx retransmission (CF-208) may reach them in the test.
	oldT1 := ack2xxT1
	ack2xxT1 = time.Hour
	t.Cleanup(func() { ack2xxT1 = oldT1 })
	d, _ := newNotifyTestDialog(u, "cid-reoffer")
	ans, sess, err := media.BuildAnswer([]byte(reofferA), media.AnswerOptions{Prefs: media.CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:16384"})
	if err != nil {
		t.Fatal(err)
	}
	u.calls.mu.Lock()
	d.invite.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	d.invite.SetBody([]byte(reofferA))
	d.ok.SetBody(ans)
	d.mediaSession = sess
	u.calls.mu.Unlock()
	return u, d, ans
}

// blockingTx is a server transaction whose Respond parks until released, so a
// test can act while a final response is "being sent".
type blockingTx struct {
	stubServerTx
	inRespond chan struct{}
	release   chan struct{}
}

func (b *blockingTx) Respond(r *sip.Response) error {
	b.res = append(b.res, r)
	if r.StatusCode >= 200 {
		close(b.inRespond)
		<-b.release
	}
	return nil
}

func peerRequest(d *dialog, u *UA, method sip.RequestMethod, cseq uint32, offer string) *sip.Request {
	u.calls.mu.Lock()
	tag := ourReInviteTagLocked(d)
	u.calls.mu.Unlock()
	req := peerByeReq("cid-reoffer", tag)
	req.Method = method
	req.RemoveHeader("CSeq")
	req.AppendHeader(&sip.CSeqHeader{SeqNo: cseq, MethodName: method})
	if offer != "" {
		req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		req.SetBody([]byte(offer))
	}
	return req
}

// RFC 3261 14.2 / RFC 3311 5.2: an incoming INVITE (offer or not) or offer
// carrying UPDATE owns the dialog until its final response is SENT; another one
// in that window draws 500 with a Retry-After of 0-10, applies nothing, and the
// ownership is released afterwards (I2/I6, CF-163/164).
func TestOverlappingIncomingRequestsDraw500UntilTheFinalIsSent(t *testing.T) {
	for _, tc := range []struct {
		name        string
		first       sip.RequestMethod
		firstOffer  string
		second      sip.RequestMethod
		secondOffer string
	}{
		{"offer then offer INVITE", sip.INVITE, reofferB, sip.INVITE, reofferB},
		{"offer then offerless INVITE", sip.INVITE, reofferB, sip.INVITE, ""},
		{"offerless then offer INVITE", sip.INVITE, "", sip.INVITE, reofferB},
		{"offerless then offerless INVITE", sip.INVITE, "", sip.INVITE, ""},
		{"offer INVITE then offer UPDATE", sip.INVITE, reofferB, sip.UPDATE, reofferB},
		{"offerless INVITE then offer UPDATE", sip.INVITE, "", sip.UPDATE, reofferB},
		{"offer UPDATE then offer INVITE", sip.UPDATE, reofferB, sip.INVITE, reofferB},
		{"offer UPDATE then offerless INVITE", sip.UPDATE, reofferB, sip.INVITE, ""},
		{"offer UPDATE then offer UPDATE", sip.UPDATE, reofferB, sip.UPDATE, reofferB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, d, _ := reofferDialog(t)
			first := &blockingTx{inRespond: make(chan struct{}), release: make(chan struct{})}
			done := make(chan struct{})
			go func() {
				defer close(done)
				if tc.first == sip.INVITE {
					u.onInvite(peerRequest(d, u, sip.INVITE, 11, tc.firstOffer), first)
				} else {
					u.onUpdate(peerRequest(d, u, sip.UPDATE, 11, tc.firstOffer), first)
				}
			}()
			select {
			case <-first.inRespond:
			case <-time.After(3 * time.Second):
				t.Fatal("the first request never reached its final response")
			}
			second := &stubServerTx{}
			if tc.second == sip.INVITE {
				u.onInvite(peerRequest(d, u, sip.INVITE, 12, tc.secondOffer), second)
			} else {
				u.onUpdate(peerRequest(d, u, sip.UPDATE, 12, tc.secondOffer), second)
			}
			rej := second.last()
			if rej.StatusCode != 500 {
				t.Fatalf("second request while the first's final is in flight: %d, want 500", rej.StatusCode)
			}
			h := rej.GetHeader("Retry-After")
			if h == nil {
				t.Fatal("500 without Retry-After")
			}
			if n, err := strconv.Atoi(h.Value()); err != nil || n < 0 || n > 10 {
				t.Errorf("Retry-After %q, want an integer in 0..10", h.Value())
			}
			close(first.release)
			<-done
			if tc.first == sip.INVITE && tc.firstOffer == "" {
				// CF-207: our offer in that 200 is outstanding (a peer offer draws
				// 491) until its ACK carries the answer.
				ackOurReOffer(t, u, d, first, 11)
			}
			// released: the next request is answered
			third := &stubServerTx{}
			u.onInvite(peerRequest(d, u, sip.INVITE, 13, ""), third)
			if third.last().StatusCode != 200 {
				t.Fatalf("after the final response: %d, want 200 (ownership released)", third.last().StatusCode)
			}
		})
	}
}

// After an applied re-offer our SDP in force is the answer (version 2), which a
// session refresh re-INVITE replays.
func TestRefreshReInviteReplaysTheCurrentSDP(t *testing.T) {
	u, d, first := reofferDialog(t)
	ans, status, _ := u.answerInDialogOffer(d, []byte(reofferB))
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	body, _ := ourReInviteSDPLocked(d)
	if string(body) != string(ans) || string(body) == string(first) {
		t.Fatalf("SDP in force is not the new answer:\n%s", body)
	}
	if o := sdpOrigin(body); o == sdpOrigin(first) {
		t.Errorf("o= did not change: %q", o)
	}
	if d.mediaSession.RemoteAddr != "127.0.0.1:15284" || d.mediaSession.Origin.Version != 2 {
		t.Errorf("session %+v", d.mediaSession)
	}
	if d.peerOfferPending {
		t.Error("peerOfferPending not cleared")
	}
}

// An unchanged o= is a no-op: our SDP byte-for-byte, nothing applied.
func TestReOfferUnchangedOriginIsANoOp(t *testing.T) {
	u, d, first := reofferDialog(t)
	ans, status, _ := u.answerInDialogOffer(d, []byte(reofferA))
	if status != 200 || string(ans) != string(first) {
		t.Fatalf("status %d, answer differs from ours", status)
	}
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if d.localSDP != nil || d.mediaSession.Origin.Version != 1 {
		t.Error("an unchanged offer was applied")
	}
}

// D-10: a re-offer that changes the peer's SRTP key is refused 488 and
// nothing changes.
func TestReInviteSRTPChangeDraws488(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, _ := newNotifyTestDialog(u, "cid-reoffer-srtp")
	offer1, _, err := media.BuildOffer(media.CodecPrefs{"PCMU"}, "127.0.0.2:20000", media.SRTPRequired)
	if err != nil {
		t.Fatal(err)
	}
	ans, sess, err := media.BuildAnswer(offer1, media.AnswerOptions{Prefs: media.CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:16384", SRTP: media.SRTPRequired})
	if err != nil {
		t.Fatal(err)
	}
	offer2, _, err := media.BuildOffer(media.CodecPrefs{"PCMU"}, "127.0.0.2:20002", media.SRTPRequired) // a fresh key, new port
	if err != nil {
		t.Fatal(err)
	}
	offer2 = []byte(replaceOrigin(string(offer2), "o=- 999 2 IN IP4 127.0.0.2"))
	u.calls.mu.Lock()
	d.invite.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	d.invite.SetBody(offer1)
	d.ok.SetBody(ans)
	d.mediaSession = sess
	u.calls.mu.Unlock()
	if _, status, _ := u.answerInDialogOffer(d, offer2); status != 488 {
		t.Fatalf("status %d, want 488", status)
	}
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if d.mediaSession != sess || d.localSDP != nil {
		t.Error("a refused re-offer changed the session")
	}
}

func replaceOrigin(sdp, o string) string {
	lines := strings.Split(strings.TrimRight(sdp, "\r\n"), "\r\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "o=") {
			lines[i] = o
		}
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

// I11: an outbound dialog compares a re-offer with the answer actually applied
// (d.answerSDP, possibly an early 183's), not the 200's body.
func TestReOfferAfterAnEarlyAnswerComparesTheAppliedAnswer(t *testing.T) {
	d := &dialog{direction: session.Outbound, answerSDP: []byte(reofferA)}
	if got := peerSDPLocked(d); string(got) != reofferA {
		t.Fatalf("outbound peer SDP = %q, want the applied answer", got)
	}
	if sdpOrigin([]byte(reofferB)) == sdpOrigin(peerSDPLocked(d)) {
		t.Error("a re-offer with the 200's later o= would count as unchanged")
	}
	d.peerSDP = []byte(reofferB)
	if string(peerSDPLocked(d)) != reofferB {
		t.Error("an accepted re-offer is not the peer SDP in force")
	}
}

// A refresh-only UPDATE (no offer) never claims the incoming-offer slot and is
// not refused while an INVITE owns it.
func TestRefreshUpdateIsNotBlockedByAnOwnedInvite(t *testing.T) {
	u, d, _ := reofferDialog(t)
	first := &blockingTx{inRespond: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() { defer close(done); u.onInvite(peerRequest(d, u, sip.INVITE, 11, reofferB), first) }()
	<-first.inRespond
	second := &stubServerTx{}
	u.onUpdate(peerRequest(d, u, sip.UPDATE, 12, ""), second)
	if second.last().StatusCode != 200 {
		t.Errorf("refresh UPDATE during an owned INVITE: %d, want 200", second.last().StatusCode)
	}
	close(first.release)
	<-done
}

// outboundReofferDialog is an answered OUTBOUND dialog: our offer (SRTP policy
// srtp) and the peer's answer, negotiated by ParseAnswer, with no loop. It
// returns the dialog and the peer's answer SDP (the peer's SDP in force).
func outboundReofferDialog(t *testing.T, srtp, peerSRTP media.SRTPPolicy) (*UA, *dialog, []byte) {
	t.Helper()
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	offer, offerSess, err := media.BuildOffer(media.CodecPrefs{"PCMU"}, "127.0.0.1:16384", srtp)
	if err != nil {
		t.Fatal(err)
	}
	peerAns, _, err := media.BuildAnswer(offer, media.AnswerOptions{Prefs: media.CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.2:20000", SRTP: peerSRTP})
	if err != nil {
		t.Fatal(err)
	}
	sess, nerr := media.ParseAnswer(offerSess, peerAns)
	if nerr != nil {
		t.Fatal(nerr)
	}
	inv := sip.NewRequest(sip.INVITE, sip.Uri{User: "bob", Host: "peer"})
	cid := sip.CallIDHeader("cid-outbound-reoffer")
	inv.AppendHeader(&cid)
	from := &sip.FromHeader{Address: sip.Uri{User: "alice", Host: "here"}, Params: sip.NewParams()}
	from.Params.Add("tag", "our-tag")
	inv.AppendHeader(from)
	inv.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "bob", Host: "peer"}, Params: sip.NewParams()})
	inv.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})
	inv.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	inv.SetBody(offer)
	ok := sip.NewResponseFromRequest(inv, 200, "OK", peerAns)
	d := &dialog{id: "d-outbound-reoffer", direction: session.Outbound, phase: phaseAnswered,
		callID: "cid-outbound-reoffer", invite: inv, ok: ok, mediaSession: sess, answerSDP: peerAns}
	u.register(d)
	return u, d, peerAns
}

// CF-186: an unchanged re-offer on an outbound dialog is answered from the live
// session; under srtp optional against a plain peer the answer carries no key.
func TestUnchangedReOfferUnderOptionalSRTPCarriesNoKey(t *testing.T) {
	u, d, peerAns := outboundReofferDialog(t, media.SRTPOptional, media.SRTPDisabled)
	u.calls.mu.Lock()
	if d.mediaSession.LocalCrypto != nil {
		u.calls.mu.Unlock()
		t.Fatal("precondition: a plain peer must leave the session without keys")
	}
	offered := string(d.invite.Body())
	u.calls.mu.Unlock()
	if !strings.Contains(offered, "a=crypto") {
		t.Fatal("precondition: our optional offer carries a key")
	}
	ans, status, _ := u.answerInDialogOffer(d, peerAns)
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	if strings.Contains(string(ans), "a=crypto") {
		t.Fatalf("the answer carries a key the peer declined:\n%s", ans)
	}
}

// Guard: a healthy SRTP call is not 488'd by an unchanged re-offer, and our key
// is unchanged (Prev.LocalCrypto reused).
func TestUnchangedReOfferOnAnOutboundSRTPDialogIsAnswered(t *testing.T) {
	u, d, peerAns := outboundReofferDialog(t, media.SRTPOptional, media.SRTPOptional)
	u.calls.mu.Lock()
	key := *d.mediaSession.LocalCrypto
	u.calls.mu.Unlock()
	ans, status, _ := u.answerInDialogOffer(d, peerAns)
	if status != 200 {
		t.Fatalf("status %d, want 200", status)
	}
	if !strings.Contains(string(ans), key.AttrLine()) {
		t.Fatalf("the answer does not carry our existing key %q:\n%s", key.AttrLine(), ans)
	}
}

// Our previous SDP is an answer after the first unchanged re-offer: the second
// repeats it byte for byte (RFC 3264 8 "MUST be identical") and the version stays 2.
func TestSecondUnchangedReOfferRepeatsOurAnswer(t *testing.T) {
	u, d, peerAns := outboundReofferDialog(t, media.SRTPDisabled, media.SRTPDisabled)
	first, status, _ := u.answerInDialogOffer(d, peerAns)
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	second, status, _ := u.answerInDialogOffer(d, peerAns)
	if status != 200 || string(second) != string(first) {
		t.Fatalf("second answer differs from the first:\n%s\n---\n%s", first, second)
	}
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if v := d.mediaSession.Origin.Version; v != 2 {
		t.Errorf("origin version %d, want 2", v)
	}
}

func TestOurLastSDPIsAnswer(t *testing.T) {
	offered := sip.NewRequest(sip.INVITE, sip.Uri{User: "a", Host: "h"})
	offered.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	offered.SetBody([]byte(reofferA))
	offerless := sip.NewRequest(sip.INVITE, sip.Uri{User: "a", Host: "h"})
	for _, tc := range []struct {
		name string
		d    *dialog
		want bool
	}{
		{"outbound, no localSDP", &dialog{direction: session.Outbound, invite: offered}, false},
		{"inbound offered", &dialog{direction: session.Inbound, invite: offered}, true},
		{"inbound offerless", &dialog{direction: session.Inbound, invite: offerless}, false},
		{"any localSDP", &dialog{direction: session.Outbound, invite: offered, localSDP: []byte("x")}, true},
		{"localSDP that is our offer", &dialog{direction: session.Outbound, invite: offered, localSDP: []byte("x"), localSDPIsOffer: true}, false},
	} {
		if got := ourLastSDPIsAnswerLocked(tc.d); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ackOurReOffer ACKs (through onAck) the 200 our handler wrote to tx for the
// offerless re-INVITE with CSeq cseq, answering our offer with a plain PCMU answer.
func ackOurReOffer(t *testing.T, u *UA, d *dialog, tx *blockingTx, cseq uint32) {
	t.Helper()
	offer := tx.res[len(tx.res)-1].Body()
	if len(offer) == 0 {
		t.Fatal("the 200 to the offerless re-INVITE carries no offer")
	}
	answer, _, err := media.BuildAnswer(offer, media.AnswerOptions{Prefs: media.CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.3:30000"})
	if err != nil {
		t.Fatal(err)
	}
	u.onAck(peerRequest(d, u, sip.ACK, cseq, string(answer)), nil)
}

// O1b: the ACK of our offer-carrying 2xx beats the handler's return from Respond;
// the handler must then leave nothing outstanding (H never undoes the ACK).
func TestAckBeforeTheReOfferHandlerResumesLeavesNothingOutstanding(t *testing.T) {
	u, d, _ := reofferDialog(t)
	first := &blockingTx{inRespond: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() { defer close(done); u.onInvite(peerRequest(d, u, sip.INVITE, 11, ""), first) }()
	select {
	case <-first.inRespond:
	case <-time.After(3 * time.Second):
		t.Fatal("the offerless re-INVITE never reached its 2xx")
	}
	ackOurReOffer(t, u, d, first, 11)
	close(first.release)
	<-done
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if ourOfferOutstandingLocked(d) {
		t.Error("our offer is still outstanding after its ACK was applied")
	}
	if !d.localSDPIsOffer || d.mediaSession.RemoteAddr != "127.0.0.3:30000" {
		t.Errorf("the ACK's answer was not installed (localSDPIsOffer=%v, remote %s)", d.localSDPIsOffer, d.mediaSession.RemoteAddr)
	}
}

// reAnswerRig builds a re-offer on d's live session and a pending state for it.
func reAnswerRig(t *testing.T, u *UA, d *dialog) (*peerReinviteState, media.Session, []byte) {
	t.Helper()
	u.calls.mu.Lock()
	live := d.mediaSession
	u.calls.mu.Unlock()
	body, sess, err := media.BuildReOffer(live, media.CodecPrefs{"PCMU"})
	if err != nil {
		t.Fatal(err)
	}
	pr := &peerReinviteState{cseq: 7, acked: true, answerPending: true, offer: sess, offerSDP: body}
	u.calls.mu.Lock()
	d.peerReinvite = pr
	u.calls.mu.Unlock()
	return pr, *sess, body
}

// Another path already ends the dialog: an unusable answer claims nothing, so no
// second BYE leaves; a dialog in a control operation is claimed and its owner woken.
func TestUnusableReAnswerOnAnEndingDialogSendsNoSecondBye(t *testing.T) {
	t.Run("already ending", func(t *testing.T) {
		u, d, _ := reofferDialog(t)
		pr, offer, _ := reAnswerRig(t, u, d)
		u.calls.mu.Lock()
		d.phase = phaseMediaTeardown
		prev := d.mediaSession
		u.calls.mu.Unlock()
		claimed, err := u.applyReAnswer(d, pr, offer, prev, nil)
		if err == nil || claimed {
			t.Fatalf("claimed=%v err=%v, want an error and no claim", claimed, err)
		}
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		if pr.answerPending || d.phase != phaseMediaTeardown {
			t.Errorf("answerPending=%v phase=%v", pr.answerPending, d.phase)
		}
	})
	t.Run("control operation in flight", func(t *testing.T) {
		u, d, _ := reofferDialog(t)
		pr, offer, _ := reAnswerRig(t, u, d)
		ended := make(chan struct{})
		u.calls.mu.Lock()
		d.phase = phaseControlOp
		d.controlOpEnded = ended
		prev := d.mediaSession
		u.calls.mu.Unlock()
		claimed, err := u.applyReAnswer(d, pr, offer, prev, nil)
		if err == nil || !claimed {
			t.Fatalf("claimed=%v err=%v, want a claim", claimed, err)
		}
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		select {
		case <-ended:
		default:
			t.Error("the control operation's owner was not woken")
		}
		if d.controlOpEnded != nil || d.phase != phaseMediaTeardown {
			t.Errorf("controlOpEnded=%v phase=%v", d.controlOpEnded, d.phase)
		}
	})
}

// D-10: an answer to our re-offer may not start, stop or re-key SRTP.
func TestReAnswerChangingSRTPIsRefused(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, _ := newNotifyTestDialog(u, "cid-reanswer-srtp")
	offer1, _, err := media.BuildOffer(media.CodecPrefs{"PCMU"}, "127.0.0.2:20000", media.SRTPRequired)
	if err != nil {
		t.Fatal(err)
	}
	ans, live, err := media.BuildAnswer(offer1, media.AnswerOptions{Prefs: media.CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:16384", SRTP: media.SRTPRequired})
	if err != nil {
		t.Fatal(err)
	}
	u.calls.mu.Lock()
	d.invite.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	d.invite.SetBody(offer1)
	d.ok.SetBody(ans)
	d.mediaSession = live
	u.calls.mu.Unlock()
	for name, mk := range map[string]func(reoffer []byte) []byte{
		"no key": func(reoffer []byte) []byte {
			return []byte(strings.Join(filterLines(string(reoffer), "a=crypto"), "\r\n"))
		},
		"a different key": func(reoffer []byte) []byte {
			a, _, err := media.BuildAnswer(reoffer, media.AnswerOptions{Prefs: media.CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.2:20002", SRTP: media.SRTPRequired})
			if err != nil {
				t.Fatal(err)
			}
			return a
		},
	} {
		t.Run(name, func(t *testing.T) {
			pr, offer, body := reAnswerRig(t, u, d)
			u.calls.mu.Lock()
			d.phase = phaseAnswered
			prev := d.mediaSession
			u.calls.mu.Unlock()
			claimed, err := u.applyReAnswer(d, pr, offer, prev, mk(body))
			if err == nil || !claimed {
				t.Fatalf("claimed=%v err=%v, want a refusal that claims the dialog", claimed, err)
			}
			u.calls.mu.Lock()
			defer u.calls.mu.Unlock()
			if d.mediaSession != prev || pr.answerPending || d.phase != phaseMediaTeardown {
				t.Errorf("session swapped=%v answerPending=%v phase=%v", d.mediaSession != prev, pr.answerPending, d.phase)
			}
		})
	}
}

func filterLines(s, drop string) []string {
	var out []string
	for _, l := range strings.Split(s, "\r\n") {
		if !strings.HasPrefix(l, drop) {
			out = append(out, l)
		}
	}
	return out
}
