package sipua

// A peer's re-offer in an established dialog (a re-INVITE or an UPDATE with an
// SDP body): RFC 3261 14.2 and RFC 3311 5.2 require the UAS to adjust the
// session parameters when the description changed and to answer it. This file
// is the one place that does it (Rule 18); the handlers only route.
//
// Rule 16 reuse: media.BuildAnswer (with AnswerOptions.Prev), sdpBody (uas.go),
// ourReInviteSDPLocked (extended through d.localSDP), the loop's destMu.
// graphify has no output in this worktree; grep found no existing re-offer path.

import (
	"errors"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// sdpOrigin returns the o= line of an SDP body ("" when absent).
func sdpOrigin(sdp []byte) string {
	for _, l := range strings.Split(string(sdp), "\n") {
		if strings.HasPrefix(l, "o=") {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

// peerSDPLocked is the peer's SDP currently in force on d: the last accepted
// re-offer, else the SDP the dialog was set up with (the INVITE's body or the
// ACK's answer inbound, the answer actually applied outbound). Caller MUST hold
// u.calls.mu.
func peerSDPLocked(d *dialog) []byte {
	if d.peerSDP != nil {
		return d.peerSDP
	}
	if d.direction == session.Inbound {
		if b, _ := sdpBody(d.invite); len(b) > 0 {
			return b
		}
		return d.ackBody
	}
	return d.answerSDP
}

// ourLastSDPIsAnswerLocked reports whether our last SDP to the peer was an answer
// (RFC 3264 8: only an answer may be repeated to an unchanged offer): d.localSDP
// (set by answerInDialogOffer, always an answer), or, with no d.localSDP, an
// inbound dialog whose INVITE carried an offer (d.ok holds our answer). False on
// an outbound dialog (our last SDP is the INVITE's offer) and on an inbound
// offerless dialog (d.ok holds our offer). Caller MUST hold u.calls.mu.
func ourLastSDPIsAnswerLocked(d *dialog) bool {
	if d.localSDP != nil {
		return !d.localSDPIsOffer
	}
	if d.direction == session.Outbound {
		return false
	}
	b, _ := sdpBody(d.invite)
	return len(b) > 0
}

// answerInDialogOffer applies the peer's offer to d's live media session and
// returns our answer (status 200), or the refusal to send: 488 for an offer we
// cannot accept or that would change the SRTP keys, 500 for a local fault. The
// caller owns the dialog's peer offer (claimPeerOfferLocked) for the whole
// exchange, so a second offer never reaches here while one is being answered. An
// offer whose o= line is the peer's current one is unchanged (RFC 3264 8, "a
// no-op"): it is answered with our previous SDP when that was an answer and
// nothing is applied; when our previous SDP was an offer (outbound dialog, inbound
// offerless dialog) a valid answer is built from the live session like any
// re-offer, the live codec first so the call never switches codec (CF-186, B-D7).
func (u *UA) answerInDialogOffer(d *dialog, offer []byte) (answer []byte, status int, reason string) {
	u.calls.mu.Lock()
	prev := d.mediaSession
	prevPeer := peerSDPLocked(d)
	ours, _ := ourReInviteSDPLocked(d)
	ourAnswer := ourLastSDPIsAnswerLocked(d)
	u.calls.mu.Unlock()

	unchanged := false
	if o := sdpOrigin(offer); prev == nil || (o != "" && o == sdpOrigin(prevPeer)) {
		if prev == nil || ourAnswer {
			return ours, 200, "OK"
		}
		unchanged = true
	}
	prefs := u.codecPrefs()
	if unchanged && prev.Codec != "" {
		live := media.CodecPrefs{prev.Codec}
		for _, c := range prefs {
			if c != prev.Codec {
				live = append(live, c)
			}
		}
		prefs = live
	}
	answer, sess, err := media.BuildAnswer(offer, media.AnswerOptions{
		Prefs: prefs, LocalAddr: prev.LocalAddr, SRTP: prev.SRTPPolicy(), Prev: prev,
	})
	if err != nil {
		var ne *media.NegotiationError
		if errors.As(err, &ne) {
			return nil, 488, "Not Acceptable Here"
		}
		return nil, 500, "Server Internal Error"
	}
	// D-10: the SRTP transform is built once, from the keys of the first
	// negotiation; a re-offer that changes SRTP use or the peer's key is refused.
	if srtpChanged(prev, sess) {
		return nil, 488, "Not Acceptable Here"
	}
	n, err := newNegotiated(sess)
	if err != nil {
		return nil, 488, "Not Acceptable Here"
	}
	u.calls.mu.Lock()
	d.mediaSession = sess // a new pointer: a published Session is never mutated
	d.localSDP = answer
	d.localSDPIsOffer = false
	d.peerSDP = append([]byte(nil), offer...)
	if d.mediaLoop != nil {
		d.mediaLoop.swap(n)
	}
	u.calls.mu.Unlock()
	return answer, 200, "OK"
}

// claimPeerOfferLocked takes d's ownership of an incoming INVITE or offer
// carrying UPDATE, held until its final response is on the wire (RFC 3261 14.2:
// until then another INVITE draws 500 with a random Retry-After, RFC 3311 5.2
// the same for UPDATE). It is claimed whether or not the request carries SDP.
// false means another request owns it. Caller MUST hold u.calls.mu.
func claimPeerOfferLocked(d *dialog) bool {
	if d.peerOfferPending {
		return false
	}
	d.peerOfferPending = true
	return true
}

// releasePeerOffer ends the ownership claimPeerOfferLocked took.
func (u *UA) releasePeerOffer(d *dialog) {
	u.calls.mu.Lock()
	d.peerOfferPending = false
	u.calls.mu.Unlock()
}

// peerOfferBusy is the 500 with a random Retry-After for a request that arrives
// while another incoming INVITE or offer on the dialog is still being answered,
// and for a local fault while applying an offer.
func peerOfferBusy(req *sip.Request) *sip.Response {
	res := sip.NewResponseFromRequest(req, 500, "Server Internal Error", nil)
	// RFC 3261 14.2 / RFC 3311 5.2: a random 0-10 s.
	res.AppendHeader(sip.NewHeader("Retry-After", strconv.Itoa(rand.IntN(11))))
	return res
}

// applyOffer routes a matched in-dialog request's SDP offer through
// answerInDialogOffer and puts the answer on res (the 200). It returns the
// refusal to send instead when the offer is refused, nil otherwise. A request
// without an offer is left alone (res keeps its body).
func (u *UA) applyOffer(req *sip.Request, d *dialog, res *sip.Response) *sip.Response {
	offer, _ := sdpBody(req)
	if len(offer) == 0 {
		return nil
	}
	answer, status, reason := u.answerInDialogOffer(d, offer)
	if status != 200 {
		if status == 500 {
			return peerOfferBusy(req)
		}
		return sip.NewResponseFromRequest(req, sip.StatusCode(status), reason, nil)
	}
	res.RemoveHeader("Content-Type")
	res.SetBody(answer)
	if len(answer) > 0 {
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	}
	return nil
}

// srtpChanged is D-10's comparison: next changes SRTP use (the presence of our key
// or of the peer's) or the peer's key against prev. The SRTP transform is built
// once, from the keys of the first negotiation.
func srtpChanged(prev, next *media.Session) bool {
	return (next.LocalCrypto == nil) != (prev.LocalCrypto == nil) || (next.RemoteCrypto == nil) != (prev.RemoteCrypto == nil) ||
		(next.RemoteCrypto != nil && *next.RemoteCrypto != *prev.RemoteCrypto)
}

// reAnswerParsedHook is a TEST-ONLY seam (nil in production; set via
// export_test.go): applyReAnswer runs it between its unlocked part and the
// publishing section.
var reAnswerParsedHook atomic.Pointer[func()]

// applyReAnswer applies the answer in the ACK to our re-offer (CF-207, RFC 3264
// 4, RFC 3261 13.2.2.4): the offer in our 2xx to an offerless re-INVITE. Called
// WITHOUT u.calls.mu (it builds outside the lock and publishes inside it, like
// answerInDialogOffer; newNegotiated may resolve an address). offer is a value copy
// of pr.offer (a published Session is never mutated), prev the live session.
//
// On an unusable answer (absent, unparseable, a codec we did not offer, a change of
// SRTP use or of the peer's key; B-D8) nothing is installed. When the dialog was
// established it is claimed phaseMediaTeardown and claimed is true, and the caller
// ends the call with endNegotiationFailed (the BYE with Reason 488, one
// dialog_ended), the one rule for an unusable ACK answer (applyAckAnswer's). When
// another path already ended or is ending the dialog it returns claimed false. In
// every case answerPending is cleared in the publishing section.
func (u *UA) applyReAnswer(d *dialog, pr *peerReinviteState, offer media.Session, prev *media.Session, body []byte) (claimed bool, err error) {
	sess, err := media.ParseAnswer(&offer, body)
	var n *negotiated
	if err == nil && srtpChanged(prev, sess) {
		if prev.RemoteCrypto != nil && sess.RemoteCrypto == nil {
			err = media.SRTPPeerAnsweredAVP()
		} else {
			err = media.SDPUnparseable()
		}
	}
	if err == nil {
		if n, err = newNegotiated(sess); err != nil {
			err = media.SDPUnparseable()
		}
	}
	if hook := reAnswerParsedHook.Load(); hook != nil {
		(*hook)()
	}
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	pr.answerPending = false
	if err == nil {
		d.mediaSession = sess
		d.localSDP = pr.offerSDP
		d.localSDPIsOffer = true
		d.peerSDP = append([]byte(nil), body...)
		if d.mediaLoop != nil {
			d.mediaLoop.swap(n)
		}
		return false, nil
	}
	if dialogEstablished(d.phase) {
		d.phase = phaseMediaTeardown
		endControlOpLocked(d)
		claimed = true
	}
	return claimed, err
}
